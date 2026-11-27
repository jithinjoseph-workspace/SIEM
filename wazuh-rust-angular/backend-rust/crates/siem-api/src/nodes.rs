//! ProVigil nodes (specs/provigil-nodes.md, phase N2): AI and data lake boxes join the master with a
//! single-use token and report their health every 10 s; the console's Nodes page lists them.
//!
//! The token never crosses the network. A node signs its join request with it (HMAC-SHA256 over the
//! time, a random nonce and the body's hash), both sides derive the node's own key from the token and
//! the nonce, and the master's answer is signed back so the node knows it reached the real master.
//! Heartbeats are signed with the node key. TLS carries everything, but the signatures do not depend
//! on the master's certificate being trusted (the console's certificate is ProVigil's own).

use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use siem_crypto::{hmac_sha256_str, sha256_bytes};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// A join token is valid this long.
const TOKEN_LIFE: i64 = 24 * 3600;
/// A signed request is accepted this far from the master's clock (the nodes take time from it).
const CLOCK_SLACK: i64 = 120;
/// A node silent this long is shown as down.
const DOWN_AFTER: i64 = 30;
pub const ROLES: [&str; 2] = ["ai", "datalake"];

const DDL: [&str; 4] = [
    "CREATE TABLE IF NOT EXISTS cluster_config (key String, value String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY key",
    "CREATE TABLE IF NOT EXISTS cluster_tokens (token String, role String, created Int64, expires Int64, used_by String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY token",
    "CREATE TABLE IF NOT EXISTS cluster_nodes (id String, name String, role String, address String, platform String, version String, cpus UInt32, mem_total UInt64, disk_total UInt64, secret String, joined Int64, removed UInt8, row_version UInt64) ENGINE = ReplacingMergeTree(row_version) ORDER BY id",
    "CREATE TABLE IF NOT EXISTS cluster_node_status (id String, at Int64, mem_used UInt64, disk_used UInt64, load Float64, detail String) ENGINE = ReplacingMergeTree(at) ORDER BY id",
];

/// One join at a time: a token is checked and used up without a second join slipping in between.
static JOIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn hex_sha256(b: &[u8]) -> String {
    hex::encode(sha256_bytes(b))
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").trim()
}

fn err(code: StatusCode, m: &str) -> Response {
    (code, Json(json!({ "status": "error", "message": m }))).into_response()
}

fn super_only(ctx: &AuthCtx) -> Option<Response> {
    (!ctx.is_super()).then(|| err(StatusCode::FORBIDDEN, "Platform admins only"))
}

/// What a join request signs: the time, the nonce and the body's hash.
pub fn join_sig(token: &str, time: i64, nonce: &str, body: &[u8]) -> String {
    hmac_sha256_str(token, &format!("join\n{time}\n{nonce}\n{}", hex_sha256(body)))
}

/// The node's own key, derived on both sides (never sent).
pub fn node_secret(token: &str, nonce: &str) -> String {
    hmac_sha256_str(token, &format!("node\n{nonce}"))
}

/// The master's proof in its join answer.
pub fn joined_proof(token: &str, nonce: &str, id: &str) -> String {
    hmac_sha256_str(token, &format!("joined\n{nonce}\n{id}"))
}

/// What a heartbeat signs.
pub fn beat_sig(secret: &str, id: &str, time: i64, body: &[u8]) -> String {
    hmac_sha256_str(secret, &format!("beat\n{id}\n{time}\n{}", hex_sha256(body)))
}

fn plain(s: &str, max: usize, extra: &str) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            if state.db.is_connected() {
                let mut ok = true;
                for ddl in DDL {
                    if let Err(e) = state.db.main().query(&provigil_common::ddl::on_cluster(ddl)).execute().await {
                        tracing::warn!("nodes table: {e}");
                        ok = false;
                    }
                }
                if ok {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}

#[derive(clickhouse::Row, Serialize, Deserialize, Clone)]
struct TokenRow {
    token: String,
    role: String,
    created: i64,
    expires: i64,
    used_by: String,
    version: u64,
}

#[derive(clickhouse::Row, Serialize, Deserialize, Clone)]
struct NodeRow {
    id: String,
    name: String,
    role: String,
    address: String,
    platform: String,
    version: String,
    cpus: u32,
    mem_total: u64,
    disk_total: u64,
    secret: String,
    joined: i64,
    removed: u8,
    row_version: u64,
}

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct StatusRow {
    id: String,
    at: i64,
    mem_used: u64,
    disk_used: u64,
    load: f64,
    detail: String,
}

#[derive(Deserialize, Default)]
pub struct TokenReq {
    #[serde(default)]
    role: String,
}

/// `POST /api/cluster/tokens` {role?} (platform admins): a single-use join token, valid 24 hours.
pub async fn create_token(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<TokenReq>) -> Response {
    if let Some(e) = super_only(&ctx) {
        return e;
    }
    if !r.role.is_empty() && !ROLES.contains(&r.role.as_str()) {
        return err(StatusCode::BAD_REQUEST, "role must be ai or datalake");
    }
    let token = format!("pvj_{}", hex::encode(rand::random::<[u8; 24]>()));
    let t = now();
    let row = TokenRow { token: token.clone(), role: r.role.clone(), created: t, expires: t + TOKEN_LIFE, used_by: String::new(), version: t as u64 };
    if let Err(e) = insert(&state, "cluster_tokens", &row).await {
        return err(StatusCode::SERVICE_UNAVAILABLE, &e);
    }
    Json(json!({ "token": token, "role": r.role, "expires": t + TOKEN_LIFE })).into_response()
}

async fn insert<T: clickhouse::Row + Serialize>(state: &AppState, table: &str, row: &T) -> Result<(), String> {
    let mut i = state.db.main().insert(table).map_err(|e| e.to_string())?;
    i.write(row).await.map_err(|e| e.to_string())?;
    i.end().await.map_err(|e| e.to_string())
}

#[derive(Deserialize)]
pub struct JoinReq {
    name: String,
    role: String,
    address: String,
    platform: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    cpus: u32,
    #[serde(default)]
    mem_total: u64,
    #[serde(default)]
    disk_total: u64,
}

/// `POST /api/cluster/join` (public route; signed with the token, see the module notes): a new node.
pub async fn join(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let (time, nonce, sig) = (header(&headers, "x-join-time").parse::<i64>().unwrap_or(0), header(&headers, "x-join-nonce"), header(&headers, "x-join-sig"));
    if (now() - time).abs() > CLOCK_SLACK || !plain(nonce, 64, "") || nonce.len() < 32 || sig.len() != 64 {
        return err(StatusCode::UNAUTHORIZED, "unsigned or stale join (check the node's clock)");
    }
    let Ok(r) = serde_json::from_slice::<JoinReq>(&body) else { return err(StatusCode::BAD_REQUEST, "bad join request") };
    if !plain(&r.name, 63, ".-_") || !ROLES.contains(&r.role.as_str()) || !plain(&r.address, 100, ".:-") || !plain(&r.platform, 40, ".-_ ") || r.version.len() > 40 {
        return err(StatusCode::BAD_REQUEST, "bad name, role, address or platform");
    }
    let _one = JOIN_LOCK.lock().await;
    let t = now();
    let tokens: Vec<TokenRow> = state.db.main().query("SELECT ?fields FROM cluster_tokens FINAL WHERE used_by = '' AND expires > ?").bind(t).fetch_all().await.unwrap_or_default();
    // the token whose signature matches; it is never sent
    let Some(tok) = tokens.into_iter().find(|k| same(&join_sig(&k.token, time, nonce, &body), sig)) else {
        return err(StatusCode::UNAUTHORIZED, "unknown, used or expired join token");
    };
    if !tok.role.is_empty() && tok.role != r.role {
        return err(StatusCode::FORBIDDEN, "this token is for another role");
    }
    let id = uuid::Uuid::new_v4().to_string();
    let node = NodeRow {
        id: id.clone(), name: r.name, role: r.role, address: r.address, platform: r.platform, version: r.version,
        cpus: r.cpus.min(4096), mem_total: r.mem_total, disk_total: r.disk_total,
        secret: node_secret(&tok.token, nonce), joined: t, removed: 0, row_version: t as u64,
    };
    if let Err(e) = insert(&state, "cluster_nodes", &node).await {
        return err(StatusCode::SERVICE_UNAVAILABLE, &e);
    }
    let used = TokenRow { used_by: id.clone(), version: tok.version + 1, ..tok.clone() };
    if let Err(e) = insert(&state, "cluster_tokens", &used).await {
        tracing::warn!("node {id} joined but its token was not marked used: {e}");
    }
    tracing::info!("node {} joined as {} ({}, {})", node.name, node.role, node.address, node.platform);
    Json(json!({ "node_id": id, "proof": joined_proof(&tok.token, nonce, &id) })).into_response()
}

#[derive(Deserialize)]
pub struct Beat {
    #[serde(default)]
    mem_used: u64,
    #[serde(default)]
    disk_used: u64,
    #[serde(default)]
    load: f64,
    #[serde(default)]
    detail: Value,
}

async fn node(state: &AppState, id: &str) -> Option<NodeRow> {
    state.db.main().query("SELECT ?fields FROM cluster_nodes FINAL WHERE id = ?").bind(id).fetch_optional::<NodeRow>().await.ok().flatten()
}

/// `POST /api/cluster/heartbeat` (public route; signed with the node key): a node's health.
pub async fn heartbeat(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let (id, time, sig) = (header(&headers, "x-node-id"), header(&headers, "x-time").parse::<i64>().unwrap_or(0), header(&headers, "x-sig"));
    if (now() - time).abs() > CLOCK_SLACK || !plain(id, 40, "-") {
        return err(StatusCode::UNAUTHORIZED, "unsigned or stale heartbeat (check the node's clock)");
    }
    let Some(n) = node(&state, id).await.filter(|n| n.removed == 0) else { return err(StatusCode::UNAUTHORIZED, "unknown or removed node") };
    if !same(&beat_sig(&n.secret, id, time, &body), sig) {
        return err(StatusCode::UNAUTHORIZED, "bad signature");
    }
    let Ok(b) = serde_json::from_slice::<Beat>(&body) else { return err(StatusCode::BAD_REQUEST, "bad heartbeat") };
    let detail = b.detail.to_string();
    if detail.len() > 4096 {
        return err(StatusCode::BAD_REQUEST, "detail too large");
    }
    let row = StatusRow { id: id.to_string(), at: now(), mem_used: b.mem_used, disk_used: b.disk_used, load: if b.load.is_finite() { b.load } else { 0.0 }, detail };
    match insert(&state, "cluster_node_status", &row).await {
        Ok(()) => Json(json!({ "status": "ok" })).into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, &e),
    }
}

/// A node's state from its last heartbeat.
pub fn node_state(last: Option<i64>, t: i64) -> &'static str {
    match last {
        None => "joining",
        Some(at) if t - at <= DOWN_AFTER => "ready",
        Some(_) => "down",
    }
}

/// `GET /api/cluster/nodes` (platform admins): every node with its latest health.
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    if let Some(e) = super_only(&ctx) {
        return e;
    }
    let nodes: Vec<NodeRow> = match state.db.main().query("SELECT ?fields FROM cluster_nodes FINAL WHERE removed = 0 ORDER BY role, name").fetch_all().await {
        Ok(n) => n,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &e.to_string()),
    };
    let status: Vec<StatusRow> = state.db.main().query("SELECT ?fields FROM cluster_node_status FINAL").fetch_all().await.unwrap_or_default();
    let t = now();
    // the data lake layout: each node's shard and copy, whether it applied its settings
    let shards = plan(&lake_nodes(&state).await);
    let secret = if shards.is_empty() { None } else { cluster_secret(&state).await.ok() };
    let list: Vec<Value> = nodes
        .into_iter()
        .map(|n| {
            let s = status.iter().find(|s| s.id == n.id);
            let detail = s.and_then(|s| serde_json::from_str::<Value>(&s.detail).ok());
            let lake = (n.role == "datalake").then(|| {
                let (shard, copy) = names(&shards, &n.name).unwrap_or_default();
                let copies = shards.iter().find(|s| s.iter().any(|(x, _)| *x == n.name)).map_or(0, Vec::len);
                let want = secret.as_deref().and_then(|k| layout_xml(&shards, &n.name, k)).map(|x| hex_sha256(x.as_bytes()));
                let applied = detail.as_ref().and_then(|d| d.get("layout")).and_then(Value::as_str);
                json!({ "shard": shard, "copy": copy, "copies": copies, "layout_applied": want.is_some() && applied == want.as_deref() })
            });
            json!({
                "id": n.id, "name": n.name, "role": n.role, "address": n.address, "platform": n.platform, "version": n.version,
                "cpus": n.cpus, "mem_total": n.mem_total, "disk_total": n.disk_total, "joined": n.joined,
                "state": node_state(s.map(|s| s.at), t), "last_seen": s.map(|s| s.at),
                "mem_used": s.map(|s| s.mem_used), "disk_used": s.map(|s| s.disk_used), "load": s.map(|s| s.load),
                "detail": detail, "lake": lake,
            })
        })
        .collect();
    let warnings: Vec<String> = shards
        .iter()
        .enumerate()
        .filter(|(_, s)| s.len() == 1)
        .map(|(i, s)| format!("Data lake shard {:02} has one copy ({}): its share of the large tables is lost if that box fails. Add another data lake node, or keep nightly backups.", i + 1, s[0].0))
        .collect();
    Json(json!({ "nodes": list, "warnings": warnings })).into_response()
}

/// `DELETE /api/cluster/nodes/:id` (platform admins): the node is removed; its key stops working.
pub async fn remove(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    if let Some(e) = super_only(&ctx) {
        return e;
    }
    let Some(n) = node(&state, &id).await else { return err(StatusCode::NOT_FOUND, "no such node") };
    let row = NodeRow { removed: 1, row_version: n.row_version.max(now() as u64) + 1, ..n };
    match insert(&state, "cluster_nodes", &row).await {
        Ok(()) => Json(json!({ "status": "ok" })).into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, &e),
    }
}

// ---- the data lake layout (N4d) ----
//
// The master decides the ClickHouse cluster of the data lake nodes from the Nodes list: nodes in
// join order, two per shard and never moved (node 1 and 2 shard 01, node 3 and 4 shard 02, ...; an
// odd last node has no second copy until the next one joins), ClickHouse Keeper on the first node.
// The first node keeps the names the data lake installer gave it (shard 01, copy replica-01): it was
// installed before the master and its tables are registered under them. Each data lake node fetches its own settings (signed like a heartbeat,
// encrypted with its node key: they carry the cluster secret) and applies them; the master then
// creates the missing databases and tables on it, so it joins the copies and fills itself.
// shortcut: one Keeper (the first data lake node); three Keepers when a site needs Keeper to survive
// that node's loss.

/// The cluster name every ProVigil ClickHouse uses.
pub const CLUSTER: &str = "ndr_cluster";

/// A data lake node in the layout: name, address.
pub type LakeNode = (String, String);

/// Shards of the data lake nodes (in join order): pairs, so a node never changes shard as nodes join.
pub fn plan(nodes: &[LakeNode]) -> Vec<Vec<LakeNode>> {
    nodes.chunks(2).map(|c| c.to_vec()).collect()
}

/// A node's shard and copy names: shard `01`, `02`, ...; the first node's copy `replica-01` (the data
/// lake installer's name), the others their node name.
pub fn names(shards: &[Vec<LakeNode>], me: &str) -> Option<(String, String)> {
    shards.iter().enumerate().find_map(|(i, s)| {
        let j = s.iter().position(|(n, _)| n == me)?;
        let replica = if i == 0 && j == 0 { "replica-01".to_string() } else { me.to_string() };
        Some((format!("{:02}", i + 1), replica))
    })
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// The ClickHouse settings file for `me` (a node of `shards`): the cluster with its shared secret
/// (servers trust each other's queries by it), this server's shard and copy name, the Keeper, and
/// the credentials servers use to copy data between them.
pub fn layout_xml(shards: &[Vec<LakeNode>], me: &str, secret: &str) -> Option<String> {
    let addr = shards.iter().flatten().find(|(n, _)| n == me)?.1.clone();
    let (shard_no, replica) = names(shards, me)?;
    let keeper = shards.first()?.first()?.1.clone();
    let mut x = String::from("<clickhouse>\n    <!-- written by ProVigil (the master's Nodes list); replaced on every change -->\n    <remote_servers replace=\"replace\">\n        <ndr_cluster>\n");
    x += &format!("            <secret>{}</secret>\n", xml_escape(secret));
    for s in shards {
        x += "            <shard>\n                <internal_replication>true</internal_replication>\n";
        for (_, a) in s {
            x += &format!("                <replica><host>{}</host><port>9000</port></replica>\n", xml_escape(a));
        }
        x += "            </shard>\n";
    }
    x += "        </ndr_cluster>\n    </remote_servers>\n";
    x += &format!("    <macros replace=\"replace\">\n        <cluster>{CLUSTER}</cluster>\n        <shard>{shard_no}</shard>\n        <replica>{}</replica>\n    </macros>\n", xml_escape(&replica));
    x += &format!("    <zookeeper replace=\"replace\">\n        <node><host>{}</host><port>9181</port></node>\n    </zookeeper>\n", xml_escape(&keeper));
    x += &format!("    <interserver_http_host>{}</interserver_http_host>\n", xml_escape(&addr));
    x += &format!(
        "    <interserver_http_credentials>\n        <user>provigil_interserver</user>\n        <password>{}</password>\n    </interserver_http_credentials>\n",
        hmac_sha256_str(secret, "interserver")
    );
    x += "</clickhouse>\n";
    Some(x)
}

/// The cluster's shared secret (made once, kept in ClickHouse).
async fn cluster_secret(state: &AppState) -> Result<String, String> {
    let have: Option<String> = state.db.main().query("SELECT value FROM cluster_config FINAL WHERE key = 'secret'").fetch_optional().await.map_err(|e| e.to_string())?;
    if let Some(s) = have.filter(|s| s.len() >= 32) {
        return Ok(s);
    }
    let s = hex::encode(rand::random::<[u8; 32]>());
    state.db.main().query("INSERT INTO cluster_config (key, value, version) VALUES ('secret', ?, 1)").bind(&s).execute().await.map_err(|e| e.to_string())?;
    // two masters starting at once: the stored one wins
    let stored: Option<String> = state.db.main().query("SELECT value FROM cluster_config FINAL WHERE key = 'secret'").fetch_optional().await.map_err(|e| e.to_string())?;
    Ok(stored.unwrap_or(s))
}

/// The data lake nodes in join order (removed ones left out).
pub async fn lake_nodes(state: &AppState) -> Vec<LakeNode> {
    let rows: Vec<NodeRow> = state.db.main().query("SELECT ?fields FROM cluster_nodes FINAL WHERE removed = 0 AND role = 'datalake' ORDER BY joined, id").fetch_all().await.unwrap_or_default();
    rows.into_iter().map(|n| (n.name, n.address)).collect()
}

/// `plain` encrypted for a node: AES-256-CBC with a key from the node key and a fresh nonce
/// (`openssl enc -d -aes-256-cbc -K <key> -iv <iv>` reads it), and a signature over it.
pub fn seal(secret: &str, nonce: &str, iv: &[u8; 16], plain: &str) -> (String, String) {
    use base64::Engine as _;
    let key = hex::decode(hmac_sha256_str(secret, &format!("layout\n{nonce}"))).unwrap_or_default();
    let data = base64::engine::general_purpose::STANDARD.encode(siem_crypto::encrypt_aes(plain.as_bytes(), &key, iv));
    let mac = hmac_sha256_str(secret, &format!("layout-mac\n{nonce}\n{data}"));
    (data, mac)
}

/// `GET /api/cluster/layout` (public route; signed by the node like a heartbeat, empty body): this
/// data lake node's ClickHouse settings (encrypted for it) and the other nodes' addresses.
pub async fn layout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (id, time, sig) = (header(&headers, "x-node-id"), header(&headers, "x-time").parse::<i64>().unwrap_or(0), header(&headers, "x-sig"));
    if (now() - time).abs() > CLOCK_SLACK || !plain(id, 40, "-") {
        return err(StatusCode::UNAUTHORIZED, "unsigned or stale request (check the node's clock)");
    }
    let Some(n) = node(&state, id).await.filter(|n| n.removed == 0) else { return err(StatusCode::UNAUTHORIZED, "unknown or removed node") };
    if !same(&beat_sig(&n.secret, id, time, b""), sig) {
        return err(StatusCode::UNAUTHORIZED, "bad signature");
    }
    if n.role != "datalake" {
        return err(StatusCode::BAD_REQUEST, "only data lake nodes have a layout");
    }
    let secret = match cluster_secret(&state).await {
        Ok(s) => s,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    let nodes = lake_nodes(&state).await;
    let shards = plan(&nodes);
    let Some(xml) = layout_xml(&shards, &n.name, &secret) else { return err(StatusCode::SERVICE_UNAVAILABLE, "node not in the layout yet") };
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let iv: [u8; 16] = rand::random();
    let (data, mac) = seal(&n.secret, &nonce, &iv, &xml);
    let peers: Vec<&str> = nodes.iter().filter(|(name, _)| *name != n.name).map(|(_, a)| a.as_str()).collect();
    Json(json!({ "version": hex_sha256(xml.as_bytes()), "nonce": nonce, "iv": hex::encode(iv), "data": data, "mac": mac, "peers": peers })).into_response()
}

// ---- a joined data lake node gets the tables (N4d) ----

/// A table on the reference server (the one the master writes to).
#[derive(clickhouse::Row, Deserialize, Clone)]
pub struct RefTable {
    pub database: String,
    pub name: String,
    pub uuid: String,
    pub q: String,
    pub engine: String,
}

const REF_TABLES: &str = "SELECT database, name, toString(uuid) AS uuid, create_table_query AS q, engine FROM system.tables \
     WHERE (database = 'ndr' OR startsWith(database, 'ndr_')) AND NOT is_temporary ORDER BY engine = 'Distributed', database, name";

/// The statements that give a server the databases and tables it lacks: databases first, tables
/// with their own id (their copy path has `{uuid}`, so they join the existing copies and fill
/// themselves), Distributed tables last.
pub fn copy_statements(reference: &[RefTable], have: &std::collections::HashSet<(String, String)>, have_dbs: &std::collections::HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut dbs: Vec<&str> = reference.iter().map(|r| r.database.as_str()).collect();
    dbs.sort_unstable();
    dbs.dedup();
    for d in dbs {
        if !have_dbs.contains(d) {
            out.push(format!("CREATE DATABASE IF NOT EXISTS `{}`", d.replace('`', "")));
        }
    }
    for r in reference {
        if have.contains(&(r.database.clone(), r.name.clone())) || r.q.is_empty() {
            continue;
        }
        let q = match r.q.strip_prefix("CREATE TABLE ") {
            Some(rest) if !r.uuid.starts_with("00000000") => {
                let (name, tail) = rest.split_once(' ').unwrap_or((rest, ""));
                format!("CREATE TABLE IF NOT EXISTS {name} UUID '{}' {tail}", r.uuid)
            }
            _ => r.q.clone(),
        };
        out.push(q);
    }
    out
}

/// What a data lake node reported last: its address, whether ClickHouse answers, the layout version it applied.
async fn lake_status(state: &AppState) -> Vec<(NodeRow, Value)> {
    let nodes: Vec<NodeRow> = state.db.main().query("SELECT ?fields FROM cluster_nodes FINAL WHERE removed = 0 AND role = 'datalake'").fetch_all().await.unwrap_or_default();
    let status: Vec<StatusRow> = state.db.main().query("SELECT ?fields FROM cluster_node_status FINAL WHERE at > ?").bind(now() - DOWN_AFTER).fetch_all().await.unwrap_or_default();
    nodes
        .into_iter()
        .filter_map(|n| {
            let d: Value = serde_json::from_str(&status.iter().find(|s| s.id == n.id)?.detail).ok()?;
            Some((n, d))
        })
        .collect()
}

/// Every minute: each ready data lake node that applied its current layout gets the databases and
/// tables it lacks (a node that joined, or tenants made while it was away).
pub fn spawn_schema_sync(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if !state.db.is_connected() {
                continue;
            }
            if let Err(e) = sync_once(&state).await {
                tracing::warn!("data lake tables: {e}");
            }
        }
    });
}

async fn sync_once(state: &AppState) -> Result<(), String> {
    let lake = lake_status(state).await;
    if lake.len() < 2 {
        return Ok(());
    }
    let secret = cluster_secret(state).await?;
    let shards = plan(&lake_nodes(state).await);
    let reference: Vec<RefTable> = state.db.root().query(REF_TABLES).fetch_all().await.map_err(|e| e.to_string())?;
    let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into());
    let password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
    for (n, d) in lake {
        let applied = d.get("layout").and_then(Value::as_str).unwrap_or("");
        let want = layout_xml(&shards, &n.name, &secret).map(|x| hex_sha256(x.as_bytes())).unwrap_or_default();
        // before its layout is in place a table would register under the wrong copy name
        if d.get("service_up") != Some(&Value::Bool(true)) || applied != want {
            continue;
        }
        let host = if n.address.contains(':') { format!("[{}]", n.address) } else { n.address.clone() };
        let c = clickhouse::Client::default().with_url(format!("http://{host}:8123")).with_user(&user).with_password(&password);
        let have: std::collections::HashSet<(String, String)> = match c.query("SELECT database, name FROM system.tables WHERE database = 'ndr' OR startsWith(database, 'ndr_')").fetch_all::<(String, String)>().await {
            Ok(v) => v.into_iter().collect(),
            Err(e) => {
                tracing::warn!("data lake node {}: not reachable from the master: {e}", n.name);
                continue;
            }
        };
        let have_dbs: std::collections::HashSet<String> = c.query("SELECT name FROM system.databases").fetch_all::<String>().await.unwrap_or_default().into_iter().collect();
        let todo = copy_statements(&reference, &have, &have_dbs);
        if todo.is_empty() {
            continue;
        }
        let mut failed = 0;
        for q in &todo {
            if let Err(e) = c.query(q).execute().await {
                failed += 1;
                tracing::warn!("data lake node {}: {}: {e}", n.name, q.lines().next().unwrap_or(""));
            }
        }
        tracing::info!("data lake node {}: {} database(s)/table(s) created, {failed} failed", n.name, todo.len() - failed);
    }
    Ok(())
}

// ---- AI nodes as AI providers (N3) ----

/// How long the list of ready AI nodes is reused before it is read again.
const AI_LIST_FOR: Duration = Duration::from_secs(10);
static AI_NODES: std::sync::Mutex<Option<(std::time::Instant, Vec<siem_ai::Provider>)>> = std::sync::Mutex::new(None);

/// A ready AI node as an AI provider: its Ollama answers OpenAI-style on port 11434 with the model
/// it reported. All nodes share one priority (`PROVIGIL_AI_NODE_PRIORITY`, default 1), so the AI
/// client gives each call to the least busy of them.
pub fn node_provider(name: &str, address: &str, model: &str) -> siem_ai::Provider {
    let priority = std::env::var("PROVIGIL_AI_NODE_PRIORITY").ok().and_then(|p| p.parse().ok()).unwrap_or(1);
    let host = if address.contains(':') { format!("[{address}]") } else { address.to_string() };
    siem_ai::Provider {
        name: format!("node:{name}"),
        provider_type: "openai".into(),
        api_key: String::new(),
        model: model.to_string(),
        base_url: format!("http://{host}:11434"),
        endpoint_path: "/v1/chat/completions".into(),
        priority,
    }
}

/// The ready AI nodes whose model server is up, as AI providers.
pub async fn ai_providers(state: &AppState) -> Vec<siem_ai::Provider> {
    if let Some((t, list)) = AI_NODES.lock().unwrap().as_ref() {
        if t.elapsed() < AI_LIST_FOR {
            return list.clone();
        }
    }
    let t = now();
    let nodes: Vec<NodeRow> = state.db.main().query("SELECT ?fields FROM cluster_nodes FINAL WHERE removed = 0 AND role = 'ai'").fetch_all().await.unwrap_or_default();
    let status: Vec<StatusRow> = if nodes.is_empty() {
        Vec::new()
    } else {
        state.db.main().query("SELECT ?fields FROM cluster_node_status FINAL WHERE at > ?").bind(t - DOWN_AFTER).fetch_all().await.unwrap_or_default()
    };
    let list: Vec<siem_ai::Provider> = nodes
        .iter()
        .filter_map(|n| {
            let d: Value = serde_json::from_str(&status.iter().find(|s| s.id == n.id)?.detail).ok()?;
            let model = d.get("model").and_then(Value::as_str).filter(|m| !m.is_empty())?;
            (d.get("service_up") == Some(&Value::Bool(true))).then(|| node_provider(&n.name, &n.address, model))
        })
        .collect();
    *AI_NODES.lock().unwrap() = Some((std::time::Instant::now(), list.clone()));
    list
}

#[cfg(test)]
mod tests {
    #[test]
    fn data_lake_nodes_pair_up_into_shards_and_never_move() {
        let n = |k: usize| (1..=k).map(|i| (format!("dl{i}"), format!("10.10.10.1{i}"))).collect::<Vec<_>>();
        let sizes = |k: usize| plan(&n(k)).iter().map(|s| s.len()).collect::<Vec<_>>();
        assert_eq!(sizes(1), [1]);
        assert_eq!(sizes(2), [2]);
        assert_eq!(sizes(3), [2, 1]);
        assert_eq!(sizes(4), [2, 2]);
        assert_eq!(sizes(8), [2, 2, 2, 2]);
        // a node keeps its shard and copy name whatever joins after it
        for k in 3..=8 {
            assert_eq!(names(&plan(&n(k)), "dl3"), Some(("02".into(), "dl3".into())));
            assert_eq!(names(&plan(&n(k)), "dl1"), Some(("01".into(), "replica-01".into())), "the installer's names");
        }
    }

    #[test]
    fn a_joined_node_gets_its_missing_tables_with_their_ids_and_distributed_ones_last() {
        let r = |db: &str, n: &str, uuid: &str, q: &str, e: &str| RefTable { database: db.into(), name: n.into(), uuid: uuid.into(), q: q.into(), engine: e.into() };
        let reference = vec![
            r("ndr", "settings", "11111111-2222-3333-4444-555555555555", "CREATE TABLE ndr.settings (`key` String) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/all/ndr/settings', '{replica}') ORDER BY key", "ReplicatedReplacingMergeTree"),
            r("ndr_acme", "siem_alerts", "66666666-2222-3333-4444-555555555555", "CREATE TABLE ndr_acme.siem_alerts (`id` String) ENGINE = Distributed('ndr_cluster', 'ndr_acme', 'siem_alerts_local', rand())", "Distributed"),
            r("ndr", "have_it", "77777777-2222-3333-4444-555555555555", "CREATE TABLE ndr.have_it (`x` UInt8) ENGINE = Memory", "Memory"),
        ];
        let have: std::collections::HashSet<(String, String)> = [("ndr".to_string(), "have_it".to_string())].into();
        let dbs: std::collections::HashSet<String> = ["ndr".to_string()].into();
        let v = copy_statements(&reference, &have, &dbs);
        assert_eq!(v[0], "CREATE DATABASE IF NOT EXISTS `ndr_acme`");
        assert!(v[1].starts_with("CREATE TABLE IF NOT EXISTS ndr.settings UUID '11111111-2222-3333-4444-555555555555' (`key` String)"), "{}", v[1]);
        assert!(v[2].starts_with("CREATE TABLE IF NOT EXISTS ndr_acme.siem_alerts UUID '66666666"), "{}", v[2]);
        assert_eq!(v.len(), 3, "a table the node has is left alone");
    }

    #[test]
    fn a_nodes_settings_name_its_shard_copy_keeper_and_the_whole_cluster() {
        let shards = plan(&[("dl1".into(), "10.0.0.11".into()), ("dl2".into(), "10.0.0.12".into()), ("dl3".into(), "10.0.0.13".into()), ("dl4".into(), "10.0.0.14".into())]);
        let x = layout_xml(&shards, "dl3", "s3cret").unwrap();
        assert!(x.contains("<shard>02</shard>") && x.contains("<replica>dl3</replica>"));
        assert!(x.contains("<node><host>10.0.0.11</host><port>9181</port></node>"), "Keeper on the first node");
        assert!(x.contains("<interserver_http_host>10.0.0.13</interserver_http_host>"));
        assert_eq!(x.matches("<replica><host>").count(), 4);
        assert!(x.contains("<secret>s3cret</secret>") && x.contains("replace=\"replace\""));
        assert!(layout_xml(&shards, "nobody", "s").is_none());
    }

    #[test]
    fn a_sealed_layout_opens_with_the_node_key() {
        use base64::Engine as _;
        let iv = [7u8; 16];
        let (data, mac) = seal("nodekey", "n1", &iv, "<clickhouse/>");
        let key = hex::decode(siem_crypto::hmac_sha256_str("nodekey", "layout\nn1")).unwrap();
        let plain = siem_crypto::decrypt_aes(&base64::engine::general_purpose::STANDARD.decode(&data).unwrap(), &key, &iv).unwrap();
        assert_eq!(plain, b"<clickhouse/>");
        assert_eq!(mac, siem_crypto::hmac_sha256_str("nodekey", &format!("layout-mac\nn1\n{data}")));
    }

    #[test]
    fn an_ai_node_is_an_openai_style_provider_on_its_model_server() {
        let p = node_provider("mac-ai-1", "10.10.10.21", "gpt-oss:20b");
        assert_eq!((p.name.as_str(), p.base_url.as_str(), p.endpoint_path.as_str(), p.model.as_str()), ("node:mac-ai-1", "http://10.10.10.21:11434", "/v1/chat/completions", "gpt-oss:20b"));
        assert_eq!(node_provider("x", "fd00::21", "m").base_url, "http://[fd00::21]:11434");
    }

    use super::*;

    #[test]
    fn hmac_matches_openssl() {
        // printf 'data' | openssl dgst -sha256 -hmac key
        assert_eq!(hmac_sha256_str("key", "data"), "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0");
    }

    #[test]
    fn a_join_is_bound_to_its_token_body_and_time() {
        let body = br#"{"name":"ai-1","role":"ai"}"#;
        let s = join_sig("pvj_a", 100, "n1", body);
        assert_eq!(s.len(), 64);
        assert_ne!(s, join_sig("pvj_b", 100, "n1", body), "another token");
        assert_ne!(s, join_sig("pvj_a", 101, "n1", body), "another time");
        assert_ne!(s, join_sig("pvj_a", 100, "n1", br#"{"name":"ai-1","role":"datalake"}"#), "a changed body");
        assert_ne!(node_secret("pvj_a", "n1"), node_secret("pvj_a", "n2"), "each join its own key");
    }

    #[test]
    fn states() {
        assert_eq!(node_state(None, 100), "joining");
        assert_eq!(node_state(Some(80), 100), "ready");
        assert_eq!(node_state(Some(60), 100), "down");
    }
}
