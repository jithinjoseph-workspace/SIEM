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

const DDL: [&str; 3] = [
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
                    if let Err(e) = state.db.main().query(ddl).execute().await {
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
    let list: Vec<Value> = nodes
        .into_iter()
        .map(|n| {
            let s = status.iter().find(|s| s.id == n.id);
            json!({
                "id": n.id, "name": n.name, "role": n.role, "address": n.address, "platform": n.platform, "version": n.version,
                "cpus": n.cpus, "mem_total": n.mem_total, "disk_total": n.disk_total, "joined": n.joined,
                "state": node_state(s.map(|s| s.at), t), "last_seen": s.map(|s| s.at),
                "mem_used": s.map(|s| s.mem_used), "disk_used": s.map(|s| s.disk_used), "load": s.map(|s| s.load),
                "detail": s.and_then(|s| serde_json::from_str::<Value>(&s.detail).ok()),
            })
        })
        .collect();
    Json(json!({ "nodes": list })).into_response()
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
