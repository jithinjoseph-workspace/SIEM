//! The ProVigil agent's state (inventory, keepalive, labels, group configuration status and OS)
//! written where the old agents' state goes: the manager's agent database
//! (provigil-db: the agent's own SQLite database and its row in global.db). The agent pages,
//! the vulnerability scanner and the compliance audit then read it exactly as before.
//!
//! The agent sends its state as events over HTTPS (`/api/v1/events/ingest`); this module turns
//! them into rows with `agent <id> sql ...` / `global sql ...` (one statement per call, under
//! the database socket's 64 KiB message size). Its file integrity and registry events are
//! turned into the old agents' syscheck messages ([`syscheck_message`]) for the analysis engine.
//! Its file integrity baseline (`fim_state`) goes straight to `fim_entry` ([`store_fim_state`]):
//! a baseline is not a change, so no alert.
//!
//! After its first full send the agent sends changes only: `system_inventory_delta` is applied to
//! the tables, then their counts and hashes are compared with the agent's ([`apply_delta`]); a
//! configuration assessment summary is compared once the analysis engine has handled it
//! ([`watch_sca`]). What differs (a new or wiped database, a lost event) gets a full send.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use siem_ipc::wdbc::{WdbQuery, WdbcSocket, WDBOUTPUT_SIZE, WDB_LOCAL_SOCK};
use tracing::{info, warn};



/// What the caller provides: the database connections and where commands and scans go.
pub trait Host: Send + Sync + 'static {
    /// The manager's home (sockets).
    fn home(&self) -> PathBuf;
    fn wdb(&self) -> &dyn WdbQuery;
    /// The connection of an agent's inventories: a full inventory does not hold up keepalive
    /// writes, and several connections take several agents' inventories at once.
    fn inventory_wdb(&self, _agent_id: &str) -> &dyn WdbQuery {
        self.wdb()
    }
    /// A command for the agent's next keepalive.
    fn queue_command(&self, agent_id: &str, command: Value);
    /// The agent's OS row changed (siem-api keeps a list in memory).
    fn os_changed(&self, _agent_id: &str, _os: &Value) {}
}

static HOST: OnceLock<Arc<dyn Host>> = OnceLock::new();

/// Set once, at start.
pub fn set_host(h: Arc<dyn Host>) {
    let _ = HOST.set(h);
}

fn host() -> &'static dyn Host {
    #[cfg(test)]
    tests::test_host();
    HOST.get().expect("agent_state::set_host at start").as_ref()
}

/// `global sql <statement>` on global.db; whether it was applied.
pub async fn global_sql(sql: &str) -> bool {
    let ok = host().wdb().query(&format!("global sql {sql}")).await.is_ok_and(|r| r.starts_with("ok"));
    if !ok {
        warn!("global.db statement not applied: {}", &sql[..sql.floor_char_boundary(160)]);
    }
    ok
}

/// `global sql <select>`: the rows.
pub async fn global_rows(sql: &str) -> Option<Vec<Value>> {
    let r = host().wdb().query(&format!("global sql {sql}")).await.ok()?;
    serde_json::from_str(r.strip_prefix("ok ")?).ok()
}

/// Whether the id is an agent of this manager (it has a row in global.db).
async fn is_provigil_agent(agent_id: &str) -> bool {
    let Ok(n) = agent_id.parse::<u32>() else { return false };
    host().wdb().query(&format!("global get-agent-info {n}")).await.is_ok_and(|r| r.starts_with("ok [{"))
}

/// Publishes one event on the router topic `wdb-agent-events`, which the vulnerability scanner
/// follows: asks it to re-scan one agent from provigil-db's inventory.
pub fn request_rescan(agent_id: &str, full: bool) -> std::io::Result<()> {
    use std::io::Write;
    let body = json!({ "action": "scanAgent", "agent_info": { "agent_id": agent_id }, "full": full }).to_string();
    // router framing: [u32 size][u32 header size][header "P" = publish][body], little endian
    let mut frame = ((body.len() + 5) as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&1u32.to_le_bytes());
    frame.push(b'P');
    frame.extend_from_slice(body.as_bytes());
    let path = host().home().join("queue/router/wdb-agent-events");
    #[cfg(windows)]
    let mut s = {
        let port: u16 = std::fs::read_to_string(path.with_extension("port"))?.trim().parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::net::TcpStream::connect(("127.0.0.1", port))?
    };
    #[cfg(unix)]
    let mut s = std::os::unix::net::UnixStream::connect(&path)?;
    s.write_all(&frame)
}

/// Rows of one INSERT, at most this many bytes of SQL (the socket takes 64 KiB).
const MAX_SQL: usize = 48 * 1024;
/// Keepalives written to global.db this often.
// the agent's heartbeat interval (the old agents' notify_time): the console's "last seen" stays current
const FLUSH_EVERY: Duration = Duration::from_secs(10);
/// Agents of one global.db statement of the flush.
const FLUSH_CHUNK: usize = 1000;
/// Flushes between rewrites of every agent's node, IP and version (about an hour).
const ROW_REFRESH_FLUSHES: u32 = 360;

/// The agents heard from since the last flush, with the version each reports.
static SEEN: Mutex<BTreeMap<u32, Option<String>>> = Mutex::new(BTreeMap::new());
/// The version last written per agent, with its node and IP.
static WRITTEN: Mutex<BTreeMap<u32, Option<String>>> = Mutex::new(BTreeMap::new());
/// The labels last stored per agent (fingerprint).
static LAST_LABELS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
/// The group configuration status last stored per agent.
static LAST_GROUP_STATUS: Mutex<Option<HashMap<String, bool>>> = Mutex::new(None);
/// The software / OS / hotfix fingerprint each agent was last scanned for vulnerabilities with.
static LAST_SOFTWARE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
/// Checksums of one read: a reply of provigil-db is at most 64 KB.
const CHECKSUM_PAGE: usize = 900;
/// Removed items of one statement.
const GONE_CHUNK: usize = 500;
/// A full send is asked for again after this long at the earliest: what stays different (an
/// agent's bug) costs what an hourly full inventory did, and nothing floods.
const FULL_AGAIN_AFTER: Duration = Duration::from_secs(3600);
/// The full sends asked for: `<agent> <what>` -> when.
static FULL_ASKED: Mutex<BTreeMap<String, Instant>> = Mutex::new(BTreeMap::new());
/// How often the configuration assessment summaries are looked at.
const SCA_WATCH_EVERY: Duration = Duration::from_secs(15);
/// A summary the analysis engine has not handled by then was dropped: the next scan's tells.
const SCA_WATCH_FOR: Duration = Duration::from_secs(600);
/// Summaries sent to the analysis engine: (agent, policy) -> (scan id, hash, when).
type ScaWatch = BTreeMap<(String, String), (i64, String, Instant)>;
static SCA_WATCH: Mutex<ScaWatch> = Mutex::new(BTreeMap::new());

/// A SQL text literal (`'` doubled, NUL removed).
fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\0', "").replace('\'', "''"))
}

fn lit_opt(v: &Value) -> String {
    match v {
        Value::String(s) => lit(s),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => lit(if *b { "yes" } else { "no" }),
        _ => "NULL".into(),
    }
}

fn int(v: &Value) -> String {
    v.as_i64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
        .map(|n| n.to_string())
        .unwrap_or_else(|| "NULL".into())
}

fn checksum(parts: &[&str]) -> String {
    let h = Sha256::digest(parts.join("\u{1}").as_bytes());
    h[..20].iter().map(|b| format!("{b:02x}")).collect()
}

fn agent_key(id: &str) -> Option<String> {
    id.parse::<u32>().ok().map(|n| format!("{n:03}"))
}

async fn exec(wdb: &dyn WdbQuery, id: &str, sql: &str) -> bool {
    let ok = wdb.query(&format!("agent {id} sql {sql}")).await.is_ok_and(|r| r.starts_with("ok "));
    if !ok {
        warn!(
            "agent {id}: statement not applied in provigil-db: {}",
            &sql[..sql.len().min(160)]
        );
    }
    ok
}

/// `INSERT INTO table (cols) VALUES (...), (...)` in statements under the size limit.
async fn insert_rows(wdb: &dyn WdbQuery, id: &str, (_, table, cols): Table, rows: &[String]) -> bool {
    let head = format!("INSERT OR REPLACE INTO {table} ({cols}) VALUES ");
    let mut sql = head.clone();
    let mut ok = true;
    for r in rows {
        if sql.len() > head.len() && sql.len() + r.len() + 2 > MAX_SQL {
            ok &= exec(wdb, id, &sql).await;
            sql = head.clone();
        }
        if sql.len() > head.len() {
            sql.push(',');
        }
        sql.push_str(r);
    }
    if sql.len() > head.len() {
        ok &= exec(wdb, id, &sql).await;
    }
    ok
}

/// Marks inventory / file integrity parts as fully synced: the database only hands a part to
/// its readers (the vulnerability scanner's `package get`, `hotfix get`) once it is.
async fn mark_synced(wdb: &dyn WdbQuery, id: &str, components: &[&str]) {
    let now = Utc::now().timestamp();
    let list = components.iter().map(|c| lit(c)).collect::<Vec<_>>().join(", ");
    exec(wdb, id, &format!("UPDATE sync_info SET last_attempt = {now}, last_completion = {now}, n_attempts = n_attempts + 1, n_completions = n_completions + 1 WHERE component IN ({list})")).await;
}

/// Replaces a table's rows with `rows`.
async fn replace(wdb: &dyn WdbQuery, id: &str, t: Table, rows: &[String]) -> bool {
    exec(wdb, id, &format!("DELETE FROM {}", t.1)).await && insert_rows(wdb, id, t, rows).await
}

/// A keepalive from a ProVigil agent: its global.db row says connected at the next [`flush`];
/// `version` is the one the agent reports (`ProVigil v<version>`).
pub fn keepalive(agent_id: &str, version: Option<&str>) {
    static FLUSHER: Once = Once::new();
    let Ok(n) = agent_id.parse::<u32>() else {
        return;
    };
    let version = version.filter(|v| !v.is_empty() && v.len() <= 32 && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')));
    SEEN.lock().unwrap().insert(n, version.map(str::to_string));
    FLUSHER.call_once(|| {
        tokio::spawn(async {
            let mut flushes = 0u32;
            loop {
                tokio::time::sleep(FLUSH_EVERY).await;
                flushes = flushes.wrapping_add(1);
                // a row re-created behind our back (a restored provigil-db) gets its fields back
                if flushes.is_multiple_of(ROW_REFRESH_FLUSHES) {
                    refresh_rows();
                }
                flush().await;
            }
        });
    });
}

/// Every row gets node, IP and version again at the next flush (a restored provigil-db).
pub fn refresh_rows() {
    WRITTEN.lock().unwrap().clear();
}

/// The version as stored: letters, digits, `.`, `-`, `_`, at most 32 characters.
pub fn clean_version(v: Option<&str>) -> Option<String> {
    v.filter(|v| !v.is_empty() && v.len() <= 32 && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))).map(str::to_string)
}

/// An agent's last keepalive: disconnected at once.
pub async fn stopped(agent_id: &str) {
    let Ok(n) = agent_id.parse::<u32>() else { return };
    let now = Utc::now().timestamp();
    global_sql(&format!("UPDATE agent SET connection_status = 'disconnected', disconnection_time = {now} WHERE id = {n}")).await;
}

/// An agent's row was replaced (enrolled again): what was stored for it is gone with the old row.
pub fn forget(agent_id: &str) {
    let Some(id) = agent_key(agent_id) else { return };
    WRITTEN.lock().unwrap().remove(&id.parse().unwrap_or(0));
    LAST_LABELS.lock().unwrap().get_or_insert_with(HashMap::new).remove(&id);
    LAST_GROUP_STATUS.lock().unwrap().get_or_insert_with(HashMap::new).remove(&id);
}

/// Agents of one tenant sending their file integrity baseline at a time.
pub const FIM_SLOTS: usize = 20;
/// A slot the agent's last `fim_state` batch did not free is freed after this long.
const FIM_SLOT_FOR: Duration = Duration::from_secs(600);
/// The baseline slots given: (tenant, agent) → when.
static FIM_SLOT_HOLDERS: Mutex<BTreeMap<(String, String), Instant>> = Mutex::new(BTreeMap::new());

/// Whether `agent`, asking in its keepalive (`fim_state_wanted`), may send its baseline now: it
/// holds a slot, or gets one of its tenant's free ones. A fleet's baselines then reach provigil-db
/// a few at a time.
pub fn fim_slot(tenant: &str, agent: &str, now: Instant, slots: usize) -> bool {
    let mut held = FIM_SLOT_HOLDERS.lock().unwrap();
    held.retain(|_, since| now.duration_since(*since) < FIM_SLOT_FOR);
    let key = (tenant.to_string(), agent.to_string());
    if held.contains_key(&key) {
        return true;
    }
    if held.keys().filter(|(t, _)| t == tenant).count() >= slots {
        return false;
    }
    held.insert(key, now);
    true
}

/// The agent's last `fim_state` batch arrived: its slot goes to the next agent.
pub fn fim_slot_free(tenant: &str, agent: &str) {
    FIM_SLOT_HOLDERS.lock().unwrap().remove(&(tenant.to_string(), agent.to_string()));
}

fn id_list(ids: &[u32]) -> String {
    ids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
}

fn keepalive_sql(ids: &[u32], now: i64) -> String {
    format!("UPDATE agent SET last_keepalive = {now}, connection_status = 'active', disconnection_time = 0, status_code = 0 WHERE id IN ({})", id_list(ids))
}

/// The node, IP and version the vulnerability scanner requires of an agent it scans.
fn agent_row_sql(version: Option<&str>, ids: &[u32]) -> String {
    let version = match version {
        Some(v) => format!("'ProVigil v{v}'"),
        None => "COALESCE(NULLIF(version, ''), 'ProVigil')".to_string(),
    };
    format!("UPDATE agent SET node_name = COALESCE(NULLIF(node_name, ''), (SELECT node_name FROM agent WHERE id = 0)), ip = COALESCE(NULLIF(ip, ''), NULLIF(register_ip, ''), 'any'), version = {version} WHERE id IN ({})", id_list(ids))
}

/// The seen agents whose version is new or changed, by version.
fn changed_versions(seen: BTreeMap<u32, Option<String>>, written: &BTreeMap<u32, Option<String>>) -> BTreeMap<Option<String>, Vec<u32>> {
    let mut changed: BTreeMap<Option<String>, Vec<u32>> = BTreeMap::new();
    for (id, version) in seen {
        if written.get(&id) != Some(&version) {
            changed.entry(version).or_default().push(id);
        }
    }
    changed
}

/// Writes the keepalives heard since the last flush, in chunks; node, IP and version only for
/// the agents where they changed (kept to try again when the statement fails).
pub async fn flush() {
    let seen = std::mem::take(&mut *SEEN.lock().unwrap());
    flush_seen(seen).await;
}

/// [`flush`] of what the caller collected: agent number -> the version it reports.
pub async fn flush_seen(seen: BTreeMap<u32, Option<String>>) {
    if seen.is_empty() {
        return;
    }
    let now = Utc::now().timestamp();
    let ids: Vec<u32> = seen.keys().copied().collect();
    for chunk in ids.chunks(FLUSH_CHUNK) {
        global_sql(&keepalive_sql(chunk, now)).await;
    }
    let changed = changed_versions(seen, &WRITTEN.lock().unwrap());
    for (version, ids) in changed {
        for chunk in ids.chunks(FLUSH_CHUNK) {
            if global_sql(&agent_row_sql(version.as_deref(), chunk)).await {
                let mut written = WRITTEN.lock().unwrap();
                written.extend(chunk.iter().map(|id| (*id, version.clone())));
            }
        }
    }
}

/// The labels the agent's keepalive carries (`labels: [{key, value, hidden}]`, `agent_ip`),
/// stored where the old agents' go (global.db `labels`, as their keepalive lines: `"key"`,
/// `!"key"` when hidden, `#"_agent_ip"`), so the analysis engine adds them to the agent's
/// alerts. Written only when they changed.
pub async fn labels(agent_id: &str, v: &Value, added: &[(String, String)]) {
    let Some(id) = agent_key(agent_id) else { return };
    let mut rows: Vec<(String, String)> = v["labels"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|l| {
                    let key = l["key"].as_str().filter(|k| !k.is_empty() && !k.contains(['\n', ':']))?;
                    let value = l["value"].as_str().unwrap_or("").replace('\n', " ");
                    Some((format!("{}\"{key}\"", if l["hidden"].as_bool() == Some(true) { "!" } else { "" }), value))
                })
                .collect()
        })
        .unwrap_or_default();
    let ip = v["agent_ip"].as_str().filter(|i| i.parse::<std::net::IpAddr>().is_ok());
    if let Some(ip) = ip {
        rows.push(("#\"_agent_ip\"".into(), ip.to_string()));
    }
    rows.extend(added.iter().map(|(k, v)| (format!("#\"{k}\""), v.clone())));
    let fp = checksum(&rows.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().iter().map(String::as_str).collect::<Vec<_>>());
    if LAST_LABELS.lock().unwrap().get_or_insert_with(HashMap::new).insert(id.clone(), fp.clone()).as_deref() == Some(fp.as_str()) {
        return;
    }
    let n: u32 = id.parse().unwrap_or(0);
    global_sql(&format!("DELETE FROM labels WHERE id = {n}")).await;
    if !rows.is_empty() {
        let values: Vec<String> = rows.iter().map(|(k, v)| format!("({n}, {}, {})", lit(k), lit(v))).collect();
        global_sql(&format!("INSERT INTO labels (id, key, value) VALUES {}", values.join(", "))).await;
    }
    if let Some(ip) = ip {
        global_sql(&format!("UPDATE agent SET ip = {} WHERE id = {n}", lit(ip))).await;
    }
}

/// `group_config_status` in global.db: whether the agent runs its groups' current configuration.
/// The statement, `None` when the status did not change.
fn group_config_sql(agent_id: &str, synced: bool) -> Option<String> {
    let id = agent_key(agent_id)?;
    let n: u32 = id.parse().ok()?;
    if LAST_GROUP_STATUS.lock().unwrap().get_or_insert_with(HashMap::new).insert(id, synced) == Some(synced) {
        return None;
    }
    Some(format!("UPDATE agent SET group_config_status = '{}' WHERE id = {n}", if synced { "synced" } else { "not synced" }))
}

pub async fn group_config(agent_id: &str, synced: bool) {
    if let Some(sql) = group_config_sql(agent_id, synced) {
        global_sql(&sql).await;
    }
}

/// (the agent's `<stem>_after` / `<stem>_before` fields, the attribute the syscheck decoder
/// reads, its `changed_attributes` name)
const FIM_ATTRS: [(&[&str], &str, &str); 9] = [
    (&["size"], "size", "size"),
    (&["permissions", "perm"], "perm", "permission"),
    (&["owner_sid", "uid"], "uid", "uid"),
    (&["owner", "user_name"], "user_name", "user_name"),
    (&["attributes"], "attributes", "attributes"),
    (&["mtime"], "mtime", "mtime"),
    (&["md5"], "hash_md5", "md5"),
    (&["sha1"], "hash_sha1", "sha1"),
    (&["sha256"], "hash_sha256", "sha256"),
];

/// A `fim` / `registry` event of the agent as the old agents' syscheck message
/// (`{"type":"event","data":{...}}`) for the analysis engine's syscheck queue; `None` without a
/// path or a known event.
pub fn syscheck_message(v: &Value) -> Option<String> {
    Some(json!({ "type": "event", "data": syscheck_data(v)? }).to_string())
}

/// The `data` of [`syscheck_message`].
fn syscheck_data(v: &Value) -> Option<Value> {
    let reg = v["event_type"].as_str().or(v["type"].as_str()) == Some("registry");
    let f = if reg { &v["registry"] } else { &v["syscheck"] };
    let path = f[if reg { "key" } else { "path" }].as_str().filter(|p| !p.is_empty())?;
    let event = f["event"].as_str().filter(|e| matches!(*e, "added" | "modified" | "deleted"))?;
    let (mut new, mut old, mut derived) = (Map::new(), Map::new(), Vec::new());
    for (stems, attr, name) in FIM_ATTRS {
        let get = |suffix: &str| stems.iter().find_map(|s| f.get(format!("{s}_{suffix}")).filter(|x| !x.is_null() && x.as_str() != Some("")).cloned());
        let (after, before) = (get("after"), get("before"));
        if after.is_some() && before.is_some() && after != before {
            derived.push(json!(name));
        }
        if let Some(a) = after {
            new.insert(attr.into(), a);
        }
        if let Some(b) = before {
            old.insert(attr.into(), b);
        }
    }
    // a deleted entry is described by its last known state
    if event == "deleted" {
        new = std::mem::take(&mut old);
    }
    let value_name = f["value_name"].as_str().filter(|_| reg);
    let arch = f["arch"].as_str().unwrap_or("[x64]");
    new.insert("type".into(), json!(match (reg, value_name) {
        (false, _) => "file",
        (true, None) => "registry_key",
        (true, Some(_)) => "registry_value",
    }));
    if let Some(t) = f["value_type"].as_str() {
        new.insert("value_type".into(), json!(t));
    }
    new.insert("checksum".into(), json!(checksum(&[path, value_name.unwrap_or(""), &Value::Object(new.clone()).to_string()])));
    let changed: Vec<Value> = match f["changed_attributes"].as_array().filter(|a| !a.is_empty()) {
        Some(a) => a
            .iter()
            .filter_map(|c| c.as_str())
            .map(|c| json!(match c {
                "perm" => "permission",
                "owner" => "uid",
                c => c,
            }))
            .collect(),
        None => derived,
    };
    let who = f["whodata"].as_object();
    // what found the change: the agent's `mode`, else who-data when it says who did it
    let mode = f["mode"].as_str().filter(|m| matches!(*m, "realtime" | "whodata" | "scheduled")).unwrap_or(if who.is_some() { "whodata" } else { "scheduled" });
    let timestamp = v["timestamp"].as_str().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok()).map(|t| t.timestamp()).unwrap_or_else(|| Utc::now().timestamp());
    let mut data = json!({ "path": path, "mode": mode, "type": event, "timestamp": timestamp, "version": if reg { 3 } else { 2 }, "attributes": new });
    if event == "modified" {
        data["old_attributes"] = Value::Object(old);
        if !changed.is_empty() {
            data["changed_attributes"] = json!(changed);
        }
    }
    if let Some(w) = who {
        data["audit"] = Value::Object(w.clone());
    }
    if let Some(d) = f["diff"].as_str() {
        data["content_changes"] = json!(d);
    }
    if reg {
        data["arch"] = json!(arch);
        if let Some(n) = value_name {
            data["value_name"] = json!(n);
        }
        // the entry's key in provigil-db (registry events from version 3 on)
        data["index"] = json!(checksum(&[arch, path, value_name.unwrap_or("")]));
    }
    Some(data)
}

/// The `syscheck save2` payloads of a `fim_state` event: each entry as the syscheck decoder saves
/// that entry when added, so a later change finds the same `full_path` (the path of a file, the
/// index of a registry value). An entry that does not fit a database message is left out.
fn fim_state_rows(v: &Value) -> Vec<String> {
    let row = |e: &Value| {
        let mut f = e.as_object()?.clone();
        f.insert("event".into(), json!("added"));
        let (kind, field) = if f.contains_key("key") { ("registry", "registry") } else { ("fim", "syscheck") };
        let Value::Object(mut d) = syscheck_data(&json!({ "type": kind, "timestamp": v["timestamp"], field: f }))? else { return None };
        for k in ["mode", "type", "content_changes", "audit"] {
            d.remove(k);
        }
        Some(Value::Object(d).to_string()).filter(|r| r.len() < WDBOUTPUT_SIZE - 64)
    };
    v["entries"].as_array().into_iter().flatten().filter_map(row).collect()
}

/// Writes a `fim_state` event; false when provigil-db did not answer (the batch comes again).
/// A row it refuses would be refused again, so that costs only the row.
async fn save_fim_state(wdb: &dyn WdbQuery, id: &str, v: &Value) -> bool {
    let n: u32 = id.parse().unwrap_or(0);
    match wdb.query(&format!("global get-agent-info {n}")).await {
        Ok(r) if r.starts_with("ok [{") => {}
        // not an agent of this manager: no database made for it
        Ok(_) => return true,
        Err(e) => {
            warn!("agent {id}: file integrity baseline not stored: {e}");
            return false;
        }
    }
    for row in fim_state_rows(v) {
        match wdb.query(&format!("agent {id} syscheck save2 {row}")).await {
            Ok(r) if r.starts_with("ok") => {}
            Ok(r) => warn!("agent {id}: file integrity row refused: {r}: {}", &row[..row.floor_char_boundary(160)]),
            Err(e) => {
                warn!("agent {id}: file integrity baseline not stored: {e}");
                return false;
            }
        }
    }
    true
}

/// The agent's `fim_state` event, written to `fim_entry` without the analysis engine. False: to
/// be sent again. On its own connection, so a baseline does not hold up other requests' queries.
pub async fn store_fim_state(agent_id: &str, v: &Value) -> bool {
    static WDB: OnceLock<WdbcSocket> = OnceLock::new();
    let Some(id) = agent_key(agent_id) else {
        return true;
    };
    save_fim_state(WDB.get_or_init(|| WdbcSocket::new(host().home().join(WDB_LOCAL_SOCK))), &id, v).await
}

/// The agent's state events of one batch, written to provigil-db.
pub async fn store(agent_id: &str, items: &[Value]) {
    if !is_provigil_agent(agent_id).await {
        return;
    }
    let Some(id) = agent_key(agent_id) else {
        return;
    };
    // file integrity, registry, configuration checks and rootcheck reach provigil-db through the
    // analysis engine
    for v in items {
        match v["event_type"].as_str().or(v["type"].as_str()) {
            Some("system_inventory") => inventory(&id, v).await,
            Some("system_inventory_delta") => inventory_delta(&id, v).await,
            _ => {}
        }
    }
}

/// (the table's name in a delta event, its provigil-db table, the columns).
type Table = (&'static str, &'static str, &'static str);

const OS: Table = ("os", "sys_osinfo", "scan_id, scan_time, hostname, architecture, os_name, os_version, os_major, os_minor, os_patch, os_build, os_platform, sysname, release, os_display_version, version, checksum, reference");
const HARDWARE: Table = ("hardware", "sys_hwinfo", "scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum");
const PACKAGES: Table = ("packages", "sys_programs", "scan_id, scan_time, format, name, size, vendor, install_time, version, architecture, location, description, checksum, item_id");
const HOTFIXES: Table = ("hotfixes", "sys_hotfixes", "scan_id, scan_time, hotfix, checksum");
const PROCESSES: Table = ("processes", "sys_processes", "scan_id, scan_time, pid, name, ppid, cmd, euser, size, vm_size, priority, nlwp, session, start_time, checksum");
const PORTS: Table = ("ports", "sys_ports", "scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, inode, state, PID, process, checksum");
const NETWORK: Table = ("network", "sys_netiface", "scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, checksum, item_id");
const NET_PROTO: Table = ("", "sys_netproto", "scan_id, iface, type, gateway, dhcp, metric, checksum");
const NET_ADDR: Table = ("", "sys_netaddr", "scan_id, iface, proto, address, netmask, broadcast, checksum");
const SERVICES: Table = ("services", "sys_services", "scan_id, scan_time, service_id, service_name, service_description, service_state, service_start_type, process_user_name, process_pid, file_path, checksum");
const USERS: Table = ("users", "sys_users", "scan_id, scan_time, user_name, user_full_name, user_home, user_uuid, user_groups, user_last_login, login_status, checksum");
const GROUPS: Table = ("groups", "sys_groups", "scan_id, scan_time, group_name, group_uuid, group_description, group_users, checksum");
const EXTENSIONS: Table = ("browser_extensions", "sys_browser_extensions", "scan_id, scan_time, browser_name, user_id, package_name, package_id, package_version, browser_profile_name, package_enabled, checksum, item_id");
/// The tables of a delta event.
const TABLES: [Table; 11] = [OS, HARDWARE, PACKAGES, HOTFIXES, PROCESSES, PORTS, NETWORK, SERVICES, USERS, GROUPS, EXTENSIONS];
/// The OS fields stored, in the order of [`OS`]'s columns.
const OS_FIELDS: [&str; 12] = ["hostname", "architecture", "os_name", "os_version", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "os_display_version"];

fn text(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_string()
}

fn list(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

/// The row's checksum: the item's hash when the agent sent one (what its table hash is made of).
fn row_ck(item: &Value, ck: String) -> String {
    item["_h"].as_str().filter(|h| !h.is_empty()).map_or(ck, str::to_string)
}

fn os_row(scan_id: i64, scan_time: &str, os: &Value) -> String {
    let vals: Vec<String> = OS_FIELDS.iter().map(|k| lit(&text(os, k))).collect();
    let ck = checksum(&OS_FIELDS.iter().map(|k| os[*k].as_str().unwrap_or("")).collect::<Vec<_>>());
    format!("({scan_id}, {scan_time}, {}, {}, {}, '')", vals.join(", "), lit(&text(os, "os_version")), lit(&row_ck(os, ck)))
}

fn hardware_row(scan_id: i64, scan_time: &str, hw: &Value) -> String {
    format!(
        "({scan_id}, {scan_time}, {}, {}, {}, {}, {}, {}, {}, {})",
        lit(hw["board_serial"].as_str().unwrap_or("unknown")),
        lit_opt(&hw["cpu_name"]),
        int(&hw["cpu_cores"]),
        lit_opt(&hw["cpu_mhz"]),
        int(&hw["ram_total_kb"]),
        int(&hw["ram_free_kb"]),
        int(&hw["ram_usage_percent"]),
        lit(&row_ck(hw, checksum(&[&hw.to_string()])))
    )
}

/// One `sys_programs` row; `format` is the package's ecosystem (`win`, `pypi`, `npm`), which
/// the vulnerability scanner matches it in.
fn package_row(scan_id: i64, scan_time: &str, p: &Value) -> String {
    let (name, version, vendor, arch) = (text(p, "name"), text(p, "version"), text(p, "publisher"), text(p, "architecture"));
    let format = p["format"].as_str().filter(|f| !f.is_empty()).unwrap_or("win");
    let location = p["location"].as_str().filter(|l| !l.is_empty()).unwrap_or(" ").to_string();
    let ck = checksum(&[format, &name, &version, &vendor, &arch, &location]);
    format!(
        "({scan_id}, {scan_time}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
        lit(format),
        lit(&name),
        lit_opt(&p["size_bytes"]),
        lit(&vendor),
        lit_opt(&p["install_date"]),
        lit(&version),
        lit(&arch),
        lit(&location),
        lit_opt(&p["description"]),
        lit(&row_ck(p, ck.clone())),
        lit(&ck)
    )
}

fn hotfix_row(scan_id: i64, scan_time: &str, h: &str) -> String {
    format!("({scan_id}, {scan_time}, {}, {})", lit(h), lit(&checksum(&[h])))
}

fn process_row(scan_id: i64, scan_time: &str, p: &Value) -> String {
    let pid = p["pid"].to_string();
    format!(
        "({scan_id}, {scan_time}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
        lit(&pid),
        lit(&text(p, "name")),
        int(&p["parent_pid"]),
        lit_opt(&p["command_line"]),
        lit_opt(&p["owner"]),
        p["memory_mb"].as_u64().map(|m| (m * 1024).to_string()).unwrap_or_else(|| "NULL".into()),
        int(&p["virtual_kb"]),
        int(&p["priority"]),
        int(&p["threads"]),
        int(&p["session_id"]),
        int(&p["start_time"]),
        lit(&row_ck(p, checksum(&[&pid, &text(p, "name")])))
    )
}

/// The full list's port `i`. The table's key is (protocol, local ip, local port, inode): the row
/// number as inode keeps connections on the same local port apart; an item with a hash takes its
/// inode from that, as a row added later has no number that is free.
fn port_row(scan_id: i64, scan_time: &str, i: usize, p: &Value) -> Option<String> {
    let proto = p["protocol"].as_str()?;
    let lip = text(p, "local_ip");
    let lport = p["local_port"].as_u64()?;
    let inode = p["_h"].as_str().and_then(|h| i64::from_str_radix(h.get(..7)?, 16).ok()).unwrap_or(i as i64);
    Some(format!(
        "({scan_id}, {scan_time}, {}, {}, {lport}, {}, {}, {inode}, {}, {}, {}, {})",
        lit(proto),
        lit(&lip),
        lit_opt(&p["remote_ip"]),
        int(&p["remote_port"]),
        lit_opt(&p["state"]),
        int(&p["pid"]),
        lit_opt(&p["process"]),
        lit(&row_ck(p, checksum(&[proto, &lip, &lport.to_string(), &text(p, "remote_ip"), &p["remote_port"].to_string()])))
    ))
}

/// The rows of network interfaces: [`NETWORK`], [`NET_PROTO`] and [`NET_ADDR`].
fn network_rows(scan_id: i64, scan_time: &str, items: &[Value]) -> [Vec<String>; 3] {
    let (mut ifaces, mut protos, mut addrs) = (Vec::new(), Vec::new(), Vec::new());
    for n in items {
        let name = text(n, "name");
        if name.is_empty() {
            continue;
        }
        let has_addr = !list(&n["ipv4"]).is_empty() || !list(&n["ipv6"]).is_empty() || !list(&n["addresses"]).is_empty();
        let state = n["state"].as_str().map(String::from).unwrap_or_else(|| if has_addr { "up".into() } else { "down".into() });
        ifaces.push(format!(
            "({scan_id}, {scan_time}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            lit(&name),
            lit(&name),
            lit(n["type"].as_str().unwrap_or("ethernet")),
            lit(&state),
            n["mtu"].as_u64().filter(|m| *m > 0).map(|m| m.to_string()).unwrap_or_else(|| "NULL".into()),
            lit_opt(&n["mac_address"]),
            int(&n["tx_packets"]),
            int(&n["rx_packets"]),
            int(&n["tx_bytes"]),
            int(&n["rx_bytes"]),
            int(&n["tx_errors"]),
            int(&n["rx_errors"]),
            int(&n["tx_dropped"]),
            int(&n["rx_dropped"]),
            lit(&row_ck(n, checksum(&[&name, &text(n, "mac_address"), &state]))),
            lit(&checksum(&[&name]))
        ));
        // addresses: the detailed list, else the plain IPv4 / IPv6 lists
        let mut found: Vec<(String, String, String, String)> = list(&n["addresses"])
            .iter()
            .filter_map(|a| Some((a["family"].as_str().unwrap_or("ipv4").to_string(), a["address"].as_str()?.to_string(), text(a, "netmask"), text(a, "broadcast"))))
            .collect();
        if found.is_empty() {
            for (fam, key) in [("ipv4", "ipv4"), ("ipv6", "ipv6")] {
                for a in list(&n[key]).iter().filter_map(|x| x.as_str()) {
                    let (addr, mask) = a.split_once('/').unwrap_or((a, ""));
                    found.push((fam.into(), addr.into(), mask.into(), String::new()));
                }
            }
        }
        for fam in ["ipv4", "ipv6"] {
            if !found.iter().any(|a| a.0 == fam) {
                continue;
            }
            let gateway = if fam == "ipv4" { lit_opt(&n["gateway"]) } else { "NULL".into() };
            let dhcp = lit(n["dhcp"].as_str().filter(|d| matches!(*d, "enabled" | "disabled")).unwrap_or("unknown"));
            protos.push(format!("({scan_id}, {}, '{fam}', {gateway}, {dhcp}, {}, {})", lit(&name), int(&n["metric"]), lit(&checksum(&[&name, fam]))));
        }
        for (fam, addr, mask, bcast) in found {
            let opt = |x: &str| if x.is_empty() { "NULL".to_string() } else { lit(x) };
            addrs.push(format!("({scan_id}, {}, '{fam}', {}, {}, {}, {})", lit(&name), lit(&addr), opt(&mask), opt(&bcast), lit(&checksum(&[&name, &fam, &addr]))));
        }
    }
    [ifaces, protos, addrs]
}

fn service_row(scan_id: i64, scan_time: &str, x: &Value) -> String {
    let (name, path) = (text(x, "name"), text(x, "path"));
    format!(
        "({scan_id}, {scan_time}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
        lit(&name),
        lit(&text(x, "display_name")),
        lit_opt(&x["description"]),
        lit(&text(x, "state")),
        lit(&text(x, "startup_type")),
        lit_opt(&x["account"]),
        int(&x["pid"]),
        lit(&path),
        lit(&row_ck(x, checksum(&[&name, &text(x, "state"), &text(x, "startup_type"), &path])))
    )
}

fn user_row(scan_id: i64, scan_time: &str, u: &Value) -> String {
    let name = text(u, "name");
    let groups = list(&u["groups"]).iter().filter_map(|g| g.as_str()).collect::<Vec<_>>().join(",");
    format!(
        "({scan_id}, {scan_time}, {}, {}, {}, {}, {}, {}, {}, {})",
        lit(&name),
        lit_opt(&u["full_name"]),
        lit_opt(&u["home"]),
        lit_opt(&u["sid"]),
        lit(&groups),
        lit_opt(&u["last_logon"]),
        lit(if u["disabled"].as_bool() == Some(true) { "disabled" } else { "enabled" }),
        lit(&row_ck(u, checksum(&[&name, &text(u, "sid"), &groups])))
    )
}

fn group_row(scan_id: i64, scan_time: &str, g: &Value) -> String {
    let members = list(&g["members"]).iter().filter_map(|m| m.as_str()).collect::<Vec<_>>().join(",");
    format!("({scan_id}, {scan_time}, {}, {}, {}, {}, {})", lit(&text(g, "name")), lit_opt(&g["sid"]), lit_opt(&g["description"]), lit(&members), lit(&row_ck(g, checksum(&[&text(g, "name"), &members]))))
}

fn extension_row(scan_id: i64, scan_time: &str, e: &Value) -> String {
    let ck = checksum(&[&text(e, "browser"), &text(e, "user"), &text(e, "profile"), &text(e, "id"), &text(e, "version")]);
    format!(
        "({scan_id}, {scan_time}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
        lit(&text(e, "browser")),
        lit(&text(e, "user")),
        lit(&text(e, "name")),
        lit(&text(e, "id")),
        lit(&text(e, "version")),
        lit(&text(e, "profile")),
        lit(if e["enabled"].as_bool() == Some(false) { "0" } else { "1" }),
        lit(&row_ck(e, ck.clone())),
        lit(&ck)
    )
}

/// The rows of a table's items (not [`NETWORK`]'s, see [`network_rows`]).
fn rows_of(table: Table, scan_id: i64, scan_time: &str, items: &[Value]) -> Vec<String> {
    let named = |key: &'static str| items.iter().filter(move |x| !text(x, key).is_empty());
    match table.0 {
        "os" => items.iter().map(|x| os_row(scan_id, scan_time, x)).collect(),
        "hardware" => items.iter().map(|x| hardware_row(scan_id, scan_time, x)).collect(),
        "packages" => named("name").map(|x| package_row(scan_id, scan_time, x)).collect(),
        "hotfixes" => items.iter().filter_map(|x| x["hotfix"].as_str()).map(|h| hotfix_row(scan_id, scan_time, h)).collect(),
        "processes" => items.iter().map(|x| process_row(scan_id, scan_time, x)).collect(),
        "ports" => items.iter().enumerate().filter_map(|(i, x)| port_row(scan_id, scan_time, i, x)).collect(),
        "services" => named("name").map(|x| service_row(scan_id, scan_time, x)).collect(),
        "users" => named("name").map(|x| user_row(scan_id, scan_time, x)).collect(),
        "groups" => named("name").map(|x| group_row(scan_id, scan_time, x)).collect(),
        "browser_extensions" => named("id").map(|x| extension_row(scan_id, scan_time, x)).collect(),
        _ => Vec::new(),
    }
}

/// The agent's row: OS and version, as the console's agent list shows them.
async fn agent_os(id: &str, os: &Value) {
    let n: u32 = id.parse().unwrap_or(0);
    global_sql(&format!(
        "UPDATE agent SET os_name = {}, os_version = {}, os_major = {}, os_minor = {}, os_build = {}, os_platform = 'windows', os_arch = {}, os_codename = {} WHERE id = {n}",
        lit(&text(os, "os_name")),
        lit(&text(os, "os_version")),
        lit(&text(os, "os_major")),
        lit(&text(os, "os_minor")),
        lit(&text(os, "os_build")),
        lit(&text(os, "architecture")),
        lit(&text(os, "os_display_version"))
    ))
    .await;
    host().os_changed(id, os);
}

/// A full `system_inventory` into the tables; the number of packages and updates.
async fn store_inventory(wdb: &dyn WdbQuery, id: &str, v: &Value, inv: &Value) -> (usize, usize) {
    let now = Utc::now();
    let scan_id = now.timestamp();
    let scan_time = lit(&now.format("%Y/%m/%d %H:%M:%S").to_string());
    let os = &v["os_info"];
    // an agent build without the OS fields leaves the stored OS and updates alone
    let has_os = os.get("os_name").and_then(|v| v.as_str()).is_some_and(|n| !n.is_empty());

    if has_os {
        replace(wdb, id, OS, &[os_row(scan_id, &scan_time, os)]).await;
    }

    // hardware: the detailed object when the agent sends it
    let hw = &inv["hardware"];
    let row = if hw.is_object() {
        hardware_row(scan_id, &scan_time, hw)
    } else {
        let ram_kb = inv["ram_mb"].as_u64().unwrap_or(0) * 1024;
        format!("({scan_id}, {scan_time}, 'unknown', NULL, {}, NULL, {ram_kb}, NULL, NULL, {})", int(&inv["cpu_cores"]), lit(&checksum(&[&inv["cpu_cores"].to_string(), &ram_kb.to_string()])))
    };
    replace(wdb, id, HARDWARE, &[row]).await;

    let pkgs = rows_of(PACKAGES, scan_id, &scan_time, &list(&inv["packages"]));
    replace(wdb, id, PACKAGES, &pkgs).await;

    // installed updates
    let hotfixes: Vec<String> = list(&v["hotfixes"]).iter().filter_map(|h| h.as_str()).map(|h| hotfix_row(scan_id, &scan_time, h)).collect();
    if has_os {
        replace(wdb, id, HOTFIXES, &hotfixes).await;
    }

    replace(wdb, id, PROCESSES, &rows_of(PROCESSES, scan_id, &scan_time, &list(&inv["processes"]))).await;

    // ports: the full list (TCP / UDP, both sides, PID, process) when the agent sends it
    let ports: Vec<String> = if inv["ports"].is_array() {
        rows_of(PORTS, scan_id, &scan_time, &list(&inv["ports"]))
    } else {
        // "0.0.0.0:135" / "[::]:445": listening TCP only
        list(&inv["listening_ports"])
            .iter()
            .filter_map(|p| p.as_str())
            .enumerate()
            .filter_map(|(i, p)| {
                let (ip, port) = p.rsplit_once(':')?;
                let port: u32 = port.parse().ok()?;
                let ip = ip.trim_matches(['[', ']']);
                let proto = if ip.contains(':') { "tcp6" } else { "tcp" };
                Some(format!("({scan_id}, {scan_time}, '{proto}', {}, {port}, NULL, NULL, {i}, 'listening', NULL, NULL, {})", lit(ip), lit(&checksum(&[proto, ip, &port.to_string()]))))
            })
            .collect()
    };
    replace(wdb, id, PORTS, &ports).await;

    // network interfaces, their settings and addresses
    let [ifaces, protos, addrs] = network_rows(scan_id, &scan_time, &list(&inv["network_interfaces"]));
    replace(wdb, id, NETWORK, &ifaces).await;
    replace(wdb, id, NET_PROTO, &protos).await;
    replace(wdb, id, NET_ADDR, &addrs).await;

    replace(wdb, id, SERVICES, &rows_of(SERVICES, scan_id, &scan_time, &list(&inv["services"]))).await;

    // users: the detailed list when the agent sends it, else the names
    let users: Vec<String> = if inv["users"].is_array() {
        rows_of(USERS, scan_id, &scan_time, &list(&inv["users"]))
    } else {
        list(&inv["local_users"]).iter().filter_map(|u| u.as_str()).map(|u| format!("({scan_id}, {scan_time}, {}, NULL, NULL, NULL, NULL, NULL, NULL, {})", lit(u), lit(&checksum(&[u])))).collect()
    };
    replace(wdb, id, USERS, &users).await;

    if inv["groups"].is_array() {
        replace(wdb, id, GROUPS, &rows_of(GROUPS, scan_id, &scan_time, &list(&inv["groups"]))).await;
    }
    if inv["browser_extensions"].is_array() {
        replace(wdb, id, EXTENSIONS, &rows_of(EXTENSIONS, scan_id, &scan_time, &list(&inv["browser_extensions"]))).await;
    }

    let mut parts = vec!["syscollector-hwinfo", "syscollector-packages", "syscollector-processes", "syscollector-ports", "syscollector-netinfo", "syscollector-netproto", "syscollector-netaddress", "syscollector-services", "syscollector-users"];
    if has_os {
        parts.extend(["syscollector-osinfo", "syscollector-hotfixes"]);
    }
    if inv["groups"].is_array() {
        parts.push("syscollector-groups");
    }
    if inv["browser_extensions"].is_array() {
        parts.push("syscollector-browser-extensions");
    }
    mark_synced(wdb, id, &parts).await;
    (pkgs.len(), hotfixes.len())
}

async fn inventory(id: &str, v: &Value) {
    let Some(inv) = v["inventory_json"].as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()) else { return };
    let (pkgs, hotfixes) = store_inventory(host().inventory_wdb(id), id, v, &inv).await;
    let os = &v["os_info"];
    if os.get("os_name").and_then(|v| v.as_str()).is_some_and(|n| !n.is_empty()) {
        agent_os(id, os).await;
    }

    // a new or changed software list: the vulnerability scanner looks at the agent again
    let fp = checksum(&[&pkgs.to_string(), &os.to_string(), &v["hotfixes"].to_string(), &inv["packages"].to_string()]);
    let changed = LAST_SOFTWARE.lock().unwrap().get_or_insert_with(HashMap::new).insert(id.to_string(), fp.clone()).as_deref() != Some(fp.as_str());
    if changed {
        match request_rescan(id, false) {
            Ok(()) => info!("agent {id}: inventory stored ({pkgs} packages, {hotfixes} updates); vulnerability scan requested"),
            Err(e) => warn!("agent {id}: inventory stored; vulnerability scan not requested: {e}"),
        }
    }
}

/// A table's row checksums in sorted order; `None` when provigil-db did not answer.
async fn checksums(wdb: &dyn WdbQuery, id: &str, table: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    loop {
        let r = wdb.query(&format!("agent {id} sql SELECT checksum FROM {table} ORDER BY checksum LIMIT {CHECKSUM_PAGE} OFFSET {}", out.len())).await.ok()?;
        let rows: Vec<Value> = serde_json::from_str(r.strip_prefix("ok ")?).ok()?;
        out.extend(rows.iter().map(|x| text(x, "checksum")));
        if rows.len() < CHECKSUM_PAGE {
            return Some(out);
        }
    }
}

/// Applies a `system_inventory_delta`: whether packages, updates or the OS changed, and whether
/// the tables then have the agent's counts and hashes (`None`: not known).
async fn apply_delta(wdb: &dyn WdbQuery, id: &str, v: &Value) -> (bool, Option<bool>) {
    let now = Utc::now();
    let scan_id = now.timestamp();
    let scan_time = lit(&now.format("%Y/%m/%d %H:%M:%S").to_string());
    let delta = &v["tables"];
    let mut software = false;
    for table @ (name, sql_table, _) in TABLES {
        let t = &delta[name];
        let new: Vec<Value> = list(&t["added"]).into_iter().chain(list(&t["changed"])).collect();
        let gone: Vec<String> = list(&t["removed"]).iter().filter_map(|h| h.as_str()).map(lit).chain(list(&t["changed"]).iter().filter_map(|i| i["_was"].as_str()).map(lit)).collect();
        software |= matches!(name, "packages" | "hotfixes" | "os") && !(new.is_empty() && gone.is_empty());
        // and the new items' own: a batch sent again must not add them twice under a new scan id
        let gone: Vec<String> = gone.into_iter().chain(new.iter().filter_map(|i| i["_h"].as_str()).map(lit)).collect();
        for chunk in gone.chunks(GONE_CHUNK) {
            let hashes = chunk.join(", ");
            if table == NETWORK {
                let names = format!("(SELECT name FROM sys_netiface WHERE checksum IN ({hashes}))");
                exec(wdb, id, &format!("DELETE FROM sys_netproto WHERE iface IN {names}")).await;
                exec(wdb, id, &format!("DELETE FROM sys_netaddr WHERE iface IN {names}")).await;
            }
            exec(wdb, id, &format!("DELETE FROM {sql_table} WHERE checksum IN ({hashes})")).await;
        }
        if table == NETWORK {
            let [ifaces, protos, addrs] = network_rows(scan_id, &scan_time, &new);
            insert_rows(wdb, id, NETWORK, &ifaces).await;
            insert_rows(wdb, id, NET_PROTO, &protos).await;
            insert_rows(wdb, id, NET_ADDR, &addrs).await;
        } else {
            insert_rows(wdb, id, table, &rows_of(table, scan_id, &scan_time, &new)).await;
        }
    }
    for (name, sql_table, _) in TABLES {
        let t = &delta[name];
        if !t.is_object() {
            continue;
        }
        let Some(rows) = checksums(wdb, id, sql_table).await else { return (software, None) };
        let refs: Vec<&str> = rows.iter().map(String::as_str).collect();
        if t["count"].as_u64() != Some(rows.len() as u64) || t["hash"].as_str() != Some(checksum(&refs).as_str()) {
            warn!("agent {id}: {name} differ from the agent's ({} rows, the agent {})", rows.len(), t["count"]);
            return (software, Some(false));
        }
    }
    (software, Some(true))
}

async fn inventory_delta(id: &str, v: &Value) {
    store_delta(host().inventory_wdb(id), id, v).await;
    let os = &v["tables"]["os"];
    if let Some(os) = list(&os["added"]).first().or(list(&os["changed"]).first()) {
        agent_os(id, os).await;
    }
}

/// [`apply_delta`], and what follows from it: a full send, or a vulnerability scan.
async fn store_delta(wdb: &dyn WdbQuery, id: &str, v: &Value) {
    let (software, same) = apply_delta(wdb, id, v).await;
    if same == Some(false) {
        // the full send asked for here gets its vulnerability scan, also with the same software
        LAST_SOFTWARE.lock().unwrap().get_or_insert_with(HashMap::new).remove(id);
        ask_full(id, "inventory", json!({ "command_id": uuid::Uuid::new_v4().to_string(), "type": "inventory_full" }));
    } else if software {
        match request_rescan(id, false) {
            Ok(()) => info!("agent {id}: software changed; vulnerability scan requested"),
            Err(e) => warn!("agent {id}: software changed; vulnerability scan not requested: {e}"),
        }
    }
}

/// Queues a full send, unless one was asked for within [`FULL_AGAIN_AFTER`].
fn ask_full(id: &str, what: &str, command: Value) {
    let now = Instant::now();
    let mut asked = FULL_ASKED.lock().unwrap();
    asked.retain(|_, at| now.duration_since(*at) < FULL_AGAIN_AFTER);
    let key = format!("{id} {what}");
    if let std::collections::btree_map::Entry::Vacant(e) = asked.entry(key) {
        info!("agent {id}: full send of {what} asked for");
        e.insert(now);
        host().queue_command(id, command);
    }
}

/// The analysis engine's request for a dump goes to remoted's queue, which reaches only agents
/// connected to remoted. So siem-api checks the summaries of its own agents: `events` are a batch
/// of the agent's on their way to the engine.
pub fn watch_sca(agent_id: &str, events: &[Value]) {
    static WATCHER: Once = Once::new();
    let Some(id) = agent_key(agent_id) else { return };
    let summaries = events.iter().filter(|e| e["event_type"] == "sca").filter_map(|e| serde_json::from_str::<Value>(e["message"].as_str()?).ok()).filter(|m| m["type"] == "summary");
    let mut watch = SCA_WATCH.lock().unwrap();
    for m in summaries {
        // it goes into provigil-db queries as text
        let policy = m["policy_id"].as_str().filter(|p| !p.is_empty() && p.len() <= 128 && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')));
        if let (Some(policy), Some(scan_id), Some(hash)) = (policy, m["scan_id"].as_i64(), m["hash"].as_str()) {
            watch.insert((id.clone(), policy.to_string()), (scan_id, hash.to_string(), Instant::now()));
        }
    }
    if !watch.is_empty() {
        WATCHER.call_once(|| {
            tokio::spawn(async {
                loop {
                    tokio::time::sleep(SCA_WATCH_EVERY).await;
                    check_sca(host().wdb(), Instant::now()).await;
                }
            });
        });
    }
}

/// Whether the agent's results are in provigil-db, once the engine has handled this summary
/// (`None`: not yet, or no answer). It stores the summary after the checks that came before it.
async fn sca_in_sync(wdb: &dyn WdbQuery, id: &str, policy: &str, scan_id: i64, hash: &str) -> Option<bool> {
    let r = wdb.query(&format!("agent {id} sql SELECT id FROM sca_scan_info WHERE policy_id = {}", lit(policy))).await.ok()?;
    let rows: Vec<Value> = serde_json::from_str(r.strip_prefix("ok ")?).ok()?;
    if rows.first()?["id"].as_i64() != Some(scan_id) {
        return None;
    }
    let r = wdb.query(&format!("agent {id} sca query_results {policy}")).await.ok()?;
    r.starts_with("ok").then(|| r.strip_prefix("ok found ") == Some(hash))
}

/// The summaries watched: those the engine has handled are compared, a difference gets a full
/// send of the policy.
async fn check_sca(wdb: &dyn WdbQuery, now: Instant) {
    let watched: Vec<_> = SCA_WATCH.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for ((id, policy), (scan_id, hash, since)) in watched {
        let same = sca_in_sync(wdb, &id, &policy, scan_id, &hash).await;
        if same.is_none() && now.duration_since(since) < SCA_WATCH_FOR {
            continue;
        }
        if same == Some(false) {
            ask_full(&id, &policy, json!({ "command_id": uuid::Uuid::new_v4().to_string(), "type": "sca_full", "policy_id": policy }));
        }
        let mut watch = SCA_WATCH.lock().unwrap();
        // a newer summary stays
        if watch.get(&(id.clone(), policy.clone())).is_some_and(|w| w.0 == scan_id) {
            watch.remove(&(id, policy));
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Commands queued, by agent; these tests pass their own database.
    #[derive(Default)]
    pub(super) struct TestHost(Mutex<BTreeMap<String, Vec<Value>>>);

    static TEST_HOST: OnceLock<Arc<TestHost>> = OnceLock::new();

    fn take_commands(id: &str) -> Vec<Value> {
        test_host().0.lock().unwrap().remove(&format!("{:03}", id.parse::<u32>().unwrap())).unwrap_or_default()
    }

    pub(super) fn test_host() -> Arc<TestHost> {
        TEST_HOST.get_or_init(|| {
            let h = Arc::new(TestHost::default());
            set_host(Arc::new(Forward(h.clone())));
            h
        }).clone()
    }

    struct Forward(Arc<TestHost>);

    impl Host for Forward {
        fn home(&self) -> PathBuf {
            std::env::temp_dir()
        }
        fn wdb(&self) -> &dyn WdbQuery {
            unreachable!("these tests pass their own database")
        }
        fn queue_command(&self, agent_id: &str, command: Value) {
            self.0.0.lock().unwrap().entry(format!("{:03}", agent_id.parse::<u32>().unwrap())).or_default().push(command);
        }
    }

    #[test]
    fn fim_slots_per_tenant() {
        let t0 = Instant::now();
        for a in 0..FIM_SLOTS {
            assert!(fim_slot("slot-a", &a.to_string(), t0, FIM_SLOTS));
        }
        assert!(!fim_slot("slot-a", "late", t0, FIM_SLOTS), "the tenant's slots are taken");
        assert!(fim_slot("slot-b", "1", t0, FIM_SLOTS), "another tenant has its own");
        assert!(fim_slot("slot-a", "3", t0 + Duration::from_secs(60), FIM_SLOTS), "a holder keeps its slot");
        fim_slot_free("slot-a", "3");
        assert!(fim_slot("slot-a", "late", t0 + Duration::from_secs(60), FIM_SLOTS), "freed by the last batch");
        assert!(!fim_slot("slot-a", "later", t0 + Duration::from_secs(60), FIM_SLOTS));
        assert!(fim_slot("slot-a", "later", t0 + FIM_SLOT_FOR, FIM_SLOTS), "freed after 10 minutes");
    }

    #[test]
    fn literals() {
        assert_eq!(lit("it's"), "'it''s'");
        assert_eq!(lit("a\0b"), "'ab'");
        assert_eq!(lit_opt(&Value::Null), "NULL");
        assert_eq!(int(&serde_json::json!("12")), "12");
        assert_eq!(checksum(&["a"]).len(), 40);
    }

    /// What the syscheck decoder requires of a message (siem-analysisd `decode_json` /
    /// `process_alert`): `type` "event", an object `data` with string `path` and `type`, an
    /// `attributes` object with a known `type`, `index` on registry events of version 3.
    fn decoder_accepts(m: &str) -> Value {
        let m: Value = serde_json::from_str(m).unwrap();
        assert_eq!(m["type"], "event");
        let d = m["data"].clone();
        assert!(d["path"].is_string());
        assert!(matches!(d["type"].as_str(), Some("added" | "modified" | "deleted")));
        let et = d["attributes"]["type"].as_str().unwrap();
        assert!(matches!(et, "file" | "registry_key" | "registry_value"));
        if et != "file" {
            assert!(d["version"].as_i64() >= Some(3) && d["index"].is_string());
        }
        assert!(d["timestamp"].is_i64() && d["attributes"]["checksum"].is_string(), "provigil-db save2 needs them");
        for k in ["size", "mtime"] {
            assert!(d["attributes"].get(k).is_none_or(Value::is_number));
        }
        d
    }

    #[test]
    fn fim_and_registry_to_syscheck_messages() {
        let added = json!({ "type": "fim", "timestamp": "2026-11-04T10:00:00Z", "syscheck": { "path": "C:\\Data\\a.txt", "event": "added", "size_after": 11, "sha256_after": "aa" } });
        let d = decoder_accepts(&syscheck_message(&added).unwrap());
        assert_eq!((d["attributes"]["type"].as_str(), d["attributes"]["size"].as_u64(), d["attributes"]["hash_sha256"].as_str()), (Some("file"), Some(11), Some("aa")));
        assert_eq!((d["mode"].as_str(), d["timestamp"].as_i64()), (Some("scheduled"), Some(1_793_786_400)));

        // the attributes the agent adds (owner, permissions, md5 / sha1, mtime) and who changed it
        let modified = json!({ "type": "fim", "syscheck": { "path": "C:\\Data\\a.txt", "event": "modified", "size_before": 11, "size_after": 12, "sha256_before": "aa", "sha256_after": "bb",
            "md5_after": "m2", "md5_before": "m1", "owner_sid_after": "S-1-5-18", "owner_after": "SYSTEM", "permissions_after": "D:(A;;FA;;;SY)", "sha1_after": "", "sha1_before": "", "mtime_after": 1700000000, "diff": "1c1\n< a\n---\n> b",
            "whodata": { "user_name": "bob", "user_id": "S-1-5-21-1", "process_name": "C:\\Windows\\notepad.exe", "process_id": 42, "access_mask": 2 } } });
        let d = decoder_accepts(&syscheck_message(&modified).unwrap());
        assert_eq!(d["changed_attributes"], json!(["size", "md5", "sha256"]));
        assert_eq!((d["old_attributes"]["size"].as_u64(), d["attributes"]["uid"].as_str(), d["attributes"]["user_name"].as_str(), d["attributes"]["perm"].as_str()), (Some(11), Some("S-1-5-18"), Some("SYSTEM"), Some("D:(A;;FA;;;SY)")));
        assert!(d["attributes"].get("hash_sha1").is_none(), "a field the agent could not read is left out");
        assert_eq!((d["mode"].as_str(), d["audit"]["process_id"].as_u64(), d["content_changes"].as_str()), (Some("whodata"), Some(42), Some("1c1\n< a\n---\n> b")));

        let deleted = json!({ "type": "fim", "syscheck": { "path": "C:\\Data\\a.txt", "event": "deleted", "size_before": 12, "sha256_before": "bb", "mode": "realtime" } });
        let d = decoder_accepts(&syscheck_message(&deleted).unwrap());
        assert_eq!(d["attributes"]["hash_sha256"], "bb", "a deletion carries the last known state");
        assert!(d.get("old_attributes").is_none());
        assert_eq!(d["mode"], "realtime");
        let odd = json!({ "type": "fim", "syscheck": { "path": "C:\\x", "event": "added", "mode": "other" } });
        assert_eq!(decoder_accepts(&syscheck_message(&odd).unwrap())["mode"], "scheduled", "an unknown mode is not passed on");

        let value = json!({ "type": "registry", "registry": { "key": "HKEY_LOCAL_MACHINE\\Software\\Run", "arch": "[x32]", "event": "modified", "value_name": "Updater", "value_type": "REG_SZ",
            "size_after": 8, "sha256_after": "s2", "sha256_before": "s1", "changed_attributes": ["size", "sha256"] } });
        let d = decoder_accepts(&syscheck_message(&value).unwrap());
        assert_eq!((d["attributes"]["type"].as_str(), d["arch"].as_str(), d["value_name"].as_str(), d["attributes"]["value_type"].as_str()), (Some("registry_value"), Some("[x32]"), Some("Updater"), Some("REG_SZ")));
        assert_eq!(d["changed_attributes"], json!(["size", "sha256"]));

        // a key's permissions changed; its deletion has the same index (provigil-db deletes by it)
        let key = json!({ "type": "registry", "registry": { "key": "HKEY_LOCAL_MACHINE\\Software\\Run", "arch": "[x64]", "event": "modified", "changed_attributes": ["owner", "perm"] } });
        let d = decoder_accepts(&syscheck_message(&key).unwrap());
        assert_eq!((d["attributes"]["type"].as_str(), d["changed_attributes"].clone()), (Some("registry_key"), json!(["uid", "permission"])));
        let gone = json!({ "type": "registry", "registry": { "key": "HKEY_LOCAL_MACHINE\\Software\\Run", "arch": "[x64]", "event": "deleted", "changed_attributes": [] } });
        assert_eq!(decoder_accepts(&syscheck_message(&gone).unwrap())["index"], d["index"]);

        assert!(syscheck_message(&json!({ "type": "fim", "syscheck": { "event": "added" } })).is_none());
        assert!(syscheck_message(&json!({ "type": "fim", "syscheck": { "path": "C:\\x", "event": "renamed" } })).is_none());
    }

    /// Stands in for provigil-db, keeping the queries; not answering from query `down` on.
    struct FakeDb {
        queries: Mutex<Vec<String>>,
        down: usize,
        agent: bool,
    }

    impl FakeDb {
        fn new(down: usize, agent: bool) -> Self {
            Self { queries: Mutex::default(), down, agent }
        }
    }

    #[tonic::async_trait]
    impl WdbQuery for FakeDb {
        async fn query(&self, query: &str) -> Result<String, siem_ipc::wdbc::WdbcError> {
            let mut q = self.queries.lock().unwrap();
            if q.len() >= self.down {
                return Err(siem_ipc::wdbc::WdbcError::Connect("down".into()));
            }
            q.push(query.to_string());
            Ok(if query.starts_with("global") && !self.agent {
                "ok []"
            } else if query.contains("refused") {
                "err Cannot save Syscheck"
            } else {
                "ok [{}]"
            }
            .to_string())
        }
    }

    fn fim_state() -> Value {
        json!({ "event_type": "fim_state", "timestamp": "2026-11-04T10:00:00Z", "agent": { "id": "7" }, "entries": [
            { "path": "C:\\Data\\a.txt", "size_after": 11, "sha256_after": "aa", "md5_after": "m", "sha1_after": "", "mtime_after": 1700000000, "owner_after": "SYSTEM", "owner_sid_after": "S-1-5-18", "permissions_after": "D:(A;;FA;;;SY)", "attributes_after": "ARCHIVE" },
            { "key": "HKEY_LOCAL_MACHINE\\Software\\Run", "arch": "[x32]", "event": "added", "changed_attributes": [], "value_name": "Updater", "value_type": "REG_SZ", "size_after": 8, "sha256_after": "s1", "value": "" },
            "not an object", { "size_after": 1 },
        ] })
    }

    /// What the decoder gives `syscheck save2` for a message (siem-analysisd `decode_json`).
    fn decoder_row(event: Value) -> Value {
        let mut m: Value = serde_json::from_str(&syscheck_message(&event).unwrap()).unwrap();
        let d = m["data"].as_object_mut().unwrap();
        for k in ["mode", "type", "tags", "content_changes", "changed_attributes", "hard_links", "old_attributes", "audit"] {
            d.remove(k);
        }
        Value::Object(d.clone())
    }

    fn changes() -> [Value; 2] {
        [
            json!({ "type": "fim", "syscheck": { "path": "C:\\Data\\a.txt", "event": "modified", "size_before": 11, "size_after": 12, "sha256_before": "aa", "sha256_after": "bb" } }),
            json!({ "type": "registry", "registry": { "key": "HKEY_LOCAL_MACHINE\\Software\\Run", "arch": "[x32]", "event": "modified", "value_name": "Updater", "value_type": "REG_SZ", "size_after": 9, "sha256_before": "s1", "sha256_after": "bb" } }),
        ]
    }

    /// The row the decoder writes for the entry added; and the same key as the change events
    /// that follow (provigil-db's key: `path` of a file, `index` of a registry value).
    #[test]
    fn fim_state_rows_are_the_decoders_rows() {
        let rows: Vec<Value> = fim_state_rows(&fim_state()).iter().map(|r| serde_json::from_str(r).unwrap()).collect();
        assert_eq!(rows.len(), 2, "what is no entry is left out");
        let (e, at) = (fim_state(), "2026-11-04T10:00:00Z");
        let mut file = e["entries"][0].clone();
        file["event"] = json!("added");
        assert_eq!(rows[0], decoder_row(json!({ "type": "fim", "timestamp": at, "syscheck": file })));
        let mut value = e["entries"][1].clone();
        value["event"] = json!("added");
        assert_eq!(rows[1], decoder_row(json!({ "event_type": "registry", "timestamp": at, "registry": value })));
        let a = &rows[0]["attributes"];
        assert_eq!((a["type"].as_str(), a["hash_sha256"].as_str(), a["uid"].as_str(), a["user_name"].as_str(), a["perm"].as_str()), (Some("file"), Some("aa"), Some("S-1-5-18"), Some("SYSTEM"), Some("D:(A;;FA;;;SY)")));

        let [file, value] = changes().map(decoder_row);
        assert_eq!(file["path"], rows[0]["path"]);
        assert_eq!((&value["index"], &value["version"], &value["arch"], &value["value_name"]), (&rows[1]["index"], &json!(3), &rows[1]["arch"], &rows[1]["value_name"]));
    }

    #[test]
    fn fim_state_row_too_long_for_the_database_left_out() {
        let v = json!({ "entries": [{ "path": "C:\\a", "permissions_after": "x".repeat(WDBOUTPUT_SIZE) }, { "path": "C:\\b" }] });
        assert_eq!(fim_state_rows(&v).len(), 1);
        assert!(fim_state_rows(&json!({ "entries": "none" })).is_empty());
    }

    #[tokio::test]
    async fn fim_state_goes_to_save2_only() {
        let db = FakeDb::new(usize::MAX, true);
        assert!(save_fim_state(&db, "007", &fim_state()).await);
        let q = db.queries.lock().unwrap();
        assert_eq!(q.len(), 3);
        assert_eq!(q[0], "global get-agent-info 7");
        assert!(q[1..].iter().all(|q| q.starts_with("agent 007 syscheck save2 {")), "{q:?}");
    }

    #[tokio::test]
    async fn fim_state_retry_rules() {
        for down in [0, 1, 2] {
            assert!(!save_fim_state(&FakeDb::new(down, true), "007", &fim_state()).await, "no answer from query {down}: the batch comes again");
        }
        // an id of no agent gets no database, and is no reason to send again
        let db = FakeDb::new(usize::MAX, false);
        assert!(save_fim_state(&db, "007", &fim_state()).await);
        assert_eq!(db.queries.lock().unwrap().len(), 1);
        // a refused row costs only that row
        let db = FakeDb::new(usize::MAX, true);
        assert!(save_fim_state(&db, "007", &json!({ "entries": [{ "path": "C:\\refused" }, { "path": "C:\\b" }] })).await);
        assert_eq!(db.queries.lock().unwrap().len(), 3);
        assert!(store_fim_state("no-number", &fim_state()).await, "not a database query at all");
    }

    /// Against a private provigil-db (never the running one): `PROVIGIL_TEST_DB_HOME` is its home.
    /// Writes a 27,000-row baseline, reports the rate, then two change events' rows: they update.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn fim_state_on_provigil_db() {
        let home = std::env::var("PROVIGIL_TEST_DB_HOME").expect("PROVIGIL_TEST_DB_HOME");
        let sock = || WdbcSocket::new(std::path::Path::new(&home).join(WDB_LOCAL_SOCK));
        let wdb = sock();
        let batch = |agent: u32, b: u32| {
            let sddl = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;S-1-15-2-1)";
            let entries: Vec<Value> = (0..200)
                .map(|i| {
                    let h = format!("{:064x}", b * 1000 + i);
                    if i % 2 == 0 {
                        json!({ "path": format!("C:\\Windows\\System32\\drivers\\etc\\{agent}-{b}-{i}.dll"), "size_after": 4096, "sha256_after": h, "md5_after": h[..32], "sha1_after": h[..40], "mtime_after": 1700000000, "owner_after": "BUILTIN\\Administrators", "owner_sid_after": "S-1-5-32-544", "permissions_after": sddl, "attributes_after": "ARCHIVE" })
                    } else {
                        json!({ "key": format!("HKEY_LOCAL_MACHINE\\Software\\Vendor\\{b}"), "arch": "[x64]", "event": "added", "changed_attributes": [], "value_name": format!("Value{i}"), "value_type": "REG_SZ", "size_after": 40, "sha256_after": h, "value": "" })
                    }
                })
                .collect();
            json!({ "event_type": "fim_state", "timestamp": "2026-11-04T10:00:00Z", "entries": entries })
        };
        let enroll = |n: u32| format!("global insert-agent {}", json!({ "id": n, "name": format!("bench-{n}"), "ip": null, "register_ip": "any", "internal_key": "k", "group": "default", "date_add": 1 }));
        let count = |id: &str| format!("agent {id} sql SELECT count(*) AS n FROM fim_entry");

        for n in 7001..=7008 {
            let _ = wdb.query(&format!("global delete-agent {n}")).await;
            assert!(wdb.query(&enroll(n)).await.unwrap().starts_with("ok"));
        }
        let batches = 135;
        let events: Vec<Value> = (0..batches).map(|b| batch(7001, b)).collect();
        let t = std::time::Instant::now();
        for v in &events {
            assert!(save_fim_state(&wdb, "7001", v).await);
        }
        let s = t.elapsed().as_secs_f64();
        println!("RATE one agent, one connection: {} rows in {s:.2} s = {:.0} rows/s", batches * 200, f64::from(batches * 200) / s);
        assert_eq!(wdb.query(&count("7001")).await.unwrap(), "ok [{\"n\":27000}]");

        // agents in turn on the one connection: what `store_fim_state` does for a fleet
        let t = std::time::Instant::now();
        for b in 0..40 {
            for n in 7002..=7008 {
                assert!(save_fim_state(&wdb, &n.to_string(), &batch(n, b)).await);
            }
        }
        let s = t.elapsed().as_secs_f64();
        println!("RATE 7 agents, one connection: {} rows in {s:.2} s = {:.0} rows/s", 40 * 7 * 200, f64::from(40 * 7 * 200) / s);

        // agents side by side, one connection each: what the database could take
        let t = std::time::Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for n in 7002..=7008 {
            let (wdb, id) = (sock(), n.to_string());
            let events: Vec<Value> = (40..80).map(|b| batch(n, b)).collect();
            tasks.spawn(async move {
                for v in &events {
                    assert!(save_fim_state(&wdb, &id, v).await);
                }
            });
        }
        tasks.join_all().await;
        let s = t.elapsed().as_secs_f64();
        println!("RATE 7 agents, 7 connections: {} rows in {s:.2} s = {:.0} rows/s", 40 * 7 * 200, f64::from(40 * 7 * 200) / s);

        // the change events after a baseline, as the decoder saves them: updated, not added
        let id = "7001";
        assert!(save_fim_state(&wdb, id, &fim_state()).await);
        let before = wdb.query(&count(id)).await.unwrap();
        for c in changes() {
            let r = wdb.query(&format!("agent {id} syscheck save2 {}", decoder_row(c))).await.unwrap();
            assert!(r.starts_with("ok"), "{r}");
        }
        assert_eq!(wdb.query(&count(id)).await.unwrap(), before, "no second row");
        let r = wdb.query(&format!("agent {id} sql SELECT count(*) AS n FROM fim_entry WHERE sha256 = 'bb'")).await.unwrap();
        assert_eq!(r, "ok [{\"n\":2}]");
    }

    /// The real provigil-db on a folder of its own, in this process.
    // the folder lives as long as the database
    struct RealDb(siem_wdb::wdb::Wdbd, #[allow(dead_code)] tempfile::TempDir);

    struct QuietEnv;

    impl siem_wdb::wdb::WdbEnv for QuietEnv {
        fn log(&self, _: &str, _: &[u8]) {}
        fn time(&self) -> i64 {
            Utc::now().timestamp()
        }
        fn timeofday(&self) -> siem_wdb::wdb::state::Tv {
            siem_wdb::wdb::state::Tv { sec: self.time(), usec: 0 }
        }
        fn router_send(&self, _: i32, _: &[u8]) {}
        fn send_peer(&self, _: i32, _: &[u8]) -> i32 {
            0
        }
        fn is_single_node(&self) -> (i32, i32) {
            (0, 0)
        }
    }

    impl RealDb {
        async fn new(agent: u32) -> Self {
            let home = tempfile::tempdir().unwrap();
            for d in ["queue/db", "queue/tasks", "backup/db"] {
                std::fs::create_dir_all(home.path().join(d)).unwrap();
            }
            let d = siem_wdb::wdb::Wdbd::new(siem_wdb::wdb::WdbConfig::default(), home.path().to_path_buf(), std::sync::Arc::new(QuietEnv));
            d.create_profile();
            let db = RealDb(d, home);
            let row = json!({ "id": agent, "name": format!("a{agent}"), "ip": null, "register_ip": "any", "internal_key": "k", "group": "default", "date_add": 1 });
            assert!(db.ask(&format!("global insert-agent {row}")).await.starts_with("ok"));
            db
        }

        async fn ask(&self, q: &str) -> String {
            self.query(q).await.unwrap()
        }

        async fn rows(&self, id: &str, sql: &str) -> Vec<Value> {
            let r = self.ask(&format!("agent {id} sql {sql}")).await;
            serde_json::from_str(r.strip_prefix("ok ").unwrap_or_else(|| panic!("{sql}: {r}"))).unwrap()
        }

        /// The provigil-db queries of the analysis engine for one check of a scan.
        async fn engine_check(&self, id: &str, policy: &str, scan_id: i64, check: u32, result: &str) {
            if self.ask(&format!("agent {id} sca query {check}")).await.starts_with("ok found") {
                assert!(self.ask(&format!("agent {id} sca update {check}|{result}||{scan_id}")).await.starts_with("ok"));
            } else {
                let m = json!({ "type": "check", "id": scan_id, "policy": "Test", "policy_id": policy, "check": { "id": check, "title": format!("Check {check}"), "result": result } });
                assert!(self.ask(&format!("agent {id} sca insert {m}")).await.starts_with("ok"));
            }
        }

        /// The same for a summary, which comes after its checks.
        async fn engine_summary(&self, id: &str, policy: &str, scan_id: i64, hash: &str) {
            let q = if self.ask(&format!("agent {id} sca query_scan {policy}")).await.starts_with("ok found") {
                format!("update_scan_info_start {policy}|1|2|{scan_id}|1|1|1|3|50|{hash}")
            } else {
                format!("insert_scan_info 1|2|{scan_id}|{policy}|1|1|1|3|50|{hash}")
            };
            assert!(self.ask(&format!("agent {id} sca {q}")).await.starts_with("ok"));
        }
    }

    impl Drop for RealDb {
        fn drop(&mut self) {
            self.0.close_all();
        }
    }

    #[tonic::async_trait]
    impl WdbQuery for RealDb {
        async fn query(&self, query: &str) -> Result<String, siem_ipc::wdbc::WdbcError> {
            let r = self.0.parse(query.as_bytes(), 0).1;
            Ok(String::from_utf8_lossy(&r[..r.iter().position(|&b| b == 0).unwrap_or(r.len())]).into_owned())
        }
    }

    /// The agent's summary event, on its way to the engine.
    fn summary_event(policy: &str, scan_id: i64, hash: &str) -> Value {
        json!({ "event_type": "sca", "location": "sca", "message": json!({ "type": "summary", "scan_id": scan_id, "policy_id": policy, "hash": hash }).to_string() })
    }

    fn results_hash(results: &[&str]) -> String {
        Sha256::digest(results.iter().map(|r| if *r == "not applicable" { "" } else { r }).collect::<Vec<_>>().join(":").as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `check_sca` looks at every test's summaries.
    static SCA_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn sca_asked(agent: &str) -> Vec<Value> {
        take_commands(agent).into_iter().filter(|c| c["type"] == "sca_full").collect()
    }

    #[tokio::test]
    async fn sca_wiped_database_refills_through_a_full_send() {
        let _one_at_a_time = SCA_TESTS.lock().await;
        let (id, policy) = ("771", "wiped_policy");
        let db = RealDb::new(771).await;
        let results = ["passed", "failed", "not applicable"];
        let hash = results_hash(&results);

        // an unchanged agent sends only its summary; the engine has not got to it yet
        watch_sca(id, &[summary_event(policy, 11, &hash)]);
        check_sca(&db, Instant::now()).await;
        assert!(sca_asked(id).is_empty(), "too early to tell");
        // handled, and there are no checks: the same case as the engine's dump request
        db.engine_summary(id, policy, 11, &hash).await;
        check_sca(&db, Instant::now()).await;
        let asked = sca_asked(id);
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0]["policy_id"], policy);
        assert!(asked[0]["command_id"].is_string());
        assert!(!SCA_WATCH.lock().unwrap().contains_key(&(id.to_string(), policy.to_string())), "done with");

        // the full send the agent answers with: the checks, the summary
        for (i, r) in results.iter().enumerate() {
            db.engine_check(id, policy, 12, i as u32 + 1, r).await;
        }
        watch_sca(id, &[summary_event(policy, 12, &hash)]);
        db.engine_summary(id, policy, 12, &hash).await;
        check_sca(&db, Instant::now()).await;
        assert!(sca_asked(id).is_empty(), "in sync, also with a not applicable check: the agent's hash is provigil-db's");

        // an unchanged scan leaves the old checks' scan ids alone, and the hash still holds
        watch_sca(id, &[summary_event(policy, 13, &hash)]);
        db.engine_summary(id, policy, 13, &hash).await;
        check_sca(&db, Instant::now()).await;
        assert!(sca_asked(id).is_empty());
        assert_eq!(db.rows(id, "SELECT count(*) AS n FROM sca_check").await, [json!({ "n": 3 })], "what the console reads");
    }

    #[tokio::test]
    async fn sca_lost_change_is_found_and_asked_for_once_an_hour() {
        let _one_at_a_time = SCA_TESTS.lock().await;
        let (id, policy) = ("772", "lost_policy");
        let db = RealDb::new(772).await;
        db.engine_check(id, policy, 21, 1, "passed").await;
        let hash = results_hash(&["failed"]);
        for scan in [22, 23] {
            db.engine_summary(id, policy, scan, &hash).await;
            watch_sca(id, &[summary_event(policy, scan, &hash)]);
            check_sca(&db, Instant::now()).await;
        }
        assert_eq!(sca_asked(id).len(), 1, "again only after an hour");
    }

    #[tokio::test]
    async fn sca_summary_the_engine_dropped_is_given_up_and_odd_ones_ignored() {
        let _one_at_a_time = SCA_TESTS.lock().await;
        let (id, policy) = ("773", "dropped_policy");
        let db = RealDb::new(773).await;
        watch_sca(id, &[summary_event(policy, 31, "h")]);
        let key = (id.to_string(), policy.to_string());
        check_sca(&db, Instant::now()).await;
        assert!(SCA_WATCH.lock().unwrap().contains_key(&key), "waited for");
        check_sca(&db, Instant::now() + SCA_WATCH_FOR).await;
        assert!(!SCA_WATCH.lock().unwrap().contains_key(&key), "the next scan tells");
        assert!(sca_asked(id).is_empty());

        for bad in ["a b", "x';DROP TABLE sca_check;--", ""] {
            watch_sca(id, &[summary_event(bad, 32, "h")]);
            assert!(!SCA_WATCH.lock().unwrap().contains_key(&(id.to_string(), bad.to_string())), "{bad}");
        }
    }

    use provigil_agent::syscollector::delta;

    fn workstation() -> Value {
        let pkg = |n: &str, v: &str| json!({ "name": n, "version": v, "publisher": "Vendor's", "install_date": "20260101", "size_bytes": 1000, "architecture": "x64", "location": format!("C:\\Program Files\\{n}"), "description": null, "source": "machine", "format": "win", "user_sid": null });
        let proc_ = |pid: u32, n: &str| json!({ "pid": pid, "name": n, "command_line": format!("{n} -k"), "owner": "SYSTEM", "parent_pid": 4, "memory_mb": 20, "cpu_time_ms": pid * 3, "start_time": 1000 + pid, "priority": 8, "threads": 6, "virtual_kb": 100, "session_id": 0 });
        let port = |p: u32, pid: u32| json!({ "protocol": "tcp", "local_ip": "0.0.0.0", "local_port": p, "remote_ip": null, "remote_port": null, "state": "listening", "pid": pid, "process": "svc.exe" });
        let nic = |n: &str, ip: &str| json!({ "name": n, "mac_address": "00:15:5d:00:00:01", "ipv4": [ip], "ipv6": [], "rx_bytes": 1, "tx_bytes": 2, "rx_packets": 3, "tx_packets": 4, "speed_mbps": 1000, "type": "ethernet", "state": "up", "mtu": 1500, "gateway": "10.0.0.1", "dhcp": "enabled", "metric": 25,
            "addresses": [{ "address": ip, "netmask": "255.255.255.0", "broadcast": "10.0.0.255", "family": "ipv4" }, { "address": "fe80::1", "netmask": null, "broadcast": null, "family": "ipv6" }] });
        json!({
            "hostname": "pc", "errors": [],
            "hardware": { "board_serial": "SN1", "cpu_name": "cpu", "cpu_cores": 8, "cpu_mhz": 2800, "ram_total_kb": 16000, "ram_free_kb": 7000, "ram_usage_percent": 50 },
            "packages": [pkg("7-Zip", "23.01"), pkg("Firefox", "120"), pkg("Old Tool", "1")],
            "processes": [proc_(4, "System"), proc_(900, "svc.exe"), proc_(1000, "gone.exe")],
            // the same port twice, as two listeners on one port
            "ports": [port(135, 900), port(445, 4), port(445, 900), port(5000, 1000)],
            "network_interfaces": [nic("Ethernet", "10.0.0.5"), nic("Wi-Fi", "10.0.0.6")],
            "services": [{ "name": "svc", "display_name": "Svc", "state": "running", "startup_type": "auto", "account": "LocalSystem", "path": "C:\\svc.exe", "pid": 900, "description": "d" }, { "name": "old", "display_name": "Old", "state": "stopped", "startup_type": "manual", "account": null, "path": "C:\\old.exe", "pid": null, "description": null }],
            "users": [{ "name": "alice", "full_name": null, "sid": "S-1-5-21-1", "home": "C:\\Users\\alice", "disabled": false, "last_logon": null, "groups": ["Users"] }, { "name": "bob", "full_name": null, "sid": "S-1-5-21-2", "home": null, "disabled": true, "last_logon": null, "groups": [] }],
            "groups": [{ "name": "Users", "sid": "S-1-5-32-545", "description": null, "members": ["alice"] }],
            "browser_extensions": [{ "browser": "chrome", "user": "alice", "profile": "Default", "id": "abc", "name": "Dark Reader", "version": "2.0", "enabled": null }],
        })
    }

    fn os_info() -> Value {
        json!({ "hostname": "pc", "architecture": "x86_64", "os_name": "Microsoft Windows 11 Pro", "os_version": "10.0.22631.4317", "os_major": "10", "os_minor": "0", "os_build": "22631", "os_patch": "4317", "os_display_version": "23H2", "os_platform": "windows", "sysname": "Windows", "release": "22631.4317" })
    }

    /// The agent's full event for this state.
    fn full_event(inv: &Value, hotfixes: &[String]) -> (Value, Value) {
        let (mut inv, mut os) = (inv.clone(), os_info());
        delta::mark_full(&delta::tables(&inv.clone(), &os.clone(), hotfixes), &mut inv, &mut os);
        (json!({ "event_type": "system_inventory", "os_info": os, "hotfixes": hotfixes }), inv)
    }

    /// The agent's delta event from one state to the next.
    fn delta_event(old: &Value, new: &Value, old_fixes: &[String], new_fixes: &[String]) -> Value {
        let saved: HashMap<String, HashMap<String, String>> = delta::tables(old, &os_info(), old_fixes).iter().map(|t| (t.name.to_string(), t.items.iter().map(|(k, (h, _))| (k.clone(), h.clone())).collect())).collect();
        let (tables, n) = delta::changes(&delta::tables(new, &os_info(), new_fixes), &saved);
        delta::event(("774", "pc"), tables, n)
    }

    /// What the console's pages read (`inventory_store`, `agent_inventory`).
    async fn pages(db: &RealDb, id: &str) -> Vec<Vec<Value>> {
        let mut out = Vec::new();
        for sql in [
            "SELECT hostname, os_name, os_version, architecture FROM sys_osinfo",
            "SELECT cpu_name, cpu_cores, ram_total FROM sys_hwinfo",
            "SELECT name, version, vendor, architecture, format, install_time, size, description FROM sys_programs ORDER BY name",
            "SELECT protocol, local_ip, local_port, remote_ip, remote_port, state, pid, process FROM sys_ports ORDER BY local_port, pid",
            "SELECT name, adapter, type, state, mtu, mac FROM sys_netiface ORDER BY name",
            "SELECT iface, type, gateway, dhcp, metric FROM sys_netproto ORDER BY iface, type",
            "SELECT iface, address, netmask FROM sys_netaddr ORDER BY iface, address",
            "SELECT name, pid, cmd FROM sys_processes ORDER BY pid",
            "SELECT hotfix FROM sys_hotfixes ORDER BY hotfix",
            "SELECT service_id, service_state, process_pid FROM sys_services ORDER BY service_id",
            "SELECT user_name, user_groups FROM sys_users ORDER BY user_name",
            "SELECT group_name, group_users FROM sys_groups ORDER BY group_name",
            "SELECT browser_name, package_name, package_version FROM sys_browser_extensions ORDER BY package_name",
        ] {
            out.push(db.rows(id, sql).await);
        }
        out
    }

    /// A workstation an hour later: one package upgraded, one removed, one new, a process, a
    /// port and a service gone, a user changed, an update added, the Wi-Fi off, the Ethernet moved.
    fn an_hour_later() -> Value {
        let mut n = workstation();
        n["packages"][1]["version"] = json!("121");
        n["packages"][0]["publisher"] = json!("Igor");
        let list = n["packages"].as_array_mut().unwrap();
        list.remove(2);
        list.push(json!({ "name": "New Tool", "version": "2", "publisher": null, "install_date": null, "size_bytes": null, "architecture": null, "location": null, "description": null, "source": "pypi", "format": "pypi", "user_sid": null }));
        n["processes"].as_array_mut().unwrap().remove(2);
        n["ports"].as_array_mut().unwrap().remove(3);
        n["services"].as_array_mut().unwrap().remove(1);
        n["users"][0]["groups"] = json!(["Users", "Administrators"]);
        n["network_interfaces"].as_array_mut().unwrap().remove(1);
        n["network_interfaces"][0]["addresses"][0]["address"] = json!("10.0.0.9");
        n["hardware"]["ram_free_kb"] = json!(1);
        n
    }

    #[tokio::test]
    async fn a_delta_leaves_the_same_data_as_a_full_send() {
        let id = "774";
        let (old, new) = (workstation(), an_hour_later());
        let (fixes, new_fixes) = (vec!["KB1".to_string(), "KB2".to_string()], vec!["KB1".to_string(), "KB3".to_string()]);
        let (with_delta, with_full) = (RealDb::new(774).await, RealDb::new(774).await);

        let (ev, inv) = full_event(&old, &fixes);
        store_inventory(&with_delta, id, &ev, &inv).await;
        assert_eq!(apply_delta(&with_delta, id, &delta_event(&old, &old, &fixes, &fixes)).await, (false, Some(true)), "a heartbeat: the tables match");

        let ev = delta_event(&old, &new, &fixes, &new_fixes);
        let tables = &ev["tables"];
        let names = |k: &str| list(&tables["packages"][k]).iter().map(|p| text(p, "name")).collect::<Vec<_>>();
        // a new version is another package; a new publisher is a change
        assert_eq!((names("added"), names("changed"), list(&tables["packages"]["removed"]).len()), (vec!["Firefox".to_string(), "New Tool".to_string()], vec!["7-Zip".to_string()], 2));
        assert!(tables["hardware"].get("changed").is_none(), "free memory alone is no change");
        assert_eq!(apply_delta(&with_delta, id, &ev).await, (true, Some(true)), "applied, and every count and hash matches");
        assert_eq!(apply_delta(&with_delta, id, &ev).await, (true, Some(true)), "the same batch again changes nothing");
        assert!(with_delta.rows(id, "SELECT name FROM sys_programs WHERE name = 'Old Tool'").await.is_empty(), "a removed item is removed from SQLite");
        assert_eq!(with_delta.rows(id, "SELECT address FROM sys_netaddr WHERE iface = 'Wi-Fi'").await, Vec::<Value>::new());

        let (ev, inv) = full_event(&new, &new_fixes);
        store_inventory(&with_full, id, &ev, &inv).await;
        let (a, b) = (pages(&with_delta, id).await, pages(&with_full, id).await);
        assert!(a.iter().all(|p| !p.is_empty()), "{a:?}");
        assert_eq!(a, b, "the console shows the same");
    }

    #[tokio::test]
    async fn only_packages_and_updates_mean_a_new_vulnerability_scan() {
        let id = "775";
        let db = RealDb::new(775).await;
        let (old, fixes) = (workstation(), vec!["KB1".to_string()]);
        let (ev, inv) = full_event(&old, &fixes);
        store_inventory(&db, id, &ev, &inv).await;
        let mut no_software = old.clone();
        no_software["processes"].as_array_mut().unwrap().remove(2);
        assert_eq!(apply_delta(&db, id, &delta_event(&old, &no_software, &fixes, &fixes)).await, (false, Some(true)));
        let fixed = vec!["KB1".to_string(), "KB2".to_string()];
        assert_eq!(apply_delta(&db, id, &delta_event(&no_software, &no_software, &fixes, &fixed)).await, (true, Some(true)));
    }

    #[tokio::test]
    async fn inventory_wiped_database_refills_through_a_full_send() {
        let id = "776";
        let (old, new, fixes) = (workstation(), an_hour_later(), vec!["KB1".to_string()]);
        let wiped = RealDb::new(776).await;

        // the first delta or heartbeat after the wipe: not what the agent has
        store_delta(&wiped, id, &delta_event(&old, &old, &fixes, &fixes)).await;
        let asked = take_commands(id);
        assert_eq!(asked.iter().filter(|c| c["type"] == "inventory_full").count(), 1, "{asked:?}");
        store_delta(&wiped, id, &delta_event(&old, &new, &fixes, &fixes)).await;
        assert!(take_commands(id).is_empty(), "again only after an hour");

        // the agent answers with everything: complete again, and the next delta fits
        let (ev, inv) = full_event(&new, &fixes);
        store_inventory(&wiped, id, &ev, &inv).await;
        assert_eq!(apply_delta(&wiped, id, &delta_event(&new, &new, &fixes, &fixes)).await, (false, Some(true)));
        let packages = wiped.rows(id, "SELECT count(*) AS n FROM sys_programs").await;
        assert_eq!(packages, [json!({ "n": new["packages"].as_array().unwrap().len() })]);
    }

    #[tokio::test]
    async fn a_lost_delta_is_found_by_the_next() {
        let id = "777";
        let db = RealDb::new(777).await;
        let (old, new, fixes) = (workstation(), an_hour_later(), vec!["KB1".to_string()]);
        let (ev, inv) = full_event(&old, &fixes);
        store_inventory(&db, id, &ev, &inv).await;
        // the event from `old` to `new` never came
        assert_eq!(apply_delta(&db, id, &delta_event(&new, &new, &fixes, &fixes)).await, (false, Some(false)));
    }

    #[tokio::test]
    async fn a_large_table_is_compared_past_one_page() {
        let id = "778";
        let db = RealDb::new(778).await;
        let mut inv = workstation();
        let pkg = inv["packages"][0].clone();
        inv["packages"] = (0..CHECKSUM_PAGE + 100).map(|i| { let mut p = pkg.clone(); p["name"] = json!(format!("p{i}")); p }).collect();
        let (ev, full) = full_event(&inv, &[]);
        store_inventory(&db, id, &ev, &full).await;
        assert_eq!(apply_delta(&db, id, &delta_event(&inv, &inv, &[], &[])).await, (false, Some(true)));
    }

    /// The agent's two hashes are this file's `checksum` (each side has its own copy).
    #[test]
    fn hashes_as_the_agent_makes_them() {
        assert_eq!(delta::short_hash("KB1"), checksum(&["KB1"]));
        assert_eq!(delta::table_hash(vec!["b".into(), "a".into()]), checksum(&["a", "b"]));
    }

    #[test]
    fn package_format() {
        let row = |p: Value| package_row(1, "'t'", &p);
        assert!(row(json!({ "name": "requests", "version": "2.31.0", "format": "pypi" })).starts_with("(1, 't', 'pypi', 'requests', "));
        assert!(row(json!({ "name": "lodash", "version": "4.17.21", "format": "npm" })).starts_with("(1, 't', 'npm', 'lodash', "));
        assert!(row(json!({ "name": "7-Zip", "version": "23.01" })).starts_with("(1, 't', 'win', '7-Zip', "), "no format: a Windows program");
        // the same name and version in two ecosystems are two rows
        let ck = |f: &str| row(json!({ "name": "x", "version": "1", "format": f })).rsplit(", ").next().unwrap().to_string();
        assert_ne!(ck("pypi"), ck("npm"));
    }

    #[test]
    fn keepalives_in_one_statement_per_chunk() {
        let ids: Vec<u32> = (1..=2500).collect();
        let sql: Vec<String> = ids.chunks(FLUSH_CHUNK).map(|c| keepalive_sql(c, 77)).collect();
        assert_eq!(sql.len(), 3);
        assert!(sql[0].starts_with("UPDATE agent SET last_keepalive = 77, connection_status = 'active', disconnection_time = 0, status_code = 0 WHERE id IN (1, 2, "));
        assert!(sql[0].ends_with(", 1000)"));
        assert!(sql[2].contains("IN (2001, ") && sql[2].ends_with(", 2500)"));
        assert!(sql.iter().all(|s| !s.contains("version")), "the keepalive alone");
        // under the database socket's limit with the longest ids
        let widest: Vec<u32> = (u32::MAX - 999..=u32::MAX).collect();
        assert!(keepalive_sql(&widest, 77).len() < MAX_SQL && agent_row_sql(Some(&"v".repeat(32)), &widest).len() < MAX_SQL);
    }

    #[test]
    fn node_ip_version_only_when_changed() {
        let v = |s: &str| Some(s.to_string());
        let seen = BTreeMap::from([(1, v("1.0.0")), (2, v("1.0.0")), (3, v("1.1.0")), (4, None), (5, v("1.0.0"))]);
        let written = BTreeMap::from([(1, v("1.0.0")), (3, v("1.0.0"))]);
        let changed = changed_versions(seen, &written);
        assert_eq!(changed, BTreeMap::from([(None, vec![4]), (v("1.0.0"), vec![2, 5]), (v("1.1.0"), vec![3])]));
        assert_eq!(
            agent_row_sql(Some("1.0.0"), &changed[&v("1.0.0")]),
            "UPDATE agent SET node_name = COALESCE(NULLIF(node_name, ''), (SELECT node_name FROM agent WHERE id = 0)), ip = COALESCE(NULLIF(ip, ''), NULLIF(register_ip, ''), 'any'), version = 'ProVigil v1.0.0' WHERE id IN (2, 5)"
        );
        assert!(agent_row_sql(None, &[4]).contains("version = COALESCE(NULLIF(version, ''), 'ProVigil') WHERE id IN (4)"));
    }

    #[test]
    fn group_config_status() {
        let sql = |s| group_config_sql("77", s);
        assert_eq!(sql(true).as_deref(), Some("UPDATE agent SET group_config_status = 'synced' WHERE id = 77"));
        assert_eq!(sql(true), None, "unchanged: not written again");
        assert_eq!(sql(false).as_deref(), Some("UPDATE agent SET group_config_status = 'not synced' WHERE id = 77"));
        assert_eq!(group_config_sql("x", true), None);
    }
}
