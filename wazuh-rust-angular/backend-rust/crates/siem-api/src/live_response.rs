//! EDR live response: on-demand investigation of a Windows agent (processes, network
//! connections, services, a folder's listing, a file). The console sends the agent
//! siem-active-response's `live-response`; the answer comes back in chunks on the
//! agent's own channel (active-responses.log lines), which go straight into the agent's
//! tenant table `siem_live_response_chunks` and never into the event or alert tables.
//! A result is put back together from ClickHouse when it is read, and checked against the
//! SHA-256 the agent sent. Results are kept 30 days; the requests (who asked for what) stay.
//!
//! `POST|GET /api/v1/agents/:id/live-response`, `GET .../live-response/:rid`,
//! `GET .../live-response/:rid/download` (a collected file)

use std::io::Read;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::tenancy::{self, AuthCtx};
use crate::AppState;

pub const DDL: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS siem_live_response (id String, agent_id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
    "CREATE TABLE IF NOT EXISTS siem_live_response_chunks (id String, agent_id String, seq UInt32, data String, received_at DateTime DEFAULT now()) ENGINE = ReplacingMergeTree ORDER BY (id, seq) TTL received_at + INTERVAL 30 DAY",
];

pub const ACTIONS: [&str; 5] = ["processes", "connections", "services", "dir", "file"];
/// A request with no answer by then is shown as unanswered (agent offline, old agent).
const ANSWER_MINUTES: i64 = 15;
/// Largest result put back together (the agent sends files up to 25 MB).
const MAX_RESULT: u64 = 64 * 1024 * 1024;

/// One request and, once answered, its outcome.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub action: String,
    #[serde(default)]
    pub path: String,
    pub requested_by: String,
    pub requested_at: String,
    /// pending | done | failed
    pub status: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub chunks: u32,
    /// of the compressed payload, as the agent sent it
    #[serde(default)]
    pub sha256: String,
    /// of a collected file
    #[serde(default)]
    pub file_sha256: String,
    #[serde(default)]
    pub completed_at: String,
}

fn reply(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "status": if code.is_success() { "ok" } else { "error" }, "message": m.into() }))).into_response()
}

async fn save(client: &clickhouse::Client, r: &Request) -> Result<(), String> {
    let doc = serde_json::to_string(r).map_err(|e| e.to_string())?;
    let version = chrono::Utc::now().timestamp_micros().max(0) as u64;
    client.query("INSERT INTO siem_live_response (id, agent_id, doc, version) VALUES (?, ?, ?, ?)").bind(&r.id).bind(&r.agent_id).bind(doc).bind(version).execute().await.map_err(|e| e.to_string())
}

async fn load(client: &clickhouse::Client, agent_id: &str, id: &str) -> Result<Option<Request>, String> {
    let doc = client
        .query("SELECT doc FROM siem_live_response FINAL WHERE id = ? AND agent_id = ?")
        .bind(id)
        .bind(agent_id)
        .fetch_optional::<String>()
        .await
        .map_err(|e| e.to_string())?;
    Ok(doc.and_then(|d| serde_json::from_str(&d).ok()))
}

/// The request as the console shows it: a pending one past [`ANSWER_MINUTES`] is unanswered.
fn view(r: &Request) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or_default();
    let late = r.status == "pending" && chrono::DateTime::parse_from_rfc3339(&r.requested_at).is_ok_and(|t| chrono::Utc::now().signed_duration_since(t) > chrono::Duration::minutes(ANSWER_MINUTES));
    if late {
        v["status"] = json!("no_answer");
        v["message"] = json!(format!("No answer from the agent in {ANSWER_MINUTES} minutes: it may be offline, or deployed before live response (redeploy it)."));
    }
    v
}

#[derive(Deserialize)]
pub struct NewRequest {
    action: String,
    #[serde(default)]
    path: Option<String>,
}

/// `POST /api/v1/agents/:id/live-response` `{action, path?}`
pub async fn create(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(agent_id): Path<String>, Json(body): Json<NewRequest>) -> Response {
    if !crate::agent_is_windows(&state, &agent_id) {
        return reply(StatusCode::BAD_REQUEST, "Live response runs on Windows agents for now");
    }
    let action = body.action.trim();
    if !ACTIONS.contains(&action) {
        return reply(StatusCode::BAD_REQUEST, "Unknown action: processes, connections, services, dir or file");
    }
    let path = body.path.as_deref().map(str::trim).unwrap_or("").to_string();
    if matches!(action, "dir" | "file") {
        if let Some(why) = siem_active_response::live::path_refusal(&path) {
            return reply(StatusCode::BAD_REQUEST, format!("The path: {why}"));
        }
        if path.len() > 1024 {
            return reply(StatusCode::BAD_REQUEST, "The path is too long");
        }
    }
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), &agent_id);
    let (agent_name, ip) = state.agents.read().unwrap().get(&agent_id).map(|a| (a.name.clone(), a.ip.clone())).unwrap_or_default();
    // a collected file leaves the endpoint: recorded like the other responses (a protected host is refused)
    if action == "file" {
        if let Err(m) = crate::decisions::gate_manual(&state, &ctx, &tenant, "manual_collect_file", &ip, json!({ "agent_id": agent_id, "path": path })).await {
            return reply(StatusCode::FORBIDDEN, m);
        }
    }
    let mut r = Request {
        id: uuid::Uuid::new_v4().simple().to_string(),
        agent_id: agent_id.clone(),
        agent_name,
        action: action.to_string(),
        path: path.clone(),
        requested_by: ctx.username.clone(),
        requested_at: chrono::Utc::now().to_rfc3339(),
        status: "pending".into(),
        ..Default::default()
    };
    let client = state.db.tenant_client(&tenant);
    if let Err(e) = save(&client, &r).await {
        return reply(StatusCode::SERVICE_UNAVAILABLE, format!("The request could not be recorded, so nothing was sent: {e}"));
    }
    if let Err(e) = crate::wazuh_manager::live_response(&agent_id, &r.id, action, &path).await {
        r.status = "failed".into();
        r.message = e.clone();
        let _ = save(&client, &r).await;
        return reply(StatusCode::SERVICE_UNAVAILABLE, e);
    }
    info!("Wazuh agent {agent_id}: live response {action} {path} by {} (request {})", ctx.username, r.id);
    (StatusCode::OK, Json(json!({ "status": "sent", "message": "Sent to the agent; the answer usually takes a few seconds.", "request": view(&r) }))).into_response()
}

/// `GET /api/v1/agents/:id/live-response`: the agent's latest 50 requests.
pub async fn list(State(state): State<AppState>, Path(agent_id): Path<String>) -> Response {
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), &agent_id);
    let docs = state
        .db
        .tenant_client(&tenant)
        .query("SELECT doc FROM siem_live_response FINAL WHERE agent_id = ? ORDER BY version DESC LIMIT 50")
        .bind(&agent_id)
        .fetch_all::<String>()
        .await;
    match docs {
        Ok(d) => Json(json!({ "requests": d.iter().filter_map(|x| serde_json::from_str::<Request>(x).ok()).map(|r| view(&r)).collect::<Vec<_>>() })).into_response(),
        Err(e) => reply(StatusCode::SERVICE_UNAVAILABLE, format!("Live response history cannot be read: {e}")),
    }
}

/// The answer's bytes, put back together and checked.
async fn assemble(client: &clickhouse::Client, r: &Request) -> Result<Vec<u8>, String> {
    let rows = client
        .query("SELECT seq, data FROM siem_live_response_chunks FINAL WHERE id = ? AND agent_id = ? ORDER BY seq")
        .bind(&r.id)
        .bind(&r.agent_id)
        .fetch_all::<(u32, String)>()
        .await
        .map_err(|e| e.to_string())?;
    decode(rows, r.chunks, &r.sha256)
}

/// Chunks (seq, base64) -> the payload, refused unless complete and matching `sha256`.
fn decode(rows: Vec<(u32, String)>, chunks: u32, sha256: &str) -> Result<Vec<u8>, String> {
    if rows.is_empty() && chunks > 0 {
        return Err("The result is no longer kept (30 days) or never arrived".into());
    }
    if rows.len() != chunks as usize || rows.iter().enumerate().any(|(i, (s, _))| *s as usize != i) {
        return Err(format!("{} of {chunks} parts arrived", rows.len()));
    }
    let b64: String = rows.into_iter().map(|(_, d)| d).collect();
    let gz = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| format!("damaged result: {e}"))?;
    let got: String = Sha256::digest(&gz).iter().map(|b| format!("{b:02x}")).collect();
    if got != sha256 {
        return Err("The result does not match the checksum the agent sent".into());
    }
    let mut out = Vec::new();
    // bounded: an agent cannot make the manager inflate a huge payload
    flate2::read::GzDecoder::new(&gz[..]).take(MAX_RESULT + 1).read_to_end(&mut out).map_err(|e| format!("damaged result: {e}"))?;
    if out.len() as u64 > MAX_RESULT {
        return Err("The result is too large".into());
    }
    Ok(out)
}

/// `GET /api/v1/agents/:id/live-response/:rid`: the request, and the listing it returned.
pub async fn get(State(state): State<AppState>, Path((agent_id, id)): Path<(String, String)>) -> Response {
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), &agent_id);
    let client = state.db.tenant_client(&tenant);
    let r = match load(&client, &agent_id, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => return reply(StatusCode::NOT_FOUND, "No such live response request"),
        Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let mut v = json!({ "request": view(&r) });
    if r.status == "done" && r.action != "file" {
        match assemble(&client, &r).await.and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| format!("damaged result: {e}"))) {
            Ok(result) => v["result"] = result,
            Err(e) => v["error"] = json!(e),
        }
    }
    Json(v).into_response()
}

/// `GET /api/v1/agents/:id/live-response/:rid/download`: a collected file.
pub async fn download(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path((agent_id, id)): Path<(String, String)>) -> Response {
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), &agent_id);
    let client = state.db.tenant_client(&tenant);
    let r = match load(&client, &agent_id, &id).await {
        Ok(Some(r)) if r.action == "file" && r.status == "done" => r,
        Ok(_) => return reply(StatusCode::NOT_FOUND, "No collected file for this request"),
        Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let bytes = match assemble(&client, &r).await {
        Ok(b) => b,
        Err(e) => return reply(StatusCode::CONFLICT, e),
    };
    info!("live response {}: file {} (agent {agent_id}) downloaded by {}", r.id, r.path, ctx.username);
    // shortcut: served as-is with a non-executable name; a password-protected archive ("infected") would stop the browser's antivirus deleting samples, add one when analysts handle malware routinely
    let base = r.path.rsplit(['\\', '/']).next().unwrap_or("file");
    let name: String = base.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}.collected\"")),
            (header::HeaderName::from_static("x-file-sha256"), r.file_sha256.clone()),
        ],
        bytes,
    )
        .into_response()
}

/// Whether an archived event or alert is a live response line (kept out of both tables).
pub fn is_result(v: &Value) -> bool {
    parse_line(v).is_some()
}

fn parse_line(v: &Value) -> Option<Value> {
    let log = v["full_log"].as_str()?;
    if !log.contains("\"script\":\"live-response\"") {
        return None;
    }
    let r: Value = serde_json::from_str(&log[log.find('{')?..]).ok()?;
    (r["script"] == "live-response").then_some(r)
}

#[derive(clickhouse::Row, Serialize)]
struct ChunkRow {
    id: String,
    agent_id: String,
    seq: u32,
    data: String,
}

/// Stores the live response lines of a batch of archived events: chunks into the agent's
/// tenant table, then each request's outcome. A line only counts for a request made to
/// the agent that sent it.
pub async fn ingest(state: &AppState, events: Vec<Value>) {
    let mut chunks: std::collections::BTreeMap<String, Vec<ChunkRow>> = std::collections::BTreeMap::new();
    let mut outcomes: Vec<(String, String, Value)> = Vec::new();
    for v in &events {
        let (Some(r), Some(agent)) = (parse_line(v), v["agent"]["id"].as_str()) else { continue };
        let Some(id) = r["id"].as_str().filter(|i| siem_active_response::live::valid_id(i)) else { continue };
        let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent);
        match (r["seq"].as_u64(), r["data"].as_str()) {
            (Some(seq), Some(data)) => chunks.entry(tenant).or_default().push(ChunkRow { id: id.to_string(), agent_id: agent.to_string(), seq: seq as u32, data: data.to_string() }),
            _ => outcomes.push((tenant, agent.to_string(), r)),
        }
    }
    for (tenant, rows) in chunks {
        let client = state.db.tenant_client(&tenant);
        // shortcut: no retry; when ClickHouse is down the result reads as incomplete and the analyst asks again
        let r: Result<(), clickhouse::error::Error> = async {
            let mut ins = client.insert("siem_live_response_chunks")?;
            for row in &rows {
                ins.write(row).await?;
            }
            ins.end().await
        }
        .await;
        if let Err(e) = r {
            warn!("live response: {} result parts of tenant {tenant} not stored: {e}", rows.len());
        }
    }
    for (tenant, agent, o) in outcomes {
        let client = state.db.tenant_client(&tenant);
        let id = o["id"].as_str().unwrap_or_default();
        let Ok(Some(mut r)) = load(&client, &agent, id).await else { continue };
        r.status = if o["status"] == "done" { "done" } else { "failed" }.into();
        r.message = o["message"].as_str().unwrap_or_default().to_string();
        r.chunks = o["chunks"].as_u64().unwrap_or(0) as u32;
        r.bytes = o["bytes"].as_u64().unwrap_or(0);
        r.sha256 = o["sha256"].as_str().unwrap_or_default().to_string();
        r.file_sha256 = o["file_sha256"].as_str().unwrap_or_default().to_string();
        r.completed_at = chrono::Utc::now().to_rfc3339();
        if let Err(e) = save(&client, &r).await {
            warn!("live response {id}: outcome not stored: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(agent: &str, body: &str) -> Value {
        json!({ "agent": { "id": agent }, "location": "active-response\\active-responses.log", "full_log": format!("2026/10/30 10:00:00 active-response/bin/live-response.exe: {body}") })
    }

    #[test]
    fn agent_lines_round_trip() {
        // incompressible, so it takes several chunks
        let payload: Vec<u8> = (0..60_000u32).flat_map(|i| i.wrapping_mul(2654435761).to_le_bytes()).collect();
        let lines = siem_active_response::live::result_lines("0a1b", "processes", &payload, "");
        let events: Vec<Value> = lines.iter().map(|l| line("049", l)).collect();
        assert!(events.iter().all(is_result));
        assert!(!is_result(&line("049", r#"{"script":"yara-scan","status":"clean"}"#)));
        assert!(!is_result(&json!({ "full_log": "user typed live-response in a shell" })));

        let mut rows = Vec::new();
        let mut done = Value::Null;
        for e in &events {
            let r = parse_line(e).unwrap();
            match r["seq"].as_u64() {
                Some(s) => rows.push((s as u32, r["data"].as_str().unwrap().to_string())),
                None => done = r,
            }
        }
        let (n, sha) = (done["chunks"].as_u64().unwrap() as u32, done["sha256"].as_str().unwrap().to_string());
        assert_eq!(decode(rows.clone(), n, &sha).unwrap(), payload);
        // a missing part, a wrong checksum, nothing kept
        assert!(decode(rows[1..].to_vec(), n, &sha).unwrap_err().contains("parts arrived"));
        assert!(decode(rows.clone(), n, &"0".repeat(64)).unwrap_err().contains("checksum"));
        assert!(decode(Vec::new(), n, &sha).unwrap_err().contains("30 days"));
    }

    #[test]
    fn unanswered_requests() {
        let mut r = Request { status: "pending".into(), requested_at: (chrono::Utc::now() - chrono::Duration::minutes(20)).to_rfc3339(), ..Default::default() };
        assert_eq!(view(&r)["status"], "no_answer");
        r.requested_at = chrono::Utc::now().to_rfc3339();
        assert_eq!(view(&r)["status"], "pending");
    }
}
