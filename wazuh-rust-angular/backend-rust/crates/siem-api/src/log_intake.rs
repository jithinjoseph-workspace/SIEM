//! Log intake beyond ProVigil agents and syslog devices (it replaces NDR's old siem-engine, and
//! accepts what it accepted):
//! - Beats (Winlogbeat, Filebeat): the Elasticsearch bulk API on its own port (SIEM_BEATS_PORT,
//!   default 9201; 0 = off), with the handshake replies Beats checks first;
//! - Windows Event Collector: POST /api/siem/wec, Windows event XML, or Winlogbeat / NXLog JSON;
//! - REST: POST /api/siem/ingest `{source_type: syslog|cef|wec|generic, raw_log}`.
//!
//! Every request carries an ingest key (`Authorization: Bearer <key>`; Beats may send
//! `ApiKey base64(id:key)`). A tenant admin creates one per source (only its SHA-256 is kept, in
//! ndr.siem_ingest_keys), and the key's client must have the SIEM module.
//! Windows events become the manager's event format (`data.win.system` / `data.win.eventdata`)
//! and go through the same analysis as the agents' events (Sigma, endpoint policies, alerts,
//! cases); other lines go through the syslog path (rules, the client's parsers, storage).

use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::tenancy::AuthCtx;
use crate::AppState;

const MAX_DOCS: usize = 20_000;
pub const MAX_BODY: usize = 50 * 1024 * 1024;
const CACHE_TTL: Duration = Duration::from_secs(60);

// ───────────────────────────── ingest keys ─────────────────────────────

#[derive(Clone)]
struct Source {
    tenant: String,
    source_id: String,
    name: String,
}

fn cache() -> &'static Mutex<HashMap<String, (Option<Source>, Instant)>> {
    static C: std::sync::OnceLock<Mutex<HashMap<String, (Option<Source>, Instant)>>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.trim().as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// The key a request carries: `Bearer <key>`, or Beats' `ApiKey base64(id:key)` (the part after
/// the colon, or the whole decoded value).
fn key_of(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?.trim();
    if let Some(k) = auth.strip_prefix("Bearer ") {
        return Some(k.trim().to_string()).filter(|k| !k.is_empty());
    }
    let k = auth.strip_prefix("ApiKey ")?.trim();
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD.decode(k).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_else(|| k.to_string());
    Some(decoded.split_once(':').map(|(_, key)| key.to_string()).unwrap_or(decoded)).filter(|k| !k.is_empty())
}

/// The source a key belongs to (active keys only; cached a minute).
async fn source_of(state: &AppState, key: &str) -> Option<Source> {
    let hash = sha256_hex(key);
    if let Some((s, at)) = cache().lock().unwrap().get(&hash) {
        if at.elapsed() < CACHE_TTL {
            return s.clone();
        }
    }
    let row = state
        .db
        .root()
        .query("SELECT tenant_id, source_id, name FROM ndr.siem_ingest_keys FINAL WHERE key_hash = ? AND active = 1 LIMIT 1")
        .bind(&hash)
        .fetch_optional::<(String, String, String)>()
        .await
        .ok()
        .flatten();
    let src = row.map(|(tenant, source_id, name)| Source { tenant, source_id, name });
    cache().lock().unwrap().insert(hash, (src.clone(), Instant::now()));
    src
}

/// The client may send SIEM logs: the SIEM module in its licence (or its settings).
fn has_siem(state: &AppState, tenant: &str) -> bool {
    let t = crate::tenancy::normalize_tenant(tenant);
    let features = crate::licence::features_for(&t).or_else(|| {
        state.tenants.read().unwrap().iter().find(|r| crate::tenancy::normalize_tenant(&r.id) == t).map(|r| r.features.clone())
    });
    features.is_none_or(|f| provigil_common::modules::client_has(&f, provigil_common::modules::SIEM))
}

/// The source of a request, or the refusal (401 without a valid key, 403 without the SIEM module).
async fn authorise(state: &AppState, headers: &HeaderMap) -> Result<Source, Response> {
    let Some(key) = key_of(headers) else {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "an ingest key is required (Authorization: Bearer <key>)" }))).into_response());
    };
    let Some(src) = source_of(state, &key).await else {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid or revoked ingest key" }))).into_response());
    };
    if !has_siem(state, &src.tenant) {
        return Err((StatusCode::FORBIDDEN, provigil_common::modules::refusal(provigil_common::modules::SIEM)).into_response());
    }
    Ok(src)
}

fn may_manage(ctx: &AuthCtx) -> bool {
    ctx.is_super() || ctx.role == "tenant_admin"
}

#[derive(Deserialize)]
pub struct NewKey {
    name: String,
}

/// `POST /api/siem/ingest-keys` `{name}` (tenant admins): a new source and its key, shown once.
pub async fn create_key(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<NewKey>) -> Response {
    if !may_manage(&ctx) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only tenant admins create ingest keys" }))).into_response();
    }
    let name = r.name.trim();
    if name.is_empty() || name.len() > 100 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "a name of 1-100 characters is required" }))).into_response();
    }
    use rand::Rng;
    let key: String = format!("pvk_{}", rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(40).map(char::from).collect::<String>());
    let source_id = uuid::Uuid::new_v4().to_string();
    let tenant = ctx.scope();
    let res = state
        .db
        .root()
        .query("INSERT INTO ndr.siem_ingest_keys (key_hash, tenant_id, source_id, name, active, created_at) VALUES (?, ?, ?, ?, 1, now())")
        .bind(sha256_hex(&key))
        .bind(&tenant)
        .bind(&source_id)
        .bind(name)
        .execute()
        .await;
    if let Err(e) = res {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": e.to_string() }))).into_response();
    }
    tracing::info!("ingest key created for source '{name}' of tenant '{tenant}' by {}", ctx.username);
    Json(json!({ "status": "ok", "source_id": source_id, "name": name, "key": key, "beats_port": beats_port(),
                 "note": "The key is shown only now: store it in the source's configuration." }))
    .into_response()
}

/// `GET /api/siem/ingest-keys`: the client's sources (never their keys).
pub async fn list_keys(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    if !may_manage(&ctx) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only tenant admins manage ingest keys" }))).into_response();
    }
    let rows = state
        .db
        .root()
        .query("SELECT source_id, name, active, toString(created_at) FROM ndr.siem_ingest_keys FINAL WHERE tenant_id = ? ORDER BY created_at DESC")
        .bind(ctx.scope())
        .fetch_all::<(String, String, u8, String)>()
        .await
        .unwrap_or_default();
    Json(json!({ "sources": rows.into_iter().map(|r| json!({ "source_id": r.0, "name": r.1, "active": r.2 == 1, "created_at": r.3 })).collect::<Vec<_>>(), "beats_port": beats_port() })).into_response()
}

/// `DELETE /api/siem/ingest-keys/:source_id`: the key stops working (kept, inactive).
pub async fn revoke_key(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(source_id): Path<String>) -> Response {
    if !may_manage(&ctx) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only tenant admins manage ingest keys" }))).into_response();
    }
    let res = state
        .db
        .root()
        .query("INSERT INTO ndr.siem_ingest_keys (key_hash, tenant_id, source_id, name, active, created_at) SELECT key_hash, tenant_id, source_id, name, 0, greatest(now(), created_at + 1) FROM ndr.siem_ingest_keys FINAL WHERE tenant_id = ? AND source_id = ? AND active = 1")
        .bind(ctx.scope())
        .bind(&source_id)
        .execute()
        .await;
    cache().lock().unwrap().clear();
    match res {
        Ok(()) => Json(json!({ "status": "ok" })).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

// ───────────────────────────── Windows events ─────────────────────────────

/// A Windows event, whatever it came in as.
#[derive(Debug, Default, PartialEq)]
struct WinEvent {
    event_id: String,
    channel: String,
    provider: String,
    computer: String,
    level: String,
    record_id: String,
    time: String,
    message: String,
    data: Vec<(String, String)>,
}

/// `CommandLine` -> `commandLine`: the manager's eventdata names (Sigma maps them back).
fn lower_camel(k: &str) -> String {
    let mut c = k.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// A Winlogbeat document (`winlog.*`), or NXLog JSON (`EventID`, `Channel`, ...). None for
/// anything else.
fn from_json(doc: &Value) -> Option<WinEvent> {
    if let Some(w) = doc.get("winlog").filter(|w| w.is_object()) {
        let mut data: Vec<(String, String)> = w["event_data"].as_object().map(|m| m.iter().map(|(k, v)| (k.clone(), text(v))).collect()).unwrap_or_default();
        if let Some(u) = w["user_data"].as_object() {
            data.extend(u.iter().map(|(k, v)| (k.clone(), text(v))));
        }
        return Some(WinEvent {
            event_id: text(&w["event_id"]),
            channel: text(&w["channel"]),
            provider: text(&w["provider_name"]),
            computer: if w["computer_name"].is_null() { text(&doc["host"]["name"]) } else { text(&w["computer_name"]) },
            level: text(&doc["log"]["level"]),
            record_id: text(&w["record_id"]),
            time: text(&doc["@timestamp"]),
            message: text(&doc["message"]),
            data,
        });
    }
    let o = doc.as_object()?;
    o.get("EventID")?;
    const SYSTEM: [&str; 12] = ["EventID", "Channel", "SourceName", "ProviderName", "Hostname", "Severity", "SeverityValue", "RecordNumber", "EventTime", "Message", "EventReceivedTime", "SourceModuleName"];
    Some(WinEvent {
        event_id: text(&o["EventID"]),
        channel: o.get("Channel").map(text).unwrap_or_default(),
        provider: o.get("ProviderName").or(o.get("SourceName")).map(text).unwrap_or_default(),
        computer: o.get("Hostname").map(text).unwrap_or_default(),
        level: o.get("Severity").map(text).unwrap_or_default(),
        record_id: o.get("RecordNumber").map(text).unwrap_or_default(),
        time: o.get("EventTime").map(text).unwrap_or_default(),
        message: o.get("Message").map(text).unwrap_or_default(),
        data: o.iter().filter(|(k, _)| !SYSTEM.contains(&k.as_str())).map(|(k, v)| (k.clone(), text(v))).collect(),
    })
}

/// Windows event XML (one or more `<Event>`), as Windows Event Collector forwards it.
fn from_xml(xml: &str) -> Vec<WinEvent> {
    use quick_xml::events::Event;
    let mut r = quick_xml::Reader::from_str(xml);
    r.config_mut().trim_text(true);
    let (mut out, mut cur): (Vec<WinEvent>, Option<WinEvent>) = (Vec::new(), None);
    let mut path: Vec<String> = Vec::new();
    let mut data_name: Option<String> = None;
    let attr = |e: &quick_xml::events::BytesStart, name: &[u8]| -> Option<String> {
        e.attributes().flatten().find(|a| a.key.local_name().as_ref() == name).and_then(|a| a.unescape_value().ok().map(|v| v.to_string()))
    };
    loop {
        match r.read_event() {
            Ok(ref ev @ (Event::Start(ref e) | Event::Empty(ref e))) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let empty = matches!(ev, Event::Empty(_));
                if name == "Event" && !empty {
                    cur = Some(WinEvent::default());
                }
                if let Some(w) = cur.as_mut() {
                    match name.as_str() {
                        "Provider" => w.provider = attr(e, b"Name").unwrap_or_default(),
                        "TimeCreated" => w.time = attr(e, b"SystemTime").unwrap_or_default(),
                        "Data" if !empty => data_name = attr(e, b"Name"),
                        _ => {}
                    }
                }
                // a self-closing tag has no end tag: it never joins the path
                if !empty {
                    path.push(name);
                }
            }
            Ok(Event::Text(t)) => {
                let v = t.unescape().map(|s| s.to_string()).unwrap_or_default();
                if let (Some(ev), Some(tag)) = (cur.as_mut(), path.last()) {
                    match tag.as_str() {
                        "EventID" => ev.event_id = v,
                        "Channel" => ev.channel = v,
                        "Computer" => ev.computer = v,
                        "Level" => ev.level = v,
                        "EventRecordID" => ev.record_id = v,
                        "Message" => ev.message = v,
                        "Data" => {
                            let key = data_name.clone().unwrap_or_else(|| format!("Data{}", ev.data.len()));
                            ev.data.push((key, v));
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"Data" {
                    data_name = None;
                }
                if e.local_name().as_ref() == b"Event" {
                    if let Some(ev) = cur.take() {
                        out.push(ev);
                    }
                }
                path.pop();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

/// The event as the manager's analysis gives it (what Sigma and the other checks read).
fn manager_event(ev: &WinEvent, agent_id: &str, source_name: &str) -> Value {
    let mut eventdata = Map::new();
    for (k, v) in &ev.data {
        if !v.is_empty() {
            eventdata.insert(lower_camel(k), Value::String(v.clone()));
        }
    }
    let computer = if ev.computer.is_empty() { source_name } else { ev.computer.as_str() };
    json!({
        "timestamp": if ev.time.is_empty() { chrono::Utc::now().to_rfc3339() } else { ev.time.clone() },
        "agent": { "id": agent_id, "name": computer },
        "manager": { "name": "provigil" },
        "location": "EventChannel",
        "decoder": { "name": "windows_eventchannel" },
        "full_log": ev.message,
        "data": { "win": {
            "system": { "eventID": ev.event_id, "channel": ev.channel, "providerName": ev.provider, "computer": computer,
                        "level": ev.level, "eventRecordID": ev.record_id, "systemTime": ev.time, "message": ev.message },
            "eventdata": Value::Object(eventdata),
        } },
    })
}

/// A source shows as one computer-like entry of its client (like a syslog device).
fn agent_id(src: &Source) -> String {
    format!("ingest-{}", src.source_id.chars().take(8).collect::<String>())
}

fn register(state: &AppState, src: &Source, os: &str) -> String {
    let id = agent_id(src);
    state.agent_tenants.write().unwrap().insert(id.clone(), src.tenant.clone());
    let mut agents = state.agents.write().unwrap();
    let a = agents.entry(id.clone()).or_insert_with(|| siem_core::Agent {
        id: id.clone(),
        name: src.name.clone(),
        ip: "any".into(),
        os: os.into(),
        version: "ingest".into(),
        status: siem_core::AgentStatus::Active,
        last_keepalive: chrono::Utc::now(),
        os_type: "network".into(),
    });
    a.last_keepalive = chrono::Utc::now();
    a.status = siem_core::AgentStatus::Active;
    id
}

/// Windows events into the analysis the agents' events go through.
fn analyse_windows(state: &AppState, src: &Source, events: Vec<WinEvent>) -> usize {
    if events.is_empty() {
        return 0;
    }
    let id = register(state, src, "Windows (Beats / WEC)");
    let n = events.len();
    let vs: Vec<Value> = events.iter().map(|e| manager_event(e, &id, &src.name)).collect();
    tokio::spawn(crate::provigil_manager::on_events(state.clone(), vs));
    n
}

/// Other log lines into the syslog path (rules, the client's parsers, storage).
fn analyse_lines(state: &AppState, src: &Source, peer: &str, lines: Vec<String>) -> usize {
    let lines: Vec<String> = lines.into_iter().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return 0;
    }
    let id = register(state, src, "Log source (Beats / REST)");
    let origin = crate::syslog::Origin::Source { id, name: src.name.clone(), tenant: src.tenant.clone() };
    let (st, peer, n) = (state.clone(), peer.to_string(), lines.len());
    tokio::spawn(async move {
        for l in lines {
            crate::syslog::process_syslog_line(&l, &peer, &origin, &st).await;
        }
    });
    n
}

/// A WEC / Winlogbeat / NXLog body: XML events, or JSON (one object, an array, or one per line).
fn windows_body(body: &str) -> (Vec<WinEvent>, Vec<String>) {
    let t = body.trim_start();
    if t.starts_with('<') {
        return (from_xml(t), Vec::new());
    }
    let docs: Vec<Value> = match serde_json::from_str::<Value>(t) {
        Ok(Value::Array(a)) => a,
        Ok(v) => vec![v],
        Err(_) => t.lines().filter_map(|l| serde_json::from_str(l).ok()).collect(),
    };
    let (mut win, mut other) = (Vec::new(), Vec::new());
    for d in docs.iter().take(MAX_DOCS) {
        match from_json(d) {
            Some(e) => win.push(e),
            None => other.push(d.to_string()),
        }
    }
    (win, other)
}

/// `POST /api/siem/wec` (ingest key)
pub async fn wec(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let src = match authorise(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let body = String::from_utf8_lossy(&body);
    if body.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "empty body" }))).into_response();
    }
    let (win, other) = windows_body(&body);
    let n = analyse_windows(&state, &src, win) + analyse_lines(&state, &src, "wec", other);
    Json(json!({ "accepted": n })).into_response()
}

#[derive(Deserialize)]
pub struct RestReq {
    #[serde(default)]
    source_type: String,
    raw_log: String,
}

/// `POST /api/siem/ingest` `{source_type, raw_log}` (ingest key)
pub async fn rest(State(state): State<AppState>, headers: HeaderMap, Json(r): Json<RestReq>) -> Response {
    let src = match authorise(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if r.raw_log.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "accepted": false, "message": "raw_log is empty" }))).into_response();
    }
    let n = if r.source_type == "wec" {
        let (win, other) = windows_body(&r.raw_log);
        analyse_windows(&state, &src, win) + analyse_lines(&state, &src, "rest", other)
    } else {
        analyse_lines(&state, &src, "rest", r.raw_log.lines().take(MAX_DOCS).map(String::from).collect())
    };
    Json(json!({ "accepted": n > 0, "count": n, "message": "queued" })).into_response()
}

// ───────────────────────────── Beats (Elasticsearch API) ─────────────────────────────

fn beats_port() -> u16 {
    std::env::var("SIEM_BEATS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9201)
}

/// The documents of a bulk body (action line, document line, ...): (Windows events, other lines).
fn bulk_docs(body: &str) -> (Vec<WinEvent>, Vec<String>) {
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    let (mut win, mut other) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i + 1 < lines.len() && win.len() + other.len() < MAX_DOCS {
        let action: Value = serde_json::from_str(lines[i]).unwrap_or(Value::Null);
        let doc: Value = serde_json::from_str(lines[i + 1]).unwrap_or(Value::Null);
        i += 2;
        if action.get("delete").is_some() {
            i -= 1; // a delete has no document line
            continue;
        }
        match from_json(&doc) {
            Some(e) => win.push(e),
            None => other.push(doc["message"].as_str().map(String::from).unwrap_or_else(|| doc.to_string())),
        }
    }
    (win, other)
}

async fn bulk(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let src = match authorise(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let (win, other) = bulk_docs(&String::from_utf8_lossy(&body));
    let n = analyse_windows(&state, &src, win) + analyse_lines(&state, &src, "beats", other);
    Json(json!({ "took": 1, "errors": false, "items": (0..n).map(|_| json!({ "index": { "result": "created", "status": 201 } })).collect::<Vec<_>>() })).into_response()
}

fn es_info() -> Value {
    json!({ "name": "provigil-siem", "cluster_name": "provigil", "cluster_uuid": "provigil-siem-001",
            "version": { "number": "8.11.0", "build_flavor": "default", "minimum_wire_compatibility_version": "7.17.0", "minimum_index_compatibility_version": "7.0.0" },
            "tagline": "You Know, for Logs" })
}

/// The Elasticsearch-compatible listener Beats send to.
pub fn serve_beats(state: AppState) {
    let port = beats_port();
    if port == 0 {
        return;
    }
    let ack = || async { Json(json!({ "acknowledged": true })) };
    let app = Router::new()
        .route("/", get(|| async { Json(es_info()) }).head(|| async { StatusCode::OK }))
        .route("/_license", get(|| async { Json(json!({ "license": { "uid": "provigil-license", "type": "basic", "status": "active" } })) }))
        .route("/_xpack", get(|| async { Json(json!({ "build": { "hash": "provigil", "date": "2024-01-01" }, "license": { "uid": "provigil", "type": "basic", "status": "active" }, "features": {} })) }))
        .route("/_index_template/:name", put(ack).get(ack).head(|| async { StatusCode::OK }))
        .route("/_component_template/:name", put(ack).get(ack))
        .route("/_ilm/policy/:name", put(ack).get(ack))
        .route("/_ingest/pipeline/:name", put(ack).get(ack))
        .route("/_data_stream/:name", put(ack).get(ack))
        .route("/_bulk", post(bulk))
        .route("/:index/_bulk", post(bulk))
        .route("/:index", head(|| async { StatusCode::OK }).put(ack))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(state);
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
            Ok(l) => {
                tracing::info!("Beats intake (Elasticsearch API) on :{port}");
                let _ = axum::serve(l, app).await;
            }
            Err(e) => tracing::warn!("Beats intake: cannot listen on :{port}: {e}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_from_headers() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer pvk_abc".parse().unwrap());
        assert_eq!(key_of(&h).as_deref(), Some("pvk_abc"));
        use base64::Engine as _;
        h.insert("authorization", format!("ApiKey {}", base64::engine::general_purpose::STANDARD.encode("ingest:pvk_xyz")).parse().unwrap());
        assert_eq!(key_of(&h).as_deref(), Some("pvk_xyz"));
        h.insert("authorization", "Basic dXNlcjpwdw==".parse().unwrap());
        assert_eq!(key_of(&h), None);
        assert_eq!(sha256_hex(" pvk_abc "), sha256_hex("pvk_abc"), "spaces around a pasted key do not matter");
    }

    #[test]
    fn winlogbeat_to_the_manager_format() {
        let doc = json!({ "@timestamp": "2026-11-24T10:00:00Z", "message": "A new process has been created.",
            "host": { "name": "PC-01" },
            "winlog": { "event_id": 4688, "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing", "computer_name": "PC-01.acme.local",
                        "record_id": 77, "event_data": { "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami" } } });
        let ev = from_json(&doc).unwrap();
        assert_eq!((ev.event_id.as_str(), ev.channel.as_str(), ev.computer.as_str()), ("4688", "Security", "PC-01.acme.local"));
        let m = manager_event(&ev, "ingest-1234abcd", "wec-1");
        assert_eq!(m["data"]["win"]["system"]["eventID"], "4688");
        assert_eq!(m["data"]["win"]["eventdata"]["commandLine"], "cmd /c whoami");
        assert_eq!(m["agent"]["name"], "PC-01.acme.local");
        assert!(from_json(&json!({ "message": "plain filebeat line" })).is_none());
    }

    #[test]
    fn nxlog_json() {
        let ev = from_json(&json!({ "EventID": 4625, "Channel": "Security", "SourceName": "Microsoft-Windows-Security-Auditing", "Hostname": "DC1", "TargetUserName": "admin", "Message": "logon failed" })).unwrap();
        assert_eq!(ev.event_id, "4625");
        assert_eq!(ev.provider, "Microsoft-Windows-Security-Auditing");
        assert!(ev.data.contains(&("TargetUserName".to_string(), "admin".to_string())));
        assert!(!ev.data.iter().any(|(k, _)| k == "EventID"), "system fields are not event data");
    }

    #[test]
    fn wec_xml() {
        let xml = r#"<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{x}"/><EventID>4624</EventID><Level>0</Level><TimeCreated SystemTime="2026-11-24T10:00:00.000Z"/><EventRecordID>9</EventRecordID><Channel>Security</Channel><Computer>PC-02</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="LogonType">3</Data><Data Name="Empty"/></EventData></Event><Event><System><EventID>7045</EventID><Channel>System</Channel><Computer>PC-03</Computer></System><EventData><Data Name="ServiceName">evil</Data></EventData></Event></Events>"#;
        let evs = from_xml(xml);
        assert_eq!(evs.len(), 2);
        assert_eq!((evs[0].event_id.as_str(), evs[0].provider.as_str(), evs[0].computer.as_str(), evs[0].time.as_str()), ("4624", "Microsoft-Windows-Security-Auditing", "PC-02", "2026-11-24T10:00:00.000Z"));
        assert!(evs[0].data.contains(&("TargetUserName".to_string(), "alice".to_string())) && evs[0].data.contains(&("LogonType".to_string(), "3".to_string())));
        assert_eq!(evs[1].data, vec![("ServiceName".to_string(), "evil".to_string())]);
    }

    #[test]
    fn bulk_bodies() {
        let body = "{\"index\":{\"_index\":\"winlogbeat-8\"}}\n{\"winlog\":{\"event_id\":4720,\"channel\":\"Security\",\"event_data\":{\"TargetUserName\":\"bob\"}}}\n{\"create\":{}}\n{\"message\":\"sshd[1]: Failed password for root\"}\n{\"delete\":{\"_id\":\"1\"}}\n";
        let (win, other) = bulk_docs(body);
        assert_eq!(win.len(), 1);
        assert_eq!(other, vec!["sshd[1]: Failed password for root".to_string()]);
        assert_eq!(lower_camel("TargetUserName"), "targetUserName");
    }
}
