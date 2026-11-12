//! The full case view: everything one case page shows, in one call, and the case actions that
//! the case list did not have. The case row itself (`soar_cases`, shared with the NDR side) is
//! not changed: the extra fields live in `soar_case_details`, the history in
//! `soar_case_events` (the case journey) and files in `soar_case_attachments`.
//!
//! `GET  /api/soar/cases/:id/detail`        case, details, SLA, alerts, entities with risk,
//!                                          journey, attachments, similar cases
//! `PUT  /api/soar/cases/:id/details`       category, subcategory
//! `PUT  /api/soar/cases/:id/disposition`   disposition (+ note)
//! `POST /api/soar/cases/:id/resolve`       disposition + resolution, closes the case
//! `POST /api/soar/cases/:id/attachments`   a file (base64, at most 10 MB)
//! `GET  /api/soar/cases/:id/attachments/:att`  download

use axum::extract::{Extension, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

pub const DDL: [&str; 3] = [
    "CREATE TABLE IF NOT EXISTS soar_case_details (case_id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY case_id",
    "CREATE TABLE IF NOT EXISTS soar_case_events (id String, case_id String, at DateTime64(3), actor String, kind String, detail String) ENGINE = MergeTree ORDER BY (case_id, at)",
    "CREATE TABLE IF NOT EXISTS soar_case_attachments (id String, case_id String, name String, mime String, size UInt64, sha256 String, data String, uploaded_by String, at DateTime) ENGINE = MergeTree ORDER BY (case_id, at)",
];

pub const DISPOSITIONS: [&str; 5] = ["True Positive", "False Positive", "Benign", "Duplicate", "Undetermined"];
const MAX_ATTACHMENT: usize = 10 * 1024 * 1024;

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Details {
    #[serde(default)]
    pub disposition: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub subcategory: String,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub resolution: String,
}

/// Hours to resolve by priority.
pub fn sla_hours(priority: &str) -> u64 {
    match priority {
        "P1" => 4,
        "P2" => 24,
        "P3" => 72,
        _ => 168,
    }
}

/// The SLA state: open cases are On Track, At Risk (under a quarter of the time left) or
/// Breached; closed ones Met or Missed.
pub fn sla_state(created: u64, due: u64, closed: Option<u64>, now: u64) -> &'static str {
    match closed {
        Some(c) if c <= due => "Met",
        Some(_) => "Missed",
        None if now > due => "Breached",
        None if (due - now) * 4 < due.saturating_sub(created) => "At Risk",
        None => "On Track",
    }
}

async fn details(state: &AppState, tenant: &str, case_id: &str) -> Details {
    state
        .db
        .tenant_client(tenant)
        .query("SELECT doc FROM soar_case_details FINAL WHERE case_id = ?")
        .bind(case_id)
        .fetch_optional::<String>()
        .await
        .ok()
        .flatten()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default()
}

async fn save_details(state: &AppState, tenant: &str, case_id: &str, d: &Details) -> Result<(), String> {
    state
        .db
        .tenant_client(tenant)
        .query("INSERT INTO soar_case_details (case_id, doc, version) VALUES (?, ?, ?)")
        .bind(case_id)
        .bind(serde_json::to_string(d).map_err(|e| e.to_string())?)
        .bind(chrono::Utc::now().timestamp_micros().max(0) as u64)
        .execute()
        .await
        .map_err(|e| e.to_string())
}

/// One step of the case journey (created, assigned, status, disposition, note, file, ...).
pub async fn journey(state: &AppState, tenant: &str, case_id: &str, actor: &str, kind: &str, detail: &str) {
    let r = state
        .db
        .tenant_client(tenant)
        .query("INSERT INTO soar_case_events (id, case_id, at, actor, kind, detail) VALUES (?, ?, now64(3), ?, ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(case_id)
        .bind(actor)
        .bind(kind)
        .bind(detail.chars().take(2000).collect::<String>())
        .execute()
        .await;
    if let Err(e) = r {
        tracing::warn!("case {case_id}: journey step '{kind}' not stored: {e}");
    }
}

/// Who opened the case, at creation.
pub async fn created(state: &AppState, tenant: &str, case_id: &str, by: &str) {
    let mut d = details(state, tenant, case_id).await;
    d.created_by = by.to_string();
    let _ = save_details(state, tenant, case_id, &d).await;
    journey(state, tenant, case_id, by, "created", "Case opened").await;
}

#[derive(clickhouse::Row, Deserialize)]
struct CaseRow {
    id: String,
    case_number: String,
    title: String,
    description: String,
    severity: String,
    priority: String,
    status: String,
    assigned_to: String,
    src_ip: String,
    dst_ip: String,
    hit_ids: Vec<String>,
    tags: Vec<String>,
    created: u32,
    updated: u32,
    closed: Option<u32>,
}

#[derive(clickhouse::Row, Deserialize, Serialize)]
struct AlertRow {
    id: String,
    timestamp: u64,
    agent_id: String,
    agent_name: String,
    rule_id: u32,
    rule_level: u8,
    rule_description: String,
    mitre_id: String,
    mitre_tactic: String,
    src_ip: String,
    dst_ip: String,
    user: String,
    location: String,
}

fn bad(m: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": m }))).into_response()
}

async fn case_row(state: &AppState, tenant: &str, id: &str) -> Option<CaseRow> {
    state
        .db
        .tenant_client(tenant)
        .query("SELECT id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, hit_ids, tags, toUInt32(toUnixTimestamp(created_at)) AS created, toUInt32(toUnixTimestamp(updated_at)) AS updated, toUInt32(toUnixTimestamp(closed_at)) AS closed FROM soar_cases FINAL WHERE id = ?")
        .bind(id)
        .fetch_optional::<CaseRow>()
        .await
        .ok()
        .flatten()
}

/// `GET /api/soar/cases/:id/detail`
pub async fn detail(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    let t = ctx.scope();
    let Some(c) = case_row(&state, &t, &id).await else {
        return (StatusCode::NOT_FOUND, Json(json!({ "status": "error", "message": "Case not found" }))).into_response();
    };
    let db = state.db.tenant_client(&t);
    let d = details(&state, &t, &id).await;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let due = c.created as u64 + sla_hours(&c.priority) * 3600;
    let alerts: Vec<AlertRow> = if c.hit_ids.is_empty() {
        Vec::new()
    } else {
        db.query("SELECT id, timestamp, agent_id, agent_name, rule_id, rule_level, rule_description, mitre_id, mitre_tactic, src_ip, dst_ip, user, location FROM siem_alerts WHERE id IN ? ORDER BY timestamp LIMIT 500")
            .bind(&c.hit_ids)
            .fetch_all()
            .await
            .unwrap_or_default()
    };

    // the entities: hosts, users and addresses from the case and its alerts, with their risk
    let host_scores: std::collections::HashMap<String, f64> = crate::posture::latest_today(&state, &t)
        .await
        .map(|d| d.posture.hosts.into_iter().map(|h| (h.agent_id, h.score)).collect())
        .unwrap_or_default();
    let mut entities: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for a in &alerts {
        if !a.agent_id.is_empty() && seen.insert(("host", a.agent_id.clone())) {
            let score = host_scores.get(&a.agent_id).copied();
            entities.push(json!({ "type": "host", "value": a.agent_name, "id": a.agent_id, "posture": score, "risk": score.map(|s| (100.0 - s).round()) }));
        }
        if !a.user.is_empty() && seen.insert(("user", a.user.clone())) {
            entities.push(json!({ "type": "user", "value": a.user }));
        }
    }
    let ips: Vec<String> = [c.src_ip.clone(), c.dst_ip.clone()].into_iter().chain(alerts.iter().flat_map(|a| [a.src_ip.clone(), a.dst_ip.clone()])).filter(|i| !i.is_empty()).collect();
    let bad_ips: std::collections::HashSet<String> = if ips.is_empty() {
        Default::default()
    } else {
        state.db.root().query("SELECT ioc_value FROM ndr.siem_threat_intel WHERE ioc_value IN ?").bind(&ips).fetch_all::<String>().await.unwrap_or_default().into_iter().collect()
    };
    for ip in ips {
        if seen.insert(("ip", ip.clone())) {
            let hit = bad_ips.contains(&ip);
            entities.push(json!({ "type": "ip", "value": ip, "threat_intel": hit, "risk": if hit { 100 } else { 0 }, "geo": crate::geomap::describe(&ip) }));
        }
    }

    let journey: Vec<Value> = db
        .query("SELECT toString(at), actor, kind, detail FROM soar_case_events WHERE case_id = ? ORDER BY at")
        .bind(&id)
        .fetch_all::<(String, String, String, String)>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| json!({ "at": r.0, "actor": r.1, "kind": r.2, "detail": r.3 }))
        .collect();
    let attachments: Vec<Value> = db
        .query("SELECT id, name, mime, size, sha256, uploaded_by, toUInt32(toUnixTimestamp(at)) FROM soar_case_attachments WHERE case_id = ? ORDER BY at")
        .bind(&id)
        .fetch_all::<(String, String, String, u64, String, String, u32)>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| json!({ "id": r.0, "name": r.1, "mime": r.2, "size": r.3, "sha256": r.4, "uploaded_by": r.5, "at": r.6 }))
        .collect();
    // similar: other cases of the same addresses or hosts in the last 90 days
    let hosts: Vec<String> = alerts.iter().map(|a| a.agent_name.clone()).filter(|h| !h.is_empty()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    let similar: Vec<Value> = db
        .query("SELECT id, case_number, title, status, toUInt32(toUnixTimestamp(created_at)) FROM soar_cases FINAL WHERE id != ? AND created_at > now() - INTERVAL 90 DAY AND ((src_ip != '' AND src_ip IN (?, ?)) OR (dst_ip != '' AND dst_ip IN (?, ?)) OR arrayExists(h -> positionCaseInsensitive(title, h) > 0, ?)) ORDER BY created_at DESC LIMIT 10")
        .bind(&id)
        .bind(&c.src_ip)
        .bind(&c.dst_ip)
        .bind(&c.src_ip)
        .bind(&c.dst_ip)
        .bind(&hosts)
        .fetch_all::<(String, String, String, String, u32)>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| json!({ "id": r.0, "case_number": r.1, "title": r.2, "status": r.3, "created_at": r.4 }))
        .collect();

    Json(json!({
        "status": "ok",
        "case": {
            "id": c.id, "case_number": c.case_number, "title": c.title, "description": c.description, "severity": c.severity,
            "priority": c.priority, "status": c.status, "assigned_to": c.assigned_to, "src_ip": c.src_ip, "dst_ip": c.dst_ip,
            "hit_ids": c.hit_ids, "tags": c.tags, "created_at": c.created, "updated_at": c.updated, "closed_at": c.closed,
        },
        "details": d,
        "sla": { "hours": sla_hours(&c.priority), "due": due, "state": sla_state(c.created as u64, due, c.closed.map(u64::from), now) },
        "alerts": alerts,
        "entities": entities,
        "journey": journey,
        "attachments": attachments,
        "similar": similar,
        "dispositions": DISPOSITIONS,
    }))
    .into_response()
}

/// `PUT /api/soar/cases/:id/details`: category and subcategory.
pub async fn set_details(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Response {
    let t = ctx.scope();
    if case_row(&state, &t, &id).await.is_none() {
        return bad("Case not found");
    }
    let mut d = details(&state, &t, &id).await;
    let clip = |k: &str| p[k].as_str().map(|s| s.trim().chars().take(80).collect::<String>());
    if let Some(v) = clip("category") {
        d.category = v;
    }
    if let Some(v) = clip("subcategory") {
        d.subcategory = v;
    }
    match save_details(&state, &t, &id, &d).await {
        Ok(()) => {
            journey(&state, &t, &id, &ctx.username, "details", &format!("Category: {} / {}", d.category, d.subcategory)).await;
            Json(json!({ "status": "success", "details": d })).into_response()
        }
        Err(e) => bad(&e),
    }
}

fn disposition_of(p: &Value) -> Option<&'static str> {
    let want = p["disposition"].as_str()?;
    DISPOSITIONS.iter().copied().find(|d| d.eq_ignore_ascii_case(want))
}

/// `PUT /api/soar/cases/:id/disposition`
pub async fn set_disposition(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Response {
    let t = ctx.scope();
    let Some(disp) = disposition_of(&p) else {
        return bad("Disposition must be one of: True Positive, False Positive, Benign, Duplicate, Undetermined");
    };
    if case_row(&state, &t, &id).await.is_none() {
        return bad("Case not found");
    }
    let mut d = details(&state, &t, &id).await;
    let before = std::mem::replace(&mut d.disposition, disp.to_string());
    if let Err(e) = save_details(&state, &t, &id, &d).await {
        return bad(&e);
    }
    let note = p["note"].as_str().unwrap_or("").trim();
    let from = if before.is_empty() { "none".to_string() } else { before };
    journey(&state, &t, &id, &ctx.username, "disposition", &format!("{from} -> {disp}{}", if note.is_empty() { String::new() } else { format!(": {note}") })).await;
    Json(json!({ "status": "success", "details": d })).into_response()
}

/// `POST /api/soar/cases/:id/resolve`: disposition and resolution, then the case is closed
/// (as a status change from the case list: security memory learns from it).
pub async fn resolve(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Response {
    let t = ctx.scope();
    let Some(disp) = disposition_of(&p) else {
        return bad("Choose a disposition to resolve the case");
    };
    let resolution = p["resolution"].as_str().unwrap_or("").trim().chars().take(4000).collect::<String>();
    if resolution.is_empty() {
        return bad("Describe the resolution");
    }
    if case_row(&state, &t, &id).await.is_none() {
        return bad("Case not found");
    }
    let mut d = details(&state, &t, &id).await;
    d.disposition = disp.to_string();
    d.resolution = resolution.clone();
    if let Err(e) = save_details(&state, &t, &id, &d).await {
        return bad(&e);
    }
    // the status change goes through the case list's own path (closing time, security memory)
    let r = crate::soar::update_case_status(State(state.clone()), Extension(ctx.clone()), Path(id.clone()), Json(json!({ "status": "Resolved" }))).await;
    if r.0["status"] != "success" {
        return (StatusCode::INTERNAL_SERVER_ERROR, r).into_response();
    }
    journey(&state, &t, &id, &ctx.username, "resolved", &format!("{disp}: {resolution}")).await;
    Json(json!({ "status": "success", "details": d })).into_response()
}

/// `POST /api/soar/cases/:id/attachments` `{ "name", "mime", "data" (base64) }`
pub async fn add_attachment(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Response {
    use sha2::{Digest, Sha256};
    let t = ctx.scope();
    let name: String = p["name"].as_str().unwrap_or("").trim().chars().filter(|c| !c.is_control() && !matches!(c, '/' | '\\')).take(200).collect();
    if name.is_empty() {
        return bad("The file needs a name");
    }
    let Some(bytes) = p["data"].as_str().and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok()) else {
        return bad("The file content is not valid base64");
    };
    if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT {
        return bad("A file must be between 1 byte and 10 MB");
    }
    if case_row(&state, &t, &id).await.is_none() {
        return bad("Case not found");
    }
    let mime = p["mime"].as_str().filter(|m| !m.is_empty() && m.len() < 100).unwrap_or("application/octet-stream").to_string();
    let sha = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
    let att = uuid::Uuid::new_v4().to_string();
    let r = state
        .db
        .tenant_client(&t)
        .query("INSERT INTO soar_case_attachments (id, case_id, name, mime, size, sha256, data, uploaded_by, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, now())")
        .bind(&att)
        .bind(&id)
        .bind(&name)
        .bind(&mime)
        .bind(bytes.len() as u64)
        .bind(&sha)
        .bind(base64::engine::general_purpose::STANDARD.encode(&bytes))
        .bind(&ctx.username)
        .execute()
        .await;
    match r {
        Ok(()) => {
            journey(&state, &t, &id, &ctx.username, "attachment", &format!("{name} ({} bytes, sha256 {sha})", bytes.len())).await;
            Json(json!({ "status": "success", "id": att, "sha256": sha })).into_response()
        }
        Err(e) => bad(&e.to_string()),
    }
}

/// `GET /api/soar/cases/:id/attachments/:att`: the file, as a download (never shown inline).
pub async fn get_attachment(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path((id, att)): Path<(String, String)>) -> Response {
    let row = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT name, data FROM soar_case_attachments WHERE case_id = ? AND id = ?")
        .bind(&id)
        .bind(&att)
        .fetch_optional::<(String, String)>()
        .await
        .ok()
        .flatten();
    let Some((name, data)) = row else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Attachment unreadable").into_response();
    };
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{safe}\"")),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sla_states() {
        let (c, h) = (1_000_000u64, 24 * 3600);
        let due = c + h;
        assert_eq!(sla_state(c, due, None, c + 3600), "On Track");
        assert_eq!(sla_state(c, due, None, due - 3600), "At Risk", "under a quarter of the time left");
        assert_eq!(sla_state(c, due, None, due + 1), "Breached");
        assert_eq!(sla_state(c, due, Some(due - 10), due + 99), "Met");
        assert_eq!(sla_state(c, due, Some(due + 10), due + 99), "Missed");
        assert_eq!(sla_hours("P1"), 4);
        assert_eq!(sla_hours("P4"), 168);
    }

    #[test]
    fn dispositions_are_a_fixed_list() {
        assert_eq!(disposition_of(&json!({ "disposition": "false positive" })), Some("False Positive"));
        assert_eq!(disposition_of(&json!({ "disposition": "maybe" })), None);
    }
}
