//! Deployment tokens: what a mass-deployment kit enrolls agents with instead of the tenant key
//! (specs/provigil-mass-deploy.md, C2). A token names its tenant, expires, enrolls at most
//! `max_enrollments` PCs and can be revoked; only its SHA-256 is stored. Agents keep sending the
//! token they enrolled with, so an expired or revoked token still identifies its tenant for them
//! (here and in the gateway's `cache.rs`); it only stops new enrollments.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, RwLock};

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// In the main database, next to `tenant_agent_keys`: the gateway reads it there.
const DDL: [&str; 3] = [
    "CREATE TABLE IF NOT EXISTS deploy_tokens (id String, tenant_id String, label String, token_hash String, groups String DEFAULT '', created_by String DEFAULT '', created_at UInt64, expires_at UInt64, max_enrollments UInt32, revoked UInt8 DEFAULT 0, updated_at UInt64) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id",
    "CREATE TABLE IF NOT EXISTS deploy_enrollments (token_id String, agent_id String, tenant_id String, agent_name String, at UInt64) ENGINE = ReplacingMergeTree(at) ORDER BY (token_id, agent_id)",
    // one row per PC of a deployment (C7), the latest report wins
    "CREATE TABLE IF NOT EXISTS deploy_targets (token_id String, tenant_id String, target String, computer String, address String, os String, method String, outcome String, reason String, agent_id String, reported_from String, at UInt64) ENGINE = ReplacingMergeTree(at) ORDER BY (token_id, target)",
];

/// The outcomes a deployment report may give (anything else is stored as "failed").
const OUTCOMES: [&str; 8] = ["installed", "already installed", "failed", "access denied", "unreachable", "not a PC", "not supported", "skipped"];
const MAX_REPORT_ROWS: usize = 1000;

pub const PREFIX: &str = "pvd_";
const DEFAULT_DAYS: u64 = 7;
const MAX_DAYS: u64 = 90;
const MAX_ENROLLMENTS: u32 = 100_000;

#[derive(Clone, Debug, clickhouse::Row, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub tenant_id: String,
    pub label: String,
    pub token_hash: String,
    pub groups: String,
    pub created_by: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_enrollments: u32,
    pub revoked: u8,
    pub updated_at: u64,
}

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct Enrollment {
    token_id: String,
    agent_id: String,
    tenant_id: String,
    agent_name: String,
    at: u64,
}

#[derive(Clone, clickhouse::Row, Serialize, Deserialize)]
struct Target {
    token_id: String,
    tenant_id: String,
    target: String,
    computer: String,
    address: String,
    os: String,
    method: String,
    outcome: String,
    reason: String,
    agent_id: String,
    reported_from: String,
    at: u64,
}

/// A report row as stored: text cut short and cleaned, the outcome one of `OUTCOMES`; `None`
/// without a computer name or address.
fn target_of(t: &Token, from: &str, r: &Value, now: u64) -> Option<Target> {
    let f = |k: &str, n: usize| -> String { r[k].as_str().unwrap_or("").chars().filter(|c| !c.is_control()).take(n).collect::<String>().trim().to_string() };
    let (computer, address) = (f("computer", 128), f("address", 64));
    let target = if computer.is_empty() { address.clone() } else { computer.to_lowercase() };
    if target.is_empty() {
        return None;
    }
    let outcome = f("outcome", 32);
    let outcome = if OUTCOMES.contains(&outcome.as_str()) { outcome } else { "failed".into() };
    Some(Target { token_id: t.id.clone(), tenant_id: t.tenant_id.clone(), target, computer, address, os: f("os", 128), method: f("method", 32), outcome, reason: f("reason", 500), agent_id: f("agent_id", 32), reported_from: from.chars().filter(|c| !c.is_control()).take(128).collect(), at: now })
}

#[derive(Default)]
struct Store {
    /// hex SHA-256 -> token
    by_hash: HashMap<String, Token>,
    /// token id -> agent ids it enrolled
    enrolled: HashMap<String, HashSet<String>>,
}

static STORE: LazyLock<RwLock<Store>> = LazyLock::new(Default::default);

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn hash_hex(k: &str) -> String {
    Sha256::digest(k.trim().as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn is_token(k: &str) -> bool {
    k.trim().starts_with(PREFIX)
}

/// The tenant of a token, whatever its state (for agents that enrolled with it).
pub fn tenant_of(k: &str) -> Option<String> {
    is_token(k).then(|| STORE.read().unwrap().by_hash.get(&hash_hex(k)).map(|t| t.tenant_id.clone())).flatten()
}

/// Whether a token may enroll this PC: `already` when the PC enrolled with it before (a
/// reinstall, which does not count again).
fn decide(t: &Token, used: usize, already: bool, now: u64) -> Result<(), String> {
    if t.revoked != 0 {
        return Err(format!("The deployment token \"{}\" was revoked", t.label));
    }
    if t.expires_at <= now {
        return Err(format!("The deployment token \"{}\" has expired", t.label));
    }
    if !already && used >= t.max_enrollments as usize {
        return Err(format!("The deployment token \"{}\" has enrolled its maximum of {} PCs", t.label, t.max_enrollments));
    }
    Ok(())
}

/// The token for an enrollment, or why it is refused. `existing`: the agent id this PC already
/// has in the tenant (same name), if any.
pub fn check_enroll(k: &str, existing: Option<&str>) -> Result<Token, String> {
    let s = STORE.read().unwrap();
    let t = s.by_hash.get(&hash_hex(k)).ok_or_else(|| "Unknown deployment token".to_string())?;
    let set = s.enrolled.get(&t.id);
    let already = existing.is_some_and(|id| set.is_some_and(|e| e.contains(id)));
    decide(t, set.map_or(0, |e| e.len()), already, now_ms())?;
    Ok(t.clone())
}

/// Records that `token` enrolled this agent (once per agent).
pub async fn record(state: &AppState, token: &Token, agent_id: &str, agent_name: &str) {
    let new = STORE.write().unwrap().enrolled.entry(token.id.clone()).or_default().insert(agent_id.to_string());
    if !new {
        return;
    }
    let row = Enrollment { token_id: token.id.clone(), agent_id: agent_id.into(), tenant_id: token.tenant_id.clone(), agent_name: agent_name.into(), at: now_ms() };
    if let Err(e) = insert(state, "deploy_enrollments", &row).await {
        tracing::warn!("deploy_enrollments: {e}");
    }
}

async fn insert<T: clickhouse::Row + Serialize>(state: &AppState, table: &str, row: &T) -> Result<(), String> {
    let mut ins = state.db.main().insert(table).map_err(|e| e.to_string())?;
    ins.write(row).await.map_err(|e| e.to_string())?;
    ins.end().await.map_err(|e| e.to_string())
}

/// Creates the tables and loads the tokens and their enrollments (at start).
pub async fn load(state: &AppState) {
    for ddl in DDL {
        if let Err(e) = state.db.main().query(ddl).execute().await {
            tracing::warn!("deploy tokens table: {e}");
        }
    }
    let tokens: Vec<Token> = state.db.main().query("SELECT ?fields FROM deploy_tokens FINAL").fetch_all().await.unwrap_or_default();
    let used: Vec<(String, String)> = state.db.main().query("SELECT token_id, agent_id FROM deploy_enrollments FINAL").fetch_all().await.unwrap_or_default();
    let mut s = STORE.write().unwrap();
    s.by_hash = tokens.into_iter().map(|t| (t.token_hash.clone(), t)).collect();
    s.enrolled.clear();
    for (t, a) in used {
        s.enrolled.entry(t).or_default().insert(a);
    }
    tracing::info!("Loaded {} deployment tokens", s.by_hash.len());
}

fn view(t: &Token, used: usize) -> Value {
    let now = now_ms();
    let state = if t.revoked != 0 { "revoked" } else if t.expires_at <= now { "expired" } else if used >= t.max_enrollments as usize { "used up" } else { "active" };
    json!({ "id": t.id, "label": t.label, "groups": t.groups, "created_by": t.created_by, "created_at": t.created_at / 1000, "expires_at": t.expires_at / 1000, "max_enrollments": t.max_enrollments, "enrolled": used, "state": state })
}

fn bad(code: StatusCode, m: &str) -> Response {
    (code, Json(json!({ "status": "error", "message": m }))).into_response()
}

/// `GET /api/v1/deploy/tokens` (tenant admin)
pub async fn list(Extension(ctx): Extension<AuthCtx>) -> Response {
    let t = ctx.scope();
    if !ctx.can_manage(&t) {
        return crate::tenancy::forbidden();
    }
    let s = STORE.read().unwrap();
    let mut rows: Vec<&Token> = s.by_hash.values().filter(|x| x.tenant_id == t).collect();
    rows.sort_by_key(|x| std::cmp::Reverse(x.created_at));
    let out: Vec<Value> = rows.iter().map(|x| view(x, s.enrolled.get(&x.id).map_or(0, |e| e.len()))).collect();
    Json(json!({ "status": "ok", "tokens": out })).into_response()
}

/// `POST /api/v1/deploy/tokens` `{label, days, max, groups}` (tenant admin): the token is in the
/// answer only, never stored or shown again.
pub async fn create(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(p): Json<Value>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return crate::tenancy::forbidden();
    }
    let label: String = p["label"].as_str().unwrap_or("").trim().chars().filter(|c| !c.is_control()).take(80).collect();
    if label.is_empty() {
        return bad(StatusCode::BAD_REQUEST, "Give the deployment a name (for example \"Head office, November\")");
    }
    let days = p["days"].as_u64().unwrap_or(DEFAULT_DAYS);
    let max = p["max"].as_u64().unwrap_or(0);
    if !(1..=MAX_DAYS).contains(&days) || !(1..=MAX_ENROLLMENTS as u64).contains(&max) {
        return bad(StatusCode::BAD_REQUEST, "Valid for 1 to 90 days, for 1 to 100000 PCs");
    }
    let groups: String = p["groups"].as_str().unwrap_or("").trim().chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, ',' | '-' | '_' | '.')).take(200).collect();
    // a group that does not exist would refuse every PC at enrollment: refuse it here instead
    let asked: Vec<String> = groups.split(',').map(str::to_string).collect();
    if let Err(m) = crate::groups::resolve(&tenant, &asked) {
        return bad(StatusCode::BAD_REQUEST, &format!("{m}: create the group first (Agent Groups), or leave groups empty"));
    }
    let id = uuid::Uuid::new_v4().simple().to_string();
    let secret = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let token = format!("{PREFIX}{}_{secret}", &id[..8]);
    let now = now_ms();
    let row = Token {
        id,
        tenant_id: tenant,
        label,
        token_hash: hash_hex(&token),
        groups,
        created_by: ctx.username.clone(),
        created_at: now,
        expires_at: now + days * 86_400_000,
        max_enrollments: max as u32,
        revoked: 0,
        updated_at: now,
    };
    if let Err(e) = insert(&state, "deploy_tokens", &row).await {
        return bad(StatusCode::INTERNAL_SERVER_ERROR, &format!("The token could not be stored: {e}"));
    }
    STORE.write().unwrap().by_hash.insert(row.token_hash.clone(), row.clone());
    Json(json!({ "status": "ok", "token": token, "info": view(&row, 0) })).into_response()
}

/// `DELETE /api/v1/deploy/tokens/:id` (tenant admin): no new enrollments; enrolled PCs stay.
pub async fn revoke(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return crate::tenancy::forbidden();
    }
    let found = STORE.read().unwrap().by_hash.values().find(|t| t.id == id && t.tenant_id == tenant).cloned();
    let Some(mut t) = found else {
        return bad(StatusCode::NOT_FOUND, "No such deployment token");
    };
    t.revoked = 1;
    t.updated_at = now_ms();
    if let Err(e) = insert(&state, "deploy_tokens", &t).await {
        return bad(StatusCode::INTERNAL_SERVER_ERROR, &format!("The token could not be revoked: {e}"));
    }
    STORE.write().unwrap().by_hash.insert(t.token_hash.clone(), t);
    Json(json!({ "status": "ok" })).into_response()
}

/// A deployment's results from `provigil-deploy report`, through the gateway (it checked the
/// token is known): `{token, from, rows}`. Accepted for expired and revoked tokens too: a run's
/// last results may come after.
pub async fn report(state: &AppState, v: &Value) -> Result<usize, (StatusCode, String)> {
    let key = v["token"].as_str().unwrap_or_default();
    let t = STORE.read().unwrap().by_hash.get(&hash_hex(key)).cloned().ok_or((StatusCode::UNAUTHORIZED, "Unknown deployment token".to_string()))?;
    let rows = v["rows"].as_array().map(Vec::as_slice).unwrap_or_default();
    if rows.len() > MAX_REPORT_ROWS {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, format!("At most {MAX_REPORT_ROWS} rows per report")));
    }
    let now = now_ms();
    let from = v["from"].as_str().unwrap_or_default();
    let targets: Vec<Target> = rows.iter().filter_map(|r| target_of(&t, from, r, now)).collect();
    if targets.is_empty() {
        return Ok(0);
    }
    let mut ins = state.db.main().insert::<Target>("deploy_targets").map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    for x in &targets {
        ins.write(x).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    ins.end().await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(targets.len())
}

/// `GET /api/v1/deploy/tokens/:id/targets` (tenant admin): every PC the deployment reported, and
/// the agents it enrolled (some may have enrolled without a report, e.g. by Group Policy).
pub async fn targets(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return crate::tenancy::forbidden();
    }
    let info = {
        let s = STORE.read().unwrap();
        s.by_hash.values().find(|t| t.id == id && t.tenant_id == tenant).map(|t| view(t, s.enrolled.get(&t.id).map_or(0, |e| e.len())))
    };
    let Some(info) = info else {
        return bad(StatusCode::NOT_FOUND, "No such deployment token");
    };
    let db = state.db.main();
    let rows: Vec<Target> = match db.query("SELECT ?fields FROM deploy_targets FINAL WHERE token_id = ? AND tenant_id = ? ORDER BY outcome, target LIMIT 100000").bind(&id).bind(&tenant).fetch_all().await {
        Ok(r) => r,
        Err(e) => return bad(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let enrolled: Vec<Enrollment> = db.query("SELECT ?fields FROM deploy_enrollments FINAL WHERE token_id = ? AND tenant_id = ? ORDER BY at").bind(&id).bind(&tenant).fetch_all().await.unwrap_or_default();
    let rows: Vec<Value> = rows.iter().map(|r| json!({ "computer": r.computer, "address": r.address, "os": r.os, "method": r.method, "outcome": r.outcome, "reason": r.reason, "agent_id": r.agent_id, "from": r.reported_from, "at": r.at / 1000 })).collect();
    let enrolled: Vec<Value> = enrolled.iter().map(|e| json!({ "agent_id": e.agent_id, "agent_name": e.agent_name, "at": e.at / 1000 })).collect();
    Json(json!({ "status": "ok", "token": info, "targets": rows, "enrolled": enrolled })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(max: u32, expires_at: u64, revoked: u8) -> Token {
        Token { id: "t1".into(), tenant_id: "acme".into(), label: "HQ".into(), token_hash: String::new(), groups: String::new(), created_by: String::new(), created_at: 0, expires_at, max_enrollments: max, revoked, updated_at: 0 }
    }

    #[test]
    fn a_token_enrolls_up_to_its_maximum_until_it_expires_or_is_revoked() {
        assert!(decide(&token(2, 100, 0), 1, false, 50).is_ok());
        assert!(decide(&token(2, 100, 0), 2, false, 50).unwrap_err().contains("maximum of 2"));
        assert!(decide(&token(2, 100, 0), 2, true, 50).is_ok(), "a reinstall does not count again");
        assert!(decide(&token(2, 100, 0), 0, false, 100).unwrap_err().contains("expired"));
        assert!(decide(&token(2, 100, 1), 0, true, 50).unwrap_err().contains("revoked"));
    }

    #[test]
    fn report_rows_are_cleaned_and_keyed_by_computer() {
        let t = token(5, 100, 0);
        let r = target_of(&t, "ADMIN-PC", &json!({ "computer": "PC-01
", "address": "10.0.0.7", "outcome": "rm -rf", "reason": "x" }), 9).unwrap();
        assert_eq!((r.target.as_str(), r.computer.as_str(), r.outcome.as_str(), r.tenant_id.as_str()), ("pc-01", "PC-01", "failed", "acme"));
        let r = target_of(&t, "", &json!({ "address": "10.0.0.8", "outcome": "unreachable" }), 9).unwrap();
        assert_eq!((r.target.as_str(), r.outcome.as_str()), ("10.0.0.8", "unreachable"));
        assert!(target_of(&t, "", &json!({ "outcome": "installed" }), 9).is_none());
    }

    #[test]
    fn tokens_are_recognised_by_prefix_and_found_by_hash() {
        assert!(is_token(" pvd_ab_cd"));
        assert!(!is_token("tk_abc"));
        assert_eq!(hash_hex("x"), hash_hex(" x "));
        assert_eq!(hash_hex("x").len(), 64);
    }
}
