//! Analyst cognitive load & trust calibration (siem-analyst-insight), per tenant.
//!
//! Logs what analysts do on the SIEM triage and suppression pages, and from it
//! adapts triage for each analyst (look at the alerts before hiding, AI verdict
//! after looking, explanation depth, summaries first). Who sees what:
//! - an analyst: their own numbers (`/api/v1/siem/insights/me`);
//! - the tenant admin: every analyst of their tenant, and the on/off switch
//!   (`/team`, `/settings`);
//! - the super admin (platform owner): not this data.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use siem_analyst_insight::{Action, Calibration, HiddenOutcome};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

const SETTINGS_DOC: &str = "insight_settings";
const CACHE_TTL: Duration = Duration::from_secs(120);
static CACHE: Mutex<Option<HashMap<(String, String), (Instant, Calibration)>>> = Mutex::new(None);

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { enabled: true }
    }
}

pub async fn settings(state: &AppState, tenant: &str) -> Settings {
    state.db.doc(tenant, DocTable::AnalystState, SETTINGS_DOC).await.ok().flatten().and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_default()
}

/// Records one action (when the tenant has the feature on). `rec` = the triage
/// recommendation it was about.
pub async fn log(state: &AppState, tenant: &str, user: &str, action: &str, rec: Option<&siem_triage::Recommendation>) {
    if !state.db.is_connected() || !settings(state, tenant).await.enabled {
        return;
    }
    let (rec_id, verdict, source, confidence) = match rec {
        Some(r) => (
            r.id.clone(),
            serde_json::to_value(r.verdict).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
            serde_json::to_value(r.source).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
            r.confidence,
        ),
        None => (String::new(), String::new(), String::new(), 0),
    };
    let r = state
        .db
        .tenant_client(tenant)
        .query("INSERT INTO siem_analyst_actions (ts, user, action, rec_id, verdict, source, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(now())
        .bind(user)
        .bind(action)
        .bind(rec_id)
        .bind(verdict)
        .bind(source)
        .bind(confidence)
        .execute()
        .await;
    if let Err(e) = r {
        tracing::debug!("analyst action not logged: {e}");
    }
    if let Some(m) = CACHE.lock().unwrap().as_mut() {
        m.remove(&(tenant.to_string(), user.to_string()));
    }
}

#[derive(clickhouse::Row, Deserialize)]
struct ActionRow {
    ts: u64,
    user: String,
    action: String,
    rec_id: String,
    verdict: String,
    source: String,
    confidence: u8,
}

async fn actions(state: &AppState, tenant: &str, user: Option<&str>) -> Vec<Action> {
    let since = now().saturating_sub(7 * 86400);
    let mut q = state.db.tenant_client(tenant).query(if user.is_some() {
        "SELECT ts, user, action, rec_id, verdict, source, confidence FROM siem_analyst_actions WHERE ts >= ? AND user = ? ORDER BY ts LIMIT 100000"
    } else {
        "SELECT ts, user, action, rec_id, verdict, source, confidence FROM siem_analyst_actions WHERE ts >= ? ORDER BY ts LIMIT 200000"
    });
    q = q.bind(since);
    if let Some(u) = user {
        q = q.bind(u);
    }
    q.fetch_all::<ActionRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| Action { ts: r.ts, user: r.user, action: r.action, rec_id: r.rec_id, verdict: r.verdict, source: r.source, confidence: r.confidence })
        .collect()
}

/// Hosts whose alerts an analyst hid (7 days) that raised a critical alert after.
async fn outcomes(state: &AppState, tenant: &str) -> Vec<HiddenOutcome> {
    let since = now().saturating_sub(7 * 86400);
    let mut out = Vec::new();
    for s in crate::suppressions::all(state, tenant).await.into_iter().filter(|s| s.created_at >= since).take(200) {
        let Some(agent) = s.agent_id.clone() else { continue };
        let n = state
            .db
            .tenant_client(tenant)
            .query("SELECT count() FROM siem_alerts WHERE agent_id = ? AND rule_level >= 12 AND timestamp > ?")
            .bind(&agent)
            .bind(s.created_at * 1000)
            .fetch_one::<u64>()
            .await
            .unwrap_or(0);
        if n > 0 {
            out.push(HiddenOutcome { user: s.created_by.clone(), later_critical: n as u32 });
        }
    }
    out
}

async fn pending_per_analyst(state: &AppState, tenant: &str, analysts: usize) -> f64 {
    let pending = crate::triage::load(state, tenant).await.recs.iter().filter(|r| r.status == "pending").count();
    pending as f64 / analysts.max(1) as f64
}

/// How triage adapts for this analyst; `None` when the tenant turned it off.
pub async fn calibration(state: &AppState, tenant: &str, user: &str) -> Option<Calibration> {
    if !state.db.is_connected() || !settings(state, tenant).await.enabled {
        return None;
    }
    let key = (tenant.to_string(), user.to_string());
    if let Some((t, c)) = CACHE.lock().unwrap().get_or_insert_with(HashMap::new).get(&key) {
        if t.elapsed() < CACHE_TTL {
            return Some(c.clone());
        }
    }
    let all = actions(state, tenant, None).await;
    let analysts = all.iter().filter(|a| now().saturating_sub(a.ts) <= 3600).map(|a| a.user.as_str()).collect::<std::collections::HashSet<_>>().len();
    let mine: Vec<Action> = all.into_iter().filter(|a| a.user == user).collect();
    let outs: Vec<HiddenOutcome> = outcomes(state, tenant).await.into_iter().filter(|o| o.user == user).collect();
    let m = siem_analyst_insight::metrics(&mine, &outs, now()).remove(user).unwrap_or_else(|| siem_analyst_insight::Metrics { user: user.to_string(), ..Default::default() });
    let c = siem_analyst_insight::calibrate(&m, pending_per_analyst(state, tenant, analysts).await);
    CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(key, (Instant::now(), c.clone()));
    Some(c)
}

/// Did this analyst open the alerts of this recommendation (24 h)?
pub async fn inspected(state: &AppState, tenant: &str, user: &str, rec_id: &str) -> bool {
    state
        .db
        .tenant_client(tenant)
        .query("SELECT count() FROM siem_analyst_actions WHERE user = ? AND action = 'inspect' AND rec_id = ? AND ts >= ?")
        .bind(user)
        .bind(rec_id)
        .bind(now().saturating_sub(86400))
        .fetch_one::<u64>()
        .await
        .unwrap_or(0)
        > 0
}

fn forbidden(m: &str) -> axum::response::Response {
    (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": m }))).into_response()
}

/// `GET /api/v1/siem/insights/me`: the caller's own numbers.
pub async fn me(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if ctx.is_super() {
        return forbidden("Analyst insights belong to each tenant");
    }
    let t = ctx.scope();
    match calibration(&state, &t, &ctx.username).await {
        Some(c) => Json(json!({ "status": "ok", "enabled": true, "calibration": c })).into_response(),
        None => Json(json!({ "status": "ok", "enabled": false })).into_response(),
    }
}

/// `GET /api/v1/siem/insights/team`: every analyst of the tenant (tenant admin only).
pub async fn team(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if !ctx.is_tenant_admin() {
        return forbidden("Only the tenant admin sees the team's insights");
    }
    let t = ctx.scope();
    let s = settings(&state, &t).await;
    if !s.enabled {
        return Json(json!({ "status": "ok", "settings": s, "analysts": [] })).into_response();
    }
    let all = actions(&state, &t, None).await;
    let n = now();
    let active = all.iter().filter(|a| n.saturating_sub(a.ts) <= 3600).map(|a| a.user.as_str()).collect::<std::collections::HashSet<_>>().len();
    let per = pending_per_analyst(&state, &t, active).await;
    let analysts: Vec<Calibration> = siem_analyst_insight::metrics(&all, &outcomes(&state, &t).await, n).values().map(|m| siem_analyst_insight::calibrate(m, per)).collect();
    Json(json!({ "status": "ok", "settings": s, "analysts": analysts })).into_response()
}

/// `PUT /api/v1/siem/insights/settings` (tenant admin only).
pub async fn put_settings(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(s): Json<Settings>) -> axum::response::Response {
    if !ctx.is_tenant_admin() {
        return forbidden("Only the tenant admin changes this");
    }
    let t = ctx.scope();
    match state.db.put_doc(&t, DocTable::AnalystState, SETTINGS_DOC, &serde_json::to_string(&s).unwrap_or_default()).await {
        Ok(()) => {
            if let Some(m) = CACHE.lock().unwrap().as_mut() {
                m.retain(|(tt, _), _| tt != &t);
            }
            Json(json!({ "status": "ok", "settings": s })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e }))).into_response(),
    }
}
