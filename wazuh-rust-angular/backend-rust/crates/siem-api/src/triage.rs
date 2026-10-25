//! Alert triage for the SIEM (siem-triage), per tenant: the SIEM triage page.s
//! `/api/v1/siem/triage` API on the tenant's Wazuh alerts of the last 24 h, and a
//! background run every 30 minutes. Applying a recommendation creates a
//! suppression (siem-suppression); nothing is hidden without a person.
//!
//! Config (env, optional): `SIEM_TRIAGE_AI_PER_HOUR` (default 20),
//! `SIEM_TRIAGE_AI_PER_RUN` (10), `SIEM_TRIAGE_INTERVAL_MINS` (30, min 5).

use std::time::Duration;

use axum::extract::{Extension, Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use siem_triage::{AlertRow, Recommendation, Source, State as TriageState, Verdict};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

const DOC_ID: &str = "triage";
const MAX_ALERTS: u64 = 3000;
const MIN_MANUAL_GAP_SECS: u64 = 60;

fn env_u32(k: &str, d: u32) -> u32 {
    std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(d)
}

fn ai_per_hour() -> u32 {
    env_u32("SIEM_TRIAGE_AI_PER_HOUR", 20)
}

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

pub async fn load(state: &AppState, tenant: &str) -> TriageState {
    state.db.doc(tenant, DocTable::AnalystState, DOC_ID).await.ok().flatten().and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_default()
}

async fn save(state: &AppState, tenant: &str, st: &TriageState) -> Result<(), String> {
    state.db.put_doc(tenant, DocTable::AnalystState, DOC_ID, &serde_json::to_string(st).map_err(|e| e.to_string())?).await
}

#[derive(clickhouse::Row, Deserialize)]
struct Row {
    id: String,
    timestamp: u64,
    agent_id: String,
    agent_name: String,
    rule_id: u32,
    rule_level: u8,
    rule_description: String,
    mitre_tactic: String,
    src_ip: String,
    location: String,
    full_log: String,
}

async fn recent_alerts(state: &AppState, tenant: &str) -> Vec<AlertRow> {
    let since_ms = (now().saturating_sub(siem_triage::LOOKBACK_HOURS as u64 * 3600)) * 1000;
    state
        .db
        .tenant_client(tenant)
        .query("SELECT id, timestamp, agent_id, agent_name, rule_id, rule_level, rule_description, mitre_tactic, src_ip, location, substring(full_log, 1, 1000) AS full_log FROM siem_alerts WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?")
        .bind(since_ms)
        .bind(MAX_ALERTS)
        .fetch_all::<Row>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| AlertRow {
            id: r.id,
            timestamp: r.timestamp / 1000,
            agent_id: r.agent_id,
            agent_name: r.agent_name,
            rule_id: r.rule_id,
            rule_level: r.rule_level as u32,
            rule_description: r.rule_description,
            mitre_tactic: r.mitre_tactic,
            src_ip: r.src_ip,
            location: r.location,
            full_log: r.full_log,
        })
        .collect()
}

/// One run for one tenant. `use_ai = false` (the page's "Run now") applies the
/// rules and earlier AI answers only: instant and free.
pub async fn run_for_tenant(state: &AppState, tenant: &str, use_ai: bool) -> Result<TriageState, String> {
    let mut st = load(state, tenant).await;
    let rows = recent_alerts(state, tenant).await;
    if rows.is_empty() && st.recs.is_empty() {
        return Ok(st);
    }
    let groups = siem_triage::group_alerts(&rows);
    let (mut decisions, ask) = siem_triage::decide(&st, &groups);
    if use_ai && !ask.is_empty() && crate::ai_assist::tenant_ai_enabled(state, tenant) {
        let providers = crate::ai_assist::providers(state, "threat").await;
        if !providers.is_empty() {
            let hour = now() / 3600;
            let allowed = (st.ai.remaining(hour, ai_per_hour()) as usize).min(env_u32("SIEM_TRIAGE_AI_PER_RUN", 10) as usize);
            let system = siem_triage::system_prompt();
            for g in ask.into_iter().take(allowed) {
                st.ai.note_call(hour);
                match siem_ai::generate(&providers, &system, &siem_triage::build_prompt(g)).await.ok().and_then(|r| siem_triage::decision_from_reply(&r.text)) {
                    Some(d) => {
                        decisions.insert(g.key.clone(), d);
                    }
                    None => tracing::warn!("triage: no usable AI answer for tenant '{tenant}' group '{}'", g.key),
                }
            }
        }
    }
    siem_triage::finish(&mut st, &groups, &decisions, now());
    save(state, tenant, &st).await?;
    Ok(st)
}

/// Every tenant, every `SIEM_TRIAGE_INTERVAL_MINS` (first run 4 minutes after start).
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(240)).await;
        loop {
            if state.db.is_connected() {
                for t in crate::predictions::tenant_ids(&state) {
                    if let Err(e) = run_for_tenant(&state, &t, true).await {
                        tracing::warn!("triage: tenant '{t}' failed: {e}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(env_u32("SIEM_TRIAGE_INTERVAL_MINS", 30).max(5) as u64 * 60)).await;
        }
    });
}

fn view(state: &AppState, tenant: &str, st: &TriageState, extra: Value) -> Json<Value> {
    let hour = now() / 3600;
    let limit = ai_per_hour();
    let pending: Vec<&Recommendation> = st.recs.iter().filter(|r| r.status == "pending").collect();
    let count = |v: Verdict| pending.iter().filter(|r| r.verdict == v).count();
    Json(json!({
        "status": "ok",
        "last_run": st.last_run,
        "lookback_hours": siem_triage::LOOKBACK_HOURS,
        "ai": {
            "enabled": crate::ai_assist::tenant_ai_enabled(state, tenant),
            "mode": "recommend-only",
            "budget_per_hour": limit,
            "used_this_hour": st.ai.used(hour),
            "remaining_this_hour": st.ai.remaining(hour, limit),
        },
        "summary": {
            "groups": pending.len(),
            "alerts": pending.iter().map(|r| r.alert_count).sum::<u32>(),
            "benign": count(Verdict::Benign),
            "suspicious": count(Verdict::Suspicious),
            "unknown": count(Verdict::Unknown),
            "alerts_likely_benign": pending.iter().filter(|r| r.verdict == Verdict::Benign).map(|r| r.alert_count).sum::<u32>(),
            "applied": st.recs.iter().filter(|r| r.status == "applied").count(),
            "dismissed": st.recs.iter().filter(|r| r.status == "dismissed").count(),
        },
        "recommendations": pending,
        "info": extra,
    }))
}

fn err(m: impl Into<String>) -> Json<Value> {
    Json(json!({ "status": "error", "message": m.into() }))
}

/// The page data, with how triage adapts for this analyst (siem-analyst-insight).
async fn page(state: &AppState, tenant: &str, user: &str, st: &TriageState, extra: Value) -> Json<Value> {
    let mut v = view(state, tenant, st, extra);
    v.0["calibration"] = crate::insights::calibration(state, tenant, user).await.map(|c| json!(c)).unwrap_or(Value::Null);
    v
}

/// `GET /api/v1/siem/triage`
pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let t = ctx.scope();
    let st = load(&state, &t).await;
    crate::insights::log(&state, &t, &ctx.username, "view", None).await;
    page(&state, &t, &ctx.username, &st, Value::Null).await
}

#[derive(clickhouse::Row, Deserialize, serde::Serialize)]
struct SampleAlert {
    id: String,
    timestamp: u64,
    rule_level: u8,
    location: String,
    full_log: String,
}

/// `POST /api/v1/siem/triage/:id/inspect`: the group's latest alerts (and the
/// analyst looked at them).
pub async fn inspect(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    let t = ctx.scope();
    let st = load(&state, &t).await;
    let Some(rec) = st.recs.iter().find(|r| r.id == id) else { return err("Recommendation not found") };
    let since_ms = now().saturating_sub(siem_triage::LOOKBACK_HOURS as u64 * 3600) * 1000;
    let alerts = state
        .db
        .tenant_client(&t)
        .query("SELECT id, timestamp, rule_level, location, substring(full_log, 1, 2000) AS full_log FROM siem_alerts WHERE rule_id = ? AND agent_id = ? AND src_ip = ? AND timestamp >= ? ORDER BY timestamp DESC LIMIT 20")
        .bind(rec.rule_id)
        .bind(&rec.agent_id)
        .bind(&rec.src_ip)
        .bind(since_ms)
        .fetch_all::<SampleAlert>()
        .await
        .unwrap_or_default();
    crate::insights::log(&state, &t, &ctx.username, "inspect", Some(rec)).await;
    Json(json!({ "status": "ok", "id": id, "alerts": alerts, "recommendation": rec }))
}

/// `POST /api/v1/siem/triage/run`: rules and cached answers only, no AI call.
pub async fn run_now(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let t = ctx.scope();
    let st = load(&state, &t).await;
    if now().saturating_sub(st.last_run) < MIN_MANUAL_GAP_SECS {
        return page(&state, &t, &ctx.username, &st, json!({ "throttled": true })).await;
    }
    match run_for_tenant(&state, &t, false).await {
        Ok(st) => page(&state, &t, &ctx.username, &st, Value::Null).await,
        Err(e) => err(e),
    }
}

#[derive(Deserialize, Default)]
pub struct ApplyBody {
    pub hours: Option<u32>,
}

/// `POST /api/v1/siem/triage/:id/apply`: the person's decision; hides that rule on that
/// agent (and source IP) for `hours` (default 24, at most 168).
pub async fn apply(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, body: Option<Json<ApplyBody>>) -> Json<Value> {
    let t = ctx.scope();
    let mut st = load(&state, &t).await;
    let Some(rec) = st.recs.iter().find(|r| r.id == id).cloned() else { return err("Recommendation not found") };
    if rec.status != "pending" {
        return err("Already handled");
    }
    if rec.verdict == Verdict::Suspicious {
        return err("Suspicious groups can't be suppressed from triage - review the alerts instead.");
    }
    // trust calibration: an analyst relying on the AI too much looks at the alerts first
    if crate::insights::calibration(&state, &t, &ctx.username).await.is_some_and(|c| c.require_inspect) && !crate::insights::inspected(&state, &t, &ctx.username, &rec.id).await {
        return err("Open this group's alerts (View alerts) before hiding it.");
    }
    let hours = body.and_then(|b| b.0.hours).unwrap_or(24);
    let req = siem_suppression::Request {
        rule_id: Some(rec.rule_id),
        rule_name: rec.rule_description.clone(),
        agent_id: Some(rec.agent_id.clone()),
        agent_name: rec.agent_name.clone(),
        src_ip: Some(rec.src_ip.clone()).filter(|s| s.parse::<std::net::IpAddr>().is_ok()),
        hours: Some(hours),
        reason: format!("Applied from alert triage ({} verdict, {}%): {}", if rec.source == Source::Ai { "AI" } else { "rule" }, rec.confidence, rec.reason),
    };
    if let Err(e) = crate::suppressions::create(&state, &t, req, "triage", rec.confidence, &ctx.username).await {
        return err(e);
    }
    let n = now();
    if let Some(r) = st.recs.iter_mut().find(|r| r.id == id) {
        r.status = "applied".into();
        r.updated_at = n;
    }
    let _ = save(&state, &t, &st).await;
    crate::insights::log(&state, &t, &ctx.username, "apply", Some(&rec)).await;
    page(&state, &t, &ctx.username, &st, json!({ "applied_hours": hours.clamp(siem_suppression::MIN_HOURS, siem_suppression::MAX_HOURS), "also_covered_groups": 0 })).await
}

/// `POST /api/v1/siem/triage/:id/dismiss`: keep showing these, stop recommending.
pub async fn dismiss(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    let t = ctx.scope();
    let mut st = load(&state, &t).await;
    let n = now();
    let rec = match st.recs.iter_mut().find(|r| r.id == id && r.status == "pending") {
        Some(r) => {
            r.status = "dismissed".into();
            r.updated_at = n;
            r.clone()
        }
        None => return err("Recommendation not found"),
    };
    let _ = save(&state, &t, &st).await;
    crate::insights::log(&state, &t, &ctx.username, "dismiss", Some(&rec)).await;
    page(&state, &t, &ctx.username, &st, Value::Null).await
}
