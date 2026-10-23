//! Threat predictions for the SIEM (siem-predict), per tenant: every 15
//! minutes the MITRE progression of each agent's alerts (24 h) predicts the
//! next attack stages; the AI writes a short briefing for the top ones (within
//! a budget). Serves `/api/v1/siem/predictions` (+ `/history`, `/run`) for the
//! SIEM Threat Predictions page.
//!
//! Config (env, optional): `SIEM_PREDICT_INTERVAL_MINS` (15, min 5),
//! `SIEM_PREDICT_AI_PER_HOUR` (6).

use std::collections::BTreeMap;
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use siem_predict::{AlertRow, Prediction};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

const BUDGET_DOC: &str = "predict_ai_budget";
const BRIEFINGS_PER_RUN: usize = 3;

fn env_u32(k: &str, d: u32) -> u32 {
    std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(d)
}

/// Every tenant the platform knows (the default one included).
pub fn tenant_ids(state: &AppState) -> Vec<String> {
    let mut ids: Vec<String> = state.tenants.read().unwrap().iter().filter(|t| t.active).map(|t| crate::tenancy::normalize_tenant(&t.id)).collect();
    ids.push(crate::tenancy::DEFAULT_TENANT.to_string());
    ids.sort();
    ids.dedup();
    ids
}

#[derive(clickhouse::Row, Deserialize)]
struct Row {
    timestamp: u64,
    agent_id: String,
    agent_name: String,
    rule_id: u32,
    rule_level: u8,
    mitre_tactic: String,
    mitre_id: String,
}

async fn stored(state: &AppState, tenant: &str, hours: u32, limit: u32) -> Vec<Prediction> {
    state
        .db
        .tenant_client(tenant)
        .query("SELECT doc FROM siem_threat_predictions WHERE predicted_at >= now() - toIntervalHour(?) ORDER BY predicted_at DESC LIMIT ?")
        .bind(hours)
        .bind(limit)
        .fetch_all::<String>()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect()
}

pub async fn run_for_tenant(state: &AppState, tenant: &str) -> Result<usize, String> {
    let since_ms = (chrono::Utc::now().timestamp().max(0) as u64).saturating_sub(24 * 3600) * 1000;
    let rows: Vec<AlertRow> = state
        .db
        .tenant_client(tenant)
        .query("SELECT timestamp, agent_id, agent_name, rule_id, rule_level, mitre_tactic, mitre_id FROM siem_alerts WHERE timestamp >= ? AND mitre_tactic != '' ORDER BY timestamp LIMIT 20000")
        .bind(since_ms)
        .fetch_all::<Row>()
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|r| AlertRow { timestamp: r.timestamp / 1000, agent_id: r.agent_id, agent_name: r.agent_name, rule_id: r.rule_id, rule_level: r.rule_level as u32, mitre_tactic: r.mitre_tactic, mitre_id: r.mitre_id })
        .collect();
    if rows.is_empty() {
        return Ok(0);
    }
    // the last probability of each attack type, for the trend
    let mut previous = BTreeMap::new();
    for p in stored(state, tenant, 24, 200).await {
        previous.entry(p.attack_type.clone()).or_insert(p.probability);
    }
    let total_agents = state.agent_tenants.read().unwrap().values().filter(|t| crate::tenancy::normalize_tenant(t) == tenant).count();
    let mut preds = siem_predict::predict(&rows, &previous, total_agents, &chrono::Utc::now().to_rfc3339());
    if preds.is_empty() {
        return Ok(0);
    }

    if crate::ai_assist::tenant_ai_enabled(state, tenant) {
        let providers = crate::ai_assist::providers(state, "threat").await;
        if !providers.is_empty() {
            let mut budget: siem_ai::HourlyBudget = state.db.doc(tenant, DocTable::AnalystState, BUDGET_DOC).await.ok().flatten().and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_default();
            let hour = chrono::Utc::now().timestamp().max(0) as u64 / 3600;
            let n = (budget.remaining(hour, env_u32("SIEM_PREDICT_AI_PER_HOUR", 6)) as usize).min(BRIEFINGS_PER_RUN);
            for p in preds.iter_mut().take(n) {
                budget.note_call(hour);
                if let Ok(r) = siem_ai::generate(&providers, "You brief SOC analysts on predicted attack stages. Plain language, no markdown.", &siem_predict::briefing_prompt(p)).await {
                    p.aria_briefing = r.text.chars().take(1200).collect();
                    p.ai_model = r.model;
                }
            }
            if let Ok(d) = serde_json::to_string(&budget) {
                let _ = state.db.put_doc(tenant, DocTable::AnalystState, BUDGET_DOC, &d).await;
            }
        }
    }

    let client = state.db.tenant_client(tenant);
    for p in &preds {
        let doc = serde_json::to_string(p).map_err(|e| e.to_string())?;
        client.query("INSERT INTO siem_threat_predictions (id, attack_type, doc) VALUES (?, ?, ?)").bind(&p.id).bind(&p.attack_type).bind(doc).execute().await.map_err(|e| e.to_string())?;
    }
    Ok(preds.len())
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(300)).await;
        loop {
            if state.db.is_connected() {
                for t in tenant_ids(&state) {
                    if let Err(e) = run_for_tenant(&state, &t).await {
                        tracing::warn!("threat predictions: tenant '{t}' failed: {e}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(env_u32("SIEM_PREDICT_INTERVAL_MINS", 15).max(5) as u64 * 60)).await;
        }
    });
}

static LAST_MANUAL: std::sync::Mutex<Option<std::collections::HashMap<String, std::time::Instant>>> = std::sync::Mutex::new(None);

/// `POST /api/v1/siem/predictions/run`: a run now (at most once a minute per tenant).
pub async fn run_now(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let t = ctx.scope();
    {
        let mut g = LAST_MANUAL.lock().unwrap();
        let m = g.get_or_insert_with(Default::default);
        if m.get(&t).is_some_and(|i| i.elapsed() < Duration::from_secs(60)) {
            return Json(json!({ "status": "error", "message": "Predictions were just updated; try again in a minute" }));
        }
        m.insert(t.clone(), std::time::Instant::now());
    }
    match run_for_tenant(&state, &t).await {
        Ok(n) => Json(json!({ "status": "ok", "predictions": n })),
        Err(e) => Json(json!({ "status": "error", "message": e })),
    }
}

/// `GET /api/v1/siem/predictions`: the latest prediction of each attack type (24 h).
pub async fn latest(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let mut seen = std::collections::HashSet::new();
    let list: Vec<Prediction> = stored(&state, &ctx.scope(), 24, 500).await.into_iter().filter(|p| seen.insert(p.attack_type.clone())).take(20).collect();
    Json(json!({ "predictions": list }))
}

/// `GET /api/v1/siem/predictions/history`: 7 days.
pub async fn history(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    Json(json!({ "predictions": stored(&state, &ctx.scope(), 168, 500).await }))
}
