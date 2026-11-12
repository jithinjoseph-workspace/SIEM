//! Predictive security posture per tenant (spec: `specs/provigil-posture.md`): every hour the
//! score of today from the tenant's own data (real agents only), after midnight (UTC) the
//! finished day with the forecast that had been made for it, and a forecast for tomorrow whose
//! range comes from the errors of past forecasts. Stored in ClickHouse (`siem_posture_daily`,
//! `siem_posture_hourly`). Serves `/api/v1/posture` (+ `/history`, `/agents`, `/run`).

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::Json;
use provigil_posture::{AlertCount, Forecast, HostSca, HostVulns, Hygiene, Inputs, Posture, Progression, Weights};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

pub const DDL: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS siem_posture_daily (day Date, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY day",
    "CREATE TABLE IF NOT EXISTS siem_posture_hourly (ts DateTime, doc String) ENGINE = MergeTree ORDER BY ts TTL ts + INTERVAL 7 DAY",
];
const HISTORY_DAYS: u32 = 14;

/// One stored day (and the live "today" points): the score, and the forecast for the next day.
#[derive(Serialize, Deserialize, Clone)]
pub struct Day {
    pub day: String,
    pub posture: Posture,
    pub forecast_next: Forecast,
    /// the forecast that had been made for this day, when there was one
    pub forecast_for_this_day: Option<f64>,
    pub computed_at: String,
}

/// This tenant's real agents: enrolled here, not removed. id -> (name, active)
fn real_agents(state: &AppState, tenant: &str) -> HashMap<String, (String, bool)> {
    let tenants = state.agent_tenants.read().unwrap();
    let deleted = state.deleted_agents.read().unwrap();
    state
        .agents
        .read()
        .unwrap()
        .values()
        .filter(|a| !deleted.contains(&a.id) && crate::tenancy::normalize_tenant(tenants.get(&a.id).map_or(crate::tenancy::DEFAULT_TENANT, |t| t.as_str())) == tenant)
        .map(|a| (a.id.clone(), (a.name.clone(), a.status == siem_core::AgentStatus::Active)))
        .collect()
}

#[derive(clickhouse::Row, Deserialize)]
struct AlertRow {
    agent_id: String,
    agent_name: String,
    rule_id: u32,
    rule_level: u8,
    rule_description: String,
    n: u64,
}

#[derive(clickhouse::Row, Deserialize)]
struct DayAlertRow {
    day: u16,
    agent_id: String,
    rule_id: u32,
    rule_level: u8,
    n: u64,
}

#[derive(clickhouse::Row, Deserialize)]
struct VulnRow {
    agent_id: String,
    critical: u64,
    high: u64,
    medium: u64,
    low: u64,
    kev: u64,
}

#[derive(clickhouse::Row, Deserialize)]
struct ScaRow {
    agent_id: String,
    passed: u64,
    failed: u64,
}

fn today_utc() -> chrono::NaiveDate {
    chrono::Utc::now().date_naive()
}

async fn inputs(state: &AppState, tenant: &str) -> Result<Inputs, String> {
    let agents = real_agents(state, tenant);
    let db = state.db.tenant_client(tenant);
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let e = |e: clickhouse::error::Error| e.to_string();

    let alerts: Vec<AlertCount> = db
        .query("SELECT agent_id, any(agent_name) AS agent_name, rule_id, rule_level, any(rule_description) AS rule_description, count() AS n FROM siem_alerts WHERE timestamp >= ? GROUP BY agent_id, rule_id, rule_level")
        .bind(now_ms - 24 * 3600 * 1000)
        .fetch_all::<AlertRow>()
        .await
        .map_err(e)?
        .into_iter()
        .filter(|r| agents.contains_key(&r.agent_id))
        .map(|r| AlertCount { agent_id: r.agent_id, agent_name: r.agent_name, rule_id: r.rule_id, level: r.rule_level, description: r.rule_description, count: r.n })
        .collect();

    // earlier days: the alert load per day; a day without any event is "no data" (manager off)
    let today = today_utc();
    let from = today - chrono::Duration::days(HISTORY_DAYS as i64);
    let day_num = |d: chrono::NaiveDate| (d - chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()).num_days() as u16;
    let rows = db
        .query("SELECT toUInt16(toDate(toDateTime(intDiv(timestamp, 1000)))) AS day, agent_id, rule_id, rule_level, count() AS n FROM siem_alerts WHERE timestamp >= ? AND timestamp < ? GROUP BY day, agent_id, rule_id, rule_level")
        .bind(from.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis() as u64)
        .bind(today.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis() as u64)
        .fetch_all::<DayAlertRow>()
        .await
        .map_err(e)?;
    let event_days: HashSet<u16> = db
        .query("SELECT DISTINCT toUInt16(toDate(toDateTime(intDiv(timestamp, 1000)))) FROM siem_events WHERE timestamp >= ?")
        .bind(from.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis() as u64)
        .fetch_all::<u16>()
        .await
        .map_err(e)?
        .into_iter()
        .collect();
    let enrolled = agents.len() as u32;
    let load_history = (0..HISTORY_DAYS as i64)
        .map(|k| {
            let d = day_num(from + chrono::Duration::days(k));
            let day: Vec<AlertCount> = rows
                .iter()
                .filter(|r| r.day == d && agents.contains_key(&r.agent_id))
                .map(|r| AlertCount { agent_id: r.agent_id.clone(), agent_name: String::new(), rule_id: r.rule_id, level: r.rule_level, description: String::new(), count: r.n })
                .collect();
            event_days.contains(&d).then(|| provigil_posture::alert_load(&day, enrolled))
        })
        .collect();

    let vulns = db
        .query(
            "SELECT agent_id, countIf(sev = 'Critical') AS critical, countIf(sev = 'High') AS high, countIf(sev = 'Medium') AS medium, countIf(sev = 'Low') AS low, \
             countIf(cve IN (SELECT ioc_value FROM ndr.siem_threat_intel WHERE ioc_type = 'cve')) AS kev \
             FROM (SELECT agent_id, JSONExtractString(doc, 'vulnerability', 'severity') AS sev, JSONExtractString(doc, 'vulnerability', 'id') AS cve FROM siem_vulnerability_state FINAL WHERE deleted = 0) GROUP BY agent_id",
        )
        .fetch_all::<VulnRow>()
        .await
        .map_err(e)?
        .into_iter()
        .filter_map(|r| {
            let name = agents.get(&r.agent_id)?.0.clone();
            Some(HostVulns { agent_id: r.agent_id, agent_name: name, critical: r.critical as u32, high: r.high as u32, medium: r.medium as u32, low: r.low as u32, kev: r.kev as u32 })
        })
        .collect();

    let sca = db
        .query("SELECT agent_id, countIf(status = 'Passed') AS passed, countIf(status = 'Failed') AS failed FROM siem_sca_checks GROUP BY agent_id")
        .fetch_all::<ScaRow>()
        .await
        .map_err(e)?
        .into_iter()
        .filter(|r| agents.contains_key(&r.agent_id))
        .map(|r| HostSca { agent_id: r.agent_id, passed: r.passed as u32, failed: r.failed as u32 })
        .collect();

    // the strongest attack signals: intent dossiers of real agents (simulations left out)
    let progression = state
        .intent_engine
        .get_dossiers()
        .into_iter()
        .filter(|d| !d.is_simulated && agents.contains_key(&d.entity_id))
        .map(|d| Progression {
            agent_name: d.entity_name,
            intent: d.primary_intent,
            probability: d.primary_probability,
            progress: d.progression_percent as f64 / 100.0,
            accelerating: d.kill_chain_velocity.eq_ignore_ascii_case("accelerating"),
        })
        .collect();

    let stale_cases = db
        .query("SELECT count() FROM soar_cases FINAL WHERE status NOT IN ('Closed', 'Resolved') AND severity IN ('CRITICAL', 'HIGH') AND created_at < now() - INTERVAL 1 DAY")
        .fetch_one::<u64>()
        .await
        .unwrap_or(0) as u32;
    let hygiene = Hygiene { agents: enrolled, active: agents.values().filter(|(_, a)| *a).count() as u32, stale_cases };
    Ok(Inputs { alerts, load_history, vulns, sca, progression, hygiene })
}

async fn stored_days(state: &AppState, tenant: &str, days: u32) -> Vec<Day> {
    state
        .db
        .tenant_client(tenant)
        .query("SELECT doc FROM siem_posture_daily FINAL WHERE day >= today() - ? ORDER BY day")
        .bind(days)
        .fetch_all::<String>()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect()
}

pub(crate) async fn latest_today(state: &AppState, tenant: &str) -> Option<Day> {
    let d = state.db.tenant_client(tenant).query("SELECT doc FROM siem_posture_hourly ORDER BY ts DESC LIMIT 1").fetch_optional::<String>().await.ok()??;
    serde_json::from_str(&d).ok()
}

/// Compute today's score and tomorrow's forecast; at the first run of a day also store the
/// finished day before it.
pub async fn run_for_tenant(state: &AppState, tenant: &str) -> Result<Day, String> {
    let i = inputs(state, tenant).await?;
    let w = Weights::default();
    let posture = provigil_posture::score(&i, &w);
    let past = stored_days(state, tenant, 60).await;
    // actual minus what had been forecast, for the range and the accuracy shown
    let errors: Vec<f64> = past.iter().filter_map(|d| d.forecast_for_this_day.map(|f| d.posture.score - f)).collect();
    let forecast_next = provigil_posture::forecast(&posture, &i.load_history, &w, &errors);
    let today = today_utc();
    let yesterday_forecast = latest_before(state, tenant, today).await.map(|d| d.forecast_next.score);
    let now = chrono::Utc::now();
    let day = Day { day: today.to_string(), posture, forecast_next, forecast_for_this_day: yesterday_forecast, computed_at: now.to_rfc3339() };
    let client = state.db.tenant_client(tenant);
    let doc = serde_json::to_string(&day).map_err(|e| e.to_string())?;
    client.query("INSERT INTO siem_posture_hourly (ts, doc) VALUES (now(), ?)").bind(&doc).execute().await.map_err(|e| e.to_string())?;
    // the day row is rewritten each hour; the last one of the day is the day's result
    client
        .query("INSERT INTO siem_posture_daily (day, doc, version) VALUES (toDate(?), ?, ?)")
        .bind(today.to_string())
        .bind(&doc)
        .bind(now.timestamp_micros().max(0) as u64)
        .execute()
        .await
        .map_err(|e| e.to_string())?;
    Ok(day)
}

/// The last stored day before `day` (its forecast is the one made for `day`).
async fn latest_before(state: &AppState, tenant: &str, day: chrono::NaiveDate) -> Option<Day> {
    let d = state
        .db
        .tenant_client(tenant)
        .query("SELECT doc FROM siem_posture_daily FINAL WHERE day < toDate(?) ORDER BY day DESC LIMIT 1")
        .bind(day.to_string())
        .fetch_optional::<String>()
        .await
        .ok()??;
    serde_json::from_str(&d).ok()
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        // after the agent registry and the intent dossiers are loaded
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            if state.db.is_connected() {
                for t in crate::predictions::tenant_ids(&state) {
                    if let Err(e) = run_for_tenant(&state, &t).await {
                        tracing::warn!("posture: tenant '{t}' failed: {e}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

/// `GET /api/v1/posture`: yesterday (actual and its forecast), today (live) and tomorrow.
pub async fn cards(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let t = ctx.scope();
    let today = latest_today(&state, &t).await;
    let yesterday = latest_before(&state, &t, today_utc()).await;
    Json(json!({
        "status": "ok",
        "yesterday": yesterday.as_ref().map(|d| json!({ "day": d.day, "score": d.posture.score, "band": d.posture.band, "forecast": d.forecast_for_this_day })),
        "today": today,
        "tomorrow": today.as_ref().map(|d| &d.forecast_next),
    }))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    days: Option<u32>,
}

/// `GET /api/v1/posture/history?days=30`: one row per day, with the forecast that was made for it.
pub async fn history(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Query(q): Query<HistoryQuery>) -> Json<Value> {
    let days = stored_days(&state, &ctx.scope(), q.days.unwrap_or(30).min(365)).await;
    let rows: Vec<Value> = days
        .iter()
        .map(|d| json!({ "day": d.day, "score": d.posture.score, "band": d.posture.band, "components": d.posture.components, "forecast": d.forecast_for_this_day, "drivers": d.posture.drivers }))
        .collect();
    Json(json!({ "status": "ok", "days": rows }))
}

/// `GET /api/v1/posture/agents`: each host's score, weakest first.
pub async fn agents(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let hosts = latest_today(&state, &ctx.scope()).await.map(|d| d.posture.hosts).unwrap_or_default();
    Json(json!({ "status": "ok", "hosts": hosts }))
}

static LAST_RUN: std::sync::Mutex<Option<HashMap<String, std::time::Instant>>> = std::sync::Mutex::new(None);

/// `POST /api/v1/posture/run`: recompute now (tenant admin; at most once a minute).
pub async fn run_now(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !(ctx.is_tenant_admin() || ctx.is_super()) {
        return (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": "Only the tenant admin recomputes the posture" }))).into_response();
    }
    let t = ctx.scope();
    {
        let mut g = LAST_RUN.lock().unwrap();
        let m = g.get_or_insert_with(Default::default);
        if m.get(&t).is_some_and(|i| i.elapsed() < Duration::from_secs(60)) {
            return Json(json!({ "status": "error", "message": "The posture was just updated; try again in a minute" })).into_response();
        }
        m.insert(t.clone(), std::time::Instant::now());
    }
    match run_for_tenant(&state, &t).await {
        Ok(d) => Json(json!({ "status": "ok", "today": d })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e }))).into_response(),
    }
}
