//! Retrospective scans for the SIEM (siem-retro), per tenant: the
//! SIEM retrospective page's `/api/v1/siem/retrospective/*`. A rule scan sends the tenant's
//! stored events (last N hours) again through the running analysisd's logtest,
//! so the current ruleset decides; a keyword scan searches them.

use axum::extract::{Extension, Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use siem_retro::{Event, Kind, Scan, ScanRequest};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

const MAX_RUNNING_PER_TENANT: usize = 1;

#[derive(clickhouse::Row, Deserialize)]
struct EventRow {
    id: String,
    timestamp: u64,
    agent_id: String,
    location: String,
    message: String,
}

async fn events(state: &AppState, tenant: &str, hours: u32, keyword: Option<&str>) -> Result<Vec<Event>, String> {
    let since_ms = (chrono::Utc::now().timestamp().max(0) as u64).saturating_sub(hours as u64 * 3600) * 1000;
    let sql = if keyword.is_some() {
        "SELECT id, timestamp, agent_id, location, substring(message, 1, 8000) AS message FROM siem_events WHERE timestamp >= ? AND positionCaseInsensitive(message, ?) > 0 ORDER BY timestamp DESC LIMIT ?"
    } else {
        "SELECT id, timestamp, agent_id, location, substring(message, 1, 8000) AS message FROM siem_events WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?"
    };
    let mut q = state.db.tenant_client(tenant).query(sql).bind(since_ms);
    if let Some(k) = keyword {
        q = q.bind(k);
    }
    let rows = q.bind(siem_retro::MAX_EVENTS).fetch_all::<EventRow>().await.map_err(|e| e.to_string())?;
    let names: std::collections::HashMap<String, String> = state.agents.read().unwrap().iter().map(|(id, a)| (id.clone(), a.name.clone())).collect();
    Ok(rows
        .into_iter()
        .map(|r| Event { agent_name: names.get(&r.agent_id).cloned().unwrap_or_default(), id: r.id, timestamp: r.timestamp, agent_id: r.agent_id, location: r.location, message: r.message })
        .collect())
}

/// One logtest request on analysisd's socket.
pub(crate) async fn logtest(req: &str) -> Result<String, String> {
    let path = crate::wazuh_manager::home().join("queue/sockets/logtest");
    let mut s = siem_ipc::local::LocalStream::connect(&path).await.map_err(|e| format!("analysisd logtest is not reachable ({}): {e}", path.display()))?;
    siem_ipc::framing::send(&mut s, req.as_bytes()).await.map_err(|e| format!("logtest: {e:?}"))?;
    let r = siem_ipc::framing::recv(&mut s, siem_ipc::OS_MAXSTR).await.map_err(|e| format!("logtest: {e:?}"))?;
    Ok(String::from_utf8_lossy(&r).into_owned())
}

async fn save(state: &AppState, tenant: &str, scan: &Scan) {
    if let Ok(doc) = serde_json::to_string(scan) {
        let _ = state.db.put_doc(tenant, DocTable::RetroScans, &scan.id, &doc).await;
    }
}

async fn run(state: AppState, tenant: String, mut scan: Scan, kind: Kind) {
    let r: Result<(), String> = async {
        match &kind {
            Kind::Keyword(k) => {
                for e in events(&state, &tenant, scan.hours_back, Some(k)).await? {
                    siem_retro::record(&mut scan, siem_retro::keyword_match(&e, k));
                }
            }
            Kind::Rule(id) => {
                let evs = events(&state, &tenant, scan.hours_back, None).await?;
                let mut token: Option<String> = None;
                for (i, e) in evs.iter().enumerate() {
                    let v = siem_retro::parse_logtest_response(&logtest(&siem_retro::logtest_request(e, token.as_deref())).await?)?;
                    if token.is_none() && !v.token.is_empty() {
                        token = Some(v.token.clone());
                    }
                    siem_retro::record(&mut scan, siem_retro::rule_match(e, &v, *id));
                    if i % 2000 == 1999 {
                        save(&state, &tenant, &scan).await; // progress
                    }
                }
                if let Some(t) = token {
                    let _ = logtest(&siem_retro::remove_session_request(&t)).await;
                }
            }
        }
        Ok(())
    }
    .await;
    siem_retro::finish(&mut scan, r.err(), chrono::Utc::now());
    save(&state, &tenant, &scan).await;
}

async fn scans(state: &AppState, tenant: &str) -> Vec<Scan> {
    state.db.docs(tenant, DocTable::RetroScans, 100).await.unwrap_or_default().iter().filter_map(|d| serde_json::from_str(d).ok()).collect()
}

/// `POST /api/v1/siem/retrospective/scan`
pub async fn start(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<ScanRequest>) -> Json<Value> {
    let kind = match r.kind() {
        Ok(k) => k,
        Err(e) => return Json(json!({ "status": "error", "message": e })),
    };
    let tenant = ctx.scope();
    if scans(&state, &tenant).await.iter().filter(|s| s.status == "running").count() >= MAX_RUNNING_PER_TENANT {
        return Json(json!({ "status": "error", "message": "A scan is already running; wait for it to finish" }));
    }
    let scan = Scan::start(uuid::Uuid::new_v4().to_string(), &r, chrono::Utc::now());
    save(&state, &tenant, &scan).await;
    let id = scan.id.clone();
    tokio::spawn(run(state, tenant, scan, kind));
    Json(json!({ "status": "ok", "scan_id": id }))
}

/// `GET /api/v1/siem/retrospective/scans`
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    Json(json!({ "scans": scans(&state, &ctx.scope()).await.iter().map(Scan::summary).collect::<Vec<_>>() }))
}

/// `GET /api/v1/siem/retrospective/scans/:id`
pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    match state.db.doc(&ctx.scope(), DocTable::RetroScans, &id).await.ok().flatten().and_then(|d| serde_json::from_str::<Scan>(&d).ok()) {
        Some(s) => Json(json!({ "scan": s })),
        None => Json(json!({ "status": "error", "message": "Scan not found" })),
    }
}

/// `GET /api/v1/siem/retrospective/fired-rules`: the Wazuh rules that fired for the tenant (7 days).
pub async fn fired_rules(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let since_ms = (chrono::Utc::now().timestamp().max(0) as u64).saturating_sub(7 * 86400) * 1000;
    let rows = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT rule_id, any(rule_description), count() FROM siem_alerts WHERE timestamp >= ? GROUP BY rule_id ORDER BY count() DESC LIMIT 300")
        .bind(since_ms)
        .fetch_all::<(u32, String, u64)>()
        .await
        .unwrap_or_default();
    Json(json!({ "rules": rows.into_iter().map(|(id, d, n)| json!({ "id": id.to_string(), "name": format!("{id}: {d}"), "hit_count": n, "engine": "Wazuh" })).collect::<Vec<_>>() }))
}
