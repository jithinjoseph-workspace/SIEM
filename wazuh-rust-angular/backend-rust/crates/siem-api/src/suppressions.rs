//! Alert suppressions for the SIEM (siem-suppression), per tenant: the AI
//! SIEM AI activity page's `/api/v1/siem/suppressions` and `/ai-activity`, and the check
//! `on_alerts` makes. A suppressed alert is still stored (ClickHouse keeps it
//! for search and audit); it is not shown live, kept in the console's recent
//! alerts, or acted on by SOAR playbooks.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Extension, Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use siem_suppression::{AlertKey, Request, Suppression};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

const CACHE_TTL: Duration = Duration::from_secs(60);
static CACHE: Mutex<Option<HashMap<String, (Instant, Vec<Suppression>)>>> = Mutex::new(None);

pub fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn invalidate(tenant: &str) {
    if let Some(m) = CACHE.lock().unwrap().as_mut() {
        m.remove(tenant);
    }
}

/// Every suppression of the tenant, newest first.
pub async fn all(state: &AppState, tenant: &str) -> Vec<Suppression> {
    state.db.docs(tenant, DocTable::Suppressions, 1000).await.unwrap_or_default().iter().filter_map(|d| serde_json::from_str(d).ok()).collect()
}

/// The ones in force (cached for a minute).
pub async fn active(state: &AppState, tenant: &str) -> Vec<Suppression> {
    if let Some((t, l)) = CACHE.lock().unwrap().get_or_insert_with(HashMap::new).get(tenant) {
        if t.elapsed() < CACHE_TTL {
            return l.clone();
        }
    }
    let n = now();
    let list: Vec<Suppression> = all(state, tenant).await.into_iter().filter(|s| s.in_force(n)).collect();
    CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(tenant.to_string(), (Instant::now(), list.clone()));
    list
}

/// Is this alert hidden by one of the tenant's suppressions?
pub async fn is_suppressed(state: &AppState, tenant: &str, a: &siem_core::Alert) -> bool {
    if !state.db.is_connected() {
        return false;
    }
    let list = active(state, tenant).await;
    if list.is_empty() {
        return false;
    }
    let src = a.decoded.src_ip.clone().unwrap_or_default();
    let key = AlertKey { rule_id: a.rule.id, level: a.rule.level as u32, agent_id: &a.agent.id, src_ip: &src };
    siem_suppression::find(&list, &key, now()).is_some()
}

/// Saves a new one (from triage or an analyst).
pub async fn create(state: &AppState, tenant: &str, r: Request, source: &str, confidence: u8, by: &str) -> Result<Suppression, String> {
    let s = Suppression::new(uuid::Uuid::new_v4().to_string(), r, source, confidence, by, now())?;
    state.db.put_doc(tenant, DocTable::Suppressions, &s.id, &serde_json::to_string(&s).map_err(|e| e.to_string())?).await?;
    invalidate(tenant);
    Ok(s)
}

/// `GET /api/v1/siem/suppressions`
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let n = now();
    Json(json!(all(&state, &ctx.scope()).await.iter().map(|s| s.view(n)).collect::<Vec<_>>()))
}

/// The alerts page's Suppress button (NDR fields) or a SIEM rule / agent.
#[derive(Deserialize, Default)]
pub struct ManualBody {
    #[serde(default)]
    pub src_ip: String,
    pub dst_ip: Option<String>,
    pub tag: Option<String>,
    pub rule_id: Option<u32>,
    #[serde(default)]
    pub rule_name: String,
    pub agent_id: Option<String>,
    pub duration_hours: Option<u32>,
    #[serde(default)]
    pub reason: String,
}

/// `POST /api/v1/siem/suppressions`
pub async fn create_manual(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(b): Json<ManualBody>) -> Json<Value> {
    // a numeric tag is a Wazuh rule id
    let rule_id = b.rule_id.or_else(|| b.tag.as_deref().and_then(|t| t.trim().parse().ok()));
    let r = Request {
        rule_id,
        rule_name: b.rule_name,
        agent_id: b.agent_id,
        agent_name: b.dst_ip.unwrap_or_default(),
        src_ip: Some(b.src_ip),
        hours: b.duration_hours,
        reason: b.reason,
    };
    match create(&state, &ctx.scope(), r, "manual", 100, &ctx.username).await {
        Ok(s) => {
            crate::insights::log(&state, &ctx.scope(), &ctx.username, "suppress", None).await;
            Json(json!({ "ok": true, "id": s.id, "expires_at": s.expires_at }))
        }
        Err(e) => Json(json!({ "error": e })),
    }
}

async fn set_active(state: &AppState, tenant: &str, id: &str, on: bool) -> Result<(), String> {
    let doc = state.db.doc(tenant, DocTable::Suppressions, id).await?.ok_or("Suppression not found")?;
    let mut s: Suppression = serde_json::from_str(&doc).map_err(|e| e.to_string())?;
    s.active = on;
    state.db.put_doc(tenant, DocTable::Suppressions, id, &serde_json::to_string(&s).map_err(|e| e.to_string())?).await?;
    invalidate(tenant);
    Ok(())
}

/// `PATCH /api/v1/siem/suppressions/:id/deactivate`
pub async fn deactivate(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    match set_active(&state, &ctx.scope(), &id, false).await {
        Ok(()) => {
            crate::insights::log(&state, &ctx.scope(), &ctx.username, "unsuppress", None).await;
            Json(json!({ "ok": true }))
        }
        Err(e) => Json(json!({ "error": e })),
    }
}

/// `DELETE /api/v1/siem/suppressions/:id`
pub async fn delete(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    let tenant = ctx.scope();
    let r = state.db.delete_doc(&tenant, DocTable::Suppressions, &id).await;
    if r.is_ok() {
        crate::insights::log(&state, &tenant, &ctx.username, "unsuppress", None).await;
    }
    invalidate(&tenant);
    match r {
        Ok(()) => Json(json!({ "ok": true })),
        Err(e) => Json(json!({ "error": e })),
    }
}

/// `GET /api/v1/siem/ai-activity`: the suppressions, and triage's AI decisions as analyses.
pub async fn activity(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let tenant = ctx.scope();
    let n = now();
    let suppressions: Vec<Value> = all(&state, &tenant).await.iter().map(|s| s.view(n)).collect();
    let analyses: Vec<Value> = crate::triage::load(&state, &tenant)
        .await
        .recs
        .iter()
        .filter(|r| r.source == siem_triage::Source::Ai)
        .map(|r| {
            json!({
                "id": r.id,
                "bundle_id": r.key,
                "community_id": r.key,
                "severity": siem_triage::severity(r.max_level),
                "src_ip": r.src_ip,
                "dst_ip": r.agent_name,
                "src_asset": r.src_ip,
                "dst_asset": r.agent_name,
                "analysis": format!("{} ({}%, {}): {}", r.tag, r.confidence, serde_json::to_value(r.verdict).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(), r.reason),
                "created_at": r.updated_at,
            })
        })
        .collect();
    Json(json!({ "suppressions": suppressions, "analyses": analyses }))
}
