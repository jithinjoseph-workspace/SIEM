use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Extension, Router,
};
use siem_core::Alert;
use std::sync::Arc;

use crate::engine::RiskFabricEngine;
use crate::models::{
    BusinessProcessDefinition, BusinessTimeWindow, FleetAgentMeta, RiskEvaluationRequest,
    RiskFabricScore, RiskFabricSummary,
};

/// Optional tenant-scoped alert override injected by host API middleware.
#[derive(Clone)]
pub struct ScopedAlerts(pub Vec<Alert>);

/// The caller's tenant, injected by the host API: whose settings a request reads and changes.
#[derive(Clone)]
pub struct TenantScope(pub String);

/// The tenant of a request (the default tenant when the host injected none).
fn tenant_of(scope: &Option<Extension<TenantScope>>) -> String {
    scope.as_ref().map(|Extension(TenantScope(t))| t.clone()).unwrap_or_else(|| "default".into())
}

type Answer = Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)>;

fn refused(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": msg })))
}

#[derive(Clone)]
pub struct RiskFabricApiState {
    pub engine: Arc<RiskFabricEngine>,
    pub get_alerts: Arc<dyn Fn() -> Vec<Alert> + Send + Sync>,
    pub fleet_reader: Option<Arc<dyn Fn() -> Vec<(String, String, String, Option<String>)> + Send + Sync>>,
    pub rich_fleet_reader: Option<Arc<dyn Fn() -> Vec<FleetAgentMeta> + Send + Sync>>,
}

pub fn router(
    engine: Arc<RiskFabricEngine>,
    get_alerts: Arc<dyn Fn() -> Vec<Alert> + Send + Sync>,
    fleet_reader: Option<Arc<dyn Fn() -> Vec<(String, String, String, Option<String>)> + Send + Sync>>,
) -> Router {
    let state = RiskFabricApiState {
        engine,
        get_alerts,
        fleet_reader,
        rich_fleet_reader: None,
    };
    build_router(state)
}

pub fn router_with_meta(
    engine: Arc<RiskFabricEngine>,
    get_alerts: Arc<dyn Fn() -> Vec<Alert> + Send + Sync>,
    rich_fleet_reader: Option<Arc<dyn Fn() -> Vec<FleetAgentMeta> + Send + Sync>>,
) -> Router {
    let state = RiskFabricApiState {
        engine,
        get_alerts,
        fleet_reader: None,
        rich_fleet_reader,
    };
    build_router(state)
}

fn build_router(state: RiskFabricApiState) -> Router {
    Router::new()
        .route("/summary", get(get_summary_handler))
        .route(
            "/processes",
            get(get_processes_handler).post(post_process_handler),
        )
        .route("/processes/:id", delete(delete_process_handler))
        .route(
            "/windows",
            get(get_windows_handler).post(post_window_handler),
        )
        .route("/windows/:id", delete(delete_window_handler))
        .route("/evaluate", post(post_evaluate_handler))
        .with_state(state)
}

fn trigger_fleet_sync(state: &RiskFabricApiState) {
    if let Some(ref rfr) = state.rich_fleet_reader {
        state.engine.sync_fleet_meta(&rfr());
    } else if let Some(ref fr) = state.fleet_reader {
        state.engine.sync_fleet(&fr());
    }
}

async fn get_summary_handler(
    State(state): State<RiskFabricApiState>,
    scope: Option<Extension<TenantScope>>,
    scoped: Option<Extension<ScopedAlerts>>,
) -> Json<RiskFabricSummary> {
    trigger_fleet_sync(&state);
    let alerts = match scoped {
        Some(Extension(ScopedAlerts(list))) => list,
        None => (state.get_alerts)(),
    };
    Json(state.engine.get_summary(&tenant_of(&scope), &alerts))
}

async fn get_processes_handler(
    State(state): State<RiskFabricApiState>,
    scope: Option<Extension<TenantScope>>,
) -> Json<Vec<BusinessProcessDefinition>> {
    trigger_fleet_sync(&state);
    Json(state.engine.get_processes(&tenant_of(&scope)))
}

async fn post_process_handler(
    State(state): State<RiskFabricApiState>,
    scope: Option<Extension<TenantScope>>,
    Json(proc): Json<BusinessProcessDefinition>,
) -> Answer {
    state.engine.add_or_update_process(&tenant_of(&scope), proc).map_err(refused)?;
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Business process updated successfully"
    })))
}

async fn delete_process_handler(
    State(state): State<RiskFabricApiState>,
    scope: Option<Extension<TenantScope>>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let ok = state.engine.delete_process(&tenant_of(&scope), &id);
    Json(serde_json::json!({
        "status": if ok { "success" } else { "not_found" }
    }))
}

async fn get_windows_handler(
    State(state): State<RiskFabricApiState>,
    scope: Option<Extension<TenantScope>>,
) -> Json<Vec<BusinessTimeWindow>> {
    Json(state.engine.get_windows(&tenant_of(&scope)))
}

async fn post_window_handler(
    State(state): State<RiskFabricApiState>,
    scope: Option<Extension<TenantScope>>,
    Json(win): Json<BusinessTimeWindow>,
) -> Answer {
    state.engine.add_or_update_window(&tenant_of(&scope), win).map_err(refused)?;
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Business time window updated successfully"
    })))
}

async fn delete_window_handler(
    State(state): State<RiskFabricApiState>,
    scope: Option<Extension<TenantScope>>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let ok = state.engine.delete_window(&tenant_of(&scope), &id);
    Json(serde_json::json!({
        "status": if ok { "success" } else { "not_found" }
    }))
}

async fn post_evaluate_handler(
    State(state): State<RiskFabricApiState>,
    scope: Option<Extension<TenantScope>>,
    Json(req): Json<RiskEvaluationRequest>,
) -> Json<RiskFabricScore> {
    trigger_fleet_sync(&state);
    Json(state.engine.simulate(&tenant_of(&scope), &req))
}
