use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Extension, Router,
};
use std::sync::Arc;

use crate::engine::DeceptionEngine;
use crate::models::{
    CreateAssetRequest, DeceptionAsset, DeceptionBlueprint, DeceptionSummary, FleetNodeInfo,
    SimulateTripwireRequest, TripwireEvent,
};

/// Which computers the caller may see and act on (its tenant's), injected by the host API.
#[derive(Clone)]
pub struct Visible(pub Arc<dyn Fn(&str) -> bool + Send + Sync>);

/// Without a host check (tests), every computer.
fn sees(v: &Option<Extension<Visible>>, agent_id: &str) -> bool {
    v.as_ref().map_or(true, |Extension(Visible(f))| f(agent_id))
}

fn not_found(what: &str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": format!("{what} not found") })))
}

/// The fleet the caller sees.
fn fleet_of(state: &DeceptionApiState, vis: &Option<Extension<Visible>>) -> Vec<FleetNodeInfo> {
    let all = match &state.get_fleet {
        Some(f) => f(),
        None => state.engine.get_fleet_nodes(),
    };
    all.into_iter().filter(|n| sees(vis, &n.id)).collect()
}

#[derive(Clone)]
pub struct DeceptionApiState {
    pub engine: Arc<DeceptionEngine>,
    pub get_alerts: Option<Arc<dyn Fn() -> Vec<siem_core::Alert> + Send + Sync>>,
    pub get_fleet: Option<Arc<dyn Fn() -> Vec<FleetNodeInfo> + Send + Sync>>,
}

pub fn router(
    engine: Arc<DeceptionEngine>,
    get_alerts: Option<Arc<dyn Fn() -> Vec<siem_core::Alert> + Send + Sync>>,
) -> Router {
    router_with_fleet(engine, get_alerts, None)
}

pub fn router_with_fleet(
    engine: Arc<DeceptionEngine>,
    get_alerts: Option<Arc<dyn Fn() -> Vec<siem_core::Alert> + Send + Sync>>,
    get_fleet: Option<Arc<dyn Fn() -> Vec<FleetNodeInfo> + Send + Sync>>,
) -> Router {
    let state = DeceptionApiState {
        engine,
        get_alerts,
        get_fleet,
    };

    Router::new()
        .route("/summary", get(get_summary_handler))
        .route("/assets", get(get_assets_handler).post(post_create_asset_handler))
        .route("/assets/:id", delete(delete_asset_handler))
        .route("/triggers", get(get_triggers_handler).delete(delete_triggers_handler))
        .route("/test-trigger", post(post_test_trigger_handler))
        .route("/templates", get(get_templates_handler))
        .route("/fleet", get(get_fleet_handler))
        .with_state(state)
}

async fn get_summary_handler(
    State(state): State<DeceptionApiState>,
    vis: Option<Extension<Visible>>,
) -> Json<DeceptionSummary> {
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    let fleet = fleet_of(&state, &vis).len();
    Json(state.engine.get_summary_where(&|id| sees(&vis, id), fleet))
}

async fn get_assets_handler(
    State(state): State<DeceptionApiState>,
    vis: Option<Extension<Visible>>,
) -> Json<Vec<DeceptionAsset>> {
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_assets().into_iter().filter(|a| sees(&vis, &a.target_agent_id)).collect())
}

async fn post_create_asset_handler(
    State(state): State<DeceptionApiState>,
    vis: Option<Extension<Visible>>,
    Json(req): Json<CreateAssetRequest>,
) -> Result<Json<DeceptionAsset>, (StatusCode, Json<serde_json::Value>)> {
    // a decoy is deployed on its computer: only on the caller's own
    if !sees(&vis, &req.target_agent_id) {
        return Err(not_found("Computer"));
    }
    Ok(Json(state.engine.create_asset(req)))
}

async fn delete_asset_handler(
    State(state): State<DeceptionApiState>,
    vis: Option<Extension<Visible>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !state.engine.asset_agent(&id).is_some_and(|a| sees(&vis, &a)) {
        return Err(not_found("Deception asset"));
    }
    match state.engine.delete_asset(&id) {
        Ok(()) => Ok(Json(serde_json::json!({
            "status": "success",
            "message": format!("Deception asset '{}' successfully decommissioned", id)
        }))),
        Err(e) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "error",
                "message": e
            })),
        )),
    }
}

async fn get_triggers_handler(
    State(state): State<DeceptionApiState>,
    vis: Option<Extension<Visible>>,
) -> Json<Vec<TripwireEvent>> {
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_triggers().into_iter().filter(|e| sees(&vis, &e.agent_id)).collect())
}

async fn delete_triggers_handler(
    State(state): State<DeceptionApiState>,
    vis: Option<Extension<Visible>>,
) -> Json<serde_json::Value> {
    state.engine.clear_triggers_where(&|id| sees(&vis, id));
    Json(serde_json::json!({
        "status": "success",
        "message": "Tripwire trigger history cleared successfully"
    }))
}

async fn post_test_trigger_handler(
    State(state): State<DeceptionApiState>,
    vis: Option<Extension<Visible>>,
    Json(req): Json<SimulateTripwireRequest>,
) -> Result<Json<TripwireEvent>, (StatusCode, Json<serde_json::Value>)> {
    if !state.engine.asset_agent(&req.asset_id).is_some_and(|a| sees(&vis, &a)) {
        return Err(not_found("Deception asset"));
    }
    match state.engine.simulate_tripwire(req) {
        Ok(event) => Ok(Json(event)),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": e
            })),
        )),
    }
}

async fn get_templates_handler(
    State(state): State<DeceptionApiState>,
) -> Json<Vec<DeceptionBlueprint>> {
    Json(state.engine.get_blueprints())
}

async fn get_fleet_handler(
    State(state): State<DeceptionApiState>,
    vis: Option<Extension<Visible>>,
) -> Json<Vec<FleetNodeInfo>> {
    Json(fleet_of(&state, &vis))
}
