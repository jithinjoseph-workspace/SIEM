use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

use crate::engine::DeceptionEngine;
use crate::models::{
    CreateAssetRequest, DeceptionAsset, DeceptionBlueprint, DeceptionSummary,
    SimulateTripwireRequest, TripwireEvent,
};

#[derive(Clone)]
pub struct DeceptionApiState {
    pub engine: Arc<DeceptionEngine>,
    pub get_alerts: Option<Arc<dyn Fn() -> Vec<siem_core::Alert> + Send + Sync>>,
}

pub fn router(
    engine: Arc<DeceptionEngine>,
    get_alerts: Option<Arc<dyn Fn() -> Vec<siem_core::Alert> + Send + Sync>>,
) -> Router {
    let state = DeceptionApiState { engine, get_alerts };

    Router::new()
        .route("/summary", get(get_summary_handler))
        .route("/assets", get(get_assets_handler).post(post_create_asset_handler))
        .route("/assets/:id", delete(delete_asset_handler))
        .route("/triggers", get(get_triggers_handler))
        .route("/test-trigger", post(post_test_trigger_handler))
        .route("/templates", get(get_templates_handler))
        .with_state(state)
}

async fn get_summary_handler(
    State(state): State<DeceptionApiState>,
) -> Json<DeceptionSummary> {
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_summary())
}

async fn get_assets_handler(
    State(state): State<DeceptionApiState>,
) -> Json<Vec<DeceptionAsset>> {
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_assets())
}

async fn post_create_asset_handler(
    State(state): State<DeceptionApiState>,
    Json(req): Json<CreateAssetRequest>,
) -> Json<DeceptionAsset> {
    let asset = state.engine.create_asset(req);
    Json(asset)
}

async fn delete_asset_handler(
    State(state): State<DeceptionApiState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
) -> Json<Vec<TripwireEvent>> {
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_triggers())
}

async fn post_test_trigger_handler(
    State(state): State<DeceptionApiState>,
    Json(req): Json<SimulateTripwireRequest>,
) -> Result<Json<TripwireEvent>, (StatusCode, Json<serde_json::Value>)> {
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
