use axum::{
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use siem_core::Alert;
use std::sync::Arc;

use crate::engine::RiskFabricEngine;
use crate::models::{
    BusinessProcessDefinition, BusinessTimeWindow, RiskEvaluationRequest, RiskFabricScore,
    RiskFabricSummary,
};

#[derive(Clone)]
pub struct RiskFabricApiState {
    pub engine: Arc<RiskFabricEngine>,
    pub get_alerts: Arc<dyn Fn() -> Vec<Alert> + Send + Sync>,
}

pub fn router(
    engine: Arc<RiskFabricEngine>,
    get_alerts: Arc<dyn Fn() -> Vec<Alert> + Send + Sync>,
) -> Router {
    let state = RiskFabricApiState { engine, get_alerts };
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

async fn get_summary_handler(
    State(state): State<RiskFabricApiState>,
) -> Json<RiskFabricSummary> {
    let alerts = (state.get_alerts)();
    Json(state.engine.get_summary(&alerts))
}

async fn get_processes_handler(
    State(state): State<RiskFabricApiState>,
) -> Json<Vec<BusinessProcessDefinition>> {
    Json(state.engine.get_processes())
}

async fn post_process_handler(
    State(state): State<RiskFabricApiState>,
    Json(proc): Json<BusinessProcessDefinition>,
) -> Json<serde_json::Value> {
    state.engine.add_or_update_process(proc);
    Json(serde_json::json!({
        "status": "success",
        "message": "Business process updated successfully"
    }))
}

async fn delete_process_handler(
    State(state): State<RiskFabricApiState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let ok = state.engine.delete_process(&id);
    Json(serde_json::json!({
        "status": if ok { "success" } else { "not_found" }
    }))
}

async fn get_windows_handler(
    State(state): State<RiskFabricApiState>,
) -> Json<Vec<BusinessTimeWindow>> {
    Json(state.engine.get_windows())
}

async fn post_window_handler(
    State(state): State<RiskFabricApiState>,
    Json(win): Json<BusinessTimeWindow>,
) -> Json<serde_json::Value> {
    state.engine.add_or_update_window(win);
    Json(serde_json::json!({
        "status": "success",
        "message": "Business time window updated successfully"
    }))
}

async fn delete_window_handler(
    State(state): State<RiskFabricApiState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let ok = state.engine.delete_window(&id);
    Json(serde_json::json!({
        "status": if ok { "success" } else { "not_found" }
    }))
}

async fn post_evaluate_handler(
    State(state): State<RiskFabricApiState>,
    Json(req): Json<RiskEvaluationRequest>,
) -> Json<RiskFabricScore> {
    let score = state.engine.simulate(&req);
    Json(score)
}
