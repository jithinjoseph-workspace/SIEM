use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::catalog::KILL_CHAIN_STAGES;
use crate::engine::IntentEngine;
use crate::models::{
    EntityIntentDossier, ExecuteActionRequest, IntentSummaryReport, PreemptiveAction,
    SimulationIntentRequest,
};

#[derive(Clone)]
pub struct IntentApiState {
    pub engine: Arc<IntentEngine>,
    pub get_alerts: Option<Arc<dyn Fn() -> Vec<siem_core::Alert> + Send + Sync>>,
    pub get_fleet: Option<Arc<dyn Fn() -> Vec<(String, String, String, Option<String>)> + Send + Sync>>,
    pub dispatcher: Option<Arc<dyn Fn(&str, &str, &str) + Send + Sync>>,
}

pub fn router(
    engine: Arc<IntentEngine>,
    get_alerts: Option<Arc<dyn Fn() -> Vec<siem_core::Alert> + Send + Sync>>,
    get_fleet: Option<Arc<dyn Fn() -> Vec<(String, String, String, Option<String>)> + Send + Sync>>,
    dispatcher: Option<Arc<dyn Fn(&str, &str, &str) + Send + Sync>>,
) -> Router {
    let state = IntentApiState {
        engine,
        get_alerts,
        get_fleet,
        dispatcher,
    };

    Router::new()
        .route("/summary", get(get_summary_handler))
        .route("/hypotheses", get(get_hypotheses_handler))
        .route("/hypotheses/:id", get(get_hypothesis_by_id_handler))
        .route("/evaluate", post(post_evaluate_handler))
        .route("/actions/execute", post(post_execute_action_handler))
        .route("/catalog", get(get_catalog_handler))
        .with_state(state)
}

async fn get_summary_handler(
    State(state): State<IntentApiState>,
) -> Json<IntentSummaryReport> {
    if let Some(fleet_reader) = &state.get_fleet {
        let fleet = fleet_reader();
        state.engine.sync_enrolled_fleet(&fleet);
    }
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_summary())
}

async fn get_hypotheses_handler(
    State(state): State<IntentApiState>,
) -> Json<Vec<EntityIntentDossier>> {
    if let Some(fleet_reader) = &state.get_fleet {
        let fleet = fleet_reader();
        state.engine.sync_enrolled_fleet(&fleet);
    }
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_dossiers())
}

async fn get_hypothesis_by_id_handler(
    State(state): State<IntentApiState>,
    Path(id): Path<String>,
) -> Result<Json<EntityIntentDossier>, (StatusCode, Json<serde_json::Value>)> {
    match state.engine.get_dossier(&id) {
        Some(dossier) => Ok(Json(dossier)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Dossier with ID '{}' not found", id)
            })),
        )),
    }
}

async fn post_evaluate_handler(
    State(state): State<IntentApiState>,
    Json(req): Json<SimulationIntentRequest>,
) -> Json<EntityIntentDossier> {
    let dossier = state.engine.simulate(&req);
    Json(dossier)
}

async fn post_execute_action_handler(
    State(state): State<IntentApiState>,
    Json(req): Json<ExecuteActionRequest>,
) -> Result<Json<PreemptiveAction>, (StatusCode, Json<serde_json::Value>)> {
    match state.engine.execute_action(&req, state.dispatcher.as_ref()) {
        Ok(action) => Ok(Json(action)),
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": err
            })),
        )),
    }
}

async fn get_catalog_handler() -> Json<serde_json::Value> {
    let archetypes = vec![
        serde_json::json!({
            "key": "ransomware_extortion",
            "name": "Ransomware & Double Extortion",
            "severity": "Critical",
            "description": "Pre-detonation indicators: shadow volume deletion, backup disablement, high-write entropy."
        }),
        serde_json::json!({
            "key": "data_exfiltration",
            "name": "Data Theft & Exfiltration",
            "severity": "High",
            "description": "Staging directories, mass archiving, encrypted egress pipelines."
        }),
        serde_json::json!({
            "key": "apt_espionage",
            "name": "Long-Term APT & Identity Dominance",
            "severity": "Critical",
            "description": "Kerberoasting, credential harvesting, golden ticket generation, dormant persistence."
        }),
        serde_json::json!({
            "key": "destructive_sabotage",
            "name": "Destructive Wiper / Sabotage",
            "severity": "Catastrophic",
            "description": "Disk-level raw writes, master boot record tampering, event log eradication."
        }),
        serde_json::json!({
            "key": "cryptojacking",
            "name": "Cryptojacking & Resource Hijacking",
            "severity": "Medium",
            "description": "Mining pool communication, hidden CPU/GPU process injection."
        }),
    ];

    Json(serde_json::json!({
        "kill_chain_stages": KILL_CHAIN_STAGES,
        "archetypes": archetypes
    }))
}
