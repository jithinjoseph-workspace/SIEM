use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use std::sync::Arc;

use crate::catalog::KILL_CHAIN_STAGES;
use crate::engine::IntentEngine;
use crate::models::{
    ActionAuditRecord, EntityIntentDossier, ExecuteActionRequest, IntentSummaryReport,
    PreemptiveAction, SimulationIntentRequest,
};

/// Which computers the caller may see and act on (its tenant's), injected by the host API.
#[derive(Clone)]
pub struct Visible(pub Arc<dyn Fn(&str) -> bool + Send + Sync>);

/// Without a host check (tests), every computer.
fn sees(v: &Option<Extension<Visible>>, agent_id: &str) -> bool {
    v.as_ref().map_or(true, |Extension(Visible(f))| f(agent_id))
}

type Refusal = (StatusCode, Json<serde_json::Value>);

fn not_found(what: &str) -> Refusal {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": format!("{what} not found") })))
}

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
        .route("/actions/audit", get(get_actions_audit_handler))
        .route("/revert/:id", post(post_revert_simulation_handler))
        .route("/catalog", get(get_catalog_handler))
        .with_state(state)
}

async fn get_summary_handler(
    State(state): State<IntentApiState>,
    vis: Option<Extension<Visible>>,
) -> Json<IntentSummaryReport> {
    if let Some(fleet_reader) = &state.get_fleet {
        let fleet = fleet_reader();
        state.engine.sync_enrolled_fleet(&fleet);
    }
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_summary_where(&|id| sees(&vis, id)))
}

async fn get_hypotheses_handler(
    State(state): State<IntentApiState>,
    vis: Option<Extension<Visible>>,
) -> Json<Vec<EntityIntentDossier>> {
    if let Some(fleet_reader) = &state.get_fleet {
        let fleet = fleet_reader();
        state.engine.sync_enrolled_fleet(&fleet);
    }
    if let Some(reader) = &state.get_alerts {
        let alerts = reader();
        state.engine.ingest_live_alerts(&alerts);
    }
    Json(state.engine.get_dossiers().into_iter().filter(|d| sees(&vis, &d.entity_id)).collect())
}

async fn get_hypothesis_by_id_handler(
    State(state): State<IntentApiState>,
    vis: Option<Extension<Visible>>,
    Path(id): Path<String>,
) -> Result<Json<EntityIntentDossier>, (StatusCode, Json<serde_json::Value>)> {
    match state.engine.get_dossier(&id).filter(|d| sees(&vis, &d.entity_id)) {
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
    vis: Option<Extension<Visible>>,
    Json(req): Json<SimulationIntentRequest>,
) -> Result<Json<EntityIntentDossier>, Refusal> {
    // a simulation is shown on that computer's dossier: only on the caller's own computers
    if !sees(&vis, &req.agent_id) {
        return Err(not_found("Computer"));
    }
    Ok(Json(state.engine.simulate(&req)))
}

async fn post_execute_action_handler(
    State(state): State<IntentApiState>,
    vis: Option<Extension<Visible>>,
    Json(req): Json<ExecuteActionRequest>,
) -> Result<Json<PreemptiveAction>, (StatusCode, Json<serde_json::Value>)> {
    // an action runs on its computer: never on another tenant's
    if !state.engine.action_agent(&req.action_id).is_some_and(|a| sees(&vis, &a)) {
        return Err(not_found("Action"));
    }
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

async fn get_actions_audit_handler(
    State(state): State<IntentApiState>,
    vis: Option<Extension<Visible>>,
) -> Json<Vec<ActionAuditRecord>> {
    Json(state.engine.get_action_audit().into_iter().filter(|r| sees(&vis, &r.target_agent_id)).collect())
}

async fn post_revert_simulation_handler(
    State(state): State<IntentApiState>,
    vis: Option<Extension<Visible>>,
    Path(id): Path<String>,
) -> Result<Json<EntityIntentDossier>, (StatusCode, Json<serde_json::Value>)> {
    if !sees(&vis, &id) {
        return Err(not_found("Computer"));
    }
    match state.engine.revert_simulation(&id) {
        Some(dossier) => {
            if let Some(reader) = &state.get_alerts {
                let alerts = reader();
                state.engine.ingest_live_alerts(&alerts);
            }
            let final_dossier = state.engine.get_dossier(&id).unwrap_or(dossier);
            Ok(Json(final_dossier))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Target '{}' not found", id)
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
