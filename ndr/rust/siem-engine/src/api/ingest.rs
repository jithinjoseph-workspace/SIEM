use axum::{extract::State, Json};
use axum::http::StatusCode;
use serde_json::{json, Value};
use crate::AppState;

#[allow(dead_code)]
pub async fn handle(
    State(_state): State<AppState>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let event_count = payload.as_array().map(|a| a.len()).unwrap_or(1);
    // TODO Phase 1: validate JWT tenant, write to Kafka siem-logs topic, dedup via Valkey
    tracing::info!("siem/ingest received {} event(s)", event_count);
    (StatusCode::ACCEPTED, Json(json!({ "status": "accepted", "count": event_count })))
}
