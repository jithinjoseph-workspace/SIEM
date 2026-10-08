// Generic REST ingest endpoint — POST /api/siem/ingest
// Auth: Authorization: Bearer <ingest_key>  (key is validated against ndr.siem_ingest_keys)
// Tenant and source are resolved from the key — not trusted from the request body.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::{info, warn};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct IngestRequest {
    /// "syslog" | "cef" | "wec" | "generic" — selects the normaliser
    pub source_type: String,
    pub raw_log:     String,
}

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub accepted: bool,
    pub message:  &'static str,
}

pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, StatusCode> {
    if req.raw_log.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // ── Authenticate via ingest key ────────────────────────────────────────
    let raw_key = extract_bearer(&headers)
        .ok_or_else(|| {
            warn!("REST ingest: missing Authorization header");
            StatusCode::UNAUTHORIZED
        })?;

    let key_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));

    let sql = format!(
        "SELECT tenant_id, source_id, name FROM ndr.siem_ingest_keys FINAL \
         WHERE key_hash = '{}' AND active = 1 LIMIT 1 FORMAT JSONEachRow",
        key_hash.replace('\'', "")
    );

    let client = reqwest::Client::new();
    let resp = client.get(&state.clickhouse_url).query(&[("query", &sql)]).send().await
        .map_err(|e| { warn!("CH key lookup error: {e}"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let text = resp.text().await.unwrap_or_default();
    let row: serde_json::Value = text.lines()
        .next()
        .and_then(|l| serde_json::from_str(l).ok())
        .ok_or_else(|| {
            warn!("REST ingest: invalid or inactive ingest key");
            StatusCode::UNAUTHORIZED
        })?;

    let tenant_id  = row["tenant_id"].as_str().unwrap_or("").to_string();
    let source_id  = row["source_id"].as_str().unwrap_or("").to_string();
    let source_type = req.source_type.clone();

    if tenant_id.is_empty() || source_id.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    info!(
        "REST ingest: tenant={} source_id={} source_type={} bytes={}",
        tenant_id, source_id, source_type, req.raw_log.len()
    );

    let pipeline = std::sync::Arc::clone(&state.pipeline);
    let raw      = req.raw_log.clone();

    tokio::spawn(async move {
        match source_type.as_str() {
            "syslog" => pipeline.process_syslog(&raw, "0.0.0.0", &tenant_id, &source_id).await,
            "cef"    => pipeline.process_cef(&raw, &tenant_id, &source_id).await,
            "wec"    => pipeline.process_wec(&raw, &tenant_id, &source_id).await,
            _        => pipeline.process_unknown(&raw, &tenant_id, &source_id).await,
        }
    });

    Ok(Json(IngestResponse { accepted: true, message: "accepted" }))
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("Authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|s| s.to_string())
}
