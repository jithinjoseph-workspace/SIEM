// WEC (Windows Event Collector) receiver
// POST /api/siem/wec  — raw Windows XML EventLog or JSON from Winlogbeat/NXLog
// Auth: Authorization: Bearer <ingest_key>  — same key system as /api/siem/ingest

use axum::{extract::State, body::Bytes, http::{HeaderMap, StatusCode}};
use sha2::{Sha256, Digest};
use tracing::{info, warn};
use crate::AppState;

pub async fn handle_wec(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if body.is_empty() {
        return StatusCode::BAD_REQUEST;
    }

    // ── Authenticate via ingest key ────────────────────────────────────────
    let raw_key = match extract_bearer(&headers) {
        Some(k) => k,
        None => {
            warn!("WEC ingest: missing Authorization header");
            return StatusCode::UNAUTHORIZED;
        }
    };

    let key_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));
    let sql = format!(
        "SELECT tenant_id, source_id FROM ndr.siem_ingest_keys FINAL \
         WHERE key_hash = '{}' AND active = 1 LIMIT 1 FORMAT JSONEachRow",
        key_hash.replace('\'', "")
    );

    let client = reqwest::Client::new();
    let resp = match client.get(&state.clickhouse_url).query(&[("query", &sql)]).send().await {
        Ok(r) => r,
        Err(e) => { warn!("WEC key lookup error: {e}"); return StatusCode::INTERNAL_SERVER_ERROR; }
    };

    let text = resp.text().await.unwrap_or_default();
    let row: serde_json::Value = match text.lines().next().and_then(|l| serde_json::from_str(l).ok()) {
        Some(v) => v,
        None => {
            warn!("WEC ingest: invalid or inactive ingest key");
            return StatusCode::UNAUTHORIZED;
        }
    };

    let tenant_id = row["tenant_id"].as_str().unwrap_or("").to_string();
    let source_id = row["source_id"].as_str().unwrap_or("").to_string();

    if tenant_id.is_empty() || source_id.is_empty() {
        return StatusCode::UNAUTHORIZED;
    }

    let raw = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(_) => { warn!("WEC: non-UTF8 body"); return StatusCode::BAD_REQUEST; }
    };

    info!("WEC ingest: tenant={} source_id={} bytes={}", tenant_id, source_id, raw.len());

    let pipeline = std::sync::Arc::clone(&state.pipeline);
    tokio::spawn(async move {
        pipeline.process_wec(&raw, &tenant_id, &source_id).await;
    });

    StatusCode::OK
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("Authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|s| s.to_string())
}
