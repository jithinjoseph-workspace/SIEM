// Elasticsearch-compatible ingest endpoints for Winlogbeat / Filebeat / Metricbeat
// Winlogbeat uses output.elasticsearch which calls:
//   GET  /             — cluster info
//   POST /_bulk        — batch index (ndjson: action\ndoc\n...)
// Auth: same Bearer key as /api/siem/ingest

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};
use sha2::{Sha256, Digest};
use tracing::{info, warn};
use crate::AppState;

/// GET / — returns ES cluster info so Winlogbeat handshake succeeds
pub async fn cluster_info() -> Json<Value> {
    Json(json!({
        "name": "promasecure-siem",
        "cluster_name": "promasecure",
        "cluster_uuid": "promasecure-siem-001",
        "version": {
            "number": "8.11.0",
            "build_flavor": "default",
            "minimum_wire_compatibility_version": "7.17.0",
            "minimum_index_compatibility_version": "7.0.0"
        },
        "tagline": "You Know, for Logs"
    }))
}

/// GET /_license — Winlogbeat checks this on startup
pub async fn license() -> Json<Value> {
    Json(json!({
        "license": {
            "uid": "promasecure-license",
            "type": "basic",
            "status": "active"
        }
    }))
}

/// GET /_xpack — X-Pack feature check
pub async fn xpack() -> Json<Value> {
    Json(json!({
        "build": { "hash": "promasecure", "date": "2024-01-01" },
        "license": { "uid": "promasecure", "type": "basic", "status": "active" },
        "features": {}
    }))
}

/// HEAD or GET on any index — tell Winlogbeat the index doesn't need setup
pub async fn index_stub() -> StatusCode { StatusCode::OK }

/// PUT _index_template / _component_template / _data_stream — just accept
pub async fn template_stub() -> Json<Value> {
    Json(json!({ "acknowledged": true }))
}

/// GET/PUT /_ilm/policy/:name — Winlogbeat 9.x checks/creates ILM policy on startup
pub async fn ilm_stub() -> Json<Value> {
    Json(json!({
        "acknowledged": true,
        "promasecure-siem": {
            "version": 1,
            "modified_date": "2024-01-01T00:00:00.000Z",
            "policy": { "phases": {} }
        }
    }))
}

/// POST /_bulk — receives ndjson from Winlogbeat, extracts docs and ingests
pub async fn bulk_ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, StatusCode> {
    // Windows Event Log can contain non-UTF-8 bytes — decode lossily
    let body = String::from_utf8_lossy(&body).into_owned();

    // ── Authenticate via ingest key ────────────────────────────────────────
    let raw_key = match extract_bearer(&headers) {
        Some(k) => k,
        None => {
            warn!("Beats bulk: missing Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let key_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));
    let sql = format!(
        "SELECT tenant_id, source_id FROM ndr.siem_ingest_keys FINAL \
         WHERE key_hash = '{}' AND active = 1 LIMIT 1 FORMAT JSONEachRow",
        key_hash.replace('\'', "")
    );

    let client = reqwest::Client::new();
    let resp = client.get(&state.clickhouse_url).query(&[("query", &sql)]).send().await
        .map_err(|e| { warn!("Beats key lookup error: {e}"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let text = resp.text().await.unwrap_or_default();
    let row: Value = text.lines()
        .next()
        .and_then(|l| serde_json::from_str(l).ok())
        .ok_or_else(|| { warn!("Beats bulk: invalid or inactive ingest key"); StatusCode::UNAUTHORIZED })?;

    let tenant_id = row["tenant_id"].as_str().unwrap_or("").to_string();
    let source_id = row["source_id"].as_str().unwrap_or("").to_string();
    if tenant_id.is_empty() || source_id.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // ── Parse ndjson — alternating action/doc lines ────────────────────────
    // Format: {"index":{...}}\n{"field":"value",...}\n...
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut accepted = 0usize;
    let pipeline = std::sync::Arc::clone(&state.pipeline);

    let mut i = 0;
    while i < lines.len() {
        // action line — skip it
        let action: Value = serde_json::from_str(lines[i]).unwrap_or(Value::Null);
        i += 1;
        if i >= lines.len() { break; }

        // doc line — the actual event
        let doc_line = lines[i];
        i += 1;

        // Determine source_type from the index name in the action line
        let source_type = if let Some(idx) = action.get("index").and_then(|a| a.get("_index")).and_then(|v| v.as_str()) {
            if idx.contains("winlogbeat") { "wec" }
            else if idx.contains("filebeat")   { "syslog" }
            else { "generic" }
        } else { "generic" };

        // Use raw JSON as the log — normaliser handles Winlogbeat schema
        let raw = doc_line.to_string();
        let tid = tenant_id.clone();
        let sid = source_id.clone();
        let st  = source_type.to_string();
        let pl  = Arc::clone(&pipeline);

        tokio::spawn(async move {
            match st.as_str() {
                "wec"    => pl.process_wec(&raw, &tid, &sid).await,
                "syslog" => pl.process_syslog(&raw, "0.0.0.0", &tid, &sid).await,
                _        => pl.process_unknown(&raw, &tid, &sid).await,
            }
        });

        accepted += 1;
    }

    info!("Beats bulk: tenant={} source_id={} accepted={}", tenant_id, source_id, accepted);

    // Return ES-compatible bulk response
    Ok(Json(json!({
        "took": 1,
        "errors": false,
        "items": (0..accepted).map(|_| json!({
            "index": { "result": "created", "status": 201 }
        })).collect::<Vec<_>>()
    })))
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("Authorization")?.to_str().ok()?;
    if let Some(k) = auth.strip_prefix("Bearer ") {
        return Some(k.to_string());
    }
    if let Some(k) = auth.strip_prefix("ApiKey ") {
        // Winlogbeat base64-encodes the api_key value before sending.
        // Try to decode it; fall back to raw value if not valid base64.
        use base64::Engine;
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(k.trim()) {
            if let Ok(s) = String::from_utf8(decoded) {
                return Some(s);
            }
        }
        return Some(k.to_string());
    }
    None
}

use std::sync::Arc;
