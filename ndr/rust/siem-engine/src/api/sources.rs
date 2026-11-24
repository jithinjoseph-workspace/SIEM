// GET/POST/DELETE /api/siem/sources — source registry CRUD

use axum::{
    extract::{State, Extension, Path},
    Json, http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::error;
use uuid::Uuid;

use crate::AppState;
use crate::api::middleware::Claims;
use crate::db_init;

#[derive(Serialize)]
pub struct SourcesResponse {
    pub sources: Vec<SourceRow>,
}

#[derive(Serialize)]
pub struct SourceRow {
    pub source_id:    String,
    pub name:         String,
    pub source_type:  String,
    pub status:       String,
    pub last_seen_at: String,
    pub eps:          f64,
    pub config_json:  String,
}

#[derive(Deserialize)]
pub struct CreateSourceRequest {
    pub name:        String,
    pub source_type: String,
    pub config_json: Option<String>,
}

#[derive(Serialize)]
pub struct CreateSourceResponse {
    pub source_id:  String,
    /// Returned once — caller must copy; never stored in plaintext
    pub ingest_key: String,
}

pub async fn list(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<SourcesResponse>, StatusCode> {
    let db = tenant_db(&claims.tenant_id);
    let sql = format!(
        "SELECT source_id, name, source_type, status, toString(last_seen_at), config_json \
         FROM {db}.siem_sources FINAL ORDER BY name LIMIT 200 FORMAT JSONEachRow"
    );

    let client = reqwest::Client::new();
    let resp = client.get(&state.clickhouse_url).query(&[("query", &sql)]).send().await
        .map_err(|e| { error!("CH sources list error: {e}"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let text = resp.text().await.unwrap_or_default();
    let sources = text.lines().filter_map(|line| {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        Some(SourceRow {
            source_id:    v["source_id"].as_str().unwrap_or("").to_string(),
            name:         v["name"].as_str().unwrap_or("").to_string(),
            source_type:  v["source_type"].as_str().unwrap_or("").to_string(),
            status:       v["status"].as_str().unwrap_or("active").to_string(),
            last_seen_at: v["toString(last_seen_at)"].as_str().unwrap_or("").to_string(),
            eps:          0.0,
            config_json:  v["config_json"].as_str().unwrap_or("{}").to_string(),
        })
    }).collect();

    Ok(Json(SourcesResponse { sources }))
}

pub async fn create(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateSourceRequest>,
) -> Result<Json<CreateSourceResponse>, StatusCode> {
    if !["admin", "super_admin", "tenant_admin"].contains(&claims.role.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    if req.name.trim().is_empty() || req.source_type.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let db        = tenant_db(&claims.tenant_id);
    let source_id = Uuid::new_v4().to_string();
    let name      = escape(req.name.trim());
    let stype     = escape(&req.source_type);
    let config    = escape(&req.config_json.unwrap_or_else(|| "{}".to_string()));

    // Generate ingest key — returned once, hash stored
    let raw_key  = format!("siem_{}", Uuid::new_v4().to_string().replace('-', ""));
    let key_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));

    let client = reqwest::Client::new();

    // Ensure tenant DB and SIEM schema exist (idempotent — IF NOT EXISTS everywhere)
    if let Err(e) = db_init::run(&state.clickhouse_url, &db).await {
        error!("SIEM schema init for {db}: {e}");
    }

    // Insert source record
    let sql = format!(
        "INSERT INTO {db}.siem_sources \
         (source_id, tenant_id, name, source_type, config_json, status, created_at) \
         VALUES ('{source_id}','{tenant}','{name}','{stype}','{config}','active',now())",
        tenant = escape(&claims.tenant_id)
    );
    let resp = client.post(&state.clickhouse_url).body(sql).send().await
        .map_err(|e| { error!("CH source create error: {e}"); StatusCode::INTERNAL_SERVER_ERROR })?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        error!("CH source insert failed: {body}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Insert into global key lookup (ndr schema — same across all tenants)
    let key_sql = format!(
        "INSERT INTO ndr.siem_ingest_keys (key_hash, tenant_id, source_id, name, active) \
         VALUES ('{key_hash}','{tenant}','{source_id}','{name}',1)",
        tenant = escape(&claims.tenant_id),
    );
    if let Err(e) = client.post(&state.clickhouse_url).body(key_sql).send().await {
        error!("CH ingest key insert error: {e}");
        // Non-fatal — source is created, key just won't validate until fixed
    }

    Ok(Json(CreateSourceResponse { source_id, ingest_key: raw_key }))
}

pub async fn delete(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(source_id): Path<String>,
) -> StatusCode {
    if !["admin", "super_admin", "tenant_admin"].contains(&claims.role.as_str()) {
        return StatusCode::FORBIDDEN;
    }
    let db  = tenant_db(&claims.tenant_id);
    let sid = escape(&source_id);

    let client = reqwest::Client::new();

    // Soft-delete source record (ReplacingMergeTree tombstone)
    let sql = format!(
        "INSERT INTO {db}.siem_sources \
         (source_id, tenant_id, name, source_type, status, created_at) \
         SELECT source_id, tenant_id, name, source_type, 'deleted', now() \
         FROM {db}.siem_sources FINAL WHERE source_id = '{sid}' LIMIT 1"
    );
    match client.post(&state.clickhouse_url).body(sql).send().await {
        Ok(r) if !r.status().is_success() => {
            error!("CH source delete failed: {}", r.text().await.unwrap_or_default());
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
        Err(e) => { error!("CH source delete error: {e}"); return StatusCode::INTERNAL_SERVER_ERROR; }
        _ => {}
    }

    // Deactivate all ingest keys for this source
    let key_deactivate = format!(
        "INSERT INTO ndr.siem_ingest_keys (key_hash, tenant_id, source_id, name, active, created_at) \
         SELECT key_hash, tenant_id, source_id, name, 0, now() \
         FROM ndr.siem_ingest_keys FINAL WHERE source_id = '{sid}' AND tenant_id = '{tenant}'",
        tenant = escape(&claims.tenant_id),
    );
    if let Err(e) = client.post(&state.clickhouse_url).body(key_deactivate).send().await {
        error!("CH ingest key deactivate error: {e}");
    }

    StatusCode::NO_CONTENT
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" { "ndr".into() } else { format!("ndr_{}", tenant_id.replace('-', "_")) }
}
