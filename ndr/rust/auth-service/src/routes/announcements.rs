use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};

use crate::AppState;
use crate::jwt::extract_token;
use provigil_common::validate_jwt;

// Deliberately lighter than crate::jwt::auth(): only checks the JWT signature
// and expiry, no Valkey session-alive lookup, so it stays local rather than
// reusing the shared auth().
async fn auth_any(headers: &HeaderMap, state: &AppState)
    -> Result<provigil_common::Claims, (StatusCode, Json<Value>)>
{
    let token = extract_token(headers).ok_or_else(|| (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "status": "error", "message": "Unauthorized" })),
    ))?;
    let claims = validate_jwt(&token, &state.jwt_secret).map_err(|_| (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "status": "error", "message": "Token invalid or expired" })),
    ))?;
    Ok(claims)
}

async fn auth_super(headers: &HeaderMap, state: &AppState)
    -> Result<provigil_common::Claims, (StatusCode, Json<Value>)>
{
    let claims = auth_any(headers, state).await?;
    if claims.role != "super_admin" {
        return Err((StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))));
    }
    Ok(claims)
}

fn parse_status(payload: &Value) -> String {
    match payload["status"].as_str().unwrap_or("draft") {
        "active" => "active", "inactive" => "inactive", _ => "draft",
    }.to_string()
}

fn parse_targets(payload: &Value) -> (String, Vec<String>, Vec<String>) {
    let audience = payload["audience"].as_str().unwrap_or("all").to_string();
    let target_roles: Vec<String> = payload["target_roles"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let target_tenants: Vec<String> = payload["target_tenants"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    (audience, target_roles, target_tenants)
}

// GET /api/announcements
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = auth_super(&headers, &state).await {
        return e.into_response();
    }
    match state.db.get_announcements().await {
        Ok(announcements) => (StatusCode::OK, Json(json!({ "status": "ok", "announcements": announcements }))).into_response(),
        Err(e) => {
            tracing::error!("get_announcements: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "announcements": [], "message": e.to_string() }))).into_response()
        }
    }
}

// GET /api/announcements/active
pub async fn list_active(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match auth_any(&headers, &state).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match state.db.get_active_announcements(&claims.role, &claims.tenant_id, &claims.sub).await {
        Ok(announcements) => (StatusCode::OK, Json(json!({ "status": "ok", "announcements": announcements }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "announcements": [], "message": e.to_string() }))).into_response(),
    }
}

// POST /api/announcements
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let claims = match auth_super(&headers, &state).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let title   = payload["title"].as_str().unwrap_or("").trim().to_string();
    let message = payload["message"].as_str().unwrap_or("").trim().to_string();
    let atype   = payload["announcement_type"].as_str()
        .or_else(|| payload["type"].as_str()).unwrap_or("info").trim().to_string();
    let status  = parse_status(&payload);
    let (audience, target_roles, target_tenants) = parse_targets(&payload);
    let start_at = payload["start_at"].as_str().or_else(|| payload["starts_at"].as_str());
    let end_at   = payload["end_at"].as_str().or_else(|| payload["ends_at"].as_str());

    if title.is_empty() || message.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": "Title and message are required" }))).into_response();
    }
    let id = uuid::Uuid::new_v4().to_string();
    match state.db.create_announcement(&id, &title, &message, &atype, &audience, &status,
        &target_roles, &target_tenants, start_at, end_at, &claims.sub).await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "id": id, "message": "Announcement created" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}

// PUT /api/announcements/:id
pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    if let Err(e) = auth_super(&headers, &state).await {
        return e.into_response();
    }
    let title   = payload["title"].as_str().unwrap_or("").trim().to_string();
    let message = payload["message"].as_str().unwrap_or("").trim().to_string();
    let atype   = payload["announcement_type"].as_str()
        .or_else(|| payload["type"].as_str()).unwrap_or("info").trim().to_string();
    let status  = parse_status(&payload);
    let (audience, target_roles, target_tenants) = parse_targets(&payload);
    let start_at = payload["start_at"].as_str().or_else(|| payload["starts_at"].as_str());
    let end_at   = payload["end_at"].as_str().or_else(|| payload["ends_at"].as_str());

    if title.is_empty() || message.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": "Title and message are required" }))).into_response();
    }
    match state.db.update_announcement(&id, &title, &message, &atype, &audience, &status,
        &target_roles, &target_tenants, start_at, end_at).await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "message": "Announcement updated" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}

// POST /api/announcements/:id/read
pub async fn mark_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let claims = match auth_any(&headers, &state).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match state.db.mark_announcement_read(&id, &claims.sub).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "message": "Marked as read" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}

// DELETE /api/announcements/:id
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = auth_super(&headers, &state).await {
        return e.into_response();
    }
    match state.db.delete_announcement(&id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "message": "Announcement deleted" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}
