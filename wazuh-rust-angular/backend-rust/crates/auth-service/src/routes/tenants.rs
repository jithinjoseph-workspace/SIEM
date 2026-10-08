use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;


use crate::AppState;
use crate::jwt::auth;

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/auth/tenants
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" && claims.role != "tenant_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    // A tenant_admin only ever sees their own tenant — otherwise this endpoint
    // leaks every other tenant's id/name/features to them (enumeration).
    let result = if claims.role == "super_admin" {
        state.db.get_all_tenants().await
    } else {
        state.db.get_tenant_by_id(&claims.tenant_id).await
    };

    match result {
        Ok(tenants) => (StatusCode::OK, Json(json!({ "status": "ok", "tenants": tenants }))).into_response(),
        Err(e) => {
            tracing::error!("get_all_tenants error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to fetch tenants" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/tenants
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTenantPayload {
    pub name: String,
    pub id:   Option<String>,
}

/// Convert any string to a URL-safe slug: lowercase, hyphens only, no leading/trailing hyphens.
fn slugify(s: &str) -> String {
    let slug = s.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let slug = slug.trim_matches('-').to_string();
    // Collapse consecutive hyphens
    let mut out = String::new();
    let mut prev_hyphen = false;
    for c in slug.chars() {
        if c == '-' {
            if !prev_hyphen { out.push(c); }
            prev_hyphen = true;
        } else {
            out.push(c);
            prev_hyphen = false;
        }
    }
    out
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateTenantPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    let name = payload.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Tenant name is required" }))).into_response();
    }

    // Use the frontend-supplied ID (slugified) or derive one from the name
    let raw_id = payload.id.as_deref().unwrap_or(name);
    let id = slugify(raw_id);
    let id = if id.is_empty() { Uuid::new_v4().to_string() } else { id };

    // Reject duplicate IDs — same check ndr-engine does
    if state.db.tenant_id_exists(&id).await {
        return (StatusCode::CONFLICT,
            Json(json!({ "status": "error", "message": format!("Tenant ID '{}' already exists", id) }))).into_response();
    }

    match state.db.create_tenant(&id, name).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "id": id, "message": "Tenant created" }))).into_response(),
        Err(e) => {
            tracing::error!("create_tenant error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to create tenant" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/auth/tenants/:id
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateTenantPayload {
    pub name:   String,
    pub active: Option<bool>,
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateTenantPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    let active = payload.active.unwrap_or(true);
    match state.db.update_tenant(&id, payload.name.trim(), active).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "message": "Tenant updated" }))).into_response(),
        Err(e) => {
            tracing::error!("update_tenant error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update tenant" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/tenants/:id/status
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetStatusPayload {
    pub active: bool,
}

pub async fn set_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<SetStatusPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    match state.db.set_tenant_active(&id, payload.active).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            tracing::error!("set_tenant_active error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update tenant status" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/tenants/:id/ai-enabled
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetAiEnabledPayload {
    pub enabled: bool,
}

pub async fn set_ai_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<SetAiEnabledPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    match state.db.set_tenant_ai_enabled(&id, payload.enabled).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            tracing::error!("set_tenant_ai_enabled error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update AI setting" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/tenants/:id/features
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetFeaturesPayload {
    pub features: Vec<String>,
}

pub async fn set_features(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<SetFeaturesPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    match state.db.set_tenant_features(&id, &payload.features).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            tracing::error!("set_tenant_features error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update features" }))).into_response()
        }
    }
}
