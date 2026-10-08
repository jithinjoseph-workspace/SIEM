use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};


use crate::AppState;
use crate::jwt::auth;
use super::login::{default_permissions, validate_password_strength};
use super::forgot::send_email;

// ─────────────────────────────────────────────────────────────────────────────
// Inline permissions helper
// ─────────────────────────────────────────────────────────────────────────────

fn permissions_from_payload(payload_perms: Option<&Value>, role: &str) -> String {
    match payload_perms {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::String(s)) => s.clone(),
        _ => default_permissions(role).join(","),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/auth/users
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    let users = match claims.role.as_str() {
        "super_admin" => state.db.get_all_users().await,
        "tenant_admin" => state.db.get_users_by_tenant(&claims.tenant_id).await
            .map(|list| list.into_iter().filter(|u| {
                u.get("role").and_then(|r| r.as_str()) != Some("super_admin")
            }).collect()),
        _ => return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response(),
    };

    match users {
        Ok(list) => (StatusCode::OK, Json(json!({ "status": "ok", "users": list }))).into_response(),
        Err(e) => {
            tracing::error!("get_users error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to fetch users" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/users
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateUserPayload {
    pub username:    String,
    pub password:    String,
    pub role:        String,
    pub tenant_id:   Option<String>,
    pub permissions: Option<Value>,
    pub gmail:       Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateUserPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    // Only super_admin and tenant_admin may create users
    if claims.role != "super_admin" && claims.role != "tenant_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    let username  = payload.username.trim().to_string();
    let password  = payload.password.trim().to_string();
    let role      = payload.role.trim().to_string();
    let gmail     = payload.gmail.as_deref().unwrap_or("").trim().to_string();

    // tenant_admin cannot create super_admin
    if claims.role == "tenant_admin" && role == "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Cannot create super_admin" }))).into_response();
    }

    // Determine tenant_id: super_admin can set any, tenant_admin is restricted to own
    let tenant_id = if claims.role == "super_admin" {
        payload.tenant_id.as_deref().unwrap_or("default").trim().to_string()
    } else {
        claims.tenant_id.clone()
    };

    if let Err(msg) = validate_password_strength(&password) {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg }))).into_response();
    }

    let permissions = permissions_from_payload(payload.permissions.as_ref(), &role);

    // Generate secret_code for tenant_admin (in own scope to avoid Send issues)
    let secret_code = if role == "tenant_admin" {
        use rand::Rng;
        let code: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();
        code
    } else {
        String::new()
    };

    let hash = match bcrypt::hash(&password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("bcrypt error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Internal error" }))).into_response();
        }
    };

    match state.db.create_user(&username, &hash, &role, &tenant_id, &permissions, &gmail, &secret_code).await {
        Ok(()) => {
            if role == "tenant_admin" && !gmail.is_empty() {
                let db = state.db.clone();
                let to_email = gmail.clone();
                let username_clone = username.clone();
                let secret_code_clone = secret_code.clone();
                tokio::spawn(async move {
                    let subject = "Your NDR Tenant Admin Secret Code";
                    let body = format!("Hello {},\n\nYour secret code is: {}\n\nPLEASE DO NOT DELETE THIS MESSAGE.\nYou will need this secret code to reset your password if you ever forget it.\n\nThank you,\nNDR Security Team", username_clone, secret_code_clone);
                    if let Err(e) = send_email(&db, &to_email, subject, &body).await {
                        tracing::error!("Failed to send secret code email to {}: {}", to_email, e);
                    }
                });
            }
            (StatusCode::OK, Json(json!({ "status": "ok", "message": "User created" }))).into_response()
        },
        Err(e) => {
            tracing::error!("create_user error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to create user" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/auth/users/:id
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateUserPayload {
    pub role:        Option<String>,
    pub tenant_id:   Option<String>,
    pub permissions: Option<Value>,
    pub active:      Option<bool>,
    pub password:    Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateUserPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" && claims.role != "tenant_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    // Fetch existing user to fill defaults
    let identity = match state.db.get_user_identity(&id).await {
        Ok(Some(i)) => i,
        Ok(None) => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_user_identity error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "DB error" }))).into_response();
        }
    };
    let (existing_username, existing_role, existing_tenant) = identity;

    // Nobody edits their own account or a super_admin account through this route.
    if existing_username == claims.sub || existing_role == "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "This user cannot be edited here" }))).into_response();
    }

    // tenant_admin may only update users in own tenant
    if claims.role == "tenant_admin" && existing_tenant != claims.tenant_id {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    let requested_role = payload.role.as_deref().unwrap_or(&existing_role);
    if claims.role == "tenant_admin" && (requested_role == "super_admin" || requested_role == "tenant_admin") {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Cannot assign that role" }))).into_response();
    }
    let role      = requested_role.to_string();
    // tenant_admin can never move a user to a different tenant, regardless of payload.
    let tenant_id = if claims.role == "tenant_admin" {
        existing_tenant.clone()
    } else {
        payload.tenant_id.as_deref().unwrap_or(&existing_tenant).to_string()
    };
    let active    = payload.active.unwrap_or(true);
    let permissions = permissions_from_payload(payload.permissions.as_ref(), &role);

    let hash = if let Some(pw) = payload.password.as_deref() {
        if let Err(msg) = validate_password_strength(pw) {
            return (StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": msg }))).into_response();
        }
        match bcrypt::hash(pw, bcrypt::DEFAULT_COST) {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::error!("bcrypt error: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "status": "error", "message": "Internal error" }))).into_response();
            }
        }
    } else {
        None
    };

    match state.db.update_user_full(&id, &role, &tenant_id, &permissions, active, hash.as_deref()).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "message": "User updated" }))).into_response(),
        Err(e) => {
            tracing::error!("update_user_full error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update user" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/users/:id/status
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

    if claims.role != "super_admin" && claims.role != "tenant_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    if let Ok(Some((username, role, target_tenant))) = state.db.get_user_identity(&id).await {
        if username == claims.sub || role == "super_admin" {
            return (StatusCode::FORBIDDEN,
                Json(json!({ "status": "error", "message": "This user cannot be deactivated here" }))).into_response();
        }
        if claims.role == "tenant_admin" && target_tenant != claims.tenant_id {
            return (StatusCode::FORBIDDEN,
                Json(json!({ "status": "error", "message": "Cannot modify users outside your tenant" }))).into_response();
        }
        if claims.role == "tenant_admin" && (role == "tenant_admin" || role == "admin") {
            return (StatusCode::FORBIDDEN,
                Json(json!({ "status": "error", "message": "Cannot modify admin users" }))).into_response();
        }
    }

    match state.db.set_user_active(&id, payload.active).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            tracing::error!("set_user_active error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update status" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/auth/users/:id/permissions
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetPermissionsPayload {
    pub permissions: Value,
}

pub async fn set_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<SetPermissionsPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    let target = match state.db.get_user_by_id(&id).await {
        Ok(Some(u))  => u,
        Ok(None)     => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_user_by_id error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "DB error" }))).into_response();
        }
    };

    if target.role == "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Super admin permissions cannot be changed here" }))).into_response();
    } else if claims.role == "tenant_admin" {
        let manageable_roles = ["analyst", "senior_analyst", "viewer", "default_user"];
        if claims.tenant_id != target.tenant_id || !manageable_roles.contains(&target.role.as_str()) {
            return (StatusCode::FORBIDDEN,
                Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
        }
    } else if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    let permissions = permissions_from_payload(Some(&payload.permissions), "analyst");

    match state.db.update_user_permissions(&id, &permissions).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            tracing::error!("update_user_permissions error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update permissions" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/users/:id/password
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ResetPasswordPayload {
    pub password: String,
}

pub async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<ResetPasswordPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    let target = match state.db.get_user_by_id(&id).await {
        Ok(Some(u))  => u,
        Ok(None)     => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_user_by_id error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "DB error" }))).into_response();
        }
    };

    if target.role == "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Super admin password cannot be changed here" }))).into_response();
    } else if claims.role == "tenant_admin" {
        let manageable_roles = ["analyst", "senior_analyst", "viewer"];
        if claims.tenant_id != target.tenant_id || !manageable_roles.contains(&target.role.as_str()) {
            return (StatusCode::FORBIDDEN,
                Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
        }
    } else if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    let password = payload.password.trim();
    if let Err(msg) = validate_password_strength(password) {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg }))).into_response();
    }

    let hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("bcrypt error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Internal error" }))).into_response();
        }
    };

    match state.db.update_user_password(&id, &hash).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "message": "Password updated" }))).into_response(),
        Err(e) => {
            tracing::error!("update_user_password error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update password" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/auth/users/:id
// ─────────────────────────────────────────────────────────────────────────────

pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    let target = match state.db.get_user_identity(&id).await {
        Ok(Some(t))  => t,
        Ok(None)     => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_user_identity error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "DB error" }))).into_response();
        }
    };
    let (username, role, tenant_id) = target;

    if claims.role == "super_admin" {
        if username == claims.sub || role == "super_admin" {
            return (StatusCode::FORBIDDEN,
                Json(json!({ "status": "error", "message": "This user cannot be deleted here" }))).into_response();
        }
    } else if claims.role == "tenant_admin" {
        let protected_roles = ["super_admin", "admin", "tenant_admin"];
        if tenant_id != claims.tenant_id || protected_roles.contains(&role.as_str()) {
            return (StatusCode::FORBIDDEN,
                Json(json!({ "status": "error", "message": "Tenant admins can only delete tenant users" }))).into_response();
        }
    } else {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    match state.db.delete_user(&id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "message": "User deleted" }))).into_response(),
        Err(e) => {
            tracing::error!("delete_user error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to delete user" }))).into_response()
        }
    }
}
