use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::jwt::auth;
use super::login::validate_password_strength;

#[derive(Deserialize)]
pub struct ResetPasswordPayload {
    pub username:     String,
    pub tenant_id:    String,
    pub new_password: String,
    /// Present for self-service reset; absent for admin-initiated reset.
    pub old_password: Option<String>,
}

/// POST /api/auth/reset-password
///
/// Self-service: validates old_password before accepting new_password — proof
/// of identity is knowing the current password, no session required, same as
/// before.
///
/// Admin reset (old_password absent): TC-084 — this branch used to trust the
/// request body alone with NO auth check whatsoever (the handler took no
/// HeaderMap, so it could not have checked one even if it tried), letting
/// anyone reset any account's password with just a username + tenant_id.
/// Now requires a live super_admin or tenant_admin session; tenant_admin is
/// restricted to their own tenant and to the same manageable-roles set
/// already enforced on the equivalent id-based endpoint in users.rs.
pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ResetPasswordPayload>,
) -> impl IntoResponse {
    let username     = payload.username.trim();
    let tenant_id    = payload.tenant_id.trim();
    let new_password = payload.new_password.trim();

    if let Err(msg) = validate_password_strength(new_password) {
        return Json(json!({ "status": "error", "message": msg })).into_response();
    }

    let user = match state.db.get_user(username, tenant_id).await {
        Ok(Some(u)) => u,
        Ok(None)    => return Json(json!({ "status": "error", "message": "User not found" })).into_response(),
        Err(e) => {
            tracing::error!("DB error in reset-password: {}", e);
            return Json(json!({ "status": "error", "message": "Service unavailable" })).into_response();
        }
    };

    match payload.old_password.as_deref() {
        // Self-service path — verify current password before accepting the change
        Some(old_pw) => {
            match bcrypt::verify(old_pw, &user.password_hash) {
                Ok(true) => {}
                Ok(false) => return Json(json!({ "status": "error", "message": "Current password is incorrect" })).into_response(),
                Err(_)    => return Json(json!({ "status": "error", "message": "Internal error" })).into_response(),
            }
        }
        // Admin reset path — now actually requires the JWT the doc comment always claimed it checked
        None => {
            let claims = match auth(&headers, &state).await {
                Ok(c) => c,
                Err((s, j)) => return (s, j).into_response(),
            };
            if claims.role != "super_admin" && claims.role != "tenant_admin" {
                return Json(json!({ "status": "error", "message": "Forbidden" })).into_response();
            }
            if user.role == "super_admin" {
                return Json(json!({ "status": "error", "message": "Super admin password cannot be changed here" })).into_response();
            }
            if claims.role == "tenant_admin" {
                let manageable_roles = ["analyst", "senior_analyst", "viewer"];
                if claims.tenant_id != user.tenant_id || !manageable_roles.contains(&user.role.as_str()) {
                    return Json(json!({ "status": "error", "message": "Forbidden" })).into_response();
                }
            }
        }
    }

    let new_hash = match bcrypt::hash(new_password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("bcrypt hash error: {}", e);
            return Json(json!({ "status": "error", "message": "Internal error" })).into_response();
        }
    };

    match state.db.set_password_hash(&user.id, &new_hash).await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Password updated successfully" })).into_response(),
        Err(e) => {
            tracing::error!("Failed to update password: {}", e);
            Json(json!({ "status": "error", "message": "Failed to update password" })).into_response()
        }
    }
}
