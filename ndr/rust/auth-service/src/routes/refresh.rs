use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use axum::http::StatusCode;
use redis::AsyncCommands;
use serde_json::json;

use crate::{jwt as session, AppState};

/// POST /api/auth/refresh
///
/// Angular calls this automatically before the access token expires.
/// Validates the session JTI is still alive in Valkey, then issues a fresh JWT.
/// The user is never logged out mid-session as long as their session is active.
pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Read token from cookie first (Angular), then Authorization header
    let token = match session::extract_token(&headers) {
        Some(t) => t,
        None    => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "No token provided" })),
        ).into_response(),
    };

    // Decode without expiry check — we only need the identity claims + JTI
    let mut validation = jsonwebtoken::Validation::default();
    validation.validate_exp = false;

    let claims = match jsonwebtoken::decode::<provigil_common::Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &validation,
    ) {
        Ok(d)  => d.claims,
        Err(_) => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Invalid token" })),
        ).into_response(),
    };

    // Confirm the session JTI is still alive in Valkey
    let session_key = format!("provigil:session:{}", claims.jti);
    let mut conn = state.valkey.clone();
    let alive: bool = match conn.exists(&session_key).await {
        Ok(v)  => v,
        Err(_) => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "error", "message": "Session store unavailable" })),
        ).into_response(),
    };

    if !alive {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Session expired — please log in again" })),
        ).into_response();
    }

    // Re-fetch live user data so a role change takes effect on refresh
    let user = match state.db.get_user(&claims.sub, &claims.tenant_id).await {
        Ok(Some(u)) => u,
        _ => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "User not found" })),
        ).into_response(),
    };

    if user.active == 0 {
        let _ = session::revoke_session(&state, &claims.jti).await;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "Account disabled",
                "code": "USER_DISABLED"
            })),
        ).into_response();
    }

    // Revoke old session JTI, issue a fresh one
    let _ = session::revoke_session(&state, &claims.jti).await;

    let must_reset_password = super::login::is_seed_password_hash(&user.password_hash);
    super::login::issue_full_token(
        &state, &headers,
        &user.id, &user.username, &user.role, &user.tenant_id,
        &user.permissions, &user.gmail, &user.secret_code, must_reset_password,
    ).await
}

