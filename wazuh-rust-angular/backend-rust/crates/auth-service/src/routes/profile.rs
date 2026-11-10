use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;


use crate::AppState;
use crate::jwt::auth;

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/auth/me/gmail
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateGmailPayload {
    pub gmail: String,
}

pub async fn update_gmail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateGmailPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    let gmail = payload.gmail.trim();

    // Validate email format
    if !gmail.is_empty() && !is_valid_email(gmail) {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Invalid email format" }))).into_response();
    }

    // We need the user's DB id. Use sub (username) to look up by username
    let user = match state.db.get_user(&claims.sub, &claims.tenant_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_user error in update_gmail: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "DB error" }))).into_response();
        }
    };

    match state.db.update_user_gmail(&user.id, gmail).await {
        Ok(()) => (StatusCode::OK,
            Json(json!({ "status": "ok", "gmail": gmail, "message": "Email updated" }))).into_response(),
        Err(e) => {
            tracing::error!("update_user_gmail error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update email" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/me/regenerate-secret
// ─────────────────────────────────────────────────────────────────────────────

pub async fn regenerate_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    // Generate 6-char alphanumeric code (in own scope before async)
    let code = {
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(6)
            .map(char::from)
            .collect::<String>()
    };

    let user = match state.db.get_user(&claims.sub, &claims.tenant_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_user error in regenerate_secret: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "DB error" }))).into_response();
        }
    };

    match state.db.update_user_secret_code(&user.id, &code).await {
        Ok(()) => (StatusCode::OK,
            Json(json!({ "status": "ok", "secret_code": code }))).into_response(),
        Err(e) => {
            tracing::error!("update_user_secret_code error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to regenerate secret" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 { return false; }
    let domain = parts[1];
    !parts[0].is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}
