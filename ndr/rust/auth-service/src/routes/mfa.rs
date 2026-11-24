use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use axum::http::StatusCode;
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use super::login::issue_full_token;

#[derive(Deserialize)]
pub struct MfaPayload {
    pub mfa_session: String,
    // Accepted from the client but not yet verified — see NOT WIRED UP note below.
    #[allow(dead_code)]
    pub code:        String,
}

/// POST /api/auth/mfa/verify
///
/// Second step of login when MFA is enabled.
/// Client sends the mfa_session token from step 1 + the 6-digit TOTP code.
/// Returns the same full JWT response as a successful login.
pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<MfaPayload>,
) -> impl IntoResponse {
    let pending_key = format!("provigil:mfa_pending:{}", payload.mfa_session);
    let mut conn = state.valkey.clone();

    let user_id: Option<String> = match conn.get(&pending_key).await {
        Ok(v)  => v,
        Err(_) => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "MFA session expired" })),
        ).into_response(),
    };

    let user_id = match user_id {
        Some(v) => v,
        None    => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "MFA session not found or expired" })),
        ).into_response(),
    };

    let user = match state.db.get_user_by_id(&user_id).await {
        Ok(Some(u)) => u,
        _ => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "User not found" })),
        ).into_response(),
    };

    // NOT WIRED UP: payload.code is never checked against crate::mfa::verify_totp
    // because there is no per-user TOTP secret column in the schema yet, and
    // nothing in login.rs currently creates a `provigil:mfa_pending:*` session
    // or requires this step — so this endpoint is unreachable through normal
    // login today. Finishing MFA needs: a secret-storage column + enrollment
    // flow, login.rs deciding when to require it, and a real code check here.
    // Consume the one-time MFA session token
    let _: redis::RedisResult<()> = conn.del(&pending_key).await;

    let must_reset_password = super::login::is_seed_password_hash(&user.password_hash);
    issue_full_token(
        &state, &headers,
        &user.id, &user.username, &user.role, &user.tenant_id,
        &user.permissions, &user.gmail, &user.secret_code, must_reset_password,
    ).await
}
