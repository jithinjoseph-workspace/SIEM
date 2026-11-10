use axum::{extract::State, Json};
use axum::http::HeaderMap;
use serde_json::{json, Value};

use crate::{jwt as session, AppState};

/// POST /api/auth/logout
///
/// Reads the Bearer token from the Authorization header, extracts the JTI,
/// and deletes it from Valkey.  The token is immediately invalid on all engines.
pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    // Cookie first (Angular withCredentials), then Authorization header
    let token = match session::extract_token(&headers) {
        Some(t) => t,
        None    => return Json(json!({ "status": "ok", "message": "Logged out" })),
    };

    // We validate the signature but ignore expiry — a just-expired token should still log out
    let mut validation = jsonwebtoken::Validation::default();
    validation.validate_exp = false;

    if let Ok(data) = jsonwebtoken::decode::<provigil_common::Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &validation,
    ) {
        let _ = session::revoke_session(&state, &data.claims.jti).await;
    }

    Json(json!({ "status": "ok", "message": "Logged out" }))
}
