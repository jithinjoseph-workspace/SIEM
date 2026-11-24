// JWT validation + feature gate middleware for siem-engine
// Every /api/siem/* and /api/xdr/* route passes through this.
// Rejects with 401 if JWT invalid, 403 if tenant lacks 'siem' feature.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

use crate::AppState;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JwtClaims {
    pub sub:       String,
    pub tenant_id: String,
    pub role:      String,
    pub features:  Vec<String>,
    pub exp:       u64,
}

/// Axum extension — routes can extract this after the middleware runs
pub type Claims = JwtClaims;

/// Validates JWT and checks the tenant has the 'siem' feature.
/// Skips auth for /api/health and /api/siem/wec (WEC uses mTLS in production).
pub async fn require_siem(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let path = req.uri().path().to_string();

    // Health endpoint — always open
    if path == "/api/health" {
        return Ok(next.run(req).await);
    }

    let token = extract_bearer(req.headers())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(json!({ "error": "missing Authorization header" }))))?;

    let claims = decode_jwt(&token, &state.jwt_secret)
        .map_err(|e| {
            warn!("JWT decode failed: {e}");
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid token" })))
        })?;

    // Feature gate — tenant must have 'siem' feature
    // Privileged admin (role = super_admin) bypasses feature check
    if claims.role != "super_admin" && !claims.features.contains(&"siem".to_string()) {
        return Err((StatusCode::FORBIDDEN, Json(json!({
            "error": "tenant does not have SIEM feature enabled"
        }))));
    }

    // Attach claims to request extensions so handlers can read them
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let auth = headers.get("Authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|s| s.to_string())
}

fn decode_jwt(token: &str, secret: &str) -> anyhow::Result<JwtClaims> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut val = Validation::new(Algorithm::HS256);
    val.validate_exp = true;
    let data = decode::<JwtClaims>(token, &key, &val)?;
    Ok(data.claims)
}
