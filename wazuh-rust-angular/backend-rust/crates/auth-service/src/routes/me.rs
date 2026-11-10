use axum::{extract::State, http::HeaderMap, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use redis::AsyncCommands;
use serde_json::json;

use crate::AppState;
use provigil_common::validate_jwt;
use super::login::default_permissions;

/// GET /api/auth/me
///
/// Called by the Angular app every 30 seconds to re-validate the session
/// and pull fresh role/feature/sensor data without a full re-login.
pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_bearer(&headers) {
        Some(t) => t,
        None => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Unauthorized" })),
        ).into_response(),
    };

    let claims = match validate_jwt(&token, &state.jwt_secret) {
        Ok(c)  => c,
        Err(_) => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Token invalid or expired" })),
        ).into_response(),
    };

    // Check session is still alive in Valkey (catches force-logout)
    let session_key = format!("provigil:session:{}", claims.jti);
    let mut conn = state.valkey.clone();
    // unwrap_or(true): Valkey transient error → assume alive; JWT expiry is the safety net.
    // unwrap_or(false) was causing random logouts on multiple rapid page refreshes.
    let alive: bool = conn.exists(&session_key).await.unwrap_or(true);
    if !alive {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Session revoked — please log in again" })),
        ).into_response();
    }
    // Sliding TTL — refresh session on each /me call so active users never expire mid-session.
    let _: redis::RedisResult<bool> = conn.expire(&session_key, state.token_ttl).await;

    // Re-fetch live user data — catches role changes, disables, etc.
    let user = match state.db.get_user(&claims.sub, &claims.tenant_id).await {
        Ok(Some(u)) => u,
        _ => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "User not found" })),
        ).into_response(),
    };

    if user.active == 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "Your account has been disabled by your administrator.",
                "code": "USER_DISABLED"
            })),
        ).into_response();
    }

    let permissions: Vec<String> = if user.role == "super_admin" || user.role == "tenant_admin" {
        default_permissions(&user.role)
    } else if user.permissions.is_empty() {
        default_permissions(&user.role)
    } else {
        user.permissions.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    };

    // License token takes precedence over DB — if a verified license exists for this tenant,
    // its feature list is authoritative (customer cannot self-upgrade via DB).
    let features = if let Some(lic) = &state.verified_license {
        if lic.tenant_id == user.tenant_id || lic.tenant_id.is_empty() {
            lic.features.clone()
        } else {
            state.db.get_tenant_features(&user.tenant_id).await.unwrap_or_else(|_| vec!["ndr".into()])
        }
    } else {
        state.db.get_tenant_features(&user.tenant_id).await.unwrap_or_else(|_| vec!["ndr".into()])
    };
    let ai_enabled = if user.role == "super_admin" {
        true
    } else {
        // Check Redis cache first (TTL 300s) to avoid a ClickHouse round-trip on every /me poll.
        let cache_key = format!("ndr:ai_enabled:{}", user.tenant_id);
        let cached: Option<String> = conn.get(&cache_key).await.unwrap_or(None);
        match cached.as_deref() {
            Some("1") => true,
            Some("0") => false,
            _ => {
                let enabled = state.db.get_tenant_ai_enabled(&user.tenant_id).await;
                let _: redis::RedisResult<()> = redis::cmd("SET")
                    .arg(&cache_key)
                    .arg(if enabled { "1" } else { "0" })
                    .arg("EX")
                    .arg(300u64)
                    .query_async(&mut conn)
                    .await;
                enabled
            }
        }
    };
    let sensor_ids = if user.role == "super_admin" || user.role == "tenant_admin" {
        vec![]
    } else {
        state.db.get_sensor_ids(&user.id).await.unwrap_or_default()
    };

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "user": {
                "id":          user.id,
                "username":    user.username,
                "role":        user.role,
                "tenant_id":   user.tenant_id,
                "permissions": permissions,
                "features":    features,
                "ai_enabled":  ai_enabled,
                "gmail":       user.gmail,
                "sensor_ids":  sensor_ids,
            }
        })),
    ).into_response()
}

/// Read token from cookie first (Angular withCredentials), then Authorization header.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    // Cookie path — Angular sends ndr_token via HttpOnly cookie with withCredentials: true
    let from_cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| {
            c.split(';').find_map(|p| {
                p.trim().strip_prefix("ndr_token=").map(str::to_owned)
            })
        });
    if from_cookie.is_some() {
        return from_cookie;
    }
    // Bearer header fallback (direct API clients, curl, siem-engine)
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
}
