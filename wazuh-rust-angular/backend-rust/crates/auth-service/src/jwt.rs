use anyhow::Result;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use redis::AsyncCommands;
use serde_json::json;

use crate::AppState;

/// Token extraction helper (cookie first, then Bearer header).
/// Was copy-pasted identically across 7 route files; consolidated here.
pub fn extract_token(headers: &HeaderMap) -> Option<String> {
    let from_cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').find_map(|p| {
            p.trim().strip_prefix("ndr_token=").map(str::to_owned)
        }));
    if from_cookie.is_some() {
        return from_cookie;
    }
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
}

/// Auth helper — validate JWT then confirm session still alive in Valkey
/// (catches force-logged-out users whose token hasn't expired yet).
/// Was copy-pasted across 7 route files; password.rs's copy had a different,
/// buggy return type (Json<Value> instead of (StatusCode, Json<Value>)) that
/// made an unauthenticated request return HTTP 200 with an error body instead
/// of a real 401 — consolidated here so there is only one, correct version.
pub async fn auth(headers: &HeaderMap, state: &AppState)
    -> Result<provigil_common::Claims, (StatusCode, Json<serde_json::Value>)>
{
    let token = extract_token(headers).ok_or_else(|| (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "status": "error", "message": "Unauthorized" })),
    ))?;
    let claims = provigil_common::validate_jwt(&token, &state.jwt_secret).map_err(|_| (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "status": "error", "message": "Token invalid or expired" })),
    ))?;
    let key = format!("provigil:session:{}", claims.jti);
    let alive: bool = state.valkey.clone().exists(&key).await.unwrap_or(false);
    if !alive {
        return Err((StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Session revoked — please log in again" }))));
    }
    Ok(claims)
}

/// Revoke a specific session JTI (used by logout and token refresh rotation).
///
/// Deletes both session namespaces: provigil:session:{jti}, which this
/// service's own auth() check reads, and ndr:session:{jti}, which
/// ndr-engine's auth_middleware reads. Both are written together at login
/// (login.rs), so leaving either one behind lets that jti keep working on
/// whichever service still sees it as alive.
///
/// Also removes the jti from the 4 tracking sets login.rs adds it to
/// (provigil:user_sessions, provigil:tenant_sessions, ndr:user_sessions,
/// ndr:tenant_sessions) - previously left behind on every single logout,
/// so the concurrent-session eviction check in login.rs (which reads these
/// sets) accumulated one permanent ghost entry per logout forever. Found
/// live: tenant-admin's set was already at the 5-session cap with 3 of the
/// 5 being dead ghosts, silently shrinking real session capacity to 2.
/// Must read the hash's username/tenant_id *before* deleting it - that's
/// the only place this function learns which sets to clean.
pub async fn revoke_session(state: &AppState, jti: &str) -> Result<()> {
    let mut conn = state.valkey.clone();
    let session_key = format!("provigil:session:{}", jti);

    let fields: std::collections::HashMap<String, String> =
        conn.hgetall(&session_key).await.unwrap_or_default();

    conn.del::<_, ()>(&session_key).await?;
    conn.del::<_, ()>(format!("ndr:session:{}", jti)).await?;

    if let (Some(username), Some(tenant_id)) = (fields.get("username"), fields.get("tenant_id")) {
        let _: redis::RedisResult<i64> = conn.srem(format!("provigil:user_sessions:{}:{}", tenant_id, username), jti).await;
        let _: redis::RedisResult<i64> = conn.srem(format!("provigil:tenant_sessions:{}", tenant_id), jti).await;
        let _: redis::RedisResult<i64> = conn.srem(format!("ndr:user_sessions:{}:{}", tenant_id, username), jti).await;
        let _: redis::RedisResult<i64> = conn.srem(format!("ndr:tenant_sessions:{}", tenant_id), jti).await;
    }

    Ok(())
}
