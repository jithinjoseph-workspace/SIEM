use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use axum::http::{header, StatusCode};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{jwt as session, AppState};
use provigil_common::create_jwt;

// ─────────────────────────────────────────────────────────────────────────────
// Input guards
// ─────────────────────────────────────────────────────────────────────────────

/// Reject usernames that contain shell-injection or SQL-injection characters.
pub fn is_safe_username(username: &str) -> bool {
    !username.is_empty()
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@' || c == '.' || c == '-')
}

pub fn validate_password_strength(pw: &str) -> Result<(), &'static str> {
    if pw.len() < 8 {
        return Err("Password must be at least 8 characters.");
    }
    if !pw.chars().any(|c| c.is_uppercase()) {
        return Err("Password must contain at least one uppercase letter.");
    }
    if !pw.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one number.");
    }
    if !pw.chars().any(|c| "!@#$%^&*()_+-=[]{}|;':\",./<>?".contains(c)) {
        return Err("Password must contain at least one special character.");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Device / IP helpers
// ─────────────────────────────────────────────────────────────────────────────

pub fn get_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("X-Forwarded-For")
        .or_else(|| headers.get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub fn parse_device_from_ua(ua: &str) -> String {
    let u = ua.to_lowercase();
    let os = if u.contains("iphone") { "iPhone" }
        else if u.contains("ipad") { "iPad" }
        else if u.contains("android") { "Android" }
        else if u.contains("windows") { "Windows" }
        else if u.contains("mac os") || u.contains("macintosh") { "macOS" }
        else if u.contains("linux") { "Linux" }
        else { "Unknown" };
    let browser = if u.contains("edg/") { "Edge" }
        else if u.contains("chrome") { "Chrome" }
        else if u.contains("firefox") { "Firefox" }
        else if u.contains("safari") { "Safari" }
        else { "Browser" };
    format!("{} / {}", browser, os)
}

// config/clickhouse/init.sql ships 'admin'/'tenant-admin' accounts with a
// fixed, publicly-known password baked into every fresh install. There's no
// forced-reset UI flow yet — the only "Forgot password" screen the frontend
// has requires a pre-configured recovery email these seed accounts don't
// have, so hard-blocking login here would just lock operators out with no
// way back in. Instead this is surfaced to the caller so the frontend can
// nag/redirect; the real fix is either wiring a forced-change screen to the
// existing POST /api/auth/reset-password (self-service, old_password-based,
// no JWT required) endpoint, or having the installer rotate this password.
const SEED_ADMIN_HASH:  &str = "$2b$12$qB5uFqakHidExby4EbdH6.tFvW34sj7CAQFZdUCzk5YSi/kV3S09.";
const SEED_TENANT_HASH: &str = "$2b$12$wi15kWc0KGLG6FEtIysJHuqRfT7PDvOoW2IC3oT3hfoQmtmygZ5h6";

pub fn is_seed_password_hash(hash: &str) -> bool {
    hash == SEED_ADMIN_HASH || hash == SEED_TENANT_HASH
}

/// Default page permissions per role (mirrors ndr-engine behaviour).
pub fn default_permissions(role: &str) -> Vec<String> {
    match role {
        "super_admin" => vec![
            "dashboard","alerts","intel","evidence","rules","soar","reports",
            "settings","users","tenants","sensors","engines","admin",
        ],
        "tenant_admin" => vec![
            "dashboard","alerts","intel","evidence","rules","soar","reports",
            "settings","users","sensors",
        ],
        _ => vec!["dashboard","alerts","intel","evidence"],
    }
    .into_iter().map(String::from).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/login
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginPayload {
    pub username:  String,
    pub password:  String,
    pub tenant_id: Option<String>,
}

pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> impl IntoResponse {
    let username  = payload.username.trim().to_string();
    let password  = payload.password.trim().to_string();
    // If no tenant_id supplied, resolve it from DB so users outside 'default' can login.
    let tenant_id = match payload.tenant_id.clone() {
        Some(t) if !t.is_empty() => t,
        _ => {
            match state.db.get_user_any_tenant(&username).await {
                Ok(Some(u)) => u.tenant_id,
                _ => "default".into(),
            }
        }
    };

    if username.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Username and password required" })),
        ).into_response();
    }

    if !is_safe_username(&username) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Invalid credentials" })),
        ).into_response();
    }

    // ── Brute-force protection ─────────────────────────────────────────────
    {
        let mut conn = state.valkey.clone();
        let lock_key = format!("provigil:login_locked:{}", username);
        let locked: bool = conn.exists(&lock_key).await.unwrap_or(false);
        if locked {
            let ttl: i64 = conn.ttl(&lock_key).await.unwrap_or(0);
            let mins = (ttl / 60).max(1);
            tracing::warn!("Login blocked — account locked: '{}'", username);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "status": "error",
                    "message": format!("Account locked. Try again in {} minute(s).", mins)
                })),
            ).into_response();
        }
    }

    // ── DB lookup ─────────────────────────────────────────────────────────
    let user = match state.db.get_user(&username, &tenant_id).await {
        Ok(Some(u)) => u,
        Ok(None)    => {
            record_failed_attempt(&state, &username).await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "status": "error", "message": "Invalid credentials. 4 attempt(s) remaining before lockout." })),
            ).into_response();
        }
        Err(e) => {
            tracing::error!("DB error during login: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "error", "message": "Authentication service unavailable" })),
            ).into_response();
        }
    };

    if user.active == 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "Your account has been disabled. Please contact your administrator."
            })),
        ).into_response();
    }

    // ── Tenant active check (super_admin bypasses) ─────────────────────────
    if user.role != "super_admin" {
        match state.db.is_tenant_active(&user.tenant_id).await {
            Ok(false) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "status": "error",
                        "message": "Your tenant has been deactivated. Contact your administrator."
                    })),
                ).into_response();
            }
            Err(e) => {
                tracing::warn!("Tenant active check failed for {}: {}", &user.tenant_id, e);
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "status": "error", "message": "Unable to verify tenant status" })),
                ).into_response();
            }
            Ok(true) => {}
        }
    }

    // ── Password verify ────────────────────────────────────────────────────
    match bcrypt::verify(&password, &user.password_hash) {
        Ok(true) => {}
        Ok(false) => {
            let remaining = record_failed_attempt(&state, &username).await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "error",
                    "message": format!("Invalid credentials. {} attempt(s) remaining before lockout.", remaining)
                })),
            ).into_response();
        }
        Err(e) => {
            tracing::error!("bcrypt error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Internal error" })),
            ).into_response();
        }
    }

    let must_reset_password = is_seed_password_hash(&user.password_hash);
    if must_reset_password {
        tracing::warn!("Login by '{}' still uses the default seed password — flagging for reset", username);
    }

    // ── Clear failed attempts on success ──────────────────────────────────
    {
        let mut conn = state.valkey.clone();
        let _: redis::RedisResult<()> = conn
            .del(format!("provigil:login_attempts:{}", username))
            .await;
    }

    issue_full_token(&state, &headers, &user.id, &user.username, &user.role, &user.tenant_id,
                     &user.permissions, &user.gmail, &user.secret_code, must_reset_password).await
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/auth/check-username?username=xxx
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CheckUsernameQuery {
    pub username: String,
}

pub async fn check_username(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<CheckUsernameQuery>,
) -> Json<Value> {
    if !is_safe_username(&q.username) {
        return Json(json!({ "exists": false }));
    }
    // Search across all tenants so users outside 'default' are found correctly.
    match state.db.get_user_any_tenant(&q.username).await {
        Ok(Some(u)) => Json(json!({ "exists": true, "tenant_id": u.tenant_id })),
        _           => Json(json!({ "exists": false })),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared: issue JWT + register session + build full response
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn issue_full_token(
    state:       &AppState,
    headers:     &HeaderMap,
    user_id:     &str,
    username:    &str,
    role:        &str,
    tenant_id:   &str,
    stored_perms: &str,
    gmail:       &str,
    secret_code: &str,
    must_reset_password: bool,
) -> axum::response::Response {
    // Role-based permissions
    let permissions: Vec<String> = if role == "super_admin" || role == "tenant_admin" {
        default_permissions(role)
    } else if stored_perms.is_empty() {
        default_permissions(role)
    } else {
        stored_perms.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    };

    // Features from tenant table
    let features = match state.db.get_tenant_features(tenant_id).await {
        Ok(f) => f,
        Err(_) => vec!["ndr".into()],
    };

    // Sensor IDs — admins get empty (see all), analysts get assigned sensors
    let sensor_ids = if role == "super_admin" || role == "tenant_admin" {
        vec![]
    } else {
        state.db.get_sensor_ids(user_id).await.unwrap_or_default()
    };

    // AI flag — super_admin always true; others read from tenant table with Valkey cache
    let ai_enabled = if role == "super_admin" {
        true
    } else {
        let cache_key = format!("provigil:ai_enabled:{}", tenant_id);
        let mut conn = state.valkey.clone();
        let cached: Option<u8> = conn.get(&cache_key).await.unwrap_or(None);
        match cached {
            Some(v) => v == 1,
            None => {
                let val = state.db.get_tenant_ai_enabled(tenant_id).await;
                let _: redis::RedisResult<()> = conn
                    .set_ex(&cache_key, if val { 1u8 } else { 0u8 }, 300usize)
                    .await;
                val
            }
        }
    };

    let (token, jti) = match create_jwt(
        username, role, tenant_id,
        permissions.clone(), features.clone(), sensor_ids.clone(),
        &state.jwt_secret, state.token_ttl,
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("JWT creation failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Could not issue token" })),
            ).into_response();
        }
    };

    // ── Register full session in Valkey ────────────────────────────────────
    let ip = get_client_ip(headers);
    let device = parse_device_from_ua(
        headers.get("User-Agent").and_then(|v| v.to_str().ok()).unwrap_or(""),
    );
    let login_ts = chrono::Utc::now().timestamp().to_string();
    {
        let mut conn = state.valkey.clone();
        let session_key    = format!("provigil:session:{}", jti);
        let user_set_key   = format!("provigil:user_sessions:{}:{}", tenant_id, username);
        let tenant_set_key = format!("provigil:tenant_sessions:{}", tenant_id);
        let _: redis::RedisResult<()> = conn.hset_multiple(&session_key, &[
            ("username",   username),
            ("role",       role),
            ("tenant_id",  tenant_id),
            ("ip",         ip.as_str()),
            ("device",     device.as_str()),
            ("login_time", login_ts.as_str()),
        ]).await;
        let _: redis::RedisResult<bool> = conn.expire(&session_key, state.token_ttl).await;
        let _: redis::RedisResult<i64>  = conn.sadd(&user_set_key, &jti).await;
        let _: redis::RedisResult<bool> = conn.expire(&user_set_key, state.refresh_ttl).await;
        let _: redis::RedisResult<i64>  = conn.sadd(&tenant_set_key, &jti).await;
        // ndr-engine's auth_middleware checks ndr:session:{jti} — write there too
        // so sessions created by auth-service are accepted by all ndr-engine API endpoints.
        let ndr_session_key = format!("ndr:session:{}", jti);
        let _: redis::RedisResult<()> = conn.hset_multiple(&ndr_session_key, &[
            ("username",   username),
            ("role",       role),
            ("tenant_id",  tenant_id),
            ("ip",         ip.as_str()),
            ("device",     device.as_str()),
            ("login_time", login_ts.as_str()),
        ]).await;
        let _: redis::RedisResult<bool> = conn.expire(&ndr_session_key, state.token_ttl).await;
        // Also register in ndr: tenant + user sets so ndr-engine's active-sessions
        // endpoint and force-logout can find sessions created by auth-service.
        let ndr_tenant_set = format!("ndr:tenant_sessions:{}", tenant_id);
        let ndr_user_set   = format!("ndr:user_sessions:{}:{}", tenant_id, username);
        let _: redis::RedisResult<i64>  = conn.sadd(&ndr_tenant_set, &jti).await;
        let _: redis::RedisResult<bool> = conn.expire(&ndr_tenant_set, state.refresh_ttl).await;
        let _: redis::RedisResult<i64>  = conn.sadd(&ndr_user_set, &jti).await;
        let _: redis::RedisResult<bool> = conn.expire(&ndr_user_set, state.refresh_ttl).await;

        // ── Enforce max concurrent sessions — evict the oldest past the cap ──
        // Nothing evicted this before: sessions just accumulated until their
        // TTL expired naturally, so one account could end up with dozens of
        // simultaneously live sessions.
        if state.max_sessions > 0 {
            let all_jtis: Vec<String> = conn.smembers(&user_set_key).await.unwrap_or_default();
            if all_jtis.len() > state.max_sessions {
                let mut by_login_time: Vec<(String, i64)> = Vec::with_capacity(all_jtis.len());
                for j in &all_jtis {
                    let lt: Option<String> = conn
                        .hget(format!("provigil:session:{}", j), "login_time")
                        .await.unwrap_or(None);
                    by_login_time.push((j.clone(), lt.and_then(|s| s.parse().ok()).unwrap_or(0)));
                }
                by_login_time.sort_by_key(|(_, t)| *t);
                let evict_count = all_jtis.len() - state.max_sessions;
                for (old_jti, _) in by_login_time.into_iter().take(evict_count) {
                    let _ = session::revoke_session(&state, &old_jti).await;
                    let _: redis::RedisResult<i64> = conn.srem(&user_set_key, &old_jti).await;
                    let _: redis::RedisResult<i64> = conn.srem(&tenant_set_key, &old_jti).await;
                    let _: redis::RedisResult<i64> = conn.srem(&ndr_user_set, &old_jti).await;
                    let _: redis::RedisResult<i64> = conn.srem(&ndr_tenant_set, &old_jti).await;
                }
                tracing::info!(
                    "Evicted {} oldest session(s) for '{}' (max_concurrent_sessions={})",
                    evict_count, username, state.max_sessions
                );
            }
        }
    }

    // ── New-device detection (background, never blocks login) ──────────────
    {
        let state2       = state.clone();
        let user_set_key = format!("provigil:user_sessions:{}:{}", tenant_id, username);
        let jti2         = jti.clone();
        let username2    = username.to_string();
        let tenant2      = tenant_id.to_string();
        let device2      = device.clone();
        let ip2          = ip.clone();
        let ts2          = login_ts.clone();
        tokio::spawn(async move {
            let mut conn = state2.valkey.clone();
            let prev_jtis: Vec<String> = conn.smembers(&user_set_key).await.unwrap_or_default();
            let mut seen = false;
            for prev in &prev_jtis {
                if prev == &jti2 { continue; }
                let pk = format!("provigil:session:{}", prev);
                let prev_device: Option<String> = conn.hget(&pk, "device").await.unwrap_or(None);
                if prev_device.as_deref() == Some(&device2) { seen = true; break; }
            }
            if !seen {
                if let Ok(Some(admin_email)) = state2.db.get_tenant_admin_email(&tenant2).await {
                    tracing::info!(
                        "New device login — user={} device={} ip={} ts={} → notify {}",
                        username2, device2, ip2, ts2, admin_email
                    );
                    // Email sending delegated to SMTP microservice or ndr-engine relay.
                    // Log the event here; the notification pipeline picks it up.
                }
            }
        });
    }

    let expires_at = chrono::Utc::now().timestamp() as u64 + state.token_ttl as u64;
    let cookie = format!(
        "ndr_token={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        token, state.token_ttl
    );

    tracing::info!("Login SUCCESS: username='{}' role='{}'", username, role);

    let mut resp = (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "user": {
                "id":          user_id,
                "username":    username,
                "role":        role,
                "tenant_id":   tenant_id,
                "permissions": permissions,
                "features":    features,
                "ai_enabled":  ai_enabled,
                "gmail":       gmail,
                "secret_code": secret_code,
                "sensor_ids":  sensor_ids,
                "expires_at":  expires_at,
                "token":       token,
                "must_reset_password": must_reset_password
            }
        })),
    ).into_response();

    if let Ok(v) = cookie.parse::<axum::http::HeaderValue>() {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Increment failure counter; returns remaining attempts. Locks on ≥5.
async fn record_failed_attempt(state: &AppState, username: &str) -> i64 {
    let mut conn = state.valkey.clone();
    let attempt_key = format!("provigil:login_attempts:{}", username);
    let lock_key    = format!("provigil:login_locked:{}", username);
    let attempts: i64 = conn.incr(&attempt_key, 1i64).await.unwrap_or(1);
    let _: redis::RedisResult<bool> = conn.expire(&attempt_key, 900usize).await;
    if attempts >= 5 {
        let _: redis::RedisResult<String> = conn.set_ex(&lock_key, "1", 900usize).await;
        let _: redis::RedisResult<()> = conn.del(&attempt_key).await;
        tracing::warn!("Account locked after {} failures: '{}'", attempts, username);
    }
    (5 - attempts).max(0)
}
