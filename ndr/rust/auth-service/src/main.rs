mod db;
mod jwt;
mod license;
mod mfa;
mod routes;

use axum::{Router, routing::{delete, get, post, put}};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::catch_panic::CatchPanicLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub use db::AuthDb;

/// Shared application state — cheap to clone (all Arc-backed).
#[derive(Clone)]
pub struct AppState {
    pub db:          Arc<AuthDb>,
    pub valkey:      redis::aio::ConnectionManager,
    pub jwt_secret:  String,
    /// Access token TTL in seconds.  Default: 3600 (1 hour).
    pub token_ttl:   usize,
    /// Refresh token TTL in seconds.  Default: 604800 (7 days).
    pub refresh_ttl: usize,
    /// Max simultaneous sessions per user; the oldest is evicted on login past
    /// this. Default: 5. 0 disables the cap.
    pub max_sessions: usize,
    /// Verified license claims from LICENSE_TOKEN — None means DB-based feature lookup.
    pub verified_license: Option<Arc<license::LicenseClaims>>,
}

/// Turns an unhandled handler panic into a logged, structured 500 instead of
/// tower_http's default (a raw stderr dump with no tracing correlation).
fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    let detail = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "unknown panic payload".to_string()
    };
    tracing::error!("handler panicked: {}", detail);
    axum::response::Response::builder()
        .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(r#"{"status":"error","message":"internal server error"}"#))
        .unwrap()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_service=info,tower_http=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let ch_url     = require_env("CLICKHOUSE_URL");
    let valkey_url = require_env("VALKEY_URL");
    let jwt_secret = require_env("JWT_SECRET");

    let db            = Arc::new(AuthDb::new(&ch_url).await?);
    let redis_client  = redis::Client::open(valkey_url.as_str())?;
    let valkey        = redis::aio::ConnectionManager::new(redis_client).await?;

    // Verify the customer's license token at startup.
    // LICENSE_PRIVATE_KEY is PromaSecure-internal only — never set in customer deployments.
    // Customers receive only LICENSE_PUBLIC_KEY + LICENSE_TOKEN.
    let verified_license: Option<Arc<license::LicenseClaims>> = {
        let pub_key = std::env::var("LICENSE_PUBLIC_KEY").unwrap_or_default();
        let token   = std::env::var("LICENSE_TOKEN").unwrap_or_default();
        if !pub_key.trim().is_empty() && !token.trim().is_empty() {
            match license::verify_license(&token, &pub_key) {
                Ok(claims) => {
                    tracing::info!(
                        "License verified — tenant: '{}', features: {:?}",
                        claims.tenant_id, claims.features
                    );
                    Some(Arc::new(claims))
                }
                Err(e) => {
                    tracing::warn!("LICENSE_TOKEN present but invalid: {} — features from DB", e);
                    None
                }
            }
        } else {
            tracing::info!("No LICENSE_TOKEN set — features resolved from database per tenant");
            None
        }
    };

    let state = AppState {
        db,
        valkey,
        jwt_secret,
        token_ttl:   std::env::var("TOKEN_TTL_SECS")
                        .ok().and_then(|v| v.parse().ok()).unwrap_or(3600),
        refresh_ttl: std::env::var("REFRESH_TTL_SECS")
                        .ok().and_then(|v| v.parse().ok()).unwrap_or(604_800),
        max_sessions: std::env::var("MAX_CONCURRENT_SESSIONS")
                        .ok().and_then(|v| v.parse().ok()).unwrap_or(5),
        verified_license,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // Public — no JWT required
        .route("/api/auth/login",            post(routes::login::handle))
        .route("/api/auth/mfa/verify",       post(routes::mfa::handle))
        .route("/api/auth/refresh",          post(routes::refresh::handle))
        .route("/api/auth/logout",           post(routes::logout::handle))
        .route("/api/auth/reset-password",   post(routes::password::handle))
        .route("/api/auth/check-username",   get(routes::login::check_username))
        // Authenticated — JWT required (validated inside the handler)
        .route("/api/auth/me",               get(routes::me::handle))
        // User management
        .route("/api/auth/users",                        get(routes::users::list))
        .route("/api/auth/users",                        post(routes::users::create))
        .route("/api/auth/users/:id",                    put(routes::users::update))
        .route("/api/auth/users/:id/status",             post(routes::users::set_status))
        .route("/api/auth/users/:id/permissions",        put(routes::users::set_permissions))
        .route("/api/auth/users/:id/password",           post(routes::users::reset_password))
        .route("/api/auth/users/:id",                    delete(routes::users::delete))
        // Tenant management
        .route("/api/auth/tenants",                      get(routes::tenants::list))
        .route("/api/auth/tenants",                      post(routes::tenants::create))
        .route("/api/auth/tenants/:id",                  put(routes::tenants::update))
        .route("/api/auth/tenants/:id/status",           post(routes::tenants::set_status))
        .route("/api/auth/tenants/:id/ai-enabled",       post(routes::tenants::set_ai_enabled))
        .route("/api/auth/tenants/:id/features",         post(routes::tenants::set_features))
        // Announcements — common to all product modes
        .route("/api/announcements",                     get(routes::announcements::list))
        .route("/api/announcements/active",              get(routes::announcements::list_active))
        .route("/api/announcements",                     post(routes::announcements::create))
        .route("/api/announcements/:id",                 put(routes::announcements::update))
        .route("/api/announcements/:id/read",            post(routes::announcements::mark_read))
        .route("/api/announcements/:id",                 delete(routes::announcements::delete))
        // Profile
        .route("/api/auth/me/gmail",                     put(routes::profile::update_gmail))
        .route("/api/auth/me/regenerate-secret",         post(routes::profile::regenerate_secret))
        // Forgot password (no auth inside handlers)
        .route("/api/auth/forgot/verify-secret",         post(routes::forgot::verify_secret))
        .route("/api/auth/forgot/send-otp",              post(routes::forgot::send_otp))
        .route("/api/auth/forgot/reset-password",        post(routes::forgot::reset_password))
        .with_state(state)
        .layer(cors)
        // Outermost layer — a handler panic (e.g. bcrypt/JWT edge case) becomes
        // a structured tracing::error! + 500 instead of an unlogged stderr dump
        // that silently kills the request with no trace of why.
        .layer(CatchPanicLayer::custom(handle_panic));

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3001".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("auth-service listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        tracing::error!("Required env var {} not set — aborting", key);
        std::process::exit(1);
    })
}
