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

impl AppState {
    /// A client's modules: the installed licence's when it is for this client (the customer
    /// cannot add modules through the client settings then), else the client settings'.
    pub async fn tenant_features(&self, tenant_id: &str) -> Vec<String> {
        if let Some(lic) = &self.verified_license {
            if lic.tenant_id == tenant_id || lic.tenant_id.is_empty() {
                return lic.features.clone();
            }
        }
        self.db.get_tenant_features(tenant_id).await.unwrap_or_else(|_| vec!["ndr".into()])
    }
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

    // The customer's first admin (the installer's TENANT_ADMIN_USER / TENANT_ADMIN_PASS) for the
    // licensed client, once. Here because every install has the sign-in service; the NDR engine
    // (which also does it) is not installed for a SIEM-only licence.
    if let Some(lic) = state.verified_license.clone() {
        let db = state.db.clone();
        tokio::spawn(async move { provision_licence_admin(&db, &lic).await });
        // a client's install keeps none of the built-in logins (they are the same everywhere). Checked
        // again and again: the schema (with them) is often made a few seconds after this service
        // starts (seen in the 1.0.36 install test), and a re-run schema could bring one back.
        let db = state.db.clone();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            loop {
                secure_default_logins(&db).await;
                let every = if started.elapsed() < std::time::Duration::from_secs(20 * 60) { 30 } else { 600 };
                tokio::time::sleep(std::time::Duration::from_secs(every)).await;
            }
        });
    }

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

/// The built-in logins every fresh database has (init.sql): `admin` with `ndr@admin123` (super admin)
/// and `tenant-admin` with `ndr@tenant123`. On a licensed install (a client's) neither may keep its
/// known password: `admin` gets SUPER_ADMIN_PASS (the installer's), or a random password written to
/// INITIAL_ADMIN_FILE (default `initial-admin-password.txt`, readable by its owner only), and a
/// `tenant-admin` still on its default is removed (the installer creates the client's own tenant
/// admin). Development installs have no licence and keep them.
async fn secure_default_logins(db: &db::AuthDb) {
    const DEFAULTS: [(&str, &str); 3] = [("admin", "ndr@admin123"), ("tenant-admin", "ndr@tenant123"), ("analyst", "ndr@tenant123")];
    for (name, default) in DEFAULTS {
        // the database may still be starting: ask again for up to 2.5 minutes
        let mut user = None;
        for _ in 0..30 {
            match db.get_user_any_tenant(name).await {
                Ok(u) => {
                    user = Some(u);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
            }
        }
        let Some(Some(u)) = user else { continue };
        if !bcrypt::verify(default, &u.password_hash).unwrap_or(false) {
            continue;
        }
        if name != "admin" {
            match db.delete_user(&u.id).await {
                Ok(()) => tracing::warn!("built-in login '{name}' (known password) removed"),
                Err(e) => tracing::error!("built-in login '{name}' (known password) NOT removed: {e}"),
            }
            continue;
        }
        let given = std::env::var("SUPER_ADMIN_PASS").unwrap_or_default().trim().to_string();
        let (new, generated) = if given.len() >= 12 && given != default {
            (given, false)
        } else {
            use rand::Rng;
            (rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(20).map(char::from).collect::<String>(), true)
        };
        if generated {
            let path = std::env::var("INITIAL_ADMIN_FILE").ok().filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "initial-admin-password.txt".into());
            if let Err(e) = write_private(&path, &format!("ProVigil super admin\nuser: admin\npassword: {new}\nChange it after signing in, then delete this file.\n")) {
                tracing::error!("super admin password not written to {path} ({e}): 'admin' keeps its built-in password");
                continue;
            }
            tracing::warn!("super admin 'admin': the built-in password is replaced; the new one is in {path} (owner only)");
        }
        let hash = match bcrypt::hash(&new, bcrypt::DEFAULT_COST) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("super admin password not set: {e}");
                continue;
            }
        };
        match db.set_password_hash(&u.id, &hash).await {
            Ok(()) => tracing::info!("super admin 'admin': built-in password replaced"),
            Err(e) => tracing::error!("super admin 'admin' still has its built-in password: {e}"),
        }
    }
}

/// A file only its owner can read (the new super admin password).
fn write_private(path: &str, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(text.as_bytes())?;
    // Windows: SYSTEM and the Administrators only (as provigil-service does for its secrets)
    #[cfg(windows)]
    {
        use std::process::{Command, Stdio};
        let ok = Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            let _ = std::fs::remove_file(path);
            return Err(std::io::Error::other("its access could not be limited to the administrators"));
        }
    }
    Ok(())
}

/// Creates the licensed client (when missing), gives it the licence's modules, and creates its
/// tenant admin from TENANT_ADMIN_USER / TENANT_ADMIN_PASS when no user has that name yet.
async fn provision_licence_admin(db: &db::AuthDb, lic: &license::LicenseClaims) {
    let user = std::env::var("TENANT_ADMIN_USER").unwrap_or_default().trim().to_string();
    let pass = std::env::var("TENANT_ADMIN_PASS").unwrap_or_default().trim().to_string();
    if user.is_empty() || pass.is_empty() {
        return;
    }
    // the database may still be starting: ask again for up to 2.5 minutes
    let mut known = None;
    for _ in 0..30 {
        match db.get_user_any_tenant(&user).await {
            Ok(u) => {
                known = Some(u.is_some());
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
        }
    }
    let Some(exists) = known else {
        tracing::warn!("tenant admin '{user}' not created: the database did not answer");
        return;
    };
    // the client first, also when its admin exists already (a start that met the schema still being
    // made left the client missing): ask again while the tables or columns are not there yet
    let tenant = if lic.tenant_id.trim().is_empty() { "default".to_string() } else { lic.tenant_id.trim().to_string() };
    let mut made = db.tenant_id_exists(&tenant).await;
    for attempt in 1..=30 {
        if made {
            break;
        }
        match db.create_tenant(&tenant, &lic.tenant_name).await {
            Ok(()) => made = true,
            Err(e) if attempt == 30 => {
                tracing::warn!("licence client '{tenant}' not created: {e}");
                return;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
        }
    }
    if !lic.features.is_empty() {
        for _ in 0..30 {
            if db.set_tenant_features(&tenant, &lic.features).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
    if exists {
        return;
    }
    let hash = match bcrypt::hash(&pass, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("tenant admin '{user}' not created: {e}");
            return;
        }
    };
    let perms = routes::login::default_permissions("tenant_admin").join(",");
    match db.create_user(&user, &hash, "tenant_admin", &tenant, &perms, "", "").await {
        Ok(()) => tracing::info!("tenant admin '{user}' created for the licensed client '{tenant}'"),
        Err(e) => tracing::warn!("tenant admin '{user}' not created: {e}"),
    }
}
