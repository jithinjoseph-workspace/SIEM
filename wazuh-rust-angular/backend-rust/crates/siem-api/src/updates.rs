//! Product updates for container installs (the NDR engine's updater, now also in siem-api so a
//! SIEM-only install has it): every 6 hours the published VERSION is compared with the install's
//! own; "apply" writes a flag file that the host's updater service watches (it pulls the new
//! images and restarts the stack). Off in cloud mode and where there is no VERSION file (a
//! Windows master has its own update path).
//!
//! PROVIGIL_VERSION_FILE (default /app/VERSION: the install's VERSION, mounted read-only),
//! PROVIGIL_VERSION_URL (default: the address the NDR engine checks), PROVIGIL_UPDATE_FLAG
//! (default /scripts/.update-requested: the host updater's watched path).

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Mutex;

use crate::tenancy::AuthCtx;

// the public release repository (release-kit.sh --upload writes it); NDR-Demo is private
const DEFAULT_VERSION_URL: &str = "https://raw.githubusercontent.com/jithinjoseph-workspace/provigil-releases/main/VERSION";

#[derive(Clone, Default)]
struct Status {
    current: String,
    latest: Option<String>,
    available: bool,
    checked: u64,
}

fn status() -> &'static Mutex<Status> {
    static S: std::sync::OnceLock<Mutex<Status>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(Status::default()))
}

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| d.to_string())
}

/// The install's product version (its VERSION file), if it has one.
fn current_version() -> Option<String> {
    std::fs::read_to_string(env_or("PROVIGIL_VERSION_FILE", "/app/VERSION")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Starts the 6-hourly check (container installs: a VERSION file and not cloud mode).
pub fn spawn() {
    let Some(current) = current_version() else { return };
    if std::env::var("DEPLOY_MODE").as_deref() == Ok("cloud") {
        return;
    }
    status().lock().unwrap().current = current.clone();
    tokio::spawn(async move {
        let url = env_or("PROVIGIL_VERSION_URL", DEFAULT_VERSION_URL);
        let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build().unwrap_or_default();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
        loop {
            tick.tick().await;
            match http.get(&url).send().await {
                Ok(r) if r.status().is_success() => {
                    let latest = r.text().await.unwrap_or_default().trim().to_string();
                    // a version is a short line of digits and dots: anything else is not one
                    if latest.is_empty() || latest.len() > 32 || !latest.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        tracing::warn!("version check: {url} did not return a version");
                        continue;
                    }
                    let mut s = status().lock().unwrap();
                    s.available = latest != current;
                    s.latest = Some(latest);
                    s.checked = chrono::Utc::now().timestamp().max(0) as u64;
                    if s.available {
                        tracing::info!("update available: {current} -> {}", s.latest.as_deref().unwrap_or(""));
                    }
                }
                Ok(r) => tracing::warn!("version check: {url} answered {}", r.status()),
                Err(e) => tracing::warn!("version check failed: {e}"),
            }
        }
    });
}

fn may_update(ctx: &AuthCtx) -> bool {
    matches!(ctx.role.as_str(), "admin" | "super_admin" | "tenant_admin")
}

/// `GET /api/admin/version`
pub async fn version(Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    if !may_update(&ctx) {
        return Json(json!({ "status": "error", "message": "Forbidden" }));
    }
    let s = status().lock().unwrap().clone();
    Json(json!({ "current_version": s.current, "latest_version": s.latest, "update_available": s.available, "last_checked_secs": s.checked }))
}

/// `POST /api/admin/apply-update`: asks the host's updater to update (it watches the flag file).
pub async fn apply(Extension(ctx): Extension<AuthCtx>) -> (StatusCode, Json<Value>) {
    if !may_update(&ctx) {
        return (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": "Forbidden" })));
    }
    let s = status().lock().unwrap().clone();
    if !s.available {
        return (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": "No update available" })));
    }
    let flag = env_or("PROVIGIL_UPDATE_FLAG", "/scripts/.update-requested");
    if let Err(e) = std::fs::write(&flag, s.latest.as_deref().unwrap_or("")) {
        tracing::error!("could not write the update flag {flag}: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": format!("Could not write update flag: {e}") })));
    }
    tracing::info!("update requested by {} -> flag {flag}", ctx.username);
    (StatusCode::ACCEPTED, Json(json!({ "status": "accepted", "message": "Update triggered. Services will restart in ~30 seconds.", "target_version": s.latest })))
}
