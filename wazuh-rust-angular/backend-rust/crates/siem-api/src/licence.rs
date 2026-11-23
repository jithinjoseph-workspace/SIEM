//! The installation's licence (on-premises): it limits NEW PC enrollments and is reported
//! against real usage. Existing PCs keep working and events are never dropped for a licence.
//!
//! Public key: built into on-premises release builds (`PROVIGIL_LICENSE_PUBLIC_KEY` at build
//! time; then a licence is required), else `LICENSE_PUBLIC_KEY` (the sign-in service's variable).
//! No key at all (cloud builds): no limits. The licence: `LICENSE_TOKEN`, else the file
//! `PROVIGIL_LICENSE_FILE` (default `data/license.jwt`), which the console can replace, so a
//! renewal needs no restart. One licence serves SIEM and NDR (same token format).

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use provigil_license::Claims;
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

fn file() -> std::path::PathBuf {
    std::env::var("PROVIGIL_LICENSE_FILE").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "data/license.jwt".into()).into()
}

fn public_key() -> Option<String> {
    provigil_license::BUILT_IN_KEY.map(str::to_string).or_else(|| std::env::var("LICENSE_PUBLIC_KEY").ok()).filter(|k| !k.trim().is_empty())
}

fn token() -> Option<String> {
    std::env::var("LICENSE_TOKEN").ok().filter(|t| !t.trim().is_empty()).or_else(|| std::fs::read_to_string(file()).ok()).map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
}

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// The licence as read now: `None` = no licence in play (no key, or a key without a licence
/// where none is required).
fn current() -> Option<Result<Claims, String>> {
    let key = public_key()?;
    match token() {
        Some(t) => Some(provigil_license::verify(&t, &key)),
        None if provigil_license::BUILT_IN_KEY.is_some() => Some(Err("no licence is installed".into())),
        None => None,
    }
}

fn day(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()
}

/// Whether one more PC may enrol, with `enrolled` PCs already in.
fn decide(lic: Option<Result<Claims, String>>, enrolled: usize, now: u64) -> Result<(), String> {
    match lic {
        None => Ok(()),
        Some(Err(e)) => Err(format!("Licence problem: {e}. New PCs cannot enrol until a valid licence is installed.")),
        Some(Ok(c)) if c.exp <= now => Err(format!("The licence expired on {}. New PCs cannot enrol until it is renewed; enrolled PCs keep working.", day(c.exp))),
        Some(Ok(c)) if c.max_agents > 0 && enrolled >= c.max_agents as usize => Err(format!("The licence allows {} PCs and {enrolled} are enrolled. Remove a PC or extend the licence.", c.max_agents)),
        Some(Ok(_)) => Ok(()),
    }
}

/// For the health checks: None when no licence is in play.
pub fn summary() -> Option<(crate::health::Level, String)> {
    use crate::health::Level;
    let n = now();
    Some(match current()? {
        Err(e) => (Level::Fail, format!("invalid: {e}")),
        Ok(c) if c.exp <= n => (Level::Fail, format!("expired on {}: new PCs cannot enrol", day(c.exp))),
        Ok(c) if c.exp - n < 30 * 86_400 => (Level::Warn, format!("expires on {}", day(c.exp))),
        Ok(c) => (Level::Ok, format!("valid until {}", day(c.exp))),
    })
}

/// Called before a NEW PC enrolls (a reinstall of an enrolled PC is not checked).
pub fn check_enroll(enrolled: usize) -> Result<(), String> {
    decide(current(), enrolled, now())
}

async fn status_json(state: &AppState) -> Value {
    let enrolled = state.enrolled.read().unwrap().len();
    let since = (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(86_400_000);
    let mut events = 0u64;
    for t in crate::predictions::tenant_ids(state) {
        events += state.db.tenant_client(&t).query("SELECT count() FROM siem_events WHERE timestamp >= ?").bind(since).fetch_one::<u64>().await.unwrap_or(0);
    }
    let avg_eps = (events as f64 / 864.0).round() / 100.0;
    let base = json!({ "required": provigil_license::BUILT_IN_KEY.is_some(), "key_present": public_key().is_some(), "pcs_enrolled": enrolled, "avg_eps_24h": avg_eps });
    let mut v = base;
    match current() {
        None => v["state"] = json!("unlicensed: no limits"),
        Some(Err(e)) => {
            v["state"] = json!("invalid");
            v["problem"] = json!(e);
        }
        Some(Ok(c)) => {
            let n = now();
            v["state"] = json!(if c.exp <= n { "expired" } else { "valid" });
            v["customer"] = json!(c.tenant_name);
            v["tenant"] = json!(c.tenant_id);
            v["expires"] = json!(day(c.exp));
            v["days_left"] = json!(if c.exp > n { (c.exp - n) / 86_400 } else { 0 });
            v["max_pcs"] = json!(c.max_agents);
            v["max_eps"] = json!(c.max_eps);
            v["features"] = json!(c.features);
            let mut warn = Vec::new();
            if c.exp > n && c.exp - n < 30 * 86_400 {
                warn.push(format!("The licence expires on {}.", day(c.exp)));
            }
            if c.max_agents > 0 && enrolled * 10 >= c.max_agents as usize * 9 {
                warn.push(format!("{enrolled} of {} licensed PCs are enrolled.", c.max_agents));
            }
            if c.max_eps > 0 && avg_eps > f64::from(c.max_eps) {
                warn.push(format!("The event rate ({avg_eps} EPS) is above the licensed {} EPS; nothing is dropped.", c.max_eps));
            }
            v["warnings"] = json!(warn);
        }
    }
    v
}

fn super_only(ctx: &AuthCtx) -> Option<Response> {
    (!ctx.is_super()).then(|| (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": "Platform admins only" }))).into_response())
}

/// `GET /api/license` (platform admins): the licence and the usage it is measured against.
pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    if let Some(r) = super_only(&ctx) {
        return r;
    }
    Json(status_json(&state).await).into_response()
}

#[derive(serde::Deserialize)]
pub struct Install {
    token: String,
}

/// `POST /api/license` (platform admins) `{token}`: installs a renewed licence (checked first).
pub async fn install(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<Install>) -> Response {
    if let Some(r) = super_only(&ctx) {
        return r;
    }
    let bad = |m: String| (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": m }))).into_response();
    let Some(key) = public_key() else { return bad("This installation has no licence key; it needs no licence".into()) };
    if std::env::var("LICENSE_TOKEN").is_ok_and(|t| !t.trim().is_empty()) {
        return bad("LICENSE_TOKEN is set in the settings and wins over an installed file; change it there".into());
    }
    let t = r.token.trim();
    match provigil_license::verify(t, &key) {
        Err(e) => bad(e),
        Ok(c) if c.exp <= now() => bad(format!("This licence expired on {}", day(c.exp))),
        Ok(c) => {
            let f = file();
            if let Some(dir) = f.parent().filter(|d| !d.as_os_str().is_empty()) {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = std::fs::write(&f, t) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": format!("cannot save the licence: {e}") }))).into_response();
            }
            tracing::info!("licence installed for '{}' until {} ({} PCs)", c.tenant_name, day(c.exp), c.max_agents);
            Json(status_json(&state).await).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lic(exp: u64, pcs: u32) -> Option<Result<Claims, String>> {
        Some(Ok(Claims { exp, max_agents: pcs, ..Default::default() }))
    }

    #[test]
    fn enrollment_against_the_licence() {
        assert!(decide(None, 10_000, 100).is_ok(), "no licence in play: no limits");
        assert!(decide(lic(200, 0), 10_000, 100).is_ok(), "0 PCs = no limit");
        assert!(decide(lic(200, 3), 2, 100).is_ok());
        assert!(decide(lic(200, 3), 3, 100).unwrap_err().contains("allows 3 PCs"));
        assert!(decide(lic(100, 3), 0, 100).unwrap_err().contains("expired"));
        assert!(decide(Some(Err("bad signature".into())), 0, 100).unwrap_err().contains("bad signature"));
    }
}
