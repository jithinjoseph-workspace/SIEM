//! Health of this installation's own servers, checked every minute: the data lake (reachable,
//! disk), this master's disk, Valkey, the agent gateway, the manager services, the AI providers,
//! silent PCs and the licence. A check that gets worse or recovers is e-mailed to the platform's
//! alert recipients (Settings, SMTP). For a managed service the master can also send its health
//! outbound to ProVigil (`HEALTH_REPORT_URL` + `HEALTH_REPORT_TOKEN`, every 5 minutes), and the
//! receiving ProVigil stores those reports (`HEALTH_REPORT_ACCEPT_TOKEN`) and lists each site.

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::tenancy::AuthCtx;
use crate::AppState;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub level: Level,
    pub detail: String,
    /// When the check reached this level (seconds).
    #[serde(default)]
    pub since: i64,
}

fn check(name: &str, level: Level, detail: impl Into<String>) -> Check {
    Check { name: name.into(), level, detail: detail.into(), since: 0 }
}

struct Memory {
    checks: Vec<Check>,
    mailed: HashMap<String, i64>,
    last_report: Option<(i64, String)>,
}

fn memory() -> &'static Mutex<Memory> {
    static M: std::sync::OnceLock<Mutex<Memory>> = std::sync::OnceLock::new();
    M.get_or_init(|| Mutex::new(Memory { checks: Vec::new(), mailed: HashMap::new(), last_report: None }))
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Free share of a disk: below 5% fails, below 15% warns.
fn disk_level(free: u64, total: u64) -> (Level, f64) {
    let pct = if total == 0 { 100.0 } else { free as f64 * 100.0 / total as f64 };
    (if pct < 5.0 { Level::Fail } else if pct < 15.0 { Level::Warn } else { Level::Ok }, (pct * 10.0).round() / 10.0)
}

async fn tcp_ok(addr: &str) -> bool {
    matches!(tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await, Ok(Ok(_)))
}

/// host:port of an http(s) URL.
fn host_port(url: &str) -> Option<String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") { (true, r) } else { (false, url.strip_prefix("http://")?) };
    let hp = rest.split('/').next()?;
    if hp.is_empty() {
        return None;
    }
    Some(if hp.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) { hp.to_string() } else { format!("{hp}:{}", if https { 443 } else { 80 }) })
}

#[derive(clickhouse::Row, Deserialize)]
struct DiskRow {
    free_space: u64,
    total_space: u64,
}

async fn run_checks(state: &AppState) -> Vec<Check> {
    let mut out = Vec::new();

    // the data lake: reachable, and its fullest disk
    match state.db.root().query("SELECT free_space, total_space FROM system.disks").fetch_all::<DiskRow>().await {
        Err(e) => out.push(check("Data lake", Level::Fail, format!("not reachable: {e}"))),
        Ok(disks) => {
            let worst = disks.iter().map(|d| disk_level(d.free_space, d.total_space)).max_by(|a, b| a.0.cmp(&b.0).then(b.1.total_cmp(&a.1)));
            match worst {
                Some((lvl, pct)) => out.push(check("Data lake", lvl, format!("reachable; {pct}% disk free"))),
                None => out.push(check("Data lake", Level::Ok, "reachable")),
            }
        }
    }

    // this master's disk (the one holding the working folder)
    let cwd = std::env::current_dir().unwrap_or_default();
    let disks = sysinfo::Disks::new_with_refreshed_list();
    if let Some(d) = disks.list().iter().filter(|d| cwd.starts_with(d.mount_point())).max_by_key(|d| d.mount_point().as_os_str().len()) {
        let (lvl, pct) = disk_level(d.available_space(), d.total_space());
        out.push(check("Master disk", lvl, format!("{pct}% free on {}", d.mount_point().display())));
    }

    out.push(if crate::tenancy::valkey_ok().await { check("Valkey", Level::Ok, "running") } else { check("Valkey", Level::Fail, "not reachable: sessions and live alerts stop") });

    let gw = std::env::var("GATEWAY_HEALTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8089".into());
    out.push(if tcp_ok(&gw).await { check("Agent gateway", Level::Ok, format!("listening on {gw}")) } else { check("Agent gateway", Level::Fail, format!("nothing listens on {gw}: agents cannot connect")) });

    if crate::provigil_manager::enabled() {
        let running = crate::provigil_manager::running();
        out.push(if running.is_empty() { check("Manager services", Level::Fail, "none running: events are not analysed") } else { check("Manager services", Level::Ok, format!("running: {}", running.join(", "))) });
    }

    // AI providers: each one's address answers (no question is asked: that costs tokens)
    let providers = crate::ai_assist::providers(state, "chat").await;
    if providers.is_empty() {
        out.push(check("AI", Level::Ok, "no provider configured"));
    } else {
        let mut down = Vec::new();
        for p in &providers {
            if let Some(hp) = host_port(&p.base_url) {
                if !tcp_ok(&hp).await {
                    down.push(p.name.clone());
                }
            }
        }
        out.push(match down.len() {
            0 => check("AI", Level::Ok, format!("{} provider(s) reachable", providers.len())),
            n if n == providers.len() => check("AI", Level::Fail, format!("no provider reachable ({})", down.join(", "))),
            _ => check("AI", Level::Warn, format!("not reachable: {}", down.join(", "))),
        });
    }

    // PCs silent for more than an hour (enrolled, not deactivated)
    let cutoff = chrono::Utc::now() - chrono::Duration::hours(1);
    let (silent, total) = {
        let enrolled = state.enrolled.read().unwrap();
        let agents = state.agents.read().unwrap();
        let live: Vec<_> = enrolled.iter().filter(|(_, a)| !a.disabled).collect();
        (live.iter().filter(|(id, _)| agents.get(*id).map_or(true, |a| a.last_keepalive < cutoff)).count(), live.len())
    };
    out.push(match silent {
        0 => check("PCs", Level::Ok, format!("{total} enrolled, all reported in the last hour")),
        n => check("PCs", Level::Warn, format!("{n} of {total} enrolled PCs silent for more than an hour")),
    });

    let lic = crate::licence::summary();
    if let Some((lvl, detail)) = lic {
        out.push(check("Licence", lvl, detail));
    }
    out
}

/// Keeps each check's `since`; returns the checks whose level changed (with the old level).
fn remember(new: &mut [Check], old: &[Check], t: i64) -> Vec<(Check, Option<Level>)> {
    let mut changed = Vec::new();
    for c in new.iter_mut() {
        match old.iter().find(|o| o.name == c.name) {
            Some(o) if o.level == c.level => c.since = o.since,
            Some(o) => {
                c.since = t;
                changed.push((c.clone(), Some(o.level)));
            }
            None => {
                c.since = t;
                // at start-up only a problem is news
                if c.level != Level::Ok {
                    changed.push((c.clone(), None));
                }
            }
        }
    }
    changed
}

async fn mail_changes(state: &AppState, changed: Vec<(Check, Option<Level>)>) {
    if changed.is_empty() {
        return;
    }
    let t = now();
    // at most one e-mail per check per 15 minutes (a flapping check does not flood)
    let due: Vec<_> = {
        let mut m = memory().lock().unwrap();
        let due: Vec<_> = changed.into_iter().filter(|(c, _)| m.mailed.get(&c.name).is_none_or(|at| t - at >= 900)).collect();
        for (c, _) in &due {
            m.mailed.insert(c.name.clone(), t);
        }
        due
    };
    if due.is_empty() {
        return;
    }
    let Some(settings) = crate::mail_settings::load(state).await else { return };
    if settings.alert_to.is_empty() || settings.smtp_auth().is_none() {
        return;
    }
    let worst = due.iter().map(|(c, _)| c.level).max().unwrap_or(Level::Ok);
    let site = site_name();
    let subject = match worst {
        Level::Ok => format!("ProVigil {site}: recovered"),
        Level::Warn => format!("ProVigil {site}: warning"),
        Level::Fail => format!("ProVigil {site}: PROBLEM"),
    };
    let text = due.iter().map(|(c, old)| format!("{}: {} -> {:?}: {}", c.name, old.map_or("start".to_string(), |o| format!("{o:?}")), c.level, c.detail)).collect::<Vec<_>>().join("\n");
    if let Err(e) = crate::alert_mail::send(state, settings.alert_to.clone(), subject, text, None).await {
        tracing::warn!("health e-mail: {e}");
    }
}

fn site_name() -> String {
    std::env::var("SITE_NAME").ok().filter(|s| !s.trim().is_empty()).or_else(|| std::env::var("COMPUTERNAME").ok()).unwrap_or_else(|| "master".into())
}

/// The outbound report for a managed service (https only, except to this machine for tests).
async fn report(checks: &[Check]) {
    let (Ok(url), Ok(token)) = (std::env::var("HEALTH_REPORT_URL"), std::env::var("HEALTH_REPORT_TOKEN")) else { return };
    if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1")) {
        tracing::warn!("HEALTH_REPORT_URL must use https://; no report sent");
        return;
    }
    let body = json!({ "site": site_name(), "time": now(), "checks": checks });
    let r = reqwest::Client::new().post(&url).bearer_auth(token.trim()).timeout(Duration::from_secs(15)).json(&body).send().await;
    let outcome = match r {
        Ok(r) if r.status().is_success() => "sent".to_string(),
        Ok(r) => format!("refused: HTTP {}", r.status()),
        Err(e) => format!("failed: {e}"),
    };
    memory().lock().unwrap().last_report = Some((now(), outcome));
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        ensure_table(&state).await;
        let mut tick = 0u64;
        loop {
            let mut checks = run_checks(&state).await;
            let old = memory().lock().unwrap().checks.clone();
            let changed = remember(&mut checks, &old, now());
            memory().lock().unwrap().checks = checks.clone();
            mail_changes(&state, changed).await;
            if tick % 5 == 0 {
                report(&checks).await;
            }
            tick += 1;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

fn super_only(ctx: &AuthCtx) -> Option<Response> {
    (!ctx.is_super()).then(|| (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": "Platform admins only" }))).into_response())
}

/// `GET /api/admin/health` (platform admins): the latest checks and the outbound report's state.
pub async fn get(Extension(ctx): Extension<AuthCtx>) -> Response {
    if let Some(r) = super_only(&ctx) {
        return r;
    }
    let m = memory().lock().unwrap();
    let worst = m.checks.iter().map(|c| c.level).max().unwrap_or(Level::Ok);
    Json(json!({
        "status": worst, "site": site_name(), "checks": m.checks,
        "report": { "configured": std::env::var("HEALTH_REPORT_URL").is_ok(), "last": m.last_report.as_ref().map(|(t, o)| json!({ "at": t, "outcome": o })) },
    }))
    .into_response()
}

// ---- receiving side: the managed sites' reports ----

const SITES_DDL: &str = "CREATE TABLE IF NOT EXISTS site_health (site String, at Int64, status String, checks String) ENGINE = ReplacingMergeTree(at) ORDER BY site";

async fn ensure_table(state: &AppState) {
    if let Err(e) = state.db.main().query(SITES_DDL).execute().await {
        tracing::warn!("site_health table: {e}");
    }
}

#[derive(Deserialize)]
pub struct Report {
    site: String,
    checks: Vec<Check>,
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `POST /api/v1/sites/health-report` (public route, token in the handler): a managed site's
/// health. shortcut: one shared token for all sites; per-site tokens when sites are many.
pub async fn receive(State(state): State<AppState>, headers: HeaderMap, Json(r): Json<Report>) -> Response {
    let expected = std::env::var("HEALTH_REPORT_ACCEPT_TOKEN").unwrap_or_default();
    let given = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if expected.trim().len() < 16 || !same(given.trim(), expected.trim()) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "status": "error" }))).into_response();
    }
    if r.site.is_empty() || r.site.len() > 100 || !r.site.chars().all(|c| c.is_ascii_alphanumeric() || "._- ".contains(c)) || r.checks.len() > 50 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": "bad report" }))).into_response();
    }
    let worst = r.checks.iter().map(|c| c.level).max().unwrap_or(Level::Ok);
    let status = serde_json::to_value(worst).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
    let checks = serde_json::to_string(&r.checks).unwrap_or_default();
    match state.db.main().query("INSERT INTO site_health (site, at, status, checks) VALUES (?, ?, ?, ?)").bind(&r.site).bind(now()).bind(&status).bind(&checks).execute().await {
        Ok(()) => Json(json!({ "status": "ok" })).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}

#[derive(clickhouse::Row, Deserialize)]
struct SiteRow {
    site: String,
    at: i64,
    status: String,
    checks: String,
}

/// `GET /api/admin/sites` (platform admins): each managed site's latest report; a site silent for
/// 15 minutes is "silent".
pub async fn sites(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    if let Some(r) = super_only(&ctx) {
        return r;
    }
    let rows: Vec<SiteRow> = state.db.main().query("SELECT site, at, status, checks FROM site_health FINAL ORDER BY site").fetch_all().await.unwrap_or_default();
    let t = now();
    let list: Vec<Value> = rows
        .into_iter()
        .map(|r| json!({ "site": r.site, "at": r.at, "status": if t - r.at > 900 { "silent".to_string() } else { r.status }, "checks": serde_json::from_str::<Value>(&r.checks).unwrap_or(Value::Null) }))
        .collect();
    Json(json!({ "sites": list })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_levels() {
        assert_eq!(disk_level(4, 100).0, Level::Fail);
        assert_eq!(disk_level(10, 100).0, Level::Warn);
        assert_eq!(disk_level(50, 100), (Level::Ok, 50.0));
    }

    #[test]
    fn host_ports() {
        assert_eq!(host_port("http://10.0.0.3:11434").as_deref(), Some("10.0.0.3:11434"));
        assert_eq!(host_port("https://api.groq.com/openai").as_deref(), Some("api.groq.com:443"));
        assert_eq!(host_port("ftp://x"), None);
    }

    #[test]
    fn only_changes_are_news() {
        let old = vec![Check { since: 5, ..check("A", Level::Ok, "") }, Check { since: 7, ..check("B", Level::Warn, "") }];
        let mut new = vec![check("A", Level::Ok, ""), check("B", Level::Fail, ""), check("C", Level::Ok, ""), check("D", Level::Warn, "")];
        let changed = remember(&mut new, &old, 100);
        assert_eq!(new[0].since, 5, "unchanged keeps its time");
        assert_eq!(new[1].since, 100);
        let names: Vec<_> = changed.iter().map(|(c, o)| (c.name.as_str(), *o)).collect();
        assert_eq!(names, vec![("B", Some(Level::Warn)), ("D", None)], "a new OK check is not news");
    }

    #[test]
    fn token_compare() {
        assert!(same("abcdef", "abcdef"));
        assert!(!same("abcdef", "abcdeg"));
        assert!(!same("abc", "abcdef"));
    }
}
