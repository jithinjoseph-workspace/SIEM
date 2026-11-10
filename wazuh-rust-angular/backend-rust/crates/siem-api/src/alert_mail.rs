//! Per-tenant alert e-mails: each tenant admin chooses who receives e-mails about the
//! tenant's own alerts, from which rule level, optionally only for some rule groups, and at
//! most how many e-mails an hour. Alerts reach `on_alerts` after suppression (provigil_manager
//! `deliver`), already tagged with their tenant; every 30 s each tenant's queued alerts go out
//! as one e-mail (one alert, or a digest of up to 50, highest level first) through the
//! platform's SMTP account (mail_settings.rs). Another tenant's alerts never reach these
//! recipients: queues, settings and limits are per tenant.
//!
//! Settings: `siem_alert_mail` in the tenant's database (id "settings").
//! `GET|PUT /api/v1/tenant/alert-mail` (saving: the tenant admin),
//! `POST /api/v1/tenant/alert-mail/test` (a test e-mail to the saved recipients).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Extension, Json as JsonBody, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use siem_core::Alert;

use crate::tenancy::{self, AuthCtx};
use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_alert_mail (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";
const SETTINGS_ID: &str = "settings";
/// How often queued alerts are e-mailed.
const FLUSH_EVERY: Duration = Duration::from_secs(30);
/// Alerts listed in one e-mail; the rest are counted.
const PER_MAIL: usize = 50;
/// Alerts held per tenant between two flushes (the highest levels are kept).
const QUEUE_MAX: usize = 2000;
/// Settings are re-read from ClickHouse after this long.
const CACHE_FOR: Duration = Duration::from_secs(60);
const MAX_RECIPIENTS: usize = 20;
const MAX_GROUPS: usize = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub recipients: Vec<String>,
    /// Lowest rule level that is e-mailed.
    #[serde(default = "default_level")]
    pub min_level: u8,
    /// Only alerts in one of these rule groups (none: every group).
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default = "default_per_hour")]
    pub max_per_hour: u32,
    #[serde(default)]
    pub updated_by: String,
    #[serde(default)]
    pub updated_at: String,
}

fn default_level() -> u8 {
    12
}

fn default_per_hour() -> u32 {
    12
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            enabled: false,
            recipients: Vec::new(),
            min_level: 12,
            groups: Vec::new(),
            max_per_hour: 12,
            updated_by: String::new(),
            updated_at: String::new(),
        }
    }
}

impl Settings {
    fn validate(mut self) -> Result<Settings, String> {
        self.recipients = self
            .recipients
            .iter()
            .map(|r| r.trim().to_lowercase())
            .filter(|r| !r.is_empty())
            .collect();
        self.recipients.dedup();
        self.groups = self
            .groups
            .iter()
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty())
            .collect();
        if self.recipients.len() > MAX_RECIPIENTS {
            return Err(format!("At most {MAX_RECIPIENTS} recipients"));
        }
        if let Some(bad) = self
            .recipients
            .iter()
            .find(|r| !crate::mail_settings::MailSettings::valid_email(r))
        {
            return Err(format!("Invalid recipient: {bad}"));
        }
        if self.groups.len() > MAX_GROUPS
            || self.groups.iter().any(|g| {
                g.len() > 64
                    || !g
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            })
        {
            return Err("Rule groups: at most 30 names of letters, digits, '_', '-', '.'".into());
        }
        if !(1..=16).contains(&self.min_level) {
            return Err("The level must be between 1 and 16".into());
        }
        if !(1..=1000).contains(&self.max_per_hour) {
            return Err("E-mails per hour must be between 1 and 1000".into());
        }
        if self.enabled && self.recipients.is_empty() {
            return Err("Add at least one recipient to turn alert e-mails on".into());
        }
        Ok(self)
    }

    /// Whether the alert is e-mailed under these settings.
    pub fn wants(&self, a: &Alert) -> bool {
        a.rule.level >= self.min_level
            && (self.groups.is_empty()
                || a.rule
                    .groups
                    .iter()
                    .any(|g| self.groups.iter().any(|w| w.eq_ignore_ascii_case(g))))
    }
}

/// Per-tenant state between flushes.
#[derive(Default)]
struct TenantMail {
    queue: Vec<Alert>,
    /// When each e-mail of the last hour went out.
    sent: VecDeque<Instant>,
    /// Alerts not e-mailed because of the hourly limit, told in the next e-mail.
    held_back: usize,
    settings: Option<(Settings, Instant)>,
}

static STATE: Mutex<Option<HashMap<String, TenantMail>>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut HashMap<String, TenantMail>) -> T) -> T {
    f(STATE.lock().unwrap().get_or_insert_with(HashMap::new))
}

fn tenant_of(a: &Alert) -> String {
    a.data
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or(tenancy::DEFAULT_TENANT)
        .to_string()
}

/// The tenant's display name (its id when unknown).
pub fn tenant_name(state: &AppState, tenant: &str) -> String {
    state
        .tenants
        .read()
        .unwrap()
        .iter()
        .find(|t| tenancy::normalize_tenant(&t.id) == tenant)
        .map(|t| t.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| tenant.to_string())
}

/// Highest level first, then oldest first.
fn by_level(q: &mut [Alert]) {
    q.sort_by(|a, b| {
        b.rule
            .level
            .cmp(&a.rule.level)
            .then(a.timestamp.cmp(&b.timestamp))
    });
}

/// Queues the shown alerts for their tenant's next e-mail. Cheap: the cached settings
/// filter when known (the flush filters again), the queue keeps the highest levels.
pub fn on_alerts(alerts: &[Alert]) {
    if alerts.is_empty() {
        return;
    }
    with(|m| {
        for a in alerts {
            let t = m.entry(tenant_of(a)).or_default();
            if let Some((s, _)) = &t.settings {
                if !s.enabled || !s.wants(a) {
                    continue;
                }
            }
            t.queue.push(a.clone());
            if t.queue.len() > 2 * QUEUE_MAX {
                by_level(&mut t.queue);
                let dropped = t.queue.len() - QUEUE_MAX;
                t.queue.truncate(QUEUE_MAX);
                if t.settings.is_some() {
                    t.held_back += dropped;
                }
            }
        }
    });
}

/// What goes out now: the wanted alerts (highest level first) and how many were held
/// back earlier. None when nothing is due: nothing wanted, or the hourly limit is reached
/// (then the alerts are only counted, for the next e-mail).
fn take(t: &mut TenantMail, s: &Settings, now: Instant) -> Option<(Vec<Alert>, usize)> {
    let mut q: Vec<Alert> = std::mem::take(&mut t.queue)
        .into_iter()
        .filter(|a| s.enabled && s.wants(a))
        .collect();
    if q.is_empty() {
        return None;
    }
    while t
        .sent
        .front()
        .is_some_and(|x| now.duration_since(*x) >= Duration::from_secs(3600))
    {
        t.sent.pop_front();
    }
    if t.sent.len() >= s.max_per_hour as usize {
        t.held_back += q.len();
        return None;
    }
    t.sent.push_back(now);
    by_level(&mut q);
    Some((q, std::mem::take(&mut t.held_back)))
}

fn cut(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

fn block(a: &Alert, log_chars: usize) -> String {
    let mut b = format!(
        "Time:     {}\nRule:     {} (level {}) - {}\nAgent:    {} {} ({})\nLocation: {}\n",
        a.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        a.rule.id,
        a.rule.level,
        a.rule.description,
        a.agent.id,
        a.agent.name,
        a.agent.ip,
        a.location
    );
    if !a.rule.groups.is_empty() {
        b.push_str(&format!("Groups:   {}\n", a.rule.groups.join(", ")));
    }
    if let Some(m) = a.rule.mitre.as_ref().filter(|m| !m.id.is_empty()) {
        b.push_str(&format!("MITRE:    {} {}\n", m.id, m.technique));
    }
    if !a.full_log.is_empty() {
        b.push_str(&format!("\n{}\n", cut(&a.full_log, log_chars)));
    }
    b
}

/// The e-mail of one flush: (subject, text).
fn compose(
    tenant: &str,
    alerts: &[Alert],
    held_back: usize,
    max_per_hour: u32,
) -> (String, String) {
    let top = alerts.iter().map(|a| a.rule.level).max().unwrap_or(0);
    let (subject, mut text) = if alerts.len() == 1 {
        (
            format!(
                "ProVigil alert - level {top} - {}",
                cut(&alerts[0].rule.description, 100)
            ),
            format!("ProVigil alert for {tenant}\n\n{}", block(&alerts[0], 4000)),
        )
    } else {
        let mut t = format!(
            "ProVigil alerts for {tenant}: {} alerts, highest level {top}\n",
            alerts.len()
        );
        for a in alerts.iter().take(PER_MAIL) {
            t.push_str(&format!(
                "\n----------------------------------------\n{}",
                block(a, 600)
            ));
        }
        if alerts.len() > PER_MAIL {
            t.push_str(&format!(
                "\n... and {} more alerts (see the console).\n",
                alerts.len() - PER_MAIL
            ));
        }
        (
            format!(
                "ProVigil alerts - {} alerts, highest level {top}",
                alerts.len()
            ),
            t,
        )
    };
    if held_back > 0 {
        text.push_str(&format!("\n{held_back} alert(s) were not e-mailed earlier: the limit is {max_per_hour} e-mail(s) an hour.\n"));
    }
    text.push_str("\nYou receive this e-mail because your ProVigil administrator added you to the alert e-mails.\n");
    (subject, text)
}

/// The tenant's saved settings (defaults when none).
pub async fn load(state: &AppState, tenant: &str) -> Result<Settings, String> {
    let rows = state
        .db
        .tenant_client(tenant)
        .query("SELECT doc FROM siem_alert_mail FINAL WHERE id = ? LIMIT 1")
        .bind(SETTINGS_ID)
        .fetch_all::<String>()
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows
        .first()
        .and_then(|d| serde_json::from_str(d).ok())
        .unwrap_or_default())
}

/// The settings, re-read when older than a minute; None while ClickHouse does not answer.
async fn settings(state: &AppState, tenant: &str) -> Option<Settings> {
    let cached = with(|m| m.get(tenant).and_then(|t| t.settings.clone()));
    if let Some((s, _)) = cached.filter(|(_, at)| at.elapsed() < CACHE_FOR) {
        return Some(s);
    }
    match load(state, tenant).await {
        Ok(s) => {
            with(|m| {
                m.entry(tenant.to_string()).or_default().settings =
                    Some((s.clone(), Instant::now()))
            });
            Some(s)
        }
        Err(e) => {
            tracing::warn!("alert e-mails of tenant {tenant}: settings not read: {e}");
            None
        }
    }
}

/// A file sent with an e-mail: (name, MIME type, bytes).
pub type Attached = (String, &'static str, Vec<u8>);

/// Sends one message to `to` through the platform SMTP account (mail_settings.rs).
pub async fn send(
    state: &AppState,
    to: Vec<String>,
    subject: String,
    text: String,
    attachment: Option<Attached>,
) -> Result<(), String> {
    let m = crate::mail_settings::load(state)
        .await
        .ok_or("Settings store unavailable")?;
    let auth = m
        .smtp_auth()
        .ok_or("The platform SMTP account is not set (super admin: Settings, SMTP)")?;
    let from = m.user.clone();
    let att = attachment.map(|(n, mime, d)| crate::mail_send::Attachment {
        name: n,
        mime: mime.to_string(),
        data: d,
    });
    crate::mail_send::send(&auth, &from, &to, &subject, &text, att).await
}

/// One flush: each tenant's queued alerts as one e-mail.
async fn flush(state: &AppState) {
    let tenants: Vec<String> = with(|m| {
        m.iter()
            .filter(|(_, t)| !t.queue.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    });
    for tenant in tenants {
        let Some(s) = settings(state, &tenant).await else {
            continue;
        };
        let Some((alerts, held_back)) =
            with(|m| take(m.entry(tenant.clone()).or_default(), &s, Instant::now()))
        else {
            continue;
        };
        let (subject, text) = compose(
            &tenant_name(state, &tenant),
            &alerts,
            held_back,
            s.max_per_hour,
        );
        match send(state, s.recipients.clone(), subject, text, None).await {
            Ok(()) => tracing::info!(
                "alert e-mail of tenant {tenant}: {} alert(s) to {} recipient(s)",
                alerts.len(),
                s.recipients.len()
            ),
            Err(e) => {
                tracing::warn!(
                    "alert e-mail of tenant {tenant} not sent ({} alert(s), retried in {}s): {e}",
                    alerts.len(),
                    FLUSH_EVERY.as_secs()
                );
                // retried with the next flush; the failed try does not count against the hourly limit
                with(|m| {
                    let t = m.entry(tenant.clone()).or_default();
                    t.sent.pop_back();
                    t.held_back += held_back;
                    let mut q = alerts;
                    q.append(&mut t.queue);
                    q.truncate(QUEUE_MAX);
                    t.queue = q;
                });
            }
        }
    }
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FLUSH_EVERY).await;
            if state.db.is_connected() {
                flush(&state).await;
            }
        }
    });
}

fn err(code: StatusCode, m: impl Into<String>) -> Response {
    (
        code,
        Json(json!({ "status": "error", "message": m.into() })),
    )
        .into_response()
}

/// `GET /api/v1/tenant/alert-mail`
pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let smtp_ready = crate::mail_settings::load(&state)
        .await
        .and_then(|m| m.smtp_auth())
        .is_some();
    match load(&state, &tenant).await {
        Ok(s) => {
            Json(json!({ "status": "ok", "settings": s, "smtp_ready": smtp_ready })).into_response()
        }
        Err(e) => err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Settings not read: {e}"),
        ),
    }
}

/// `PUT /api/v1/tenant/alert-mail`
pub async fn put(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    JsonBody(body): JsonBody<Settings>,
) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let mut s = match body.validate() {
        Ok(s) => s,
        Err(m) => return err(StatusCode::BAD_REQUEST, m),
    };
    s.updated_by = ctx.username.clone();
    s.updated_at = chrono::Utc::now().to_rfc3339();
    let doc = serde_json::to_string(&s).unwrap_or_default();
    let version = chrono::Utc::now().timestamp_micros().max(0) as u64;
    if let Err(e) = state
        .db
        .tenant_client(&tenant)
        .query("INSERT INTO siem_alert_mail (id, doc, version) VALUES (?, ?, ?)")
        .bind(SETTINGS_ID)
        .bind(&doc)
        .bind(version)
        .execute()
        .await
    {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Settings not saved: {e}"),
        );
    }
    with(|m| m.entry(tenant.clone()).or_default().settings = Some((s.clone(), Instant::now())));
    tracing::info!(
        "alert e-mails of tenant {tenant} saved by {}: {}, {} recipient(s), level {}+",
        ctx.username,
        if s.enabled { "on" } else { "off" },
        s.recipients.len(),
        s.min_level
    );
    Json(json!({ "status": "ok", "settings": s })).into_response()
}

/// `POST /api/v1/tenant/alert-mail/test`: a test e-mail to the saved recipients.
pub async fn test(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let s = match load(&state, &tenant).await {
        Ok(s) => s,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Settings not read: {e}"),
            )
        }
    };
    if s.recipients.is_empty() {
        return err(StatusCode::BAD_REQUEST, "Save at least one recipient first");
    }
    let text = format!("This is a test of the ProVigil alert e-mails of {}.\nAlerts of level {} and above will be e-mailed to this address.\n", tenant_name(&state, &tenant), s.min_level);
    match send(&state, s.recipients.clone(), "ProVigil alert e-mails - test".into(), text, None).await {
        Ok(()) => Json(json!({ "status": "ok", "message": format!("Test e-mail sent to {} recipient(s)", s.recipients.len()) })).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(tenant: &str, level: u8, groups: &[&str]) -> Alert {
        let mut a: Alert = serde_json::from_value(json!({
            "id": uuid::Uuid::new_v4(), "timestamp": "2026-11-03T10:00:00Z",
            "rule": { "id": 5710, "level": level, "description": "sshd: attempt to login using a non-existent user", "groups": groups, "mitre": null },
            "agent": { "id": "049", "name": "pc-49", "ip": "10.0.0.49" },
            "full_log": "Nov  3 10:00:00 pc sshd[1]: Invalid user x", "decoded": { "decoder_name": "sshd", "extra": {} }, "location": "/var/log/auth.log"
        }))
        .unwrap();
        a.data.insert("tenant_id".into(), json!(tenant));
        a
    }

    fn on(min_level: u8, max_per_hour: u32) -> Settings {
        Settings {
            enabled: true,
            recipients: vec!["soc@a.io".into()],
            min_level,
            max_per_hour,
            ..Default::default()
        }
    }

    #[test]
    fn validation() {
        assert!(on(12, 12).validate().is_ok());
        assert!(Settings {
            recipients: vec!["bad@x".into()],
            ..on(12, 12)
        }
        .validate()
        .is_err());
        assert!(Settings {
            recipients: vec![],
            ..on(12, 12)
        }
        .validate()
        .is_err());
        assert!(Settings {
            groups: vec!["a b".into()],
            ..on(12, 12)
        }
        .validate()
        .is_err());
        assert!(on(0, 12).validate().is_err());
        assert!(on(12, 0).validate().is_err());
        let s = Settings {
            recipients: vec![" SOC@A.io ".into(), "soc@a.io".into()],
            ..on(12, 12)
        }
        .validate()
        .unwrap();
        assert_eq!(s.recipients, vec!["soc@a.io"]);
    }

    #[test]
    fn wanted_by_level_and_group() {
        let s = Settings {
            groups: vec!["Authentication_failed".into()],
            ..on(10, 12)
        };
        assert!(s.wants(&alert("a", 10, &["sshd", "authentication_failed"])));
        assert!(!s.wants(&alert("a", 9, &["authentication_failed"])));
        assert!(!s.wants(&alert("a", 12, &["sshd"])));
    }

    #[test]
    fn tenants_kept_apart_and_hourly_limit() {
        let mut ta = TenantMail::default();
        let mut tb = TenantMail::default();
        for a in [
            alert("a", 12, &[]),
            alert("b", 13, &[]),
            alert("a", 3, &[]),
            alert("a", 14, &[]),
        ] {
            if tenant_of(&a) == "a" {
                &mut ta
            } else {
                &mut tb
            }
            .queue
            .push(a);
        }
        let now = Instant::now();
        let (sent, held) = take(&mut ta, &on(12, 1), now).unwrap();
        assert_eq!(
            sent.iter().map(|a| a.rule.level).collect::<Vec<_>>(),
            vec![14, 12],
            "tenant a: its own alerts at level 12+, highest first"
        );
        assert!(sent.iter().all(|a| tenant_of(a) == "a") && held == 0);
        // the hour's one e-mail is used: the next alerts are counted, told in the next e-mail
        ta.queue.push(alert("a", 15, &[]));
        assert!(take(&mut ta, &on(12, 1), now + Duration::from_secs(60)).is_none());
        ta.queue.push(alert("a", 15, &[]));
        let (sent, held) = take(&mut ta, &on(12, 1), now + Duration::from_secs(3601)).unwrap();
        assert_eq!((sent.len(), held), (1, 1));
        let (sent, _) = take(&mut tb, &on(12, 12), now).unwrap();
        assert_eq!(sent.len(), 1);
        assert!(take(
            &mut tb,
            &Settings {
                enabled: false,
                ..on(1, 12)
            },
            now
        )
        .is_none());
    }

    #[test]
    fn digest_text() {
        let alerts: Vec<Alert> = (0..60)
            .map(|i| alert("a", 12 + (i % 3) as u8, &["sshd"]))
            .collect();
        let (subject, text) = compose("Acme", &alerts, 4, 12);
        assert_eq!(subject, "ProVigil alerts - 60 alerts, highest level 14");
        assert!(text.starts_with("ProVigil alerts for Acme: 60 alerts"));
        assert!(
            text.contains("... and 10 more alerts")
                && text.contains("4 alert(s) were not e-mailed earlier")
        );
        let (subject, text) = compose("Acme", &alerts[..1], 0, 12);
        assert!(subject.starts_with("ProVigil alert - level 12 - sshd"));
        assert!(
            text.contains("Agent:    049 pc-49 (10.0.0.49)") && text.contains("Invalid user x")
        );
    }
}
