//! Platform SMTP settings (super admin): stored in `ndr.settings` (the
//! `global_smtp_*` keys auth-service already reads for password-reset mail)
//! and applied to the Wazuh manager, so wazuh-maild and monitord's reports
//! send through the same account (TLS + login via `etc/smtp_auth.conf`).

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::tenancy::AuthCtx;
use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MailSettings {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Empty in requests: keep the stored one. Never returned.
    #[serde(default)]
    pub password: String,
    /// Alert e-mails from the manager (wazuh-maild).
    #[serde(default)]
    pub alert_enabled: bool,
    #[serde(default)]
    pub alert_to: Vec<String>,
    /// Lowest rule level that is e-mailed (`<email_alert_level>`).
    #[serde(default = "default_level")]
    pub alert_level: u8,
    #[serde(default = "default_maxperhour")]
    pub max_per_hour: u32,
}

fn default_level() -> u8 {
    12
}

fn default_maxperhour() -> u32 {
    12
}

impl Default for MailSettings {
    fn default() -> Self {
        MailSettings { host: String::new(), port: 587, user: String::new(), password: String::new(), alert_enabled: false, alert_to: Vec::new(), alert_level: 12, max_per_hour: 12 }
    }
}

impl MailSettings {
    /// 465 implicit TLS, 25 plain (relay), anything else STARTTLS.
    pub fn security(&self) -> &'static str {
        match self.port {
            465 => "tls",
            25 => "none",
            _ => "starttls",
        }
    }

    /// What Wazuh's `email_to` reader accepts, and nothing XML would need escaped.
    fn valid_email(s: &str) -> bool {
        let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+');
        match s.split_once('@') {
            Some((l, d)) => !l.is_empty() && !d.is_empty() && l.chars().all(ok) && d.chars().all(|c| ok(c) && c != '+') && d.contains('.'),
            None => false,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if !self.host.is_empty() && !self.host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')) {
            return Err("Invalid SMTP host".into());
        }
        if self.port == 0 {
            return Err("Invalid SMTP port".into());
        }
        if !self.user.is_empty() && !Self::valid_email(&self.user) {
            return Err("The account must be an e-mail address (it is also the sender)".into());
        }
        if self.password.contains(['\r', '\n']) {
            return Err("Invalid password".into());
        }
        if let Some(bad) = self.alert_to.iter().find(|t| !Self::valid_email(t)) {
            return Err(format!("Invalid recipient: {bad}"));
        }
        if self.alert_enabled && (self.host.is_empty() || self.user.is_empty() || self.alert_to.is_empty()) {
            return Err("Alert e-mails need the SMTP host, the account and at least one recipient".into());
        }
        if !(1..=16).contains(&self.alert_level) || !(1..=1_000_000).contains(&self.max_per_hour) {
            return Err("Invalid alert level or e-mails per hour".into());
        }
        Ok(())
    }
}

const KEYS: [&str; 8] = [
    "global_smtp_host",
    "global_smtp_port",
    "global_smtp_user",
    "global_smtp_password",
    "global_alert_email_enabled",
    "global_alert_email_to",
    "global_alert_email_level",
    "global_alert_email_maxperhour",
];

#[derive(clickhouse::Row, Deserialize)]
struct Row {
    key: String,
    value: String,
}

/// The stored settings (defaults for anything missing).
pub async fn load(state: &AppState) -> Option<MailSettings> {
    if !state.db.is_connected() {
        return None;
    }
    let q = format!("SELECT key, value FROM ndr.settings FINAL WHERE key IN ({})", KEYS.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(","));
    let rows = state.db.root().query(&q).fetch_all::<Row>().await.ok()?;
    let mut s = MailSettings::default();
    for r in rows {
        match r.key.as_str() {
            "global_smtp_host" => s.host = r.value,
            "global_smtp_port" => s.port = r.value.parse().unwrap_or(587),
            "global_smtp_user" => s.user = r.value,
            "global_smtp_password" => s.password = r.value,
            "global_alert_email_enabled" => s.alert_enabled = r.value == "yes",
            "global_alert_email_to" => s.alert_to = r.value.split(',').map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect(),
            "global_alert_email_level" => s.alert_level = r.value.parse().unwrap_or(12),
            "global_alert_email_maxperhour" => s.max_per_hour = r.value.parse().unwrap_or(12),
            _ => {}
        }
    }
    Some(s)
}

async fn store(state: &AppState, s: &MailSettings) -> Result<(), String> {
    let vals = [
        s.host.clone(),
        s.port.to_string(),
        s.user.clone(),
        s.password.clone(),
        if s.alert_enabled { "yes" } else { "no" }.to_string(),
        s.alert_to.join(","),
        s.alert_level.to_string(),
        s.max_per_hour.to_string(),
    ];
    for (k, v) in KEYS.iter().zip(vals) {
        state.db.root().query("INSERT INTO ndr.settings (key, value) VALUES (?, ?)").bind(*k).bind(v).execute().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn forbidden() -> axum::response::Response {
    (StatusCode::FORBIDDEN, Json(serde_json::json!({ "status": "error", "message": "Only platform admins can change the SMTP settings" }))).into_response()
}

/// `GET /api/settings/smtp`
pub async fn get_smtp(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if !ctx.is_super() {
        return forbidden();
    }
    let Some(mut s) = load(&state).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "message": "Settings store unavailable" }))).into_response();
    };
    let has_password = !s.password.is_empty();
    s.password.clear();
    Json(serde_json::json!({ "status": "ok", "config": s, "has_password": has_password, "security": s.security() })).into_response()
}

/// `POST /api/settings/smtp`
pub async fn post_smtp(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(mut s): Json<MailSettings>) -> axum::response::Response {
    if !ctx.is_super() {
        return forbidden();
    }
    s.host = s.host.trim().to_string();
    s.user = s.user.trim().to_string();
    s.alert_to = s.alert_to.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    if s.password.is_empty() {
        s.password = load(&state).await.map(|o| o.password).unwrap_or_default();
    }
    if let Err(m) = s.validate() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": m }))).into_response();
    }
    if let Err(e) = store(&state, &s).await {
        tracing::warn!("SMTP settings not saved: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "status": "error", "message": "Settings could not be saved" }))).into_response();
    }
    crate::wazuh_manager::apply_mail_settings(&s);
    Json(serde_json::json!({ "status": "ok" })).into_response()
}

#[derive(Deserialize)]
pub struct TestReq {
    pub to: String,
}

/// `POST /api/settings/smtp/test`: one e-mail through the saved settings.
pub async fn post_smtp_test(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(req): Json<TestReq>) -> axum::response::Response {
    if !ctx.is_super() {
        return forbidden();
    }
    let to = req.to.trim().to_string();
    if !MailSettings::valid_email(&to) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": "Invalid recipient" }))).into_response();
    }
    let Some(s) = load(&state).await.filter(|s| !s.host.is_empty()) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": "Save the SMTP settings first" }))).into_response();
    };
    let auth = siem_maild::smtp_ext::SmtpAuth { host: s.host.clone(), port: s.port, security: s.security().into(), user: s.user.clone(), password: s.password.clone() };
    let from = s.user.clone();
    let r = tokio::task::spawn_blocking(move || siem_maild::smtp_ext::send_test(&auth, &from, &to)).await;
    match r {
        Ok(Ok(())) => Json(serde_json::json!({ "status": "ok", "message": "Test e-mail sent" })).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "status": "error", "message": e }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        let mut s = MailSettings { host: "smtp.gmail.com".into(), user: "a.b@gmail.com".into(), alert_to: vec!["soc+x@corp.io".into()], alert_enabled: true, ..Default::default() };
        assert!(s.validate().is_ok());
        s.alert_to.push("bad<x>@corp.io".into());
        assert!(s.validate().is_err());
        s.alert_to.pop();
        s.host = "smtp.gmail.com</smtp_server>".into();
        assert!(s.validate().is_err());
        assert_eq!(MailSettings { port: 465, ..Default::default() }.security(), "tls");
    }
}
