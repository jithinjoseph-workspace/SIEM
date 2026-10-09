//! Agent self-enrollment with the SIEM manager.
//!
//! An agent without an identity (no `client.keys`, no `SIEM_AGENT_ID`)
//! calls `POST <manager>/api/v1/agents/enroll` with its name, group and the
//! tenant's agent key (`X-Tenant-Key`). The manager returns an agent id that
//! is unique across every tenant, and the agent stores it in `client.keys`
//! (`ID NAME IP KEY`), so later starts reuse it. Re-enrolling the same name
//! in the same tenant gives the same id back.
//!
//! The tenant key comes from `SIEM_TENANT_KEY` / `WAZUH_TENANT_KEY` or from
//! `"tenant_key"` in `agent-config.json`; it is exported as
//! `SIEM_TENANT_KEY` so every request the agent sends carries it.

use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Enrollment {
    pub agent_id: String,
    pub agent_name: String,
    pub ip: String,
    pub raw_key: String,
    pub tenant_id: String,
}

/// The tenant agent key from the environment or a parsed `agent-config.json`.
pub fn tenant_key(config_json: Option<&serde_json::Value>) -> Option<String> {
    std::env::var("SIEM_TENANT_KEY")
        .ok()
        .or_else(|| std::env::var("WAZUH_TENANT_KEY").ok())
        .or_else(|| config_json.and_then(|v| v.get("tenant_key")).and_then(|v| v.as_str()).map(str::to_string))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Makes the tenant key visible to the HTTP senders (they read `SIEM_TENANT_KEY`).
pub fn export_tenant_key(key: Option<&str>) {
    if let Some(k) = key {
        if std::env::var("SIEM_TENANT_KEY").map(|v| v.trim().is_empty()).unwrap_or(true) {
            std::env::set_var("SIEM_TENANT_KEY", k);
        }
    }
}

/// Wazuh agent names: letters, digits, '.', '_', '-' (anything else becomes '-').
pub fn sanitize_name(name: &str) -> String {
    let s: String = name
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .take(128)
        .collect();
    if s.len() < 2 { format!("agent-{s}") } else { s }
}

/// One enrollment request.
pub async fn enroll(
    manager_url: &str,
    name: &str,
    groups: &str,
    os_type: &str,
    tenant_key: Option<&str>,
) -> Result<Enrollment, String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let url = format!("{}/api/v1/agents/enroll", manager_url.trim_end_matches('/'));
    let mut req = client.post(&url).json(&serde_json::json!({
        "name": sanitize_name(name),
        "groups": groups,
        "os_type": os_type,
    }));
    if let Some(k) = tenant_key {
        req = req.header("X-Tenant-Key", k);
    }
    let resp = req.send().await.map_err(|e| format!("{url}: {e}"))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = body.get("message").and_then(|v| v.as_str()).unwrap_or("");
        return Err(format!("{url}: HTTP {status} {msg}"));
    }
    let field = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let e = Enrollment {
        agent_id: field("agent_id"),
        agent_name: field("agent_name"),
        ip: field("agent_ip"),
        raw_key: field("raw_key"),
        tenant_id: field("tenant_id"),
    };
    if e.agent_id.is_empty() {
        return Err(format!("{url}: no agent_id in reply"));
    }
    Ok(e)
}

/// Enrolls, retrying every 30 s until the manager answers (an agent cannot
/// report anything without an id). A rejected tenant key is retried too:
/// it may be fixed on the manager side without reinstalling.
pub async fn enroll_until_done(manager_url: &str, name: &str, groups: &str, os_type: &str, tenant_key: Option<&str>) -> Enrollment {
    loop {
        match enroll(manager_url, name, groups, os_type, tenant_key).await {
            Ok(e) => {
                tracing::info!("Enrolled with manager: agent id {} ('{}') in tenant '{}'", e.agent_id, e.agent_name, e.tenant_id);
                return e;
            }
            Err(err) => {
                tracing::warn!("Enrollment failed ({err}); retrying in 30s");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }
}

/// Stores the identity as a Wazuh `client.keys` line (`ID NAME IP KEY`).
pub fn write_client_keys(path: &Path, e: &Enrollment) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let ip = if e.ip.is_empty() { "any" } else { &e.ip };
    std::fs::write(path, format!("{} {} {} {}\n", e.agent_id, e.agent_name, ip, e.raw_key))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
    }
    Ok(())
}

// ───────────────────────── deactivation ─────────────────────────

/// The agent's state on the manager: Some(true) active, Some(false)
/// deactivated, None when the manager cannot be reached.
pub async fn agent_state(manager_url: &str, agent_id: &str) -> Option<bool> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().ok()?;
    let url = format!("{}/api/v1/agent/state?agent_id={}", manager_url.trim_end_matches('/'), agent_id);
    let body: serde_json::Value = client.get(&url).send().await.ok()?.json().await.ok()?;
    match body.get("state").and_then(|v| v.as_str()) {
        Some("deactivated") => Some(false),
        Some(_) => Some(true),
        None => None,
    }
}

/// A deactivated agent stays dormant here (no collectors, nothing sent) and
/// checks once a minute; it continues as soon as it is reactivated. When the
/// manager cannot be reached the agent starts normally (uploads are refused
/// with 410 if it is in fact deactivated).
pub async fn wait_until_active(manager_url: &str, agent_id: &str) {
    let mut announced = false;
    while agent_state(manager_url, agent_id).await == Some(false) {
        if !announced {
            tracing::warn!("Agent {agent_id} is deactivated on the manager: monitoring stopped, waiting to be reactivated");
            announced = true;
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
    if announced {
        tracing::info!("Agent {agent_id} was reactivated: starting monitoring");
    }
}

/// Stops the agent after the manager deactivated it. The service manager
/// (systemd Restart=always / Windows service recovery) starts it again, and
/// the new process waits dormant in wait_until_active.
pub fn stop_deactivated(agent_id: &str) -> ! {
    tracing::warn!("Agent {agent_id} was deactivated by the manager: stopping all monitoring");
    std::process::exit(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(sanitize_name("web server #1"), "web-server--1");
        assert_eq!(sanitize_name("x"), "agent-x");
        assert_eq!(sanitize_name("linux-node-01"), "linux-node-01");
    }

    #[test]
    fn key_from_config() {
        let v = serde_json::json!({ "tenant_key": " tk_abc " });
        if std::env::var("SIEM_TENANT_KEY").is_err() && std::env::var("WAZUH_TENANT_KEY").is_err() {
            assert_eq!(tenant_key(Some(&v)).as_deref(), Some("tk_abc"));
        }
    }
}
