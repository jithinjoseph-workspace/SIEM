//! ProVigil Agent Self-Enrollment with SIEM Manager
//!
//! Agents without identity call POST /api/v1/agents/enroll to receive a unique agent_id.
//! The manager returns agent_id which is stored in client.keys for reuse.
//! 100% clean-room implementation.

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

/// Extract tenant key from environment or config JSON
pub fn tenant_key(config_json: Option<&serde_json::Value>) -> Option<String> {
    std::env::var("SIEM_TENANT_KEY")
        .ok()
        .or_else(|| std::env::var("WAZUH_TENANT_KEY").ok())
        .or_else(|| config_json.and_then(|v| v.get("tenant_key")).and_then(|v| v.as_str()).map(str::to_string))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Export tenant key to environment for HTTP senders
pub fn export_tenant_key(key: Option<&str>) {
    if let Some(k) = key {
        if std::env::var("SIEM_TENANT_KEY").map(|v| v.trim().is_empty()).unwrap_or(true) {
            std::env::set_var("SIEM_TENANT_KEY", k);
        }
    }
}

/// Export agent's own key as X-Agent-Key
pub fn export_agent_key(key: &str) {
    if !key.trim().is_empty() {
        std::env::set_var("SIEM_AGENT_KEY", key.trim());
    }
}

/// Sanitize agent name: letters, digits, '.', '_', '-' only
pub fn sanitize_name(name: &str) -> String {
    let s: String = name
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .take(128)
        .collect();
    if s.len() < 2 { format!("agent-{s}") } else { s }
}

/// Single enrollment request to manager
pub async fn enroll(
    manager_url: &str,
    name: &str,
    groups: &str,
    os_type: &str,
    tenant_key: Option<&str>,
) -> Result<Enrollment, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

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

/// Enroll with retries every 30s until manager responds
pub async fn enroll_until_done(
    manager_url: &str,
    name: &str,
    groups: &str,
    os_type: &str,
    tenant_key: Option<&str>
) -> Enrollment {
    loop {
        match enroll(manager_url, name, groups, os_type, tenant_key).await {
            Ok(e) => {
                tracing::info!(
                    "Enrolled with manager: agent id {} ('{}') in tenant '{}'",
                    e.agent_id, e.agent_name, e.tenant_id
                );
                return e;
            }
            Err(err) => {
                tracing::warn!("Enrollment failed ({err}); retrying in 30s");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }
}

/// Write identity to client.keys file (ID NAME IP KEY)
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

/// Check agent state on manager: Some(true) = active, Some(false) = deactivated
pub async fn agent_state(manager_url: &str, agent_id: &str) -> Option<bool> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;

    let url = format!(
        "{}/api/v1/agent/state?agent_id={}",
        manager_url.trim_end_matches('/'),
        agent_id
    );

    let body: serde_json::Value = client.get(&url).send().await.ok()?.json().await.ok()?;

    match body.get("state").and_then(|v| v.as_str()) {
        Some("deactivated") => Some(false),
        Some(_) => Some(true),
        None => None,
    }
}

/// Wait until agent is activated on manager (checks every 60s)
pub async fn wait_until_active(manager_url: &str, agent_id: &str) {
    let mut announced = false;
    while agent_state(manager_url, agent_id).await == Some(false) {
        if !announced {
            tracing::warn!(
                "Agent {agent_id} is deactivated on manager: monitoring stopped, waiting to be reactivated"
            );
            announced = true;
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
    if announced {
        tracing::info!("Agent {agent_id} was reactivated: starting monitoring");
    }
}

/// Stop agent after deactivation (service manager will restart it)
pub fn stop_deactivated(agent_id: &str) -> ! {
    tracing::warn!("Agent {agent_id} was deactivated by manager: stopping all monitoring");
    std::process::exit(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_names() {
        assert_eq!(sanitize_name("web server #1"), "web-server--1");
        assert_eq!(sanitize_name("x"), "agent-x");
        assert_eq!(sanitize_name("linux-node-01"), "linux-node-01");
    }

    #[test]
    fn test_key_from_config() {
        let v = serde_json::json!({ "tenant_key": " tk_abc " });
        if std::env::var("SIEM_TENANT_KEY").is_err() && std::env::var("WAZUH_TENANT_KEY").is_err() {
            assert_eq!(tenant_key(Some(&v)).as_deref(), Some("tk_abc"));
        }
    }
}
