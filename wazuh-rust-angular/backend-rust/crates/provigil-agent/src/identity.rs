//! Agent Identity and One-Click Enrollment.
//!
//! Replaces legacy `siem-authd` and `client.keys` with modern HTTPS enrollment.

use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

pub(crate) const IDENTITY_FILE: &str = "data/agent-identity.json";
/// Written after a forced enrollment; the install script removes it.
pub(crate) const FORCE_USED_FILE: &str = "data/force-enroll-used";

/// `force_enroll` counts once per install: an agent removed in the console later must not
/// bring itself back at its next enrollment.
pub fn force_allowed(configured: bool, used: &Path) -> bool {
    configured && !used.exists()
}

/// The tenant key to send, when one is configured: empty and the placeholder "default" are
/// not keys (sending them makes the manager refuse every request with 401).
pub fn real_tenant_key(key: &str) -> Option<&str> {
    let k = key.trim();
    (!k.is_empty() && !k.eq_ignore_ascii_case("default")).then_some(k)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub agent_name: String,
    pub tenant_id: String,
    pub auth_token: String,
    pub enrolled_at: DateTime<Utc>,
}

impl AgentIdentity {
    /// Loads saved identity from disk if available.
    pub fn load_local() -> Option<Self> {
        let path = Path::new(IDENTITY_FILE);
        if path.is_file() {
            if let Ok(data) = fs::read_to_string(path) {
                if let Ok(ident) = serde_json::from_str(&data) {
                    return Some(ident);
                }
            }
        }

        // Fallback: check client.keys (written by deployment PowerShell script)
        let possible_keys_paths = [
            Path::new("client.keys"),
            Path::new("data/client.keys"),
            Path::new("/opt/provigil-agent/etc/client.keys"),
            Path::new("/etc/provigil-agent/client.keys"),
            Path::new("C:\\Program Files (x86)\\ProVigil Agent\\client.keys"),
            Path::new("C:\\Program Files\\ProVigil Agent\\client.keys"),
        ];

        for kpath in possible_keys_paths {
            if kpath.is_file() {
                if let Ok(content) = fs::read_to_string(kpath) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let tenant_key = [
                                Path::new("provigil-agent.json"),
                                Path::new("/opt/provigil-agent/etc/provigil-agent.json"),
                                Path::new("/etc/provigil-agent/provigil-agent.json"),
                                Path::new("C:\\Program Files (x86)\\ProVigil Agent\\provigil-agent.json"),
                                Path::new("C:\\Program Files\\ProVigil Agent\\provigil-agent.json"),
                            ].iter()
                            .find(|p| p.is_file())
                            .and_then(|p| fs::read_to_string(p).ok())
                            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                            .and_then(|v| v["tenant_key"].as_str().map(String::from))
                            .unwrap_or_else(|| "default".to_string());

                            let ident = AgentIdentity {
                                agent_id: parts[0].to_string(),
                                agent_name: parts[1].to_string(),
                                tenant_id: tenant_key,
                                auth_token: parts[3].to_string(),
                                enrolled_at: Utc::now(),
                            };
                            let _ = ident.save_local();
                            return Some(ident);
                        }
                    }
                }
            }
        }

        None
    }

    /// Saves identity to disk securely.
    pub fn save_local(&self) -> std::io::Result<()> {
        if let Some(parent) = Path::new(IDENTITY_FILE).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(IDENTITY_FILE, json)?;
        restrict(Path::new(IDENTITY_FILE));
        Ok(())
    }

    /// Enrolls the agent with the ProVigil SIEM manager (over HTTPS or gRPC).
    pub async fn enroll(
        link: &dyn crate::transport::Link,
        tenant_key: &str,
        agent_name: &str,
        groups: &str,
        force: bool,
    ) -> Result<Self, String> {
        let agent_name = &clean_name(agent_name);
        let payload = enroll_body(tenant_key, agent_name, groups, force);

        info!(url = %link.url(), agent_name = %agent_name, "Attempting agent enrollment");

        let resp_json = link.enroll(&payload).await.map_err(|e| match e {
            crate::transport::Fail::Status(status, body) => format!("Enrollment rejected ({status}): {body}"),
            crate::transport::Fail::Bad(e) => format!("Failed to parse enrollment response: {e}"),
            e => format!("Enrollment request failed: {e}"),
        })?;

        // an answer without an id or key is not an enrollment (never invent one)
        let agent_id = resp_json["agent_id"]
            .as_str()
            .or_else(|| resp_json["id"].as_str())
            .filter(|s| !s.is_empty())
            .ok_or("Enrollment answer has no agent id")?
            .to_string();

        let auth_token = resp_json["raw_key"]
            .as_str()
            .or_else(|| resp_json["token"].as_str())
            .or_else(|| resp_json["auth_token"].as_str())
            .filter(|s| !s.is_empty())
            .ok_or("Enrollment answer has no agent key")?
            .to_string();

        let tenant_id = resp_json["tenant_id"]
            .as_str()
            .unwrap_or(tenant_key)
            .to_string();

        let identity = AgentIdentity {
            agent_id,
            agent_name: agent_name.to_string(),
            tenant_id,
            auth_token,
            enrolled_at: Utc::now(),
        };

        if let Err(e) = identity.save_local() {
            error!(error = %e, "Failed to persist agent identity to disk");
        } else {
            info!(agent_id = %identity.agent_id, "Agent identity enrolled and saved successfully");
        }
        if force {
            if let Err(e) = fs::write(FORCE_USED_FILE, "") {
                error!(error = %e, "force_enroll not marked as used");
            }
        }

        Ok(identity)
    }
}


/// The name the manager accepts: letters, digits, `.`, `_` and `-` (others become `-`).
fn clean_name(name: &str) -> String {
    name.trim().chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' }).collect()
}

/// The enrollment request (the tenant key also goes in a header).
fn enroll_body(tenant_key: &str, name: &str, groups: &str, force: bool) -> serde_json::Value {
    let os_type = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    serde_json::json!({
        "name": name,
        "tenant_key": tenant_key,
        "hostname": sysinfo::System::host_name().unwrap_or_default(),
        "os": crate::osinfo::enroll_os_string(),
        "os_type": os_type,
        "groups": groups.trim(),
        "version": env!("CARGO_PKG_VERSION"),
        "force": force,
    })
}

/// Only SYSTEM and Administrators (or owner root `0600` on Unix) may open the file.
fn restrict(path: &Path) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let r = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output();
        if !r.as_ref().is_ok_and(|o| o.status.success()) {
            error!(file = %path.display(), "Agent identity file not restricted to SYSTEM and Administrators");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            error!(file = %path.display(), error = %e, "Agent identity file permissions not set to 0600");
        }
    }
    #[cfg(not(any(windows, unix)))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_request() {
        assert_eq!(clean_name(" Jo's PC (2) "), "Jo-s-PC--2-");
        assert_eq!(clean_name("web-01.corp_x"), "web-01.corp_x");
        let b = enroll_body("tk", "pc", " web,db ", false);
        assert_eq!((b["os_type"].as_str(), b["groups"].as_str(), b["name"].as_str()), (Some("windows"), Some("web,db"), Some("pc")));
        assert_eq!(b["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(b["force"], false);
        assert_eq!(enroll_body("tk", "pc", "", true)["force"], true);
    }

    #[test]
    fn force_enroll_counts_once() {
        let dir = tempfile::tempdir().unwrap();
        let used = dir.path().join("force-enroll-used");
        assert!(!force_allowed(false, &used));
        assert!(force_allowed(true, &used));
        fs::write(&used, "").unwrap();
        assert!(!force_allowed(true, &used), "a later enrollment of the same install");
    }

    #[cfg(windows)]
    #[test]
    fn identity_file_only_for_system_and_administrators() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent-identity.json");
        fs::write(&p, "{}").unwrap();
        restrict(&p);
        let out = std::process::Command::new("icacls").arg(&p).output().unwrap();
        let acl = String::from_utf8_lossy(&out.stdout);
        assert_eq!(acl.matches(":(F)").count(), 2, "{acl}");
        assert!(!acl.contains("(I)"), "no inherited entries: {acl}");
    }
}
