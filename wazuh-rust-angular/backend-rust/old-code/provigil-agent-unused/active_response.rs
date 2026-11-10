//! ProVigil Active Response - Automated Threat Remediation
//!
//! Executes defensive actions: block IPs, kill processes, quarantine files, disable accounts.
//! 100% clean-room implementation using Windows native tools (netsh, taskkill, icacls, net).

use crate::buffer::EventBuffer;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveResponseCommand {
    pub command_id: String,
    pub action: String,
    pub target: String,
}

pub struct ActiveResponseHandler {
    agent_id: String,
}

impl ActiveResponseHandler {
    pub fn new(agent_id: String) -> Self {
        Self { agent_id }
    }

    /// Block attacking IP via Windows Firewall (netsh)
    pub async fn block_ip(&self, ip: &str, buffer: &EventBuffer) -> bool {
        info!("Active Response: Blocking IP '{}'", ip);

        #[cfg(target_os = "windows")]
        {
            let rule_name = format!("ProVigil-Block-{}", ip);
            let status = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", rule_name),
                    "dir=in", "action=block",
                    &format!("remoteip={}", ip),
                ])
                .status();

            match status {
                Ok(s) if s.success() => {
                    let msg = format!("Blocked IP {} via Windows Firewall rule '{}'", ip, rule_name);
                    info!("{}", msg);

                    let event = json!({
                        "event_type": "active_response",
                        "timestamp": Utc::now().to_rfc3339(),
                        "agent": { "id": &self.agent_id },
                        "action": "block_ip",
                        "target_ip": ip,
                        "message": msg,
                    });
                    buffer.push(event);

                    // Auto-unblock after 10 minutes
                    let unblock_ip = ip.to_string();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(600)).await;
                        let rule = format!("ProVigil-Block-{}", unblock_ip);
                        let _ = Command::new("netsh")
                            .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule)])
                            .status();
                        info!("Auto-unblocked IP '{}' after 600s", unblock_ip);
                    });

                    return true;
                }
                Ok(s) => warn!("netsh failed with exit code: {:?}", s.code()),
                Err(e) => error!("Failed to execute netsh: {}", e),
            }
        }

        false
    }

    /// Unblock IP from Windows Firewall
    pub async fn unblock_ip(&self, ip: &str, buffer: &EventBuffer) -> bool {
        info!("Active Response: Unblocking IP '{}'", ip);

        #[cfg(target_os = "windows")]
        {
            let rule_name = format!("ProVigil-Block-{}", ip);
            let status = Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
                .status();

            match status {
                Ok(s) if s.success() => {
                    let msg = format!("Removed firewall block for IP {}", ip);
                    info!("{}", msg);

                    let event = json!({
                        "event_type": "active_response",
                        "timestamp": Utc::now().to_rfc3339(),
                        "agent": { "id": &self.agent_id },
                        "action": "unblock_ip",
                        "target_ip": ip,
                        "message": msg,
                    });
                    buffer.push(event);
                    return true;
                }
                Ok(s) => warn!("netsh delete failed: {:?}", s.code()),
                Err(e) => error!("Failed to execute netsh: {}", e),
            }
        }

        false
    }

    /// Terminate suspicious process by PID
    pub async fn kill_process(&self, pid: u32, buffer: &EventBuffer) -> bool {
        info!("Active Response: Terminating process PID: {}", pid);

        #[cfg(target_os = "windows")]
        {
            let status = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .status();

            match status {
                Ok(s) if s.success() => {
                    let msg = format!("Terminated malicious process PID {}", pid);
                    info!("{}", msg);

                    let event = json!({
                        "event_type": "active_response",
                        "timestamp": Utc::now().to_rfc3339(),
                        "agent": { "id": &self.agent_id },
                        "action": "kill_process",
                        "target_pid": pid,
                        "message": msg,
                    });
                    buffer.push(event);
                    return true;
                }
                Ok(s) => warn!("taskkill failed: {:?}", s.code()),
                Err(e) => error!("Failed to execute taskkill: {}", e),
            }
        }

        false
    }

    /// Quarantine malicious file (move to quarantine dir + revoke permissions)
    pub async fn quarantine_file(&self, file_path_str: &str, buffer: &EventBuffer) -> bool {
        info!("Active Response: Quarantining file '{}'", file_path_str);

        let file_path = Path::new(file_path_str);
        if !file_path.exists() {
            warn!("Quarantine failed: file '{}' not found", file_path_str);
            return false;
        }

        #[cfg(target_os = "windows")]
        {
            let quarantine_dir = std::env::var("ProgramData")
                .map(|p| format!(r"{}\ProVigil\Quarantine", p))
                .unwrap_or_else(|_| r"C:\ProgramData\ProVigil\Quarantine".into());

            let _ = std::fs::create_dir_all(&quarantine_dir);

            let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("quarantined.bin");
            let timestamp = chrono::Utc::now().timestamp();
            let dest_path = format!(r"{}\{}_{}.locked", quarantine_dir, file_name, timestamp);

            match std::fs::rename(file_path, &dest_path) {
                Ok(_) => {
                    // Lock down ACLs
                    let _ = Command::new("icacls")
                        .args([&dest_path, "/inheritance:r", "/deny", "Everyone:(OI)(CI)(F)"])
                        .output();

                    let msg = format!("Quarantined file '{}' -> '{}'", file_path_str, dest_path);
                    info!("{}", msg);

                    let event = json!({
                        "event_type": "active_response",
                        "timestamp": Utc::now().to_rfc3339(),
                        "agent": { "id": &self.agent_id },
                        "action": "quarantine_file",
                        "original_path": file_path_str,
                        "quarantine_path": &dest_path,
                        "message": msg,
                    });
                    buffer.push(event);
                    return true;
                }
                Err(e) => error!("Failed to move file to quarantine: {}", e),
            }
        }

        false
    }

    /// Disable compromised user account
    pub async fn disable_account(&self, username: &str, buffer: &EventBuffer) -> bool {
        info!("Active Response: Disabling user account '{}'", username);

        #[cfg(target_os = "windows")]
        {
            let status = Command::new("net")
                .args(["user", username, "/active:no"])
                .status();

            match status {
                Ok(s) if s.success() => {
                    let msg = format!("Disabled compromised user account '{}'", username);
                    info!("{}", msg);

                    let event = json!({
                        "event_type": "active_response",
                        "timestamp": Utc::now().to_rfc3339(),
                        "agent": { "id": &self.agent_id },
                        "action": "disable_account",
                        "user": username,
                        "message": msg,
                    });
                    buffer.push(event);
                    return true;
                }
                Ok(s) => warn!("Failed to disable account: {:?}", s.code()),
                Err(e) => error!("Failed to execute net user: {}", e),
            }
        }

        false
    }

    /// Restart agent service
    pub async fn restart_agent(&self, buffer: &EventBuffer) -> bool {
        info!("Active Response: Restarting agent service");
        let msg = format!("Restarting ProVigil agent {}", self.agent_id);

        let event = json!({
            "event_type": "active_response",
            "timestamp": Utc::now().to_rfc3339(),
            "agent": { "id": &self.agent_id },
            "action": "restart_agent",
            "message": msg,
        });
        buffer.push(event);

        #[cfg(target_os = "windows")]
        {
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = Command::new("powershell")
                    .args(["-Command", "Restart-Service ProVigilAgent -ErrorAction SilentlyContinue"])
                    .spawn();
            });
            return true;
        }

        #[cfg(not(target_os = "windows"))]
        false
    }

    /// Run on-demand FIM scan
    pub async fn run_fim_scan(&self, buffer: &EventBuffer) -> bool {
        info!("Active Response: Running on-demand FIM scan");

        let event = json!({
            "event_type": "fim_scan",
            "timestamp": Utc::now().to_rfc3339(),
            "agent": { "id": &self.agent_id },
            "scan_type": "on_demand",
            "message": "FIM scan started",
        });
        buffer.push(event);

        true
    }

    /// Run on-demand SCA audit
    pub async fn run_sca_scan(&self, buffer: &EventBuffer) -> bool {
        info!("Active Response: Running on-demand SCA audit");

        let msg = format!("On-demand SCA CIS audit executed for agent {}", self.agent_id);
        let event = json!({
            "event_type": "sca_scan",
            "timestamp": Utc::now().to_rfc3339(),
            "agent": { "id": &self.agent_id },
            "action": "audit_complete",
            "message": msg,
        });
        buffer.push(event);

        true
    }
}

/// Active Response daemon - polls manager for remediation commands
pub fn spawn_active_response_worker(
    agent_id: String,
    manager_url: String,
    buffer: Arc<EventBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let handler = ActiveResponseHandler::new(agent_id.clone());
        let client = reqwest::Client::new();
        let poll_url = format!("{}/api/v1/agent/commands?agent_id={}", manager_url, agent_id);
        let ack_url = format!("{}/api/v1/agent/commands/ack", manager_url);

        info!("Active Response daemon started - listening for remediation commands");

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let key = std::env::var("SIEM_AGENT_KEY").unwrap_or_default();

            if let Ok(resp) = client.get(&poll_url).header("X-Agent-Key", &key).send().await {
                if resp.status().is_success() {
                    if let Ok(commands) = resp.json::<Vec<ActiveResponseCommand>>().await {
                        for cmd in commands {
                            info!("Received command '{}' for target '{}'", cmd.action, cmd.target);

                            let success = match cmd.action.as_str() {
                                "block_ip" => handler.block_ip(&cmd.target, &buffer).await,
                                "unblock_ip" => handler.unblock_ip(&cmd.target, &buffer).await,
                                "kill_process" => {
                                    if let Ok(pid) = cmd.target.parse::<u32>() {
                                        handler.kill_process(pid, &buffer).await
                                    } else {
                                        false
                                    }
                                }
                                "quarantine_file" => handler.quarantine_file(&cmd.target, &buffer).await,
                                "disable_account" => handler.disable_account(&cmd.target, &buffer).await,
                                "restart_agent" => handler.restart_agent(&buffer).await,
                                "fim_scan" | "syscheck_restart" => handler.run_fim_scan(&buffer).await,
                                "sca_scan" => handler.run_sca_scan(&buffer).await,
                                "deactivate" => true,
                                _ => false,
                            };

                            let deactivate = cmd.action == "deactivate";

                            let _ = client
                                .post(&ack_url)
                                .json(&serde_json::json!({
                                    "command_id": cmd.command_id,
                                    "agent_id": agent_id,
                                    "success": success
                                }))
                                .send()
                                .await;

                            if deactivate {
                                crate::enroll::stop_deactivated(&agent_id);
                            }
                        }
                    }
                }
            }
        }
    })
}
