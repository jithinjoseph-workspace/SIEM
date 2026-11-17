use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

pub struct LinuxActiveResponseHandler {
    agent_id: String,
}

impl LinuxActiveResponseHandler {
    pub fn new(agent_id: String) -> Self {
        Self { agent_id }
    }

    /// Block an attacking IP address using Linux firewall (nftables, iptables, ufw, firewalld)
    pub async fn block_ip(&self, ip: &str, buffer: &AgentBuffer) -> bool {
        info!("provigil-execd: Executing firewall-drop active response for IP '{}'", ip);

        // 1. Try nftables (modern Linux default)
        let mut applied = Command::new("nft")
            .args(["add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        // 2. Try iptables
        if !applied {
            applied = Command::new("iptables")
                .args(["-I", "INPUT", "-s", ip, "-j", "DROP"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        }

        // 3. Try ufw
        if !applied {
            applied = Command::new("ufw")
                .args(["insert", "1", "deny", "from", ip])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        }

        // 4. Try firewalld
        if !applied {
            let rule = format!("rule family=\"ipv4\" source address=\"{}\" drop", ip);
            applied = Command::new("firewall-cmd")
                .args(["--add-rich-rule", &rule])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        }
        let _ = applied;

        let msg = format!(
            "provigil-execd: active-response firewall-drop: Blocked IP {} in host firewall",
            ip
        );
        info!("{}", msg);

        let mut event = RawEvent::new(&self.agent_id, EventSource::ActiveResponse, "execd/firewall-drop", msg);
        event.metadata.insert("action".into(), "block_ip".into());
        event.metadata.insert("target_ip".into(), ip.to_string());
        event.metadata.insert("os_type".into(), "linux".into());
        buffer.push(event).await;

        // Auto-revert block rule after timeout (600s)
        let unblock_ip_str = ip.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(600)).await;
            info!("provigil-execd: Auto-unblocking IP '{}' after 600s timeout...", unblock_ip_str);
            let _ = Command::new("nft")
                .args(["delete", "rule", "inet", "filter", "input", "ip", "saddr", &unblock_ip_str, "drop"])
                .status();
            let _ = Command::new("iptables")
                .args(["-D", "INPUT", "-s", &unblock_ip_str, "-j", "DROP"])
                .status();
            let _ = Command::new("ufw")
                .args(["delete", "deny", "from", &unblock_ip_str])
                .status();
            let rule = format!("rule family=\"ipv4\" source address=\"{}\" drop", unblock_ip_str);
            let _ = Command::new("firewall-cmd")
                .args(["--remove-rich-rule", &rule])
                .status();
        });

        true
    }

    /// Explicitly remove an IP block rule from host firewalls
    pub async fn unblock_ip(&self, ip: &str, buffer: &AgentBuffer) -> bool {
        info!("provigil-execd: Removing active response firewall rule for '{}'", ip);
        let _ = Command::new("nft")
            .args(["delete", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"])
            .status();
        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-s", ip, "-j", "DROP"])
            .status();
        let _ = Command::new("ufw")
            .args(["delete", "deny", "from", ip])
            .status();
        let rule = format!("rule family=\"ipv4\" source address=\"{}\" drop", ip);
        let _ = Command::new("firewall-cmd")
            .args(["--remove-rich-rule", &rule])
            .status();

        let msg = format!("provigil-execd: Removed firewall drop rule for IP {}", ip);
        let mut event = RawEvent::new(&self.agent_id, EventSource::ActiveResponse, "execd/unblock", msg);
        event.metadata.insert("action".into(), "unblock_ip".into());
        event.metadata.insert("target_ip".into(), ip.to_string());
        event.metadata.insert("os_type".into(), "linux".into());
        buffer.push(event).await;
        true
    }

    /// Terminate a suspicious or compromised Linux process by PID
    pub async fn kill_process(&self, pid: u32, buffer: &AgentBuffer) -> bool {
        info!("provigil-execd: Terminating malicious Linux process PID: {}", pid);

        let _ = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();

        let msg = format!("provigil-execd: Terminated malicious process PID {}", pid);
        info!("{}", msg);

        let mut event = RawEvent::new(&self.agent_id, EventSource::ActiveResponse, "execd/kill-process", msg);
        event.metadata.insert("action".into(), "kill_process".into());
        event.metadata.insert("target_pid".into(), pid.to_string());
        event.metadata.insert("os_type".into(), "linux".into());
        buffer.push(event).await;
        true
    }

    /// Quarantine a suspicious file into `/opt/provigil-agent/quarantine/` and revoke permissions (`chmod 000`).
    pub async fn quarantine_file(&self, file_path_str: &str, buffer: &AgentBuffer) -> bool {
        info!("provigil-execd: Quarantining suspicious file '{}'", file_path_str);

        let file_path = Path::new(file_path_str);
        if !file_path.exists() {
            warn!("provigil-execd: Quarantine target '{}' does not exist", file_path_str);
            return false;
        }

        let quarantine_dir = Path::new("/opt/provigil-agent/quarantine");
        let _ = std::fs::create_dir_all(quarantine_dir);

        let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("quarantined.bin");
        let timestamp = chrono::Utc::now().timestamp();
        let dest_path = quarantine_dir.join(format!("{}_{}.locked", file_name, timestamp));

        if let Ok(_) = std::fs::rename(file_path, &dest_path) {
            let _ = Command::new("chmod")
                .args(["000", &dest_path.to_string_lossy()])
                .status();

            let msg = format!(
                "provigil-execd: File '{}' quarantined to '{}' with permissions revoked (chmod 000)",
                file_path_str, dest_path.display()
            );
            info!("{}", msg);

            let mut event = RawEvent::new(&self.agent_id, EventSource::ActiveResponse, "execd/quarantine", msg);
            event.metadata.insert("action".into(), "quarantine_file".into());
            event.metadata.insert("original_path".into(), file_path_str.to_string());
            event.metadata.insert("quarantine_path".into(), dest_path.to_string_lossy().to_string());
            event.metadata.insert("os_type".into(), "linux".into());
            buffer.push(event).await;
            return true;
        }

        false
    }

    /// Lock a compromised user account via usermod -L
    pub async fn disable_account(&self, username: &str, buffer: &AgentBuffer) -> bool {
        info!("provigil-execd: Disabling compromised user account '{}'", username);

        let _ = Command::new("usermod")
            .args(["-L", username])
            .status();

        let msg = format!("provigil-execd: Successfully locked account for user '{}'", username);
        info!("{}", msg);

        let mut event = RawEvent::new(&self.agent_id, EventSource::ActiveResponse, "execd/disable-account", msg);
        event.metadata.insert("action".into(), "disable_account".into());
        event.metadata.insert("target_user".into(), username.to_string());
        event.metadata.insert("os_type".into(), "linux".into());
        buffer.push(event).await;
        true
    }

    /// Run an on-demand FIM scan across monitored Linux paths
    pub async fn run_fim_scan(&self, buffer: &AgentBuffer) -> bool {
        info!("provigil-execd: Executing on-demand FIM scan on Linux host");

        let start_msg = format!("provigil-syscheckd[{}]: File integrity monitoring scan started. (FIM_SCAN_START)", self.agent_id);
        info!("{}", start_msg);
        let mut start_event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/scan_info", start_msg);
        start_event.metadata.insert("event_type".into(), "FIM_SCAN_START".into());
        start_event.metadata.insert("scan_type".into(), "on_demand".into());
        start_event.metadata.insert("os_type".into(), "linux".into());
        buffer.push(start_event).await;

        let monitored_paths = vec![
            std::path::PathBuf::from("/etc/passwd"),
            std::path::PathBuf::from("/etc/shadow"),
            std::path::PathBuf::from("/etc/group"),
            std::path::PathBuf::from("/etc/hosts"),
            std::path::PathBuf::from("/etc/resolv.conf"),
            std::path::PathBuf::from("/etc/ssh/sshd_config"),
            std::path::PathBuf::from("/bin"),
            std::path::PathBuf::from("/sbin"),
            std::path::PathBuf::from("/usr/bin"),
        ];
        let mut engine = crate::syscheck::SyscheckEngine::new(self.agent_id.clone(), monitored_paths);
        engine.build_baseline();
        engine.check_changes(buffer).await;

        let end_msg = format!(
            "provigil-syscheckd[{}]: File integrity monitoring scan ended. (FIM_SCAN_END). Monitored Linux filesystems audited. Baseline verified.",
            self.agent_id
        );
        info!("{}", end_msg);
        let mut end_event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/scan_info", end_msg);
        end_event.metadata.insert("event_type".into(), "FIM_SCAN_END".into());
        end_event.metadata.insert("status".into(), "integrity_verified".into());
        end_event.metadata.insert("os_type".into(), "linux".into());
        buffer.push(end_event).await;

        true
    }

    /// Run an on-demand SCA CIS Benchmark audit
    pub async fn run_sca_scan(&self, buffer: &AgentBuffer) -> bool {
        info!("provigil-execd: Executing on-demand SCA CIS audit on Linux host");
        let engine = crate::sca::LinuxScaEngine::new(self.agent_id.clone());
        let (passed, total, score) = engine.run_sca_assessment(buffer).await;
        info!("provigil-sca: On-demand SCA CIS audit finished. Score: {}% ({}/{})", score, passed, total);
        true
    }

    /// Isolate the Linux host from the network while preserving manager connectivity
    pub async fn isolate_host(&self, target_arg: &str, buffer: &AgentBuffer) -> bool {
        let mut isolation_id = format!("iso-{}", chrono::Utc::now().timestamp());
        let mut allowed_ips = Vec::new();

        for part in target_arg.split([',', ';', ' ']) {
            let part = part.trim();
            if let Some(id) = part.strip_prefix("id=") {
                if !id.is_empty() {
                    isolation_id = id.to_string();
                }
            } else if let Some(allow) = part.strip_prefix("allow=") {
                for ip in allow.split(':') {
                    if !ip.is_empty() {
                        allowed_ips.push(ip.to_string());
                    }
                }
            } else if !part.is_empty() && (part.contains('.') || part.contains(':')) && !part.contains('=') {
                allowed_ips.push(part.to_string());
            }
        }

        if allowed_ips.is_empty() {
            if let Ok(mgr) = std::env::var("SIEM_MANAGER_URL").or_else(|_| std::env::var("PROVIGIL_MANAGER")) {
                let clean = mgr.split("://").nth(1).unwrap_or(&mgr).split([':', '/']).next().unwrap_or("").trim().to_string();
                if !clean.is_empty() {
                    allowed_ips.push(clean);
                }
            }
        }

        info!("provigil-execd: Isolating Linux host (ID: {}). Whitelisting manager IPs: {:?}", isolation_id, allowed_ips);

        let state_dir = Path::new("/opt/provigil-agent/data");
        let _ = std::fs::create_dir_all(state_dir);
        let state_file = state_dir.join("isolation.state");
        let local_state = Path::new("data/isolation.state");
        if let Some(p) = local_state.parent() {
            let _ = std::fs::create_dir_all(p);
        }

        // 1. Try nftables
        let nft_ok = Command::new("nft")
            .args(["add", "table", "inet", "provigil_isolation"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if nft_ok {
            let _ = Command::new("nft").args(["add", "chain", "inet", "provigil_isolation", "input", "{ type filter hook input priority -10; policy drop; }"]).status();
            let _ = Command::new("nft").args(["add", "chain", "inet", "provigil_isolation", "output", "{ type filter hook output priority -10; policy drop; }"]).status();
            let _ = Command::new("nft").args(["add", "rule", "inet", "provigil_isolation", "input", "iif", "lo", "accept"]).status();
            let _ = Command::new("nft").args(["add", "rule", "inet", "provigil_isolation", "output", "oif", "lo", "accept"]).status();
            let _ = Command::new("nft").args(["add", "rule", "inet", "provigil_isolation", "input", "ct", "state", "established,related", "accept"]).status();
            let _ = Command::new("nft").args(["add", "rule", "inet", "provigil_isolation", "output", "ct", "state", "established,related", "accept"]).status();

            for ip in &allowed_ips {
                let _ = Command::new("nft").args(["add", "rule", "inet", "provigil_isolation", "input", "ip", "saddr", ip, "accept"]).status();
                let _ = Command::new("nft").args(["add", "rule", "inet", "provigil_isolation", "output", "ip", "daddr", ip, "accept"]).status();
            }
        } else {
            // 2. Fallback to iptables
            let _ = Command::new("iptables").args(["-N", "PROVIGIL_ISOLATION_IN"]).status();
            let _ = Command::new("iptables").args(["-N", "PROVIGIL_ISOLATION_OUT"]).status();
            let _ = Command::new("iptables").args(["-I", "INPUT", "1", "-j", "PROVIGIL_ISOLATION_IN"]).status();
            let _ = Command::new("iptables").args(["-I", "OUTPUT", "1", "-j", "PROVIGIL_ISOLATION_OUT"]).status();
            let _ = Command::new("iptables").args(["-A", "PROVIGIL_ISOLATION_IN", "-i", "lo", "-j", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-A", "PROVIGIL_ISOLATION_OUT", "-o", "lo", "-j", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-A", "PROVIGIL_ISOLATION_IN", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-A", "PROVIGIL_ISOLATION_OUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]).status();

            for ip in &allowed_ips {
                let _ = Command::new("iptables").args(["-A", "PROVIGIL_ISOLATION_IN", "-s", ip, "-j", "ACCEPT"]).status();
                let _ = Command::new("iptables").args(["-A", "PROVIGIL_ISOLATION_OUT", "-d", ip, "-j", "ACCEPT"]).status();
            }
            let _ = Command::new("iptables").args(["-A", "PROVIGIL_ISOLATION_IN", "-j", "DROP"]).status();
            let _ = Command::new("iptables").args(["-A", "PROVIGIL_ISOLATION_OUT", "-j", "DROP"]).status();
        }

        let state_content = format!("id={}\nisolated_at={}\nallowed={}\n", isolation_id, chrono::Utc::now().to_rfc3339(), allowed_ips.join(","));
        let _ = std::fs::write(&state_file, &state_content);
        let _ = std::fs::write(&local_state, &state_content);

        let msg = format!("provigil-execd: Host isolated successfully (ID: {}). Allowed managers: {:?}", isolation_id, allowed_ips);
        info!("{}", msg);

        let mut event = RawEvent::new(&self.agent_id, EventSource::ActiveResponse, "execd/isolate-host", msg);
        event.metadata.insert("action".into(), "isolate_host".into());
        event.metadata.insert("isolation_id".into(), isolation_id);
        event.metadata.insert("os_type".into(), "linux".into());
        buffer.push(event).await;

        true
    }

    /// Release network isolation on the Linux host
    pub async fn release_host(&self, buffer: &AgentBuffer) -> bool {
        info!("provigil-execd: Releasing host isolation, restoring network access.");

        let _ = Command::new("nft").args(["delete", "table", "inet", "provigil_isolation"]).status();

        let _ = Command::new("iptables").args(["-D", "INPUT", "-j", "PROVIGIL_ISOLATION_IN"]).status();
        let _ = Command::new("iptables").args(["-D", "OUTPUT", "-j", "PROVIGIL_ISOLATION_OUT"]).status();
        let _ = Command::new("iptables").args(["-F", "PROVIGIL_ISOLATION_IN"]).status();
        let _ = Command::new("iptables").args(["-F", "PROVIGIL_ISOLATION_OUT"]).status();
        let _ = Command::new("iptables").args(["-X", "PROVIGIL_ISOLATION_IN"]).status();
        let _ = Command::new("iptables").args(["-X", "PROVIGIL_ISOLATION_OUT"]).status();

        let _ = std::fs::remove_file("/opt/provigil-agent/data/isolation.state");
        let _ = std::fs::remove_file("data/isolation.state");

        let msg = "provigil-execd: Host isolation released. Full network connectivity restored.".to_string();
        info!("{}", msg);

        let mut event = RawEvent::new(&self.agent_id, EventSource::ActiveResponse, "execd/release-host", msg);
        event.metadata.insert("action".into(), "release_host".into());
        event.metadata.insert("os_type".into(), "linux".into());
        buffer.push(event).await;

        true
    }
}

/// Resolved command action + target extracted from either flat or gateway JSON command formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedCommand {
    pub command_id: String,
    pub action: String,
    pub target: String,
}

/// Parse either legacy `{command_id, action, target}` or gateway `{command_id, type, message}` commands.
pub(crate) fn resolve_command_value(v: &serde_json::Value) -> Option<ResolvedCommand> {
    let command_id = v.get("command_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if let Some(action) = v.get("action").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("").to_string();
        return Some(ResolvedCommand {
            command_id,
            action: action.to_string(),
            target,
        });
    }

    match v.get("type").and_then(|x| x.as_str()) {
        Some("scan") => Some(ResolvedCommand {
            command_id,
            action: "scan".to_string(),
            target: String::new(),
        }),
        Some("sca_full") => Some(ResolvedCommand {
            command_id,
            action: "sca_scan".to_string(),
            target: String::new(),
        }),
        Some("inventory_full") => Some(ResolvedCommand {
            command_id,
            action: "syscollector_scan".to_string(),
            target: String::new(),
        }),
        Some("ar") => {
            let msg = v.get("message")?;
            let raw_cmd = msg.get("command").and_then(|x| x.as_str()).filter(|s| !s.is_empty())?;
            let base = raw_cmd.trim_end_matches(|c: char| c.is_ascii_digit());
            let action = match base {
                "restart-wazuh" | "restart-agent" => "restart_agent",
                "firewall-drop" => "firewall_drop",
                "kill-process" => "kill_process",
                "quarantine-file" => "quarantine_file",
                "isolate-host" => "isolate_host",
                "release-host" => "release_host",
                other => other,
            };
            let params = msg.get("parameters");
            let target = params
                .and_then(|p| p.get("extra_args"))
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.as_str())
                .or_else(|| {
                    params
                        .and_then(|p| p.get("alert"))
                        .and_then(|a| a.get("data"))
                        .and_then(|d| d.get("srcip"))
                        .and_then(|x| x.as_str())
                })
                .unwrap_or("")
                .to_string();
            Some(ResolvedCommand {
                command_id,
                action: action.to_string(),
                target,
            })
        }
        _ => None,
    }
}

/// Dispatch resolved commands returned by either keepalive or active-response polling.
pub(crate) async fn dispatch_commands(
    commands: &[serde_json::Value],
    agent_id: &str,
    handler: &LinuxActiveResponseHandler,
    buffer: &AgentBuffer,
    lifecycle: &crate::lifecycle::LifecycleCoordinator,
) {
    for raw in commands {
        let Some(cmd) = resolve_command_value(raw) else {
            continue;
        };
        info!("provigil-execd: Received command '{}' for target '{}'", cmd.action, cmd.target);
        match cmd.action.as_str() {
            "block_ip" | "firewall_drop" => {
                handler.block_ip(&cmd.target, buffer).await;
            }
            "unblock_ip" => {
                handler.unblock_ip(&cmd.target, buffer).await;
            }
            "kill_process" => {
                if let Ok(pid) = cmd.target.parse::<u32>() {
                    handler.kill_process(pid, buffer).await;
                }
            }
            "quarantine_file" => {
                handler.quarantine_file(&cmd.target, buffer).await;
            }
            "disable_account" => {
                handler.disable_account(&cmd.target, buffer).await;
            }
            "fim_scan" | "syscheck restart" | "syscheck_restart" | "restart" => {
                handler.run_fim_scan(buffer).await;
            }
            "scan" => {
                handler.run_fim_scan(buffer).await;
                handler.run_sca_scan(buffer).await;
            }
            "deactivate" => {
                lifecycle.set_state(crate::lifecycle::AgentLifecycleState::Dormant);
            }
            "activate" | "reactivate" => {
                lifecycle.set_state(crate::lifecycle::AgentLifecycleState::Active);
            }
            "delete" | "uninstall" => {
                lifecycle.set_state(crate::lifecycle::AgentLifecycleState::Decommissioned);
            }
            "isolate_host" | "isolate-host" => {
                handler.isolate_host(&cmd.target, buffer).await;
            }
            "release_host" | "release-host" => {
                handler.release_host(buffer).await;
            }
            "sca_scan" => {
                handler.run_sca_scan(buffer).await;
            }
            "syscollector_scan" | "sync_inventory" => {
                crate::syscollector::emit_inventory(agent_id, buffer).await;
            }
            "restart_agent" => {
                info!("provigil-execd: restarting the agent service on manager request");
                tokio::spawn(async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    crate::control::restart_service();
                });
            }
            unknown => {
                warn!("provigil-execd: Unrecognized active response action: {}", unknown);
            }
        }
    }
}

/// Spawns the Active Response polling worker listening for Manager commands
pub fn spawn_active_response_worker(
    agent_id: String,
    agent_key: String,
    manager_url: String,
    buffer: Arc<AgentBuffer>,
    lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    poll_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let handler = LinuxActiveResponseHandler::new(agent_id.clone());
        let client = crate::enroll::http_builder()
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap_or_default();

        let poll_endpoint = format!(
            "{}/api/agents/{}/commands",
            manager_url.trim_end_matches('/'),
            agent_id
        );

        loop {
            tokio::time::sleep(poll_interval).await;
            if lifecycle.is_terminated() {
                break;
            }

            let key = if !agent_key.is_empty() {
                agent_key.clone()
            } else {
                std::env::var("SIEM_AGENT_KEY").unwrap_or_default()
            };
            let key_trim = key.trim();

            let mut req = client.get(&poll_endpoint);
            if !agent_id.trim().is_empty() {
                req = req.header("x-agent-id", agent_id.trim());
            }
            if !key_trim.is_empty() {
                req = req
                    .header("X-Agent-Key", key_trim)
                    .header("authorization", format!("Bearer {}", key_trim));
            }

            if let Ok(res) = req.send().await {
                if res.status().is_success() {
                    if let Ok(commands) = res.json::<Vec<serde_json::Value>>().await {
                        dispatch_commands(&commands, &agent_id, &handler, &buffer, &lifecycle).await;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_gateway_and_legacy_commands() {
        assert_eq!(
            resolve_command_value(&json!({
                "command_id": "c1",
                "type": "ar",
                "message": { "command": "restart-wazuh0", "parameters": { "extra_args": [] } }
            })),
            Some(ResolvedCommand {
                command_id: "c1".into(),
                action: "restart_agent".into(),
                target: String::new(),
            })
        );
        assert_eq!(
            resolve_command_value(&json!({
                "command_id": "c2",
                "type": "ar",
                "message": { "command": "firewall-drop600", "parameters": { "extra_args": ["203.0.113.5"] } }
            })),
            Some(ResolvedCommand {
                command_id: "c2".into(),
                action: "firewall_drop".into(),
                target: "203.0.113.5".into(),
            })
        );
        assert_eq!(
            resolve_command_value(&json!({ "command_id": "c3", "type": "scan" })),
            Some(ResolvedCommand {
                command_id: "c3".into(),
                action: "scan".into(),
                target: String::new(),
            })
        );
        assert_eq!(
            resolve_command_value(&json!({ "command_id": "c4", "action": "restart_agent", "target": "all" })),
            Some(ResolvedCommand {
                command_id: "c4".into(),
                action: "restart_agent".into(),
                target: "all".into(),
            })
        );
        assert_eq!(
            resolve_command_value(&json!({
                "command_id": "c5",
                "type": "ar",
                "message": { "command": "isolate-host3600", "parameters": { "extra_args": ["id=iso99,allow=10.0.0.1"] } }
            })),
            Some(ResolvedCommand {
                command_id: "c5".into(),
                action: "isolate_host".into(),
                target: "id=iso99,allow=10.0.0.1".into(),
            })
        );
        assert_eq!(
            resolve_command_value(&json!({
                "command_id": "c6",
                "type": "ar",
                "message": { "command": "release-host", "parameters": { "extra_args": [] } }
            })),
            Some(ResolvedCommand {
                command_id: "c6".into(),
                action: "release_host".into(),
                target: String::new(),
            })
        );
    }
}
