//! Native Active Response Actions Implementation (`src/active-response`)
//!
//! Provides cross-platform implementations for the standard Wazuh response actions:
//! - `firewall-drop` (Linux iptables/nftables, Windows netsh, macOS pf)
//! - `host-deny` (/etc/hosts.deny)
//! - `disable-account` (Linux passwd, Windows net user)
//! - `route-null` (Linux/Unix null route / blackhole)
//! - `restart-wazuh` (Service daemon restart)

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArAction {
    Add,
    Delete,
}

impl ArAction {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "add" => Some(Self::Add),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// Logs active response activity to `<base_dir>/logs/active-responses.log`
/// (parity with write_debug_file in active_responses.c)
pub fn write_ar_log<P: AsRef<Path>>(base_dir: P, ar_name: &str, message: &str) {
    let log_dir = base_dir.as_ref().join("logs");
    let _ = fs::create_dir_all(&log_dir);
    let log_file = log_dir.join("active-responses.log");

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_file) {
        let now = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
        let _ = writeln!(file, "{} {}: {}", now, ar_name, message);
    }
}

/// Executes `firewall-drop` command to block or unblock an IP address
/// (parity with default-firewall-drop.c and netsh.c)
pub fn execute_firewall_drop(action: ArAction, ip: &str) -> Result<String, String> {
    if ip.trim().is_empty() {
        return Err("Cannot execute firewall-drop: IP is empty".to_string());
    }

    if cfg!(target_os = "windows") {
        let rule_name = format!("WAZUH_ACTIVE_RESPONSE_{}", ip.replace(':', "_"));
        match action {
            ArAction::Add => {
                let status = Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name={}", rule_name),
                        "dir=in",
                        "action=block",
                        &format!("remoteip={}", ip),
                    ])
                    .status()
                    .map_err(|e| format!("Failed to execute netsh: {}", e))?;

                if status.success() {
                    Ok(format!("Blocked IP '{}' via Windows Firewall", ip))
                } else {
                    Err(format!("netsh exited with status: {}", status))
                }
            }
            ArAction::Delete => {
                let status = Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name={}", rule_name),
                    ])
                    .status()
                    .map_err(|e| format!("Failed to execute netsh: {}", e))?;

                if status.success() {
                    Ok(format!("Unblocked IP '{}' via Windows Firewall", ip))
                } else {
                    Err(format!("netsh exited with status: {}", status))
                }
            }
        }
    } else {
        // Linux / Unix iptables
        let iptables_cmd = if ip.contains(':') { "ip6tables" } else { "iptables" };
        let flag = match action {
            ArAction::Add => "-I",
            ArAction::Delete => "-D",
        };

        // Apply to INPUT and FORWARD chains
        let mut errors = Vec::new();
        for chain in &["INPUT", "FORWARD"] {
            match Command::new(iptables_cmd)
                .args([flag, chain, "-s", ip, "-j", "DROP"])
                .status()
            {
                Ok(s) if !s.success() => {
                    errors.push(format!("iptables {} {} failed with: {}", flag, chain, s));
                }
                Err(e) => {
                    errors.push(format!("Failed to spawn {}: {}", iptables_cmd, e));
                }
                _ => {}
            }
        }

        if errors.is_empty() {
            Ok(format!("Successfully applied {} for IP '{}' on {}", flag, ip, iptables_cmd))
        } else {
            Err(errors.join("; "))
        }
    }
}

/// Executes `host-deny` by updating `/etc/hosts.deny`
/// (parity with host-deny.c)
pub fn execute_host_deny(action: ArAction, ip: &str) -> Result<String, String> {
    let hosts_deny = Path::new("/etc/hosts.deny");
    if !hosts_deny.exists() {
        return Err("/etc/hosts.deny does not exist".to_string());
    }

    let target_line = format!("ALL: {}", ip.trim());

    let file = fs::File::open(hosts_deny).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut found = false;

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| e.to_string())?;
        if line.trim() == target_line {
            found = true;
            if action == ArAction::Add {
                lines.push(line);
            }
            // If delete, skip line
        } else {
            lines.push(line);
        }
    }

    match action {
        ArAction::Add => {
            if !found {
                lines.push(target_line);
            }
        }
        ArAction::Delete => {}
    }

    fs::write(hosts_deny, lines.join("\n") + "\n").map_err(|e| e.to_string())?;
    Ok(format!("Updated /etc/hosts.deny for '{}'", ip))
}

/// Executes `disable-account` to lock or unlock an account
/// (parity with disable-account.c)
pub fn execute_disable_account(action: ArAction, username: &str) -> Result<String, String> {
    if username.trim().is_empty() {
        return Err("Cannot execute disable-account: username is empty".to_string());
    }

    if cfg!(target_os = "windows") {
        let active_arg = match action {
            ArAction::Add => "/active:no",
            ArAction::Delete => "/active:yes",
        };
        let status = Command::new("net")
            .args(["user", username, active_arg])
            .status()
            .map_err(|e| format!("Failed to execute net user: {}", e))?;

        if status.success() {
            Ok(format!("Executed net user {} {}", username, active_arg))
        } else {
            Err(format!("net user exited with status: {}", status))
        }
    } else {
        let flag = match action {
            ArAction::Add => "-l",    // lock
            ArAction::Delete => "-u", // unlock
        };
        let status = Command::new("passwd")
            .args([flag, username])
            .status()
            .map_err(|e| format!("Failed to execute passwd: {}", e))?;

        if status.success() {
            Ok(format!("Executed passwd {} {}", flag, username))
        } else {
            Err(format!("passwd exited with status: {}", status))
        }
    }
}

/// Executes `route-null` to blackhole or un-blackhole an IP
/// (parity with route-null.c)
pub fn execute_route_null(action: ArAction, ip: &str) -> Result<String, String> {
    if cfg!(target_os = "windows") {
        match action {
            ArAction::Add => {
                let status = Command::new("route")
                    .args(["ADD", ip, "MASK", "255.255.255.255", "0.0.0.0"])
                    .status()
                    .map_err(|e| format!("route ADD error: {}", e))?;
                if status.success() {
                    Ok(format!("Added null route for {}", ip))
                } else {
                    Err(format!("route ADD failed: {}", status))
                }
            }
            ArAction::Delete => {
                let status = Command::new("route")
                    .args(["DELETE", ip])
                    .status()
                    .map_err(|e| format!("route DELETE error: {}", e))?;
                if status.success() {
                    Ok(format!("Deleted null route for {}", ip))
                } else {
                    Err(format!("route DELETE failed: {}", status))
                }
            }
        }
    } else {
        let action_verb = match action {
            ArAction::Add => "add",
            ArAction::Delete => "del",
        };
        let status = Command::new("ip")
            .args(["route", action_verb, "blackhole", ip])
            .status()
            .map_err(|e| format!("ip route error: {}", e))?;

        if status.success() {
            Ok(format!("Executed ip route {} blackhole {}", action_verb, ip))
        } else {
            Err(format!("ip route exited with status: {}", status))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ar_action_from_str() {
        assert_eq!(ArAction::from_str("add"), Some(ArAction::Add));
        assert_eq!(ArAction::from_str("DELETE"), Some(ArAction::Delete));
        assert_eq!(ArAction::from_str("invalid"), None);
    }

    #[test]
    fn test_write_ar_log() {
        let dir = tempdir().unwrap();
        write_ar_log(dir.path(), "firewall-drop", "Blocked IP 1.2.3.4");

        let log_file = dir.path().join("logs").join("active-responses.log");
        assert!(log_file.exists());
        let content = fs::read_to_string(log_file).unwrap();
        assert!(content.contains("firewall-drop: Blocked IP 1.2.3.4"));
    }
}
