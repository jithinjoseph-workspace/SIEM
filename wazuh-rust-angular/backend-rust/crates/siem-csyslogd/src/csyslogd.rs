//! Main Syslog Forwarder Daemon runtime (`src/os_csyslogd/csyslogd.c`)
//!
//! Orchestrates alert reading, filtering, formatting, and forwarding across
//! all configured Syslog destinations.

use crate::config::SyslogConfig;
use crate::formatter::SyslogAlert;
use crate::sender::UdpSyslogSender;
use tracing::{debug, error, warn};

/// Main daemon engine for wazuh-csyslogd
pub struct SyslogDaemon {
    pub configs: Vec<SyslogConfig>,
    pub senders: Vec<UdpSyslogSender>,
    pub short_host: String,
    pub fqdn_host: String,
}

impl SyslogDaemon {
    /// Creates a new `SyslogDaemon` from configuration list.
    pub fn new(configs: Vec<SyslogConfig>) -> Self {
        let (short_host, fqdn_host) = detect_hostnames();
        let mut senders = Vec::new();

        for cfg in &configs {
            senders.push(UdpSyslogSender::new(cfg.server.clone(), cfg.port));
        }

        Self {
            configs,
            senders,
            short_host,
            fqdn_host,
        }
    }

    /// Initializes UDP sockets for all configured syslog destinations.
    pub fn init_senders(&mut self) {
        for (i, sender) in self.senders.iter_mut().enumerate() {
            if let Err(e) = sender.connect() {
                warn!(
                    "Failed to connect UDP socket to {}:{} (destination #{}): {}",
                    sender.server, sender.port, i, e
                );
            }
        }
    }

    /// Dispatches an alert to all matching syslog servers.
    /// Returns the number of successful transmissions.
    pub fn process_alert(&mut self, alert: &SyslogAlert) -> usize {
        let mut forwarded_count = 0;

        for (i, cfg) in self.configs.iter().enumerate() {
            if !alert.matches_filter(cfg) {
                debug!(
                    "Alert (rule {}) did not match filter for server {}:{}",
                    alert.rule, cfg.server, cfg.port
                );
                continue;
            }

            let formatted = alert.format_message(cfg, &self.short_host, &self.fqdn_host);

            if let Some(sender) = self.senders.get_mut(i) {
                match sender.send(&formatted) {
                    Ok(_) => {
                        forwarded_count += 1;
                        debug!(
                            "Forwarded alert (rule {}) to {}:{} via {:?}",
                            alert.rule, cfg.server, cfg.port, cfg.format
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to forward alert to {}:{}: {}",
                            cfg.server, cfg.port, e
                        );
                    }
                }
            }
        }

        forwarded_count
    }

    /// Parses a JSON alert (matching Wazuh `alerts.json` format) and forwards it.
    pub fn process_json_str(&mut self, json_str: &str) -> Result<usize, serde_json::Error> {
        let val: serde_json::Value = serde_json::from_str(json_str)?;
        let alert = parse_wazuh_json_alert(&val);
        Ok(self.process_alert(&alert))
    }
}

/// Parses a standard Wazuh `alerts.json` event into `SyslogAlert`.
pub fn parse_wazuh_json_alert(val: &serde_json::Value) -> SyslogAlert {
    let mut alert = SyslogAlert::default();
    alert.raw_json = Some(val.clone());

    // Timestamp
    if let Some(ts) = val.get("timestamp").and_then(|v| v.as_str()) {
        alert.date = Some(ts.to_string());
    }

    // Location
    if let Some(loc) = val.get("location").and_then(|v| v.as_str()) {
        alert.location = loc.to_string();
    }

    // Rule object
    if let Some(rule) = val.get("rule") {
        if let Some(lvl) = rule.get("level").and_then(|v| v.as_u64()) {
            alert.level = lvl as u32;
        }
        if let Some(id_str) = rule.get("id").and_then(|v| v.as_str()) {
            if let Ok(id) = id_str.parse::<u32>() {
                alert.rule = id;
            }
        } else if let Some(id) = rule.get("id").and_then(|v| v.as_u64()) {
            alert.rule = id as u32;
        }
        if let Some(desc) = rule.get("description").and_then(|v| v.as_str()) {
            alert.comment = desc.to_string();
        }
        if let Some(groups) = rule.get("groups").and_then(|v| v.as_array()) {
            let grp_strs: Vec<&str> = groups.iter().filter_map(|g| g.as_str()).collect();
            if !grp_strs.is_empty() {
                alert.group = Some(grp_strs.join(","));
            }
        }
    }

    // Agent object
    if let Some(agent) = val.get("agent") {
        if let Some(agent_name) = agent.get("name").and_then(|v| v.as_str()) {
            if !alert.location.contains("->") && !alert.location.is_empty() {
                alert.location = format!("{}->{}", agent_name, alert.location);
            }
        }
    }

    // Data object fields
    if let Some(data) = val.get("data") {
        if let Some(srcip) = data.get("srcip").and_then(|v| v.as_str()) {
            alert.srcip = Some(srcip.to_string());
        }
        if let Some(dstip) = data.get("dstip").and_then(|v| v.as_str()) {
            alert.dstip = Some(dstip.to_string());
        }
        if let Some(srcport) = data.get("srcport").and_then(|v| v.as_u64()) {
            alert.srcport = Some(srcport as u16);
        }
        if let Some(dstport) = data.get("dstport").and_then(|v| v.as_u64()) {
            alert.dstport = Some(dstport as u16);
        }
        if let Some(user) = data.get("dstuser").or_else(|| data.get("srcuser")).and_then(|v| v.as_str()) {
            alert.user = Some(user.to_string());
        }
    }

    // Full log
    if let Some(full_log) = val.get("full_log").and_then(|v| v.as_str()) {
        alert.log.push(full_log.to_string());
    }

    alert
}

/// Detects local system hostnames matching `main.c: gethostname()`.
pub fn detect_hostnames() -> (String, String) {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string());

    let fqdn_host = hostname.clone();
    let short_host = match hostname.find('.') {
        Some(idx) => hostname[..idx].to_string(),
        None => hostname,
    };

    (short_host, fqdn_host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyslogFormat;
    use std::net::UdpSocket;

    #[test]
    fn test_daemon_process_json_alert() {
        // Create local UDP mock receiver
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = receiver.local_addr().unwrap().port();

        let cfg = SyslogConfig {
            server: "127.0.0.1".to_string(),
            port,
            level: 3,
            format: SyslogFormat::Default,
            ..Default::default()
        };

        let mut daemon = SyslogDaemon::new(vec![cfg]);
        daemon.init_senders();

        let json_alert = r#"{
            "timestamp": "2026-07-10T12:00:00.000+0000",
            "rule": {
                "level": 5,
                "id": "5715",
                "description": "sshd authentication success",
                "groups": ["syslog", "sshd"]
            },
            "location": "/var/log/secure",
            "data": {
                "srcip": "10.0.0.10",
                "dstuser": "root"
            },
            "full_log": "Accepted publickey for root from 10.0.0.10 port 49202"
        }"#;

        let sent = daemon.process_json_str(json_alert).unwrap();
        assert_eq!(sent, 1);

        let mut buf = [0u8; 2048];
        let (bytes, _) = receiver.recv_from(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..bytes]);
        assert!(msg.contains("Rule: 5715 - sshd authentication success;"));
        assert!(msg.contains("srcip: 10.0.0.10;"));
        assert!(msg.contains("user: root;"));
    }
}
