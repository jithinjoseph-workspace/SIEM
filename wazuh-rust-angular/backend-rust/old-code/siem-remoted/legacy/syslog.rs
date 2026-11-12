//! Agentless Syslog Ingestion Listener (syslog.c, syslogtcp.c)
//!
//! Receives and parses RFC 3164 (BSD) and RFC 5424 syslog messages over UDP and TCP (port 514)
//! from firewalls, routers, switches, and agentless appliances.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static RFC3164_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^<(\d{1,3})>([A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+([^\s:]+)\s+([^:]+):\s*(.*)$")
        .unwrap()
});

static RFC5424_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[[^\]]*\]|-)\s*(.*)$")
        .unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyslogMessage {
    pub priority: u8,
    pub facility: u8,
    pub severity: u8,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub message: String,
}

impl SyslogMessage {
    /// Parse raw syslog message line (RFC 3164, RFC 5424, or fallback raw).
    pub fn parse(raw: &str) -> Self {
        let trimmed = raw.trim();

        // 1. Try RFC 5424
        if let Some(caps) = RFC5424_REGEX.captures(trimmed) {
            let pri: u8 = caps[1].parse().unwrap_or(13);
            let facility = pri >> 3;
            let severity = pri & 0x07;
            let ts = if &caps[2] != "-" { Some(caps[2].to_string()) } else { None };
            let host = if &caps[3] != "-" { Some(caps[3].to_string()) } else { None };
            let app = if &caps[4] != "-" { Some(caps[4].to_string()) } else { None };
            let msg = caps[7].to_string();

            return Self {
                priority: pri,
                facility,
                severity,
                timestamp: ts,
                hostname: host,
                app_name: app,
                message: msg,
            };
        }

        // 2. Try RFC 3164
        if let Some(caps) = RFC3164_REGEX.captures(trimmed) {
            let pri: u8 = caps[1].parse().unwrap_or(13);
            let facility = pri >> 3;
            let severity = pri & 0x07;
            let ts = Some(caps[2].to_string());
            let host = Some(caps[3].to_string());
            let app = Some(caps[4].to_string());
            let msg = caps[5].to_string();

            return Self {
                priority: pri,
                facility,
                severity,
                timestamp: ts,
                hostname: host,
                app_name: app,
                message: msg,
            };
        }

        // 3. Simple PRI prefix `<PRI>message`
        if trimmed.starts_with('<') {
            if let Some(end_pri) = trimmed.find('>') {
                if let Ok(pri) = trimmed[1..end_pri].parse::<u8>() {
                    let facility = pri >> 3;
                    let severity = pri & 0x07;
                    let msg = trimmed[end_pri + 1..].trim().to_string();
                    return Self {
                        priority: pri,
                        facility,
                        severity,
                        timestamp: None,
                        hostname: None,
                        app_name: None,
                        message: msg,
                    };
                }
            }
        }

        // 4. Raw fallback
        Self {
            priority: 13, // user.notice
            facility: 1,
            severity: 5,
            timestamp: None,
            hostname: None,
            app_name: None,
            message: trimmed.to_string(),
        }
    }
}
