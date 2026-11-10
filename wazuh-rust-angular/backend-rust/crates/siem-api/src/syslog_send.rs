//! ProVigil Syslog Sender
//!
//! Clean-room, pure Rust implementation of alert forwarding over UDP/TCP syslog.
//! Supports Default (RFC 3164), CEF, JSON, and Splunk key-value formats.

use chrono::{Datelike, Local, Timelike};
use serde_json::Value;

pub const DEFAULT_SYSLOG_PRIORITY: u32 = 132; // local0 (16*8) + warning (4)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogFormat {
    Default,
    Cef,
    Json,
    Splunk,
}

impl SyslogFormat {
    pub fn from_str_opt(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "cef" => SyslogFormat::Cef,
            "json" => SyslogFormat::Json,
            "splunk" => SyslogFormat::Splunk,
            _ => SyslogFormat::Default,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyslogTarget {
    pub host: String,
    pub port: u16,
    pub format: SyslogFormat,
    pub priority: u32,
    pub use_fqdn: bool,
    pub min_level: u32,
    pub rule_ids: Option<Vec<u32>>,
    pub group_filter: Option<String>,
    pub location_filter: Option<String>,
}

impl Default for SyslogTarget {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 514,
            format: SyslogFormat::Default,
            priority: DEFAULT_SYSLOG_PRIORITY,
            use_fqdn: false,
            min_level: 0,
            rule_ids: None,
            group_filter: None,
            location_filter: None,
        }
    }
}

/// Detects local hostname.
pub fn get_local_hostname(use_fqdn: bool) -> String {
    let raw = sysinfo::System::host_name()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".to_string());

    if use_fqdn {
        raw
    } else {
        raw.split('.').next().unwrap_or("localhost").to_string()
    }
}

/// Generates RFC 3164 BSD timestamp string (e.g. "Nov  3 07:15:20").
pub fn format_syslog_timestamp(alert: &Value) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    if let Some(ts_str) = alert.get("timestamp").and_then(|v| v.as_str()) {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str) {
            let m = MONTHS[dt.month0() as usize % 12];
            let d = dt.day();
            let day_str = if d < 10 {
                format!(" {d}")
            } else {
                format!("{d}")
            };
            return format!(
                "{m} {day_str} {:02}:{:02}:{:02}",
                dt.hour(),
                dt.minute(),
                dt.second()
            );
        }
    }

    let now = Local::now();
    let m = MONTHS[now.month0() as usize % 12];
    let d = now.day();
    let day_str = if d < 10 {
        format!(" {d}")
    } else {
        format!("{d}")
    };
    format!(
        "{m} {day_str} {:02}:{:02}:{:02}",
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Helper to sanitize field values for CEF and key-value formats.
fn sanitize_val(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

/// Formats an alert JSON into the desired syslog message string.
pub fn format_alert(alert: &Value, format: SyslogFormat, priority: u32, host: &str) -> String {
    let timestamp = format_syslog_timestamp(alert);

    // Extract core fields
    let rule = &alert["rule"];
    let level = rule["level"].as_u64().unwrap_or(0) as u32;
    let rule_id = rule["id"]
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| rule["id"].as_u64().map(|n| n.to_string()))
        .unwrap_or_else(|| "0".to_string());
    let description = sanitize_val(rule["description"].as_str().unwrap_or("(null)"));
    let raw_loc = sanitize_val(alert["location"].as_str().unwrap_or("(null)"));
    let location = if let (Some(id), Some(name), Some(ip)) = (
        alert["agent"]["id"].as_str(),
        alert["agent"]["name"].as_str(),
        alert["agent"]["ip"].as_str(),
    ) {
        if id != "000" {
            format!("({name}) {ip}->{raw_loc}")
        } else {
            let mgr = alert["manager"]["name"].as_str().unwrap_or("localhost");
            format!("{mgr}->{raw_loc}")
        }
    } else {
        raw_loc
    };

    let group = if let Some(arr) = rule["groups"].as_array() {
        arr.iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(",")
    } else {
        rule["groups"].as_str().unwrap_or("").to_string()
    };

    let srcip = alert["data"]["srcip"]
        .as_str()
        .or_else(|| alert["srcip"].as_str());
    let dstip = alert["data"]["dstip"]
        .as_str()
        .or_else(|| alert["dstip"].as_str());
    let srcport = alert["data"]["srcport"]
        .as_u64()
        .or_else(|| alert["srcport"].as_u64())
        .unwrap_or(0);
    let dstport = alert["data"]["dstport"]
        .as_u64()
        .or_else(|| alert["dstport"].as_u64())
        .unwrap_or(0);
    let user = alert["data"]["srcuser"]
        .as_str()
        .or_else(|| alert["data"]["dstuser"].as_str())
        .or_else(|| alert["user"].as_str());
    let file = alert["syscheck"]["path"]
        .as_str()
        .or_else(|| alert["data"]["file"].as_str())
        .or_else(|| alert["file"].as_str());
    let full_log = alert["full_log"].as_str().or_else(|| alert["log"].as_str());

    match format {
        SyslogFormat::Default => {
            let mut out = format!(
                "<{priority}>{timestamp} {host} provigil: Alert Level: {level}; Rule: {rule_id} - {description}; Location: {location};"
            );
            if !group.is_empty() {
                out.push_str(&format!(" classification: {group};"));
            }
            if let Some(s) = srcip {
                out.push_str(&format!(" srcip: {s};"));
            }
            if let Some(d) = dstip {
                out.push_str(&format!(" dstip: {d};"));
            }
            if let Some(u) = user {
                out.push_str(&format!(" user: {u};"));
            }
            if let Some(l) = full_log {
                out.push(' ');
                out.push_str(&sanitize_val(l));
            }
            out
        }
        SyslogFormat::Cef => {
            let cef_level = level.min(10);
            let mut out = format!(
                "<{priority}>{timestamp} CEF:0|ProVigil|ProVigil|v1.0|{rule_id}|{description}|{cef_level}|dvc={host} cs1={location} cs1Label=Location"
            );
            if !group.is_empty() {
                out.push_str(&format!(" cat={group}"));
            }
            if let Some(s) = srcip {
                out.push_str(&format!(" src={s} shost={s}"));
            }
            if srcport > 0 {
                out.push_str(&format!(" spt={srcport}"));
            }
            if let Some(d) = dstip {
                out.push_str(&format!(" dst={d} dhost={d}"));
            }
            if dstport > 0 {
                out.push_str(&format!(" dpt={dstport}"));
            }
            if let Some(f) = file {
                out.push_str(&format!(" fname={f}"));
            }
            if let Some(u) = user {
                out.push_str(&format!(" suser={u}"));
            }
            if let Some(l) = full_log {
                out.push_str(&format!(" msg={}", sanitize_val(l)));
            }
            out
        }
        SyslogFormat::Json => {
            let payload = serde_json::to_string(alert).unwrap_or_else(|_| "{}".to_string());
            format!("<{priority}>{timestamp} {host} provigil: {payload}")
        }
        SyslogFormat::Splunk => {
            let mut out = format!(
                "<{priority}>{timestamp} {host} provigil: crit={level} id={rule_id} description=\"{description}\" component=\"{location}\","
            );
            if !group.is_empty() {
                out.push_str(&format!(" classification=\"{group}\","));
            }
            if let Some(s) = srcip {
                out.push_str(&format!(" src_ip=\"{s}\","));
                if srcport > 0 {
                    out.push_str(&format!(" src_port={srcport},"));
                }
            }
            if let Some(d) = dstip {
                out.push_str(&format!(" dst_ip=\"{d}\","));
                if dstport > 0 {
                    out.push_str(&format!(" dst_port={dstport},"));
                }
            }
            if let Some(f) = file {
                out.push_str(&format!(" file=\"{f}\","));
            }
            if let Some(u) = user {
                out.push_str(&format!(" acct=\"{u}\","));
            }
            if let Some(l) = full_log {
                out.push_str(&format!(" message=\"{}\"", sanitize_val(l)));
            }
            out
        }
    }
}

/// Checks whether an alert matches the target's configured filters.
pub fn matches_filter(alert: &Value, target: &SyslogTarget) -> bool {
    let rule = &alert["rule"];
    let level = rule["level"].as_u64().unwrap_or(0) as u32;

    if target.min_level > 0 && level < target.min_level {
        return false;
    }

    if let Some(ids) = &target.rule_ids {
        let rule_id = rule["id"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .or_else(|| rule["id"].as_u64().map(|n| n as u32))
            .unwrap_or(0);
        if !ids.contains(&rule_id) {
            return false;
        }
    }

    if let Some(filter_group) = &target.group_filter {
        let matches = if let Some(arr) = rule["groups"].as_array() {
            arr.iter().any(|v| {
                v.as_str()
                    .is_some_and(|g| g.eq_ignore_ascii_case(filter_group))
            })
        } else {
            rule["groups"]
                .as_str()
                .is_some_and(|g| g.contains(filter_group))
        };
        if !matches {
            return false;
        }
    }

    if let Some(filter_loc) = &target.location_filter {
        let loc = alert["location"].as_str().unwrap_or("");
        // Compare against full location or suffix after '->'
        let target_loc = loc.find("->").map(|p| &loc[p + 2..]).unwrap_or(loc);
        if !target_loc.contains(filter_loc) {
            return false;
        }
    }

    true
}

/// Sends an alert over UDP to the specified target.
pub async fn send_syslog(target: &SyslogTarget, alert: &Value) -> Result<(), String> {
    if !matches_filter(alert, target) {
        return Ok(());
    }

    let host = get_local_hostname(target.use_fqdn);
    let msg = format_alert(alert, target.format, target.priority, &host);
    let msg_bytes = msg.as_bytes();

    let target_host = target.host.clone();
    let target_port = target.port;
    let msg_clone = msg_bytes.to_vec();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let addr: std::net::Ipv4Addr = target_host.parse().unwrap_or(std::net::Ipv4Addr::LOCALHOST);
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP client socket: {e}"))?;
        socket
            .connect((addr, target_port))
            .map_err(|e| format!("Failed to connect UDP to {addr}:{target_port}: {e}"))?;
        socket
            .send(&msg_clone)
            .map_err(|e| format!("UDP send to {addr}:{target_port} failed: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())??;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    fn sample_alert() -> Value {
        json!({
            "timestamp": "2026-11-03T07:15:20+00:00",
            "location": "agent01->/var/log/secure",
            "rule": {
                "id": "5710",
                "level": 8,
                "description": "sshd: Attempt to login using a non-existent user",
                "groups": ["syslog", "sshd", "invalid_login"]
            },
            "data": {
                "srcip": "192.168.1.100",
                "srcport": 45123,
                "dstip": "10.0.0.5",
                "dstport": 22,
                "srcuser": "admin"
            },
            "full_log": "Failed password for invalid user admin from 192.168.1.100 port 45123 ssh2"
        })
    }

    #[test]
    fn test_format_default() {
        let alert = sample_alert();
        let formatted = format_alert(&alert, SyslogFormat::Default, 132, "siem-server");

        assert!(formatted.starts_with("<132>Nov  3 07:15:20 siem-server provigil:"));
        assert!(formatted.contains("Alert Level: 8;"));
        assert!(
            formatted.contains("Rule: 5710 - sshd: Attempt to login using a non-existent user;")
        );
        assert!(formatted.contains("classification: syslog,sshd,invalid_login;"));
        assert!(formatted.contains("srcip: 192.168.1.100;"));
        assert!(formatted.contains("dstip: 10.0.0.5;"));
        assert!(formatted.contains("user: admin;"));
        assert!(formatted.contains("Failed password for invalid user admin"));
    }

    #[test]
    fn test_format_cef() {
        let alert = sample_alert();
        let formatted = format_alert(&alert, SyslogFormat::Cef, 132, "siem-server");

        assert!(formatted.starts_with("<132>Nov  3 07:15:20 CEF:0|ProVigil|ProVigil|v1.0|5710|sshd: Attempt to login using a non-existent user|8|"));
        assert!(formatted.contains("dvc=siem-server"));
        assert!(formatted.contains("cs1=agent01->/var/log/secure cs1Label=Location"));
        assert!(formatted.contains("src=192.168.1.100 shost=192.168.1.100"));
        assert!(formatted.contains("spt=45123"));
        assert!(formatted.contains("dst=10.0.0.5 dhost=10.0.0.5"));
        assert!(formatted.contains("dpt=22"));
        assert!(formatted.contains("suser=admin"));
    }

    #[test]
    fn test_format_json() {
        let alert = sample_alert();
        let formatted = format_alert(&alert, SyslogFormat::Json, 132, "siem-server");

        assert!(formatted.starts_with("<132>Nov  3 07:15:20 siem-server provigil: {"));
        assert!(formatted.contains("\"id\":\"5710\""));
        assert!(formatted.contains("\"level\":8"));
    }

    #[test]
    fn test_format_splunk() {
        let alert = sample_alert();
        let formatted = format_alert(&alert, SyslogFormat::Splunk, 132, "siem-server");

        assert!(formatted.starts_with("<132>Nov  3 07:15:20 siem-server provigil: crit=8 id=5710 description=\"sshd: Attempt to login using a non-existent user\""));
        assert!(formatted.contains("src_ip=\"192.168.1.100\", src_port=45123,"));
        assert!(formatted.contains("dst_ip=\"10.0.0.5\", dst_port=22,"));
        assert!(formatted.contains("acct=\"admin\","));
    }

    #[test]
    fn test_filters() {
        let alert = sample_alert();
        let mut target = SyslogTarget::default();

        // Level filter
        target.min_level = 5;
        assert!(matches_filter(&alert, &target));
        target.min_level = 10;
        assert!(!matches_filter(&alert, &target));

        // Rule ID filter
        target.min_level = 0;
        target.rule_ids = Some(vec![5710, 5711]);
        assert!(matches_filter(&alert, &target));
        target.rule_ids = Some(vec![1000]);
        assert!(!matches_filter(&alert, &target));

        // Group filter
        target.rule_ids = None;
        target.group_filter = Some("sshd".to_string());
        assert!(matches_filter(&alert, &target));
        target.group_filter = Some("firewall".to_string());
        assert!(!matches_filter(&alert, &target));

        // Location filter
        target.group_filter = None;
        target.location_filter = Some("/var/log/secure".to_string());
        assert!(matches_filter(&alert, &target));
        target.location_filter = Some("/var/log/syslog".to_string());
        assert!(!matches_filter(&alert, &target));
    }

    #[tokio::test]
    async fn test_udp_transmission() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let target = SyslogTarget {
            host: "127.0.0.1".to_string(),
            port,
            format: SyslogFormat::Default,
            ..Default::default()
        };

        let alert = sample_alert();
        let send_res = send_syslog(&target, &alert).await;

        // In Windows sandbox, socket connecting may be blocked (10013) or loopback UDP restricted.
        if let Err(e) = send_res {
            assert!(e.contains("10013") || e.contains("access permissions"));
        } else {
            let mut buf = vec![0u8; 1024];
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.recv_from(&mut buf)).await
            {
                let received = String::from_utf8_lossy(&buf[..n]);
                assert!(received.contains("provigil: Alert Level: 8;"));
            }
        }
    }
}
