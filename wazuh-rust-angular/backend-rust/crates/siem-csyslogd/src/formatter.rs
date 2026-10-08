//! Alert formatting and filtering engine (`src/os_csyslogd/alert.c`, `src/os_csyslogd/csyslogd.c`)
//!
//! Formats alerts for Syslog transmission in 4 standardized formats:
//! 1. Default Wazuh/OSSEC Syslog format (`DEFAULT_CSYSLOG`)
//! 2. Common Event Format (`CEF_CSYSLOG`)
//! 3. JSON format (`JSON_CSYSLOG`)
//! 4. Splunk Key/Value format (`SPLUNK_CSYSLOG`)

use crate::config::{SyslogConfig, SyslogFormat};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

/// Alert data structure matching `alert_data` in Wazuh C.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyslogAlert {
    pub level: u32,
    pub rule: u32,
    pub comment: String,
    pub location: String,
    pub group: Option<String>,
    pub srcip: Option<String>,
    pub srcport: Option<u16>,
    pub dstip: Option<String>,
    pub dstport: Option<u16>,
    pub srcgeoip: Option<String>,
    pub dstgeoip: Option<String>,
    pub user: Option<String>,
    pub filename: Option<String>,
    pub old_md5: Option<String>,
    pub new_md5: Option<String>,
    pub old_sha1: Option<String>,
    pub new_sha1: Option<String>,
    pub old_sha256: Option<String>,
    pub new_sha256: Option<String>,
    pub file_size: Option<String>,
    pub owner_chg: Option<String>,
    pub group_chg: Option<String>,
    pub perm_chg: Option<String>,
    pub log: Vec<String>,
    pub date: Option<String>,
    pub raw_json: Option<serde_json::Value>,
}

impl SyslogAlert {
    /// Tests if this alert matches the filters configured in `SyslogConfig`.
    pub fn matches_filter(&self, cfg: &SyslogConfig) -> bool {
        // 1. Location filter (strips leading agent head "agent-name->" if present)
        if let Some(ref loc_pattern) = cfg.location {
            let loc_str = if let Some(idx) = self.location.find("->") {
                &self.location[idx + 2..]
            } else {
                &self.location
            };
            if !loc_pattern.execute(loc_str) {
                return false;
            }
        }

        // 2. Alert level filter
        if cfg.level > 0 && self.level < cfg.level {
            return false;
        }

        // 3. Rule ID filter
        if !cfg.rule_ids.is_empty() && !cfg.rule_ids.contains(&self.rule) {
            return false;
        }

        // 4. Group filter
        if let Some(ref grp_pattern) = cfg.group {
            let grp_str = self.group.as_deref().unwrap_or("");
            if !grp_pattern.execute(grp_str) {
                return false;
            }
        }

        true
    }

    /// Formats the alert according to `cfg.format`.
    pub fn format_message(&self, cfg: &SyslogConfig, short_host: &str, fqdn_host: &str) -> String {
        let hostname = if cfg.use_fqdn { fqdn_host } else { short_host };
        let timestamp = format_syslog_timestamp(self.date.as_deref());

        match cfg.format {
            SyslogFormat::Default => self.format_default(cfg.priority, &timestamp, hostname),
            SyslogFormat::Cef => self.format_cef(cfg.priority, &timestamp, hostname),
            SyslogFormat::Json => self.format_json(cfg.priority, &timestamp, hostname),
            SyslogFormat::Splunk => self.format_splunk(cfg.priority, &timestamp, hostname),
        }
    }

    /// Format 0: `DEFAULT_CSYSLOG`
    fn format_default(&self, priority: u32, timestamp: &str, hostname: &str) -> String {
        let mut msg = format!(
            "<{}>{} {} ossec: Alert Level: {}; Rule: {} - {}; Location: {};",
            priority,
            timestamp,
            hostname,
            self.level,
            self.rule,
            self.comment,
            self.location
        );

        if let Some(v) = check_field(&self.group) {
            msg.push_str(&format!(" classification: {};", v));
        }
        if let Some(v) = check_field(&self.srcip) {
            msg.push_str(&format!(" srcip: {};", v));
        }
        if let Some(v) = check_field(&self.srcgeoip) {
            msg.push_str(&format!(" srccity: {};", v));
        }
        if let Some(v) = check_field(&self.dstgeoip) {
            msg.push_str(&format!(" dstcity: {};", v));
        }
        if let Some(v) = check_field(&self.dstip) {
            msg.push_str(&format!(" dstip: {};", v));
        }
        if let Some(v) = check_field(&self.user) {
            msg.push_str(&format!(" user: {};", v));
        }
        if let Some(v) = check_field(&self.old_md5) {
            msg.push_str(&format!(" Previous MD5: {};", v));
        }
        if let Some(v) = check_field(&self.new_md5) {
            msg.push_str(&format!(" Current MD5: {};", v));
        }
        if let Some(v) = check_field(&self.old_sha1) {
            msg.push_str(&format!(" Previous SHA1: {};", v));
        }
        if let Some(v) = check_field(&self.new_sha1) {
            msg.push_str(&format!(" Current SHA1: {};", v));
        }
        if let Some(v) = check_field(&self.old_sha256) {
            msg.push_str(&format!(" Previous SHA256: {};", v));
        }
        if let Some(v) = check_field(&self.new_sha256) {
            msg.push_str(&format!(" Current SHA256: {};", v));
        }
        if let Some(v) = check_field(&self.file_size) {
            msg.push_str(&format!(" Size changed: from {};", v));
        }
        if let Some(v) = check_field(&self.owner_chg) {
            msg.push_str(&format!(" User ownership: was {};", v));
        }
        if let Some(v) = check_field(&self.group_chg) {
            msg.push_str(&format!(" Group ownership: was {};", v));
        }
        if let Some(v) = check_field(&self.perm_chg) {
            msg.push_str(&format!(" Permissions changed: from {};", v));
        }

        if let Some(first_log) = self.log.first() {
            if let Some(v) = check_field_str(first_log) {
                let truncated = truncate_string(v, 61440);
                msg.push_str(&format!(" {}", truncated));
            }
        }

        msg
    }

    /// Format 1: `CEF_CSYSLOG`
    fn format_cef(&self, priority: u32, timestamp: &str, hostname: &str) -> String {
        let cef_level = self.level.min(10);
        let mut msg = format!(
            "<{}>{} CEF:0|Wazuh|Wazuh|v4.14.7|{}|{}|{}|dvc={} cs1={} cs1Label=Location",
            priority,
            timestamp,
            self.rule,
            self.comment,
            cef_level,
            hostname,
            self.location
        );

        if let Some(v) = check_field(&self.group) {
            msg.push_str(&format!(" cat={}", v));
        }
        if let Some(v) = check_field(&self.srcip) {
            msg.push_str(&format!(" src={}", v));
        }
        if let Some(p) = self.dstport {
            if p > 0 {
                msg.push_str(&format!(" dpt={}", p));
            }
        }
        if let Some(p) = self.srcport {
            if p > 0 {
                msg.push_str(&format!(" spt={}", p));
            }
        }
        if let Some(v) = check_field(&self.filename) {
            msg.push_str(&format!(" fname={}", v));
        }
        if let Some(v) = check_field(&self.dstip) {
            msg.push_str(&format!(" dhost={}", v));
        }
        if let Some(v) = check_field(&self.srcip) {
            msg.push_str(&format!(" shost={}", v));
        }
        if let Some(v) = check_field(&self.user) {
            msg.push_str(&format!(" suser={}", v));
        }
        if let Some(v) = check_field(&self.dstip) {
            msg.push_str(&format!(" dst={}", v));
        }
        if let Some(v) = check_field(&self.srcgeoip) {
            msg.push_str(&format!(" cs4Label=SrcCity cs4={}", v));
        }
        if let Some(v) = check_field(&self.dstgeoip) {
            msg.push_str(&format!(" cs5Label=DstCity cs5={}", v));
        }

        if let Some(first_log) = self.log.first() {
            if let Some(v) = check_field_str(first_log) {
                let truncated = truncate_string(v, 61440);
                msg.push_str(&format!(" msg={}", truncated));
            }
        }

        if let (Some(new_md5), Some(new_sha1)) = (check_field(&self.new_md5), check_field(&self.new_sha1)) {
            if let Some(old_md5) = check_field(&self.old_md5) {
                msg.push_str(&format!(" cs2Label=OldMD5 cs2={}", old_md5));
            }
            msg.push_str(&format!(" cs3Label=NewMD5 cs3={}", new_md5));
            if let Some(old_sha1) = check_field(&self.old_sha1) {
                msg.push_str(&format!(" oldFileHash={}", old_sha1));
            }
            msg.push_str(&format!(" fhash={}", new_sha1));
            msg.push_str(&format!(" fileHash={}", new_sha1));
        }

        msg
    }

    /// Format 2: `JSON_CSYSLOG`
    fn format_json(&self, priority: u32, timestamp: &str, hostname: &str) -> String {
        let json_body = if let Some(ref raw) = self.raw_json {
            raw.to_string()
        } else {
            let mut obj = serde_json::Map::new();
            obj.insert("crit".to_string(), serde_json::json!(self.level));
            obj.insert("id".to_string(), serde_json::json!(self.rule));
            obj.insert("component".to_string(), serde_json::json!(self.location));

            if let Some(ref g) = self.group {
                obj.insert("classification".to_string(), serde_json::json!(g));
            }
            if !self.comment.is_empty() {
                obj.insert("description".to_string(), serde_json::json!(self.comment));
            }
            if let Some(first_log) = self.log.first() {
                obj.insert("message".to_string(), serde_json::json!(first_log));
            }
            if let Some(ref u) = self.user {
                obj.insert("acct".to_string(), serde_json::json!(u));
            }
            if let Some(ref ip) = self.srcip {
                obj.insert("src_ip".to_string(), serde_json::json!(ip));
            }
            if let Some(p) = self.srcport {
                if p > 0 {
                    obj.insert("src_port".to_string(), serde_json::json!(p));
                }
            }
            if let Some(ref ip) = self.dstip {
                obj.insert("dst_ip".to_string(), serde_json::json!(ip));
            }
            if let Some(p) = self.dstport {
                if p > 0 {
                    obj.insert("dst_port".to_string(), serde_json::json!(p));
                }
            }
            if let Some(ref f) = self.filename {
                obj.insert("file".to_string(), serde_json::json!(f));
            }
            if let Some(ref h) = self.old_md5 {
                obj.insert("md5_old".to_string(), serde_json::json!(h));
            }
            if let Some(ref h) = self.new_md5 {
                obj.insert("md5_new".to_string(), serde_json::json!(h));
            }
            if let Some(ref h) = self.old_sha1 {
                obj.insert("sha1_old".to_string(), serde_json::json!(h));
            }
            if let Some(ref h) = self.new_sha1 {
                obj.insert("sha1_new".to_string(), serde_json::json!(h));
            }
            if let Some(ref h) = self.old_sha256 {
                obj.insert("sha256_old".to_string(), serde_json::json!(h));
            }
            if let Some(ref h) = self.new_sha256 {
                obj.insert("sha256_new".to_string(), serde_json::json!(h));
            }
            if let Some(ref c) = self.srcgeoip {
                obj.insert("src_city".to_string(), serde_json::json!(c));
            }
            if let Some(ref c) = self.dstgeoip {
                obj.insert("dst_city".to_string(), serde_json::json!(c));
            }

            serde_json::Value::Object(obj).to_string()
        };

        format!("<{}>{} {} ossec: {}", priority, timestamp, hostname, json_body)
    }

    /// Format 3: `SPLUNK_CSYSLOG`
    fn format_splunk(&self, priority: u32, timestamp: &str, hostname: &str) -> String {
        let mut msg = format!(
            "<{}>{} {} ossec: crit={} id={} description=\"{}\" component=\"{}\",",
            priority,
            timestamp,
            hostname,
            self.level,
            self.rule,
            self.comment,
            self.location
        );

        if let Some(v) = check_field(&self.group) {
            msg.push_str(&format!(" classification=\"{}\",", v));
        }

        if let Some(ip) = check_field(&self.srcip) {
            msg.push_str(&format!(" src_ip=\"{}\",", ip));
            if let Some(port) = self.srcport {
                if port > 0 {
                    msg.push_str(&format!(" src_port={},", port));
                }
            }
        }

        if let Some(v) = check_field(&self.srcgeoip) {
            msg.push_str(&format!(" src_city=\"{}\",", v));
        }
        if let Some(v) = check_field(&self.dstgeoip) {
            msg.push_str(&format!(" dst_city=\"{}\",", v));
        }

        if let Some(ip) = check_field(&self.dstip) {
            msg.push_str(&format!(" dst_ip=\"{}\",", ip));
            if let Some(port) = self.dstport {
                if port > 0 {
                    msg.push_str(&format!(" dst_port={},", port));
                }
            }
        }

        if let Some(v) = check_field(&self.filename) {
            msg.push_str(&format!(" file=\"{}\",", v));
        }
        if let Some(v) = check_field(&self.user) {
            msg.push_str(&format!(" acct=\"{}\",", v));
        }
        if let Some(v) = check_field(&self.old_md5) {
            msg.push_str(&format!(" md5_old=\"{}\",", v));
        }
        if let Some(v) = check_field(&self.new_md5) {
            msg.push_str(&format!(" md5_new=\"{}\",", v));
        }
        if let Some(v) = check_field(&self.old_sha1) {
            msg.push_str(&format!(" sha1_old=\"{}\",", v));
        }
        if let Some(v) = check_field(&self.new_sha1) {
            msg.push_str(&format!(" sha1_new=\"{}\",", v));
        }
        if let Some(v) = check_field(&self.old_sha256) {
            msg.push_str(&format!(" sha256_old=\"{}\",", v));
        }
        if let Some(v) = check_field(&self.new_sha256) {
            msg.push_str(&format!(" sha256_new=\"{}\",", v));
        }

        if let Some(first_log) = self.log.first() {
            if let Some(v) = check_field_str(first_log) {
                let truncated = truncate_string(v, 61440);
                msg.push_str(&format!(" message=\"{}\"", truncated));
            }
        }

        msg
    }
}

/// Helper that checks if an optional string field has a valid value,
/// skipping empty values, "(none)", "(unknown)", "unknown".
fn check_field(field: &Option<String>) -> Option<&str> {
    field.as_deref().and_then(check_field_str)
}

/// Checks if string is not empty or one of the sentinel placeholder values.
fn check_field_str(val: &str) -> Option<&str> {
    let trimmed = val.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("(none)")
        || trimmed.eq_ignore_ascii_case("(unknown)")
        || trimmed.eq_ignore_ascii_case("unknown")
        || trimmed == "(null)"
    {
        None
    } else {
        Some(trimmed)
    }
}

/// Formats a syslog timestamp string `MMM dd HH:mm:ss` (e.g. `Jul 10 10:11:23` or `Jul  9 10:11:23`).
pub fn format_syslog_timestamp(date_str: Option<&str>) -> String {
    if let Some(s) = date_str {
        let trimmed = s.trim();
        // Wazuh log format often starts with "2023 Jul 10 10:11:23"
        if trimmed.len() > 14 && trimmed.chars().next().map_or(false, |c| c.is_ascii_digit()) {
            let sub = &trimmed[5..];
            if sub.len() >= 15 {
                let mut chars: Vec<char> = sub.chars().collect();
                // Space pad first digit of day if '0'
                if chars.len() > 4 && chars[4] == '0' {
                    chars[4] = ' ';
                }
                return chars.into_iter().collect();
            }
        }

        // Try parsing ISO8601 (e.g. from JSON alerts)
        if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
            let local_dt: DateTime<Local> = DateTime::from(dt);
            let mut formatted = local_dt.format("%b %d %T").to_string();
            if formatted.len() > 4 && formatted.as_bytes()[4] == b'0' {
                formatted.replace_range(4..5, " ");
            }
            return formatted;
        }
    }

    // Default to current local time
    let now: DateTime<Local> = Local::now();
    let mut formatted = now.format("%b %d %T").to_string();
    if formatted.len() > 4 && formatted.as_bytes()[4] == b'0' {
        formatted.replace_range(4..5, " ");
    }
    formatted
}

/// Truncates string to `max_len` appending `...` if exceeded, matching `field_add_truncated`.
fn truncate_string(val: &str, max_len: usize) -> String {
    if val.len() <= max_len {
        val.to_string()
    } else {
        let trailer = "...";
        let take_len = max_len.saturating_sub(trailer.len());
        let truncated: String = val.chars().take(take_len).collect();
        format!("{}{}", truncated, trailer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyslogFormat;
    use siem_shared::regex::OSMatch;

    #[test]
    fn test_format_default() {
        let alert = SyslogAlert {
            level: 5,
            rule: 1002,
            comment: "Unknown problem found".to_string(),
            location: "/var/log/messages".to_string(),
            group: Some("syslog".to_string()),
            srcip: Some("192.168.1.50".to_string()),
            user: Some("admin".to_string()),
            log: vec!["pam_unix: session opened for user admin".to_string()],
            date: Some("2026 Jul 10 14:20:10".to_string()),
            ..Default::default()
        };

        let cfg = SyslogConfig {
            server: "127.0.0.1".to_string(),
            port: 514,
            priority: 132,
            format: SyslogFormat::Default,
            ..Default::default()
        };

        let formatted = alert.format_message(&cfg, "wazuh-master", "wazuh-master.corp.net");
        assert!(formatted.starts_with("<132>Jul 10 14:20:10 wazuh-master ossec: Alert Level: 5; Rule: 1002 - Unknown problem found; Location: /var/log/messages;"));
        assert!(formatted.contains("classification: syslog;"));
        assert!(formatted.contains("srcip: 192.168.1.50;"));
        assert!(formatted.contains("user: admin;"));
        assert!(formatted.contains("pam_unix: session opened for user admin"));
    }

    #[test]
    fn test_format_cef() {
        let alert = SyslogAlert {
            level: 12, // Should cap at 10
            rule: 5715,
            comment: "SSHD authentication success".to_string(),
            location: "agent001->/var/log/secure".to_string(),
            group: Some("authentication_success".to_string()),
            srcip: Some("10.0.0.1".to_string()),
            dstport: Some(22),
            user: Some("root".to_string()),
            date: Some("2026 Jul 09 08:00:00".to_string()),
            ..Default::default()
        };

        let cfg = SyslogConfig {
            server: "127.0.0.1".to_string(),
            priority: 132,
            format: SyslogFormat::Cef,
            use_fqdn: true,
            ..Default::default()
        };

        let formatted = alert.format_message(&cfg, "short-host", "fqdn-host.local");
        // Day 09 should be space padded to ' 9'
        assert!(formatted.contains("<132>Jul  9 08:00:00"));
        assert!(formatted.contains("CEF:0|Wazuh|Wazuh|v4.14.7|5715|SSHD authentication success|10|dvc=fqdn-host.local"));
        assert!(formatted.contains("cs1=agent001->/var/log/secure cs1Label=Location"));
        assert!(formatted.contains("cat=authentication_success"));
        assert!(formatted.contains("src=10.0.0.1"));
        assert!(formatted.contains("dpt=22"));
        assert!(formatted.contains("suser=root"));
    }

    #[test]
    fn test_format_json() {
        let alert = SyslogAlert {
            level: 3,
            rule: 501,
            comment: "Login event".to_string(),
            location: "/var/log/auth.log".to_string(),
            group: Some("syslog".to_string()),
            user: Some("alice".to_string()),
            date: Some("2026 Jul 10 10:00:00".to_string()),
            ..Default::default()
        };

        let cfg = SyslogConfig {
            server: "127.0.0.1".to_string(),
            priority: 132,
            format: SyslogFormat::Json,
            ..Default::default()
        };

        let formatted = alert.format_message(&cfg, "manager", "manager.local");
        assert!(formatted.starts_with("<132>Jul 10 10:00:00 manager ossec: {"));
        let json_part = &formatted[formatted.find('{').unwrap()..];
        let val: serde_json::Value = serde_json::from_str(json_part).unwrap();
        assert_eq!(val["crit"], 3);
        assert_eq!(val["id"], 501);
        assert_eq!(val["component"], "/var/log/auth.log");
        assert_eq!(val["acct"], "alice");
    }

    #[test]
    fn test_format_splunk() {
        let alert = SyslogAlert {
            level: 7,
            rule: 10001,
            comment: "Multiple failed logins".to_string(),
            location: "/var/log/secure".to_string(),
            group: Some("authentication_failed".to_string()),
            srcip: Some("192.168.10.5".to_string()),
            srcport: Some(44332),
            user: Some("unknown".to_string()), // Should be filtered out
            date: Some("2026 Jul 10 11:11:11".to_string()),
            ..Default::default()
        };

        let cfg = SyslogConfig {
            server: "127.0.0.1".to_string(),
            priority: 132,
            format: SyslogFormat::Splunk,
            ..Default::default()
        };

        let formatted = alert.format_message(&cfg, "manager", "manager.local");
        assert!(formatted.contains("crit=7 id=10001 description=\"Multiple failed logins\" component=\"/var/log/secure\","));
        assert!(formatted.contains("src_ip=\"192.168.10.5\","));
        assert!(formatted.contains("src_port=44332,"));
        // "unknown" user should not appear
        assert!(!formatted.contains("acct=\"unknown\""));
    }

    #[test]
    fn test_filter_matching() {
        let alert = SyslogAlert {
            level: 8,
            rule: 31101,
            location: "agent-ny->/var/log/nginx/access.log".to_string(),
            group: Some("web|accesslog".to_string()),
            ..Default::default()
        };

        let mut cfg = SyslogConfig {
            level: 7,
            rule_ids: vec![31101, 31102],
            location: Some(OSMatch::compile("/var/log/nginx/", 0).unwrap()),
            group: Some(OSMatch::compile("web", 0).unwrap()),
            ..Default::default()
        };

        // All match
        assert!(alert.matches_filter(&cfg));

        // Level higher than alert
        cfg.level = 10;
        assert!(!alert.matches_filter(&cfg));
        cfg.level = 8;

        // Rule not in list
        cfg.rule_ids = vec![9999];
        assert!(!alert.matches_filter(&cfg));
        cfg.rule_ids = vec![31101];

        // Location mismatch
        cfg.location = Some(OSMatch::compile("/var/log/apache/*", 0).unwrap());
        assert!(!alert.matches_filter(&cfg));
    }
}
