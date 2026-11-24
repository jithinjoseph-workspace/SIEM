// OCSF normalizer — converts raw logs to unified OcsfEvent structs
// Parsers: Windows XML (EventLog), Syslog RFC5424/3164, Firewall CEF, Generic JSON

use serde::{Deserialize, Serialize};
use chrono::Utc;
use std::collections::HashMap;
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;

// ─── Output types ─────────────────────────────────────────────────────────────

/// Unified OCSF-aligned event written to siem_logs ClickHouse table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfEvent {
    pub log_id:       String,
    pub tenant_id:    String,
    pub source_id:    String,
    pub source_type:  String,
    pub event_class:  String,   // OCSF class name
    pub severity:     String,   // CRITICAL | HIGH | MEDIUM | LOW | INFO
    pub timestamp:    String,   // ISO8601 UTC
    pub raw_log:      String,
    pub parsed:       serde_json::Value,  // OCSF-normalised fields
    pub ip_tokens:    Vec<String>,        // HMAC tokens replacing raw IPs
    pub threat_match: Option<ThreatMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMatch {
    pub ioc_type:  String,
    pub ioc_value: String,
    pub severity:  String,
    pub source:    String,
}

// ─── Windows XML EventLog ─────────────────────────────────────────────────────

/// Parse a Windows Event Log XML batch — returns one OcsfEvent per <Event> element.
/// Input is the raw XML body from a WEC HTTPS POST.
pub fn parse_windows_xml(xml: &str, tenant_id: &str, source_id: &str) -> Vec<OcsfEvent> {
    let mut events = Vec::new();
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut current: Option<WinEventBuilder> = None;
    let mut current_data_name: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match tag.as_str() {
                    "Event" => current = Some(WinEventBuilder::default()),
                    "Data" => {
                        if let Some(ref mut b) = current {
                            b.last_tag = "Data".to_string();
                            current_data_name = e.attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"Name")
                                .map(|a| String::from_utf8_lossy(&a.value).to_string());
                        }
                    }
                    "TimeCreated" => {
                        if let Some(ref mut b) = current {
                            b.timestamp = e.attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"SystemTime")
                                .map(|a| String::from_utf8_lossy(&a.value).to_string());
                        }
                    }
                    "Execution" => {
                        if let Some(ref mut b) = current {
                            b.process_id = e.attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"ProcessID")
                                .map(|a| String::from_utf8_lossy(&a.value).to_string());
                        }
                    }
                    "Provider" => {
                        if let Some(ref mut b) = current {
                            b.provider = e.attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"Name")
                                .map(|a| String::from_utf8_lossy(&a.value).to_string());
                        }
                    }
                    other => {
                        if let Some(ref mut b) = current {
                            b.last_tag = other.to_string();
                        }
                    }
                }
            }

            Ok(XmlEvent::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                if let Some(ref mut b) = current {
                    if let Some(ref name) = current_data_name.clone() {
                        // Inside <Data Name="...">text</Data>
                        b.event_data.insert(name.clone(), text.clone());
                        if text.parse::<std::net::IpAddr>().is_ok() {
                            b.raw_ips.push(text.clone());
                        }
                        current_data_name = None;
                    } else {
                        // Route by the currently open tag
                        match b.last_tag.as_str() {
                            "EventID"  => b.event_id  = Some(text),
                            "Computer" => b.computer  = Some(text),
                            "Channel"  => b.channel   = Some(text),
                            "Level"    => b.level     = Some(text),
                            _ => {}
                        }
                    }
                }
            }

            Ok(XmlEvent::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "TimeCreated" {
                    if let Some(ref mut b) = current {
                        b.timestamp = e.attributes()
                            .filter_map(|a| a.ok())
                            .find(|a| a.key.as_ref() == b"SystemTime")
                            .map(|a| String::from_utf8_lossy(&a.value).to_string());
                    }
                }
                if tag == "Provider" {
                    if let Some(ref mut b) = current {
                        b.provider = e.attributes()
                            .filter_map(|a| a.ok())
                            .find(|a| a.key.as_ref() == b"Name")
                            .map(|a| String::from_utf8_lossy(&a.value).to_string());
                    }
                }
            }

            // Capture simple text elements by tag name
            Ok(XmlEvent::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "Event" {
                    if let Some(b) = current.take() {
                        if let Some(ev) = b.build(tenant_id, source_id, xml) {
                            events.push(ev);
                        }
                    }
                }
            }

            Ok(XmlEvent::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    // Fallback: if XML had no parseable <Event> elements, return one raw event
    if events.is_empty() {
        events.push(raw_fallback(xml, tenant_id, source_id, "wec"));
    }
    events
}

#[derive(Default)]
struct WinEventBuilder {
    event_id:   Option<String>,
    timestamp:  Option<String>,
    computer:   Option<String>,
    channel:    Option<String>,
    provider:   Option<String>,
    process_id: Option<String>,
    level:      Option<String>,
    event_data: HashMap<String, String>,
    raw_ips:    Vec<String>,
    last_tag:   String,  // current open tag — used to route Text events
}

impl WinEventBuilder {
    fn build(self, tenant_id: &str, source_id: &str, raw: &str) -> Option<OcsfEvent> {
        let event_id = self.event_id.clone().unwrap_or_default();
        let (event_class, severity) = eventid_to_ocsf(&event_id);
        let timestamp = self.timestamp.unwrap_or_else(|| Utc::now().to_rfc3339());

        let parsed = serde_json::json!({
            "event_id":  event_id,
            "computer":  self.computer.unwrap_or_default(),
            "channel":   self.channel.unwrap_or_default(),
            "provider":  self.provider.unwrap_or_default(),
            "process_id":self.process_id.unwrap_or_default(),
            "level":     self.level.unwrap_or_default(),
            "event_data": self.event_data,
        });

        // ip_token pass — replace raw IPs in parsed with tokens
        // ip_token pass happens in pipeline.rs with the real tenant key
        let ip_tokens = vec![];

        Some(OcsfEvent {
            log_id:      uuid::Uuid::new_v4().to_string(),
            tenant_id:   tenant_id.to_string(),
            source_id:   source_id.to_string(),
            source_type: "wec".to_string(),
            event_class,
            severity,
            timestamp,
            raw_log:     raw.to_string(),
            parsed,
            ip_tokens,
            threat_match: None,
        })
    }
}

/// Map Windows EventID → (OCSF class, severity string)
fn eventid_to_ocsf(event_id: &str) -> (String, String) {
    match event_id {
        // Authentication events
        "4624" => ("authentication".into(), "INFO".into()),    // Successful logon
        "4625" => ("authentication".into(), "HIGH".into()),    // Failed logon
        "4634" | "4647" => ("authentication".into(), "INFO".into()), // Logoff
        "4648" => ("authentication".into(), "MEDIUM".into()),  // Logon with explicit creds
        "4740" => ("authentication".into(), "HIGH".into()),    // Account locked out
        "4768" => ("authentication".into(), "INFO".into()),    // Kerberos TGT requested
        "4771" => ("authentication".into(), "HIGH".into()),    // Kerberos pre-auth failed
        "4776" => ("authentication".into(), "MEDIUM".into()),  // NTLM auth attempt

        // Process events
        "4688" => ("process_activity".into(), "INFO".into()),  // Process created
        "4689" => ("process_activity".into(), "INFO".into()),  // Process exited

        // Account management
        "4720" => ("account_change".into(), "MEDIUM".into()),  // User account created
        "4722" => ("account_change".into(), "LOW".into()),     // User account enabled
        "4725" => ("account_change".into(), "MEDIUM".into()),  // User account disabled
        "4726" => ("account_change".into(), "HIGH".into()),    // User account deleted
        "4732" | "4728" => ("group_management".into(), "MEDIUM".into()), // Member added to group
        "4756" => ("group_management".into(), "HIGH".into()),  // Member added to universal group

        // Scheduled tasks
        "4698" => ("scheduled_job_activity".into(), "MEDIUM".into()), // Task created
        "4702" => ("scheduled_job_activity".into(), "LOW".into()),    // Task updated

        // Service control
        "7045" => ("system_activity".into(), "HIGH".into()),   // New service installed

        // Policy changes
        "4719" => ("policy_change".into(), "HIGH".into()),     // System audit policy changed
        "4670" => ("policy_change".into(), "MEDIUM".into()),   // Permissions changed

        // Network
        "5156" => ("network_activity".into(), "INFO".into()),  // WFP allowed connection
        "5157" => ("network_activity".into(), "MEDIUM".into()), // WFP blocked connection

        _ => ("system_activity".into(), "INFO".into()),
    }
}

// ─── Syslog RFC5424 / RFC3164 ─────────────────────────────────────────────────

/// Parse a single syslog line — auto-detects RFC5424 vs RFC3164.
/// RFC5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
/// RFC3164: <PRI>MONTH DAY HH:MM:SS HOSTNAME TAG: MSG
pub fn parse_syslog(raw: &str, peer_ip: &str, tenant_id: &str, source_id: &str) -> OcsfEvent {
    let trimmed = raw.trim();

    // Extract PRI: leading <NNN>
    let (facility, syslog_sev, rest) = extract_pri(trimmed);

    // RFC5424: PRI followed by version digit "1 "
    let is_5424 = rest.starts_with("1 ") || rest.starts_with("1\t");

    let mut parsed = if is_5424 {
        parse_rfc5424(rest, peer_ip)
    } else {
        parse_rfc3164(rest, peer_ip)
    };

    // Collect raw IPs for tokenisation
    if peer_ip.parse::<std::net::IpAddr>().is_ok() {
        if let Some(obj) = parsed.as_object_mut() {
            obj.insert("peer_ip".into(), serde_json::Value::String(peer_ip.to_string()));
        }
    }

    let severity = syslog_severity_to_ocsf(syslog_sev);
    let event_class = syslog_facility_to_class(facility);
    let timestamp = parsed.get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let timestamp = if timestamp.is_empty() { Utc::now().to_rfc3339() } else { timestamp };

    let ip_tokens = vec![]; // pipeline.rs applies real tenant key

    OcsfEvent {
        log_id:      uuid::Uuid::new_v4().to_string(),
        tenant_id:   tenant_id.to_string(),
        source_id:   source_id.to_string(),
        source_type: "syslog".to_string(),
        event_class,
        severity,
        timestamp,
        raw_log:     raw.to_string(),
        parsed,
        ip_tokens,
        threat_match: None,
    }
}

/// Extract PRI value → (facility, severity, remaining string)
fn extract_pri(s: &str) -> (u8, u8, &str) {
    if s.starts_with('<') {
        if let Some(end) = s.find('>') {
            if let Ok(pri) = s[1..end].parse::<u8>() {
                return (pri >> 3, pri & 0x07, &s[end + 1..]);
            }
        }
    }
    (1, 6, s) // default: user facility, informational
}

fn parse_rfc5424(s: &str, _peer: &str) -> serde_json::Value {
    // Format: 1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    let parts: Vec<&str> = s.splitn(8, ' ').collect();
    serde_json::json!({
        "version":   parts.first().copied().unwrap_or("-"),
        "timestamp": parts.get(1).copied().unwrap_or("-"),
        "hostname":  parts.get(2).copied().unwrap_or("-"),
        "app_name":  parts.get(3).copied().unwrap_or("-"),
        "proc_id":   parts.get(4).copied().unwrap_or("-"),
        "msg_id":    parts.get(5).copied().unwrap_or("-"),
        "sd":        parts.get(6).copied().unwrap_or("-"),
        "message":   parts.get(7).copied().unwrap_or(""),
        "format":    "rfc5424",
    })
}

fn parse_rfc3164(s: &str, _peer: &str) -> serde_json::Value {
    // Format: MMM DD HH:MM:SS HOSTNAME TAG: MSG
    // Month Day Time = first 15 chars if well-formed
    let (ts, rest) = if s.len() > 15 {
        (&s[..15], s[16..].trim())
    } else {
        ("", s)
    };

    let parts: Vec<&str> = rest.splitn(3, ' ').collect();
    let hostname = parts.first().copied().unwrap_or("-");
    let tag_msg  = parts.get(1).copied().unwrap_or("").to_string()
        + " "
        + parts.get(2).copied().unwrap_or("");

    let (tag, message) = if let Some(idx) = tag_msg.find(": ") {
        (&tag_msg[..idx], tag_msg[idx + 2..].to_string())
    } else {
        (tag_msg.as_str(), String::new())
    };

    serde_json::json!({
        "timestamp": ts,
        "hostname":  hostname,
        "tag":       tag,
        "message":   message,
        "format":    "rfc3164",
    })
}

fn syslog_severity_to_ocsf(sev: u8) -> String {
    match sev {
        0 | 1 => "CRITICAL".into(), // Emergency, Alert
        2      => "CRITICAL".into(), // Critical
        3      => "HIGH".into(),     // Error
        4      => "MEDIUM".into(),   // Warning
        5 | 6  => "INFO".into(),     // Notice, Informational
        7      => "INFO".into(),     // Debug
        _      => "INFO".into(),
    }
}

fn syslog_facility_to_class(facility: u8) -> String {
    match facility {
        0       => "system_activity".into(),  // kernel
        4 | 10  => "authentication".into(),   // auth, authpriv
        9 | 15  => "scheduled_job_activity".into(), // cron
        _       => "system_activity".into(),
    }
}

// ─── Firewall CEF ─────────────────────────────────────────────────────────────

/// Parse a CEF (Common Event Format) log line.
/// Format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
pub fn parse_cef(raw: &str, tenant_id: &str, source_id: &str) -> OcsfEvent {
    let line = raw.trim();

    // Strip optional syslog header before "CEF:"
    let cef_start = line.find("CEF:").unwrap_or(0);
    let cef = &line[cef_start..];

    let parts: Vec<&str> = cef.splitn(8, '|').collect();

    let cef_severity_str = parts.get(6).copied().unwrap_or("0");
    let cef_severity: u8 = cef_severity_str.parse().unwrap_or(0);
    let severity = cef_severity_to_ocsf(cef_severity);

    let name        = parts.get(5).copied().unwrap_or("").to_string();
    let sig_id      = parts.get(4).copied().unwrap_or("").to_string();
    let vendor      = parts.get(1).copied().unwrap_or("").to_string();
    let product     = parts.get(2).copied().unwrap_or("").to_string();
    let ext_str     = parts.get(7).copied().unwrap_or("");
    let extensions  = parse_cef_extensions(ext_str);

    let timestamp = extensions.get("rt")
        .or(extensions.get("end"))
        .or(extensions.get("start"))
        .cloned()
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let parsed = serde_json::json!({
        "vendor":      vendor,
        "product":     product,
        "sig_id":      sig_id,
        "name":        name,
        "cef_severity": cef_severity,
        "extensions":  extensions,
    });

    let ip_tokens = vec![]; // pipeline.rs applies real tenant key

    OcsfEvent {
        log_id:      uuid::Uuid::new_v4().to_string(),
        tenant_id:   tenant_id.to_string(),
        source_id:   source_id.to_string(),
        source_type: "firewall_cef".to_string(),
        event_class: "network_activity".to_string(),
        severity,
        timestamp,
        raw_log:     raw.to_string(),
        parsed,
        ip_tokens,
        threat_match: None,
    }
}

/// Parse CEF extension field: "key=value key2=value2 ..."
/// Values may contain spaces escaped as \=; handle simple unescaped case
fn parse_cef_extensions(ext: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Split on whitespace before a key= pattern
    let mut remaining = ext;
    while !remaining.is_empty() {
        if let Some(eq_pos) = remaining.find('=') {
            // key is the last whitespace-delimited token before '='
            let before_eq = &remaining[..eq_pos];
            let key = before_eq.rsplit_once(' ')
                .map(|(_, k)| k)
                .unwrap_or(before_eq)
                .trim();
            let after_eq = &remaining[eq_pos + 1..];
            // Value ends at next "word=" pattern or end of string
            let value_end = find_next_key(after_eq);
            let value = after_eq[..value_end].trim().to_string();
            if !key.is_empty() {
                map.insert(key.to_string(), value.clone());
            }
            // Advance past "key=value "
            let consumed = eq_pos + 1 + value_end;
            remaining = remaining[consumed..].trim_start();
        } else {
            break;
        }
    }
    map
}

/// Find where the next key= starts in a CEF extension value string
fn find_next_key(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' {
            // Check if the next non-space sequence contains '=' before ' '
            let rest = &s[i + 1..];
            if let Some(eq) = rest.find('=') {
                let space = rest.find(' ').unwrap_or(rest.len());
                if eq < space {
                    return i; // next key starts here
                }
            }
        }
        i += 1;
    }
    s.len()
}

fn cef_severity_to_ocsf(s: u8) -> String {
    match s {
        0..=3  => "LOW".into(),
        4..=6  => "MEDIUM".into(),
        7..=8  => "HIGH".into(),
        9..=10 => "CRITICAL".into(),
        _      => "INFO".into(),
    }
}

// ─── Generic JSON ─────────────────────────────────────────────────────────────

/// Parse generic JSON REST payload — used when source type is unknown
pub fn parse_generic(raw: &str, tenant_id: &str, source_id: &str) -> OcsfEvent {
    let parsed = serde_json::from_str(raw)
        .unwrap_or_else(|_| serde_json::json!({ "raw": raw }));

    let timestamp = parsed.get("timestamp")
        .or(parsed.get("time"))
        .or(parsed.get("@timestamp"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let timestamp = if timestamp.is_empty() { Utc::now().to_rfc3339() } else { timestamp };

    let ip_tokens = vec![]; // pipeline.rs applies real tenant key

    OcsfEvent {
        log_id:      uuid::Uuid::new_v4().to_string(),
        tenant_id:   tenant_id.to_string(),
        source_id:   source_id.to_string(),
        source_type: "generic".to_string(),
        event_class: "unknown".to_string(),
        severity:    "INFO".to_string(),
        timestamp,
        raw_log:     raw.to_string(),
        parsed,
        ip_tokens,
        threat_match: None,
    }
}

// ─── Fallback ─────────────────────────────────────────────────────────────────

fn raw_fallback(raw: &str, tenant_id: &str, source_id: &str, source_type: &str) -> OcsfEvent {
    OcsfEvent {
        log_id:      uuid::Uuid::new_v4().to_string(),
        tenant_id:   tenant_id.to_string(),
        source_id:   source_id.to_string(),
        source_type: source_type.to_string(),
        event_class: "unknown".to_string(),
        severity:    "INFO".to_string(),
        timestamp:   Utc::now().to_rfc3339(),
        raw_log:     raw.to_string(),
        parsed:      serde_json::json!({ "raw": raw }),
        ip_tokens:   vec![],
        threat_match: None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_rfc5424_parses() {
        let raw = "<165>1 2023-01-01T00:00:00Z myhost myapp 1234 ID47 - An application log";
        let ev = parse_syslog(raw, "10.0.0.1", "tenant1", "src1");
        assert_eq!(ev.source_type, "syslog");
        assert_eq!(ev.parsed["format"], "rfc5424");
        assert_eq!(ev.parsed["hostname"], "myhost");
    }

    #[test]
    fn syslog_rfc3164_parses() {
        let raw = "<34>Oct 11 22:14:15 mymachine su: failed for user on /dev/pts/8";
        let ev = parse_syslog(raw, "10.0.0.2", "tenant1", "src1");
        assert_eq!(ev.source_type, "syslog");
        assert_eq!(ev.parsed["format"], "rfc3164");
        assert_eq!(ev.parsed["hostname"], "mymachine");
    }

    #[test]
    fn syslog_auth_failure_is_high() {
        // severity 3 = Error → HIGH
        let raw = "<99>1 2023-01-01T00:00:00Z host sshd 1 - - Failed password";
        let ev = parse_syslog(raw, "1.2.3.4", "t", "s");
        assert_eq!(ev.severity, "HIGH");
    }

    #[test]
    fn cef_parses_severity() {
        let raw = "CEF:0|Palo Alto|Firewall|9.0|1001|Deny Traffic|8|src=1.2.3.4 dst=5.6.7.8 dpt=22";
        let ev = parse_cef(raw, "tenant1", "src1");
        assert_eq!(ev.event_class, "network_activity");
        assert_eq!(ev.severity, "HIGH");
        assert_eq!(ev.parsed["extensions"]["dpt"], "22");
    }

    #[test]
    fn cef_critical_severity() {
        let raw = "CEF:0|Vendor|Product|1.0|sig|Ransomware|10|src=10.0.0.1";
        let ev = parse_cef(raw, "tenant1", "src1");
        assert_eq!(ev.severity, "CRITICAL");
    }

    #[test]
    fn windows_xml_4625_is_high() {
        let xml = r#"<Event>
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>4625</EventID>
            <TimeCreated SystemTime="2023-06-01T10:00:00Z"/>
            <Computer>WIN-DC01</Computer>
            <Channel>Security</Channel>
          </System>
          <EventData>
            <Data Name="TargetUserName">administrator</Data>
            <Data Name="IpAddress">192.168.1.100</Data>
          </EventData>
        </Event>"#;
        let evs = parse_windows_xml(xml, "tenant1", "src1");
        assert!(!evs.is_empty());
        let ev = &evs[0];
        assert_eq!(ev.event_class, "authentication");
        assert_eq!(ev.severity, "HIGH");
    }

    #[test]
    fn eventid_mapping_covers_common_ids() {
        for id in ["4624", "4625", "4688", "4720", "7045", "5157"] {
            let (class, sev) = eventid_to_ocsf(id);
            assert!(!class.is_empty());
            assert!(!sev.is_empty());
        }
    }

    #[test]
    fn generic_json_parses() {
        let raw = r#"{"timestamp":"2023-01-01T00:00:00Z","msg":"test","src_ip":"1.2.3.4"}"#;
        let ev = parse_generic(raw, "t1", "s1");
        assert_eq!(ev.source_type, "generic");
        assert_eq!(ev.timestamp, "2023-01-01T00:00:00Z");
    }
}
