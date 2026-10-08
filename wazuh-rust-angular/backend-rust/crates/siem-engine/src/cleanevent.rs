//! Event cleaning and pre-decoding (parity with src/analysisd/cleanevent.c & cleanevent.h)

use regex::Regex;
use std::sync::LazyLock;

static SYSLOG_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // 1. Standard BSD syslog: "Oct  3 14:45:00 hostname prog[123]: msg"
    // 2. ISO 8601 syslog: "2026-10-03T14:45:00.123+00:00 hostname prog[123]: msg"
    Regex::new(r"^(?:(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+)?(?:(?P<host>[\w\.\-]+)\s+)?(?P<prog>[\w\.\-\(\)/]+?)(?:\[(?P<pid>\d+)\])?:?\s+(?P<msg>.*)$").unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanedEvent {
    pub location: String,
    pub module: String,
    pub full_log: String,
    pub log: String,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub program_name: Option<String>,
    pub pid: Option<u32>,
    pub agent_id: String,
}

/// Extract module name from raw message header (matching extract_module_from_message in cleanevent.c)
/// Message format: `queue_id:location:message` where location may have `(agent) ip->module`
pub fn extract_module_from_message(msg: &str) -> String {
    // Skip optional 2-byte queue id (e.g. "1:")
    let trimmed = if msg.len() >= 2 && msg.as_bytes()[1] == b':' {
        &msg[2..]
    } else {
        msg
    };

    if let Some(pos) = trimmed.find(':') {
        let location = &trimmed[..pos];
        extract_module_from_location(location)
    } else {
        extract_module_from_location(trimmed)
    }
}

/// Extract module name from location string (matching extract_module_from_location in cleanevent.c)
/// Examples:
/// "(agent1) 192.168.1.10->/var/log/syslog" => "/var/log/syslog"
/// "(agent1) 192.168.1.10->syscheck" => "syscheck"
/// "syscheck" => "syscheck"
pub fn extract_module_from_location(location: &str) -> String {
    if let Some(idx) = location.find("->") {
        location[idx + 2..].to_string()
    } else {
        location.to_string()
    }
}

/// Parses and cleans an ingested message string (matching OS_CleanMSG in cleanevent.c)
pub fn os_clean_msg(raw_msg: &str) -> Option<CleanedEvent> {
    let mut s = raw_msg;

    // Check for queue ID prefix (e.g. "1:")
    if s.len() >= 2 && s.as_bytes()[1] == b':' {
        s = &s[2..];
    }

    // Split location and message body
    // Location can have escaped colons '|:'
    let mut loc_end = None;
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b':' {
            if i > 0 && bytes[i - 1] == b'|' {
                continue; // Escaped colon
            }
            loc_end = Some(i);
            break;
        }
    }

    let (location, body) = match loc_end {
        Some(idx) => {
            let loc = s[..idx].replace("|:", ":");
            let rest = &s[idx + 1..];
            (loc, rest)
        }
        None => ("stdin".to_string(), s),
    };

    let module = extract_module_from_location(&location);

    // Extract agent_id if location is formatted like "(agent_name) ip->module" or contains agent id
    let agent_id = if location.starts_with('(') {
        if let Some(end_paren) = location.find(')') {
            let inner = &location[1..end_paren];
            // If inner has an ID prefix
            inner.to_string()
        } else {
            "000".to_string()
        }
    } else {
        "000".to_string()
    };

    // Pre-decode syslog header
    let mut timestamp = None;
    let mut hostname = None;
    let mut program_name = None;
    let mut pid = None;
    let mut log = body.to_string();

    if let Some(caps) = SYSLOG_REGEX.captures(body) {
        if let Some(ts) = caps.name("timestamp") {
            timestamp = Some(ts.as_str().to_string());
        }
        if let Some(host) = caps.name("host") {
            hostname = Some(host.as_str().to_string());
        }
        if let Some(prog) = caps.name("prog") {
            program_name = Some(prog.as_str().to_string());
        }
        if let Some(p) = caps.name("pid") {
            pid = p.as_str().parse::<u32>().ok();
        }
        if let Some(m) = caps.name("msg") {
            log = m.as_str().to_string();
        }
    }

    Some(CleanedEvent {
        location,
        module,
        full_log: body.to_string(),
        log,
        timestamp,
        hostname,
        program_name,
        pid,
        agent_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_module_from_location() {
        assert_eq!(
            extract_module_from_location("(agent01) 10.0.0.5->syscheck"),
            "syscheck"
        );
        assert_eq!(
            extract_module_from_location("(web01) 192.168.1.1->/var/log/nginx/access.log"),
            "/var/log/nginx/access.log"
        );
        assert_eq!(
            extract_module_from_location("syscollector"),
            "syscollector"
        );
    }

    #[test]
    fn test_os_clean_msg_syslog() {
        let raw = "1:(agent01) 10.0.0.5->/var/log/auth.log:Oct 03 14:45:00 webserver sshd[12345]: Failed password for root from 1.2.3.4 port 54321 ssh2";
        let cleaned = os_clean_msg(raw).expect("clean message failed");

        assert_eq!(cleaned.location, "(agent01) 10.0.0.5->/var/log/auth.log");
        assert_eq!(cleaned.module, "/var/log/auth.log");
        assert_eq!(cleaned.agent_id, "agent01");
        assert_eq!(cleaned.timestamp, Some("Oct 03 14:45:00".to_string()));
        assert_eq!(cleaned.hostname, Some("webserver".to_string()));
        assert_eq!(cleaned.program_name, Some("sshd".to_string()));
        assert_eq!(cleaned.pid, Some(12345));
        assert_eq!(
            cleaned.log,
            "Failed password for root from 1.2.3.4 port 54321 ssh2"
        );
    }
}
