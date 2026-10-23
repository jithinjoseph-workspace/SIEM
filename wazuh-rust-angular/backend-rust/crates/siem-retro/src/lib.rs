//! Retrospective scans for the SIEM: "would this rule have caught anything in
//! the last N hours?". Two kinds:
//!
//! - **rule**: the tenant's stored events are sent again through analysisd's
//!   logtest (`queue/sockets/logtest`), so the *current* ruleset decides,
//!   including rules added or changed after the events arrived;
//! - **keyword**: the events whose text contains the keyword.
//!
//! This crate holds the scan record, the logtest messages and the matching;
//! siem-api reads the events and talks to the socket. The JSON is the NDR
//! retrospective's, so the same page shows it.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const HOURS_CHOICES: [u32; 4] = [24, 48, 72, 168];
/// Events read per scan (newest first).
pub const MAX_EVENTS: u64 = 20_000;
pub const MAX_MATCHES: usize = 500;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScanRequest {
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub rule_name: String,
    /// The keyword (when no rule is picked).
    #[serde(default)]
    pub rule_content: String,
    #[serde(default)]
    pub hours_back: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// A Wazuh rule id.
    Rule(u32),
    Keyword(String),
}

impl ScanRequest {
    /// A numeric rule id, else a keyword of at least 3 characters.
    pub fn kind(&self) -> Result<Kind, String> {
        if let Ok(id) = self.rule_id.trim().parse::<u32>() {
            return Ok(Kind::Rule(id));
        }
        let k = self.rule_content.trim();
        if k.chars().count() >= 3 {
            return Ok(Kind::Keyword(k.chars().take(200).collect()));
        }
        if !self.rule_id.trim().is_empty() {
            return Err("Pick a Wazuh rule (numeric id), or enter a keyword".into());
        }
        Err("Select a rule from the list, or enter a keyword of at least 3 characters".into())
    }

    pub fn hours(&self) -> u32 {
        if HOURS_CHOICES.contains(&self.hours_back) { self.hours_back } else { 24 }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Match {
    /// RFC 3339
    pub ts: String,
    pub src_ip: String,
    /// The agent the event came from.
    pub dst_ip: String,
    pub alert_signature: String,
    pub severity: String,
    /// The event id.
    pub community_id: String,
    pub rule_id: u32,
    pub level: u32,
    pub location: String,
    pub log: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_content: String,
    pub hours_back: u32,
    /// "running" | "done" | "failed"
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub match_count: usize,
    pub events_scanned: usize,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub matches: Vec<Match>,
}

impl Scan {
    pub fn start(id: String, r: &ScanRequest, now: chrono::DateTime<chrono::Utc>) -> Scan {
        Scan {
            id,
            rule_id: r.rule_id.trim().to_string(),
            rule_name: r.rule_name.chars().take(200).collect(),
            rule_content: r.rule_content.chars().take(200).collect(),
            hours_back: r.hours(),
            status: "running".into(),
            started_at: now.to_rfc3339(),
            ..Default::default()
        }
    }

    /// The list entry (without the matches).
    pub fn summary(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or(json!({}));
        if let Some(o) = v.as_object_mut() {
            o.remove("matches");
        }
        v
    }
}

/// One stored event (a `siem_events` row).
#[derive(Debug, Clone, Default)]
pub struct Event {
    pub id: String,
    pub timestamp: u64,
    pub agent_id: String,
    pub agent_name: String,
    pub location: String,
    pub message: String,
}

pub fn severity(level: u32) -> &'static str {
    match level {
        12.. => "CRITICAL",
        8..=11 => "HIGH",
        4..=7 => "MEDIUM",
        _ => "LOW",
    }
}

fn rfc3339(ts: u64) -> String {
    // stored timestamps are seconds, or milliseconds for newer rows
    let secs = if ts > 100_000_000_000 { ts / 1000 } else { ts };
    chrono::DateTime::from_timestamp(secs as i64, 0).map(|t| t.to_rfc3339()).unwrap_or_default()
}

/// `log_processing` for one event. JSON events (Windows eventchannel, JSON logs)
/// use the json format, everything else syslog.
pub fn logtest_request(e: &Event, token: Option<&str>) -> String {
    let format = if e.message.trim_start().starts_with('{') { "json" } else { "syslog" };
    let mut params = json!({ "event": e.message, "log_format": format, "location": if e.location.is_empty() { "retrospective" } else { e.location.as_str() } });
    if let Some(t) = token {
        params["token"] = json!(t);
    }
    json!({ "version": 1, "origin": { "name": "siem-api", "module": "retrospective" }, "command": "log_processing", "parameters": params }).to_string()
}

pub fn remove_session_request(token: &str) -> String {
    json!({ "version": 1, "origin": { "name": "siem-api", "module": "retrospective" }, "command": "remove_session", "parameters": { "token": token } }).to_string()
}

/// What logtest said about one event.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Verdict {
    pub token: String,
    pub rule_id: u32,
    pub level: u32,
    pub description: String,
    pub src_ip: String,
}

pub fn parse_logtest_response(resp: &str) -> Result<Verdict, String> {
    let v: Value = serde_json::from_str(resp.trim_end_matches('\0')).map_err(|e| format!("bad logtest reply: {e}"))?;
    if v["error"].as_i64().unwrap_or(0) != 0 {
        let msg = v["data"]["messages"].as_array().and_then(|m| m.first()).and_then(|m| m.as_str()).unwrap_or("logtest error");
        return Err(msg.to_string());
    }
    let d = &v["data"];
    let out = &d["output"];
    let rule = &out["rule"];
    let num = |x: &Value| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())).unwrap_or(0) as u32;
    Ok(Verdict {
        token: d["token"].as_str().unwrap_or("").to_string(),
        rule_id: num(&rule["id"]),
        level: num(&rule["level"]),
        description: rule["description"].as_str().unwrap_or("").to_string(),
        src_ip: out["data"]["srcip"].as_str().unwrap_or("").to_string(),
    })
}

/// A rule match: logtest put the event on this rule.
pub fn rule_match(e: &Event, v: &Verdict, wanted: u32) -> Option<Match> {
    (v.rule_id == wanted).then(|| Match {
        ts: rfc3339(e.timestamp),
        src_ip: v.src_ip.clone(),
        dst_ip: if e.agent_name.is_empty() { e.agent_id.clone() } else { e.agent_name.clone() },
        alert_signature: format!("Rule {}: {}", v.rule_id, v.description),
        severity: severity(v.level).into(),
        community_id: e.id.clone(),
        rule_id: v.rule_id,
        level: v.level,
        location: e.location.clone(),
        log: e.message.chars().take(500).collect(),
    })
}

/// A keyword match (case-insensitive).
pub fn keyword_match(e: &Event, keyword: &str) -> Option<Match> {
    e.message.to_lowercase().contains(&keyword.to_lowercase()).then(|| Match {
        ts: rfc3339(e.timestamp),
        src_ip: String::new(),
        dst_ip: if e.agent_name.is_empty() { e.agent_id.clone() } else { e.agent_name.clone() },
        alert_signature: format!("Keyword: {keyword}"),
        severity: "INFO".into(),
        community_id: e.id.clone(),
        location: e.location.clone(),
        log: e.message.chars().take(500).collect(),
        ..Default::default()
    })
}

/// Adds a match (keeping at most [`MAX_MATCHES`]; the count goes on).
pub fn record(scan: &mut Scan, m: Option<Match>) {
    scan.events_scanned += 1;
    if let Some(m) = m {
        scan.match_count += 1;
        if scan.matches.len() < MAX_MATCHES {
            scan.matches.push(m);
        }
    }
}

pub fn finish(scan: &mut Scan, error: Option<String>, now: chrono::DateTime<chrono::Utc>) {
    scan.completed_at = Some(now.to_rfc3339());
    match error {
        Some(e) => {
            scan.status = "failed".into();
            scan.error = e;
        }
        None => scan.status = "done".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(msg: &str) -> Event {
        Event { id: "e1".into(), timestamp: 1_729_664_111, agent_id: "001".into(), agent_name: "web-01".into(), location: "/var/log/auth.log".into(), message: msg.into() }
    }

    #[test]
    fn request_kinds() {
        let r = |id: &str, kw: &str| ScanRequest { rule_id: id.into(), rule_content: kw.into(), hours_back: 48, ..Default::default() }.kind();
        assert_eq!(r("5712", ""), Ok(Kind::Rule(5712)));
        assert_eq!(r("", "mimikatz"), Ok(Kind::Keyword("mimikatz".into())));
        assert!(r("", "ab").is_err());
        assert!(r("2b1f3c4d-uuid", "").is_err());
        assert_eq!(ScanRequest { hours_back: 5, ..Default::default() }.hours(), 24);
    }

    #[test]
    fn logtest_messages() {
        let q: Value = serde_json::from_str(&logtest_request(&ev("Oct 23 sshd[1]: Failed password"), Some("abcd1234"))).unwrap();
        assert_eq!((q["command"].as_str(), q["parameters"]["log_format"].as_str(), q["parameters"]["token"].as_str()), (Some("log_processing"), Some("syslog"), Some("abcd1234")));
        let q: Value = serde_json::from_str(&logtest_request(&ev("{\"win\":{}}"), None)).unwrap();
        assert_eq!(q["parameters"]["log_format"], "json");
        assert!(q["parameters"].get("token").is_none());

        let resp = r#"{"error":0,"data":{"token":"abcd1234","messages":["WARNING: (7309): new session"],"output":{"rule":{"id":"5716","level":5,"description":"sshd: authentication failed."},"data":{"srcip":"203.0.113.9"}},"alert":true,"codemsg":1}}"#;
        let v = parse_logtest_response(resp).unwrap();
        assert_eq!((v.token.as_str(), v.rule_id, v.level, v.src_ip.as_str()), ("abcd1234", 5716, 5, "203.0.113.9"));
        assert!(rule_match(&ev("x"), &v, 5716).is_some());
        assert!(rule_match(&ev("x"), &v, 5710).is_none());
        assert!(parse_logtest_response(r#"{"error":1,"data":{"messages":["(7313): 'event' JSON field not found"]}}"#).unwrap_err().contains("7313"));
    }

    #[test]
    fn scan_record() {
        let mut s = Scan::start("s1".into(), &ScanRequest { rule_content: "Failed".into(), hours_back: 24, ..Default::default() }, chrono::Utc::now());
        record(&mut s, keyword_match(&ev("sshd: Failed password"), "failed"));
        record(&mut s, keyword_match(&ev("accepted"), "failed"));
        finish(&mut s, None, chrono::Utc::now());
        assert_eq!((s.status.as_str(), s.match_count, s.events_scanned), ("done", 1, 2));
        assert_eq!(s.matches[0].ts, "2024-10-23T06:15:11+00:00");
        assert!(s.summary().get("matches").is_none());
    }
}
