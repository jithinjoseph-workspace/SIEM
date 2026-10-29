//! EDR file reputation: every file hash in the event stream — Sysmon process starts, driver
//! and DLL loads, executables written or deleted, alternate data streams, and FIM changes —
//! checked against threat intel (the feeds and the tenant's own watchlist, `intel.rs`).
//! A known-bad file is an alert: rule 940100 when it ran or loaded as a driver, 940101 when
//! it was written, loaded as a DLL or deleted. One alert per agent and file per hour, so a
//! sample that runs in a loop does not flood the console.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Known malware ran (process start) or loaded as a driver.
pub const RULE_EXECUTED: u32 = 940100;
/// Known malware written, loaded as a DLL, or deleted.
pub const RULE_FILE: u32 = 940101;

const REPEAT: Duration = Duration::from_secs(3600);
const MAX_SEEN: usize = 100_000;

/// The file an event is about: its path, hashes (lower-case MD5 / SHA-1 / SHA-256) and
/// whether it executed.
#[derive(Debug, PartialEq)]
pub struct FileSeen {
    pub path: String,
    pub hashes: Vec<String>,
    pub executed: bool,
    pub event: &'static str,
}

/// Sysmon's `MD5=..,SHA256=..,IMPHASH=..` (the import hash names no file: left out).
fn sysmon_hashes(s: &str) -> Vec<String> {
    s.split(',')
        .filter_map(|p| p.split_once('='))
        .filter(|(k, _)| matches!(k.trim().to_ascii_uppercase().as_str(), "MD5" | "SHA1" | "SHA256"))
        .map(|(_, v)| v.trim().to_ascii_lowercase())
        .filter(|v| matches!(v.len(), 32 | 40 | 64) && v.chars().all(|c| c.is_ascii_hexdigit()))
        .collect()
}

pub fn file_of(v: &Value) -> Option<FileSeen> {
    let undouble = |s: &str| s.replace("\\\\", "\\");
    if let Some(sc) = v.get("syscheck").filter(|s| s.is_object()) {
        let hashes: Vec<String> = ["sha256_after", "sha1_after", "md5_after"]
            .iter()
            .filter_map(|k| sc[*k].as_str())
            .map(|h| h.to_ascii_lowercase())
            .filter(|h| matches!(h.len(), 32 | 40 | 64) && h.chars().all(|c| c.is_ascii_hexdigit()))
            .collect();
        let path = sc["path"].as_str().unwrap_or("").to_string();
        return (!hashes.is_empty()).then_some(FileSeen { path, hashes, executed: false, event: "file changed (FIM)" });
    }
    let win = &v["data"]["win"];
    if win["system"]["channel"].as_str() != Some("Microsoft-Windows-Sysmon/Operational") {
        return None;
    }
    let ed = &win["eventdata"];
    let s = |k: &str| ed[k].as_str().unwrap_or("");
    let (path, executed, event) = match win["system"]["eventID"].as_str().unwrap_or("") {
        "1" => (s("image"), true, "process started"),
        "6" => (s("imageLoaded"), true, "driver loaded"),
        "7" => (s("imageLoaded"), false, "DLL loaded"),
        "15" => (s("targetFilename"), false, "file stream written"),
        "23" | "26" => (s("targetFilename"), false, "file deleted"),
        "29" => (s("targetFilename"), false, "executable written"),
        _ => return None,
    };
    let hashes = sysmon_hashes(if ed["hashes"].is_string() { s("hashes") } else { s("hash") });
    (!hashes.is_empty()).then(|| FileSeen { path: undouble(path), hashes, executed, event })
}

fn seen() -> &'static Mutex<HashMap<(String, String, String), Instant>> {
    static S: OnceLock<Mutex<HashMap<(String, String, String), Instant>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether this agent's file was reported within the hour (and remembers it now if not).
fn reported_recently(tenant: &str, agent: &str, hash: &str) -> bool {
    let mut m = seen().lock().unwrap();
    let now = Instant::now();
    if m.len() >= MAX_SEEN {
        m.retain(|_, t| now.duration_since(*t) < REPEAT);
        // shortcut: still full means > 100k distinct bad files an hour; forget them all then
        if m.len() >= MAX_SEEN {
            m.clear();
        }
    }
    let key = (tenant.to_string(), agent.to_string(), hash.to_string());
    match m.get(&key) {
        Some(t) if now.duration_since(*t) < REPEAT => true,
        _ => {
            m.insert(key, now);
            false
        }
    }
}

/// The alerts of a batch of archived events (each with its tenant).
pub fn check(events: &[(Value, String)]) -> Vec<(siem_core::Alert, String)> {
    let mut out = Vec::new();
    for (v, tenant) in events {
        let Some(f) = file_of(v) else { continue };
        let Some((hash, hits)) = f.hashes.iter().map(|h| (h, crate::intel::lookup_for(tenant, h))).find(|(_, hits)| !hits.is_empty()) else {
            continue;
        };
        let agent = v["agent"]["id"].as_str().unwrap_or("");
        // written and then run: both are reported
        if reported_recently(tenant, agent, &format!("{hash}:{}", f.executed)) {
            continue;
        }
        out.push((alert_for(v, &f, hash, &hits), tenant.clone()));
    }
    out
}

fn alert_for(v: &Value, f: &FileSeen, hash: &str, hits: &[crate::intel::Hit]) -> siem_core::Alert {
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    let sources: Vec<&str> = hits.iter().map(|h| h.source.as_str()).collect();
    let name = f.path.rsplit(['\\', '/']).next().filter(|n| !n.is_empty()).unwrap_or(hash);
    let (id, level, technique) = if f.executed { (RULE_EXECUTED, 14, ("T1204.002", "Execution", "Malicious File")) } else { (RULE_FILE, 12, ("T1105", "Command and Control", "Ingress Tool Transfer")) };
    let mut data: HashMap<String, Value> = v["data"].as_object().map(|o| o.iter().map(|(k, x)| (k.clone(), x.clone())).collect()).unwrap_or_default();
    data.insert("file_reputation".into(), json!({ "hash": hash, "path": f.path, "event": f.event, "hits": hits }));
    let ed = &v["data"]["win"]["eventdata"];
    siem_core::Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: v["timestamp"].as_str().and_then(|t| chrono::DateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.3f%z").ok()).map(|t| t.with_timezone(&chrono::Utc)).unwrap_or_else(chrono::Utc::now),
        rule: siem_core::RuleAlertInfo {
            id,
            level,
            description: format!("Known malware {}: {name} ({})", f.event, sources.join(", ")),
            groups: vec!["edr".into(), "malware".into(), "threat_intel".into()],
            mitre: Some(siem_core::MitreAttack { id: technique.0.into(), tactic: technique.1.into(), technique: technique.2.into() }),
        },
        agent: siem_core::AgentAlertInfo { id: s(&v["agent"]["id"]), name: s(&v["agent"]["name"]), ip: s(&v["agent"]["ip"]) },
        manager: None,
        decoder: None,
        full_log: format!("{} {} (sha/md5 {hash}) listed by {}", f.event, f.path, sources.join(", ")),
        decoded: siem_core::DecodedFields {
            decoder_name: s(&v["decoder"]["name"]),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            user: ed["user"].as_str().map(|u| u.replace("\\\\", "\\")),
            program_name: None,
            process_id: ed["processId"].as_str().and_then(|p| p.parse().ok()),
            file_path: Some(f.path.clone()).filter(|p| !p.is_empty()),
            action: None,
            status: None,
            extra: HashMap::new(),
        },
        location: s(&v["location"]),
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sysmon(eid: &str, ed: Value) -> Value {
        json!({ "agent": { "id": "007" }, "data": { "win": { "system": { "channel": "Microsoft-Windows-Sysmon/Operational", "eventID": eid }, "eventdata": ed } } })
    }

    #[test]
    fn files_and_hashes_of_events() {
        let sha = "a".repeat(64);
        let md5 = "B".repeat(32);
        let f = file_of(&sysmon("1", json!({ "image": "C:\\\\Users\\\\x\\\\evil.exe", "hashes": format!("MD5={md5},SHA256={sha},IMPHASH={}", "c".repeat(32)) }))).unwrap();
        assert_eq!(f, FileSeen { path: "C:\\Users\\x\\evil.exe".into(), hashes: vec!["b".repeat(32), sha.clone()], executed: true, event: "process started" });
        assert!(!file_of(&sysmon("29", json!({ "targetFilename": "C:\\\\t\\\\a.exe", "hashes": format!("SHA256={sha}") }))).unwrap().executed);
        assert_eq!(file_of(&sysmon("15", json!({ "targetFilename": "x", "hash": format!("SHA256={sha}") }))).unwrap().hashes, vec![sha.clone()]);
        assert!(file_of(&sysmon("1", json!({ "image": "x", "hashes": "IMPHASH=abc" }))).is_none(), "an import hash names no file");
        assert!(file_of(&sysmon("3", json!({ "image": "x" }))).is_none(), "network events carry no file");
        let fim = json!({ "syscheck": { "path": "/usr/bin/x", "sha256_after": sha, "md5_after": "" } });
        assert_eq!(file_of(&fim).unwrap().hashes, vec![sha]);
    }

    #[test]
    fn one_alert_per_agent_and_file_an_hour() {
        let h = "f".repeat(64);
        assert!(!reported_recently("t", "001", &h));
        assert!(reported_recently("t", "001", &h));
        assert!(!reported_recently("t", "002", &h), "another agent");
        assert!(!reported_recently("u", "001", &h), "another tenant");
    }
}
