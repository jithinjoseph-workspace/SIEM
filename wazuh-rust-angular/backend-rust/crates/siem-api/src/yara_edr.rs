//! EDR YARA scanning: the rules (YARA Forge core, fetched daily over HTTPS, installed only
//! when the whole set compiles, plus the SIEM's harmless test rule) go to every agent as
//! `shared/siem-yara.rules`, compressed and base64-encoded (never as plain text: antivirus
//! takes YARA strings for malware); the manager asks a Windows agent's `yara-scan` program to scan
//! the new executables and the programs started from user-writable folders its Sysmon
//! reports, and turns the results into alerts (rule 940102).
//!
//! Each file content (SHA-256) is scanned once per rule version and tenant: a file already
//! known to match alerts on any other agent at once, a clean one is not scanned again. At
//! most 20 automatic scans per agent in 10 minutes. `GET /api/v1/edr/yara`: the rule set.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

pub const RULE_MATCH: u32 = 940102;

const SOURCE: &str = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
const SHARED_NAME: &str = "siem-yara.rules";
const MAX_DOWNLOAD: usize = 64 * 1024 * 1024;
const SCANS_PER_WINDOW: usize = 20;
const WINDOW: Duration = Duration::from_secs(600);
const RESCAN_AFTER: Duration = Duration::from_secs(3600);
const MAX_CACHE: usize = 200_000;

#[derive(Default, Clone, serde::Serialize)]
struct RuleSet {
    version: String,
    rules: usize,
    updated_at: u64,
    source: String,
    last_error: Option<String>,
}

fn rule_set() -> &'static RwLock<RuleSet> {
    static R: OnceLock<RwLock<RuleSet>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(RuleSet::default()))
}

/// The rule set's version, as the agent computes it (the first 8 bytes of its SHA-256).
pub fn version_of(text: &str) -> String {
    Sha256::digest(text.as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn store() -> PathBuf {
    crate::data_file_path("yara").join("current.rules")
}

/// Writes the rules where remoted sends them from: every group's shared folder (only when
/// the content changed, so agents download it once per version).
fn install(text: &str) -> Result<(), String> {
    let stored = siem_active_response::yara::encode_rules(text);
    let _ = std::fs::create_dir_all(store().parent().unwrap_or(std::path::Path::new(".")));
    std::fs::write(store(), &stored).map_err(|e| format!("{}: {e}", store().display()))?;
    let shared = crate::wazuh_manager::home().join("etc").join("shared");
    for d in std::fs::read_dir(&shared).map_err(|e| format!("{}: {e}", shared.display()))?.flatten() {
        if !d.path().is_dir() {
            continue;
        }
        // the plain-text file of the first version
        let _ = std::fs::remove_file(d.path().join("siem-yara.yar"));
        let f = d.path().join(SHARED_NAME);
        if std::fs::read_to_string(&f).ok().as_deref() != Some(stored.as_str()) {
            std::fs::write(&f, &stored).map_err(|e| format!("{}: {e}", f.display()))?;
        }
    }
    Ok(())
}

/// The core rules of the YARA Forge release zip with the test rule, compiled to check them.
async fn fetch() -> Result<(String, usize), String> {
    let resp = reqwest::Client::new().get(SOURCE).timeout(Duration::from_secs(180)).send().await.map_err(|e| format!("download: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("download: HTTP {}", resp.status().as_u16()));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("download: {e}"))?;
    if bytes.len() > MAX_DOWNLOAD {
        return Err("download larger than 64 MB".into());
    }
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| format!("zip: {e}"))?;
    let name = zip.file_names().find(|n| n.ends_with(".yar")).map(String::from).ok_or("no .yar file in the release")?;
    let mut core = String::new();
    std::io::Read::read_to_string(&mut std::io::Read::take(zip.by_name(&name).map_err(|e| format!("zip: {e}"))?, MAX_DOWNLOAD as u64), &mut core).map_err(|e| format!("zip: {e}"))?;
    let text = format!("{core}\n{}", siem_active_response::yara::TEST_RULE);
    let checked = text.clone();
    let rules = tokio::task::spawn_blocking(move || siem_active_response::yara::compile(&checked).map(|s| s.rules().count()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("the rules do not compile: {e}"))?;
    Ok((text, rules))
}

fn set(text: &str, rules: usize, source: &str) {
    *rule_set().write().unwrap() = RuleSet { version: version_of(text), rules, updated_at: chrono::Utc::now().timestamp().max(0) as u64, source: source.into(), last_error: None };
}

/// Installs the last rule set at start, then a new one every day (an hour after a failure).
pub fn spawn() {
    tokio::spawn(async {
        if let Some(text) = std::fs::read_to_string(store()).ok().and_then(|s| siem_active_response::yara::decode_rules(&s).ok()) {
            let rules = text.matches("\nrule ").count() + text.matches("\nprivate rule ").count();
            match install(&text) {
                Ok(()) => set(&text, rules, "last download"),
                Err(e) => warn!("YARA rules: {e}"),
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let wait = match fetch().await {
                Ok((text, rules)) => {
                    let changed = rule_set().read().unwrap().version != version_of(&text);
                    match install(&text) {
                        Ok(()) => {
                            set(&text, rules, SOURCE);
                            if changed {
                                info!("YARA rules: {rules} rules (version {}) sent to the agents", version_of(&text));
                            }
                            Duration::from_secs(24 * 3600)
                        }
                        Err(e) => {
                            warn!("YARA rules: {e}");
                            Duration::from_secs(3600)
                        }
                    }
                }
                Err(e) => {
                    warn!("YARA rules not updated: {e}");
                    rule_set().write().unwrap().last_error = Some(e);
                    Duration::from_secs(3600)
                }
            };
            tokio::time::sleep(wait).await;
        }
    });
}

/// `GET /api/v1/edr/yara`
pub async fn status() -> Json<Value> {
    Json(json!({ "status": "ok", "rules": *rule_set().read().unwrap() }))
}

// ───────────────────────── triggers and results ─────────────────────────

struct Memory {
    /// (tenant, sha256) -> (rule version, rules matched)
    verdicts: HashMap<(String, String), (String, Vec<String>)>,
    /// (tenant, agent, sha256 or path) -> when asked
    asked: HashMap<(String, String, String), Instant>,
    /// agent -> its recent automatic scans
    recent: HashMap<String, VecDeque<Instant>>,
}

fn memory() -> &'static Mutex<Memory> {
    static M: OnceLock<Mutex<Memory>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(Memory { verdicts: HashMap::new(), asked: HashMap::new(), recent: HashMap::new() }))
}

/// Folders a user (or malware without admin rights) can write to.
fn user_writable(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("\\users\\") || p.contains("\\$recycle.bin\\") || ["c:\\programdata\\", "c:\\windows\\temp\\", "c:\\perflogs\\"].iter().any(|r| p.starts_with(r))
}

const SCANNED_EXT: [&str; 11] = ["exe", "dll", "scr", "sys", "ps1", "vbs", "js", "jse", "hta", "bat", "msi"];

/// The file a Sysmon event asks to scan: (path, sha256 if known).
fn candidate(v: &Value) -> Option<(String, Option<String>)> {
    let win = &v["data"]["win"];
    if win["system"]["channel"].as_str() != Some("Microsoft-Windows-Sysmon/Operational") {
        return None;
    }
    let ed = &win["eventdata"];
    let s = |k: &str| ed[k].as_str().unwrap_or("").replace("\\\\", "\\");
    let path = match win["system"]["eventID"].as_str()? {
        "1" => s("image"),
        "29" => s("targetFilename"),
        "11" => {
            let p = s("targetFilename");
            let ext = p.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
            if !SCANNED_EXT.contains(&ext.as_str()) {
                return None;
            }
            p
        }
        _ => return None,
    };
    if path.is_empty() || !user_writable(&path) {
        return None;
    }
    let sha = ed["hashes"].as_str().and_then(|h| h.split(',').find_map(|p| p.trim().strip_prefix("SHA256=").map(|x| x.to_ascii_lowercase())));
    Some((path, sha))
}

/// A `yara-scan` result line from the agent's active-responses.log.
fn result_of(v: &Value) -> Option<Value> {
    let log = v["full_log"].as_str()?;
    if !log.contains("yara-scan") {
        return None;
    }
    let r: Value = serde_json::from_str(&log[log.find('{')?..]).ok()?;
    (r["script"] == "yara-scan").then_some(r)
}

/// Per batch of archived events: the alerts (scan results that matched, and files already
/// known to match) and the scans to ask for (tenant, agent, path).
pub fn check(events: &[(Value, String)]) -> (Vec<(siem_core::Alert, String)>, Vec<(String, String, String)>) {
    let current = rule_set().read().unwrap().version.clone();
    let mut alerts = Vec::new();
    let mut scans = Vec::new();
    let mut m = memory().lock().unwrap();
    let now = Instant::now();
    for (v, tenant) in events {
        let agent = v["agent"]["id"].as_str().unwrap_or("").to_string();
        if agent.is_empty() || agent == "000" {
            continue;
        }
        if let Some(r) = result_of(v) {
            let (Some(sha), Some(version)) = (r["sha256"].as_str(), r["rules_version"].as_str()) else { continue };
            let rules: Vec<String> = r["rules"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            if m.verdicts.len() >= MAX_CACHE {
                // shortcut: a full cache starts again (files get scanned once more)
                m.verdicts.clear();
            }
            m.verdicts.insert((tenant.clone(), sha.to_string()), (version.to_string(), rules.clone()));
            if !rules.is_empty() && !crate::file_reputation::reported_recently(tenant, &agent, &format!("{sha}:yara")) {
                alerts.push((alert_for(v, r["path"].as_str().unwrap_or(""), sha, &rules), tenant.clone()));
            }
            continue;
        }
        let Some((path, sha)) = candidate(v) else { continue };
        if let Some((version, rules)) = sha.as_ref().and_then(|h| m.verdicts.get(&(tenant.clone(), h.clone()))).filter(|(ver, _)| *ver == current) {
            let _ = version;
            if !rules.is_empty() && !crate::file_reputation::reported_recently(tenant, &agent, &format!("{}:yara", sha.as_deref().unwrap_or(""))) {
                alerts.push((alert_for(v, &path, sha.as_deref().unwrap_or(""), &rules.clone()), tenant.clone()));
            }
            continue;
        }
        let key = (tenant.clone(), agent.clone(), sha.clone().unwrap_or_else(|| path.to_ascii_lowercase()));
        if m.asked.get(&key).is_some_and(|t| now.duration_since(*t) < RESCAN_AFTER) {
            continue;
        }
        let q = m.recent.entry(agent.clone()).or_default();
        while q.front().is_some_and(|t| now.duration_since(*t) > WINDOW) {
            q.pop_front();
        }
        if q.len() >= SCANS_PER_WINDOW {
            continue;
        }
        q.push_back(now);
        if m.asked.len() >= MAX_CACHE {
            m.asked.retain(|_, t| now.duration_since(*t) < RESCAN_AFTER);
        }
        m.asked.insert(key, now);
        scans.push((tenant.clone(), agent, path));
    }
    (alerts, scans)
}

fn alert_for(v: &Value, path: &str, sha: &str, rules: &[String]) -> siem_core::Alert {
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    let name = path.rsplit(['\\', '/']).next().filter(|n| !n.is_empty()).unwrap_or(sha);
    let shown: Vec<&str> = rules.iter().take(3).map(String::as_str).collect();
    let more = if rules.len() > 3 { format!(" and {} more", rules.len() - 3) } else { String::new() };
    let mut data: HashMap<String, Value> = v["data"].as_object().map(|o| o.iter().map(|(k, x)| (k.clone(), x.clone())).collect()).unwrap_or_default();
    data.insert("yara".into(), json!({ "rules": rules, "path": path, "sha256": sha, "rules_version": rule_set().read().unwrap().version }));
    siem_core::Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        rule: siem_core::RuleAlertInfo {
            id: RULE_MATCH,
            level: 13,
            description: format!("YARA match in {name}: {}{more}", shown.join(", ")),
            groups: vec!["edr".into(), "malware".into(), "yara".into()],
            mitre: Some(siem_core::MitreAttack { id: "T1204.002".into(), tactic: "Execution".into(), technique: "Malicious File".into() }),
        },
        agent: siem_core::AgentAlertInfo { id: s(&v["agent"]["id"]), name: s(&v["agent"]["name"]), ip: s(&v["agent"]["ip"]) },
        manager: None,
        decoder: None,
        full_log: format!("YARA rules {} matched {path} (sha256 {sha})", rules.join(", ")),
        decoded: siem_core::DecodedFields {
            decoder_name: "yara".into(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            user: None,
            program_name: None,
            process_id: None,
            file_path: Some(path.to_string()).filter(|p| !p.is_empty()),
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

    fn sysmon(agent: &str, eid: &str, ed: Value) -> Value {
        json!({ "agent": { "id": agent, "name": "pc" }, "data": { "win": { "system": { "channel": "Microsoft-Windows-Sysmon/Operational", "eventID": eid }, "eventdata": ed } } })
    }

    fn ar(agent: &str, r: Value) -> Value {
        json!({ "agent": { "id": agent, "name": "pc" }, "location": "active-response\\active-responses.log",
                "full_log": format!("2026/10/29 10:00:00 C:\\Program Files (x86)\\ossec-agent\\active-response\\bin\\yara-scan.exe: {r}") })
    }

    #[test]
    fn scans_once_alerts_on_match_and_on_known_files() {
        let sha = "ab".repeat(32);
        let ev = |agent: &str| sysmon(agent, "1", json!({ "image": "C:\\\\Users\\\\a\\\\Downloads\\\\x.exe", "hashes": format!("MD5={},SHA256={}", "1".repeat(32), sha.to_uppercase()) }));
        let t = "yara-test-tenant".to_string();
        // first sight: one scan asked, not twice
        let (a, s) = check(&[(ev("101"), t.clone()), (ev("101"), t.clone())]);
        assert!(a.is_empty());
        assert_eq!(s, [(t.clone(), "101".to_string(), "C:\\Users\\a\\Downloads\\x.exe".to_string())]);
        // Windows' own folders are not scanned
        let sys = sysmon("101", "1", json!({ "image": "C:\\\\Windows\\\\System32\\\\notepad.exe", "hashes": "SHA256=cd" }));
        assert!(check(&[(sys, t.clone())]).1.is_empty());
        // the agent reports a match: an alert, with the file to quarantine
        let version = rule_set().read().unwrap().version.clone();
        let res = ar("101", json!({ "path": "C:\\Users\\a\\Downloads\\x.exe", "sha256": sha, "rules": ["Evil_Rule"], "rules_version": version, "status": "match", "script": "yara-scan" }));
        let (a, _) = check(&[(res, t.clone())]);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].0.rule.id, a[0].0.decoded.file_path.as_deref()), (RULE_MATCH, Some("C:\\Users\\a\\Downloads\\x.exe")));
        // the same file on another agent: an alert at once, no scan
        let (a, s) = check(&[(ev("102"), t.clone())]);
        assert_eq!((a.len(), s.len()), (1, 0));
    }

    #[test]
    fn at_most_20_automatic_scans_per_agent_in_10_minutes() {
        let t = "yara-rate-tenant".to_string();
        let evs: Vec<(Value, String)> = (0..30).map(|i| (sysmon("201", "29", json!({ "targetFilename": format!("C:\\\\Users\\\\a\\\\f{i}.exe"), "hashes": format!("SHA256={:064x}", i) })), t.clone())).collect();
        assert_eq!(check(&evs).1.len(), SCANS_PER_WINDOW);
        let other = sysmon("202", "11", json!({ "targetFilename": "C:\\\\ProgramData\\\\x\\\\run.ps1" }));
        assert_eq!(check(&[(other, t.clone())]).1.len(), 1, "another agent has its own budget; scripts without a hash too");
        let txt = sysmon("202", "11", json!({ "targetFilename": "C:\\\\Users\\\\a\\\\notes.txt" }));
        assert!(check(&[(txt, t)]).1.is_empty(), "not an executable or script");
    }
}
