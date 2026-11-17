//! What ProVigil itself does on a computer, recognised so it raises no alert (provigil_manager
//! `deliver`, before anything is stored):
//!
//! - **the agent's own programs**: a process whose parent is the agent at its install path
//!   (`<drive>:\Program Files[ (x86)]\ProVigil Agent\provigil-agent.exe`, or a response program
//!   in its `active-response\bin`), and every process those start, followed by process id (Sysmon
//!   process creation gives each new process's id and its parent's). Matched by exact path, so a
//!   program merely called `provigil-agent.exe` elsewhere still alerts. A process id is
//!   forgotten after 30 minutes, and re-decided whenever a new process takes it;
//! - **the installer's files**: a file the console's install command downloads into
//!   `Temp\provigil-<guid>\` whose name is one of the published agent files, and whose SHA-256,
//!   when the event carries it, is the published one;
//! - **the configuration assessment baseline**: a check result seen for the first time (no
//!   previous result: a new install or a wiped database) is stored on the compliance page, not
//!   alerted; a result that changed still alerts.
//!
//! The process ids are also learned from every archived event (`learn`), so a program the
//! agent starts is known even when it raised no alert itself.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use siem_core::Alert;

const KEEP: Duration = Duration::from_secs(30 * 60);
const MAX: usize = 200_000;

/// (agent id, process id) -> when it was known to be ProVigil's
static OWN: LazyLock<Mutex<HashMap<(String, String), Instant>>> = LazyLock::new(Default::default);

fn field(ed: &Value, k: &str) -> String {
    // the event channel decoder doubles backslashes
    ed.get(k).and_then(Value::as_str).unwrap_or_default().replace("\\\\", "\\")
}

/// The agent or one of its response programs, at the install path.
pub fn agent_program(path: &str) -> bool {
    let p = path.trim_matches('"').to_ascii_lowercase().replace('/', "\\");
    let Some(rest) = p.get(2..).filter(|_| p.as_bytes().get(1) == Some(&b':')) else { return false };
    let Some(inside) = rest.strip_prefix("\\program files\\provigil agent\\").or_else(|| rest.strip_prefix("\\program files (x86)\\provigil agent\\")) else { return false };
    inside == "provigil-agent.exe" || (inside.starts_with("active-response\\bin\\") && inside.ends_with(".exe") && !inside[20..].contains('\\'))
}

/// Records what this event says about ProVigil's processes; whether the event is ProVigil's own.
pub fn see(agent: &str, ed: &Value) -> bool {
    if agent.is_empty() {
        return false;
    }
    let (image, parent, pid, ppid) = (field(ed, "image"), field(ed, "parentImage"), field(ed, "processId"), field(ed, "parentProcessId"));
    let mut own = OWN.lock().unwrap();
    let now = Instant::now();
    let known = |own: &HashMap<(String, String), Instant>, p: &str| !p.is_empty() && own.get(&(agent.to_string(), p.to_string())).is_some_and(|t| now.duration_since(*t) < KEEP);
    // a process start decides its id: ProVigil's, or not (an id can be reused)
    if ed.get("parentProcessId").is_some() || ed.get("parentImage").is_some() {
        let mine = agent_program(&parent) || agent_program(&image) || known(&own, &ppid);
        if !pid.is_empty() {
            if mine {
                if own.len() >= MAX {
                    own.retain(|_, t| now.duration_since(*t) < KEEP);
                }
                own.insert((agent.to_string(), pid), now);
            } else {
                own.remove(&(agent.to_string(), pid));
            }
        }
        return mine;
    }
    // anything else a process does (a file, a connection, a registry value)
    agent_program(&image) || known(&own, &pid)
}

/// Learns from every archived event (`{agent: {id}, data: {win: {eventdata}}}`).
pub fn learn(v: &Value) {
    if let (Some(agent), Some(ed)) = (v.pointer("/agent/id").and_then(Value::as_str), v.pointer("/data/win/eventdata")) {
        see(agent, ed);
    }
}

/// A file the install command downloads: `...\Temp\provigil-<guid>\<published file>`.
pub fn installer_file(target: &str, sha256: &str, published: &std::collections::BTreeMap<String, String>) -> bool {
    let t = target.to_ascii_lowercase().replace('/', "\\");
    let Some((dir, name)) = t.rsplit_once('\\') else { return false };
    let Some((parent, folder)) = dir.rsplit_once('\\') else { return false };
    let guid = folder.strip_prefix("provigil-").unwrap_or("");
    let guid_ok = guid.len() == 36 && guid.chars().all(|c| c.is_ascii_hexdigit() || c == '-') && guid.matches('-').count() == 4;
    if !guid_ok || !parent.ends_with("\\temp") {
        return false;
    }
    match published.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
        Some((_, h)) => sha256.is_empty() || sha256.eq_ignore_ascii_case(h),
        None => false,
    }
}

/// Why an alert is ProVigil's own activity (None: a real alert).
pub fn reason(a: &Alert, published: &std::collections::BTreeMap<String, String>) -> Option<&'static str> {
    if a.rule.groups.iter().any(|g| g == "sca") {
        let sca = a.data.get("sca");
        let check = sca.and_then(|s| s.get("check"));
        if sca.and_then(|s| s.get("type")).and_then(Value::as_str) == Some("check") && check.and_then(|c| c.get("previous_result")).is_none() {
            return Some("configuration check baseline");
        }
    }
    let ed = a.data.get("win").and_then(|w| w.get("eventdata"))?;
    if see(&a.agent.id, ed) {
        return Some("ProVigil agent's own program");
    }
    let sha = field(ed, "hashes").split(',').find_map(|h| h.trim().strip_prefix("SHA256=").map(str::to_string)).unwrap_or_default();
    installer_file(&field(ed, "targetFilename"), &sha, published).then_some("ProVigil installer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const AGENT: &str = r"C:\Program Files (x86)\ProVigil Agent\provigil-agent.exe";

    #[test]
    fn the_agent_by_exact_path_only() {
        assert!(agent_program(AGENT));
        assert!(agent_program(r"D:\Program Files\ProVigil Agent\provigil-agent.exe"));
        assert!(agent_program(r"C:\Program Files (x86)\ProVigil Agent\active-response\bin\netsh.exe"));
        assert!(!agent_program(r"C:\Users\x\AppData\Local\Temp\provigil-agent.exe"), "the name elsewhere");
        assert!(!agent_program(r"C:\Program Files (x86)\ProVigil Agent\tools\provigil-agent.exe"));
        assert!(!agent_program(r"C:\Program Files (x86)\ProVigil Agent\active-response\bin\sub\x.exe"));
    }

    #[test]
    fn children_and_grandchildren_followed_by_process_id() {
        let a = "test-own-1";
        // the agent starts cmd (pid 100), which starts powershell (pid 200)
        assert!(see(a, &json!({ "image": r"C:\Windows\System32\cmd.exe", "parentImage": AGENT, "processId": "100", "parentProcessId": "50" })));
        assert!(see(a, &json!({ "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "parentImage": r"C:\Windows\System32\cmd.exe", "processId": "200", "parentProcessId": "100" })));
        // something powershell does
        assert!(see(a, &json!({ "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "processId": "200", "targetFilename": "x" })));
        // another agent's pid 200 is not ours
        assert!(!see("test-own-2", &json!({ "image": "x.exe", "processId": "200", "targetFilename": "x" })));
        // pid 100 reused by an unrelated process: no longer ours
        assert!(!see(a, &json!({ "image": r"C:\Windows\System32\cmd.exe", "parentImage": r"C:\Windows\explorer.exe", "processId": "100", "parentProcessId": "9" })));
        assert!(!see(a, &json!({ "image": r"C:\Windows\System32\cmd.exe", "processId": "100", "targetFilename": "x" })));
        // a program called provigil-agent.exe elsewhere starting cmd
        assert!(!see(a, &json!({ "image": r"C:\Windows\System32\cmd.exe", "parentImage": r"C:\Temp\provigil-agent.exe", "processId": "300", "parentProcessId": "7" })));
    }

    #[test]
    fn installer_files_by_folder_name_and_hash() {
        let published = std::collections::BTreeMap::from([("provigil-agent.exe".to_string(), "ab".repeat(32)), ("netsh.exe".to_string(), "cd".repeat(32))]);
        let t = r"C:\Users\josep\AppData\Local\Temp\provigil-1a519fe0-9963-4f48-9371-83c0163d27ba\provigil-agent.exe";
        assert!(installer_file(t, "", &published));
        assert!(installer_file(t, &"AB".repeat(32), &published));
        assert!(!installer_file(t, &"ef".repeat(32), &published), "another file under that name");
        assert!(!installer_file(r"C:\Users\x\AppData\Local\Temp\provigil-1a519fe0-9963-4f48-9371-83c0163d27ba\evil.exe", "", &published));
        assert!(!installer_file(r"C:\Users\x\Downloads\provigil-1a519fe0-9963-4f48-9371-83c0163d27ba\netsh.exe", "", &published), "not a temp folder");
        assert!(!installer_file(r"C:\Users\x\AppData\Local\Temp\provigil-x\netsh.exe", "", &published), "not a guid");
    }

    fn alert(groups: &[&str], data: Value) -> Alert {
        Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            rule: siem_core::RuleAlertInfo { id: 1, level: 7, description: "d".into(), groups: groups.iter().map(|g| g.to_string()).collect(), mitre: None },
            agent: siem_core::AgentAlertInfo { id: "test-own-3".into(), name: "pc".into(), ip: String::new() },
            manager: None,
            decoder: None,
            full_log: String::new(),
            decoded: Default::default(),
            location: String::new(),
            data: data.as_object().unwrap().clone().into_iter().collect(),
        }
    }

    #[test]
    fn baseline_checks_not_alerted_changes_are() {
        let p = Default::default();
        assert_eq!(reason(&alert(&["sca"], json!({ "sca": { "type": "check", "check": { "result": "failed" } } })), &p), Some("configuration check baseline"));
        assert_eq!(reason(&alert(&["sca"], json!({ "sca": { "type": "check", "check": { "result": "failed", "previous_result": "passed" } } })), &p), None);
        assert_eq!(reason(&alert(&["sca"], json!({ "sca": { "type": "summary" } })), &p), None, "a score alert stays");
        assert_eq!(reason(&alert(&["windows"], json!({ "win": { "eventdata": { "image": "x.exe", "parentImage": AGENT, "processId": "5", "parentProcessId": "1" } } })), &p), Some("ProVigil agent's own program"));
        assert_eq!(reason(&alert(&["windows"], json!({ "win": { "eventdata": { "image": "x.exe", "parentImage": r"C:\Windows\explorer.exe", "processId": "6", "parentProcessId": "1" } } })), &p), None);
    }
}
