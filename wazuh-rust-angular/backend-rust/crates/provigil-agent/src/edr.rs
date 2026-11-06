//! Runs the manager's response commands with ProVigil's response programs
//! (`active-response\bin\*.exe`, crate `siem-active-response`).
//!
//! The manager queues, for the next keepalive:
//! - `{"type":"ar","message":{"command":"isolate-host600","parameters":{...}}}`: the command
//!   name ends in its timeout in seconds (0: none). The program gets one JSON line on its input
//!   (`command` = `add`); when the timeout is up it runs again with `delete` (unblock, release,
//!   lock again). Pending undos are kept in `data\ar_timeouts.json` over agent restarts.
//!   Repeated offenders (`ar_repeated_offenders`): a key that already ran N times in the last
//!   24 h gets the N-th configured timeout; its run times are kept in the same file.
//! - `{"type":"scan"}`: an immediate file integrity, rootcheck and configuration assessment scan.
//! - `{"type":"sca_full","policy_id":...}`, `{"type":"inventory_full"}`: the manager's data is not
//!   what the agent sent (a new or wiped database): a scan now, sent in full.
//!
//! A program that can be undone first asks `check_keys` on its output: it gets `abort` while
//! the same key is still active (the block or isolation is already in place; its undo is then
//! moved to the new timeout), else `continue`.
//! The programs log their results to `active-response\active-responses.log`, which the agent
//! sends to the manager (see `lib.rs`).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Notify;
use tracing::{info, warn};

/// How long one program may run (a YARA scan of a big folder takes a while).
const RUN_LIMIT: Duration = Duration::from_secs(600);
/// The program that stops this service and starts it again.
const RESTART_PROGRAM: &str = "restart-agent";
/// The pending undos, kept over agent restarts.
pub const TIMEOUTS_FILE: &str = "data/ar_timeouts.json";

/// A response in force and its undo: `due` in Unix seconds (None: no timeout, kept in force
/// only while its program runs).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Undo {
    program: String,
    key: String,
    command: String,
    parameters: Value,
    due: Option<i64>,
}

/// `ar_timeouts.json`: the pending undos and the run times (Unix seconds) per `program key`.
#[derive(Default, Serialize, Deserialize)]
struct Saved {
    undos: Vec<Undo>,
    #[serde(default)]
    runs: HashMap<String, Vec<i64>>,
}

/// Runs older than this do not count as repeats.
const REPEAT_WINDOW: i64 = 86_400;

pub struct EdrExecutor {
    /// Responses in force by (program, key): a repeat is not applied twice but extends the undo.
    active: Mutex<HashMap<(String, String), Undo>>,
    timeouts: PathBuf,
    /// Timed runs in the last 24 h per `program key`.
    runs: Mutex<HashMap<String, Vec<i64>>>,
    /// `ar_repeated_offenders`, in minutes.
    pub repeated_offenders: Mutex<Vec<u64>>,
    /// `active_response_enabled`.
    pub enabled: AtomicBool,
    /// Woken by a `scan` command: the file integrity, rootcheck and configuration assessment loops.
    pub scan_fim: Arc<Notify>,
    pub scan_rootcheck: Arc<Notify>,
    pub scan_sca: Arc<Notify>,
    /// The policies the manager wants in full at the next configuration assessment.
    pub sca_full: Arc<Mutex<HashSet<String>>>,
    /// Woken by `inventory_full`.
    pub inventory_full: Arc<Notify>,
}

/// `isolate-host600` -> (`isolate-host`, 600).
pub fn split_command(name: &str) -> (String, u64) {
    let digits = name.len() - name.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    let (base, t) = name.split_at(name.len() - digits);
    (base.to_string(), t.parse().unwrap_or(0))
}

/// The program a command runs: release and unlock are the isolate and tamper programs.
pub fn program_of(base: &str) -> &str {
    match base {
        "release-host" => "isolate-host",
        "tamper-unlock" => "tamper-protect",
        // the manager's response config names the restart command after the old agent
        "restart-wazuh" => RESTART_PROGRAM,
        b => b,
    }
}

/// Only letters, digits, `-` and `_`: the name stays inside `active-response\bin`.
fn valid_name(name: &str) -> bool {
    name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn program_path(program: &str) -> PathBuf {
    let exe = if cfg!(windows) { format!("{program}.exe") } else { program.to_string() };
    PathBuf::from("active-response").join("bin").join(exe)
}

/// The restart program stops this service before it starts it again: it must outlive the agent.
fn detach(c: &mut tokio::process::Command, detached: bool) {
    c.kill_on_drop(!detached);
    // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, else CREATE_NO_WINDOW
    #[cfg(windows)]
    c.creation_flags(if detached { 0x0000_0008 | 0x0000_0200 } else { 0x0800_0000 });
}

/// The request line a response program reads.
fn request(name: &str, command: &str, parameters: &Value) -> String {
    let parameters = if parameters.is_object() { parameters.clone() } else { json!({ "extra_args": [], "alert": {} }) };
    format!("{}\n", json!({ "version": 1, "origin": { "name": name, "module": "provigil-agent" }, "command": command, "parameters": parameters }))
}

fn answer(command: &str) -> String {
    format!("{}\n", json!({ "version": 1, "origin": { "name": "provigil-agent", "module": "provigil-agent" }, "command": command, "parameters": {} }))
}

impl EdrExecutor {
    pub fn new() -> Self {
        Self::with_timeouts(TIMEOUTS_FILE)
    }

    pub fn with_timeouts(timeouts: impl Into<PathBuf>) -> Self {
        EdrExecutor {
            active: Mutex::default(),
            timeouts: timeouts.into(),
            runs: Mutex::default(),
            repeated_offenders: Mutex::default(),
            enabled: AtomicBool::new(true),
            scan_fim: Arc::new(Notify::new()),
            scan_rootcheck: Arc::new(Notify::new()),
            scan_sca: Arc::new(Notify::new()),
            sca_full: Arc::default(),
            inventory_full: Arc::new(Notify::new()),
        }
    }

    /// The undos saved before the last stop: overdue ones run now, the others at their time.
    pub fn restore(self: &Arc<Self>) {
        let Ok(text) = std::fs::read_to_string(&self.timeouts) else { return };
        // a plain list: the file as agents before repeated offenders wrote it
        let saved = serde_json::from_str::<Saved>(&text)
            .or_else(|_| serde_json::from_str::<Vec<Undo>>(&text).map(|undos| Saved { undos, ..Saved::default() }))
            .unwrap_or_else(|e| {
                warn!(error = %e, file = %self.timeouts.display(), "Pending response undos not readable");
                Saved::default()
            });
        *self.runs.lock().unwrap() = saved.runs;
        for u in saved.undos.into_iter().filter(|u| u.due.is_some()) {
            let k = (u.program.clone(), u.key.clone());
            self.active.lock().unwrap().insert(k.clone(), u);
            self.arm(k);
        }
    }

    fn save(&self) {
        let undos: Vec<Undo> = self.active.lock().unwrap().values().filter(|u| u.due.is_some()).cloned().collect();
        let list = Saved { undos, runs: self.runs.lock().unwrap().clone() };
        let saved = self
            .timeouts
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|_| std::fs::write(&self.timeouts, serde_json::to_string(&list).unwrap_or_default()));
        if let Err(e) = saved {
            warn!(error = %e, "Pending response undos not saved");
        }
    }

    /// Whether `k` is already in force (its undo then moves to `timeout` from now, when that is
    /// later); else it is recorded as in force.
    fn claim(&self, k: &(String, String), name: &str, params: &Value, timeout: u64) -> bool {
        let now = chrono::Utc::now().timestamp();
        let timeout = self.repeat_timeout(k, timeout, now);
        let due = (timeout > 0).then(|| now + timeout as i64);
        let mut active = self.active.lock().unwrap();
        if let Some(u) = active.get_mut(k) {
            u.due = u.due.max(due);
            return true;
        }
        if timeout > 0 {
            self.runs.lock().unwrap().entry(format!("{} {}", k.0, k.1)).or_default().push(now);
        }
        active.insert(k.clone(), Undo { program: k.0.clone(), key: k.1.clone(), command: name.into(), parameters: params.clone(), due });
        false
    }

    /// A timed response's timeout: the `ar_repeated_offenders` entry for the times `k` already
    /// ran in the last 24 h (the last entry when more), else `timeout`.
    fn repeat_timeout(&self, k: &(String, String), timeout: u64, now: i64) -> u64 {
        let mut runs = self.runs.lock().unwrap();
        runs.retain(|_, t| {
            t.retain(|&at| at > now - REPEAT_WINDOW);
            !t.is_empty()
        });
        let ran = runs.get(&format!("{} {}", k.0, k.1)).map_or(0, Vec::len);
        let list = self.repeated_offenders.lock().unwrap();
        let minutes = if ran == 0 { None } else { list.get(ran.min(list.len()).saturating_sub(1)) };
        match minutes {
            Some(m) if timeout > 0 => m * 60,
            _ => timeout,
        }
    }

    /// Undoes `k` when its time is up (read again on waking: a repeat may have extended it); one
    /// without a timeout is no longer in force.
    fn arm(self: &Arc<Self>, k: (String, String)) {
        let me = self.clone();
        tokio::spawn(async move {
            let u = loop {
                let left = {
                    let mut active = me.active.lock().unwrap();
                    let now = chrono::Utc::now().timestamp();
                    match active.get(&k).map(|u| u.due) {
                        None => return,
                        Some(None) => {
                            active.remove(&k);
                            return;
                        }
                        Some(Some(due)) if due > now => due - now,
                        Some(Some(_)) => break active.remove(&k).expect("present"),
                    }
                };
                tokio::time::sleep(Duration::from_secs(left as u64)).await;
            };
            info!(command = %u.command, "Timeout reached: undoing the response");
            if let Err(e) = me.run(&u.program, &u.command, "delete", &u.parameters, 0).await {
                warn!(command = %u.command, error = %e, "Undo failed");
            }
            // saved after the undo ran: a stop during it leaves it in the file for the next start
            me.save();
        });
    }

    /// One command from the manager; the outcome is reported back to it.
    pub async fn execute_command(self: &Arc<Self>, cmd: &Value) -> Value {
        let id = cmd["command_id"].as_str().unwrap_or("").to_string();
        match cmd["type"].as_str() {
            Some("scan") => {
                info!(command_id = %id, "Scan requested by the manager");
                self.scan_fim.notify_one();
                self.scan_rootcheck.notify_one();
                self.scan_sca.notify_one();
                json!({ "command_id": id, "status": "success", "message": "File integrity, rootcheck and configuration assessment scan started" })
            }
            Some("sca_full") => {
                let Some(policy) = cmd["policy_id"].as_str().filter(|p| !p.is_empty()) else {
                    return json!({ "command_id": id, "status": "error", "error": "No policy named" });
                };
                info!(command_id = %id, policy = %policy, "Full configuration assessment requested by the manager");
                self.sca_full.lock().unwrap().insert(policy.to_string());
                self.scan_sca.notify_one();
                json!({ "command_id": id, "status": "success", "message": "Full configuration assessment started" })
            }
            Some("inventory_full") => {
                info!(command_id = %id, "Full inventory requested by the manager");
                self.inventory_full.notify_one();
                json!({ "command_id": id, "status": "success", "message": "Full inventory started" })
            }
            Some("ar") => {
                let msg = &cmd["message"];
                let Some(name) = msg["command"].as_str().filter(|n| !n.is_empty()) else {
                    return json!({ "command_id": id, "status": "error", "error": "Response command without a name" });
                };
                if !valid_name(name) {
                    warn!(command_id = %id, command = %name, "Response command name not valid: refused");
                    return json!({ "command_id": id, "status": "error", "command": name, "error": "Response command name not valid" });
                }
                if !self.enabled.load(Ordering::SeqCst) {
                    return json!({ "command_id": id, "status": "error", "command": name, "error": "Responses are disabled on this agent (active_response_enabled)" });
                }
                let (base, timeout) = split_command(name);
                let program = program_of(&base).to_string();
                let params = msg["parameters"].clone();
                info!(command_id = %id, command = %name, "Running response");
                let r = self.run(&program, name, "add", &params, timeout).await;
                // an explicit release / tamper-off ends what that program put in force
                let args = params["extra_args"].as_array().cloned().unwrap_or_default();
                if r.is_ok() && (base == "release-host" || args.iter().any(|a| a == "release" || a == "off")) {
                    self.active.lock().unwrap().retain(|(p, _), _| *p != program);
                }
                if let Ok((true, Some(k))) = &r {
                    self.arm(k.clone());
                }
                if r.is_ok() {
                    self.save();
                }
                match r {
                    Ok((true, _)) => json!({ "command_id": id, "status": "success", "command": name }),
                    Ok((false, _)) => json!({ "command_id": id, "status": "skipped", "command": name, "message": "Already in force" }),
                    Err(e) => json!({ "command_id": id, "status": "error", "command": name, "error": e }),
                }
            }
            other => {
                warn!(command_id = %id, kind = ?other, "Command type not supported by this agent");
                json!({ "command_id": id, "status": "error", "error": "Command type not supported by this agent" })
            }
        }
    }

    /// Runs `program` once: whether it was applied (false: aborted, the same key is in force,
    /// whose undo then moves to `timeout` from now) and the key it asked about.
    async fn run(&self, program: &str, name: &str, command: &str, params: &Value, timeout: u64) -> Result<(bool, Option<(String, String)>), String> {
        let path = program_path(program);
        if !path.is_file() {
            return Err(format!("{} is not installed", path.display()));
        }
        let mut c = tokio::process::Command::new(&path);
        c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        detach(&mut c, program == RESTART_PROGRAM);
        let mut child = c.spawn().map_err(|e| format!("{}: {e}", path.display()))?;
        let mut stdin = child.stdin.take().ok_or("no input pipe")?;
        let mut out = BufReader::new(child.stdout.take().ok_or("no output pipe")?).lines();
        stdin.write_all(request(name, command, params).as_bytes()).await.map_err(|e| e.to_string())?;
        stdin.flush().await.map_err(|e| e.to_string())?;
        let mut applied = true;
        let mut recorded = None;
        let work = async {
            // the program may ask check_keys once (only on add); the input stays open for the answer
            while let Ok(Some(line)) = out.next_line().await {
                let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
                if v["command"] != "check_keys" {
                    continue;
                }
                let keys: Vec<String> = v["parameters"]["keys"].as_array().map(|a| a.iter().filter_map(|k| k.as_str().map(String::from)).collect()).unwrap_or_default();
                let key = (program.to_string(), keys.join(","));
                let in_force = command == "add" && self.claim(&key, name, params, timeout);
                applied = !in_force;
                if command == "add" {
                    recorded = Some(key);
                }
                let reply = if in_force { "abort" } else { "continue" };
                let _ = stdin.write_all(answer(reply).as_bytes()).await;
                let _ = stdin.flush().await;
            }
            drop(stdin);
            child.wait().await
        };
        let status = tokio::time::timeout(RUN_LIMIT, work).await.map_err(|_| format!("{program} did not finish in {} s", RUN_LIMIT.as_secs()))?.map_err(|e| e.to_string())?;
        if !status.success() && applied {
            if let Some(k) = &recorded {
                self.active.lock().unwrap().remove(k);
            }
            return Err(format!("{program} ended with code {}", status.code().unwrap_or(-1)));
        }
        Ok((applied, recorded))
    }
}

impl Default for EdrExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_names() {
        assert_eq!(split_command("isolate-host600"), ("isolate-host".into(), 600));
        assert_eq!(split_command("kill-process0"), ("kill-process".into(), 0));
        assert_eq!(split_command("netsh86400"), ("netsh".into(), 86400));
        assert_eq!(program_of("release-host"), "isolate-host");
        assert_eq!(program_of("tamper-unlock"), "tamper-protect");
        assert_eq!(program_of("yara-scan"), "yara-scan");
    }

    #[test]
    fn request_line_is_what_the_programs_read() {
        let p = json!({ "extra_args": ["pid=42"], "alert": {} });
        let r: Value = serde_json::from_str(request("kill-process0", "add", &p).trim()).unwrap();
        assert_eq!((r["version"].as_u64(), r["command"].as_str()), (Some(1), Some("add")));
        assert!(r["origin"].is_object() && r["parameters"]["extra_args"][0] == "pid=42");
        // a message without parameters still gets an object
        let r: Value = serde_json::from_str(request("x0", "delete", &Value::Null).trim()).unwrap();
        assert!(r["parameters"].is_object());
        let a: Value = serde_json::from_str(answer("continue").trim()).unwrap();
        assert_eq!(a["command"], "continue");
    }

    #[tokio::test]
    async fn missing_program_and_unknown_type() {
        let e = Arc::new(EdrExecutor::new());
        let r = e.execute_command(&json!({ "command_id": "1", "type": "ar", "message": { "command": "no-such-program0", "parameters": {} } })).await;
        assert_eq!(r["status"], "error");
        let r = e.execute_command(&json!({ "command_id": "2", "action": "live_response", "parameters": { "command": "whoami" } })).await;
        assert_eq!(r["status"], "error", "raw shell commands are never run");
        let r = e.execute_command(&json!({ "command_id": "3", "type": "scan" })).await;
        assert_eq!(r["status"], "success");
    }

    #[tokio::test]
    async fn full_sends_asked_for() {
        let e = Arc::new(EdrExecutor::new());
        let r = e.execute_command(&json!({ "command_id": "1", "type": "sca_full", "policy_id": "cis_win11" })).await;
        assert_eq!(r["status"], "success");
        assert!(e.sca_full.lock().unwrap().contains("cis_win11"));
        tokio::time::timeout(Duration::from_secs(1), e.scan_sca.notified()).await.expect("the scan is woken");
        assert_eq!(e.execute_command(&json!({ "command_id": "2", "type": "sca_full" })).await["status"], "error");
        assert_eq!(e.execute_command(&json!({ "command_id": "3", "type": "inventory_full" })).await["status"], "success");
        tokio::time::timeout(Duration::from_secs(1), e.inventory_full.notified()).await.expect("the inventory is woken");
    }

    #[tokio::test]
    async fn names_outside_the_folder_and_disabled_responses_refused() {
        let e = Arc::new(EdrExecutor::new());
        for bad in [r"..\..\Windows\System32\cmd0", "../x0", "a b0", "x.exe0"] {
            let r = e.execute_command(&json!({ "command_id": "1", "type": "ar", "message": { "command": bad } })).await;
            assert_eq!(r["error"], "Response command name not valid", "{bad}");
        }
        e.enabled.store(false, Ordering::SeqCst);
        let r = e.execute_command(&json!({ "command_id": "2", "type": "ar", "message": { "command": "kill-process0" } })).await;
        assert!(r["error"].as_str().unwrap().contains("active_response_enabled"));
    }

    #[tokio::test]
    async fn repeat_extends_and_no_timeout_is_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        let e = Arc::new(EdrExecutor::with_timeouts(dir.path().join("ar_timeouts.json")));
        let k = ("isolate-host".to_string(), "h".to_string());
        assert!(!e.claim(&k, "isolate-host60", &json!({}), 60), "first: applied");
        let first = e.active.lock().unwrap()[&k].due.unwrap();
        assert!(e.claim(&k, "isolate-host600", &json!({}), 600), "repeat: in force");
        assert!(e.active.lock().unwrap()[&k].due.unwrap() >= first + 500, "the undo moved later");
        assert!(e.claim(&k, "isolate-host10", &json!({}), 10));
        assert!(e.active.lock().unwrap()[&k].due.unwrap() >= first + 500, "never earlier");

        let k0 = ("firewall-drop".to_string(), "10.0.0.1".to_string());
        assert!(!e.claim(&k0, "firewall-drop0", &json!({}), 0));
        e.arm(k0.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!e.active.lock().unwrap().contains_key(&k0), "timeout 0: no longer in force after its run");
        assert!(!e.claim(&k0, "firewall-drop0", &json!({}), 0), "so a repeat runs again");
    }

    #[tokio::test]
    async fn repeated_offenders_get_longer_timeouts() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ar_timeouts.json");
        let e = Arc::new(EdrExecutor::with_timeouts(&file));
        *e.repeated_offenders.lock().unwrap() = vec![30, 60, 120];
        let k = ("firewall-drop".to_string(), "10.0.0.9".to_string());
        let mut given = Vec::new();
        for _ in 0..5 {
            let now = chrono::Utc::now().timestamp();
            assert!(!e.claim(&k, "firewall-drop600", &json!({}), 600));
            given.push(e.active.lock().unwrap().remove(&k).unwrap().due.unwrap() - now);
        }
        let minutes: Vec<i64> = given.iter().map(|s| (s + 30) / 60).collect();
        assert_eq!(minutes, [10, 30, 60, 120, 120], "first the command's own, then the list, then its last entry");
        assert!(!e.claim(&k, "firewall-drop0", &json!({}), 0));
        assert_eq!(e.active.lock().unwrap().remove(&k).unwrap().due, None, "no timeout: not changed, not counted");

        // kept with the undos; runs older than 24 h do not count
        e.save();
        let r = Arc::new(EdrExecutor::with_timeouts(&file));
        r.restore();
        assert_eq!(r.runs.lock().unwrap()["firewall-drop 10.0.0.9"].len(), 5);
        *r.repeated_offenders.lock().unwrap() = vec![30, 60];
        let old = chrono::Utc::now().timestamp() - REPEAT_WINDOW - 10;
        r.runs.lock().unwrap().insert("firewall-drop 10.0.0.9".into(), vec![old, old]);
        assert_eq!(r.repeat_timeout(&k, 600, chrono::Utc::now().timestamp()), 600);
    }

    #[tokio::test]
    async fn undos_saved_and_restored() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data").join("ar_timeouts.json");
        let now = chrono::Utc::now().timestamp();
        let undo = |key: &str, due: i64| Undo { program: "no-such-program".into(), key: key.into(), command: "no-such-program60".into(), parameters: json!({}), due: Some(due) };
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        // the plain list older agents wrote
        std::fs::write(&file, serde_json::to_string(&[undo("overdue", now - 5), undo("later", now + 3600)]).unwrap()).unwrap();

        let e = Arc::new(EdrExecutor::with_timeouts(&file));
        e.restore();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let keys: Vec<String> = e.active.lock().unwrap().keys().map(|k| k.1.clone()).collect();
        assert_eq!(keys, ["later"], "the overdue undo ran at start, the other is armed");
        let saved = serde_json::from_str::<Saved>(&std::fs::read_to_string(&file).unwrap()).unwrap().undos;
        assert_eq!(saved.len(), 1);
        assert_eq!((saved[0].key.as_str(), saved[0].due), ("later", Some(now + 3600)));
    }

    /// The restart program survives the agent: no kill on drop, its own process group. Live check:
    /// "restart agent" from the console on an installed agent; the service is running again.
    #[cfg(windows)]
    #[tokio::test]
    async fn restart_program_outlives_the_agent() {
        let alive = |pid: u32| {
            let out = std::process::Command::new("tasklist").args(["/FI", &format!("PID eq {pid}"), "/NH"]).output().unwrap();
            String::from_utf8_lossy(&out.stdout).contains(&pid.to_string())
        };
        let more = std::path::Path::new(&std::env::var("SystemRoot").unwrap()).join(r"System32\more.com");
        for detached in [true, false] {
            let mut c = tokio::process::Command::new(&more);
            c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
            detach(&mut c, detached);
            let mut child = c.spawn().unwrap();
            let stdin = child.stdin.take();
            let pid = child.id().unwrap();
            drop(child);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(alive(pid), detached, "detached {detached}");
            drop(stdin); // more ends at the end of its input
        }
        assert_eq!(program_path(RESTART_PROGRAM), PathBuf::from(r"active-response\bin\restart-agent.exe"));
        assert_eq!(program_of("restart-wazuh"), "restart-agent");
    }
}

/// With the real response programs (release build): `cargo build --release -p siem-active-response`
/// then `cargo test -p provigil-agent live_programs -- --ignored --nocapture`.
#[cfg(all(test, windows))]
mod live {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn live_programs() {
        let release = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release");
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("active-response/bin")).unwrap();
        for p in ["kill-process.exe", "live-response.exe"] {
            std::fs::copy(release.join(p), dir.path().join("active-response/bin").join(p)).unwrap();
        }
        std::env::set_current_dir(dir.path()).unwrap();
        let e = Arc::new(EdrExecutor::new());
        let mut victim = std::process::Command::new("ping").args(["-n", "60", "127.0.0.1"]).stdout(Stdio::null()).spawn().unwrap();
        let pid = victim.id();
        let r = e.execute_command(&json!({ "command_id": "k1", "type": "ar", "message": { "command": "kill-process0", "parameters": { "extra_args": [format!("pid={pid}")], "alert": {} } } })).await;
        println!("kill-process: {r}");
        assert_eq!(r["status"], "success");
        let gone = (0..20).any(|_| { std::thread::sleep(Duration::from_millis(100)); victim.try_wait().unwrap().is_some() });
        assert!(gone, "the process was ended");
        let r = e.execute_command(&json!({ "command_id": "l1", "type": "ar", "message": { "command": "live-response0", "parameters": { "extra_args": ["id=0123456789abcdef0123456789abcdef", "action=processes"], "alert": {} } } })).await;
        println!("live-response: {r}");
        let log = std::fs::read_to_string("active-response/active-responses.log").unwrap();
        let mut pos = 0;
        let lines = crate::ar_log::new_lines(std::path::Path::new("active-response/active-responses.log"), &mut pos);
        println!("{} log lines, e.g. {}", lines.len(), lines.iter().find(|l| l.contains("live-response")).map(|l| &l[..l.len().min(200)]).unwrap_or(""));
        assert!(log.contains("kill-process") && log.contains("\"script\":\"live-response\""));
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
    }
}
