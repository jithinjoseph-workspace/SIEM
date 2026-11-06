//! osquery (`osquery` in `provigil-agent.json`): when enabled and installed, the agent keeps the
//! osquery daemon running (when `run_daemon`) and follows its results log (JSON lines) like a
//! `json` log file; each result goes to the manager as a `logfile` event, location `osquery`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info, warn};

use crate::buffer::EventBuffer;
use crate::config::LocalFile;
use crate::logfiles::{self, FileCollector};

/// The daemon is started again at most this often.
const DAEMON_CHECK: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OsqueryConfig {
    pub enabled: bool,
    pub log_path: String,
    /// Start the daemon when it is not running.
    pub run_daemon: bool,
    pub bin_path: String,
    /// Passed to the daemon as `--config_path`.
    pub config_path: Option<String>,
}

impl Default for OsqueryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: r"C:\Program Files\osquery\log\osqueryd.results.log".into(),
            run_daemon: true,
            bin_path: r"C:\Program Files\osquery\osqueryd\osqueryd.exe".into(),
            config_path: None,
        }
    }
}

/// The osquery thread; `None` when disabled, or not installed (one warning).
pub fn spawn(cfg: &OsqueryConfig, positions: PathBuf, buffer: Arc<EventBuffer>, agent: Value, running: fn() -> bool) -> Option<JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    let mut cfg = cfg.clone();
    // the folder of the daemon, as older configurations name it
    if Path::new(&cfg.bin_path).is_dir() {
        cfg.bin_path = Path::new(&cfg.bin_path).join("osqueryd.exe").to_string_lossy().into_owned();
    }
    let needed = if cfg.run_daemon { PathBuf::from(&cfg.bin_path) } else { Path::new(&cfg.log_path).parent().map(Path::to_path_buf).unwrap_or_default() };
    if !needed.exists() {
        warn!(path = %needed.display(), "osquery is enabled but not installed: its results are not collected");
        return None;
    }
    let mut results = Results::new(&cfg, positions);
    let started = crate::thread("osquery".into(), move || {
        let mut checked: Option<Instant> = None;
        // the daemon this agent started: stopped with the agent (one the user runs is left alone)
        let mut ours: Option<Child> = None;
        while running() {
            if cfg.run_daemon && checked.is_none_or(|t| t.elapsed() >= DAEMON_CHECK) {
                ours = keep_daemon(&cfg).or(ours);
                checked = Some(Instant::now());
            }
            results.pass(&agent).into_iter().for_each(|e| buffer.push(e));
            std::thread::sleep(Duration::from_secs(1));
        }
        stop_started(ours, &cfg.bin_path);
    });
    started.map_err(|e| error!(error = %e, "osquery thread not started")).ok()
}

/// Starts the daemon when no process of that program runs; the started one.
fn keep_daemon(cfg: &OsqueryConfig) -> Option<Child> {
    let name = Path::new(&cfg.bin_path).file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut sys = sysinfo::System::new();
    sys.refresh_processes();
    if sys.processes().values().any(|p| p.name().to_lowercase() == name) {
        return None;
    }
    let mut c = Command::new(&cfg.bin_path);
    if let Some(p) = cfg.config_path.as_deref().filter(|p| !p.is_empty()) {
        c.arg(format!("--config_path={p}"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        Ok(child) => {
            info!(program = %cfg.bin_path, "osquery daemon started");
            Some(child)
        }
        Err(e) => {
            warn!(program = %cfg.bin_path, error = %e, "osquery daemon not started");
            None
        }
    }
}

/// Ends the daemon this agent started, when it still runs.
fn stop_started(started: Option<Child>, program: &str) {
    if let Some(mut c) = started {
        if matches!(c.try_wait(), Ok(None)) {
            info!(program, "Stopping the osquery daemon this agent started");
            crate::commands::kill_tree(&mut c);
        }
    }
}

/// The results log, followed like a `json` log file (from its end the first time).
struct Results(FileCollector);

impl Results {
    fn new(cfg: &OsqueryConfig, positions: PathBuf) -> Self {
        let entry = LocalFile { location: cfg.log_path.clone(), log_format: "json".into(), ..LocalFile::default() };
        Self(FileCollector::for_entries(&[entry], positions))
    }

    fn pass(&mut self, agent: &Value) -> Vec<Value> {
        self.0.pass(Instant::now()).into_iter().map(|(_, m, _)| logfiles::event("logfile", "osquery", &m, agent)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    fn running() -> bool {
        true
    }

    #[test]
    fn results_log_followed() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("osqueryd.results.log");
        std::fs::write(&log, "{\"name\":\"old\"}\n").unwrap();
        let cfg = OsqueryConfig { enabled: true, run_daemon: false, log_path: log.to_string_lossy().into_owned(), ..Default::default() };
        let mut r = Results::new(&cfg, dir.path().join("osquery_positions.json"));
        assert!(r.pass(&json!({})).is_empty(), "results already there are old");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"{\"name\":\"pack_x_users\",\"action\":\"added\"}\nnot json\n{\"name\":\"b\"}\n")
            .unwrap();
        let ev = r.pass(&json!({"id": "001"}));
        assert_eq!(ev.len(), 2);
        assert_eq!((ev[0]["event_type"].as_str(), ev[0]["location"].as_str()), (Some("logfile"), Some("osquery")));
        assert_eq!(ev[0]["message"], "{\"name\":\"pack_x_users\",\"action\":\"added\"}");
        assert_eq!(ev[1]["agent"]["id"], "001");
    }

    /// A daemon already running (the user's) is not started again, so never stopped by the
    /// agent; the one the agent started is stopped.
    #[cfg(windows)]
    #[test]
    fn only_the_started_daemon_is_stopped() {
        let ping = |n: &str| Command::new("ping").args(["-n", n, "127.0.0.1"]).stdout(Stdio::null()).spawn().unwrap();
        let mut users = ping("30");
        let cfg = OsqueryConfig { bin_path: r"C:\Windows\System32\PING.EXE".into(), ..Default::default() };
        assert!(keep_daemon(&cfg).is_none(), "one runs already: not started");
        stop_started(None, "ping");
        assert!(matches!(users.try_wait(), Ok(None)), "the user's daemon is left alone");
        let _ = users.kill();

        let t = Instant::now();
        stop_started(Some(ping("30")), "ping");
        assert!(t.elapsed() < Duration::from_secs(10), "the started one is ended");
    }

    #[test]
    fn disabled_or_not_installed_starts_nothing() {
        let buffer = Arc::new(EventBuffer::new(10));
        let dir = tempfile::tempdir().unwrap();
        let off = OsqueryConfig::default();
        assert!(spawn(&off, dir.path().join("p.json"), buffer.clone(), json!({}), running).is_none());
        let missing = OsqueryConfig { enabled: true, bin_path: dir.path().join("osqueryd.exe").to_string_lossy().into_owned(), ..Default::default() };
        assert!(spawn(&missing, dir.path().join("p.json"), buffer.clone(), json!({}), running).is_none());
        let folder = OsqueryConfig { bin_path: dir.path().to_string_lossy().into_owned(), ..missing };
        assert!(spawn(&folder, dir.path().join("p.json"), buffer, json!({}), running).is_none(), "a folder without the daemon");
    }
}
