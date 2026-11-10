//! Scheduled commands (`commands` in `provigil-agent.json`): each runs on its own thread at its
//! interval, with a time limit (its process tree is ended past it). Every output line (standard
//! output, then standard error) goes to the manager as a `command` event, location
//! `command_<name>`. With `sha256` set, the program must have that SHA-256 or it is not run.
//!
//! The program is the command's first word (found through PATH) and is started directly, not
//! through a shell, so the program checked is the one that runs.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{error, warn};

use crate::buffer::EventBuffer;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// One entry of `commands`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScheduledCommand {
    pub name: String,
    pub command: String,
    pub interval_secs: u64,
    /// The first run at start (else after the first interval).
    pub run_on_start: bool,
    /// Run it, send nothing.
    pub ignore_output: bool,
    pub timeout_secs: u64,
    /// The SHA-256 (hex) the program must have.
    pub sha256: Option<String>,
}

impl Default for ScheduledCommand {
    fn default() -> Self {
        Self { name: String::new(), command: String::new(), interval_secs: 86_400, run_on_start: true, ignore_output: false, timeout_secs: 600, sha256: None }
    }
}

/// One thread per command (an entry without a command is left out with a warning).
pub fn spawn(list: &[ScheduledCommand], buffer: Arc<EventBuffer>, agent: Value, running: fn() -> bool) -> Vec<JoinHandle<()>> {
    let mut threads = Vec::new();
    for c in list {
        if c.command.trim().is_empty() {
            warn!(name = %c.name, "Scheduled command without a command: not used");
            continue;
        }
        let (c, buffer, agent) = (c.clone(), buffer.clone(), agent.clone());
        match crate::thread(format!("command {}", c.name), move || c.schedule(&buffer, &agent, running)) {
            Ok(t) => threads.push(t),
            Err(e) => error!(error = %e, "Scheduled command thread not started"),
        }
    }
    threads
}

impl ScheduledCommand {
    fn schedule(&self, buffer: &EventBuffer, agent: &Value, running: fn() -> bool) {
        let every = Duration::from_secs(self.interval_secs.max(1));
        if !self.run_on_start {
            crate::nap(every, running);
        }
        while running() {
            match self.run(running) {
                Err(e) => error!(name = %self.name, error = %e, "Scheduled command not run"),
                Ok(None) => warn!(name = %self.name, timeout_secs = self.timeout_secs, "Scheduled command ran past its timeout: ended"),
                Ok(Some(lines)) if !self.ignore_output => self.events(lines, agent).into_iter().for_each(|e| buffer.push(e)),
                Ok(Some(_)) => {}
            }
            crate::nap(every, running);
        }
    }

    fn events(&self, lines: Vec<String>, agent: &Value) -> Vec<Value> {
        let location = format!("command_{}", self.name);
        lines.iter().map(|l| crate::logfiles::event("command", &location, l, agent)).collect()
    }

    /// The program, checked against `sha256`, started with the rest of the command line.
    fn start(&self) -> Result<Child, String> {
        let (program, rest) = split_first(self.command.trim());
        let path = resolve(program).ok_or_else(|| format!("program '{program}' not found"))?;
        if let Some(want) = self.sha256.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let have = std::fs::read(&path).map(|b| format!("{:x}", Sha256::digest(&b))).map_err(|e| format!("{}: {e}", path.display()))?;
            if !have.eq_ignore_ascii_case(want) {
                return Err(format!("{} has SHA-256 {have}, not the configured {want}: refused", path.display()));
            }
        }
        let mut cmd = Command::new(&path);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
            // as written: the program parses its own command line
            if !rest.is_empty() {
                cmd.raw_arg(rest);
            }
        }
        // shortcut: no quoting on other systems (the agent runs on Windows), split on spaces
        #[cfg(not(windows))]
        cmd.args(rest.split_whitespace());
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The output lines; `None` when it ran past its timeout or the agent stopped (its process
    /// tree is then ended); `Err` when refused or not started.
    pub(crate) fn run(&self, running: fn() -> bool) -> Result<Option<Vec<String>>, String> {
        let child = self.start()?;
        Ok(finish(child, Duration::from_secs(self.timeout_secs.max(1)), running))
    }
}

fn finish(mut child: Child, timeout: Duration, running: fn() -> bool) -> Option<Vec<String>> {
    let out = child.stdout.take().map(read_all);
    let err = child.stderr.take().map(read_all);
    let end = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < end && running() => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                kill_tree(&mut child);
                return None;
            }
        }
    }
    let mut lines = Vec::new();
    for rx in [out, err].into_iter().flatten() {
        // a program it started may keep the pipe open: not waited for long
        let b = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        lines.extend(String::from_utf8_lossy(&b).lines().map(str::trim_end).filter(|l| !l.is_empty()).map(String::from));
    }
    Some(lines)
}

fn read_all(mut r: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = r.read_to_end(&mut b);
        let _ = tx.send(b);
    });
    rx
}

/// Ends the process and every process it started.
pub(crate) fn kill_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let _ = Command::new(Path::new(&root).join(r"System32\taskkill.exe"))
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The program (without its quotes) and the rest of the command line.
fn split_first(s: &str) -> (&str, &str) {
    if let Some(q) = s.strip_prefix('"') {
        let end = q.find('"').unwrap_or(q.len());
        return (&q[..end], q.get(end + 1..).unwrap_or("").trim_start());
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    (&s[..end], s[end..].trim_start())
}

/// The file `program` names: as written when it has a folder, else the first match in PATH;
/// on Windows also with each PATHEXT extension.
fn resolve(program: &str) -> Option<PathBuf> {
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into()).split(';').filter(|e| !e.is_empty()).map(String::from).collect()
    } else {
        Vec::new()
    };
    let p = Path::new(program);
    let dirs: Vec<PathBuf> = if p.is_absolute() || p.components().count() > 1 {
        vec![PathBuf::new()]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect()
    };
    dirs.into_iter()
        .map(|d| d.join(p))
        .flat_map(|base| {
            let with_ext = exts.iter().map(|e| PathBuf::from(format!("{}{e}", base.display()))).collect::<Vec<_>>();
            std::iter::once(base).chain(with_ext)
        })
        .find(|c| c.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn yes() -> bool {
        true
    }

    fn cmd(command: &str) -> ScheduledCommand {
        ScheduledCommand { name: "t".into(), command: command.into(), ..Default::default() }
    }

    #[test]
    fn command_line_split() {
        assert_eq!(split_first(r#""C:\Program Files\x.exe" -a "b c""#), (r"C:\Program Files\x.exe", r#"-a "b c""#));
        assert_eq!(split_first("netstat -an"), ("netstat", "-an"));
        assert_eq!(split_first("whoami"), ("whoami", ""));
        assert!(resolve("no-such-program-pv").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn sha256_checked_and_output_lines_become_events() {
        let c = ScheduledCommand { sha256: Some("00".repeat(32)), ..cmd(r#"cmd /C "echo a&echo b 1>&2""#) };
        let e = c.run(yes).unwrap_err();
        assert!(e.contains("refused"), "{e}");

        let exe = resolve("cmd").unwrap();
        assert!(exe.to_string_lossy().to_lowercase().ends_with("cmd.exe"), "{}", exe.display());
        let good = format!("{:X}", Sha256::digest(std::fs::read(&exe).unwrap()));
        let c = ScheduledCommand { sha256: Some(good), ..c };
        let lines = c.run(yes).unwrap().unwrap();
        assert_eq!(lines, ["a", "b"], "standard output, then standard error");
        let ev = c.events(lines, &json!({"id": "001"}));
        assert_eq!(ev.len(), 2);
        assert_eq!((ev[0]["event_type"].as_str(), ev[0]["location"].as_str(), ev[0]["message"].as_str()), (Some("command"), Some("command_t"), Some("a")));
        assert_eq!(ev[1]["agent"]["id"], "001");
    }

    #[cfg(windows)]
    #[test]
    fn timeout_ends_the_process_tree() {
        let child = cmd("cmd /C ping -n 30 127.0.0.1").start().unwrap();
        let shell = sysinfo::Pid::from_u32(child.id());
        std::thread::sleep(Duration::from_millis(700));
        let mut sys = sysinfo::System::new();
        sys.refresh_processes();
        let ping = *sys.processes().iter().find(|(_, p)| p.parent() == Some(shell) && p.name().eq_ignore_ascii_case("ping.exe")).expect("ping started").0;
        let t = Instant::now();
        assert!(finish(child, Duration::from_secs(1), yes).is_none());
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(300));
        sys.refresh_processes();
        assert!(sys.process(ping).is_none(), "the program the command started was ended too");
    }
}
