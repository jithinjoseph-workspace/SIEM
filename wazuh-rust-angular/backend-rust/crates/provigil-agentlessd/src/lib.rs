//! Agentless monitoring (`provigil-agentlessd`): runs the `agentless/` scripts against hosts
//! without an agent, on the schedule of each `<agentless>` section, and forwards what they
//! print to the detection engine: `FWD:` lines as integrity events, `LOG:` lines as log events,
//! and for `periodic_diff` the text after `STORE:` is kept and compared with the previous run;
//! a change becomes a "Change detected" event with the differences.
//!
//! See `specs/provigil-execd.md` (agentless part) for the decisions.

pub mod config;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use provigil_daemon::Log;
use provigil_execd::process::{Bind, Program, NOT_STARTED};
use provigil_ipc::queue::ids;

pub use config::Entry;

pub const NAME: &str = "provigil-agentlessd";
pub const SCRIPTS: &str = "agentless";
pub const ENTRIES: &str = "queue/agentless";
pub const DIFF_DIR: &str = "queue/diff";
pub const SOCKET: &str = "queue/sockets/agentless";
const NEW_STATE: &str = "new-entry";
const LAST_STATE: &str = "last-entry";
/// The longest difference text sent.
const DIFF_MAX: usize = 65536 - 256 * 2;
/// The longest change event.
const ALERT_MAX: usize = 65536 - 256;
const MORE: &str = "More changes...";

/// At most 1,023 bytes (paths and locations).
pub fn cut(mut s: String) -> String {
    if s.len() > 1023 {
        let mut n = 1023;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
    s
}

fn errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.split(" (os error").next().unwrap_or(&s).to_string()
}

fn until_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// The script's command line: `agentless/<type> [use_sudo|use_su] <host> <arguments...>`.
pub fn command_line(kind: &str, host: &str, arguments: &str) -> Vec<String> {
    let mut argv = vec![cut(format!("{SCRIPTS}/{kind}"))];
    match host.as_bytes().first() {
        Some(b'o') => argv.push("use_sudo".into()),
        Some(b's') => argv.push("use_su".into()),
        _ => {}
    }
    argv.push(host.get(1..).unwrap_or("").to_string());
    argv.extend(arguments.split(' ').filter(|t| !t.is_empty()).map(String::from));
    argv
}

/// The detection engine's event queue, connected again when it goes away.
pub struct Queue {
    home: PathBuf,
    rt: tokio::runtime::Handle,
    sender: Option<provigil_ipc::aio::DatagramSender>,
    log: Arc<Log>,
    busy_reported: AtomicBool,
}

impl Queue {
    /// Connects, trying until the queue is there (waiting 10 s, 15 s, ... up to a minute).
    pub fn open(home: &Path, rt: tokio::runtime::Handle, log: Arc<Log>) -> Queue {
        let mut q = Queue { home: home.to_path_buf(), rt, sender: None, log, busy_reported: AtomicBool::new(false) };
        q.connect();
        q
    }

    fn connect(&mut self) {
        let path = self.home.join(provigil_ipc::queue::EVENT_QUEUE);
        let mut wait = 5u64;
        for attempt in 1u64.. {
            match self.rt.block_on(provigil_ipc::aio::DatagramSender::connect(&path)) {
                Ok(s) => {
                    self.log.debug(format!("Connected to '{}' after {} attempts.", provigil_ipc::queue::EVENT_QUEUE, attempt - 1));
                    self.sender = Some(s);
                    return;
                }
                Err(e) => {
                    self.log.debug(format!("Can't connect to '{}': {} ({}). Attempt: {attempt}", provigil_ipc::queue::EVENT_QUEUE, strerror(&e), errno(&e)));
                    wait = (wait + 5).min(60);
                    std::thread::sleep(Duration::from_secs(wait));
                }
            }
        }
    }

    /// One event; false when the queue is gone (a full queue drops the event and says so once).
    fn try_send(&self, text: &[u8], location: &str, queue: u8) -> bool {
        let Some(s) = &self.sender else { return false };
        let Some(mut m) = provigil_ipc::queue::message(until_nul(text), location.split('\0').next().unwrap_or(""), queue) else { return true };
        m.push(0);
        match self.rt.block_on(s.send(&m)) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.log.debug2("Socket busy, discarding message.");
                if !self.busy_reported.swap(true, Ordering::Relaxed) {
                    self.log.warn("Socket busy, discarding message.");
                }
                true
            }
            Err(_) => {
                self.log.debug("socketerr (not available).");
                false
            }
        }
    }

    /// One event, connecting again once when the queue went away.
    pub fn send(&mut self, text: &[u8], location: &str, queue: u8) {
        if !self.try_send(text, location, queue) {
            self.log.debug("(1224): Error sending message to queue.");
            self.sender = None;
            self.connect();
            self.try_send(text, location, queue);
        }
    }
}

/// Where events go: the queue, or a stand-in in tests.
pub trait Events {
    fn send(&mut self, text: &[u8], location: &str, queue: u8);
}

impl Events for Queue {
    fn send(&mut self, text: &[u8], location: &str, queue: u8) {
        Queue::send(self, text, location, queue)
    }
}

/// The service: the sections and where events go.
pub struct Lessd<E: Events> {
    pub home: PathBuf,
    pub log: Arc<Log>,
    pub events: E,
    pub entries: Vec<Entry>,
}

/// A script started for a check: running, or refused because its user may change it.
pub enum Script {
    Run(Program),
    Refused,
}

impl Script {
    pub fn read_line(&mut self, size: usize) -> Option<Vec<u8>> {
        match self {
            Script::Run(p) => p.read_line(size),
            Script::Refused => None,
        }
    }

    /// The wait status; a refused script counts as one that could not start.
    pub fn close(self) -> i32 {
        match self {
            Script::Run(p) => p.close(),
            Script::Refused => NOT_STARTED,
        }
    }
}

impl<E: Events> Lessd<E> {
    fn path(&self, rel: &str) -> String {
        self.home.join(rel).to_string_lossy().into_owned()
    }

    /// Starts a script; one its user may change is refused (others could make it run anything).
    pub fn start(&self, argv: &[&str], bind: Bind) -> Option<Script> {
        #[cfg(unix)]
        {
            if let Ok(c) = std::ffi::CString::new(self.path(argv[0])) {
                // SAFETY: a valid C string
                if unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0 {
                    self.log.error(format!("At wpopenv(): file '{}' has write permissions.", argv[0]));
                    return Some(Script::Refused);
                }
            }
        }
        Program::start(&self.home, argv[0], argv, bind).ok().map(Script::Run)
    }

    fn script_event(&mut self, kind: &str, host: &str, text: &[u8], queue: u8) {
        let location = cut(format!("({kind}) {host}->syscheck"));
        self.events.send(text, &location, queue);
    }

    /// Records that a host was checked (the list the tools read).
    pub fn save_entry(&self, host: &str, kind: &str, what: &str) {
        let rel = cut(format!("{ENTRIES}/({kind}) {host}"));
        if let Err(e) = std::fs::write(self.home.join(&rel), format!("type: {what}\n")) {
            self.log.error(format!("(1103): Could not open file '{rel}' due to [({})-({})].", errno(&e), strerror(&e)));
        }
    }

    /// The file for this run's stored text, creating its folder when needed.
    pub fn open_state(&self, host: &str, kind: &str) -> Option<std::fs::File> {
        let rel = cut(format!("{DIFF_DIR}/{host}->{kind}/{NEW_STATE}"));
        if let Ok(f) = std::fs::File::create(self.home.join(&rel)) {
            return Some(f);
        }
        let dir = cut(format!("{DIFF_DIR}/{host}->{kind}"));
        if !self.home.join(&dir).is_dir() {
            #[allow(unused_mut)]
            let mut b = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o770);
            if let Err(e) = b.create(self.home.join(&dir)) {
                self.log.error(format!("(1107): Could not create directory '{dir}' due to [({})-({})].", errno(&e), strerror(&e)));
                return None;
            }
        }
        match std::fs::File::create(self.home.join(&rel)) {
            Ok(f) => Some(f),
            Err(e) => {
                self.log.error(format!("(1103): Could not open file '{rel}' due to [({})-({})].", errno(&e), strerror(&e)));
                None
            }
        }
    }

    /// The change event for the differences saved at `when`.
    pub fn change_event(&mut self, host: &str, kind: &str, when: i64) {
        let rel = format!("{DIFF_DIR}/{host}->{kind}/diff.{}", when as i32);
        let Ok(f) = std::fs::File::open(self.home.join(&rel)) else {
            self.log.error("Unable to generate diff alert.");
            return;
        };
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::io::Read::take(f, DIFF_MAX as u64), &mut buf);
        match buf.len() {
            0 => {
                self.log.error("Unable to generate diff alert (fread).");
                return;
            }
            DIFF_MAX => {
                // cut at a line end, room left for the note
                let mut n = DIFF_MAX - MORE.len();
                while n > 0 && buf[n - 1] != b'\n' {
                    n -= 1;
                }
                buf.truncate(n);
                buf.extend_from_slice(MORE.as_bytes());
            }
            _ => {}
        }
        let mut event = b"ossec: agentless: Change detected:\n".to_vec();
        event.extend_from_slice(until_nul(&buf));
        event.truncate(ALERT_MAX);
        let location = cut(format!("({kind}) {host}->{NAME}"));
        self.events.send(&event, &location, ids::LOCALFILE);
        self.save_entry(host, kind, "diff");
    }

    /// Compares this run's stored text with the last one; a change is kept as `state.<time>`,
    /// its differences as `diff.<time>`, and sent.
    pub fn compare_states(&mut self, host: &str, kind: &str) {
        let dir = format!("{DIFF_DIR}/{host}->{kind}");
        let new = cut(format!("{dir}/{NEW_STATE}"));
        let last = cut(format!("{dir}/{LAST_STATE}"));
        let rename_failed = |log: &Log, a: &str, b: &str, e: std::io::Error| log.error(format!("(1124): Could not rename file '{a}' to '{b}' due to [({})-({})].", errno(&e), strerror(&e)));
        // the first run: this state becomes the last one
        let Some(last_md5) = provigil_fileop::md5_file(&self.path(&last)) else {
            if let Err(e) = std::fs::rename(self.home.join(&new), self.home.join(&last)) {
                rename_failed(&self.log, &new, &last, e);
            }
            return;
        };
        let Some(new_md5) = provigil_fileop::md5_file(&self.path(&new)) else {
            self.log.error(format!("Invalid internal state (missing '{new}')."));
            return;
        };
        if new_md5 == last_md5 {
            let _ = std::fs::remove_file(self.home.join(&new));
            return;
        }
        let changed_at = provigil_fileop::mtime(&self.path(&last)).unwrap_or(-1);
        let kept = cut(format!("{dir}/state.{}", changed_at as i32));
        if let Err(e) = std::fs::rename(self.home.join(&last), self.home.join(&kept)) {
            return rename_failed(&self.log, &last, &kept, e);
        }
        if let Err(e) = std::fs::rename(self.home.join(&new), self.home.join(&last)) {
            return rename_failed(&self.log, &new, &last, e);
        }
        let changed_at = provigil_fileop::mtime(&self.path(&last)).unwrap_or(-1);
        let mut p = match Program::start(&self.home, "diff", &["diff", &kept, &last], Bind { stdout: true, ..Default::default() }) {
            Ok(p) => p,
            Err(e) => {
                self.log.error(format!("Unable to run diff for {host}->{kind}: {} ({})", strerror(&e), errno(&e)));
                return;
            }
        };
        let diff = cut(format!("{dir}/diff.{}", changed_at as i32));
        let mut f = match std::fs::File::create(self.home.join(&diff)) {
            Ok(f) => f,
            Err(e) => {
                self.log.error(format!("Unable to open diff file '{diff}': {} ({})", strerror(&e), errno(&e)));
                p.close();
                return;
            }
        };
        if let Err(e) = f.write_all(&p.read_all()) {
            self.log.error(format!("Unable to write diff file '{diff}': {} ({})", strerror(&e), errno(&e)));
        }
        drop(f);
        // diff ends with status 1 when the files differ
        if p.close() != 256 {
            self.log.error(format!("Unable to run diff for {host}->{kind}"));
            return;
        }
        self.change_event(host, kind, changed_at);
    }

    /// One round of section `i`. With `test`, only checks that the script runs (`<script> test
    /// test`); a failing script is then given up. -1 when the test failed.
    pub fn run_section(&mut self, i: usize, test: bool) -> i32 {
        let (hosts, kind, state, arguments) = {
            let e = &self.entries[i];
            (e.hosts.clone(), e.kind.clone(), e.state, e.arguments.clone())
        };
        for host_mark in hosts.iter().filter(|h| !h.is_empty()) {
            if test {
                // the first host is enough
                let script = cut(format!("{SCRIPTS}/{kind}"));
                let code = match self.start(&[&script, "test", "test"], Bind::default()) {
                    Some(s) => s.close(),
                    None => 0,
                };
                if code != 0 {
                    if code == NOT_STARTED {
                        self.log.error(format!("Expect command not found (or bad arguments) for '{kind}'."));
                    }
                    self.log.error(format!("Test failed for '{kind}' ({}). Ignoring.", code / 256));
                    self.entries[i].errors = 99;
                    return -1;
                }
                self.log.info(format!("Test passed for '{kind}'."));
                return 0;
            }
            let host = &host_mark[1..];
            let argv = command_line(&kind, host_mark, &arguments);
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            let Some(mut s) = self.start(&argv, Bind { stdin: false, stdout: true, stderr: true }) else {
                self.log.error(format!("Subprocess failed on '{kind}' for '{host}'."));
                self.entries[i].errors += 1;
                continue;
            };
            let mut store: Option<std::fs::File> = None;
            while let Some(raw) = s.read_line(2048) {
                let mut line = until_nul(&raw);
                if let Some(p) = line.iter().position(|&c| c == b'\r') {
                    line = &line[..p];
                }
                if let Some(p) = line.iter().position(|&c| c == b'\n') {
                    line = &line[..p];
                }
                // the text after the 4-letter mark and a space (nothing on a bare mark)
                let rest = line.get(5..).unwrap_or(b"");
                if let Some(m) = line.strip_prefix(b"ERROR: ") {
                    self.log.error(format!("{kind}: {host}: {}", String::from_utf8_lossy(m)));
                    self.entries[i].errors += 1;
                    break;
                } else if let Some(m) = line.strip_prefix(b"INFO: ") {
                    self.log.info(format!("{kind}: {host}: {}", String::from_utf8_lossy(m)));
                } else if line.starts_with(b"FWD:") {
                    self.script_event(&kind, host, rest, ids::SYSCHECK);
                } else if line.starts_with(b"LOG:") {
                    self.script_event(&kind, host, rest, ids::LOCALFILE);
                } else if state & config::DIFF != 0 && line.starts_with(b"STORE: ") {
                    store = self.open_state(host, &kind);
                } else if let Some(f) = store.as_mut() {
                    let _ = f.write_all(line).and_then(|_| f.write_all(b"\n"));
                } else {
                    self.log.debug(format!("Buffer: {}", String::from_utf8_lossy(line)));
                }
            }
            if store.take().is_some() {
                self.compare_states(host, &kind);
            } else {
                self.save_entry(host, &kind, "syscheck");
            }
            s.close();
        }
        0
    }

    /// The schedule: every minute, each due section in turn (one second more pause after each
    /// section). The first round only tests the scripts.
    pub fn run(&mut self) -> ! {
        let mut test = true;
        loop {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
            for i in 0..self.entries.len() {
                if self.entries[i].errors >= 10 {
                    if self.entries[i].errors != 99 {
                        self.log.error(format!("Too many failures for '{}'. Ignoring it.", self.entries[i].kind));
                        self.entries[i].errors = 99;
                    }
                } else if self.entries[i].state & config::PERIODIC != 0 && self.entries[i].last_run + (self.entries[i].frequency as i64) < now {
                    self.run_section(i, test);
                    if !test {
                        self.entries[i].last_run = now;
                    }
                }
                std::thread::sleep(Duration::from_secs(i as u64 + 1));
            }
            test = false;
            std::thread::sleep(Duration::from_secs(60));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[derive(Default)]
    struct Sent(Vec<(Vec<u8>, String, u8)>);
    #[cfg(unix)]
    impl Events for Sent {
        fn send(&mut self, text: &[u8], location: &str, queue: u8) {
            self.0.push((text.to_vec(), location.to_string(), queue));
        }
    }

    // `host->script` folder names cannot exist on Windows; agentless monitoring runs on Linux
    #[cfg(unix)]
    #[test]
    fn change_events() {
        let h = tempfile::tempdir().unwrap();
        for d in ["queue/diff/h->t", "queue/agentless"] {
            std::fs::create_dir_all(h.path().join(d)).unwrap();
        }
        let mut l = Lessd { home: h.path().to_path_buf(), log: Arc::new(Log::null()), events: Sent::default(), entries: Vec::new() };
        std::fs::write(h.path().join("queue/diff/h->t/diff.100"), "2c2
< b=2
---
> b=3
").unwrap();
        l.change_event("h", "t", 100);
        let (text, location, queue) = &l.events.0[0];
        assert_eq!(String::from_utf8_lossy(text), "ossec: agentless: Change detected:
2c2
< b=2
---
> b=3
");
        assert_eq!((location.as_str(), *queue), ("(t) h->provigil-agentlessd", ids::LOCALFILE));
        assert_eq!(std::fs::read_to_string(h.path().join("queue/agentless/(t) h")).unwrap(), "type: diff
");
        // a long difference is cut at a line end and marked
        let line = format!("{}
", "x".repeat(99));
        std::fs::write(h.path().join("queue/diff/h->t/diff.200"), line.repeat(1000)).unwrap();
        l.change_event("h", "t", 200);
        let text = &l.events.0[1].0;
        assert!(text.ends_with(b"
More changes...") && text.len() <= ALERT_MAX, "{}", text.len());
        // no difference file: nothing sent
        l.change_event("h", "t", 300);
        assert_eq!(l.events.0.len(), 2);
        // a whole round: the first state is kept, the same one again changes nothing, a new one
        // is compared with diff and sent
        let state = |text: &str| std::fs::write(h.path().join("queue/diff/h->t/new-entry"), text).unwrap();
        state("a=1
b=2
");
        l.compare_states("h", "t");
        state("a=1
b=2
");
        l.compare_states("h", "t");
        assert_eq!(l.events.0.len(), 2);
        state("a=1
b=3
");
        l.compare_states("h", "t");
        let last = String::from_utf8_lossy(&l.events.0[2].0).into_owned();
        assert!(last.starts_with("ossec: agentless: Change detected:
2c2
< b=2
---
> b=3"), "{last}");
        assert_eq!(std::fs::read_to_string(h.path().join("queue/diff/h->t/last-entry")).unwrap(), "a=1
b=3
");
    }

    #[test]
    fn command_lines() {
        assert_eq!(command_line("ssh_generic_diff", " root@h", ""), ["agentless/ssh_generic_diff", "root@h"]);
        assert_eq!(command_line("t", "oadmin@h", "ls  -la /etc"), ["agentless/t", "use_sudo", "admin@h", "ls", "-la", "/etc"]);
        assert_eq!(command_line("t", "sadmin@h", "x"), ["agentless/t", "use_su", "admin@h", "x"]);
    }
}
