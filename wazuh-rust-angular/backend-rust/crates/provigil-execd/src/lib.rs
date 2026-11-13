//! The manager's active responses (`provigil-execd`): responses the detection engine runs on
//! the manager itself (`<location>` server, or local for the manager's own events) arrive on
//! `queue/alerts/execq`. Each runs the program `etc/shared/ar.conf` names for it, with the JSON
//! protocol of the response programs (`add`, the program's `check_keys` answer, `continue` or
//! `abort`, later `delete`), keeps the responses to undo after their timeout (longer for repeated
//! offenders), and answers requests on `queue/sockets/com`.
//!
//! See `specs/provigil-execd.md` for the decisions.

pub mod com;
pub mod process;
pub mod respond;
pub mod settings;
pub mod table;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64};
use std::sync::{Arc, Mutex};

use provigil_daemon::{Log, Options};

pub const NAME: &str = "provigil-execd";
pub const CONF: &str = "etc/ossec.conf";
pub const AR_CONF: &str = "etc/shared/ar.conf";
pub const AR_BINDIR: &str = "active-response/bin";
pub const INCOMING: &str = "var/incoming";
pub const EXEC_QUEUE: &str = "queue/alerts/execq";
pub const COM_SOCKET: &str = "queue/sockets/com";
pub const CLUSTER_SOCKET: &str = "queue/cluster/c-internal.sock";
/// Commands kept from `ar.conf` (one more is accepted, as before).
pub const MAX_COMMANDS: usize = 64;
/// Room for a command name: at most 256 bytes.
pub const NAME_ROOM: usize = 257;
/// Room for a program path: at most 255 bytes.
pub const PATH_ROOM: usize = 256;
/// Room for a response key: at most 4,095 bytes.
pub const KEY_ROOM: usize = 4096;
pub const DISABLED: &str = "(1350): Active response disabled.";
pub const SHUTDOWN: &str = "(1314): Shutdown received. Deleting responses.";

/// A response to undo when its time is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub program: String,
    /// The `delete` message for the program.
    pub message: Vec<u8>,
    /// The program name and the keys it answered: one entry per key.
    pub key: String,
    pub added: i64,
    pub seconds: i32,
}

/// The service's state.
pub struct Execd {
    pub home: PathBuf,
    pub log: Arc<Log>,
    pub opts: Options,
    pub disabled: AtomicBool,
    /// Timeouts in minutes for the 1st, 2nd, ... repetition of a response (at most 6).
    pub offenders: Mutex<Vec<i32>>,
    /// Restarts are refused until this time.
    pub restart_lock: AtomicI64,
    pub request_timeout: AtomicI32,
    pub max_restart_lock: AtomicI32,
    pub pending: Mutex<Vec<Pending>>,
    /// Repetitions per response key; None when no offender timeouts are set.
    pub repeats: Mutex<Option<HashMap<String, i32>>>,
    pub table: Mutex<table::Table>,
    /// Programs started without waiting (restarts), reaped by the main loop.
    pub detached: Mutex<Vec<std::process::Child>>,
}

impl Execd {
    pub fn new(home: &Path, log: Arc<Log>, opts: Options) -> Execd {
        Execd {
            home: home.to_path_buf(),
            log,
            opts,
            disabled: AtomicBool::new(false),
            offenders: Mutex::new(Vec::new()),
            restart_lock: AtomicI64::new(0),
            request_timeout: AtomicI32::new(0),
            max_restart_lock: AtomicI32::new(0),
            pending: Mutex::new(Vec::new()),
            repeats: Mutex::new(None),
            table: Mutex::new(table::Table::default()),
            detached: Mutex::new(Vec::new()),
        }
    }

    /// Starts counting repetitions when offender timeouts are set (at start-up, after the
    /// settings).
    pub fn start_counting(&self) {
        if !self.offender_minutes().is_empty() {
            *self.repeats.lock().unwrap_or_else(|e| e.into_inner()) = Some(HashMap::new());
        }
    }

    /// Starts a program without waiting (restarts); errors are logged.
    pub fn run_detached(&self, argv: &[&str]) {
        match process::start_detached(&self.home, argv) {
            Ok(c) => self.detached.lock().unwrap_or_else(|e| e.into_inner()).push(c),
            Err(e) => self.log.error(format!("(1312): Error executing '{}': {}", argv[0], strerror(&e))),
        }
    }

    /// Reaps the detached programs that ended.
    pub fn reap(&self) {
        self.detached.lock().unwrap_or_else(|e| e.into_inner()).retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_))));
    }
}

/// The current time in seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// At most `room - 1` bytes of `s` (on a character boundary).
pub fn cut(s: &str, room: usize) -> String {
    let mut n = s.len().min(room.saturating_sub(1));
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}

/// A leading whole number (white space and a sign allowed before it), clamped to the i32
/// range; 0 when there is none.
pub fn atoi(s: &str) -> i32 {
    let t = s.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut v: i64 = 0;
    for c in digits.bytes().take_while(u8::is_ascii_digit) {
        v = (v * 10 + (c - b'0') as i64).min(i32::MAX as i64 + 1);
    }
    let v = if neg { -v } else { v };
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// The last part of a path.
pub fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(p) => &path[p + 1..],
        None => path,
    }
}

pub fn errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// The system's text for an error, without Rust's "(os error N)".
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.split(" (os error").next().unwrap_or(&s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!((atoi(" 42x"), atoi("-7"), atoi("x"), atoi("99999999999"), atoi("-99999999999")), (42, -7, 0, i32::MAX, i32::MIN));
        assert_eq!((basename("active-response/bin/x"), basename("x"), basename("a/")), ("x", "x", ""));
        assert_eq!((cut("abcdef", 4), cut("é", 2)), ("abc".to_string(), String::new()));
    }
}
