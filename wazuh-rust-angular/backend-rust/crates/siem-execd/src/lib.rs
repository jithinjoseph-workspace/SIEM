//! Port of Wazuh 4.14.7 `wazuh-execd` (`src/os_execd/`): the active
//! response executor. It reads `ar.conf`, runs the response scripts with the
//! JSON protocol (`add`, `check_keys`, `continue`/`abort`, `delete`), keeps
//! the timeout list and the repeated offenders, and answers the `com`
//! requests (`wcom_dispatch`).
//!
//! On Unix it is the `wazuh-execd` daemon reading `queue/alerts/execq`. On
//! Windows it runs inside `wazuh-agent.exe` (`WinExecdStart`): agentd pushes
//! the messages to a queue drained by one thread, and calls
//! `ExecdTimeoutRun` from its main loop.
//!
//! [`Execd`] holds what C keeps in globals; each module ports one C file.

pub mod config;
pub mod exec;
pub mod execd;
pub mod wcom;
pub mod wfd;

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use siem_config::internal_options::InternalOptions;
use siem_log::WLog;

/// `ARGV0` (the Windows agent logs execd under its own name)
#[cfg(unix)]
pub const ARGV0: &str = "wazuh-execd";
#[cfg(windows)]
pub const ARGV0: &str = "wazuh-agent";
/// `ARGV0` of the os_execd objects (`execd.h`), also in the Windows agent:
/// the "module" of the AR messages.
pub const EXECD_NAME: &str = "wazuh-execd";

#[cfg(unix)]
mod paths {
    pub const OSSECCONF: &str = "etc/ossec.conf";
    pub const DEFAULTAR: &str = "etc/shared/ar.conf";
    pub const INCOMING_DIR: &str = "var/incoming";
}
#[cfg(windows)]
mod paths {
    pub const OSSECCONF: &str = "ossec.conf";
    pub const DEFAULTAR: &str = "shared/ar.conf";
    pub const INCOMING_DIR: &str = "incoming";
}
pub use paths::*;
/// `AR_BINDIR`
pub const AR_BINDIR: &str = "active-response/bin";
pub const EXECQUEUE: &str = "queue/alerts/execq";
pub const COM_LOCAL_SOCK: &str = "queue/sockets/com";
pub const CLUSTER_SOCK: &str = "queue/cluster/c-internal.sock";
pub const GROUPGLOBAL: &str = "wazuh";

pub const ADD_ENTRY: &str = "add";
pub const DELETE_ENTRY: &str = "delete";
pub const CONTINUE_ENTRY: &str = "continue";
pub const ABORT_ENTRY: &str = "abort";
pub const CHECK_KEYS_ENTRY: &str = "check_keys";
/// `MAX_AR`
pub const MAX_AR: usize = 64;
/// `EXECD_TIMEOUT`
pub const EXECD_TIMEOUT: i64 = 1;
pub const OS_MAXSTR: usize = 65536;
pub const OS_FLSIZE: usize = 256;
pub const OS_SIZE_4096: usize = 4096;
pub const OS_SIZE_8192: usize = 8192;

pub const EXEC_DISABLED: &str = "(1350): Active response disabled.";
pub const EXEC_SHUTDOWN: &str = "(1314): Shutdown received. Deleting responses.";

pub fn strerror(e: i32) -> String {
    siem_ipc::os_net::strerror(e)
}

pub fn errno() -> i32 {
    siem_ipc::os_net::errno()
}

/// `time(NULL)`
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `timeout_data`
#[derive(Debug, Clone)]
pub struct TimeoutData {
    pub command: String,
    pub parameters: Vec<u8>,
    pub rkey: String,
    pub time_of_addition: i64,
    pub time_to_block: i32,
}

/// The `ar.conf` table (`exec_names`, `exec_cmd`, `exec_timeout`).
#[derive(Default)]
pub struct ExecTable {
    pub names: Vec<String>,
    pub cmds: Vec<String>,
    pub timeouts: Vec<i32>,
    /// `f_time_reading`
    pub read_once: bool,
}

/// The execd globals.
pub struct Execd {
    pub log: Arc<WLog>,
    pub opts: InternalOptions,
    /// `is_disabled`
    pub is_disabled: AtomicI32,
    /// `repeated_offenders_timeout[7]`
    pub repeated_offenders_timeout: Mutex<[i32; 7]>,
    /// `pending_upg`
    pub pending_upg: AtomicI64,
    /// `req_timeout` / `max_restart_lock`
    pub req_timeout: AtomicI32,
    pub max_restart_lock: AtomicI32,
    /// `timeout_list` (with `timeout_list_mutex` on Windows)
    pub timeout_list: Mutex<Option<Vec<TimeoutData>>>,
    /// `repeated_hash` (rkey -> times, as text)
    pub repeated_hash: Mutex<Option<HashMap<String, String>>>,
    pub table: Mutex<ExecTable>,
}

impl Execd {
    pub fn new(log: Arc<WLog>, opts: InternalOptions) -> Execd {
        Execd {
            log,
            opts,
            is_disabled: AtomicI32::new(0),
            repeated_offenders_timeout: Mutex::new([0; 7]),
            pending_upg: AtomicI64::new(0),
            req_timeout: AtomicI32::new(0),
            max_restart_lock: AtomicI32::new(0),
            timeout_list: Mutex::new(None),
            repeated_hash: Mutex::new(None),
            table: Mutex::new(ExecTable { read_once: true, ..Default::default() }),
        }
    }

    /// `merror_exit`
    pub fn exit_critical(&self, msg: impl AsRef<[u8]>) -> ! {
        self.log.critical(msg);
        siem_log::cexit::fatal_exit();
    }

    /// `mlerror_exit(LOGLEVEL_ERROR, ...)`
    pub fn exit_error(&self, msg: impl AsRef<[u8]>) -> ! {
        self.log.error(msg);
        siem_log::cexit::fatal_exit();
    }

    /// `getDefine_Int`
    pub fn define_int(&self, high: &str, low: &str, min: i32, max: i32) -> i32 {
        match self.opts.get_int(high, low, min, max) {
            Ok(v) => v,
            Err(e) => self.exit_critical(e.0),
        }
    }

    pub fn is_disabled(&self) -> bool {
        self.is_disabled.load(Ordering::SeqCst) != 0
    }
}

/// `basename_ex`: glibc `basename` on Unix, `PathFindFileNameA` on Windows
/// (after the last `\`, `/` or `:`).
pub fn basename_ex(path: &str) -> &str {
    #[cfg(unix)]
    let seps: &[char] = &['/'];
    #[cfg(windows)]
    let seps: &[char] = &['\\', '/', ':'];
    match path.rfind(seps) {
        Some(p) if p + 1 < path.len() => &path[p + 1..],
        Some(_) if cfg!(windows) => &path[path.len()..],
        Some(_) => "",
        None => path,
    }
}

/// `cJSON_ReplaceItemInObject`: the first member matching `key`
/// (case-insensitive) is replaced in place, under the key `key`; nothing
/// happens when there is no such member.
pub fn json_replace(obj: Option<&mut siem_cjson::Json>, key: &str, v: siem_cjson::Json) {
    if let Some(siem_cjson::Json::Object(m)) = obj {
        if let Some(e) = m.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(key.as_bytes())) {
            *e = (key.as_bytes().to_vec(), v);
        }
    }
}

/// `snprintf(buf, size, "%s", s)`: at most `size - 1` bytes (on a char
/// boundary).
pub fn trunc(s: &str, size: usize) -> String {
    let mut n = s.len().min(size.saturating_sub(1));
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}
