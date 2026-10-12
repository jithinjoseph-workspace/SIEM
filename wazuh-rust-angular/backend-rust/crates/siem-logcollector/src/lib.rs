//! Port of Wazuh 4.14.7 `wazuh-logcollector` (`src/logcollector/`) for
//! Linux: localfile monitoring (files, globs, date-based names, commands,
//! journald), the format readers, per-target output queues, the
//! `file_status.json` positions, statistics and the `lccom` socket.
//!
//! [`Lc`] holds what the C daemon keeps in globals; the file lists live in
//! [`Files`] behind the `files_update_rwlock`, each entry in its own mutex
//! as in C. The `<localfile>` parsing itself is in
//! `siem_config::localfile`.



pub mod cfile;
pub mod collector;
pub mod config;
#[cfg(target_os = "linux")]
pub mod journal;
#[cfg(not(target_os = "linux"))]
#[path = "journal_none.rs"]
pub mod journal;
pub mod lccom;
pub mod logbuilder;
pub mod output;
pub mod read_alert;
pub mod readers;
pub mod state;
pub mod status;
#[cfg(windows)]
pub mod eventchannel;
#[cfg(windows)]
pub mod eventlog;
#[cfg(windows)]
pub mod win;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use siem_config::internal_options::InternalOptions;
use siem_config::localfile::Localfile;
use siem_config::socket::SocketMode;
use siem_log::WLog;

pub use cfile::{cstr, strlen, CFile};

#[cfg(unix)]
mod paths {
    pub const ARGV0: &str = "wazuh-logcollector";
    pub const OSSECCONF: &str = "etc/ossec.conf";
    pub const AGENTCONFIG: &str = "etc/shared/agent.conf";
    pub const AGENT_INFO_FILE: &str = "queue/sockets/.agent_info";
    pub const LOCALFILE_STATUS: &str = "queue/logcollector/file_status.json";
    pub const LOGCOLLECTOR_STATE: &str = "var/run/wazuh-logcollector.state";
}
/// Windows: logcollector is a thread of `wazuh-agent.exe`.
#[cfg(windows)]
mod paths {
    pub const ARGV0: &str = "wazuh-agent";
    pub const OSSECCONF: &str = "ossec.conf";
    pub const AGENTCONFIG: &str = "shared/agent.conf";
    pub const AGENT_INFO_FILE: &str = ".agent_info";
    pub const LOCALFILE_STATUS: &str = "queue\\logcollector\\file_status.json";
    pub const LOGCOLLECTOR_STATE: &str = "wazuh-logcollector.state";
}
pub use paths::*;
pub const DEFAULTQUEUE: &str = "queue/sockets/queue";
pub const LC_LOCAL_SOCK: &str = "queue/sockets/logcollector";
/// `WIN32_MAX_FILES`
pub const WIN32_MAX_FILES: i32 = 200;
pub const GROUPGLOBAL: &str = "wazuh";

pub const OS_MAXSTR: usize = 65536;
/// `OS_LOG_HEADER`
pub const OS_LOG_HEADER: usize = 256;
/// `OS_MAX_LOG_SIZE` (`OS_MAXSTR - OS_LOG_HEADER - 1`)
pub const OS_MAX_LOG_SIZE: usize = OS_MAXSTR - OS_LOG_HEADER - 1;
pub const OS_SIZE_1024: usize = 1024;
pub const OS_SIZE_2048: usize = 2048;

pub const LOCALFILE_MQ: u8 = b'1';
pub const HOSTINFO_MQ: u8 = b'3';

pub const N_MIN_INPUT_THREADS: i32 = 1;
pub const OUTPUT_MIN_QUEUE_SIZE: i32 = 128;

/// `strerror` with glibc wording.
pub fn strerror(e: i32) -> String {
    siem_ipc::os_net::strerror(e)
}

pub fn errno() -> i32 {
    siem_ipc::os_net::errno()
}

/// The fields of `localtime(time(NULL))` the readers print.
pub struct LocalTm {
    pub tm_mon: i32,
    pub tm_mday: i32,
    pub tm_hour: i32,
    pub tm_min: i32,
    pub tm_sec: i32,
}

/// `localtime_r(time(NULL))` (`localtime_s` on Windows)
pub fn local_tm_now() -> LocalTm {
    #[cfg(unix)]
    // SAFETY: time/localtime_r on valid buffers.
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        LocalTm { tm_mon: tm.tm_mon, tm_mday: tm.tm_mday, tm_hour: tm.tm_hour, tm_min: tm.tm_min, tm_sec: tm.tm_sec }
    }
    #[cfg(windows)]
    {
        use chrono::{Datelike, Timelike};
        let n = chrono::Local::now();
        LocalTm {
            tm_mon: n.month0() as i32,
            tm_mday: n.day() as i32,
            tm_hour: n.hour() as i32,
            tm_min: n.minute() as i32,
            tm_sec: n.second() as i32,
        }
    }
}

/// `time(NULL)`
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn sleep_secs(n: i64) {
    if n > 0 {
        std::thread::sleep(std::time::Duration::from_secs(n as u64));
    }
}

pub fn fopen_error(path: &str, e: i32) -> String {
    format!("(1103): Could not open file '{path}' due to [({e})-({})].", strerror(e))
}

pub fn fstat_error(path: &str, e: i32) -> String {
    format!("(1118): Could not retrieve information of file '{path}' due to [({e})-({})].", strerror(e))
}

/// `'%.*s'`: at most `n` bytes of a C string.
pub fn sample(b: &[u8], n: i32) -> String {
    let s = cstr(b);
    String::from_utf8_lossy(&s[..s.len().min(n.max(0) as usize)]).into_owned()
}

/// A `socket_forwarder` at run time.
#[derive(Debug)]
pub struct SockFwd {
    pub name: String,
    pub location: String,
    pub mode: SocketMode,
    pub prefix: Option<String>,
    /// (`socket`, `last_attempt`)
    pub conn: Mutex<(i32, i64)>,
}

impl SockFwd {
    pub fn new(name: &str, location: &str, mode: SocketMode, prefix: Option<String>) -> SockFwd {
        SockFwd { name: name.into(), location: location.into(), mode, prefix, conn: Mutex::new((-1, 0)) }
    }
}

/// `logtarget`
#[derive(Debug, Clone)]
pub struct LogTarget {
    pub format: Option<String>,
    pub socket: Arc<SockFwd>,
}

/// A reader function (`void *(*read)(logreader *, int *rc, int drop_it)`).
pub type ReadFn = fn(&Lc, &mut Reader, &mut i32, i32);

/// `logreader`: the configuration plus the run-time fields.
pub struct Reader {
    pub c: Localfile,
    pub size: i64,
    pub dev: u64,
    /// `fd`: the inode of the open file.
    pub fd: u64,
    pub duplicated: i32,
    pub log_target: Option<Arc<Vec<LogTarget>>>,
    pub read: Option<ReadFn>,
    pub fp: Option<CFile>,
    /// `position` (saved by `close_file`).
    pub position: i64,
}

impl Reader {
    pub fn new(c: Localfile) -> Reader {
        Reader { c, size: 0, dev: 0, fd: 0, duplicated: 0, log_target: None, read: None, fp: None, position: 0 }
    }

    /// `memcpy` of an entry (the open file is not shared).
    pub fn copy(&self) -> Reader {
        Reader {
            c: self.c.shallow_copy(),
            size: self.size,
            dev: self.dev,
            fd: self.fd,
            duplicated: self.duplicated,
            log_target: self.log_target.clone(),
            read: self.read,
            fp: None,
            position: self.position,
        }
    }

    pub fn file(&self) -> &str {
        self.c.file.as_deref().unwrap_or("")
    }

    pub fn targets(&self) -> Arc<Vec<LogTarget>> {
        self.log_target.clone().unwrap_or_default()
    }
}

/// `logreader_glob`
pub struct Glob {
    pub gpath: String,
    pub exclude_path: Option<String>,
    pub num_files: i32,
    /// Expanded files, then the template (`file == None`).
    pub gfiles: Vec<Mutex<Reader>>,
}

/// `logff` and `globs`.
#[derive(Default)]
pub struct Files {
    pub logff: Vec<Mutex<Reader>>,
    pub globs: Vec<Glob>,
}

/// `IT_control`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum It {
    Continue,
    Next,
    Leave,
}

/// Look at an entry without blocking: an entry another thread is reading
/// was handed out by `update_current` and its `file`/`logformat` only
/// change under the write lock, so a busy entry counts as present.
fn peek(m: &Mutex<Reader>, f: impl Fn(&Reader) -> bool) -> bool {
    match m.try_lock() {
        Ok(g) => f(&g),
        Err(std::sync::TryLockError::Poisoned(p)) => f(&p.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => true,
    }
}

impl Files {
    /// `update_current`: advance `(i, j)` over `logff` then each glob.
    pub fn update_current(&self, i: &mut i32, j: &mut i32) -> It {
        if *j < 0 {
            let ok = self
                .logff
                .get(*i as usize)
                .map(|m| peek(m, |r| r.c.logformat.is_some()))
                .unwrap_or(false);
            if !ok {
                if !self.globs.is_empty() && !self.globs[0].gfiles.is_empty() {
                    *i = -1;
                    *j = 0;
                    return It::Next;
                }
                return It::Leave;
            }
        } else {
            let g = &self.globs[*j as usize];
            let file_ok = *i <= g.num_files
                && g.gfiles
                    .get(*i as usize)
                    .map(|m| peek(m, |r| r.c.file.is_some()))
                    .unwrap_or(false);
            if !file_ok {
                *i = -1;
                *j += 1;
                if (*j as usize) >= self.globs.len() {
                    return It::Leave;
                }
                return It::Next;
            }
        }
        It::Continue
    }

    /// The entry `(i, j)` points at.
    pub fn entry(&self, i: i32, j: i32) -> &Mutex<Reader> {
        if j < 0 {
            &self.logff[i as usize]
        } else {
            &self.globs[j as usize].gfiles[i as usize]
        }
    }

    pub fn entry_mut(&mut self, i: i32, j: i32) -> &mut Reader {
        let m = if j < 0 { &mut self.logff[i as usize] } else { &mut self.globs[j as usize].gfiles[i as usize] };
        m.get_mut().unwrap_or_else(|e| e.into_inner())
    }
}

/// The run-time internal options (`logcollector.*`).
#[derive(Default)]
pub struct Ints {
    pub accept_remote: AtomicI32,
    pub loop_timeout: AtomicI32,
    pub open_file_attempts: AtomicI32,
    pub vcheck_files: AtomicI32,
    pub maximum_lines: AtomicI32,
    pub maximum_files: AtomicI32,
    pub sock_fail_time: AtomicI32,
    pub sample_log_length: AtomicI32,
    pub force_reload: AtomicI32,
    pub reload_interval: AtomicI32,
    pub reload_delay: AtomicI32,
    pub free_excluded_files_interval: AtomicI32,
    pub state_interval: AtomicI32,
    pub nofile: AtomicI32,
    pub lc_debug_level: AtomicI32,
    pub n_input_threads: AtomicI32,
    pub output_queue_size: AtomicI32,
}

pub fn get(v: &AtomicI32) -> i32 {
    v.load(Ordering::SeqCst)
}

/// The logcollector daemon state.
pub struct Lc {
    pub log: Arc<WLog>,
    pub opts: InternalOptions,
    pub ints: Ints,
    /// `files_update_rwlock` + `logff` / `globs`
    pub files: RwLock<Files>,
    /// `logsk`
    pub logsk: RwLock<Vec<Arc<SockFwd>>>,
    pub default_agent: Arc<SockFwd>,
    pub current_files: AtomicI32,
    pub total_files: AtomicI32,
    /// `_can_read`
    pub can_read: AtomicBool,
    pub status: status::FileStatusTable,
    pub excluded_files: Mutex<HashSet<String>>,
    pub excluded_binaries: Mutex<HashSet<String>>,
    pub queues: output::Queues,
    pub state: state::LcState,
    pub builder: logbuilder::LogBuilder,
    pub logr_queue: AtomicI32,
    /// `_cday`
    pub cday: AtomicI32,
    pub journald: journal::Journald,
    /// Statics of the readers (`__mysql_last_time`, `djb_host`, ...).
    pub statics: Mutex<HashMap<&'static str, Vec<u8>>>,
    pub reported_queue_full: AtomicBool,
    pub last_mono: AtomicI64,
    /// `win_el_mutex`: one input thread reads the event logs at a time
    #[cfg(windows)]
    pub win_el_mutex: Mutex<()>,
}

impl Lc {
    pub fn new(log: Arc<WLog>, opts: InternalOptions) -> Lc {
        Lc {
            log,
            opts,
            ints: Ints::default(),
            files: RwLock::new(Files::default()),
            logsk: RwLock::new(Vec::new()),
            default_agent: Arc::new(SockFwd::new("agent", "", SocketMode::Udp, None)),
            current_files: AtomicI32::new(0),
            total_files: AtomicI32::new(0),
            can_read: AtomicBool::new(false),
            status: status::FileStatusTable::default(),
            excluded_files: Mutex::new(HashSet::new()),
            excluded_binaries: Mutex::new(HashSet::new()),
            queues: output::Queues::default(),
            state: state::LcState::default(),
            builder: logbuilder::LogBuilder::default(),
            logr_queue: AtomicI32::new(-1),
            cday: AtomicI32::new(0),
            journald: journal::Journald::default(),
            statics: Mutex::new(HashMap::new()),
            reported_queue_full: AtomicBool::new(false),
            last_mono: AtomicI64::new(0),
            #[cfg(windows)]
            win_el_mutex: Mutex::new(()),
        }
    }

    pub fn exit_critical(&self, msg: impl AsRef<[u8]>) -> ! {
        self.log.critical(msg);
        siem_log::cexit::fatal_exit();
    }

    /// `getDefine_Int`
    pub fn define_int(&self, high: &str, low: &str, min: i32, max: i32) -> i32 {
        match self.opts.get_int(high, low, min, max) {
            Ok(v) => v,
            Err(e) => self.exit_critical(e.0),
        }
    }

    /// `can_read()`
    pub fn can_read(&self) -> bool {
        self.can_read.load(Ordering::SeqCst)
    }

    pub fn max_lines(&self) -> i32 {
        get(&self.ints.maximum_lines)
    }

    pub fn sample_len(&self) -> i32 {
        get(&self.ints.sample_log_length)
    }

    /// `CURRENT_FILES`
    pub fn current_files_msg(&self) -> String {
        format!(
            "(1961): Files being monitored: {}/{}.",
            self.current_files.load(Ordering::SeqCst),
            get(&self.ints.maximum_files)
        )
    }
}
