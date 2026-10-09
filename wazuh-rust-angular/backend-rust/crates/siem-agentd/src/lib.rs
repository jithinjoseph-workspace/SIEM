//! Port of Wazuh 4.14.7 `wazuh-agentd` (`src/client-agent/`): the agent
//! daemon that keeps the encrypted session with the manager, forwards the
//! local event queue (`queue/sockets/queue`) and dispatches what the
//! manager sends back (active responses, shared files, requests).
//!
//! The structure follows the C code: [`Agentd`] holds what C keeps in the
//! globals `agt`, `keys` and friends, and each module ports one C file.
//! Like the C daemon it uses blocking sockets and threads. Unix only.

#![cfg(unix)]

pub mod agcom;
pub mod agentd;
pub mod buffer;
pub mod config;
pub mod enrollment;
pub mod keys;
pub mod notify;
pub mod receiver;
pub mod reload;
pub mod request;
pub mod rotate_log;
pub mod sendmsg;
pub mod start_agent;
pub mod state;
pub mod uninstall;

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use siem_config::client::{AgentConfig, AgentServer, IPPROTO_UDP};
use siem_config::internal_options::InternalOptions;
use siem_config::labels::Label;
use siem_log::WLog;

/// `ARGV0`
pub const ARGV0: &str = "wazuh-agentd";
/// `__ossec_name` / `__ossec_version`
pub const OSSEC_NAME: &str = "Wazuh";
pub const OSSEC_VERSION: &str = "v4.14.7";

// rc.h
pub const CONTROL_HEADER: &str = "#!-";
pub const EXECD_HEADER: &str = "execd ";
pub const FILE_UPDATE_HEADER: &str = "up file ";
pub const FILE_CLOSE_HEADER: &str = "close file ";
pub const HC_STARTUP: &str = "agent startup ";
pub const HC_SHUTDOWN: &str = "agent shutdown ";
pub const HC_ACK: &str = "agent ack ";
pub const HC_REQUEST: &str = "req ";
pub const CFGA_DB_DUMP: &str = "sca-dump";
pub const HC_SK: &str = "syscheck ";
pub const HC_SYSCOLLECTOR: &str = "syscollector_";
pub const HC_FIM_FILE: &str = "fim_file ";
pub const HC_FIM_REGISTRY: &str = "fim_registry ";
pub const HC_FIM_REGISTRY_KEY: &str = "fim_registry_key ";
pub const HC_FIM_REGISTRY_VALUE: &str = "fim_registry_value ";
pub const HC_FORCE_RECONNECT: &str = "force_reconnect";
pub const HC_ERROR: &str = "err ";
/// `REQ_RESPONSE_LENGTH`
pub const REQ_RESPONSE_LENGTH: usize = 64;

// defs.h (Unix paths, relative to the Wazuh home)
pub const OSSECCONF: &str = "etc/ossec.conf";
pub const AGENTCONFIG: &str = "etc/shared/agent.conf";
pub const SHAREDCFG_DIR: &str = "etc/shared";
pub const SHAREDCFG_FILE: &str = "etc/shared/merged.mg";
pub const SHAREDCFG_FILENAME: &str = "merged.mg";
pub const KEYS_FILE: &str = "etc/client.keys";
pub const RIDS_DIR: &str = "queue/rids";
pub const SENDER_COUNTER: &str = "sender_counter";
pub const DEFAULTQUEUE: &str = "queue/sockets/queue";
pub const EXECQUEUE: &str = "queue/alerts/execq";
pub const CFGAQUEUE: &str = "queue/alerts/cfgaq";
pub const AGENT_INFO_FILE: &str = "queue/sockets/.agent_info";
pub const COM_LOCAL_SOCK: &str = "queue/sockets/com";
pub const SYS_LOCAL_SOCK: &str = "queue/sockets/syscheck";
pub const WM_LOCAL_SOCK: &str = "queue/sockets/wmodules";
pub const OS_PIDFILE: &str = "var/run";
pub const USER: &str = "wazuh";
pub const GROUPGLOBAL: &str = "wazuh";
pub const NOTIFY_TIME: i32 = 20;
pub const RECONNECT_TIME: i32 = 60;

pub const OS_MAXSTR: usize = 65536;
pub const OS_HEADER_SIZE: usize = 128;
pub const OS_SIZE_2048: usize = 2048;
pub const OS_SIZE_1024: usize = 1024;
pub const IPSIZE: usize = 46;

// error_messages
pub const LOCALFILE_MQ: char = '1';
pub const CLIENT_ERROR: &str = "(1215): No client configured. Exiting.";
pub const AG_INV_IP: &str = "(4105): No valid server IP found.";
pub const AG_INV_INT: &str =
    "(4114): All server addresses are IPv6 link-local and no interface to any <server> block has been configured.";
pub const AG_NOKEYS_EXIT: &str = "(4109): Unable to start without auth keys. Exiting.";
pub const ENC_READ: &str = "(1410): Reading authentication keys file.";
pub const PID_ERROR: &str = "(1212): Unable to create PID file.";
pub const DISABLED_BUFFER: &str = "Agent buffer disabled.";
pub const LOST_ERROR: &str = "(1137): Lost connection with manager. Setting lock.";
pub const SERVER_UP: &str = "Server responded. Releasing lock.";
pub const SERVER_UNAV: &str = "Server unavailable. Setting lock.";
pub const SEC_ERROR: &str = "(1217): Error creating encrypted message.";
pub const TCP_EPIPE: &str = "(1248): Unable to send message. Connection has been closed by remote server.";
pub const CONN_REF: &str = "(1249): Unable to send message. Connection with remote server refused.";
pub const NO_CLIENT_KEYS: &str = "(1751): File client.keys not found or empty.";
pub const TOLERANCE_TIME: &str = "Tolerance time set to Zero, defined flooding condition when buffer is full.";
pub const FULL_BUFFER: &str = "Agent buffer is full: Events may be lost.";
pub const OS_FULL_BUFFER: &str = "wazuh: Agent buffer: 'full'.";
pub const FLOODED_BUFFER: &str = "Agent buffer is flooded: Producing too many events.";
pub const OS_FLOOD_BUFFER: &str = "wazuh: Agent buffer: 'flooded'.";
pub const OS_NORMAL_BUFFER: &str = "wazuh: Agent buffer: 'normal'.";
pub const AG_IN_UNMERGE: &str = "wazuh: Could not unmerge shared file.";

pub fn startup_msg(pid: u32) -> String {
    format!("Started (pid: {pid}).")
}
pub fn fopen_error(path: &str, e: i32) -> String {
    format!("(1103): Could not open file '{path}' due to [({e})-({})].", strerror(e))
}
pub fn select_error(e: i32) -> String {
    format!("(1114): Error during select()-call due to [({e})-({})].", strerror(e))
}
pub fn no_authfile(f: &str) -> String {
    format!("(1402): Authentication key file '{f}' not found.")
}
pub fn mem_error(e: i32) -> String {
    format!("(1102): Could not acquire memory due to [({e})-({})].", strerror(e))
}

/// `strerror` with glibc wording.
pub fn strerror(e: i32) -> String {
    siem_ipc::os_net::strerror(e)
}

/// `errno`
pub fn errno() -> i32 {
    siem_ipc::os_net::errno()
}

/// `time(NULL)`
pub fn now() -> i64 {
    // SAFETY: time(NULL) has no preconditions.
    unsafe { libc::time(std::ptr::null_mut()) as i64 }
}

/// `w_get_monotonic_time`
pub fn monotonic() -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer to a timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as i64
}

/// `sleep(n)` for a C `int`/`time_t` (negative values sleep 0).
pub fn sleep_secs(n: i64) {
    if n > 0 {
        std::thread::sleep(std::time::Duration::from_secs(n as u64));
    }
}

/// `agent_status_t`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStatus {
    Pending,
    Active,
    NActive,
}

/// Internal options read at run time (the C `int` globals of agentd).
#[derive(Default)]
pub struct Internals {
    pub agent_debug_level: AtomicI32,
    pub warn_level: AtomicI32,
    pub normal_level: AtomicI32,
    pub tolerance: AtomicI32,
    pub timeout: AtomicI32,
    pub interval: AtomicI32,
    pub min_eps: AtomicI32,
    pub remote_conf: AtomicI32,
    pub rotate_log: AtomicI32,
    pub log_compress: AtomicI32,
    pub keep_log_days: AtomicI32,
    pub day_wait: AtomicI32,
    pub size_rotate_read: AtomicI32,
    pub daily_rotations: AtomicI32,
    pub request_pool: AtomicI32,
    pub rto_sec: AtomicI32,
    pub rto_msec: AtomicI32,
    pub max_attempts: AtomicI32,
}

impl Internals {
    pub fn get(v: &AtomicI32) -> i32 {
        v.load(Ordering::SeqCst)
    }
}

/// The agent daemon: C's `agt`, `atc`, `keys` and the module statics.
pub struct Agentd {
    pub log: Arc<WLog>,
    pub opts: InternalOptions,
    /// `agt` configuration fields.
    pub cfg: RwLock<AgentConfig>,
    /// `agt->labels`. Replaced (never edited in place) on reload, so its
    /// pointer tells `run_notify` when to re-format them.
    pub labels: RwLock<Arc<Vec<Label>>>,
    /// `atc->package_uninstallation`
    pub package_uninstallation: AtomicBool,
    /// `agt->flags.remote_conf`
    pub remote_conf_flag: AtomicBool,
    pub sock: AtomicI32,
    pub rip_id: AtomicUsize,
    pub m_queue: AtomicI32,
    pub execdq: AtomicI32,
    pub cfgadq: AtomicI32,
    pub keys: Mutex<keys::AgentKeys>,
    /// `send_mutex` (sendmsg.c)
    pub send_mutex: Mutex<()>,
    pub available_server: AtomicI64,
    pub last_connection_time: AtomicI64,
    pub ints: Internals,
    pub state: state::State,
    pub buffer: buffer::Buffer,
    pub req: request::Requests,
    pub notify: Mutex<notify::NotifyState>,
    pub recv: Mutex<receiver::RecvState>,
    /// `needs_config_reload` (set by SIGUSR1)
    pub needs_config_reload: AtomicBool,
}

impl Agentd {
    pub fn new(log: Arc<WLog>, opts: InternalOptions) -> Agentd {
        Agentd {
            log,
            opts,
            cfg: RwLock::new(AgentConfig::client_defaults(OSSEC_VERSION)),
            labels: RwLock::new(Arc::new(Vec::new())),
            package_uninstallation: AtomicBool::new(false),
            remote_conf_flag: AtomicBool::new(false),
            sock: AtomicI32::new(-1),
            rip_id: AtomicUsize::new(0),
            m_queue: AtomicI32::new(-1),
            execdq: AtomicI32::new(0),
            cfgadq: AtomicI32::new(-1),
            keys: Mutex::new(keys::AgentKeys { verify_counter: true, ..Default::default() }),
            send_mutex: Mutex::new(()),
            available_server: AtomicI64::new(0),
            last_connection_time: AtomicI64::new(0),
            ints: Internals::default(),
            state: state::State::default(),
            buffer: buffer::Buffer::default(),
            req: request::Requests::default(),
            notify: Mutex::new(notify::NotifyState::default()),
            recv: Mutex::new(receiver::RecvState::default()),
            needs_config_reload: AtomicBool::new(false),
        }
    }

    /// `merror_exit`: CRITICAL log, then `exit(1)` (running the atexit hooks).
    pub fn exit_critical(&self, msg: impl AsRef<[u8]>) -> ! {
        self.log.critical(msg);
        std::process::exit(1);
    }

    /// `mlerror_exit(LOGLEVEL_ERROR, msg)`
    pub fn exit_error(&self, msg: impl AsRef<[u8]>) -> ! {
        self.log.error(msg);
        std::process::exit(1);
    }

    /// `getDefine_Int`: exits on a missing or invalid option, as C does.
    pub fn define_int(&self, high: &str, low: &str, min: i32, max: i32) -> i32 {
        match self.opts.get_int(high, low, min, max) {
            Ok(v) => v,
            Err(e) => self.exit_critical(e.0),
        }
    }

    pub fn sock(&self) -> i32 {
        self.sock.load(Ordering::SeqCst)
    }

    pub fn rip_id(&self) -> usize {
        self.rip_id.load(Ordering::SeqCst)
    }

    /// `agt->server[i]`
    pub fn server(&self, i: usize) -> Option<AgentServer> {
        self.cfg.read().unwrap().server.get(i).cloned()
    }

    /// `agt->server[agt->rip_id]`
    pub fn current_server(&self) -> AgentServer {
        self.server(self.rip_id()).unwrap_or_default()
    }

    /// `agt->server[agt->rip_id].protocol == IPPROTO_UDP`
    pub fn is_udp(&self) -> bool {
        self.current_server().protocol == IPPROTO_UDP
    }

    pub fn buffer_enabled(&self) -> bool {
        self.cfg.read().unwrap().buffer
    }
}

/// `"%c:%s:%s"` with `LOCALFILE_MQ` and the "wazuh-agent" location.
pub fn agent_event(msg: &str) -> String {
    format!("{LOCALFILE_MQ}:wazuh-agent:{msg}")
}

/// `snprintf(buf, size, ...)`: keep at most `size - 1` bytes.
pub fn trunc_bytes(mut v: Vec<u8>, size: usize) -> Vec<u8> {
    if v.len() > size.saturating_sub(1) {
        v.truncate(size.saturating_sub(1));
    }
    v
}
