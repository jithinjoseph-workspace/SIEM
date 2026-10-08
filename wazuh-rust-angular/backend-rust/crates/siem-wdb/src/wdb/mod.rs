//! Faithful port of wazuh-db's library (wazuh_db/ of Wazuh 4.14.7): the
//! per-agent, global, tasks and MITRE SQLite databases, the query parser and
//! the per-domain operations, on SQLite 3.50.4 (siem-sqlite) like the C.
//!
//! The C globals (`wconfig`, the pool, `wdb_state`, the router handles) live
//! in [`Wdbd`]; process services (logging, clock, router, peer socket) go
//! through [`WdbEnv`] so tests can pin and capture them. Paths are relative
//! to [`Wdbd::base`] (empty in the daemon, which chdirs/chroots to its home).

pub mod agentdb;
pub mod config;
#[cfg(target_os = "linux")]
pub mod daemon;
pub mod delta;
pub mod fim;
pub mod global;
#[cfg(target_os = "linux")]
pub mod http;
#[cfg(target_os = "linux")]
pub mod httplib;
pub mod integrity;
pub mod metadata;
pub use siem_njson as njson;
pub mod parser;
pub mod parser_agent;
pub mod parser_global;
pub mod pool;
pub mod sca;
pub mod schema;
pub mod sk;
pub mod state;
pub mod stmts;
pub mod syscollector;
pub mod tables;
pub mod task;
pub mod upgrade;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use siem_cjson::Json;
use siem_sqlite::{Db, Stmt};

pub use pool::{Guard, Pool};
pub use stmts::*;

pub use siem_sqlite::{
    SQLITE_BLOB, SQLITE_BUSY, SQLITE_CONSTRAINT, SQLITE_DONE, SQLITE_ERROR, SQLITE_FLOAT, SQLITE_INTEGER, SQLITE_MISUSE, SQLITE_NULL,
    SQLITE_OK, SQLITE_OPEN_CREATE, SQLITE_OPEN_READONLY, SQLITE_OPEN_READWRITE, SQLITE_ROW, SQLITE_TEXT,
};

pub type B = Vec<u8>;

pub const OS_SUCCESS: i32 = 0;
pub const OS_INVALID: i32 = -1;
pub const OS_NOTFOUND: i32 = -2;
pub const OS_SIZELIM: i32 = -4;
pub const OS_SOCKTERR: i32 = -6;

pub const OS_SIZE_64: usize = 64;
pub const OS_SIZE_128: usize = 128;
pub const OS_SIZE_256: usize = 256;
pub const OS_SIZE_8192: usize = 8192;
pub const OS_SIZE_512: usize = 512;
pub const OS_SIZE_1024: usize = 1024;
pub const OS_SIZE_2048: usize = 2048;
pub const OS_SIZE_4096: usize = 4096;
pub const OS_SIZE_6144: usize = 6144;
pub const OS_MAXSTR: usize = 65536;
pub const OS_FLSIZE: usize = 256;
/// `PATH_MAX`
pub const PATH_MAX: usize = 4096;

pub const ARGV0: &str = "wazuh-db";
pub const WDB_DIR: &str = "var/db";
pub const WDB2_DIR: &str = "queue/db";
pub const WDB_GLOB_NAME: &str = "global";
pub const WDB_MITRE_NAME: &str = "mitre";
pub const WDB_PROF_NAME: &str = ".template.db";
pub const WDB_PROF_PATH: &str = "queue/db/.template.db";
pub const WDB_TASK_DIR: &str = "queue/tasks";
pub const WDB_TASK_NAME: &str = "tasks";
pub const WDB_BACKUP_FOLDER: &str = "backup/db";
pub const WDB_LOCAL_SOCK: &str = "queue/db/wdb";

pub const WDB_MAX_COMMAND_SIZE: usize = 512;
pub const WDB_MAX_RESPONSE_SIZE: usize = OS_MAXSTR - WDB_MAX_COMMAND_SIZE;
pub const WDB_MAX_QUERY_SIZE: usize = OS_MAXSTR - WDB_MAX_COMMAND_SIZE;
pub const WDB_BLOCK_SEND_TIMEOUT_S: i32 = 1;
pub const WDB_RESPONSE_OK_SIZE: usize = 3;
pub const WDB_GROUP_HASH_SIZE: usize = 8;
pub const WDB_MULTI_GROUP_DELIM: u8 = b'-';
pub const SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE: &str = "legacy";
pub const WDB_NETADDR_IPV4: i32 = 0;

pub const STMT_MULTI_COLUMN: bool = false;
pub const STMT_SINGLE_COLUMN: bool = true;

const MAX_ATTEMPTS: i32 = 1000;

// wdb_component_t
pub const WDB_FIM: i32 = 0;
pub const WDB_FIM_FILE: i32 = 1;
pub const WDB_FIM_REGISTRY: i32 = 2;
pub const WDB_FIM_REGISTRY_KEY: i32 = 3;
pub const WDB_FIM_REGISTRY_VALUE: i32 = 4;
pub const WDB_SYSCOLLECTOR_PROCESSES: i32 = 5;
pub const WDB_SYSCOLLECTOR_PACKAGES: i32 = 6;
pub const WDB_SYSCOLLECTOR_HOTFIXES: i32 = 7;
pub const WDB_SYSCOLLECTOR_PORTS: i32 = 8;
pub const WDB_SYSCOLLECTOR_NETPROTO: i32 = 9;
pub const WDB_SYSCOLLECTOR_NETADDRESS: i32 = 10;
pub const WDB_SYSCOLLECTOR_NETINFO: i32 = 11;
pub const WDB_SYSCOLLECTOR_HWINFO: i32 = 12;
pub const WDB_SYSCOLLECTOR_OSINFO: i32 = 13;
pub const WDB_SYSCOLLECTOR_USERS: i32 = 14;
pub const WDB_SYSCOLLECTOR_GROUPS: i32 = 15;
pub const WDB_SYSCOLLECTOR_BROWSER_EXTENSIONS: i32 = 16;
pub const WDB_SYSCOLLECTOR_SERVICES: i32 = 17;
pub const WDB_GENERIC_COMPONENT: i32 = 18;

/// A byte string piece of a log message or a response.
pub trait AsMsg {
    fn put(&self, out: &mut Vec<u8>);
}

impl AsMsg for str {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}
impl AsMsg for String {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}
impl AsMsg for [u8] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl AsMsg for Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl<const N: usize> AsMsg for [u8; N] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
macro_rules! asmsg_int {
    ($($t:ty),*) => {$(
        impl AsMsg for $t {
            fn put(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(self.to_string().as_bytes());
            }
        }
    )*};
}
asmsg_int!(i32, i64, u32, u64, usize, isize, u8, u16, i16);
impl<T: AsMsg + ?Sized> AsMsg for &T {
    fn put(&self, out: &mut Vec<u8>) {
        (**self).put(out)
    }
}

/// Concatenates message pieces (strings, bytes, integers) into bytes.
#[macro_export]
macro_rules! msg {
    ($($a:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut v: Vec<u8> = Vec::new();
        $( $crate::wdb::AsMsg::put(&$a, &mut v); )*
        v
    }};
}
pub use crate::msg;

/// `snprintf(buf, size, ...)`: at most `size - 1` bytes.
pub fn trunc(mut v: B, size: usize) -> B {
    v.truncate(size.saturating_sub(1));
    v
}

/// `snprintf(output, OS_MAXSTR + 1, ...)`
pub fn out(parts: B) -> B {
    trunc(parts, OS_MAXSTR + 1)
}

/// The bytes before the first NUL (what C sees of a buffer).
pub fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `%.32s`
pub fn s32(b: &[u8]) -> &[u8] {
    let b = cstr(b);
    &b[..b.len().min(32)]
}

/// The process services wazuh-db uses.
pub trait WdbEnv: Send + Sync {
    /// A log message ("ERROR", "WARNING", "INFO", "DEBUG", "DEBUG2").
    fn log(&self, level: &str, msg: &[u8]);
    /// `time(NULL)`
    fn time(&self) -> i64;
    /// `gettimeofday`
    fn timeofday(&self) -> state::Tv;
    /// `router_provider_send` on the agent (1) or inventory (2) topic.
    fn router_send(&self, handle: i32, msg: &[u8]);
    /// `OS_SendSecureTCP(peer, len, msg)`
    fn send_peer(&self, peer: i32, msg: &[u8]) -> i32;
    /// `OS_SetSendTimeout(peer, secs)`
    fn set_send_timeout(&self, _peer: i32, _secs: i32) -> i32 {
        0
    }
    /// `w_is_single_node(&is_worker)`: (return value, is_worker)
    fn is_single_node(&self) -> (i32, i32);
    /// `w_time_delay(ms)`
    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    /// `close(peer)` (the packages/hotfixes streams on a socket error)
    fn close_peer(&self, _peer: i32) {}
    /// The offset of `localtime(t)` from UTC, in seconds east.
    fn utc_offset(&self, t: i64) -> i64 {
        use chrono::{Local, Offset, TimeZone};
        match Local.timestamp_opt(t, 0).single() {
            Some(d) => d.offset().fix().local_minus_utc() as i64,
            None => 0,
        }
    }
}

/// `wdb_backup_settings_node`
#[derive(Debug, Clone)]
pub struct BackupSettings {
    pub enabled: bool,
    pub interval: i64,
    pub max_files: i32,
}

/// `wdb_config` (`wdb_init_conf` defaults for the backup settings).
#[derive(Debug, Clone)]
pub struct WdbConfig {
    pub worker_pool_size: i32,
    pub commit_time_min: i32,
    pub commit_time_max: i32,
    pub open_db_limit: i32,
    pub fragmentation_threshold: i32,
    pub fragmentation_delta: i32,
    pub free_pages_percentage: i32,
    pub max_fragmentation: i32,
    pub check_fragmentation_interval: i32,
    /// indexed by `wdb_backup_db` (`WDB_GLOBAL_BACKUP`)
    pub backup: Vec<BackupSettings>,
    pub is_worker_node: bool,
}

pub const WDB_GLOBAL_BACKUP: usize = 0;
pub const WDB_LAST_BACKUP: usize = 1;

impl Default for WdbConfig {
    /// internal_options.conf defaults + `wdb_init_conf`
    fn default() -> Self {
        WdbConfig {
            worker_pool_size: 8,
            commit_time_min: 10,
            commit_time_max: 60,
            open_db_limit: 64,
            fragmentation_threshold: 75,
            fragmentation_delta: 5,
            free_pages_percentage: 0,
            max_fragmentation: 90,
            check_fragmentation_interval: 7200,
            backup: vec![BackupSettings { enabled: true, interval: 86400, max_files: 3 }; WDB_LAST_BACKUP],
            is_worker_node: false,
        }
    }
}

/// `wdb_t` (the part protected by its mutex).
pub struct Wdb {
    pub db: Option<Db>,
    pub stmt: Vec<Option<Arc<Stmt>>>,
    pub id: String,
    pub peer: i32,
    pub transaction: bool,
    pub transaction_begin_time: i64,
    /// `cache_list`: (query, statement)
    pub cache_list: Vec<(B, Arc<Stmt>)>,
    pub enabled: bool,
}

impl Wdb {
    /// `wdb_init`
    pub fn new(id: &str) -> Wdb {
        Wdb {
            db: None,
            stmt: vec![None; WDB_STMT_SIZE],
            id: id.to_string(),
            peer: 0,
            transaction: false,
            transaction_begin_time: 0,
            cache_list: Vec::new(),
            enabled: true,
        }
    }

    /// `sqlite3_errmsg(wdb->db)` ("out of memory" for a NULL handle)
    pub fn errmsg(&self) -> B {
        match &self.db {
            Some(d) => d.errmsg(),
            None => b"out of memory".to_vec(),
        }
    }

    pub fn db(&self) -> &Db {
        // a closed handle is the C NULL connection
        self.db.as_ref().unwrap_or(&siem_sqlite::NULL_DB)
    }

    /// `wdb->stmt[i]` after `wdb_stmt_cache`
    pub fn st(&self, i: usize) -> Arc<Stmt> {
        self.stmt[i].clone().expect("statement cached")
    }
}

/// `wdb_step`: `sqlite3_step` retried while busy.
pub fn wdb_step(env: &dyn WdbEnv, stmt: &Stmt) -> i32 {
    let mut attempts = 0;
    loop {
        let r = stmt.step();
        if r != SQLITE_BUSY {
            return r;
        }
        if attempts == MAX_ATTEMPTS {
            env.log("DEBUG", b"Maximum attempts exceeded for sqlite3_step()");
            return -1;
        }
        attempts += 1;
    }
}

/// `wdb_prepare`: `sqlite3_prepare_v2` retried while busy.
pub fn wdb_prepare(env: &dyn WdbEnv, db: &Db, sql: &[u8]) -> (i32, Option<Stmt>) {
    let mut attempts = 0;
    loop {
        let (r, st, _) = db.prepare_v2(sql);
        if r != SQLITE_BUSY {
            return (r, st);
        }
        if attempts == MAX_ATTEMPTS {
            env.log("DEBUG", b"Maximum attempts exceeded for sqlite3_prepare_v2()");
            return (-1, None);
        }
        attempts += 1;
    }
}

/// `atoi`
pub fn atoi(s: &[u8]) -> i32 {
    strtol(s) as i32
}

/// `strtol(s, NULL, 10)` (saturating, leading spaces and sign).
pub fn strtol(s: &[u8]) -> i64 {
    strtol_end(s).0
}

/// `strtol(s, &end, 10)`: the value and the offset of `end`.
pub fn strtol_end(s: &[u8]) -> (i64, usize) {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: i128 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = (v * 10 + (s[i] - b'0') as i128).min(i64::MAX as i128 + 1);
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    let v = if neg { -v } else { v };
    (v.clamp(i64::MIN as i128, i64::MAX as i128) as i64, i)
}

/// Whether `strtol(s, ..., 10)` saturates (sets ERANGE).
pub fn strtol_overflows(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: i128 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v * 10 + (s[i] - b'0') as i128;
        if v > i64::MAX as i128 + 1 {
            return true;
        }
        i += 1;
    }
    if neg {
        v > i64::MAX as i128 + 1
    } else {
        v > i64::MAX as i128
    }
}

/// `wstr_chr(s, c)`: the first `c` not escaped with a backslash.
pub fn wstr_chr(s: &[u8], c: u8) -> Option<usize> {
    let mut escaped = false;
    for (i, &ch) in s.iter().enumerate() {
        if ch == 0 {
            return None;
        }
        if !escaped {
            if ch == c {
                return Some(i);
            }
            if ch == b'\\' {
                escaped = true;
            }
        } else {
            escaped = false;
        }
    }
    None
}

/// wazuh-db's process-wide state.
pub struct Wdbd {
    pub cfg: WdbConfig,
    /// The home directory paths are relative to (empty in the daemon).
    pub base: PathBuf,
    pub pool: Arc<Pool>,
    pub state: state::State,
    pub env: Arc<dyn WdbEnv>,
    /// `router_agent_events_handle != NULL`
    pub router_agent: bool,
    /// `router_inventory_events_handle != NULL`
    pub router_inventory: bool,
    /// `profile_mutex` of `wdb_create_agent_db2`
    profile_mutex: Mutex<()>,
    /// The cached global group hash (`global_group_hash`, empty: none)
    pub group_hash: Mutex<B>,
    /// The `static int last_id` of `wdb_parse_global_sync_agent_info_get`
    pub sync_last_id: Mutex<i32>,
}

impl Wdbd {
    pub fn new(cfg: WdbConfig, base: PathBuf, env: Arc<dyn WdbEnv>) -> Wdbd {
        Wdbd {
            cfg,
            base,
            pool: Arc::new(Pool::default()),
            state: state::State::default(),
            env,
            router_agent: false,
            router_inventory: false,
            profile_mutex: Mutex::new(()),
            group_hash: Mutex::new(Vec::new()),
            sync_last_id: Mutex::new(0),
        }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.base.join(rel)
    }

    pub fn time(&self) -> i64 {
        self.env.time()
    }

    pub fn merror(&self, m: &[u8]) {
        self.env.log("ERROR", m);
    }
    pub fn mwarn(&self, m: &[u8]) {
        self.env.log("WARNING", m);
    }
    pub fn minfo(&self, m: &[u8]) {
        self.env.log("INFO", m);
    }
    pub fn mdebug1(&self, m: &[u8]) {
        self.env.log("DEBUG", m);
    }
    pub fn mdebug2(&self, m: &[u8]) {
        self.env.log("DEBUG2", m);
    }

    pub fn step(&self, st: &Stmt) -> i32 {
        wdb_step(&*self.env, st)
    }

    /// `wdb_pool_get_or_create`
    pub fn pool_get_or_create(&self, name: &str) -> Guard {
        self.pool.get_or_create(name, self.time())
    }

    /// `wdb_pool_get`
    pub fn pool_get(&self, name: &str) -> Option<Guard> {
        self.pool.get(name, self.time())
    }

    /// `wdb_pool_leave` (stamps the current time)
    pub fn leave(&self, mut g: Guard) {
        g.set_leave_time(self.time());
        drop(g);
    }

    fn open_path(path: &Path) -> B {
        path.to_string_lossy().as_bytes().to_vec()
    }

    /// `sqlite3_open_v2(path, &wdb->db, flags, NULL)`: true when it fails
    /// (the handle is kept for `sqlite3_errmsg`, like the C).
    fn open_into(wdb: &mut Wdb, path: &Path, flags: i32) -> bool {
        let (rc, db) = Db::open_v2(&Self::open_path(path), flags);
        wdb.db = db;
        rc != SQLITE_OK
    }

    /// `wdb_open_global`: the locked global database or None.
    pub fn open_global(&self) -> Option<Guard> {
        let mut wdb = self.pool_get_or_create(WDB_GLOB_NAME);
        if wdb.db.is_none() {
            let rel = format!("{WDB2_DIR}/{WDB_GLOB_NAME}.db");
            let path = self.path(&rel);
            if Self::open_into(&mut wdb, &path, SQLITE_OPEN_READWRITE) {
                self.mdebug1(b"Global database not found, creating.");
                self.close(&mut wdb, false);
                if self.create_global(&path) != OS_SUCCESS {
                    self.merror(&msg!("Couldn't create SQLite database '", rel, "'"));
                    self.leave(wdb);
                    return None;
                }
                if Self::open_into(&mut wdb, &path, SQLITE_OPEN_READWRITE) {
                    self.merror(&msg!("Can't open SQLite database '", rel, "': ", wdb.errmsg()));
                    self.close(&mut wdb, false);
                    self.leave(wdb);
                    return None;
                }
            } else {
                let ok = self.upgrade_global(&mut wdb);
                if !ok || wdb.db.is_none() {
                    self.leave(wdb);
                    return None;
                }
            }
            self.enable_foreign_keys(&wdb);
            self.set_synchronous_normal(&wdb);
        }
        Some(wdb)
    }

    /// `wdb_open_mitre`
    pub fn open_mitre(&self) -> Option<Guard> {
        let mut wdb = self.pool_get_or_create(WDB_MITRE_NAME);
        if wdb.db.is_some() {
            return Some(wdb);
        }
        let rel = format!("{WDB_DIR}/{WDB_MITRE_NAME}.db");
        if Self::open_into(&mut wdb, &self.path(&rel), SQLITE_OPEN_READWRITE) {
            self.merror(&msg!("Can't open SQLite database '", rel, "': ", wdb.errmsg()));
            self.close(&mut wdb, false);
            self.leave(wdb);
            return None;
        }
        Some(wdb)
    }

    /// `wdb_open_agent2`
    pub fn open_agent2(&self, agent_id: i32) -> Option<Guard> {
        let sagent_id = format!("{agent_id:03}");
        let mut wdb = self.pool_get_or_create(&sagent_id);
        if wdb.db.is_some() {
            return Some(wdb);
        }
        let rel = format!("{WDB2_DIR}/{sagent_id}.db");
        let path = self.path(&rel);
        if Self::open_into(&mut wdb, &path, SQLITE_OPEN_READWRITE) {
            self.mdebug1(&msg!("No SQLite database found for agent '", sagent_id, "', creating."));
            self.close(&mut wdb, false);
            if self.create_agent_db2(&sagent_id) < 0 {
                self.merror(&msg!("Couldn't create SQLite database '", rel, "'"));
                self.leave(wdb);
                return None;
            }
            if Self::open_into(&mut wdb, &path, SQLITE_OPEN_READWRITE) {
                self.merror(&msg!("Can't open SQLite database '", rel, "': ", wdb.errmsg()));
                self.close(&mut wdb, false);
                self.leave(wdb);
                return None;
            }
        } else if !self.upgrade(&mut wdb) {
            self.leave(wdb);
            return None;
        }
        Some(wdb)
    }

    /// `wdb_open_tasks`
    pub fn open_tasks(&self) -> Option<Guard> {
        let mut wdb = self.pool_get_or_create(WDB_TASK_NAME);
        if wdb.db.is_none() {
            let rel = format!("{WDB_TASK_DIR}/{WDB_TASK_NAME}.db");
            let path = self.path(&rel);
            if Self::open_into(&mut wdb, &path, SQLITE_OPEN_READWRITE) {
                self.mdebug1(b"Tasks database not found, creating.");
                self.close(&mut wdb, false);
                if self.create_file(&path, schema::task_manager()) != OS_SUCCESS {
                    self.merror(&msg!("Couldn't create SQLite database '", rel, "'"));
                    self.leave(wdb);
                    return None;
                }
                if Self::open_into(&mut wdb, &path, SQLITE_OPEN_READWRITE) {
                    self.merror(&msg!("Can't open SQLite database '", rel, "': ", wdb.errmsg()));
                    self.close(&mut wdb, false);
                    self.leave(wdb);
                    return None;
                }
            }
        }
        Some(wdb)
    }

    /// `wdb_create_agent_db2`: copy the profile database. 0 or -1.
    pub fn create_agent_db2(&self, agent_id: &str) -> i32 {
        let source = {
            let _g = self.profile_mutex.lock();
            match std::fs::read(self.path(WDB_PROF_PATH)) {
                Ok(d) => d,
                Err(_) => {
                    self.mdebug1(b"Profile database not found, creating.");
                    if self.create_profile() < 0 {
                        return -1;
                    }
                    match std::fs::read(self.path(WDB_PROF_PATH)) {
                        Ok(d) => d,
                        Err(_) => {
                            self.merror(&msg!("Couldn't open profile '", WDB_PROF_PATH, "'."));
                            return -1;
                        }
                    }
                }
            }
        };
        let rel = trunc(format!("{WDB2_DIR}/{agent_id}.db").into_bytes(), OS_FLSIZE);
        let rel = String::from_utf8_lossy(&rel).into_owned();
        let rel_temp = String::from_utf8_lossy(&trunc(format!("{rel}.new").into_bytes(), OS_FLSIZE)).into_owned();
        let path = self.path(&rel);
        let path_temp = self.path(&rel_temp);
        if let Err(e) = std::fs::write(&path_temp, &source) {
            let (n, t) = errno_text(&e);
            self.merror(&msg!("Couldn't create database '", rel, "': ", t, " (", n, ")"));
            return -1;
        }
        set_mode(&path_temp, 0o640);
        if let Err(e) = std::fs::rename(&path_temp, &path) {
            let (n, t) = errno_text(&e);
            self.merror(&msg!(
                "(1124): Could not rename file '",
                rel_temp,
                "' to '",
                rel,
                "' due to [(",
                n,
                ")-(",
                t,
                ")]."
            ));
            let _ = std::fs::remove_file(&path_temp);
            return -1;
        }
        0
    }

    /// `wdb_begin` / `wdb_commit` / `wdb_rollback`
    fn any_transaction(&self, wdb: &Wdb, sql: &[u8]) -> i32 {
        let (rc, st, _) = wdb.db().prepare_v2(sql);
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.mdebug1(&msg!("sqlite3_prepare_v2(): ", wdb.errmsg()));
            return -1;
        };
        if self.step(&st) != SQLITE_DONE {
            self.mdebug1(&msg!("SQLite: ", wdb.errmsg()));
            return -1;
        }
        0
    }

    pub fn begin(&self, wdb: &Wdb) -> i32 {
        self.any_transaction(wdb, b"BEGIN;")
    }

    pub fn commit(&self, wdb: &Wdb) -> i32 {
        self.any_transaction(wdb, b"COMMIT;")
    }

    pub fn rollback(&self, wdb: &Wdb) -> i32 {
        self.any_transaction(wdb, b"ROLLBACK;")
    }

    /// `wdb_write_state_transaction`
    fn write_state_transaction(&self, wdb: &mut Wdb, state: bool, f: fn(&Self, &Wdb) -> i32) -> i32 {
        if (state && wdb.transaction) || (!state && !wdb.transaction) {
            return 0;
        }
        if f(self, wdb) == -1 {
            return -1;
        }
        wdb.transaction = state;
        if state {
            wdb.transaction_begin_time = self.time();
        }
        0
    }

    /// `wdb_begin2`
    pub fn begin2(&self, wdb: &mut Wdb) -> i32 {
        self.write_state_transaction(wdb, true, Self::begin)
    }

    /// `wdb_commit2`
    pub fn commit2(&self, wdb: &mut Wdb) -> i32 {
        self.write_state_transaction(wdb, false, Self::commit)
    }

    /// `wdb_rollback2`
    pub fn rollback2(&self, wdb: &mut Wdb) -> i32 {
        self.write_state_transaction(wdb, false, Self::rollback)
    }

    /// `wdb_create_global`
    pub fn create_global(&self, path: &Path) -> i32 {
        if self.create_file(path, schema::global()) != OS_SUCCESS {
            OS_INVALID
        } else if self.insert_info(b"openssl_support", b"yes") != OS_SUCCESS {
            OS_INVALID
        } else {
            OS_SUCCESS
        }
    }

    /// `wdb_create_profile`
    pub fn create_profile(&self) -> i32 {
        self.create_file(&self.path(WDB_PROF_PATH), schema::agents())
    }

    /// `wdb_create_file`: run an SQL script into a new database file.
    pub fn create_file(&self, path: &Path, source: &str) -> i32 {
        let (rc, db) = Db::open_v2(&Self::open_path(path), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        let Some(db) = db else {
            return OS_INVALID;
        };
        if rc != SQLITE_OK {
            self.mdebug1(&msg!("Couldn't create SQLite database '", rel_display(&self.base, path), "': ", db.errmsg()));
            return OS_INVALID;
        }
        let mut sql = source.as_bytes();
        while !sql.is_empty() {
            let (rc, st, tail) = db.prepare_v2(sql);
            if rc != SQLITE_OK {
                self.mdebug1(&msg!("Preparing statement: ", db.errmsg()));
                return OS_INVALID;
            }
            // a NULL statement (only comments/spaces) steps as SQLITE_MISUSE
            let result = match &st {
                Some(st) => self.step(st),
                None => SQLITE_MISUSE,
            };
            match result {
                SQLITE_MISUSE | SQLITE_ROW | SQLITE_DONE => {}
                _ => {
                    self.mdebug1(&msg!("Stepping statement: ", db.errmsg()));
                    return OS_INVALID;
                }
            }
            drop(st);
            sql = &sql[tail..];
        }
        drop(db);
        // getuid() != 0 in tests and in the daemon after privsep
        if is_root() {
            // chown(path, root, wazuh): done by the installer in practice
        } else {
            self.mdebug1(b"Ignoring chown when creating file from SQL.");
        }
        set_mode(path, 0o640);
        OS_SUCCESS
    }

    /// `wdb_vacuum`
    pub fn vacuum(&self, wdb: &Wdb) -> i32 {
        let (rc, st) = wdb_prepare(&*self.env, wdb.db(), b"VACUUM;");
        match st.filter(|_| rc == 0) {
            Some(st) => {
                if self.step(&st) == SQLITE_DONE {
                    0
                } else {
                    -1
                }
            }
            None => {
                self.mdebug1(&msg!("SQLite: ", wdb.errmsg()));
                -1
            }
        }
    }

    /// `wdb_get_db_state`: the fragmentation (0-100) or OS_INVALID.
    pub fn get_db_state(&self, wdb: &Wdb) -> i32 {
        if self.execute_non_select_query(wdb, b"CREATE TEMP TABLE IF NOT EXISTS s(rowid INTEGER PRIMARY KEY, pageno INT);") == OS_INVALID {
            self.mdebug1(b"Error creating temporary table.");
            return OS_INVALID;
        }
        if self.execute_non_select_query(wdb, b"DELETE FROM s;") == OS_INVALID {
            self.mdebug1(b"Error truncate temporary table.");
            return OS_INVALID;
        }
        if self.execute_non_select_query(wdb, b"INSERT INTO s(pageno) SELECT pageno FROM dbstat ORDER BY path;") != OS_INVALID {
            let r = self.select_from_temp_table(wdb);
            if r == OS_INVALID {
                self.mdebug1(b"Error in select from temporary table.");
            }
            r
        } else {
            self.mdebug1(b"Error inserting into temporary table.");
            OS_INVALID
        }
    }

    /// `wdb_get_db_free_pages_percentage`
    pub fn get_db_free_pages_percentage(&self, wdb: &Wdb) -> i32 {
        let Some(total_pages) = self.execute_single_int_select_query(wdb, b"SELECT page_count FROM pragma_page_count();") else {
            self.mdebug1(&msg!("Error getting total_pages for '", wdb.id, "' database."));
            return OS_INVALID;
        };
        let Some(free_pages) = self.execute_single_int_select_query(wdb, b"SELECT freelist_count FROM pragma_freelist_count();") else {
            self.mdebug1(&msg!("Error getting free_pages for '", wdb.id, "' database."));
            return OS_INVALID;
        };
        (((free_pages as f32) / (total_pages as f32)) * 100.00f32) as i32
    }

    /// `wdb_execute_single_int_select_query`
    fn execute_single_int_select_query(&self, wdb: &Wdb, query: &[u8]) -> Option<i32> {
        let (rc, st, _) = wdb.db().prepare_v2(query);
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.mdebug1(&msg!("sqlite3_prepare_v2(): ", wdb.errmsg()));
            return None;
        };
        if self.step(&st) == SQLITE_ROW {
            Some(st.column_int(0))
        } else {
            self.mdebug1(&msg!("SQLite: ", wdb.errmsg()));
            None
        }
    }

    /// `wdb_execute_non_select_query`
    fn execute_non_select_query(&self, wdb: &Wdb, query: &[u8]) -> i32 {
        let (rc, st, _) = wdb.db().prepare_v2(query);
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.mdebug1(&msg!("sqlite3_prepare_v2(): ", wdb.errmsg()));
            return OS_INVALID;
        };
        if self.step(&st) != SQLITE_DONE {
            self.mdebug1(&msg!("SQLite: ", wdb.errmsg()));
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdb_select_from_temp_table`
    fn select_from_temp_table(&self, wdb: &Wdb) -> i32 {
        let (rc, st, _) =
            wdb.db().prepare_v2(b"SELECT sum(s1.pageno+1==s2.pageno)*1.0/count(*) FROM s AS s1, s AS s2 WHERE s1.rowid+1=s2.rowid;");
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.mdebug1(&msg!("sqlite3_prepare_v2(): ", wdb.errmsg()));
            return OS_INVALID;
        };
        if self.step(&st) == SQLITE_ROW {
            100 - (st.column_double(0) * 100.0) as i32
        } else {
            self.mdebug1(&msg!("SQLite: ", wdb.errmsg()));
            OS_INVALID
        }
    }

    /// `wdb_insert_info`: a key/value into global.db's info table.
    pub fn insert_info(&self, key: &[u8], value: &[u8]) -> i32 {
        let rel = format!("{WDB2_DIR}/{WDB_GLOB_NAME}.db");
        let (rc, db) = Db::open_v2(&Self::open_path(&self.path(&rel)), SQLITE_OPEN_READWRITE);
        let Some(db) = db else {
            return OS_INVALID;
        };
        if rc != SQLITE_OK {
            self.mdebug1(&msg!("Couldn't open SQLite database '", rel, "': ", db.errmsg()));
            return OS_INVALID;
        }
        let (rc, st) = wdb_prepare(&*self.env, &db, b"INSERT INTO info (key, value) VALUES (?, ?);");
        let Some(st) = st.filter(|_| rc == 0) else {
            self.mdebug1(&msg!("SQLite: ", db.errmsg()));
            // the C leaks the connection here
            std::mem::forget(db);
            return OS_INVALID;
        };
        st.bind_text(1, Some(key));
        st.bind_text(2, Some(value));
        if self.step(&st) == SQLITE_DONE {
            OS_SUCCESS
        } else {
            OS_INVALID
        }
    }

    /// `wdb_close_all`
    pub fn close_all(&self) {
        for k in self.pool.keys() {
            if let Some(mut node) = self.pool_get(&k) {
                if node.db.is_some() {
                    self.close(&mut node, true);
                }
                self.leave(node);
            }
        }
    }

    /// `wdb_commit_old`
    pub fn commit_old(&self) {
        for k in self.pool.keys() {
            let Some(mut node) = self.pool_get(&k) else {
                continue;
            };
            let cur_time = self.time();
            let last = node.node().last();
            if node.transaction
                && (cur_time - last > self.cfg.commit_time_min as i64
                    || cur_time - node.transaction_begin_time > self.cfg.commit_time_max as i64)
            {
                let start = self.env.timeofday();
                self.commit2(&mut node);
                let end = self.env.timeofday();
                let d = state::Tv::diff(end, start);
                let ms = (d.sec as f64 + d.usec as f64 / 1e6) * 1e3;
                self.mdebug2(&msg!("Agent '", node.id, "' database commited. Time: ", format!("{ms:.3}"), " ms."));
            }
            self.leave(node);
        }
    }

    /// `wdb_check_fragmentation`
    pub fn check_fragmentation(&self) {
        for k in self.pool.keys() {
            let Some(mut node) = self.pool_get(&k) else {
                continue;
            };
            if node.db.is_none() {
                self.leave(node);
                continue;
            }
            let current_fragmentation = self.get_db_state(&node);
            let current_free_pages_percentage = self.get_db_free_pages_percentage(&node);
            if current_fragmentation == OS_INVALID || current_free_pages_percentage == OS_INVALID {
                self.merror(&msg!("Couldn't get current state for the database '", node.id, "'"));
            } else {
                match self.get_last_vacuum_data(&node) {
                    None => {
                        self.merror(&msg!("Couldn't get last vacuum info for the database '", node.id, "'"));
                    }
                    Some((last_vacuum_time, last_vacuum_value)) => {
                        let c = &self.cfg;
                        if current_free_pages_percentage >= c.free_pages_percentage
                            && (current_fragmentation > c.max_fragmentation
                                || (current_fragmentation > c.fragmentation_threshold
                                    && (last_vacuum_time == 0
                                        || (last_vacuum_time > 0 && current_fragmentation > last_vacuum_value + c.fragmentation_delta))))
                        {
                            if self.commit2(&mut node) < 0 {
                                self.merror(&msg!(
                                    "Couldn't execute commit statement, before vacuum, for the database '",
                                    node.id,
                                    "'"
                                ));
                                self.leave(node);
                                continue;
                            }
                            self.finalize_all_statements(&mut node);
                            let start = self.env.timeofday();
                            if self.vacuum(&node) < 0 {
                                self.merror(&msg!("Couldn't execute vacuum for the database '", node.id, "'"));
                                self.leave(node);
                                continue;
                            }
                            let end = self.env.timeofday();
                            let d = state::Tv::diff(end, start);
                            let ms = (d.sec as f64 + d.usec as f64 / 1e6) * 1e3;
                            self.mdebug1(&msg!("Vacuum executed on the '", node.id, "' database. Time: ", format!("{ms:.3}"), " ms."));
                            let after = self.get_db_state(&node);
                            if after == OS_INVALID {
                                self.merror(&msg!("Couldn't get fragmentation after vacuum for the database '", node.id, "'"));
                            } else {
                                let t = self.time().to_string();
                                let v = after.to_string();
                                if self.update_last_vacuum_data(&node, t.as_bytes(), v.as_bytes()) != OS_SUCCESS {
                                    self.merror(&msg!("Couldn't update last vacuum info for the database '", node.id, "'"));
                                }
                                if after >= current_fragmentation {
                                    self.mwarn(&msg!(
                                        "After vacuum, the database '",
                                        node.id,
                                        "' has become just as fragmented or worse"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            self.leave(node);
        }
    }

    /// `wdb_get_last_vacuum_data`: (last_vacuum_time, last_vacuum_value).
    fn get_last_vacuum_data(&self, wdb: &Wdb) -> Option<(i32, i32)> {
        let data =
            self.exec(wdb.db(), b"SELECT key, value FROM metadata WHERE key in ('last_vacuum_time', 'last_vacuum_value');")?;
        let items = match &data {
            Json::Array(a) => a,
            _ => return None,
        };
        if items.is_empty() {
            self.mdebug2(b"No vacuum data in metadata table.");
            return Some((0, 0));
        }
        let mut t = -1;
        let mut v = -1;
        for item in items {
            match (item.get("key"), item.get("value")) {
                (Some(k), Some(val)) => {
                    let ks = k.as_bytes().unwrap_or(b"");
                    let vs = val.as_bytes().unwrap_or(b"");
                    if ks == b"last_vacuum_time" {
                        t = atoi(vs);
                    } else if ks == b"last_vacuum_value" {
                        v = atoi(vs);
                    }
                }
                _ => self.merror(b"It was not possible to get key or value from database response."),
            }
        }
        if t != -1 && v != -1 {
            Some((t, v))
        } else {
            self.merror(b"Missing field last_vacuum_time or last_vacuum_value from metadata table.");
            None
        }
    }

    /// `wdb_update_last_vacuum_data`
    pub fn update_last_vacuum_data(&self, wdb: &Wdb, last_vacuum_time: &[u8], last_vacuum_value: &[u8]) -> i32 {
        let (rc, st, _) = wdb.db().prepare_v2(
            b"INSERT INTO metadata (key, value) VALUES ('last_vacuum_time', ?), ('last_vacuum_value', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
        );
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.mdebug1(&msg!("sqlite3_prepare_v2(): ", wdb.errmsg()));
            return -1;
        };
        st.bind_text(1, Some(last_vacuum_time));
        st.bind_text(2, Some(last_vacuum_value));
        let r = self.step(&st);
        if r != SQLITE_DONE && r != SQLITE_CONSTRAINT {
            self.merror(&msg!("(5211): SQL error: '", wdb.errmsg(), "'"));
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdb_close_old`
    pub fn close_old(&self) {
        let keys = self.pool.keys();
        let mut closed = 0i64;
        for k in keys {
            if self.pool.size() as i64 - closed <= self.cfg.open_db_limit as i64 {
                break;
            }
            let Some(mut node) = self.pool_get(&k) else {
                continue;
            };
            if node.db.is_some() && node.node().refcount() == 1 && node.id != WDB_GLOB_NAME {
                self.mdebug2(&msg!("Closing database for agent ", node.id));
                self.close(&mut node, true);
                closed += 1;
            }
            self.leave(node);
        }
        self.pool.clean();
    }

    /// `wdb_exec_stmt_silent`
    pub fn exec_stmt_silent(&self, st: &Stmt) -> i32 {
        match self.step(st) {
            SQLITE_ROW | SQLITE_DONE => OS_SUCCESS,
            _ => {
                self.mdebug1(b"SQL statement execution failed");
                OS_INVALID
            }
        }
    }

    /// `wdb_exec_row_stmt`
    pub fn exec_row_stmt(&self, st: &Stmt, status: &mut i32, column_mode: bool) -> Option<Json> {
        if column_mode == STMT_SINGLE_COLUMN {
            self.exec_row_stmt_single_column(Some(st), status)
        } else {
            self.exec_row_stmt_multi_column(st, status)
        }
    }

    /// `wdb_exec_row_stmt_multi_column`
    pub fn exec_row_stmt_multi_column(&self, st: &Stmt, status: &mut i32) -> Option<Json> {
        let s = self.step(st);
        let mut result = None;
        if s == SQLITE_ROW {
            let count = st.column_count();
            if count > 0 {
                let mut o = Json::object();
                for i in 0..count {
                    match st.column_type(i) {
                        SQLITE_INTEGER | SQLITE_FLOAT => {
                            o.add(st.column_name(i), Json::number(st.column_double(i)));
                        }
                        SQLITE_TEXT | SQLITE_BLOB => {
                            o.add(st.column_name(i), Json::String(st.column_text(i).unwrap_or_default()));
                        }
                        _ => {}
                    }
                }
                result = Some(o);
            }
        } else if s != SQLITE_DONE {
            self.mdebug1(b"SQL statement execution failed");
        }
        *status = s;
        result
    }

    /// `wdb_exec_stmt_sized`
    pub fn exec_stmt_sized(&self, st: Option<&Stmt>, max_size: usize, status: &mut i32, column_mode: bool) -> Option<Json> {
        let Some(st) = st else {
            self.mdebug1(b"Invalid SQL statement.");
            *status = SQLITE_ERROR;
            return None;
        };
        let mut result = Vec::new();
        let mut result_size = 2usize;
        loop {
            let Some(row) = self.exec_row_stmt(st, status, column_mode) else {
                break;
            };
            let row_len = row.print_unformatted().len() + 1;
            if result_size + row_len < max_size {
                result.push(row);
                result_size += row_len;
            } else {
                break;
            }
        }
        if *status != SQLITE_DONE && *status != SQLITE_ROW {
            return None;
        }
        Some(Json::Array(result))
    }

    /// `wdb_exec_stmt_send`: each row sent as "due <json>" to the peer.
    pub fn exec_stmt_send(&self, st: Option<&Stmt>, peer: i32) -> i32 {
        let Some(st) = st else {
            self.mdebug1(b"Invalid SQL statement.");
            return OS_INVALID;
        };
        if self.env.set_send_timeout(peer, WDB_BLOCK_SEND_TIMEOUT_S) < 0 {
            let e = std::io::Error::last_os_error();
            let (n, t) = errno_text(&e);
            self.merror(&msg!("Socket ", peer, " error setting timeout: ", t, " (", n, ")"));
            return OS_SOCKTERR;
        }
        let mut status = OS_SUCCESS;
        let mut sql_status = SQLITE_ERROR;
        let payload_size = OS_MAXSTR - 4;
        while let Some(row) = self.exec_row_stmt(st, &mut sql_status, STMT_MULTI_COLUMN) {
            let printed = row.print_unformatted();
            // cJSON_PrintPreallocated: the text and its NUL must fit
            if printed.len() < payload_size {
                let response = msg!("due ", cstr(&printed));
                if self.env.send_peer(peer, &response) < 0 {
                    let e = std::io::Error::last_os_error();
                    let (n, t) = errno_text(&e);
                    self.merror(&msg!("Socket ", peer, " error: ", t, " (", n, ")"));
                    status = OS_SOCKTERR;
                    break;
                }
            } else {
                self.merror(&msg!("SQL row response for statement ", st.sql(), " is too big to be sent"));
                status = OS_SIZELIM;
                break;
            }
        }
        if status == OS_SUCCESS && sql_status != SQLITE_DONE {
            status = OS_INVALID;
        }
        status
    }

    /// `wdb_exec_stmt`
    pub fn exec_stmt(&self, st: Option<&Stmt>) -> Option<Json> {
        let Some(st) = st else {
            self.mdebug1(b"Invalid SQL statement.");
            return None;
        };
        let mut status = SQLITE_ERROR;
        let mut result = Vec::new();
        while let Some(row) = self.exec_row_stmt(st, &mut status, STMT_MULTI_COLUMN) {
            result.push(row);
        }
        if status != SQLITE_DONE {
            return None;
        }
        Some(Json::Array(result))
    }

    /// `wdb_exec_row_stmt_single_column`
    pub fn exec_row_stmt_single_column(&self, st: Option<&Stmt>, status: &mut i32) -> Option<Json> {
        let Some(st) = st else {
            self.mdebug1(b"Invalid SQL statement.");
            return None;
        };
        let s = self.step(st);
        let mut result = None;
        if s == SQLITE_ROW {
            if st.column_count() > 0 {
                match st.column_type(0) {
                    SQLITE_INTEGER | SQLITE_FLOAT => result = Some(Json::number(st.column_double(0))),
                    SQLITE_TEXT | SQLITE_BLOB => result = Some(Json::String(st.column_text(0).unwrap_or_default())),
                    _ => {}
                }
            }
        } else if s != SQLITE_DONE {
            self.mdebug1(b"SQL statement execution failed");
        }
        *status = s;
        result
    }

    /// `wdb_exec`
    pub fn exec(&self, db: &Db, sql: &[u8]) -> Option<Json> {
        let (rc, st, _) = db.prepare_v2(sql);
        let st = match st {
            Some(st) if rc == SQLITE_OK => st,
            _ => {
                self.mdebug1(&msg!("sqlite3_prepare_v2(): ", db.errmsg()));
                self.mdebug2(&msg!("SQL: ", cstr(sql)));
                return None;
            }
        };
        let r = self.exec_stmt(Some(&st));
        if r.is_none() {
            self.mdebug1(&msg!("wdb_exec_stmt(): ", db.errmsg()));
        }
        r
    }

    /// `wdb_close`
    pub fn close(&self, wdb: &mut Wdb, commit: bool) -> i32 {
        if wdb.transaction && commit {
            self.commit2(wdb);
        }
        self.finalize_all_statements(wdb);
        wdb.db = None;
        OS_SUCCESS
    }

    /// `wdb_finalize_all_statements`
    pub fn finalize_all_statements(&self, wdb: &mut Wdb) {
        for s in wdb.stmt.iter_mut() {
            *s = None;
        }
        wdb.cache_list.clear();
    }

    /// `wdb_stmt_cache`: prepare (or reset) a statement of `SQL_STMT`.
    pub fn stmt_cache(&self, wdb: &mut Wdb, index: usize) -> i32 {
        if index >= WDB_STMT_SIZE {
            self.merror(&msg!("DB(", wdb.id, ") SQL statement index (", index, ") out of bounds"));
            return -1;
        }
        match &wdb.stmt[index] {
            None => {
                let (rc, st, _) = wdb.db().prepare_v2(SQL_STMT[index].as_bytes());
                match st {
                    Some(st) if rc == SQLITE_OK => wdb.stmt[index] = Some(Arc::new(st)),
                    _ => {
                        self.merror(&msg!("DB(", wdb.id, ") sqlite3_prepare_v2() stmt(", index, "): ", wdb.errmsg()));
                        return -1;
                    }
                }
            }
            Some(st) => {
                st.reset();
                st.clear_bindings();
            }
        }
        0
    }

    /// `wdb_sql_exec`: run an SQL script.
    pub fn sql_exec(&self, wdb: &Wdb, sql: &str) -> i32 {
        let (_, err) = wdb.db().exec(sql.as_bytes());
        match err {
            Some(e) => {
                self.mwarn(&msg!("DB(", wdb.id, ") wdb_sql_exec returned error: '", e, "'"));
                -1
            }
            None => 0,
        }
    }

    /// `wdb_remove_database`
    pub fn remove_database(&self, agent_id: &str) -> i32 {
        let rel = format!("{WDB2_DIR}/{agent_id}.db");
        match std::fs::remove_file(self.path(&rel)) {
            Ok(()) => 0,
            Err(e) => {
                let (n, t) = errno_text(&e);
                self.mdebug1(&msg!("(1129): Could not unlink file '", rel, "' due to [(", n, ")-(", t, ")]."));
                -1
            }
        }
    }

    /// `wdb_remove_multiple_agents`
    pub fn remove_multiple_agents(&self, agent_list: &[u8]) -> Option<Json> {
        let agent_list = cstr(agent_list);
        if agent_list.is_empty() || agent_list == b" " {
            return None;
        }
        let mut json_agents = Json::object();
        // errno is not reset: after an overflow (ERANGE) every later token
        // of the list is rejected too. (The C also sees an ERANGE/EINVAL
        // left by earlier requests of the worker thread, whatever failing
        // libc call set it; that carry-over is not modelled.)
        let mut erange = false;
        // `agent` keeps the previous agent's text for invalid tokens
        // (uninitialized before the first valid one in C)
        let mut agent: B = Vec::new();
        for a in w_strtok(agent_list) {
            if a.is_empty() {
                continue;
            }
            let (id, end) = strtol_end(&a);
            if strtol_overflows(&a) {
                erange = true;
            }
            let mut result: &str = "ok";
            if erange || end < a.len() {
                self.mwarn(&msg!("Invalid agent ID when deleting database '", a, "'\n"));
                result = "Invalid agent ID";
            } else {
                agent = trunc(format!("{:03}", id).into_bytes(), OS_SIZE_128);
                let agent_s = String::from_utf8_lossy(&agent).into_owned();
                if let Some(mut wdb) = self.pool_get(&agent_s) {
                    if self.close(&mut wdb, false) < 0 {
                        result = "Can't close";
                    }
                    self.leave(wdb);
                }
                self.mdebug1(&msg!("Removing db for agent '", agent_s, "'"));
                if self.remove_database(&agent_s) < 0 {
                    result = "Can't delete";
                }
            }
            json_agents.add(agent.clone(), Json::string(result));
        }
        let mut response = Json::object();
        response.add("agents", json_agents);
        self.mdebug1(&msg!("Deleting databases. JSON output: ", response.print_unformatted()));
        Some(response)
    }

    /// `wdb_journal_wal`
    pub fn journal_wal(&self, db: &Db) -> i32 {
        if let (_, Some(e)) = db.exec(SQL_STMT[WDB_STMT_PRAGMA_JOURNAL_WAL].as_bytes()) {
            self.merror(&msg!("Cannot set database journaling mode to WAL: '", e, "'"));
            return -1;
        }
        0
    }

    /// `wdb_enable_foreign_keys`
    pub fn enable_foreign_keys(&self, wdb: &Wdb) -> i32 {
        if let (_, Some(e)) = wdb.db().exec(SQL_STMT[WDB_STMT_PRAGMA_ENABLE_FOREIGN_KEYS].as_bytes()) {
            self.merror(&msg!("Cannot enable foreign keys: '", e, "'"));
            return -1;
        }
        0
    }

    /// `wdb_set_synchronous_normal`
    pub fn set_synchronous_normal(&self, wdb: &Wdb) -> i32 {
        if let (_, Some(e)) = wdb.db().exec(SQL_STMT[WDB_STMT_PRAGMA_SYNCHRONOUS_NORMAL].as_bytes()) {
            self.merror(&msg!("Cannot set synchronous mode: '", e, "'"));
            return -1;
        }
        0
    }

    /// `wdb_init_stmt_in_cache`
    pub fn init_stmt_in_cache(&self, wdb: &mut Wdb, index: usize) -> Option<Arc<Stmt>> {
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.mdebug1(b"Cannot begin transaction");
            return None;
        }
        if self.stmt_cache(wdb, index) < 0 {
            self.mdebug1(b"Cannot cache statement");
            return None;
        }
        wdb.stmt[index].clone()
    }

    /// `wdb_get_cache_stmt`: a statement cached by its query text.
    pub fn get_cache_stmt(&self, wdb: &mut Wdb, query: &[u8]) -> Option<Arc<Stmt>> {
        let query = cstr(query);
        if let Some((_, st)) = wdb.cache_list.iter().find(|(q, _)| q == query) {
            let st = st.clone();
            if st.reset() != SQLITE_OK || st.clear_bindings() != SQLITE_OK {
                self.mdebug1(&msg!("DB(", wdb.id, ") sqlite3_reset() stmt(", st.sql(), "): ", wdb.errmsg()));
            }
            return Some(st);
        }
        let (rc, st, _) = wdb.db().prepare_v2(query);
        match st {
            Some(st) if rc == SQLITE_OK => {
                let st = Arc::new(st);
                wdb.cache_list.push((query.to_vec(), st.clone()));
                Some(st)
            }
            _ => {
                self.merror(&msg!("DB(", wdb.id, ") sqlite3_prepare_v2() : ", wdb.errmsg()));
                None
            }
        }
    }

    /// `wdb_get_internal_config`
    pub fn get_internal_config(&self) -> Json {
        let c = &self.cfg;
        let mut w = Json::object();
        w.add("commit_time_max", Json::number(c.commit_time_max as f64));
        w.add("commit_time_min", Json::number(c.commit_time_min as f64));
        w.add("open_db_limit", Json::number(c.open_db_limit as f64));
        w.add("worker_pool_size", Json::number(c.worker_pool_size as f64));
        w.add("fragmentation_threshold", Json::number(c.fragmentation_threshold as f64));
        w.add("fragmentation_delta", Json::number(c.fragmentation_delta as f64));
        w.add("free_pages_percentage", Json::number(c.free_pages_percentage as f64));
        w.add("max_fragmentation", Json::number(c.max_fragmentation as f64));
        w.add("check_fragmentation_interval", Json::number(c.check_fragmentation_interval as f64));
        let mut root = Json::object();
        root.add("wazuh_db", w);
        root
    }

    /// `wdb_get_config`
    pub fn get_config(&self) -> Json {
        let mut backups = Json::array();
        for (i, b) in self.cfg.backup.iter().enumerate() {
            let mut n = Json::object();
            if i == WDB_GLOBAL_BACKUP {
                n.add("database", Json::string("global"));
            }
            n.add("enabled", Json::bool(b.enabled));
            n.add("interval", Json::number(b.interval as f64));
            n.add("max_files", Json::number(b.max_files as f64));
            backups.push(n);
        }
        let mut wdb = Json::object();
        wdb.add("backup", backups);
        let mut root = Json::object();
        root.add("wdb", wdb);
        root
    }

    /// `wdb_check_backup_enabled`
    pub fn check_backup_enabled(&self) -> bool {
        self.cfg.backup.iter().any(|b| b.enabled)
    }
}

/// `w_strtok` (shared/string_op.c): split by spaces; double quotes group
/// words (`""` is an empty token), a backslash takes the next character.
pub fn w_strtok(s: &[u8]) -> Vec<B> {
    let s = cstr(s);
    let mut output = Vec::new();
    let mut accum: Option<B> = None;
    let mut quoting = false;
    let cat = |a: &mut Option<B>, b: &[u8]| a.get_or_insert_with(Vec::new).extend_from_slice(b);
    let mut i = 0;
    while let Some(off) = s[i..].iter().position(|&c| c == b' ' || c == b'"' || c == b'\\') {
        let mut j = i + off;
        match s[j] {
            b' ' => {
                if quoting {
                    cat(&mut accum, &s[i..=j]);
                } else {
                    if j > i {
                        cat(&mut accum, &s[i..j]);
                    }
                    if let Some(a) = accum.take() {
                        output.push(a);
                    }
                }
            }
            b'"' => {
                if j > i || quoting {
                    cat(&mut accum, &s[i..j]);
                }
                quoting = !quoting;
            }
            _ => {
                if j > i {
                    cat(&mut accum, &s[i..j]);
                }
                if j + 1 < s.len() {
                    j += 1;
                    cat(&mut accum, &s[j..=j]);
                }
            }
        }
        i = j + 1;
    }
    if i < s.len() {
        cat(&mut accum, &s[i..]);
    }
    if let Some(a) = accum {
        output.push(a);
    }
    output
}

/// (errno, strerror) of an I/O error.
pub fn errno_text(e: &std::io::Error) -> (i32, String) {
    let n = e.raw_os_error().unwrap_or(0);
    let mut t = e.to_string();
    if let Some(p) = t.find(" (os error") {
        t.truncate(p);
    }
    (n, t)
}

fn rel_display(base: &Path, p: &Path) -> String {
    p.strip_prefix(base).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

#[cfg(unix)]
pub fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
pub fn set_mode(_p: &Path, _mode: u32) {}
