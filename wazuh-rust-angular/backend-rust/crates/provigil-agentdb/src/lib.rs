//! ProVigil agent database: per-agent, global and task SQLite databases behind a one-line text
//! protocol. Specification: `specs/provigil-db.md` (behaviour), `specs/provigil-db-layout.md`
//! (files), `specs/provigil-db-texts.md` (texts).

#[macro_use]
pub mod text;
mod global;
mod layout;
mod rows;
mod task;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{ArcMutexGuard, Mutex, RawMutex};
pub use siem_cjson::Json;
use siem_sqlite::{Db, Stmt, SQLITE_BUSY, SQLITE_DONE, SQLITE_OK, SQLITE_OPEN_CREATE, SQLITE_OPEN_READWRITE, SQLITE_ROW};

use text::{answer, near, split_word};

/// Result codes of a request (also the per-kind codes of some agent commands).
pub const OK: i32 = 0;
pub const INVALID: i32 = -1;

/// Folders and files, relative to the home folder.
pub const DB_DIR: &str = "queue/db";
pub const TASK_DIR: &str = "queue/tasks";
pub const BACKUP_DIR: &str = "backup/db";
pub const GLOBAL_NAME: &str = "global";
pub const TASK_NAME: &str = "tasks";
pub const MITRE_NAME: &str = "mitre";

/// Answer status words, by status code.
pub const STATUS_WORDS: [&str; 5] = ["ok", "due", "err", "ign", "unk"];
pub const ST_OK: i32 = 0;
pub const ST_DUE: i32 = 1;
pub const ST_ERROR: i32 = 2;
pub const ST_UNKNOWN: i32 = 4;

/// The largest answer body (the protocol's command room left out).
pub const MAX_RESPONSE: usize = 65536 - 128;

/// Router topics the database publishes on.
pub const TOPIC_AGENT: i32 = 1;
pub const TOPIC_INVENTORY: i32 = 2;

/// What the database needs from the process around it (and what tests replace).
pub trait Env: Send + Sync {
    /// A log line: level "ERROR", "WARNING", "INFO", "DEBUG" or "DEBUG2".
    fn log(&self, level: &str, msg: &[u8]);
    /// Seconds since 1970.
    fn time(&self) -> i64;
    /// Publishes on a router topic.
    fn router_send(&self, topic: i32, msg: &[u8]);
    /// Sends one message to the connected client; negative on failure.
    fn send_peer(&self, peer: i32, msg: &[u8]) -> i32;
    fn set_send_timeout(&self, _peer: i32, _secs: i32) -> i32 {
        0
    }
    /// (single node, is cluster worker)
    fn is_single_node(&self) -> (i32, i32);
    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    fn close_peer(&self, _peer: i32) {}
    /// Seconds east of UTC of local time at `t`.
    fn utc_offset(&self, _t: i64) -> i64 {
        0
    }
}

/// Settings (internal options `wazuh_db.*` and the backup section).
#[derive(Clone, Debug)]
pub struct Settings {
    pub commit_time_min: i64,
    pub commit_time_max: i64,
    pub open_db_limit: usize,
    pub backup_max_files: usize,
    pub is_worker_node: bool,
    /// Whether deleted agents are published on the agent router topic.
    pub router_agent: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { commit_time_min: 10, commit_time_max: 60, open_db_limit: 64, backup_max_files: 3, is_worker_node: false, router_agent: false }
    }
}

/// One open database file and its state.
pub struct Handle {
    pub id: String,
    pub db: Option<Db>,
    pub transaction: bool,
    pub begin_time: i64,
    pub last_use: i64,
    pub enabled: bool,
    pub peer: i32,
    /// Prepared statements kept open between requests (by SQL text), like a statement cache:
    /// SQLite's last error text then still describes the previous statement.
    pub(crate) stmts: HashMap<String, Arc<Stmt>>,
}

impl Handle {
    pub fn db(&self) -> &Db {
        self.db.as_ref().expect("database open")
    }
    pub fn errmsg(&self) -> Vec<u8> {
        self.db.as_ref().map(|d| d.errmsg()).unwrap_or_default()
    }
    /// Closes the cached statements (before VACUUM or a backup).
    pub fn drop_statements(&mut self) {
        self.stmts.clear();
    }
}

pub type Locked = ArcMutexGuard<RawMutex, Handle>;

pub struct Engine {
    home: PathBuf,
    env: Arc<dyn Env>,
    pub settings: Settings,
    dbs: Mutex<HashMap<String, Arc<Mutex<Handle>>>>,
    /// The cursor of `sync-agent-info-get`.
    sync_last_id: Mutex<i32>,
    /// The cached global group hash (empty = not cached).
    group_hash: Mutex<Vec<u8>>,
}

pub type Answer = (i32, Vec<u8>);

impl Engine {
    pub fn new(home: impl Into<PathBuf>, settings: Settings, env: Arc<dyn Env>) -> Engine {
        Engine { home: home.into(), env, settings, dbs: Mutex::new(HashMap::new()), sync_last_id: Mutex::new(0), group_hash: Mutex::new(Vec::new()) }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    pub fn time(&self) -> i64 {
        self.env.time()
    }

    fn log(&self, level: &str, m: Vec<u8>) {
        self.env.log(level, &m);
    }
    pub fn error(&self, m: Vec<u8>) {
        self.log("ERROR", m)
    }
    pub fn warn(&self, m: Vec<u8>) {
        self.log("WARNING", m)
    }
    pub fn info(&self, m: Vec<u8>) {
        self.log("INFO", m)
    }
    pub fn debug(&self, m: Vec<u8>) {
        self.log("DEBUG", m)
    }
    pub fn debug2(&self, m: Vec<u8>) {
        self.log("DEBUG2", m)
    }

    /// Handles one request line; returns the result code and the answer.
    pub fn handle(&self, request: &[u8], peer: i32) -> Answer {
        let req = text::until_nul(request);
        let start = req.iter().position(|&c| c != b' ' && c != b'\n').unwrap_or(req.len());
        let req = &req[start..];
        let (actor, rest) = split_word(req);
        let Some(rest) = rest else {
            self.debug(b"Invalid DB query syntax.".to_vec());
            self.debug2(cat!("DB query: ", req));
            return (INVALID, near("err Invalid DB query syntax", req));
        };
        match actor {
            b"global" => self.global_actor(rest, peer),
            b"task" => self.task_actor(rest, peer),
            _ => {
                self.debug(cat!("DB(000) Invalid DB query actor: ", actor));
                (INVALID, answer(cat!("err Invalid DB query actor: '", text::first32(actor), "'")))
            }
        }
    }

    // ------------------------------------------------------------------ database files

    pub(crate) fn cached(&self, name: &str) -> Locked {
        let h = self
            .dbs
            .lock()
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(Handle { id: name.to_string(), db: None, transaction: false, begin_time: 0, last_use: 0, enabled: true, peer: -1, stmts: HashMap::new() })))
            .clone();
        let mut g = h.lock_arc();
        g.last_use = self.time();
        g
    }

    /// Creates a database file from a layout: runs each statement, makes it private to the owner.
    pub(crate) fn create_file(&self, rel: &str, layout: &[&str]) -> bool {
        let path = self.path(rel);
        let (rc, db) = Db::open_v2(path.to_string_lossy().as_bytes(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        let Some(db) = db else { return false };
        if rc != SQLITE_OK {
            self.debug(cat!("Couldn't create SQLite database '", rel, "': ", db.errmsg()));
            return false;
        }
        for sql in layout {
            let (rc, st, _) = db.prepare_v2(sql.as_bytes());
            if rc != SQLITE_OK {
                self.debug(cat!("Preparing statement: ", db.errmsg()));
                return false;
            }
            if let Some(st) = st {
                let r = self.step(&st);
                if r != SQLITE_ROW && r != SQLITE_DONE {
                    self.debug(cat!("Stepping statement: ", db.errmsg()));
                    return false;
                }
            }
        }
        drop(db);
        if !running_as_root() {
            self.debug(b"Ignoring chown when creating file from SQL.".to_vec());
        }
        owner_only(&path);
        true
    }

    /// Opens `rel` into the handle; false (handle kept for its error text) when it fails.
    pub(crate) fn open_into(&self, h: &mut Handle, rel: &str) -> bool {
        let (rc, db) = Db::open_v2(self.path(rel).to_string_lossy().as_bytes(), SQLITE_OPEN_READWRITE);
        h.db = db;
        rc == SQLITE_OK
    }

    /// The layout version stored in a file (None when it has no metadata or no version).
    fn stored_version(&self, h: &Handle, table: &str) -> Option<Vec<u8>> {
        let sql = format!("SELECT value FROM {table} WHERE key = 'db_version';");
        let (rc, st, _) = h.db().prepare_v2(sql.as_bytes());
        let st = st.filter(|_| rc == SQLITE_OK)?;
        if self.step(&st) == SQLITE_ROW {
            st.column_text(0)
        } else {
            None
        }
    }

    /// Refuses a file written with another layout version (decision D-1).
    fn check_version(&self, h: &mut Handle, rel: &str, table: &str, want: &str) {
        match self.stored_version(h, table) {
            Some(v) if v == want.as_bytes() => {}
            v => {
                let found = v.unwrap_or_else(|| b"none".to_vec());
                self.error(cat!(
                    "DB(", h.id.clone(), ") '", rel, "' has layout version ", found, ", this version reads only version ", want,
                    ". The file is not used."
                ));
                h.enabled = false;
            }
        }
    }

    fn pragmas(&self, h: &Handle) {
        if let (_, Some(e)) = h.db().exec(b"PRAGMA foreign_keys = ON;") {
            self.error(cat!("Cannot enable foreign keys: '", e, "'"));
        }
        if let (_, Some(e)) = h.db().exec(b"PRAGMA synchronous = NORMAL;") {
            self.error(cat!("Cannot set synchronous mode: '", e, "'"));
        }
    }

    /// The global database, created when missing.
    pub fn open_global(&self) -> Option<Locked> {
        let mut h = self.cached(GLOBAL_NAME);
        if h.db.is_none() {
            let rel = format!("{DB_DIR}/{GLOBAL_NAME}.db");
            if !self.open_into(&mut h, &rel) {
                self.debug(b"Global database not found, creating.".to_vec());
                h.db = None;
                if !self.create_file(&rel, layout::GLOBAL) || !self.insert_info(b"openssl_support", b"yes") {
                    self.error(cat!("Couldn't create SQLite database '", rel.clone(), "'"));
                    return None;
                }
                if !self.open_into(&mut h, &rel) {
                    self.error(cat!("Can't open SQLite database '", rel.clone(), "': ", h.errmsg()));
                    h.db = None;
                    return None;
                }
            } else {
                self.check_version(&mut h, &rel, "metadata", layout::GLOBAL_VERSION);
            }
            self.pragmas(&h);
        }
        Some(h)
    }

    /// A key/value into the global database's `info` table (on creation).
    fn insert_info(&self, key: &[u8], value: &[u8]) -> bool {
        let rel = format!("{DB_DIR}/{GLOBAL_NAME}.db");
        let (rc, db) = Db::open_v2(self.path(&rel).to_string_lossy().as_bytes(), SQLITE_OPEN_READWRITE);
        let Some(db) = db else { return false };
        if rc != SQLITE_OK {
            self.debug(cat!("Couldn't open SQLite database '", rel, "': ", db.errmsg()));
            return false;
        }
        let (rc, st, _) = db.prepare_v2(b"INSERT INTO info (key, value) VALUES (?, ?);");
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.debug(cat!("SQLite: ", db.errmsg()));
            return false;
        };
        st.bind_text(1, Some(key));
        st.bind_text(2, Some(value));
        if self.step(&st) == SQLITE_DONE {
            true
        } else {
            self.debug(cat!("SQLite: ", db.errmsg()));
            false
        }
    }

    // ------------------------------------------------------------------ statements

    /// One step, retried while the file is busy.
    pub fn step(&self, st: &Stmt) -> i32 {
        for _ in 0..=1000 {
            let r = st.step();
            if r != SQLITE_BUSY {
                return r;
            }
        }
        self.debug(b"Maximum attempts exceeded for sqlite3_step()".to_vec());
        -1
    }

    fn run_plain(&self, h: &Handle, sql: &[u8]) -> bool {
        let (rc, st, _) = h.db().prepare_v2(sql);
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.debug(cat!("sqlite3_prepare_v2(): ", h.errmsg()));
            return false;
        };
        if self.step(&st) != SQLITE_DONE {
            self.debug(cat!("SQLite: ", h.errmsg()));
            return false;
        }
        true
    }

    /// Starts a transaction unless one is open.
    pub fn begin(&self, h: &mut Handle) -> bool {
        if h.transaction {
            return true;
        }
        if !self.run_plain(h, b"BEGIN;") {
            return false;
        }
        h.transaction = true;
        h.begin_time = self.time();
        true
    }

    /// Commits the open transaction, if any.
    pub fn commit(&self, h: &mut Handle) -> bool {
        if !h.transaction {
            return true;
        }
        if !self.run_plain(h, b"COMMIT;") {
            return false;
        }
        h.transaction = false;
        true
    }

    /// Prepares a statement inside a transaction (begun when none is open); a statement used
    /// before is reset and reused.
    pub fn prepare(&self, h: &mut Handle, sql: &str) -> Option<Arc<Stmt>> {
        if !h.transaction && !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
            return None;
        }
        if let Some(st) = h.stmts.get(sql) {
            let st = st.clone();
            // a failed previous run makes reset report that error; it is not logged
            st.reset();
            st.clear_bindings();
            return Some(st);
        }
        let (rc, st, _) = h.db().prepare_v2(sql.as_bytes());
        match st.filter(|_| rc == SQLITE_OK) {
            Some(st) => {
                let st = Arc::new(st);
                h.stmts.insert(sql.to_string(), st.clone());
                Some(st)
            }
            None => {
                self.error(cat!("DB(", h.id.clone(), ") sqlite3_prepare_v2() stmt(", sql, "): ", h.errmsg()));
                self.debug(b"Cannot cache statement".to_vec());
                None
            }
        }
    }

    /// Runs a statement that returns nothing useful.
    pub fn run(&self, st: &Stmt) -> bool {
        match self.step(st) {
            SQLITE_ROW | SQLITE_DONE => true,
            _ => {
                self.debug(b"SQL statement execution failed".to_vec());
                false
            }
        }
    }

    /// Commits transactions that have been idle or open too long (called every second).
    pub fn commit_old(&self) {
        let handles: Vec<_> = self.dbs.lock().values().cloned().collect();
        for h in handles {
            let mut h = h.lock();
            let now = self.time();
            if h.transaction && (now - h.last_use > self.settings.commit_time_min || now - h.begin_time > self.settings.commit_time_max) {
                self.commit(&mut h);
                self.debug2(cat!("Agent '", h.id.clone(), "' database commited. Time: 0.000 ms."));
            }
        }
    }

    /// After an invalid result: a database file that vanished is closed (recreated next time).
    fn check_file(&self, h: &mut Handle) {
        let rel = format!("{DB_DIR}/{}.db", h.id);
        if std::fs::File::open(self.path(&rel)).is_err() {
            self.warn(cat!("DB(", rel, ") not found. This behavior is unexpected, the database will be recreated."));
            self.close(h, false);
        }
    }

    // ------------------------------------------------------------------ maintenance (§ 1.6–1.8)

    fn int_query(&self, h: &Handle, sql: &[u8]) -> Option<i32> {
        let (rc, st, _) = h.db().prepare_v2(sql);
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.debug(cat!("sqlite3_prepare_v2(): ", h.errmsg()));
            return None;
        };
        if self.step(&st) == SQLITE_ROW {
            Some(st.column_int(0))
        } else {
            self.debug(cat!("SQLite: ", h.errmsg()));
            None
        }
    }

    /// Fragmentation 0–100: the share of pages not followed by their next page.
    pub fn fragmentation(&self, h: &Handle) -> i32 {
        if !self.run_plain(h, b"CREATE TEMP TABLE IF NOT EXISTS s(rowid INTEGER PRIMARY KEY, pageno INT);") {
            self.debug(b"Error creating temporary table.".to_vec());
            return INVALID;
        }
        if !self.run_plain(h, b"DELETE FROM s;") {
            self.debug(b"Error truncate temporary table.".to_vec());
            return INVALID;
        }
        if !self.run_plain(h, b"INSERT INTO s(pageno) SELECT pageno FROM dbstat ORDER BY path;") {
            self.debug(b"Error inserting into temporary table.".to_vec());
            return INVALID;
        }
        let (rc, st, _) = h.db().prepare_v2(b"SELECT sum(s1.pageno+1==s2.pageno)*1.0/count(*) FROM s AS s1, s AS s2 WHERE s1.rowid+1=s2.rowid;");
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.debug(cat!("sqlite3_prepare_v2(): ", h.errmsg()));
            self.debug(b"Error in select from temporary table.".to_vec());
            return INVALID;
        };
        if self.step(&st) == SQLITE_ROW {
            100 - (st.column_double(0) * 100.0) as i32
        } else {
            self.debug(cat!("SQLite: ", h.errmsg()));
            self.debug(b"Error in select from temporary table.".to_vec());
            INVALID
        }
    }

    pub fn free_pages_percentage(&self, h: &Handle) -> i32 {
        let Some(total) = self.int_query(h, b"SELECT page_count FROM pragma_page_count();") else {
            self.debug(cat!("Error getting total_pages for '", h.id.clone(), "' database."));
            return INVALID;
        };
        let Some(free) = self.int_query(h, b"SELECT freelist_count FROM pragma_freelist_count();") else {
            self.debug(cat!("Error getting free_pages for '", h.id.clone(), "' database."));
            return INVALID;
        };
        (((free as f32) / (total as f32)) * 100.00f32) as i32
    }

    fn store_vacuum(&self, h: &Handle, time: &[u8], value: &[u8]) -> bool {
        let (rc, st, _) = h.db().prepare_v2(
            b"INSERT INTO metadata (key, value) VALUES ('last_vacuum_time', ?), ('last_vacuum_value', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
        );
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.debug(cat!("sqlite3_prepare_v2(): ", h.errmsg()));
            return false;
        };
        st.bind_text(1, Some(time));
        st.bind_text(2, Some(value));
        let r = self.step(&st);
        if r != SQLITE_DONE && r != siem_sqlite::SQLITE_CONSTRAINT {
            self.error(cat!("(5211): SQL error: '", h.errmsg(), "'"));
            return false;
        }
        true
    }

    pub(crate) fn vacuum_command(&self, h: &mut Handle, who: &str) -> Answer {
        if !self.commit(h) {
            self.debug(cat!(who, " Cannot end transaction."));
            return (INVALID, b"err Cannot end transaction".to_vec());
        }
        h.drop_statements();
        let vacuumed = match self.prepared_plain(h, b"VACUUM;") {
            Some(st) => self.step(&st) == SQLITE_DONE,
            None => false,
        };
        if !vacuumed {
            self.debug(cat!(who, " Cannot vacuum database."));
            return (INVALID, b"err Cannot vacuum database".to_vec());
        }
        let after = self.fragmentation(h);
        if after == INVALID {
            self.debug(cat!(who, " Couldn't get fragmentation after vacuum for the database."));
            return (INVALID, b"err Vacuum performed, but couldn't get fragmentation information after vacuum".to_vec());
        }
        if !self.store_vacuum(h, self.time().to_string().as_bytes(), after.to_string().as_bytes()) {
            self.debug(cat!(who, " Couldn't update last vacuum info for the database."));
            return (INVALID, b"err Vacuum performed, but last vacuum information couldn't be updated in the metadata table".to_vec());
        }
        let mut j = Json::object();
        j.add("fragmentation_after_vacuum", Json::number(after as f64));
        (OK, answer(cat!("ok ", j.print_unformatted())))
    }

    fn prepared_plain(&self, h: &Handle, sql: &[u8]) -> Option<Stmt> {
        for _ in 0..=1000 {
            let (rc, st, _) = h.db().prepare_v2(sql);
            if rc == SQLITE_BUSY {
                continue;
            }
            if rc != SQLITE_OK {
                self.debug(cat!("SQLite: ", h.errmsg()));
                return None;
            }
            return st;
        }
        None
    }

    pub(crate) fn fragmentation_command(&self, h: &Handle, who: &str) -> Answer {
        let state = self.fragmentation(h);
        let free = self.free_pages_percentage(h);
        if state < 0 || free < 0 {
            self.debug(cat!(who, " Cannot get database fragmentation."));
            return (INVALID, b"err Cannot get database fragmentation".to_vec());
        }
        let mut j = Json::object();
        j.add("fragmentation", Json::number(state as f64));
        j.add("free_pages_percentage", Json::number(free as f64));
        (OK, answer(cat!("ok ", j.print_unformatted())))
    }

    pub(crate) fn sleep_command(&self, args: Option<&[u8]>, cmd: &[u8], who: &str) -> Answer {
        match args.map(text::read_ulong) {
            Some(ms) if ms != u64::MAX => {
                self.env.sleep_ms(ms);
                (OK, b"ok ".to_vec())
            }
            _ => {
                self.debug(cat!(who, " Invalid DB query syntax."));
                self.debug2(cat!(who, " query error near: ", cmd));
                (INVALID, near("err Invalid DB query syntax", cmd))
            }
        }
    }

    pub fn close(&self, h: &mut Handle, commit: bool) {
        if h.transaction && commit {
            self.commit(h);
        }
        h.transaction = false;
        h.stmts.clear();
        h.db = None;
    }
}

#[cfg(unix)]
fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    // the process owns its home folder; root runs only before dropping privileges
    std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
}
#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
}

#[cfg(unix)]
fn owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
}
#[cfg(not(unix))]
fn owner_only(_: &Path) {}
