//! The database module (spec § 1): keeps global.db in step with the manager. Its own row
//! (agent 0), the agents of the key table, the groups of `etc/shared`, legacy group files and
//! databases of agents that no longer exist. Runs once at start, then every `interval` seconds.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use provigil_daemon::{Log, Options};
use provigil_ipc::agentdb::{parse_answer, AgentDb, DbError, Status};
use serde_json::{json, Map, Value};
use siem_crypto::keystore::KeyStore;

pub const TAG: &str = "provigil-modulesd:database";
const KEYS_FILE: &str = "etc/client.keys";
const SHARED_DIR: &str = "etc/shared";
const LEGACY_GROUPS_DIR: &str = "queue/agent-groups";
const DB_DIR: &str = "queue/db";
const TIMESTAMP_FILE: &str = "queue/agents-timestamp";
/// At most this many groups per agent (the newest kept).
const MAX_GROUPS: usize = 128;
/// The version written in the manager's row.
const MANAGER_VERSION: &str = "Wazuh v4.14.7";

/// The module's settings (internal options `provigil_database.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub sync_agents: bool,
    pub real_time: bool,
    pub interval: i64,
    pub max_queued_events: i64,
}

impl Settings {
    /// The settings, None when `sync_agents` is off (the module does not run); an error text
    /// for a value out of range.
    pub fn read(opts: &Options) -> Result<Option<Settings>, String> {
        let g = |k: &str, min: i64, max: i64| opts.int("provigil_database", k, 0, min, max);
        let s = Settings {
            sync_agents: g("sync_agents", 0, 1)? != 0,
            real_time: g("real_time", 0, 1)? != 0,
            interval: g("interval", 0, 86400)?,
            max_queued_events: g("max_queued_events", 0, i32::MAX as i64)?,
        };
        Ok(s.sync_agents.then_some(s))
    }
}

pub struct Database {
    pub settings: Settings,
    log: Arc<Log>,
    db: Arc<dyn AgentDb>,
    home: PathBuf,
    /// A worker node (also when the cluster setting cannot be read).
    worker: bool,
}

impl Database {
    pub fn new(settings: Settings, log: Arc<Log>, db: Arc<dyn AgentDb>, home: &Path) -> Database {
        Database { settings, log, db, home: home.to_path_buf(), worker: false }
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    fn mlog(&self, level: &str, m: impl AsRef<[u8]>) {
        self.log.tagged(TAG, level, m);
    }

    /// Start-up work, then the interval loop (never returns).
    pub fn run(mut self) {
        self.startup();
        let mut keys_stamp = None;
        let interval = self.settings.interval.max(0);
        std::thread::sleep(Duration::from_secs(interval as u64));
        loop {
            let start = now();
            let t = Instant::now();
            self.cycle(&mut keys_stamp);
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            self.mlog("DEBUG", format!("Cycle completed: {ms:.3} ms ({ms:.3} clock ms)."));
            let left = start + interval - now();
            if left >= 0 {
                std::thread::sleep(Duration::from_secs(left as u64));
            } else {
                self.mlog("WARNING", format!("Time interval exceeded by {} seconds.", -left));
            }
        }
    }

    /// What runs once at start.
    pub fn startup(&mut self) {
        self.mlog("INFO", "Module started.");
        // unreadable settings, or a cluster without a node type, count as a worker
        self.worker = match provigil_daemon::read_conf(&self.home) {
            Ok(x) => provigil_daemon::is_worker(&x) != Some(false),
            Err(_) => true,
        };
        self.sync_manager();
        // workers and masters both load the keys at start
        self.sync_agents();
        update_groups(&*self.db, &self.log, &self.p(SHARED_DIR));
        self.sync_legacy_group_files();
        self.remove_dangling_databases();
    }

    /// One pass of the loop: key-table changes (workers re-sync), then the groups.
    pub fn cycle(&self, keys_stamp: &mut Option<(i64, u64)>) {
        if self.settings.sync_agents {
            self.check_agents(keys_stamp);
            update_groups(&*self.db, &self.log, &self.p(SHARED_DIR));
        }
    }

    /// The manager's own row: host name, node name, OS fields, version and statuses.
    fn sync_manager(&self) {
        let host = std::env::var("COMPUTERNAME").ok().or_else(hostname_unix);
        match &host {
            Some(h) => {
                update_agent_name(&*self.db, &self.log, 0, h);
            }
            None => self.mlog("ERROR", format!("Couldn't get manager's hostname: {}.", os_text(&std::io::Error::last_os_error()))),
        }
        let node = match provigil_daemon::read_conf(&self.home) {
            Ok(x) => provigil_daemon::node_name(&x),
            Err(e) => {
                self.log.debug(format!("(1226): Error reading XML file 'etc/ossec.conf': {e}."));
                None
            }
        }
        .unwrap_or_else(|| "undefined".into());
        let uname = siem_fileop::version_op::getuname();
        let mut data = manager_os(uname.split(" - ").next().unwrap_or(""));
        data.insert("id".into(), json!(0));
        data.insert("version".into(), json!(MANAGER_VERSION));
        data.insert("node_name".into(), json!(node));
        data.insert("connection_status".into(), json!("active"));
        data.insert("sync_status".into(), json!("synced"));
        data.insert("group_config_status".into(), json!("synced"));
        if let Some(h) = &host {
            data.insert("manager_host".into(), json!(h));
        }
        let _ = query(&*self.db, &self.log, &format!("global update-agent-data {}", Value::Object(data)));
    }

    /// Re-syncs (on workers) when the key table changed: the key service's version, or the
    /// file's modification time and identity.
    fn check_agents(&self, stamp: &mut Option<(i64, u64)>) {
        if siem_crypto::keystore::platform_source().is_some() {
            match siem_crypto::keystore::platform_fetch(siem_crypto::keystore::VERSION_REQ) {
                Err(e) => self.mlog("ERROR", format!("Couldn't get the agent keys' version: {e}.")),
                Ok((v, _)) => self.changed(stamp, (v as i64, u64::MAX)),
            }
            return;
        }
        match std::fs::metadata(self.p(KEYS_FILE)) {
            Err(e) => self.mlog("ERROR", format!("Couldn't get client.keys stat: {}.", os_text(&e))),
            Ok(m) => self.changed(stamp, file_stamp(&m)),
        }
    }

    fn changed(&self, stamp: &mut Option<(i64, u64)>, now: (i64, u64)) {
        if Some(now) != *stamp {
            if self.worker {
                self.sync_agents();
            }
            *stamp = Some(now);
        }
    }

    /// Loads the key table and brings global.db in line with it.
    pub fn sync_agents(&self) {
        let t = Instant::now();
        self.mlog("DEBUG", "Synchronizing agents.");
        let keys = match KeyStore::read(&self.p(KEYS_FILE).to_string_lossy(), true, false) {
            Ok(k) => k,
            Err(e) => {
                self.log.critical(e.to_string());
                std::process::exit(1);
            }
        };
        self.sync_keys(&keys);
        self.mlog("DEBUG", "Agents synchronization completed.");
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        self.mlog("DEBUG", format!("wm_sync_agents(): {ms:.3} ms ({ms:.3} clock ms)."));
    }

    /// Inserts the keys global.db lacks; removes the agents without a key, with their database,
    /// diff folder, counter and timestamp line.
    pub fn sync_keys(&self, keys: &KeyStore) {
        let Some(agents) = all_agents(&*self.db, &self.log) else {
            self.mlog("ERROR", "Couldn't synchronize the keystore with the DB.");
            return;
        };
        for e in &keys.entries {
            let id = siem_regex::os_ip::atoi(&e.id);
            if id != 0 && !agents.contains(&e.id) {
                self.mlog("DEBUG2", format!("Synchronizing agent {} '{}'.", e.id, e.name));
                let ip = siem_regex::os_ip::cidr_to_str(&e.ip).unwrap_or_else(|| e.ip.ip.clone());
                let added = date_added(&self.log, &self.p(TIMESTAMP_FILE), id);
                if insert_agent(&*self.db, &self.log, id, &e.name, &ip, &e.raw_key, added) != 0 {
                    self.mlog("DEBUG", format!("Couldn't insert agent '{}' in the database.", e.id));
                }
            }
        }
        // an empty key list never empties global.db: it means the keys could not be read (the
        // service started without siem-api's key service and without client.keys), spec M-4
        let registered = agents.iter().filter(|a| siem_regex::os_ip::atoi(a) != 0).count();
        if keys.entries.iter().all(|e| siem_regex::os_ip::atoi(&e.id) == 0) && registered > 0 {
            self.mlog("WARNING", format!("The key list is empty: none of the {registered} registered agents is removed. Check that siem-api's key service is running."));
            return;
        }
        for id_text in &agents {
            let id = siem_regex::os_ip::atoi(id_text);
            if id == 0 || keys.entries.iter().any(|e| &e.id == id_text) {
                continue;
            }
            let name = agent_name(&*self.db, &self.log, id);
            if remove_agent(&*self.db, &self.log, id) < 0 {
                self.mlog("DEBUG", format!("Couldn't remove agent '{id_text}' from the database."));
                continue;
            }
            if query(&*self.db, &self.log, &format!("wazuhdb remove {id}")).is_err() {
                self.mlog("DEBUG", format!("Could not remove the provigil-db DB of the agent {id}."));
            }
            if let Some(n) = name.filter(|n| !n.is_empty()) {
                let _ = std::fs::remove_dir_all(self.p("queue/diff").join(n));
            }
            let _ = std::fs::remove_file(self.p("queue/rids").join(id_text));
            remove_timestamp_line(&self.log, &self.p(TIMESTAMP_FILE), id_text);
        }
    }

    /// `queue/db/<id>.db` of an agent global.db does not know is removed.
    fn remove_dangling_databases(&self) {
        let dir = self.p(DB_DIR);
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                self.mlog("ERROR", format!("Couldn't open directory '{DB_DIR}': {}.", os_text(&e)));
                return;
            }
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(|c: char| c.is_ascii_digit()) {
                continue;
            }
            if !name.contains('.') {
                self.mlog("WARNING", format!("Strange file found: '{DB_DIR}/{name}'"));
                continue;
            }
            let digits = name.bytes().take_while(u8::is_ascii_digit).count();
            let id: i32 = name[..digits].parse().unwrap_or(0);
            if id > 0 && name[digits..].starts_with(".db") && agent_name(&*self.db, &self.log, id).is_some_and(|n| n.is_empty()) {
                let rel = format!("{DB_DIR}/{name}");
                self.mlog("WARNING", format!("Removing dangling WDB DB file: '{rel}'"));
                if let Err(e) = std::fs::remove_file(dir.join(&name)) {
                    self.mlog("DEBUG", format!("(1129): Could not unlink file '{rel}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), os_text(&e)));
                }
            }
        }
    }

    /// Group files of the old layout (`queue/agent-groups/<id>`): imported, then deleted; a
    /// worker only deletes them. The folder goes when it is left empty.
    fn sync_legacy_group_files(&self) {
        let dir = self.p(LEGACY_GROUPS_DIR);
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                self.mlog("DEBUG", format!("Couldn't open directory '{LEGACY_GROUPS_DIR}': {}.", os_text(&e)));
                return;
            }
        };
        self.mlog("DEBUG", format!("Scanning directory '{LEGACY_GROUPS_DIR}'."));
        let mut empty = true;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let rel = format!("{LEGACY_GROUPS_DIR}/{name}");
            if self.worker {
                self.mlog("DEBUG", format!("Group file '{rel}' won't be synced in a worker node, removing."));
                let _ = std::fs::remove_file(e.path());
            } else if self.import_group_file(&name, &e.path(), &rel) == 0 {
                self.mlog("DEBUG", format!("Group file '{rel}' successfully synced, removing."));
                let _ = std::fs::remove_file(e.path());
            } else {
                self.log.error(format!("Failed during the groups file '{rel}' syncronization."));
                empty = false;
            }
        }
        if empty {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                self.mlog("DEBUG", format!("Unable to remove directory '{LEGACY_GROUPS_DIR}': '{}' ({})", os_text(&e), e.raw_os_error().unwrap_or(0)));
            }
        }
    }

    fn import_group_file(&self, file: &str, path: &Path, rel: &str) -> i32 {
        let id = siem_regex::os_ip::atoi(file);
        if id <= 0 {
            self.mlog("DEBUG", format!("Couldn't extract agent ID from file '{rel}'."));
            return -1;
        }
        let Ok(data) = std::fs::read(path) else {
            self.mlog("DEBUG", format!("Groups file '{rel}' could not be opened for syncronization."));
            return -1;
        };
        let text = String::from_utf8_lossy(&data);
        let Some(line) = text.split('\n').next().filter(|_| !text.is_empty()) else {
            self.mlog("DEBUG", format!("Empty group file '{rel}'."));
            return 0;
        };
        let groups: Vec<String> = line.split(',').map(String::from).collect();
        let keep = &groups[groups.len().saturating_sub(MAX_GROUPS)..];
        let single = provigil_daemon::read_conf(&self.home).map(|x| provigil_daemon::single_node(&x).0).unwrap_or(true);
        set_agent_groups(&*self.db, &self.log, id, keep, "override", if single { "synced" } else { "syncreq" })
    }
}

// ------------------------------------------------------------------ global.db requests

/// A request; on failure the error code (-2 not reachable, -1 no answer), logged as before.
fn query(db: &dyn AgentDb, log: &Log, q: &str) -> Result<String, i32> {
    db.query(q).map_err(|e| {
        if let DbError::Connect(_) = e {
            log.error("Unable to connect to socket 'queue/db/wdb'.");
        }
        e.code()
    })
}

/// The JSON of an `ok` answer.
fn query_json(db: &dyn AgentDb, log: &Log, q: &str) -> Option<Value> {
    let a = match query(db, log, q) {
        Ok(a) => a,
        Err(-2) => {
            log.error("Unable to connect to socket 'queue/db/wdb'");
            return None;
        }
        Err(_) => {
            log.error("No response from provigil-db.");
            return None;
        }
    };
    match parse_answer(&a) {
        (Status::Ok, rest) => serde_json::from_str(rest).ok(),
        (Status::Error, rest) => {
            log.error(format!("Bad response from provigil-db: {rest}"));
            None
        }
        _ => None,
    }
}

/// 0 for an `ok` answer, -1 otherwise (with the debug lines of each case).
fn query_ok(db: &dyn AgentDb, log: &Log, q: &str) -> i32 {
    match query(db, log, q) {
        Ok(a) if parse_answer(&a).0 == Status::Ok => 0,
        Ok(_) => {
            log.debug("Global DB Error reported in the result of the query");
            -1
        }
        Err(-1) => {
            log.debug("Global DB Error in the response from socket");
            log.debug2(format!("Global DB SQL query: {q}"));
            -1
        }
        Err(_) => {
            log.debug("Global DB Cannot execute SQL query; err database queue/db/global.db");
            log.debug2(format!("Global DB SQL query: {q}"));
            -1
        }
    }
}

fn insert_agent(db: &dyn AgentDb, log: &Log, id: i32, name: &str, register_ip: &str, key: &str, date_add: i64) -> i32 {
    let data = json!({ "id": id, "name": name, "ip": Value::Null, "register_ip": register_ip, "internal_key": key, "group": Value::Null, "date_add": date_add });
    query_ok(db, log, &format!("global insert-agent {data}"))
}

fn update_agent_name(db: &dyn AgentDb, log: &Log, id: i32, name: &str) -> i32 {
    query_ok(db, log, &format!("global update-agent-name {}", json!({ "id": id, "name": name })))
}

fn remove_agent(db: &dyn AgentDb, log: &Log, id: i32) -> i32 {
    query_ok(db, log, &format!("global delete-agent {id}"))
}

/// The agent's name; "" when global.db does not have it; None on error.
fn agent_name(db: &dyn AgentDb, log: &Log, id: i32) -> Option<String> {
    let Some(v) = query_json(db, log, &format!("global select-agent-name {id}")) else {
        log.error(format!("Error querying provigil-db to get the agent's {id} name."));
        return None;
    };
    Some(v.get(0).and_then(|a| a.get("name")).and_then(Value::as_str).unwrap_or("").to_string())
}

/// Every agent id (`%03d`) except the manager, read a page at a time.
fn all_agents(db: &dyn AgentDb, log: &Log) -> Option<BTreeSet<String>> {
    let (mut last, mut ids) = (0i64, BTreeSet::new());
    loop {
        let st = match query(db, log, &format!("global get-all-agents last_id {last}")) {
            Ok(a) => {
                let (st, rest) = parse_answer(&a);
                if matches!(st, Status::Ok | Status::Due) {
                    match serde_json::from_str::<Value>(rest) {
                        Ok(Value::Array(list)) => {
                            let mut newest = 0;
                            for agent in list {
                                if let Some(n) = agent.get("id").and_then(Value::as_i64) {
                                    ids.insert(format!("{n:03}"));
                                    newest = n;
                                }
                            }
                            last = newest;
                            st
                        }
                        Ok(_) => {
                            last = 0;
                            st
                        }
                        Err(_) => Status::Error,
                    }
                } else {
                    last = 0;
                    st
                }
            }
            Err(_) => Status::Error,
        };
        match st {
            Status::Due => continue,
            Status::Error => {
                log.error("Error querying provigil-db to get agent's IDs.");
                return None;
            }
            _ => return Some(ids),
        }
    }
}

/// The group's id, -1 when missing or on error.
fn find_group(db: &dyn AgentDb, log: &Log, name: &str) -> i64 {
    let Some(v) = query_json(db, log, &format!("global find-group {name}")) else {
        log.error("Error querying provigil-db to get the agent group id.");
        return -1;
    };
    v.get(0).and_then(|g| g.get("id")).and_then(Value::as_i64).unwrap_or(-1)
}

fn set_agent_groups(db: &dyn AgentDb, log: &Log, id: i32, groups: &[String], mode: &str, sync: &str) -> i32 {
    let q = format!("global set-agent-groups {}", json!({ "mode": mode, "sync_status": sync, "data": [{ "id": id, "groups": groups }] }));
    match query(db, log, &q) {
        Ok(a) if parse_answer(&a).0 == Status::Ok => 0,
        Ok(_) => {
            log.debug("Global DB Error reported in the result of the query");
            -1
        }
        Err(_) => {
            log.debug("Global DB Error in the response from socket");
            log.debug2(format!("Global DB SQL query: {q}"));
            -1
        }
    }
}

/// Groups follow the folders of `dir`: a group whose folder is gone is removed, a folder
/// without a group is added.
pub fn update_groups(db: &dyn AgentDb, log: &Log, dir: &Path) -> i32 {
    let Some(v) = query_json(db, log, "global select-groups") else {
        log.error("Error querying provigil-db to update groups.");
        return -1;
    };
    for g in v.as_array().into_iter().flatten() {
        if let Some(name) = g.get("name").and_then(Value::as_str) {
            if std::fs::read_dir(dir.join(name)).is_err() {
                query_ok(db, log, &format!("global delete-group {name}"));
            }
        }
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            log.error(format!("Couldn't open directory '{}': {}.", rel_shared(dir), os_text(&e)));
            return -1;
        }
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if e.path().is_dir() && find_group(db, log, &name) <= 0 {
            query_ok(db, log, &format!("global insert-agent-group {name}"));
        }
    }
    0
}

/// The shared folder as the log names it.
fn rel_shared(dir: &Path) -> String {
    if dir.ends_with(SHARED_DIR) {
        SHARED_DIR.to_string()
    } else {
        dir.display().to_string()
    }
}

// ------------------------------------------------------------------ files

/// The registration date of `queue/agents-timestamp` (`<id> <name> <ip> <date> <time>`, local
/// time); 0 when the agent is not listed.
fn date_added(log: &Log, file: &Path, id: i32) -> i64 {
    use chrono::TimeZone;
    let Ok(data) = std::fs::read(file) else { return 0 };
    for line in String::from_utf8_lossy(&data).split_inclusive('\n') {
        let Some(sp) = line.find(' ') else { continue };
        if siem_regex::os_ip::atoi(&line[..sp]) != id {
            continue;
        }
        let parts: Vec<&str> = line.splitn(5, ' ').collect();
        if parts.len() < 5 {
            return 0;
        }
        let text = format!("{} {}", parts[3], parts[4].split('\n').next().unwrap_or(""));
        return match chrono::NaiveDateTime::parse_from_str(text.trim_end(), "%Y-%m-%d %H:%M:%S").ok().and_then(|d| chrono::Local.from_local_datetime(&d).earliest()) {
            Some(t) => t.timestamp(),
            None => {
                log.error(format!("Invalid date format in file '{TIMESTAMP_FILE}' for agent '{id}'"));
                0
            }
        };
    }
    0
}

/// Removes the agent's line from `queue/agents-timestamp`.
fn remove_timestamp_line(log: &Log, file: &Path, id: &str) {
    let Ok(data) = std::fs::read(file) else { return };
    let text = String::from_utf8_lossy(&data);
    let kept: String = text.split_inclusive('\n').filter(|l| l.find(' ').is_some_and(|sp| &l[..sp] != id)).collect();
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(".tmp");
    if std::fs::write(&tmp, kept).is_err() {
        log.error("Couldn't open timestamp file.");
        return;
    }
    let _ = std::fs::rename(&tmp, file);
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Modification time and identity of a file (its size stands in where there is no inode).
fn file_stamp(m: &std::fs::Metadata) -> (i64, u64) {
    let mtime = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
    #[cfg(unix)]
    let id = std::os::unix::fs::MetadataExt::ino(m);
    #[cfg(not(unix))]
    let id = m.len();
    (mtime, id)
}

fn hostname_unix() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|h| h.trim().to_string()).filter(|h| !h.is_empty())
}

/// The OS's text for an error, without Rust's "(os error N)".
pub fn os_text(e: &std::io::Error) -> String {
    let t = e.to_string();
    t.split(" (os error").next().unwrap_or("").to_string()
}

/// The manager's OS fields from this machine's description: Windows `<name> [Ver: <a.b.c>] |...`,
/// Unix `<sys> |<host> |<release> |<build> |<arch> [<name>|<platform>: <version>]`.
pub fn manager_os(uname: &str) -> Map<String, Value> {
    let mut m = Map::new();
    let mut put = |k: &str, v: &str| {
        if !v.is_empty() {
            m.insert(k.to_string(), json!(v));
        }
    };
    put("os_uname", &uname.chars().take(255).collect::<String>());
    let numbers = |v: &str| -> Vec<String> { v.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).map(str::to_string).collect() };
    if let Some((name, rest)) = uname.split_once(" [Ver: ") {
        let version = rest.split(']').next().unwrap_or("");
        let n = numbers(version);
        put("os_name", name.trim());
        put("os_version", version);
        put("os_platform", "windows");
        put("os_major", n.first().map_or("", String::as_str));
        put("os_minor", n.get(1).map_or("", String::as_str));
        put("os_build", n.get(2).map_or("", String::as_str));
        return m;
    }
    let parts: Vec<&str> = uname.split(" |").collect();
    if parts.len() >= 5 {
        let (machine, distro) = parts[4].split_once(" [").unwrap_or((parts[4], ""));
        put("os_arch", machine.trim());
        let distro = distro.trim_end_matches(']');
        let (name, rest) = distro.split_once('|').unwrap_or((distro, ""));
        let (platform, version) = rest.split_once(": ").unwrap_or((rest, ""));
        let n = numbers(version);
        put("os_name", if name.is_empty() { parts[0] } else { name });
        put("os_platform", if platform.is_empty() { parts[0] } else { platform }.to_lowercase().as_str());
        put("os_version", version);
        put("os_major", n.first().map_or("", String::as_str));
        put("os_minor", n.get(1).map_or("", String::as_str));
        put("os_build", parts[2].trim());
    }
    m
}

#[cfg(test)]
mod tests {
    use super::manager_os;

    #[test]
    fn windows_and_unix_descriptions() {
        let w = manager_os("Microsoft Windows 11 Pro [Ver: 10.0.22631.4317] |x |y");
        assert_eq!((w["os_name"].as_str(), w["os_major"].as_str(), w["os_build"].as_str(), w["os_platform"].as_str()), (Some("Microsoft Windows 11 Pro"), Some("10"), Some("22631"), Some("windows")));
        let u = manager_os("Linux |mgr |5.15.0-91-generic |#101-Ubuntu SMP |x86_64 [Ubuntu|ubuntu: 22.04.3 LTS (Jammy Jellyfish)]");
        assert_eq!((u["os_name"].as_str(), u["os_platform"].as_str(), u["os_major"].as_str(), u["os_minor"].as_str(), u["os_arch"].as_str()), (Some("Ubuntu"), Some("ubuntu"), Some("22"), Some("04"), Some("x86_64")));
        assert!(manager_os("No system info available").get("os_name").is_none());
    }
}
