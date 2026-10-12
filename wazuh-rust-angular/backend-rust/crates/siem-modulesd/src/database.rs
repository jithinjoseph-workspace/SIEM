//! `wm_database.c`: the manager's database module. It keeps global.db in
//! step with the manager: its own name and OS (agent 000), the agents of
//! `client.keys` (at start-up, and on change in worker nodes) and the
//! groups of `etc/shared`.
//!
//! Real-time mode follows `etc/` and `etc/shared` with inotify (Linux);
//! other hosts use the interval loop, like the C without `INOTIFY_ENABLED`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use siem_config::internal_options::InternalOptions;
use siem_crypto::keystore::KeyStore;
use siem_ipc::wdbc::WdbQuery;
use siem_log::WLog;
use siem_remoted::agent_info::{parse_uname_string, truncated_uname, AgentInfoData};

use crate::wdb::*;

/// `WM_DATABASE_LOGTAG`
pub const WM_DATABASE_LOGTAG: &str = "wazuh-modulesd:database";
/// `KEYS_FILE`
pub const KEYS_FILE: &str = "etc/client.keys";
/// `SHAREDCFG_DIR`
pub const SHAREDCFG_DIR: &str = "etc/shared";
/// `GROUPS_DIR`
pub const GROUPS_DIR: &str = "queue/agent-groups";
/// `WDB2_DIR`
pub const WDB2_DIR: &str = "queue/db";
/// `DIFF_DIR`
pub const DIFF_DIR: &str = "queue/diff";
/// `RIDS_DIR`
pub const RIDS_DIR: &str = "queue/rids";
/// `OSSECCONF`
pub const OSSECCONF: &str = "etc/ossec.conf";
/// `MAX_GROUPS_PER_MULTIGROUP`
const MAX_GROUPS_PER_MULTIGROUP: usize = 128;
/// `__ossec_name " " __ossec_version`
const OSSEC_NAME_VERSION: &str = "Wazuh v4.14.7";

/// `wm_database`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WmDatabase {
    pub sync_agents: bool,
    pub real_time: bool,
    pub interval: i32,
    pub max_queued_events: i32,
}

/// `wm_database_read`: the module when `wazuh_database.sync_agents` is set.
pub fn wm_database_read(opts: &InternalOptions) -> Result<Option<WmDatabase>, String> {
    let g = |low: &str, min: i32, max: i32| opts.get_int("wazuh_database", low, min, max).map_err(|e| e.0);
    let data = WmDatabase {
        sync_agents: g("sync_agents", 0, 1)? != 0,
        real_time: g("real_time", 0, 1)? != 0,
        interval: g("interval", 0, 86400)?,
        max_queued_events: g("max_queued_events", 0, i32::MAX)?,
    };
    Ok(data.sync_agents.then_some(data))
}

/// `wm_database_dump`
pub fn wm_database_dump(data: &WmDatabase) -> serde_json::Value {
    let yn = |b: bool| if b { "yes" } else { "no" };
    serde_json::json!({ "database": {
        "sync_agents": yn(data.sync_agents),
        "real_time": yn(data.real_time),
        "interval": data.interval,
        "max_queued_events": data.max_queued_events,
    }})
}

/// The module state (`module`, `is_worker`, `wdb_wmdb_sock`).
pub struct Database {
    pub data: WmDatabase,
    pub log: Arc<WLog>,
    pub db: Arc<dyn WdbQuery>,
    /// `w_is_worker()`: 1, 0, or OS_INVALID (-1, also true in C).
    is_worker: i32,
}

impl Database {
    pub fn new(data: WmDatabase, log: Arc<WLog>, db: Arc<dyn WdbQuery>) -> Self {
        Database { data, log, db, is_worker: 0 }
    }

    fn info(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(WM_DATABASE_LOGTAG, "INFO", m);
    }
    fn error(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(WM_DATABASE_LOGTAG, "ERROR", m);
    }
    fn warn(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(WM_DATABASE_LOGTAG, "WARNING", m);
    }
    fn debug1(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(WM_DATABASE_LOGTAG, "DEBUG", m);
    }
    fn debug2(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(WM_DATABASE_LOGTAG, "DEBUG2", m);
    }

    fn db(&self) -> &dyn WdbQuery {
        &*self.db
    }

    /// `wm_database_main`: never returns.
    pub async fn main(mut self) {
        self.info("Module started.");

        // Check if it is a worker node
        self.is_worker = match siem_config::cluster::is_worker(std::path::Path::new(OSSECCONF)) {
            Some(true) => 1,
            Some(false) => 0,
            None => -1,
        };

        // Manager name synchronization
        self.sync_manager().await;

        // During the startup, both workers and master nodes should perform the
        // agents synchronization with the database using the keys.
        self.sync_agents().await;

        // Groups synchronization with the database
        update_groups(self.db(), &self.log, SHAREDCFG_DIR).await;

        // Legacy agent-group files
        self.sync_legacy_groups_files().await;

        // Remove dangling agent databases
        self.clean_dangling_wdb_dbs().await;

        #[cfg(target_os = "linux")]
        if self.data.real_time {
            return self.real_time_loop().await;
        }

        // Systems that don't support inotify, or real-time disabled
        self.interval_loop().await
    }

    async fn interval_loop(&self) -> ! {
        let interval = self.data.interval.max(0) as i64;
        let mut keys_stamp: Option<(i64, u64)> = None;
        // Initial wait
        tokio::time::sleep(Duration::from_secs(interval as u64)).await;
        loop {
            let tstart = now();
            let spec0 = Instant::now();
            if self.data.sync_agents {
                self.check_agents(&mut keys_stamp).await;
                update_groups(self.db(), &self.log, SHAREDCFG_DIR).await;
            }
            let ms = spec0.elapsed().as_secs_f64() * 1000.0;
            self.debug1(format!("Cycle completed: {ms:.3} ms ({ms:.3} clock ms)."));
            let tsleep = tstart + interval - now();
            if tsleep >= 0 {
                tokio::time::sleep(Duration::from_secs(tsleep as u64)).await;
            } else {
                self.warn(format!("Time interval exceeded by {} seconds.", -tsleep));
            }
        }
    }

    /// `wm_sync_manager`
    async fn sync_manager(&self) {
        let host = hostname();
        match &host {
            Some(h) => {
                update_agent_name(self.db(), &self.log, 0, h).await;
            }
            None => {
                let e = std::io::Error::last_os_error();
                self.error(format!("Couldn't get manager's hostname: {}.", errno_text(&e)));
            }
        }
        let node_name = get_node_name(&self.log);
        let full = siem_fileop::version_op::getuname();
        let os_uname = full.split(" - ").next().unwrap_or("").to_string();
        let mut osd = parse_uname_string(&os_uname);
        osd.os_uname = Some(truncated_uname(&os_uname).to_string());
        let data = AgentInfoData {
            id: 0,
            osd: Some(osd),
            version: Some(OSSEC_NAME_VERSION.into()),
            manager_host: host,
            node_name: Some(node_name),
            connection_status: Some("active".into()),
            sync_status: Some("synced".into()),
            group_config_status: Some("synced".into()),
            ..Default::default()
        };
        let q = format!("global update-agent-data {}", data.to_wdb_json());
        let _ = query_ex(self.db(), &self.log, &q).await;
    }

    /// `wm_check_agents`: synchronizes when `client.keys` changed.
    async fn check_agents(&self, stamp: &mut Option<(i64, u64)>) {
        match std::fs::metadata(KEYS_FILE) {
            Err(e) => self.error(format!("Couldn't get client.keys stat: {}.", errno_text(&e))),
            Ok(m) => {
                let s = file_stamp(&m);
                if Some(s) != *stamp {
                    if self.is_worker != 0 {
                        self.sync_agents().await;
                    }
                    *stamp = Some(s);
                }
            }
        }
    }

    /// `wm_sync_agents`
    pub async fn sync_agents(&self) {
        let t0 = Instant::now();
        self.debug1("Synchronizing agents.");
        // OS_PassEmptyKeyfile(); OS_ReadKeys(&keys, W_RAW_KEY, 0)
        let keys = match KeyStore::read(KEYS_FILE, true, false) {
            Ok(k) => k,
            Err(e) => {
                self.log.critical(e.to_string());
                std::process::exit(1);
            }
        };
        self.sync_keys_with_wdb(&keys).await;
        self.debug1("Agents synchronization completed.");
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        self.debug1(format!("wm_sync_agents(): {ms:.3} ms ({ms:.3} clock ms)."));
    }

    /// `sync_keys_with_wdb`: inserts the keys global.db does not have and
    /// removes (with their artifacts) the agents without a key.
    pub async fn sync_keys_with_wdb(&self, keys: &KeyStore) {
        let Some(agents) = get_all_agents(self.db(), &self.log, false).await else {
            self.error("Couldn't synchronize the keystore with the DB.");
            return;
        };
        // Add new agents to the database
        for entry in &keys.entries {
            let agent_id = siem_regex::os_ip::atoi(&entry.id);
            if agent_id != 0 && !agents.contains(&entry.id) {
                self.debug2(format!("Synchronizing agent {} '{}'.", entry.id, entry.name));
                let ip = siem_regex::os_ip::cidr_to_str(&entry.ip).unwrap_or_else(|| entry.ip.ip.clone());
                let date_add = get_agent_date_added(&self.log, agent_id);
                if insert_agent(self.db(), &self.log, agent_id, &entry.name, &ip, &entry.raw_key, None, date_add).await != 0 {
                    self.debug1(format!("Couldn't insert agent '{}' in the database.", entry.id));
                }
            }
        }
        // Delete from the database all the agents without a key and all its artifacts
        for id in &agents {
            let agent_id = siem_regex::os_ip::atoi(id);
            if agent_id != 0 && !keys.entries.iter().any(|e| &e.id == id) {
                let agent_name = get_agent_name(self.db(), &self.log, agent_id).await;
                if remove_agent(self.db(), &self.log, agent_id).await < 0 {
                    self.debug1(format!("Couldn't remove agent '{id}' from the database."));
                    continue;
                }
                // Agent not found. Removing agent artifacts
                self.clean_agent_artifacts(agent_id, agent_name.as_deref()).await;
                // Remove agent-related files
                remove_counter(id);
                remove_agent_timestamp(&self.log, id);
            }
        }
    }

    /// `wm_clean_agent_artifacts`
    async fn clean_agent_artifacts(&self, agent_id: i32, agent_name: Option<&str>) {
        if query_ex(self.db(), &self.log, &format!("wazuhdb remove {agent_id}")).await.is_err() {
            self.debug1(format!("Could not remove the wazuh-db DB of the agent {agent_id}."));
        }
        delete_diff(agent_name);
    }

    /// `wm_clean_dangling_wdb_dbs`
    async fn clean_dangling_wdb_dbs(&self) {
        let rd = match std::fs::read_dir(WDB2_DIR) {
            Ok(r) => r,
            Err(e) => {
                self.error(format!("Couldn't open directory '{WDB2_DIR}': {}.", errno_text(&e)));
                return;
            }
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.as_bytes().first().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }
            let Some(dot) = name.find('.') else {
                self.warn(format!("Strange file found: '{WDB2_DIR}/{name}'"));
                continue;
            };
            let digits = name.bytes().take_while(|c| c.is_ascii_digit()).count();
            let id: i32 = name[..digits].parse().unwrap_or(0);
            let end = &name[digits..];
            let _ = dot;
            if id > 0 && end.starts_with(".db") {
                if let Some(n) = get_agent_name(self.db(), &self.log, id).await {
                    if n.is_empty() {
                        let path = format!("{WDB2_DIR}/{name}");
                        self.warn(format!("Removing dangling WDB DB file: '{path}'"));
                        if let Err(e) = std::fs::remove_file(&path) {
                            let n = e.raw_os_error().unwrap_or(0);
                            self.debug1(format!("(1129): Could not unlink file '{path}' due to [({n})-({})].", errno_text(&e)));
                        }
                    }
                }
            }
        }
    }

    /// `wm_sync_legacy_groups_files`
    async fn sync_legacy_groups_files(&self) {
        let rd = match std::fs::read_dir(GROUPS_DIR) {
            Ok(r) => r,
            Err(e) => {
                self.debug1(format!("Couldn't open directory '{GROUPS_DIR}': {}.", errno_text(&e)));
                return;
            }
        };
        self.debug1(format!("Scanning directory '{GROUPS_DIR}'."));
        let mut is_dir_empty = true;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let path = format!("{GROUPS_DIR}/{name}");
            if self.is_worker != 0 {
                self.debug1(format!("Group file '{path}' won't be synced in a worker node, removing."));
                let _ = std::fs::remove_file(&path);
            } else if self.sync_group_file(&name, &path).await == 0 {
                self.debug1(format!("Group file '{path}' successfully synced, removing."));
                let _ = std::fs::remove_file(&path);
            } else {
                self.log.error(format!("Failed during the groups file '{path}' syncronization."));
                is_dir_empty = false;
            }
        }
        if is_dir_empty {
            if let Err(e) = siem_fileop::rmdir_ex(GROUPS_DIR) {
                let n = e.raw_os_error().unwrap_or(0);
                self.debug1(format!("Unable to remove directory '{GROUPS_DIR}': '{}' ({n})", errno_text(&e)));
            }
        }
    }

    /// `wm_sync_group_file`
    async fn sync_group_file(&self, group_file: &str, path: &str) -> i32 {
        let id_agent = siem_regex::os_ip::atoi(group_file);
        if id_agent <= 0 {
            self.debug1(format!("Couldn't extract agent ID from file '{path}'."));
            return -1;
        }
        let Ok(data) = std::fs::read(path) else {
            self.debug1(format!("Groups file '{path}' could not be opened for syncronization."));
            return -1;
        };
        let text = String::from_utf8_lossy(&data);
        let Some(line) = text.split_inclusive('\n').next().filter(|l| !l.is_empty()) else {
            self.debug1(format!("Empty group file '{path}'."));
            return 0;
        };
        let line = line.split('\n').next().unwrap_or("");
        let groups: Vec<String> = line.split(',').map(String::from).collect();
        let start = groups.len().saturating_sub(MAX_GROUPS_PER_MULTIGROUP);
        let single = siem_config::cluster::is_single_node(std::path::Path::new(OSSECCONF)).0.unwrap_or(true);
        set_agent_groups(self.db(), &self.log, id_agent, &groups[start..], "override", if single { "synced" } else { "syncreq" }).await
    }

    /// `wm_sync_shared_group`
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    async fn sync_shared_group(&self, fname: &str) -> i32 {
        let t0 = Instant::now();
        let path = format!("{SHAREDCFG_DIR}/{fname}");
        if std::fs::read_dir(&path).is_err() {
            // The group was deleted
            remove_group_db(self.db(), &self.log, fname).await;
        } else if find_group(self.db(), &self.log, fname).await <= 0 {
            insert_group(self.db(), &self.log, fname).await;
        }
        self.debug2(format!("wm_sync_shared_group(): {:.3} ms.", t0.elapsed().as_secs_f64() * 1000.0));
        0
    }

    /// `wm_sync_file`
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    async fn sync_file(&self, dirname: &str, fname: &str) -> i32 {
        self.debug2(format!("Synchronizing file '{dirname}/{fname}'"));
        if dirname == SHAREDCFG_DIR {
            self.sync_shared_group(fname).await
        } else {
            self.error(format!("Directory name '{dirname}' not recognized."));
            -1
        }
    }

    /// The `INOTIFY_ENABLED` branch: `etc/` (client.keys) and `etc/shared`.
    #[cfg(target_os = "linux")]
    async fn real_time_loop(&self) {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let log = self.log.clone();
        let limit = if self.data.max_queued_events > 0 { self.data.max_queued_events as usize } else { 16384 };
        if !inotify::start(&log, self.data, tx, limit) {
            std::process::exit(1);
        }
        while let Some(path) = rx.recv().await {
            if path == KEYS_FILE {
                // The syncronization with client.keys only happens in worker nodes
                if self.is_worker != 0 {
                    self.sync_agents().await;
                }
            } else if let Some(p) = path.rfind('/') {
                self.sync_file(&path[..p], &path[p + 1..]).await;
            } else {
                self.error(format!("Couldn't extract file name from '{path}'"));
            }
            inotify::done(&path);
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// mtime + inode (the size stands in for the inode where there is none).
fn file_stamp(m: &std::fs::Metadata) -> (i64, u64) {
    let mtime = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        m.ino()
    };
    #[cfg(not(unix))]
    let ino = m.len();
    (mtime, ino)
}

/// `gethostname`
fn hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer bounds the write.
        if unsafe { libc_gethostname(buf.as_mut_ptr(), buf.len()) } != 0 {
            return None;
        }
        let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..n]).into_owned())
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

#[cfg(unix)]
unsafe fn libc_gethostname(p: *mut u8, n: usize) -> i32 {
    unsafe extern "C" {
        fn gethostname(name: *mut u8, len: usize) -> i32;
    }
    unsafe { gethostname(p, n) }
}

/// `get_node_name`
fn get_node_name(log: &WLog) -> String {
    match siem_xml::OsXml::read_file(std::path::Path::new(OSSECCONF), false) {
        Ok(mut x) => x.get_one_content_for_element(&["ossec_config", "cluster", "node_name"]),
        Err(e) => {
            log.debug1(format!("(1226): Error reading XML file '{OSSECCONF}': {} (line {}).", e.message, e.line));
            None
        }
    }
    .unwrap_or_else(|| "undefined".into())
}

/// `delete_diff`
fn delete_diff(name: Option<&str>) {
    let Some(name) = name.filter(|n| !n.is_empty()) else { return };
    let _ = siem_fileop::rmdir_ex(&format!("{DIFF_DIR}/{name}"));
}

/// `OS_RemoveCounter`
fn remove_counter(id: &str) {
    let _ = std::fs::remove_file(format!("{RIDS_DIR}/{id}"));
}

/// `OS_RemoveAgentTimestamp`
fn remove_agent_timestamp(log: &WLog, id: &str) {
    let Ok(data) = std::fs::read(TIMESTAMP_FILE) else { return };
    let text = String::from_utf8_lossy(&data);
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let Some(sep) = line.find(' ') else { continue };
        if &line[..sep] != id {
            out.push_str(line);
        }
    }
    let tmp = format!("{TIMESTAMP_FILE}.tmp");
    if std::fs::write(&tmp, out).is_err() {
        log.error("Couldn't open timestamp file.");
        return;
    }
    let _ = std::fs::rename(&tmp, TIMESTAMP_FILE);
}

#[cfg(target_os = "linux")]
mod inotify {
    //! `wm_inotify_setup` / `wm_inotify_start` / `wm_inotify_push` / `wm_inotify_pop`.

    use std::collections::HashSet;
    use std::sync::Mutex;

    use super::*;

    static PTABLE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

    /// `wm_inotify_pop`'s `OSHash_Delete`
    pub fn done(path: &str) {
        if let Some(t) = PTABLE.lock().unwrap().as_mut() {
            t.remove(path);
        }
    }

    const MAX_QUEUED_EVENTS_PATH: &str = "/proc/sys/fs/inotify/max_queued_events";

    fn get_max_queued_events(log: &WLog) -> i32 {
        match std::fs::read_to_string(MAX_QUEUED_EVENTS_PATH) {
            Ok(s) => s.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(-1),
            Err(e) => {
                let n = e.raw_os_error().unwrap_or(0);
                log.tagged(WM_DATABASE_LOGTAG, "ERROR", format!("(1103): Could not open file '{MAX_QUEUED_EVENTS_PATH}' due to [({n})-({})].", errno_text(&e)));
                -1
            }
        }
    }

    fn set_max_queued_events(log: &WLog, size: i32) -> i32 {
        match std::fs::write(MAX_QUEUED_EVENTS_PATH, format!("{size}\n")) {
            Ok(()) => 0,
            Err(e) => {
                let n = e.raw_os_error().unwrap_or(0);
                log.tagged(WM_DATABASE_LOGTAG, "ERROR", format!("(1103): Could not open file '{MAX_QUEUED_EVENTS_PATH}' due to [({n})-({})].", errno_text(&e)));
                -1
            }
        }
    }

    /// `wm_inotify_setup` + the reader thread. False on `mterror_exit`.
    pub fn start(log: &Arc<WLog>, data: WmDatabase, tx: tokio::sync::mpsc::UnboundedSender<String>, limit: usize) -> bool {
        *PTABLE.lock().unwrap() = Some(HashSet::new());
        let mut old = -1;
        if data.max_queued_events != 0 {
            old = get_max_queued_events(log);
            if old >= 0 && old != data.max_queued_events {
                log.tagged(WM_DATABASE_LOGTAG, "DEBUG", format!("Setting inotify queued events limit to '{}'", data.max_queued_events));
                if set_max_queued_events(log, data.max_queued_events) < 0 {
                    old = -1;
                }
            }
        }
        // SAFETY: plain inotify syscalls.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            log.tagged(WM_DATABASE_LOGTAG, "CRITICAL", format!("Couldn't init inotify: {}.", errno_text(&e)));
            return false;
        }
        if old >= 0 && old != data.max_queued_events {
            log.tagged(WM_DATABASE_LOGTAG, "DEBUG2", format!("Restoring inotify queued events limit to '{old}'"));
            set_max_queued_events(log, old);
        }
        let add = |p: &str, mask: u32| -> i32 {
            let c = std::ffi::CString::new(p).unwrap();
            // SAFETY: valid descriptor and path.
            unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) }
        };
        let mut wd_agents = -2;
        let mut wd_shared_groups = -2;
        if data.sync_agents {
            wd_agents = add("etc", libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO);
            if wd_agents < 0 {
                let e = std::io::Error::last_os_error();
                log.tagged(WM_DATABASE_LOGTAG, "ERROR", format!("Couldn't watch client.keys file: {}.", errno_text(&e)));
            }
            log.tagged(WM_DATABASE_LOGTAG, "DEBUG2", format!("wd_agents='{wd_agents}'"));
            wd_shared_groups = add(
                SHAREDCFG_DIR,
                libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_MOVED_FROM | libc::IN_CREATE | libc::IN_DELETE,
            );
            if wd_shared_groups < 0 {
                let e = std::io::Error::last_os_error();
                log.tagged(WM_DATABASE_LOGTAG, "ERROR", format!("Couldn't watch the shared groups directory: {}.", errno_text(&e)));
            }
            log.tagged(WM_DATABASE_LOGTAG, "DEBUG2", format!("wd_shared_groups='{wd_shared_groups}'"));
        }
        let log = log.clone();
        std::thread::spawn(move || reader(log, fd, wd_agents, wd_shared_groups, tx, limit));
        true
    }

    /// `wm_inotify_start`
    fn reader(log: Arc<WLog>, fd: i32, wd_agents: i32, wd_shared: i32, tx: tokio::sync::mpsc::UnboundedSender<String>, limit: usize) {
        const HDR: usize = std::mem::size_of::<libc::inotify_event>();
        let mut buffer = vec![0u8; HDR + 256];
        loop {
            log.tagged(WM_DATABASE_LOGTAG, "DEBUG", "Waiting for event notification...");
            loop {
                // SAFETY: the buffer bounds the read.
                let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
                if count < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::EAGAIN) {
                        log.tagged(WM_DATABASE_LOGTAG, "ERROR", format!("read(): {}.", errno_text(&e)));
                    }
                    break;
                }
                let count = count as usize;
                let mut i = 0;
                while i < count {
                    // SAFETY: the kernel wrote whole events into the buffer.
                    let ev: libc::inotify_event = unsafe { std::ptr::read_unaligned(buffer[i..].as_ptr().cast()) };
                    let name_bytes = &buffer[i + HDR..(i + HDR + ev.len as usize).min(count)];
                    let name = String::from_utf8_lossy(&name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len())]).into_owned();
                    log.tagged(WM_DATABASE_LOGTAG, "DEBUG2", format!("inotify: i='{i}', name='{name}', mask='{}', wd='{}'", ev.mask, ev.wd));
                    i += HDR + ev.len as usize;
                    if ev.len as usize > buffer.len() {
                        log.tagged(WM_DATABASE_LOGTAG, "ERROR", format!("Inotify event too large ({})", ev.len));
                        break;
                    }
                    let dirname = if ev.wd == wd_agents {
                        if name == "client.keys" {
                            "etc"
                        } else {
                            continue;
                        }
                    } else if ev.wd == wd_shared {
                        SHAREDCFG_DIR
                    } else if ev.wd == -1 && ev.mask == libc::IN_Q_OVERFLOW {
                        log.tagged(WM_DATABASE_LOGTAG, "ERROR", "Inotify event queue overflowed.");
                        continue;
                    } else {
                        log.tagged(WM_DATABASE_LOGTAG, "ERROR", format!("Unknown watch descriptor '{}', mask='{}'.", ev.wd, ev.mask));
                        continue;
                    };
                    let path = format!("{dirname}/{name}");
                    if name.starts_with('.') && std::fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false) {
                        log.tagged(WM_DATABASE_LOGTAG, "DEBUG2", "Discarding hidden file.");
                        continue;
                    }
                    push(&log, &tx, &path, limit);
                }
                if count == 0 {
                    break;
                }
            }
        }
    }

    /// `wm_inotify_push`
    fn push(log: &WLog, tx: &tokio::sync::mpsc::UnboundedSender<String>, path: &str, limit: usize) {
        let mut g = PTABLE.lock().unwrap();
        let t = g.as_mut().unwrap();
        if t.len() >= limit {
            log.tagged(WM_DATABASE_LOGTAG, "ERROR", format!("Internal queue is full ({limit})."));
            return;
        }
        if !t.insert(path.to_string()) {
            log.tagged(WM_DATABASE_LOGTAG, "DEBUG2", format!("Adding '{path}': file already exists at path table."));
            return;
        }
        log.tagged(WM_DATABASE_LOGTAG, "DEBUG2", format!("Adding '{path}' to path table."));
        if tx.send(path.to_string()).is_err() {
            log.tagged(WM_DATABASE_LOGTAG, "ERROR", "Couldn't insert key into queue.");
        }
    }
}
