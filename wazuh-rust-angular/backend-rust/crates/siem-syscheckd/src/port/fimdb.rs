//! `syscheckd/src/db` (`FIMDB`, `DB`, `FileItem`, `RegistryKey`,
//! `RegistryValue`, `file.cpp`, `registry.cpp`, `db.cpp`) on siem-dbsync.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use siem_cjson::Json;
use siem_dbsync::dbsync::Query;
use siem_dbsync::rsync::{RemoteSync, SyncCallback};
use siem_dbsync::{DBSync, DBSyncTxn, DbManagement, DbEngineType, HostType, ResultCallback, ReturnTypeCallback};
use siem_njson::Value;

use super::config::*;

pub const FIM_DB_MEMORY_PATH: &str = ":memory:";
pub const FIM_DB_DISK_PATH: &str = "queue/fim/db/fim.db";
pub const FIMDB_FILE_TABLE_NAME: &str = "file_entry";
pub const FIMDB_FILE_TXN_TABLE: &str = "{\"table\": \"file_entry\"}";
pub const FIMDB_REGISTRY_KEY_TABLENAME: &str = "registry_key";
pub const FIMDB_REGISTRY_KEY_TXN_TABLE: &str = "{\"table\": \"registry_key\"}";
pub const FIMDB_REGISTRY_VALUE_TABLENAME: &str = "registry_data";
pub const FIMDB_REGISTRY_VALUE_TXN_TABLE: &str = "{\"table\": \"registry_data\"}";
pub const FIM_COMPONENT_FILE: &str = "fim_file";
pub const FIM_COMPONENT_REGISTRY_KEY: &str = "fim_registry_key";
pub const FIM_COMPONENT_REGISTRY_VALUE: &str = "fim_registry_value";
const QUEUE_SIZE: u32 = 4096;

/// `FIMDBErrorCode`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FimDbError {
    Ok = 0,
    Err = -1,
    Full = -2,
}

/// `modules_log_level_t`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    ErrorExit,
    DebugVerbose,
}

/// `fim_event_mode`
pub const FIM_SCHEDULED: i32 = 0;
pub const FIM_REALTIME: i32 = 1;
pub const FIM_WHODATA: i32 = 2;

/// `fim_file_data`
#[derive(Clone, Debug, Default)]
pub struct FileData {
    pub size: u64,
    pub perm_json: Option<Json>,
    pub perm: Option<Vec<u8>>,
    pub attributes: Option<Vec<u8>>,
    pub uid: Option<Vec<u8>>,
    pub gid: Option<Vec<u8>>,
    pub user_name: Option<Vec<u8>>,
    pub group_name: Option<Vec<u8>>,
    pub mtime: i64,
    pub inode: u64,
    pub hash_md5: String,
    pub hash_sha1: String,
    pub hash_sha256: String,
    pub mode: i32,
    pub last_event: i64,
    pub dev: u64,
    pub scanned: u32,
    pub options: i32,
    pub checksum: String,
}

/// `fim_registry_key`
#[derive(Clone, Debug, Default)]
pub struct RegKey {
    pub id: u32,
    pub path: Vec<u8>,
    pub hash_full_path: String,
    pub perm_json: Option<Json>,
    pub perm: Option<Vec<u8>>,
    pub uid: Option<Vec<u8>>,
    pub gid: Option<Vec<u8>>,
    pub user_name: Option<Vec<u8>>,
    pub group_name: Option<Vec<u8>>,
    pub mtime: i64,
    pub arch: i32,
    pub scanned: u32,
    pub last_event: i64,
    pub checksum: String,
}

/// `fim_registry_value_data`
#[derive(Clone, Debug, Default)]
pub struct RegValue {
    pub id: u32,
    pub path: Vec<u8>,
    pub hash_full_path: String,
    pub arch: i32,
    pub name: Vec<u8>,
    pub type_: u32,
    pub size: u64,
    pub hash_md5: String,
    pub hash_sha1: String,
    pub hash_sha256: String,
    pub scanned: u32,
    pub last_event: i64,
    pub checksum: String,
    pub mode: i32,
}

/// `FIMDBCreator<OS_TYPE>::encodeString`: on Windows, ANSI strings become UTF-8.
pub fn encode_string(s: &[u8]) -> Vec<u8> {
    #[cfg(windows)]
    {
        if !super::win::utf8_valid(s) {
            return siem_sysinfo::win::enc::ansi_to_utf8(s);
        }
    }
    s.to_vec()
}

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.as_bytes().to_vec(), v)).collect())
}

fn s(b: &[u8]) -> Value {
    Value::Str(b.to_vec())
}

/// `{"table": ..., "data": [data], "options"?}` of the items.
fn statement(table: &str, data: Value, old_data: bool) -> Value {
    let mut conf = vec![("table", s(table.as_bytes())), ("data", Value::Array(vec![data]))];
    if old_data {
        conf.push(("options", obj(vec![("return_old_data", Value::Bool(true)), ("ignore", Value::Array(vec![s(b"last_event")]))])));
    }
    obj(conf)
}

/// `FileItem(fim, oldData)->toJSON()`
pub fn file_item_json(path: &[u8], d: &FileData, old_data: bool) -> Value {
    let e = |o: &Option<Vec<u8>>| s(&encode_string(o.as_deref().unwrap_or(b"")));
    let data = obj(vec![
        ("path", s(&encode_string(path))),
        ("mode", Value::Int(d.mode as i64)),
        ("last_event", Value::Int(d.last_event)),
        ("scanned", Value::UInt(d.scanned as u64)),
        ("options", Value::Int(d.options as i64)),
        ("checksum", s(d.checksum.as_bytes())),
        ("dev", Value::UInt(d.dev)),
        ("inode", Value::UInt(d.inode)),
        ("size", Value::UInt(d.size)),
        ("perm", e(&d.perm)),
        ("attributes", e(&d.attributes)),
        ("uid", s(d.uid.as_deref().unwrap_or(b""))),
        ("gid", s(d.gid.as_deref().unwrap_or(b""))),
        ("user_name", e(&d.user_name)),
        ("group_name", e(&d.group_name)),
        ("hash_md5", s(d.hash_md5.as_bytes())),
        ("hash_sha1", s(d.hash_sha1.as_bytes())),
        ("hash_sha256", s(d.hash_sha256.as_bytes())),
        ("mtime", Value::Int(d.mtime)),
    ]);
    statement(FIMDB_FILE_TABLE_NAME, data, old_data)
}

/// `RegistryKey(fim, oldData)->toJSON()`
pub fn reg_key_json(k: &RegKey, old_data: bool) -> Value {
    let e = |o: &Option<Vec<u8>>| s(&encode_string(o.as_deref().unwrap_or(b"")));
    let data = obj(vec![
        ("path", s(&encode_string(&k.path))),
        ("arch", s(if k.arch == 0 { b"[x32]" } else { b"[x64]" })),
        ("last_event", Value::Int(k.last_event)),
        ("scanned", Value::UInt(k.scanned as u64)),
        ("checksum", s(k.checksum.as_bytes())),
        ("perm", e(&k.perm)),
        ("uid", s(k.uid.as_deref().unwrap_or(b""))),
        ("gid", s(k.gid.as_deref().unwrap_or(b""))),
        ("user_name", e(&k.user_name)),
        ("group_name", e(&k.group_name)),
        ("mtime", Value::Int(k.mtime)),
        ("hash_full_path", s(k.hash_full_path.as_bytes())),
    ]);
    statement(FIMDB_REGISTRY_KEY_TABLENAME, data, old_data)
}

/// `RegistryValue(fim, oldData)->toJSON()`
pub fn reg_value_json(v: &RegValue, old_data: bool) -> Value {
    let data = obj(vec![
        ("path", s(&encode_string(&v.path))),
        ("arch", s(if v.arch == 0 { b"[x32]" } else { b"[x64]" })),
        ("name", s(&encode_string(&v.name))),
        ("last_event", Value::Int(v.last_event)),
        ("scanned", Value::UInt(v.scanned as u64)),
        ("checksum", s(v.checksum.as_bytes())),
        ("size", Value::UInt(v.size)),
        ("hash_md5", s(v.hash_md5.as_bytes())),
        ("hash_sha1", s(v.hash_sha1.as_bytes())),
        ("hash_sha256", s(v.hash_sha256.as_bytes())),
        ("type", Value::UInt(v.type_ as u64)),
        ("hash_full_path", s(v.hash_full_path.as_bytes())),
    ]);
    statement(FIMDB_REGISTRY_VALUE_TABLENAME, data, old_data)
}

/// `FileItem(json)->toFimEntry()`: the path (ANSI on Windows) and the data.
pub fn file_from_json(j: &Value) -> Option<(Vec<u8>, FileData)> {
    let st = |k: &str| j.at(k).ok().and_then(|v| v.get_string().ok()).unwrap_or_default();
    let int = |k: &str| j.at(k).ok().and_then(|v| v.get_i64_arith().ok()).unwrap_or(0);
    let path = st("path");
    #[cfg(windows)]
    let path = siem_sysinfo::win::enc::utf8_to_ansi(&path);
    let d = FileData {
        size: int("size") as u64,
        perm: Some(st("perm")),
        attributes: Some(st("attributes")),
        uid: Some(st("uid")),
        gid: Some(st("gid")),
        user_name: Some(st("user_name")),
        group_name: Some(st("group_name")),
        mtime: int("mtime"),
        inode: int("inode") as u64,
        hash_md5: String::from_utf8_lossy(&st("hash_md5")).into_owned(),
        hash_sha1: String::from_utf8_lossy(&st("hash_sha1")).into_owned(),
        hash_sha256: String::from_utf8_lossy(&st("hash_sha256")).into_owned(),
        mode: int("mode") as i32,
        last_event: int("last_event"),
        dev: int("dev") as u64,
        scanned: int("scanned") as u32,
        options: int("options") as i32,
        checksum: String::from_utf8_lossy(&st("checksum")).into_owned(),
        perm_json: None,
    };
    Some((path, d))
}

/// njson -> cJSON (the C side parses `json.dump()`).
pub fn to_cjson(v: &Value) -> Option<Json> {
    siem_cjson::parse(&v.dump().ok()?)
}

/// The sync state of `FIMDB` (`m_*` members guarded by `m_fimSyncMutex`).
struct SyncState {
    stopping: bool,
    run_integrity: bool,
    current_sync_interval: u32,
    sync_successful: bool,
    time_last_sync_msg: i64,
}

/// `FIMDB` + `DB`
pub struct FimDb {
    pub dbsync: DBSync,
    pub rsync: RemoteSync,
    sync_interval: u32,
    sync_max_interval: u32,
    sync_response_timeout: u32,
    sync_registry_enabled: bool,
    file_cb: SyncCallback,
    registry_cb: SyncCallback,
    log: Arc<dyn Fn(LogLevel, &str) + Send + Sync>,
    state: Mutex<SyncState>,
    cv: Condvar,
}

static FIMDB: OnceLock<Arc<FimDb>> = OnceLock::new();

pub fn instance() -> Option<&'static Arc<FimDb>> {
    FIMDB.get()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `"WHERE x BETWEEN '?' and '?' ORDER BY x"` query parameters.
fn q(filter: &str, columns: &[&str], count_field: Option<&str>) -> Value {
    let mut v = vec![
        ("row_filter", s(filter.as_bytes())),
        ("column_list", Value::Array(columns.iter().map(|c| s(c.as_bytes())).collect())),
        ("distinct_opt", Value::Bool(false)),
        ("order_by_opt", s(b"")),
    ];
    if let Some(c) = count_field {
        v.push(("count_field_name", s(c.as_bytes())));
    }
    obj(v)
}

/// `RegisterConfiguration::builder()...config()` of fileSyncConfig and friends.
fn sync_config(table: &str, component: &str, index: &str) -> Value {
    let range = format!("WHERE {index} BETWEEN '?' and '?' ORDER BY {index}");
    obj(vec![
        ("decoder_type", s(b"JSON_RANGE")),
        ("table", s(table.as_bytes())),
        ("component", s(component.as_bytes())),
        ("index", s(index.as_bytes())),
        ("checksum_field", s(b"checksum")),
        ("last_event", s(b"last_event")),
        ("no_data_query_json", q(&range, &["*"], None)),
        ("count_range_query_json", q(&range, &["count(*) AS count"], Some("count"))),
        ("row_data_query_json", q(&format!("WHERE {index} = '?'"), &["*"], None)),
        ("range_checksum_query_json", q(&range, &["*"], None)),
    ])
}

/// `FIM_*_START_CONFIG_STATEMENT`
fn start_config(table: &str, component: &str, index: &str) -> Value {
    let one = |order: &str| {
        obj(vec![
            ("column_list", Value::Array(vec![s(index.as_bytes())])),
            ("row_filter", s(b" ")),
            ("distinct_opt", Value::Bool(false)),
            ("order_by_opt", s(order.as_bytes())),
            ("count_opt", Value::Int(1)),
        ])
    };
    obj(vec![
        ("table", s(table.as_bytes())),
        ("first_query", one(&format!("{index} DESC"))),
        ("last_query", one(&format!("{index} ASC"))),
        ("component", s(component.as_bytes())),
        ("index", s(index.as_bytes())),
        ("last_event", s(b"last_event")),
        ("checksum_field", s(b"checksum")),
        (
            "range_checksum_query_json",
            obj(vec![
                ("row_filter", s(format!("WHERE {index} BETWEEN '?' and '?' ORDER BY {index}").as_bytes())),
                ("column_list", Value::Array(vec![s(format!("{index}, checksum").as_bytes())])),
                ("distinct_opt", Value::Bool(false)),
                ("order_by_opt", s(b"")),
                ("count_opt", Value::Int(100)),
            ]),
        ),
    ])
}

const CREATE_FILE_DB_STATEMENT: &str = "CREATE TABLE IF NOT EXISTS file_entry (
    path TEXT NOT NULL,
    mode INTEGER,
    last_event INTEGER,
    scanned INTEGER,
    options INTEGER,
    checksum TEXT NOT NULL,
    dev INTEGER,
    inode INTEGER,
    size INTEGER,
    perm TEXT,
    attributes TEXT,
    uid TEXT,
    gid TEXT,
    user_name TEXT,
    group_name TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    mtime INTEGER,
    PRIMARY KEY(path)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS path_index ON file_entry (path);
    CREATE INDEX IF NOT EXISTS inode_index ON file_entry (dev, inode);";

const CREATE_REGISTRY_KEY_DB_STATEMENT: &str = "CREATE TABLE IF NOT EXISTS registry_key (
    path TEXT NOT NULL,
    perm TEXT,
    uid TEXT,
    gid TEXT,
    user_name TEXT,
    group_name TEXT,
    mtime INTEGER,
    arch TEXT CHECK (arch IN ('[x32]', '[x64]')),
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,
    hash_full_path TEXT NOT NULL,
    PRIMARY KEY (arch, path)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS path_index ON registry_key (path);";

const CREATE_REGISTRY_VALUE_DB_STATEMENT: &str = "CREATE TABLE IF NOT EXISTS registry_data (
    path TEXT,
    arch TEXT CHECK (arch IN ('[x32]', '[x64]')),
    name TEXT NOT NULL,
    type INTEGER,
    size INTEGER,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,
    hash_full_path TEXT NOT NULL,
    PRIMARY KEY(path, arch, name)
    FOREIGN KEY (path) REFERENCES registry_key(path)
    FOREIGN KEY (arch) REFERENCES registry_key(arch)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS key_name_index ON registry_data (path, name);";

/// `RegistryTypes<WINDOWS>::typeText`
pub fn registry_type_text(t: u32) -> Option<&'static str> {
    Some(match t {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        12 => "REG_UNKNOWN",
        _ => return None,
    })
}

fn obj_mut<'a>(v: &'a mut Value, k: &str) -> Option<&'a mut BTreeMap<Vec<u8>, Value>> {
    match v {
        Value::Object(m) => match m.get_mut(k.as_bytes()) {
            Some(Value::Object(o)) => Some(o),
            _ => None,
        },
        _ => None,
    }
}

/// The `perm` string as JSON when it parses (`nlohmann::json::parse(perm, nullptr, false)`).
fn perm_to_json(attrs: &mut BTreeMap<Vec<u8>, Value>) {
    if let Some(Value::Str(p)) = attrs.get(&b"perm"[..]) {
        if let Ok(j) = siem_njson::parse(p) {
            attrs.insert(b"perm".to_vec(), j);
        }
    }
}

/// `fim_db_init`: the sync callbacks get (component, message).
#[allow(clippy::too_many_arguments)]
pub fn fim_db_init(
    storage: i32,
    sync_interval: u32,
    sync_max_interval: u32,
    sync_response_timeout: u32,
    sync_callback: Arc<dyn Fn(&str, &[u8]) + Send + Sync>,
    log: Arc<dyn Fn(LogLevel, &str) + Send + Sync>,
    file_limit: i32,
    value_limit: i32,
    sync_registry_enabled: bool,
    sync_thread_pool: i32,
    sync_queue_size: u32,
    error_log: Option<Arc<dyn Fn(&str) + Send + Sync>>,
) -> FimDbError {
    if let Some(e) = &error_log {
        let (e1, e2) = (e.clone(), e.clone());
        siem_dbsync::initialize(move |m: &[u8]| e1(&String::from_utf8_lossy(m)));
        siem_dbsync::rsync::initialize(move |m: &[u8]| e2(&String::from_utf8_lossy(m)));
    }
    let path = if storage == FIM_DB_MEMORY { FIM_DB_MEMORY_PATH } else { FIM_DB_DISK_PATH };
    let stmt = if cfg!(windows) {
        format!("{CREATE_FILE_DB_STATEMENT}{CREATE_REGISTRY_KEY_DB_STATEMENT}{CREATE_REGISTRY_VALUE_DB_STATEMENT}")
    } else {
        CREATE_FILE_DB_STATEMENT.to_string()
    };
    let db = match DBSync::new(HostType::Agent, DbEngineType::Sqlite3, path.as_bytes(), stmt.as_bytes(), DbManagement::Volatile, &[]) {
        Ok(d) => d,
        Err(e) => {
            log(LogLevel::Error, &format!("Error, id: {}", String::from_utf8_lossy(e.what())));
            return FimDbError::Err;
        }
    };
    let rsync = RemoteSync::new(sync_thread_pool as u32, sync_queue_size as usize);
    let (cb1, log1) = (sync_callback.clone(), log.clone());
    // callbackSyncFileWrapper
    let file_cb: SyncCallback = Arc::new(move |msg: &[u8]| {
        let Ok(mut j) = siem_njson::parse(msg) else { return };
        if j.at("type").ok().and_then(|t| t.get_string().ok()).as_deref() == Some(b"state") {
            if let Some(Value::Object(data)) = match &mut j {
                Value::Object(m) => m.get_mut(&b"data"[..]),
                _ => None,
            } {
                if let Some(Value::Object(attrs)) = data.get_mut(&b"attributes"[..]) {
                    perm_to_json(attrs);
                    attrs.insert(b"type".to_vec(), s(b"file"));
                    for k in ["dev", "last_event", "mode", "options", "path", "scanned"] {
                        attrs.remove(k.as_bytes());
                    }
                    if let Some(i) = attrs.get(&b"inode"[..]) {
                        if !matches!(i, Value::Str(_)) {
                            let d = i.dump().unwrap_or_default();
                            attrs.insert(b"inode".to_vec(), Value::Str(d));
                        }
                    }
                }
            }
            if let Some(f) = FIMDB.get() {
                f.set_time_last_sync_msg();
            }
        }
        match j.dump() {
            Ok(d) => cb1(FIM_COMPONENT_FILE, &d),
            Err(e) => log1(LogLevel::Error, &String::from_utf8_lossy(&e)),
        }
    });
    let (cb2, log2) = (sync_callback.clone(), log.clone());
    // callbackSyncRegistryWrapper
    let registry_cb: SyncCallback = Arc::new(move |msg: &[u8]| {
        let Ok(mut j) = siem_njson::parse(msg) else { return };
        let component = j.at("component").ok().and_then(|c| c.get_string().ok()).unwrap_or_default();
        if j.at("type").ok().and_then(|t| t.get_string().ok()).as_deref() == Some(b"state") {
            let Some(data) = obj_mut(&mut j, "data") else { return };
            let attrs = match data.get_mut(&b"attributes"[..]) {
                Some(Value::Object(a)) => a,
                _ => return,
            };
            if component == FIM_COMPONENT_REGISTRY_VALUE.as_bytes() {
                let t = attrs.get(&b"type"[..]).and_then(|t| t.get_u64().ok()).unwrap_or(0) as u32;
                let Some(text) = registry_type_text(t) else {
                    log2(LogLevel::Error, "map::at");
                    return;
                };
                attrs.insert(b"value_type".to_vec(), s(text.as_bytes()));
                attrs.insert(b"type".to_vec(), s(b"registry_value"));
                let name = attrs.remove(&b"name"[..]).unwrap_or(Value::Null);
                data.insert(b"value_name".to_vec(), name);
            } else {
                perm_to_json(attrs);
                attrs.insert(b"type".to_vec(), s(b"registry_key"));
            }
            let attrs = match data.get_mut(&b"attributes"[..]) {
                Some(Value::Object(a)) => a,
                _ => return,
            };
            let path = attrs.remove(&b"path"[..]).unwrap_or(Value::Null);
            let arch = attrs.remove(&b"arch"[..]).unwrap_or(Value::Null);
            for k in ["hash_full_path", "last_event", "scanned"] {
                attrs.remove(k.as_bytes());
            }
            data.insert(b"path".to_vec(), path);
            data.insert(b"arch".to_vec(), arch);
            data.insert(b"version".to_vec(), Value::Int(3));
            if let Some(f) = FIMDB.get() {
                f.set_time_last_sync_msg();
            }
        }
        match j.dump() {
            Ok(d) => cb2(&String::from_utf8_lossy(&component), &d),
            Err(e) => log2(LogLevel::Error, &String::from_utf8_lossy(&e)),
        }
    });
    // FIMDBCreator::setLimits
    let _ = db.set_table_max_row(FIMDB_FILE_TABLE_NAME.as_bytes(), file_limit as i64);
    if cfg!(windows) {
        let _ = db.set_table_max_row(FIMDB_REGISTRY_KEY_TABLENAME.as_bytes(), value_limit as i64);
        let _ = db.set_table_max_row(FIMDB_REGISTRY_VALUE_TABLENAME.as_bytes(), value_limit as i64);
    }
    let f = Arc::new(FimDb {
        dbsync: db,
        rsync,
        sync_interval,
        sync_max_interval,
        sync_response_timeout,
        sync_registry_enabled,
        file_cb,
        registry_cb,
        log,
        state: Mutex::new(SyncState { stopping: false, run_integrity: false, current_sync_interval: sync_interval, sync_successful: true, time_last_sync_msg: 0 }),
        cv: Condvar::new(),
    });
    let _ = FIMDB.set(f);
    FimDbError::Ok
}

impl FimDb {
    pub fn log(&self, l: LogLevel, m: &str) {
        (self.log)(l, m);
    }

    fn stopping(&self) -> bool {
        self.state.lock().map(|s| s.stopping).unwrap_or(true)
    }

    pub fn set_time_last_sync_msg(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.time_last_sync_msg = now();
        }
    }

    /// `FIMDB::registerRSync`
    fn register_rsync(&self) {
        let h = self.dbsync.handle();
        let r = (|| -> siem_dbsync::R {
            self.rsync.register_sync_id(FIM_COMPONENT_FILE.as_bytes(), h, &sync_config(FIMDB_FILE_TABLE_NAME, FIM_COMPONENT_FILE, "path"), self.file_cb.clone())?;
            if cfg!(windows) && self.sync_registry_enabled {
                self.rsync.register_sync_id(
                    FIM_COMPONENT_REGISTRY_KEY.as_bytes(),
                    h,
                    &sync_config(FIMDB_REGISTRY_KEY_TABLENAME, FIM_COMPONENT_REGISTRY_KEY, "hash_full_path"),
                    self.registry_cb.clone(),
                )?;
                self.rsync.register_sync_id(
                    FIM_COMPONENT_REGISTRY_VALUE.as_bytes(),
                    h,
                    &sync_config(FIMDB_REGISTRY_VALUE_TABLENAME, FIM_COMPONENT_REGISTRY_VALUE, "hash_full_path"),
                    self.registry_cb.clone(),
                )?;
            }
            Ok(())
        })();
        if let Err(e) = r {
            self.log(LogLevel::Error, &String::from_utf8_lossy(e.what()));
        }
    }

    /// `FIMDB::sync`
    fn sync(&self) {
        if self.stopping() {
            return;
        }
        self.log(LogLevel::Debug, "Executing FIM sync.");
        let h = self.dbsync.handle();
        let r = (|| -> siem_dbsync::R {
            self.rsync.start_sync(h, &start_config(FIMDB_FILE_TABLE_NAME, FIM_COMPONENT_FILE, "path"), self.file_cb.clone())?;
            if cfg!(windows) && self.sync_registry_enabled {
                self.rsync.start_sync(h, &start_config(FIMDB_REGISTRY_KEY_TABLENAME, FIM_COMPONENT_REGISTRY_KEY, "hash_full_path"), self.registry_cb.clone())?;
                self.rsync.start_sync(h, &start_config(FIMDB_REGISTRY_VALUE_TABLENAME, FIM_COMPONENT_REGISTRY_VALUE, "hash_full_path"), self.registry_cb.clone())?;
            }
            Ok(())
        })();
        match r {
            Ok(()) => self.log(LogLevel::Debug, "Finished FIM sync."),
            Err(e) => self.log(LogLevel::Error, &format!("Cannot sync database:{}", String::from_utf8_lossy(e.what()))),
        }
    }

    /// `FIMDB::syncAlgorithm`
    fn sync_algorithm(&self) {
        let run = {
            let Ok(mut st) = self.state.lock() else { return };
            if (now() - st.time_last_sync_msg) as u32 > self.sync_response_timeout {
                let mut m = None;
                if st.sync_successful && st.current_sync_interval > self.sync_interval {
                    st.current_sync_interval = self.sync_interval;
                    m = Some(format!("Previous sync was successful. Sync interval is reset to: '{}s'", st.current_sync_interval));
                }
                st.sync_successful = true;
                drop(st);
                if let Some(m) = m {
                    self.log(LogLevel::DebugVerbose, &m);
                }
                true
            } else {
                st.current_sync_interval = st.current_sync_interval.saturating_mul(2).min(self.sync_max_interval);
                let m = format!("Sync still in progress. Skipped next sync and increased interval to '{}s'", st.current_sync_interval);
                drop(st);
                self.log(LogLevel::DebugVerbose, &m);
                false
            }
        };
        if run {
            self.sync();
        }
    }

    /// `fim_run_integrity`: the sync thread (first sync before returning).
    pub fn run_integrity(self: &Arc<Self>) -> FimDbError {
        {
            let Ok(mut st) = self.state.lock() else { return FimDbError::Err };
            if st.run_integrity {
                drop(st);
                self.log(LogLevel::Error, "FIM integrity thread already running.");
                return FimDbError::Err;
            }
            st.run_integrity = true;
        }
        self.register_rsync();
        let me = Arc::clone(self);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let _ = std::thread::Builder::new().name("fim_integrity".into()).spawn(move || {
            me.log(LogLevel::Info, "FIM sync module started.");
            me.sync();
            let _ = tx.send(());
            loop {
                let Ok(st) = me.state.lock() else { return };
                let wait = Duration::from_secs(st.current_sync_interval as u64);
                let Ok((st, _)) = me.cv.wait_timeout_while(st, wait, |s| !s.stopping) else { return };
                if st.stopping {
                    return;
                }
                drop(st);
                me.sync_algorithm();
            }
        });
        let _ = rx.recv();
        FimDbError::Ok
    }

    /// `fim_sync_push_msg`
    pub fn push_message(&self, data: &[u8]) -> FimDbError {
        if self.stopping() {
            return FimDbError::Ok;
        }
        // Utils::replaceFirst(rawData, "dbsync ", "")
        let raw = match data.windows(7).position(|w| w == b"dbsync ") {
            Some(i) => [&data[..i], &data[i + 7..]].concat(),
            None => data.to_vec(),
        };
        if let Ok(mut st) = self.state.lock() {
            st.time_last_sync_msg = now();
            st.sync_successful = false;
        }
        if let Err(e) = self.rsync.push_message(&raw) {
            self.log(LogLevel::Error, &String::from_utf8_lossy(e.what()));
        }
        FimDbError::Ok
    }

    /// `DB::countEntries`
    pub fn count_entries(&self, table: &str, inode: bool) -> i32 {
        let col = if inode { "count(DISTINCT (inode || ',' || dev)) AS count" } else { "count(*) AS count" };
        let query = Query::builder().table(table).column_list(&[col]).row_filter("").order_by_opt("").distinct_opt(false);
        let count = Arc::new(Mutex::new(0i32));
        let c2 = count.clone();
        let mut cb = move |t: ReturnTypeCallback, j: &Value| -> siem_dbsync::R {
            if t == ReturnTypeCallback::Selected {
                if let Ok(v) = j.at("count").and_then(|v| v.get_i64_arith()) {
                    *c2.lock().unwrap() = v as i32;
                }
            }
            Ok(())
        };
        if let Err(e) = self.dbsync.select_rows(query.query(), &mut cb) {
            self.log(LogLevel::Error, &String::from_utf8_lossy(e.what()));
        }
        let v = *count.lock().unwrap();
        v
    }

    /// `fim_db_get_path`: Ok(None) when there is no (single) entry.
    pub fn get_path(&self, path: &[u8]) -> Result<Option<(Vec<u8>, FileData)>, ()> {
        let enc = encode_string(path);
        let query = Query::builder()
            .table(FIMDB_FILE_TABLE_NAME)
            .column_list(&[
                "path", "mode", "last_event", "scanned", "options", "checksum", "dev", "inode", "size", "perm", "attributes", "uid", "gid", "user_name", "group_name", "hash_md5", "hash_sha1",
                "hash_sha256", "mtime",
            ])
            .row_filter("WHERE path=?")
            .row_filter_bind_text(&String::from_utf8_lossy(&enc))
            .order_by_opt("path")
            .distinct_opt(false)
            .count_opt(100);
        let rows = Arc::new(Mutex::new(Vec::<Value>::new()));
        let r2 = rows.clone();
        let mut cb = move |t: ReturnTypeCallback, j: &Value| -> siem_dbsync::R {
            if t == ReturnTypeCallback::Selected {
                r2.lock().unwrap().push(j.clone());
            }
            Ok(())
        };
        if let Err(e) = self.dbsync.select_rows(query.query(), &mut cb) {
            self.log(LogLevel::Error, &String::from_utf8_lossy(e.what()));
            return Err(());
        }
        let rows = rows.lock().unwrap();
        if rows.len() == 1 {
            Ok(file_from_json(&rows[0]))
        } else {
            self.log(LogLevel::DebugVerbose, &format!("No entry found for {}", String::from_utf8_lossy(path)));
            Ok(None)
        }
    }

    /// `fim_db_remove_path`
    pub fn remove_path(&self, path: &[u8]) -> FimDbError {
        let enc = encode_string(path);
        let query = Query::builder().table(FIMDB_FILE_TABLE_NAME).delete_data(obj(vec![("path", s(&enc))])).delete_row_filter("");
        if self.stopping() {
            return FimDbError::Ok;
        }
        match self.dbsync.delete_rows(query.query()) {
            Ok(()) => FimDbError::Ok,
            Err(e) => {
                self.log(LogLevel::Error, &String::from_utf8_lossy(e.what()));
                FimDbError::Err
            }
        }
    }

    /// `DB::searchFile` by path pattern (`LIKE`) or inode/dev.
    pub fn search(&self, pattern: Option<&[u8]>, inode_dev: Option<(u64, u64)>) -> Result<Vec<Vec<u8>>, ()> {
        let mut b = Query::builder().table(FIMDB_FILE_TABLE_NAME).column_list(&["path"]);
        if let Some((ino, dev)) = inode_dev {
            b = b.row_filter("WHERE inode=? AND dev=?").row_filter_bind_int(ino as i64).row_filter_bind_int(dev as i64);
        } else if let Some(p) = pattern {
            b = b.row_filter("WHERE path LIKE ?").row_filter_bind_text(&String::from_utf8_lossy(&encode_string(p)));
        }
        let b = b.order_by_opt("path").distinct_opt(false);
        let out = Arc::new(Mutex::new(Vec::new()));
        let o2 = out.clone();
        let mut cb = move |t: ReturnTypeCallback, j: &Value| -> siem_dbsync::R {
            if t == ReturnTypeCallback::Selected {
                if let Ok(p) = j.at("path").and_then(|p| p.get_string()) {
                    o2.lock().unwrap().push(p);
                }
            }
            Ok(())
        };
        if let Err(e) = self.dbsync.select_rows(b.query(), &mut cb) {
            self.log(LogLevel::Error, &String::from_utf8_lossy(e.what()));
            return Err(());
        }
        let v = std::mem::take(&mut *out.lock().unwrap());
        Ok(v)
    }

    /// `FIMDB::updateItem`: `syncRow` with the event callback.
    pub fn update_item(&self, item: &Value, cb: &mut dyn FnMut(ReturnTypeCallback, &Value) -> siem_dbsync::R) -> Result<(), siem_dbsync::Error> {
        if self.stopping() {
            return Ok(());
        }
        self.dbsync.sync_row(item, cb)
    }

    /// `fim_db_transaction_start`
    pub fn transaction_start(&self, table: &str, cb: ResultCallback) -> Option<DBSyncTxn> {
        let tables = siem_njson::parse(table.as_bytes()).ok()?;
        match DBSyncTxn::new(self.dbsync.handle(), &tables, 0, QUEUE_SIZE, cb) {
            Ok(t) => Some(t),
            Err(e) => {
                self.log(LogLevel::Error, &String::from_utf8_lossy(e.what()));
                None
            }
        }
    }

    /// `fim_db_transaction_sync_row`
    pub fn transaction_sync_row(&self, txn: &DBSyncTxn, item: &Value) -> FimDbError {
        match txn.sync_txn_row(item) {
            Ok(()) => FimDbError::Ok,
            Err(e) => {
                self.log(LogLevel::Error, &String::from_utf8_lossy(e.what()));
                FimDbError::Err
            }
        }
    }

    /// `fim_db_transaction_deleted_rows` (closes the transaction).
    pub fn transaction_deleted_rows(&self, txn: DBSyncTxn, cb: &mut dyn FnMut(ReturnTypeCallback, &Value) -> siem_dbsync::R) -> FimDbError {
        let r = txn.get_deleted_rows(cb);
        drop(txn);
        if r.is_err() {
            FimDbError::Err
        } else {
            FimDbError::Ok
        }
    }

    /// `FIMDB::teardown`
    pub fn teardown(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.stopping = true;
        }
        self.cv.notify_all();
    }
}

/// `DB::createJsonEvent` (file events of `fim_db_file_update`).
pub fn create_json_event(file: &Value, result: &Value, modified: bool, mode: i32, options: i32) -> (Value, i32) {
    const MODES: [&str; 3] = ["scheduled", "realtime", "whodata"];
    let data = file.at("data").ok().and_then(|d| d.iter().first().map(|v| (*v).clone())).unwrap_or(Value::Null);
    let g = |k: &str| data.at(k).ok().cloned().unwrap_or(Value::Null);
    let ne = |k: &str| !matches!(data.at(k), Ok(Value::Str(x)) if x.is_empty());
    let event_type = if modified { 2 } else { 0 };
    let mut attrs = BTreeMap::new();
    let put = |m: &mut BTreeMap<Vec<u8>, Value>, k: &str, v: Value| {
        m.insert(k.as_bytes().to_vec(), v);
    };
    put(&mut attrs, "type", s(b"file"));
    if options & CHECK_SIZE != 0 {
        put(&mut attrs, "size", g("size"));
    }
    if options & CHECK_PERM != 0 {
        put(&mut attrs, "perm", g("perm"));
    }
    let has = |k: &str| data.contains(k) && ne(k);
    if has("uid") && options & CHECK_OWNER != 0 {
        put(&mut attrs, "uid", g("uid"));
    }
    if has("gid") && options & CHECK_GROUP != 0 {
        put(&mut attrs, "gid", g("gid"));
    }
    if ne("user_name") {
        put(&mut attrs, "user_name", g("user_name"));
    }
    if ne("group_name") {
        put(&mut attrs, "group_name", g("group_name"));
    }
    if options & CHECK_INODE != 0 {
        put(&mut attrs, "inode", g("inode"));
    }
    if options & CHECK_MTIME != 0 {
        put(&mut attrs, "mtime", g("mtime"));
    }
    if options & CHECK_MD5SUM != 0 {
        put(&mut attrs, "hash_md5", g("hash_md5"));
    }
    if options & CHECK_SHA1SUM != 0 {
        put(&mut attrs, "hash_sha1", g("hash_sha1"));
    }
    if options & CHECK_SHA256SUM != 0 {
        put(&mut attrs, "hash_sha256", g("hash_sha256"));
    }
    if ne("checksum") {
        put(&mut attrs, "checksum", g("checksum"));
    }
    if ne("attributes") && options & CHECK_ATTRS != 0 {
        put(&mut attrs, "attributes", g("attributes"));
    }
    let mut d = BTreeMap::new();
    put(&mut d, "path", g("path"));
    put(&mut d, "version", s(b"2.0"));
    put(&mut d, "mode", s(MODES[mode as usize % 3].as_bytes()));
    put(&mut d, "type", s(if modified { b"modified" } else { b"added" }));
    put(&mut d, "attributes", Value::Object(attrs));
    let ts = if result.contains("last_event") { result.at("last_event").ok().cloned().unwrap_or(Value::Null) } else { g("last_event") };
    put(&mut d, "timestamp", ts);
    if result.contains("old") {
        let old = result.at("old").ok().cloned().unwrap_or(Value::Null);
        let mut oa = BTreeMap::new();
        let mut changed = Vec::new();
        put(&mut oa, "type", s(b"file"));
        let mut field = |oa: &mut BTreeMap<Vec<u8>, Value>, on: bool, k: &str, label: Option<&str>| {
            if !on {
                return;
            }
            if old.contains(k) {
                oa.insert(k.as_bytes().to_vec(), old.at(k).ok().cloned().unwrap_or(Value::Null));
                if let Some(l) = label {
                    changed.push(s(l.as_bytes()));
                }
            } else {
                oa.insert(k.as_bytes().to_vec(), g(k));
            }
        };
        field(&mut oa, options & CHECK_SIZE != 0, "size", Some("size"));
        field(&mut oa, options & CHECK_PERM != 0, "perm", Some("permission"));
        field(&mut oa, has("uid") && options & CHECK_OWNER != 0, "uid", Some("uid"));
        field(&mut oa, has("gid") && options & CHECK_GROUP != 0, "gid", Some("gid"));
        field(&mut oa, ne("user_name"), "user_name", Some("user_name"));
        field(&mut oa, ne("group_name"), "group_name", Some("group_name"));
        field(&mut oa, options & CHECK_INODE != 0, "inode", Some("inode"));
        field(&mut oa, options & CHECK_MTIME != 0, "mtime", Some("mtime"));
        field(&mut oa, options & CHECK_MD5SUM != 0, "hash_md5", Some("md5"));
        field(&mut oa, options & CHECK_SHA1SUM != 0, "hash_sha1", Some("sha1"));
        field(&mut oa, options & CHECK_SHA256SUM != 0, "hash_sha256", Some("sha256"));
        field(&mut oa, ne("attributes") && options & CHECK_ATTRS != 0, "attributes", Some("attributes"));
        field(&mut oa, ne("checksum"), "checksum", None);
        put(&mut d, "old_attributes", Value::Object(oa));
        put(&mut d, "changed_attributes", Value::Array(changed));
    }
    let mut ev = BTreeMap::new();
    put(&mut ev, "type", s(b"event"));
    put(&mut ev, "data", Value::Object(d));
    (Value::Object(ev), event_type)
}
