//! `Syscollector` (syscollectorImp.cpp, syscollector.cpp): scans the system
//! through the data provider, keeps the inventory in dbsync, reports the
//! row changes ("deltas") and answers the manager's integrity sync through
//! rsync.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};
use sha1::{Digest, Sha1};
use siem_dbsync::rsync::{RemoteSync, SyncCallback};
use siem_dbsync::{DBSync, DBSyncTxn, DbEngineType, DbManagement, HostType, ReturnTypeCallback, UNLIMITED_QUEUE_SIZE};
use siem_njson::Value;

use super::normalizer::SysNormalizer;
use super::tables_def::*;

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

/// A C++ exception from the data provider (`what()`).
pub type ProviderError = String;

/// `ISysInfo`: what the module reads.
pub trait SysInfoSource: Send + Sync {
    fn hardware(&self) -> Result<Value, ProviderError>;
    fn os(&self) -> Result<Value, ProviderError>;
    fn networks(&self) -> Result<Value, ProviderError>;
    fn ports(&self) -> Result<Value, ProviderError>;
    fn hotfixes(&self) -> Result<Value, ProviderError>;
    fn groups(&self) -> Result<Value, ProviderError>;
    fn users(&self) -> Result<Value, ProviderError>;
    fn services(&self) -> Result<Value, ProviderError>;
    fn browser_extensions(&self) -> Result<Value, ProviderError>;
    /// `packages(callback)`: Err from the callback is an exception it threw.
    fn packages(&self, cb: &mut dyn FnMut(Value) -> Result<(), ProviderError>) -> Result<(), ProviderError>;
    fn processes(&self, cb: &mut dyn FnMut(Value) -> Result<(), ProviderError>) -> Result<(), ProviderError>;
}

#[cfg(windows)]
impl SysInfoSource for siem_sysinfo::SysInfo {
    fn hardware(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::hardware(self).map_err(|e| e.0)
    }
    fn os(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::os(self).map_err(|e| e.0)
    }
    fn networks(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::networks(self).map_err(|e| e.0)
    }
    fn ports(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::ports(self).map_err(|e| e.0)
    }
    fn hotfixes(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::hotfixes(self).map_err(|e| e.0)
    }
    fn groups(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::groups(self).map_err(|e| e.0)
    }
    fn users(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::users(self).map_err(|e| e.0)
    }
    fn services(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::services(self).map_err(|e| e.0)
    }
    fn browser_extensions(&self) -> Result<Value, ProviderError> {
        siem_sysinfo::SysInfo::browser_extensions(self).map_err(|e| e.0)
    }
    fn packages(&self, cb: &mut dyn FnMut(Value) -> Result<(), ProviderError>) -> Result<(), ProviderError> {
        self.packages_cb(cb).map_err(|e| e.0)
    }
    fn processes(&self, cb: &mut dyn FnMut(Value) -> Result<(), ProviderError>) -> Result<(), ProviderError> {
        self.processes_cb(|v| cb(v).map_err(siem_sysinfo::win::Error)).map_err(|e| e.0)
    }
}

pub type ReportFn = Arc<dyn Fn(&[u8]) + Send + Sync>;
pub type LogFn = Arc<dyn Fn(LogLevel, &str) + Send + Sync>;

/// `QUEUE_SIZE`
const QUEUE_SIZE: u32 = 4096;

fn op_name(r: ReturnTypeCallback) -> &'static str {
    match r {
        ReturnTypeCallback::Modified => "MODIFIED",
        ReturnTypeCallback::Deleted => "DELETED",
        ReturnTypeCallback::Inserted => "INSERTED",
        ReturnTypeCallback::MaxRows => "MAX_ROWS",
        ReturnTypeCallback::DbError => "DB_ERROR",
        ReturnTypeCallback::Selected => "SELECTED",
        // OPERATION_MAP.at(): std::out_of_range
        ReturnTypeCallback::Generic => "",
    }
}

fn what(e: &siem_dbsync::Error) -> String {
    String::from_utf8_lossy(e.what()).into_owned()
}

fn jerr(e: Vec<u8>) -> String {
    String::from_utf8_lossy(&e).into_owned()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn dump(v: &Value) -> Result<Vec<u8>, String> {
    v.dump().map_err(jerr)
}

/// `getItemId(item, idFields)`: SHA-1 of the fields' text.
fn get_item_id(item: &Value, fields: &[&str]) -> Result<String, String> {
    let mut h = Sha1::new();
    for f in fields {
        let v = item.at_b(f.as_bytes()).map_err(jerr)?;
        match v {
            Value::Str(b) => h.update(b),
            // get<unsigned long>() (32 bits in the agent), to_string
            other => h.update((other.get_i64_arith().map_err(jerr)? as u32).to_string().as_bytes()),
        }
    }
    Ok(hex(&h.finalize()))
}

/// `getItemChecksum(item)`: SHA-1 of `item.dump()`.
fn get_item_checksum(item: &Value) -> Result<String, String> {
    Ok(hex(&Sha1::digest(dump(item)?)))
}

/// `removeKeysWithEmptyValue`
fn remove_keys_with_empty_value(v: &mut Value) {
    let strip = |o: &mut Value| {
        if let Value::Object(m) = o {
            m.retain(|_, x| !matches!(x, Value::Str(s) if s.is_empty()));
        }
    };
    match v {
        Value::Array(a) => a.iter_mut().for_each(strip),
        Value::Object(_) => strip(v),
        _ => {}
    }
}

/// `sanitizeJsonValue`: trims the spaces of every string but " ".
fn sanitize_json_value(v: &mut Value) {
    match v {
        Value::Object(m) => m.values_mut().for_each(sanitize_json_value),
        Value::Array(a) => a.iter_mut().for_each(sanitize_json_value),
        Value::Str(s) => {
            if s.as_slice() != b" " {
                let end = s.iter().rposition(|&c| c != b' ').map(|p| p + 1).unwrap_or(0);
                s.truncate(end);
                let start = s.iter().position(|&c| c != b' ').unwrap_or(s.len());
                s.drain(..start);
            }
        }
        _ => {}
    }
}

/// `isElementDuplicated(input, {key, value})`
fn is_element_duplicated(input: &Value, key: &str, value: &str) -> Result<bool, String> {
    for e in input.iter() {
        if e.at_b(key.as_bytes()).map_err(jerr)? == &Value::Str(value.as_bytes().to_vec()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn set(v: &mut Value, k: &str, x: Value) -> Result<(), String> {
    v.set(k.as_bytes(), x).map_err(jerr)
}

fn at(v: &Value, k: &str) -> Result<Value, String> {
    v.at_b(k.as_bytes()).cloned().map_err(jerr)
}

/// `Utils::getCurrentTimestamp()` ("YYYY/MM/DD hh:mm:ss", UTC)
pub fn current_timestamp() -> String {
    chrono::Utc::now().format("%Y/%m/%d %H:%M:%S").to_string()
}

fn parse(text: &str) -> Value {
    siem_njson::parse(text.as_bytes()).unwrap_or(Value::Null)
}

/// The scan and sync options (`init`'s arguments).
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub interval: u32,
    pub scan_on_start: bool,
    pub hardware: bool,
    pub os: bool,
    pub network: bool,
    pub packages: bool,
    pub ports: bool,
    pub ports_all: bool,
    pub processes: bool,
    pub hotfixes: bool,
    pub groups: bool,
    pub users: bool,
    pub services: bool,
    pub browser_extensions: bool,
    pub notify_on_first_scan: bool,
}

struct State {
    stopping: bool,
    rsync: Option<RemoteSync>,
}

/// `Syscollector` (the module's singleton).
pub struct Syscollector {
    mutex: Mutex<State>,
    cv: Condvar,
}

/// What a scan works with (the members set by `init`).
struct Ctx {
    info: Arc<dyn SysInfoSource>,
    report_diff: ReportFn,
    report_sync: ReportFn,
    log: LogFn,
    o: Options,
    db: DBSync,
    normalizer: SysNormalizer,
    notify: std::sync::atomic::AtomicBool,
    scan_time: Mutex<String>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

static INSTANCE: std::sync::OnceLock<Syscollector> = std::sync::OnceLock::new();

impl Syscollector {
    /// `Syscollector::instance()`
    pub fn instance() -> &'static Syscollector {
        INSTANCE.get_or_init(|| Syscollector { mutex: Mutex::new(State { stopping: true, rsync: None }), cv: Condvar::new() })
    }

    /// `getCreateStatement()`
    pub fn create_statement() -> String {
        [
            OS_SQL_STATEMENT,
            HW_SQL_STATEMENT,
            PACKAGES_SQL_STATEMENT,
            HOTFIXES_SQL_STATEMENT,
            PROCESSES_SQL_STATEMENT,
            PORTS_SQL_STATEMENT,
            NETIFACE_SQL_STATEMENT,
            NETPROTO_SQL_STATEMENT,
            NETADDR_SQL_STATEMENT,
            GROUPS_SQL_STATEMENT,
            USERS_SQL_STATEMENT,
            SERVICES_SQL_STATEMENT,
            BROWSER_EXTENSIONS_SQL_STATEMENT,
        ]
        .concat()
    }

    /// `init(...)`: runs the scan loop until `destroy`. Err is an exception
    /// out of the DBSync / RemoteSync construction.
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        &self,
        info: Arc<dyn SysInfoSource>,
        report_diff: ReportFn,
        report_sync: ReportFn,
        log: LogFn,
        db_path: &str,
        normalizer_config_path: &str,
        normalizer_type: &str,
        o: Options,
    ) -> Result<(), String> {
        let db = DBSync::new(HostType::Agent, DbEngineType::Sqlite3, db_path.as_bytes(), Self::create_statement().as_bytes(), DbManagement::Volatile, &[])
            .map_err(|e| what(&e))?;
        let rsync = RemoteSync::new(std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1), UNLIMITED_QUEUE_SIZE);
        let normalizer = SysNormalizer::new(normalizer_config_path, normalizer_type);
        let mut st = self.mutex.lock();
        st.stopping = false;
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ctx = Arc::new(Ctx {
            info,
            report_diff,
            report_sync,
            log,
            notify: std::sync::atomic::AtomicBool::new(o.notify_on_first_scan),
            o,
            db,
            normalizer,
            scan_time: Mutex::new(String::new()),
            stopping: stopping.clone(),
        });
        Self::register_with_rsync(&ctx, &rsync);
        st.rsync = Some(rsync);
        self.sync_loop(&ctx, &mut st);
        Ok(())
    }

    /// `destroy()`
    pub fn destroy(&self) {
        let mut st = self.mutex.lock();
        st.stopping = true;
        self.cv.notify_all();
    }

    /// `push(data)`: a manager sync message ("dbsync " removed).
    pub fn push(&self, data: &str) -> Result<(), String> {
        let st = self.mutex.lock();
        if !st.stopping {
            let raw = data.replacen("dbsync ", "", 1);
            if let Some(r) = &st.rsync {
                r.push_message(raw.as_bytes()).map_err(|e| what(&e))?;
            }
        }
        Ok(())
    }

    /// `registerWithRsync()`
    fn register_with_rsync(ctx: &Arc<Ctx>, rsync: &RemoteSync) {
        let c = ctx.clone();
        let wrapper: SyncCallback = Arc::new(move |data: &[u8]| {
            let text = String::from_utf8_lossy(data).into_owned();
            let Ok(mut j) = siem_njson::parse(data) else { return };
            if c.stopping.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let sent = match j.find(b"data").and_then(|d| d.find(b"attributes")).cloned() {
                Some(mut attrs) => {
                    remove_keys_with_empty_value(&mut attrs);
                    let _ = attrs.set(b"scan_time", Value::Str(current_timestamp().into_bytes()));
                    if let Ok(d) = j.index_mut(b"data") {
                        let _ = d.set(b"attributes", attrs);
                    }
                    String::from_utf8_lossy(&j.dump().unwrap_or_default()).into_owned()
                }
                None => text,
            };
            (c.report_sync)(sent.as_bytes());
            (c.log)(LogLevel::DebugVerbose, &format!("Sync sent: {sent}"));
        });
        let o = &ctx.o;
        let h = ctx.db.handle();
        let reg = |id: &str, cfg: &str| {
            let _ = rsync.register_sync_id(id.as_bytes(), h, &parse(cfg), wrapper.clone());
        };
        if o.os {
            reg("syscollector_osinfo", OS_SYNC_CONFIG_STATEMENT);
        }
        if o.hardware {
            reg("syscollector_hwinfo", HW_SYNC_CONFIG_STATEMENT);
        }
        if o.processes {
            reg("syscollector_processes", PROCESSES_SYNC_CONFIG_STATEMENT);
        }
        if o.packages {
            reg("syscollector_packages", PACKAGES_SYNC_CONFIG_STATEMENT);
        }
        if o.hotfixes {
            reg("syscollector_hotfixes", HOTFIXES_SYNC_CONFIG_STATEMENT);
        }
        if o.ports {
            reg("syscollector_ports", PORTS_SYNC_CONFIG_STATEMENT);
        }
        if o.network {
            reg("syscollector_network_iface", NETIFACE_SYNC_CONFIG_STATEMENT);
            reg("syscollector_network_protocol", NETPROTO_SYNC_CONFIG_STATEMENT);
            reg("syscollector_network_address", NETADDRESS_SYNC_CONFIG_STATEMENT);
        }
        if o.groups {
            reg("syscollector_groups", GROUPS_SYNC_CONFIG_STATEMENT);
        }
        if o.users {
            reg("syscollector_users", USERS_SYNC_CONFIG_STATEMENT);
        }
        if o.services {
            reg("syscollector_services", SERVICES_SYNC_CONFIG_STATEMENT);
        }
        if o.browser_extensions {
            reg("syscollector_browser_extensions", BROWSER_EXTENSIONS_SYNC_CONFIG_STATEMENT);
        }
    }

    /// `syncLoop(lock)`
    fn sync_loop(&self, ctx: &Arc<Ctx>, st: &mut parking_lot::MutexGuard<'_, State>) {
        (ctx.log)(LogLevel::Info, "Module started.");
        if ctx.o.scan_on_start {
            scan(ctx);
            sync(ctx, st.rsync.as_ref());
        }
        loop {
            let timeout = Duration::from_secs(ctx.o.interval as u64);
            let deadline = std::time::Instant::now() + timeout;
            while !st.stopping {
                if self.cv.wait_until(st, deadline).timed_out() {
                    break;
                }
            }
            if st.stopping {
                break;
            }
            scan(ctx);
            sync(ctx, st.rsync.as_ref());
        }
        ctx.stopping.store(true, std::sync::atomic::Ordering::SeqCst);
        st.rsync = None;
        self.cv.notify_all();
    }
}

impl Ctx {
    fn stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `notifyChange(result, data, table)`
    fn notify_change(&self, result: ReturnTypeCallback, data: &Value, table: &str) -> Result<(), String> {
        if result == ReturnTypeCallback::DbError {
            (self.log)(LogLevel::Error, &String::from_utf8_lossy(&dump(data)?));
        } else if self.notify.load(std::sync::atomic::Ordering::SeqCst) && !self.stopping() {
            let items: Vec<&Value> = if data.is_array() { data.iter() } else { vec![data] };
            for item in items {
                let mut msg = Value::Null;
                set(&mut msg, "type", Value::Str(table.as_bytes().to_vec()))?;
                set(&mut msg, "operation", Value::Str(op_name(result).as_bytes().to_vec()))?;
                set(&mut msg, "data", item.clone())?;
                let d = msg.index_mut(b"data").map_err(jerr)?;
                d.set(b"scan_time", Value::Str(self.scan_time.lock().clone().into_bytes())).map_err(jerr)?;
                remove_keys_with_empty_value(d);
                let m = dump(&msg)?;
                (self.report_diff)(&m);
                (self.log)(LogLevel::DebugVerbose, &format!("Delta sent: {}", String::from_utf8_lossy(&m)));
            }
        }
        Ok(())
    }

    fn txn(self: &Arc<Self>, table: &'static str) -> Result<DBSyncTxn, String> {
        let c = self.clone();
        let cb: siem_dbsync::ResultCallback = Arc::new(move |r, d| c.notify_change(r, d, table).map_err(siem_dbsync::Error::std));
        DBSyncTxn::new(self.db.handle(), &Value::Array(vec![Value::Str(table.as_bytes().to_vec())]), 0, QUEUE_SIZE, cb).map_err(|e| what(&e))
    }

    fn deleted(self: &Arc<Self>, txn: &DBSyncTxn, table: &'static str) -> Result<(), String> {
        let c = self.clone();
        let mut cb = move |r: ReturnTypeCallback, d: &Value| c.notify_change(r, d, table).map_err(siem_dbsync::Error::std);
        txn.get_deleted_rows(&mut cb).map_err(|e| what(&e))
    }

    /// `updateChanges(table, values)`
    fn update_changes(self: &Arc<Self>, table: &'static str, values: Value) -> Result<(), String> {
        let txn = self.txn(table)?;
        let mut input = Value::Null;
        set(&mut input, "table", Value::Str(table.as_bytes().to_vec()))?;
        set(&mut input, "data", values)?;
        txn.sync_txn_row(&input).map_err(|e| what(&e))?;
        self.deleted(&txn, table)
    }

    fn scan_hardware(self: &Arc<Self>) -> Result<(), String> {
        if self.o.hardware {
            (self.log)(LogLevel::DebugVerbose, "Starting hardware scan");
            let mut hw = self.info.hardware()?;
            sanitize_json_value(&mut hw);
            let ck = get_item_checksum(&hw)?;
            set(&mut hw, "checksum", Value::Str(ck.into_bytes()))?;
            self.update_changes(HW_TABLE, Value::Array(vec![hw]))?;
            (self.log)(LogLevel::DebugVerbose, "Ending hardware scan");
        }
        Ok(())
    }

    fn scan_os(self: &Arc<Self>) -> Result<(), String> {
        if self.o.os {
            (self.log)(LogLevel::DebugVerbose, "Starting os scan");
            let mut os = self.info.os()?;
            sanitize_json_value(&mut os);
            // std::to_string(system_clock::now().time_since_epoch().count()) (ns)
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            set(&mut os, "checksum", Value::Str(now.to_string().into_bytes()))?;
            self.update_changes(OS_TABLE, Value::Array(vec![os]))?;
            (self.log)(LogLevel::DebugVerbose, "Ending os scan");
        }
        Ok(())
    }

    /// `getNetworkData()`
    fn network_data(&self) -> Result<Value, String> {
        let mut ret = Value::Null;
        let mut networks = self.info.networks()?;
        if !networks.is_null() {
            sanitize_json_value(&mut networks);
            if let Some(ifaces) = networks.find(b"iface") {
                let (mut iface_list, mut proto_list, mut addr_list) = (Value::Null, Value::Null, Value::Null);
                for item in ifaces.iter() {
                    let mut it = Value::Null;
                    for k in ["name", "adapter", "type", "state", "mtu", "mac", "tx_packets", "rx_packets", "tx_errors", "rx_errors", "tx_bytes", "rx_bytes", "tx_dropped", "rx_dropped"] {
                        set(&mut it, k, at(item, k)?)?;
                    }
                    let ck = get_item_checksum(&it)?;
                    set(&mut it, "checksum", Value::Str(ck.into_bytes()))?;
                    let id = get_item_id(&it, NETIFACE_ITEM_ID_FIELDS)?;
                    set(&mut it, "item_id", Value::Str(id.into_bytes()))?;
                    iface_list.push_back(it).map_err(jerr)?;
                    for (fam, ty, proto) in [("IPv4", "ipv4", 0i64), ("IPv6", "ipv6", 1i64)] {
                        let Some(addrs) = item.find(fam.as_bytes()) else { continue };
                        let first = addrs.iter().first().cloned().cloned().ok_or_else(|| "[json.exception.invalid_iterator.214] cannot get value".to_string())?;
                        let mut p = Value::Null;
                        set(&mut p, "iface", at(item, "name")?)?;
                        set(&mut p, "gateway", at(item, "gateway")?)?;
                        set(&mut p, "type", Value::Str(ty.as_bytes().to_vec()))?;
                        set(&mut p, "dhcp", at(&first, "dhcp")?)?;
                        set(&mut p, "metric", at(&first, "metric")?)?;
                        let ck = get_item_checksum(&p)?;
                        set(&mut p, "checksum", Value::Str(ck.into_bytes()))?;
                        let id = get_item_id(&p, NETPROTO_ITEM_ID_FIELDS)?;
                        set(&mut p, "item_id", Value::Str(id.into_bytes()))?;
                        proto_list.push_back(p).map_err(jerr)?;
                        for a in addrs.iter() {
                            let mut a = a.clone();
                            set(&mut a, "iface", at(item, "name")?)?;
                            set(&mut a, "proto", Value::Int(proto))?;
                            let ck = get_item_checksum(&a)?;
                            set(&mut a, "checksum", Value::Str(ck.into_bytes()))?;
                            let id = get_item_id(&a, NETADDRESS_ITEM_ID_FIELDS)?;
                            set(&mut a, "item_id", Value::Str(id.into_bytes()))?;
                            if let Value::Object(m) = &mut a {
                                m.remove(b"dhcp".as_slice());
                                m.remove(b"metric".as_slice());
                            }
                            addr_list.push_back(a).map_err(jerr)?;
                        }
                    }
                }
                set(&mut ret, NET_IFACE_TABLE, iface_list)?;
                set(&mut ret, NET_PROTOCOL_TABLE, proto_list)?;
                set(&mut ret, NET_ADDRESS_TABLE, addr_list)?;
            }
        }
        Ok(ret)
    }

    fn scan_network(self: &Arc<Self>) -> Result<(), String> {
        if self.o.network {
            (self.log)(LogLevel::DebugVerbose, "Starting network scan");
            let data = self.network_data()?;
            if !data.is_null() {
                for t in [NET_IFACE_TABLE, NET_PROTOCOL_TABLE, NET_ADDRESS_TABLE] {
                    if let Some(v) = data.find(t.as_bytes()) {
                        self.update_changes(t, v.clone())?;
                    }
                }
            }
            (self.log)(LogLevel::DebugVerbose, "Ending network scan");
        }
        Ok(())
    }

    fn scan_packages(self: &Arc<Self>) -> Result<(), String> {
        if self.o.packages {
            (self.log)(LogLevel::DebugVerbose, "Starting packages scan");
            let txn = self.txn(PACKAGES_TABLE)?;
            let mut cb = |mut raw: Value| -> Result<(), String> {
                sanitize_json_value(&mut raw);
                let ck = get_item_checksum(&raw)?;
                set(&mut raw, "checksum", Value::Str(ck.into_bytes()))?;
                let id = get_item_id(&raw, PACKAGES_ITEM_ID_FIELDS)?;
                set(&mut raw, "item_id", Value::Str(id.into_bytes()))?;
                self.normalizer.normalize("packages", &mut raw);
                self.normalizer.remove_excluded("packages", &mut raw);
                if !raw.empty() {
                    let mut input = Value::Null;
                    set(&mut input, "table", Value::Str(PACKAGES_TABLE.as_bytes().to_vec()))?;
                    set(&mut input, "data", Value::Array(vec![raw]))?;
                    txn.sync_txn_row(&input).map_err(|e| what(&e))?;
                }
                Ok(())
            };
            self.info.packages(&mut cb)?;
            self.deleted(&txn, PACKAGES_TABLE)?;
            (self.log)(LogLevel::DebugVerbose, "Ending packages scan");
        }
        Ok(())
    }

    fn scan_hotfixes(self: &Arc<Self>) -> Result<(), String> {
        if self.o.hotfixes {
            (self.log)(LogLevel::DebugVerbose, "Starting hotfixes scan");
            let mut h = self.info.hotfixes()?;
            if !h.is_null() {
                sanitize_json_value(&mut h);
                if let Value::Array(a) = &mut h {
                    for x in a.iter_mut() {
                        let ck = get_item_checksum(x)?;
                        set(x, "checksum", Value::Str(ck.into_bytes()))?;
                    }
                }
                self.update_changes(HOTFIXES_TABLE, h)?;
            }
            (self.log)(LogLevel::DebugVerbose, "Ending hotfixes scan");
        }
        Ok(())
    }

    /// `getPortsData()`
    fn ports_data(&self) -> Result<Value, String> {
        let mut ret = Value::Null;
        let mut data = self.info.ports()?;
        if !data.is_null() {
            sanitize_json_value(&mut data);
            for item in data.iter() {
                let mut item = item.clone();
                let proto = String::from_utf8_lossy(item.at_b(b"protocol").map_err(jerr)?.get_ref_str().map_err(jerr)?).into_owned();
                let keep = if proto.starts_with("tcp") {
                    self.o.ports_all || item.at_b(b"state").map_err(jerr)? == &Value::Str(b"listening".to_vec())
                } else {
                    proto.starts_with("udp")
                };
                if keep {
                    let id = get_item_id(&item, PORTS_ITEM_ID_FIELDS)?;
                    if !is_element_duplicated(&ret, "item_id", &id)? {
                        let ck = get_item_checksum(&item)?;
                        set(&mut item, "checksum", Value::Str(ck.into_bytes()))?;
                        set(&mut item, "item_id", Value::Str(id.into_bytes()))?;
                        ret.push_back(item).map_err(jerr)?;
                    }
                }
            }
        }
        Ok(ret)
    }

    fn scan_ports(self: &Arc<Self>) -> Result<(), String> {
        if self.o.ports {
            (self.log)(LogLevel::DebugVerbose, "Starting ports scan");
            let d = self.ports_data()?;
            self.update_changes(PORTS_TABLE, d)?;
            (self.log)(LogLevel::DebugVerbose, "Ending ports scan");
        }
        Ok(())
    }

    fn scan_processes(self: &Arc<Self>) -> Result<(), String> {
        if self.o.processes {
            (self.log)(LogLevel::DebugVerbose, "Starting processes scan");
            let txn = self.txn(PROCESSES_TABLE)?;
            let mut cb = |mut raw: Value| -> Result<(), String> {
                sanitize_json_value(&mut raw);
                let ck = get_item_checksum(&raw)?;
                set(&mut raw, "checksum", Value::Str(ck.into_bytes()))?;
                let mut input = Value::Null;
                set(&mut input, "table", Value::Str(PROCESSES_TABLE.as_bytes().to_vec()))?;
                set(&mut input, "data", Value::Array(vec![raw]))?;
                txn.sync_txn_row(&input).map_err(|e| what(&e))
            };
            self.info.processes(&mut cb)?;
            self.deleted(&txn, PROCESSES_TABLE)?;
            (self.log)(LogLevel::DebugVerbose, "Ending processes scan");
        }
        Ok(())
    }

    /// The groups / users / services / browser extensions lists: each item
    /// sanitized, checksummed (and given an item id).
    fn list(&self, v: Value, id_fields: Option<&[&str]>) -> Result<Value, String> {
        let mut ret = Value::Null;
        if !v.is_null() {
            for item in v.iter() {
                let mut item = item.clone();
                sanitize_json_value(&mut item);
                let ck = get_item_checksum(&item)?;
                set(&mut item, "checksum", Value::Str(ck.into_bytes()))?;
                if let Some(f) = id_fields {
                    let id = get_item_id(&item, f)?;
                    set(&mut item, "item_id", Value::Str(id.into_bytes()))?;
                }
                ret.push_back(item).map_err(jerr)?;
            }
        }
        Ok(ret)
    }

    fn scan_list(self: &Arc<Self>, enabled: bool, what: &str, table: &'static str, get: impl Fn(&Self) -> Result<Value, String>, ids: Option<&[&str]>) -> Result<(), String> {
        if enabled {
            (self.log)(LogLevel::DebugVerbose, &format!("Starting {what} scan"));
            let v = get(self)?;
            let d = self.list(v, ids)?;
            self.update_changes(table, d)?;
            (self.log)(LogLevel::DebugVerbose, &format!("Ending {what} scan"));
        }
        Ok(())
    }
}

/// `TRY_CATCH_TASK(task)`
fn task(ctx: &Arc<Ctx>, f: impl FnOnce() -> Result<(), String>) {
    if !ctx.stopping() {
        if let Err(e) = f() {
            (ctx.log)(LogLevel::Error, &e);
        }
    }
}

/// `scan()`
fn scan(ctx: &Arc<Ctx>) {
    (ctx.log)(LogLevel::Info, "Starting evaluation.");
    *ctx.scan_time.lock() = current_timestamp();
    task(ctx, || ctx.scan_hardware());
    task(ctx, || ctx.scan_os());
    task(ctx, || ctx.scan_network());
    task(ctx, || ctx.scan_packages());
    task(ctx, || ctx.scan_hotfixes());
    task(ctx, || ctx.scan_ports());
    task(ctx, || ctx.scan_processes());
    task(ctx, || ctx.scan_list(ctx.o.groups, "groups", GROUPS_TABLE, |c| c.info.groups(), None));
    task(ctx, || ctx.scan_list(ctx.o.users, "users", USERS_TABLE, |c| c.info.users(), None));
    task(ctx, || ctx.scan_list(ctx.o.services, "services", SERVICES_TABLE, |c| c.info.services(), Some(SERVICES_ITEM_ID_FIELDS)));
    task(ctx, || {
        ctx.scan_list(ctx.o.browser_extensions, "browser extensions", BROWSER_EXTENSIONS_TABLE, |c| c.info.browser_extensions(), Some(BROWSER_EXTENSIONS_ITEM_ID_FIELDS))
    });
    ctx.notify.store(true, std::sync::atomic::Ordering::SeqCst);
    (ctx.log)(LogLevel::Info, "Evaluation finished.");
}

/// `sync()`
fn sync(ctx: &Arc<Ctx>, rsync: Option<&RemoteSync>) {
    let Some(rsync) = rsync else { return };
    (ctx.log)(LogLevel::Debug, "Starting syscollector sync");
    let h = ctx.db.handle();
    let rf = ctx.report_sync.clone();
    let report: SyncCallback = Arc::new(move |d: &[u8]| rf(d));
    let start = |cfg: &str| -> Result<(), String> { rsync.start_sync(h, &parse(cfg), report.clone()).map_err(|e| what(&e)) };
    task(ctx, || start(HW_START_CONFIG_STATEMENT));
    task(ctx, || start(OS_START_CONFIG_STATEMENT));
    task(ctx, || {
        start(NETIFACE_START_CONFIG_STATEMENT)?;
        start(NETPROTO_START_CONFIG_STATEMENT)?;
        start(NETADDRESS_START_CONFIG_STATEMENT)
    });
    task(ctx, || start(PACKAGES_START_CONFIG_STATEMENT));
    task(ctx, || start(HOTFIXES_START_CONFIG_STATEMENT));
    task(ctx, || start(PORTS_START_CONFIG_STATEMENT));
    task(ctx, || start(PROCESSES_START_CONFIG_STATEMENT));
    task(ctx, || start(GROUPS_START_CONFIG_STATEMENT));
    task(ctx, || start(USERS_START_CONFIG_STATEMENT));
    task(ctx, || start(SERVICES_START_CONFIG_STATEMENT));
    task(ctx, || start(BROWSER_EXTENSIONS_START_CONFIG_STATEMENT));
    (ctx.log)(LogLevel::Debug, "Ending syscollector sync");
}
