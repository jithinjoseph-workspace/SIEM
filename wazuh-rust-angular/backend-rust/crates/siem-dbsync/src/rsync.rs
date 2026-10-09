//! `shared_modules/rsync`: the agent side of the integrity sync protocol.
//!
//! `startSync` sends the whole table's checksum (`integrity_check_global`,
//! or `integrity_clear` when it is empty); the manager answers through
//! `pushMessage` (`<header> checksum_fail|no_data {"begin","end","id"}`),
//! which an async dispatcher decodes and answers with split checksums
//! (`integrity_check_left` / `integrity_check_right`) or `state` rows.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;

use parking_lot::{Condvar, Mutex};
use sha1::{Digest, Sha1};
use siem_njson::Value;

use crate::dbsync::{DBSync, DbSyncHandle};
use crate::engine::{replace_all, replace_first};
use crate::error::*;
use crate::ReturnTypeCallback;

/// `RSYNC_HANDLE` (0 is NULL).
pub type RsyncHandle = u64;

/// The message callback (`std::function<void(const std::string&)>`).
pub type SyncCallback = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// `RSYNC_LOG_TAG`
pub const RSYNC_LOG_TAG: &str = "rsync";

/// `full_log_fnc_t` with the message already formatted: (level, tag, file,
/// line, function, message).
pub type FullLogFn = Box<dyn Fn(i32, &str, &str, i32, &str, &[u8]) + Send + Sync>;

static LOG: OnceLock<Box<dyn Fn(&[u8]) + Send + Sync>> = OnceLock::new();
static FULL_LOG: OnceLock<FullLogFn> = OnceLock::new();
static CLOCK: OnceLock<fn() -> i64> = OnceLock::new();

/// `LOGLEVEL_DEBUG_VERBOSE`
const LOGLEVEL_DEBUG_VERBOSE: i32 = 5;

fn log_message(msg: &[u8]) {
    if !msg.is_empty() {
        if let Some(f) = LOG.get() {
            f(msg);
        }
    }
}

/// `logDebug2(tag, ...)` at the given source location.
fn log_debug2(file: &str, line: i32, func: &str, msg: &[u8]) {
    if let Some(f) = FULL_LOG.get() {
        f(LOGLEVEL_DEBUG_VERBOSE, RSYNC_LOG_TAG, file, line, func, msg);
    }
}

/// `std::time(nullptr)` (tests may pin it, once, before any sync).
pub fn set_clock(f: fn() -> i64) {
    let _ = CLOCK.set(f);
}

fn now() -> i64 {
    match CLOCK.get() {
        Some(f) => f(),
        None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
    }
}

/// `RemoteSync::initialize(logFunction)`: the first one stays.
pub fn initialize(log: impl Fn(&[u8]) + Send + Sync + 'static) {
    let _ = LOG.set(Box::new(log));
}

/// `RemoteSync::initializeFullLogFunction(f)` / `Log::assignLogFunction`
pub fn initialize_full_log_function(f: FullLogFn) {
    let _ = FULL_LOG.set(f);
}

// ------------------------------------------------------------ messages

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IntegrityMsgType {
    Left,
    Right,
    Global,
    Clear,
}

/// `IntegrityCommands`
fn integrity_command(t: IntegrityMsgType) -> &'static str {
    match t {
        IntegrityMsgType::Left => "integrity_check_left",
        IntegrityMsgType::Right => "integrity_check_right",
        IntegrityMsgType::Global => "integrity_check_global",
        IntegrityMsgType::Clear => "integrity_clear",
    }
}

/// `SplitContext`
#[derive(Clone, Debug)]
struct SplitContext {
    checksum: Vec<u8>,
    tail: Vec<u8>,
    begin: Vec<u8>,
    end: Vec<u8>,
    id: i32,
    ty: IntegrityMsgType,
}

impl Default for SplitContext {
    fn default() -> Self {
        SplitContext { checksum: Vec::new(), tail: Vec::new(), begin: Vec::new(), end: Vec::new(), id: 0, ty: IntegrityMsgType::Left }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CalcChecksumType {
    Complete,
    Split,
}

struct ChecksumContext {
    left: SplitContext,
    right: SplitContext,
    ty: CalcChecksumType,
    size: usize,
}

/// `SyncInputData`
#[derive(Clone, Debug, Default)]
pub struct SyncInputData {
    pub command: Vec<u8>,
    pub begin: Vec<u8>,
    pub end: Vec<u8>,
    pub id: i32,
}

/// `MessageChecksum<SplitContext>::send`
fn send_checksum(callback: &SyncCallback, config: &Value, data: &SplitContext) -> R {
    let mut out = Value::Null;
    j(out.set(b"component", j(config.at("component"))?.clone()))?;
    j(out.set(b"type", Value::string(integrity_command(data.ty))))?;
    let mut od = Value::Null;
    j(od.set(b"id", Value::Int(data.id as i64)))?;
    if data.ty != IntegrityMsgType::Clear {
        j(od.set(b"begin", Value::Str(data.begin.clone())))?;
        j(od.set(b"end", Value::Str(data.end.clone())))?;
        if data.ty == IntegrityMsgType::Left {
            j(od.set(b"tail", Value::Str(data.tail.clone())))?;
        }
        j(od.set(b"checksum", Value::Str(data.checksum.clone())))?;
    }
    j(out.set(b"data", od))?;
    if !data.checksum.is_empty() || data.ty == IntegrityMsgType::Clear {
        callback(&j(out.dump())?);
    }
    Ok(())
}

/// `MessageRowData<nlohmann::json>::send`
fn send_row_data(callback: &SyncCallback, config: &Value, data: &Value) -> R {
    let mut out = Value::Null;
    j(out.set(b"component", j(config.at("component"))?.clone()))?;
    j(out.set(b"type", Value::string("state")))?;
    let mut od = Value::Null;
    let index_name = j(j(config.at("index"))?.get_ref_str())?;
    j(od.set(b"index", j(data.at_b(index_name))?.clone()))?;
    let timestamp = match config.find(b"last_event") {
        Some(le) => j(data.at_b(j(le.get_ref_str())?))?.clone(),
        None => Value::string(""),
    };
    j(od.set(b"timestamp", timestamp))?;
    j(od.set(b"attributes", data.clone()))?;
    j(out.set(b"data", od))?;
    callback(&j(out.dump())?);
    Ok(())
}

/// `Utils::asciiToHex(HashData::hash())`
fn hex(d: &[u8]) -> Vec<u8> {
    d.iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes()
}

/// `std::to_string(json.get<unsigned long>())` or the string itself.
fn index_string(v: &Value) -> R<Vec<u8>> {
    if let Value::Str(s) = v {
        Ok(s.clone())
    } else {
        Ok(j(v.get_u64())?.to_string().into_bytes())
    }
}

// ----------------------------------------------------- the dbsync queries

fn select(dbsync: DbSyncHandle, data: &Value, cb: &mut dyn FnMut(ReturnTypeCallback, &Value) -> R) -> R {
    DBSync::from_handle(dbsync).select_rows(data, cb)
}

/// The `query` of a select from a configuration query (`row_filter` with
/// its `?` placeholders replaced, `column_list`, `distinct_opt`,
/// `order_by_opt`).
fn query_param(query_select: &Value, row_filter: Vec<u8>) -> R<Value> {
    let mut q = Value::Null;
    j(q.set(b"row_filter", Value::Str(row_filter)))?;
    j(q.set(b"column_list", j(query_select.at("column_list"))?.clone()))?;
    j(q.set(b"distinct_opt", j(query_select.at("distinct_opt"))?.clone()))?;
    j(q.set(b"order_by_opt", j(query_select.at("order_by_opt"))?.clone()))?;
    Ok(q)
}

fn sanitized(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    replace_all(&mut v, b"'", b"''");
    v
}

/// `getRangeCount(wrapper, config, syncData)`
fn get_range_count(dbsync: DbSyncHandle, config: &Value, sync_data: &SyncInputData) -> R<usize> {
    let mut select_data = Value::Null;
    j(select_data.set(b"table", j(config.at("table"))?.clone()))?;
    j(select_data.index_mut(b"query"))?;
    let query_select = j(config.at("count_range_query_json"))?;
    let count_field_name = j(j(query_select.at("count_field_name"))?.get_ref_str())?.to_vec();
    let mut size = 0usize;
    let mut row_filter = j(j(query_select.at("row_filter"))?.get_ref_str())?.to_vec();
    replace_first(&mut row_filter, b"?", &sanitized(&sync_data.begin));
    replace_first(&mut row_filter, b"?", &sanitized(&sync_data.end));
    j(select_data.set(b"query", query_param(query_select, row_filter)?))?;
    let mut cb = |_: ReturnTypeCallback, result: &Value| -> R {
        size = j(j(result.at_b(&count_field_name))?.get_u64())? as usize;
        Ok(())
    };
    select(dbsync, &select_data, &mut cb)?;
    Ok(size)
}

/// `fillChecksum(wrapper, config, begin, end, ctx)`
fn fill_checksum(dbsync: DbSyncHandle, config: &Value, begin: &[u8], end: &[u8], ctx: &mut ChecksumContext) -> R {
    let mut select_data = Value::Null;
    j(select_data.set(b"table", j(config.at("table"))?.clone()))?;
    let query_select = j(config.at("range_checksum_query_json"))?;
    let checksum_field_name = j(j(config.at("checksum_field"))?.get_ref_str())?.to_vec();
    let mut index = 1usize;
    let middle = ctx.size / 2;
    let mut hash = Sha1::new();
    let mut row_filter = j(j(query_select.at("row_filter"))?.get_ref_str())?.to_vec();
    replace_first(&mut row_filter, b"?", &sanitized(begin));
    replace_first(&mut row_filter, b"?", &sanitized(end));
    j(select_data.set(b"query", query_param(query_select, row_filter)?))?;
    let mut cb = |_: ReturnTypeCallback, result: &Value| -> R {
        let checksum_value = j(j(result.at_b(&checksum_field_name))?.get_ref_str())?.to_vec();
        hash.update(&checksum_value);
        if ctx.ty == CalcChecksumType::Split {
            let index_field_name = j(j(config.at("index"))?.get_ref_str())?;
            let r = j(result.at_b(index_field_name))?;
            if middle + 1 == index {
                ctx.right.begin = index_string(r)?;
                ctx.left.tail = ctx.right.begin.clone();
            } else if middle == index {
                ctx.left.end = index_string(r)?;
                let h = std::mem::replace(&mut hash, Sha1::new());
                ctx.left.checksum = hex(&h.finalize());
            }
            index += 1;
        }
        Ok(())
    };
    select(dbsync, &select_data, &mut cb)?;
    ctx.right.checksum = hex(&hash.finalize());
    Ok(())
}

/// `getRowData(wrapper, config, index)`
fn get_row_data(dbsync: DbSyncHandle, config: &Value, index: &[u8]) -> R<Value> {
    let mut row_data = Value::Null;
    let mut select_data = Value::Null;
    j(select_data.set(b"table", j(config.at("table"))?.clone()))?;
    j(select_data.index_mut(b"query"))?;
    let query_select;
    let mut row_filter;
    if !index.is_empty() {
        query_select = j(config.at("row_data_query_json"))?.clone();
        row_filter = j(j(query_select.at("row_filter"))?.get_ref_str())?.to_vec();
        replace_first(&mut row_filter, b"?", &sanitized(index));
    } else {
        query_select = j(config.at("query"))?.clone();
        row_filter = j(j(query_select.at("row_filter"))?.get_ref_str())?.to_vec();
    }
    j(select_data.set(b"query", query_param(&query_select, row_filter)?))?;
    let mut cb = |_: ReturnTypeCallback, result: &Value| -> R {
        row_data = result.clone();
        Ok(())
    };
    select(dbsync, &select_data, &mut cb)?;
    Ok(row_data)
}

/// `executeSelectQuery(wrapper, table, first, last)`
fn execute_select_query(dbsync: DbSyncHandle, table: &[u8], first: &Value, last: &Value) -> R<Value> {
    let mut out = Value::Null;
    if !first.empty() && !last.empty() {
        let mut f = Value::Null;
        let mut l = Value::Null;
        j(f.set(b"table", Value::Str(table.to_vec())))?;
        j(l.set(b"table", Value::Str(table.to_vec())))?;
        j(f.set(b"query", first.clone()))?;
        j(l.set(b"query", last.clone()))?;
        j(out.set(b"first_result", get_row_data(dbsync, &f, b"")?))?;
        j(out.set(b"last_result", get_row_data(dbsync, &l, b"")?))?;
    }
    Ok(out)
}

/// `sendChecksumFail(wrapper, config, callback, syncData)`
fn send_checksum_fail(dbsync: DbSyncHandle, config: &Value, callback: &SyncCallback, sync_data: &SyncInputData) -> R {
    let size = get_range_count(dbsync, config, sync_data)?;
    if size == 1 && sync_data.begin == sync_data.end {
        let row_data = get_row_data(dbsync, config, &sync_data.begin)?;
        send_row_data(callback, config, &row_data)
    } else if size > 1 {
        let mut ctx = ChecksumContext {
            left: SplitContext { id: sync_data.id, ty: IntegrityMsgType::Left, begin: sync_data.begin.clone(), ..Default::default() },
            right: SplitContext { id: sync_data.id, ty: IntegrityMsgType::Right, end: sync_data.end.clone(), ..Default::default() },
            ty: CalcChecksumType::Split,
            size,
        };
        fill_checksum(dbsync, config, &sync_data.begin, &sync_data.end, &mut ctx)?;
        send_checksum(callback, config, &ctx.left)?;
        send_checksum(callback, config, &ctx.right)
    } else {
        Err(Error::rsync(RSYNC_UNEXPECTED_SIZE))
    }
}

/// `sendAllData(wrapper, config, callback, syncData)`
fn send_all_data(dbsync: DbSyncHandle, config: &Value, callback: &SyncCallback, sync_data: &SyncInputData) -> R {
    let mut select_data = Value::Null;
    j(select_data.set(b"table", j(config.at("table"))?.clone()))?;
    let query_select = j(config.at("no_data_query_json"))?;
    j(select_data.index_mut(b"query"))?;
    let mut row_filter = j(j(query_select.at("row_filter"))?.get_ref_str())?.to_vec();
    replace_first(&mut row_filter, b"?", &sync_data.begin);
    replace_first(&mut row_filter, b"?", &sync_data.end);
    j(select_data.set(b"query", query_param(query_select, row_filter)?))?;
    let mut cb = |_: ReturnTypeCallback, result: &Value| -> R {
        let component = j(j(config.at("component"))?.get_ref_str())?;
        if RSyncImplementation::instance().is_component_registered(component) {
            send_row_data(callback, config, result)
        } else {
            Err(Error::std("Synchronization cancelled, component inactivated"))
        }
    };
    select(dbsync, &select_data, &mut cb)
}

// ------------------------------------------------------------ dispatcher

type Job = Box<dyn FnOnce() + Send>;

/// `Utils::AsyncDispatcher` over a `SafeQueue`.
struct AsyncDispatcher {
    queue: Mutex<VecDeque<Job>>,
    canceled: AtomicBool,
    cv: Condvar,
    running: AtomicBool,
    max_queue_size: usize,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl AsyncDispatcher {
    fn new(number_of_threads: u32, max_queue_size: usize) -> Arc<AsyncDispatcher> {
        let d = Arc::new(AsyncDispatcher {
            queue: Mutex::new(VecDeque::new()),
            canceled: AtomicBool::new(false),
            cv: Condvar::new(),
            running: AtomicBool::new(true),
            max_queue_size,
            threads: Mutex::new(Vec::new()),
        });
        let n = if number_of_threads == 0 { 1 } else { number_of_threads };
        for _ in 0..n {
            let dd = d.clone();
            d.threads.lock().push(std::thread::spawn(move || dd.dispatch()));
        }
        d
    }

    fn queue_push(&self, f: Job) {
        let mut q = self.queue.lock();
        if !self.canceled.load(Ordering::SeqCst) {
            q.push_back(f);
            self.cv.notify_one();
        }
    }

    fn pop(&self) -> Option<Job> {
        let mut q = self.queue.lock();
        while q.is_empty() && !self.canceled.load(Ordering::SeqCst) {
            self.cv.wait(&mut q);
        }
        if !self.canceled.load(Ordering::SeqCst) {
            q.pop_front()
        } else {
            None
        }
    }

    fn push(&self, f: Job) {
        if self.running.load(Ordering::SeqCst) {
            let len = self.queue.lock().len();
            if self.max_queue_size == 0 || len < self.max_queue_size {
                self.queue_push(f);
            }
        }
    }

    fn dispatch(&self) {
        while self.running.load(Ordering::SeqCst) {
            if let Some(f) = self.pop() {
                f();
            }
        }
    }

    /// `rundown()`: waits for everything queued, then stops.
    fn rundown(&self) {
        if self.running.load(Ordering::SeqCst) {
            let done = Arc::new((Mutex::new(false), Condvar::new()));
            let d2 = done.clone();
            self.queue_push(Box::new(move || {
                *d2.0.lock() = true;
                d2.1.notify_all();
            }));
            let mut g = done.0.lock();
            while !*g && !self.canceled.load(Ordering::SeqCst) {
                done.1.wait(&mut g);
            }
            drop(g);
            self.cancel();
        }
    }

    fn cancel(&self) {
        self.running.store(false, Ordering::SeqCst);
        {
            let _q = self.queue.lock();
            self.canceled.store(true, Ordering::SeqCst);
            self.cv.notify_all();
        }
        let threads = std::mem::take(&mut *self.threads.lock());
        let me = std::thread::current().id();
        for t in threads {
            if t.thread().id() != me {
                let _ = t.join();
            }
        }
    }
}

type RegisteredCallback = Arc<dyn Fn(SyncInputData) + Send + Sync>;

/// `Utils::MsgDispatcher<std::string, SyncInputData, ..., SyncDecoder>`
struct MsgDispatcher {
    dispatcher: Arc<AsyncDispatcher>,
    /// `SyncDecoder::m_decodersRegistered` (only JSON_RANGE exists)
    decoders: Mutex<BTreeMap<Vec<u8>, ()>>,
    callbacks: Mutex<BTreeMap<Vec<u8>, RegisteredCallback>>,
}

impl MsgDispatcher {
    fn new(thread_pool_size: u32, max_queue_size: usize) -> Arc<MsgDispatcher> {
        Arc::new(MsgDispatcher {
            dispatcher: AsyncDispatcher::new(thread_pool_size, max_queue_size),
            decoders: Mutex::new(BTreeMap::new()),
            callbacks: Mutex::new(BTreeMap::new()),
        })
    }

    fn push(self: &Arc<Self>, raw: Vec<u8>) {
        let me = self.clone();
        self.dispatcher.push(Box::new(move || me.dispatch(&raw)));
    }

    /// `SyncDecoder::decode(rawData)`
    fn decode(&self, raw: &[u8]) -> (Vec<u8>, SyncInputData) {
        let r = (|| -> R<(Vec<u8>, SyncInputData)> {
            let Some(first) = raw.iter().position(|&c| c == b' ') else {
                return Err(Error::rsync(RSYNC_INVALID_HEADER));
            };
            let header = raw[..first].to_vec();
            if !self.decoders.lock().contains_key(&header) {
                return Err(Error::std("map::at"));
            }
            Ok((header, json_decode(raw)?))
        })();
        match r {
            Ok(v) => v,
            Err(e) => {
                cerr_what(&e);
                (Vec::new(), SyncInputData::default())
            }
        }
    }

    /// `dispatch(raw)`
    fn dispatch(&self, raw: &[u8]) {
        let (header, data) = self.decode(raw);
        let cb = self.callbacks.lock().get(&header).cloned();
        if let Some(cb) = cb {
            cb(data);
        }
    }
}

/// `std::cerr << e.what() << '\n'`
fn cerr_what(e: &Error) {
    crate::cerr_line(e.what().split(|&c| c == 0).next().unwrap_or_default());
}

/// `JSONMessageDecoder::decode(rawData)`
fn json_decode(raw: &[u8]) -> R<SyncInputData> {
    let mut ret = SyncInputData::default();
    let Some(first) = raw.iter().position(|&c| c == b' ') else {
        return Ok(ret);
    };
    let from_first = &raw[first + 1..];
    let Some(second) = from_first.iter().position(|&c| c == b' ') else {
        return Ok(ret);
    };
    ret.command = from_first[..second].to_vec();
    let rest = &from_first[second + 1..];
    let json = j(siem_njson::parse(rest))?;
    let begin = j(json.at("begin"))?;
    let end = j(json.at("end"))?;
    if begin.is_string() {
        ret.begin = j(begin.get_string())?;
        ret.end = j(end.get_string())?;
    } else {
        ret.begin = j(begin.get_u64())?.to_string().into_bytes();
        ret.end = j(end.get_u64())?.to_string().into_bytes();
    }
    ret.id = j(j(json.at("id"))?.get_i32())?;
    Ok(ret)
}

// -------------------------------------------------------- implementation

struct RSyncContext {
    msg_dispatcher: Arc<MsgDispatcher>,
}

/// `RSyncImplementation::instance()`
pub struct RSyncImplementation {
    contexts: Mutex<BTreeMap<RsyncHandle, Arc<RSyncContext>>>,
    /// `RegistrationController`: component → handle
    registration: Mutex<BTreeMap<Vec<u8>, RsyncHandle>>,
    /// `SynchronizationController`: handle → table → sync id
    synchronization: Mutex<HashMap<RsyncHandle, HashMap<Vec<u8>, i32>>>,
}

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

impl RSyncImplementation {
    pub fn instance() -> &'static RSyncImplementation {
        static I: OnceLock<RSyncImplementation> = OnceLock::new();
        I.get_or_init(|| RSyncImplementation {
            contexts: Mutex::new(BTreeMap::new()),
            registration: Mutex::new(BTreeMap::new()),
            synchronization: Mutex::new(HashMap::new()),
        })
    }

    fn remove_component_by_handle(&self, handle: RsyncHandle) {
        self.registration.lock().retain(|_, h| *h != handle);
    }

    /// `release()`
    pub fn release(&self) {
        let mut contexts = self.contexts.lock();
        self.synchronization.lock().clear();
        for (h, ctx) in contexts.iter() {
            self.remove_component_by_handle(*h);
            ctx.msg_dispatcher.dispatcher.rundown();
        }
        contexts.clear();
    }

    /// `releaseContext(handle)`
    pub fn release_context(&self, handle: RsyncHandle) -> R {
        self.remove_component_by_handle(handle);
        self.remote_sync_context(handle)?.msg_dispatcher.dispatcher.rundown();
        let mut contexts = self.contexts.lock();
        self.synchronization.lock().remove(&handle);
        contexts.remove(&handle);
        Ok(())
    }

    /// `create(threadPoolSize, maxQueueSize)`
    pub fn create(&self, thread_pool_size: u32, max_queue_size: usize) -> RsyncHandle {
        let ctx = Arc::new(RSyncContext { msg_dispatcher: MsgDispatcher::new(thread_pool_size, max_queue_size) });
        let h = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
        self.contexts.lock().insert(h, ctx);
        h
    }

    fn remote_sync_context(&self, handle: RsyncHandle) -> R<Arc<RSyncContext>> {
        self.contexts.lock().get(&handle).cloned().ok_or_else(|| Error::rsync(RSYNC_INVALID_HANDLE))
    }

    /// `startRSync(handle, wrapper, startConfiguration, callback)`
    pub fn start_rsync(&self, handle: RsyncHandle, dbsync: DbSyncHandle, start_configuration: &Value, callback: &SyncCallback) -> R {
        let _ctx = self.remote_sync_context(handle)?;
        let js_start_params_table = j(start_configuration.at("table"))?;
        let first_query = start_configuration.find(b"first_query");
        let last_query = start_configuration.find(b"last_query");
        let (true, Some(first_query), Some(last_query)) = (!js_start_params_table.empty(), first_query, last_query) else {
            return Err(Error::rsync(RSYNC_INPUT_JSON_INCOMPLETE));
        };
        let table = j(js_start_params_table.get_string())?;
        let out = execute_select_query(dbsync, &table, first_query, last_query)?;
        let first_result = j(out.at("first_result"))?;
        let last_result = j(out.at("last_result"))?;
        let mut ctx = ChecksumContext { left: SplitContext::default(), right: SplitContext::default(), ty: CalcChecksumType::Complete, size: 0 };
        ctx.right.id = now() as i32;
        if !first_result.empty() && !last_result.empty() {
            let index_field = j(j(start_configuration.at("index"))?.get_ref_str())?;
            let begin = j(first_result.at_b(index_field))?;
            let end = j(last_result.at_b(index_field))?;
            ctx.ty = CalcChecksumType::Complete;
            ctx.right.ty = IntegrityMsgType::Global;
            if begin.is_string() {
                ctx.right.begin = j(begin.get_string())?;
                ctx.right.end = j(end.get_string())?;
                let (b, e) = (j(begin.get_string())?, j(end.get_string())?);
                fill_checksum(dbsync, start_configuration, &b, &e, &mut ctx)?;
            } else {
                let b = j(begin.get_u64())?.to_string().into_bytes();
                let e = j(end.get_u64())?.to_string().into_bytes();
                ctx.right.begin = b.clone();
                ctx.right.end = e.clone();
                fill_checksum(dbsync, start_configuration, &b, &e, &mut ctx)?;
            }
        } else {
            ctx.right.ty = IntegrityMsgType::Clear;
        }
        self.synchronization.lock().entry(handle).or_default().insert(table, ctx.right.id);
        send_checksum(callback, start_configuration, &ctx.right)?;
        log_debug2(
            "rsyncImplementation.cpp",
            120,
            "startRSync",
            format!("Remote sync started: {}", integrity_command(ctx.right.ty)).as_bytes(),
        );
        Ok(())
    }

    /// `SynchronizationController::checkId(handle, table, id)`
    fn check_id(&self, handle: RsyncHandle, table: &[u8], value: i32) -> R {
        let mut s = self.synchronization.lock();
        let Some(tables) = s.get_mut(&handle) else {
            return Err(Error::rsync(RSYNC_HANDLE_NOT_FOUND));
        };
        if let Some(current) = tables.get_mut(table) {
            if value < *current {
                *current = value;
            }
            if value > *current {
                let msg = format!("Sync id: {} is not the current id: {} for table: {}", value, *current, String::from_utf8_lossy(table));
                log_debug2("synchronizationController.hpp", 72, "checkId", msg.as_bytes());
                return Err(Error::std("Sync id is not the current id"));
            }
        }
        Ok(())
    }

    /// `registerSyncId(handle, messageHeaderId, wrapper, syncConfiguration,
    /// callback)`
    pub fn register_sync_id(
        &self,
        handle: RsyncHandle,
        message_header_id: &[u8],
        dbsync: DbSyncHandle,
        sync_configuration: &Value,
        callback: SyncCallback,
    ) -> R {
        if self.is_component_registered(message_header_id) {
            return Err(Error::rsync(RSYNC_COMPONENT_ALREADY_REGISTERED));
        }
        let ctx = self.remote_sync_context(handle)?;
        let decoder_type = j(j(sync_configuration.at("decoder_type"))?.get_string())?;
        if decoder_type != b"JSON_RANGE" {
            return Err(Error::std("map::at"));
        }
        ctx.msg_dispatcher.decoders.lock().insert(message_header_id.to_vec(), ());
        let config = sync_configuration.clone();
        let register_callback: RegisteredCallback = Arc::new(move |sync_data: SyncInputData| {
            let r = (|| -> R {
                let table = j(j(config.at("table"))?.get_string())?;
                RSyncImplementation::instance().check_id(handle, &table, sync_data.id)?;
                if sync_data.command == b"checksum_fail" {
                    send_checksum_fail(dbsync, &config, &callback, &sync_data)
                } else if sync_data.command == b"no_data" {
                    send_all_data(dbsync, &config, &callback, &sync_data)
                } else {
                    Err(Error::rsync(RSYNC_INVALID_OPERATION))
                }
            })();
            if let Err(e) = r {
                cerr_what(&e);
            }
        });
        ctx.msg_dispatcher.callbacks.lock().entry(message_header_id.to_vec()).or_insert(register_callback);
        self.registration.lock().insert(message_header_id.to_vec(), handle);
        Ok(())
    }

    /// `push(handle, data)`
    pub fn push(&self, handle: RsyncHandle, data: &[u8]) -> R {
        self.remote_sync_context(handle)?.msg_dispatcher.push(data.to_vec());
        Ok(())
    }

    /// `isComponentRegistered(component)`
    pub fn is_component_registered(&self, component: &[u8]) -> bool {
        self.registration.lock().contains_key(component)
    }
}

// ------------------------------------------------------------- C++ API

/// `RemoteSync`
pub struct RemoteSync {
    handle: RsyncHandle,
    should_be_removed: bool,
}

impl RemoteSync {
    /// `RemoteSync(threadPoolSize, maxQueueSize)`
    pub fn new(thread_pool_size: u32, max_queue_size: usize) -> RemoteSync {
        RemoteSync { handle: RSyncImplementation::instance().create(thread_pool_size, max_queue_size), should_be_removed: true }
    }

    /// `RemoteSync(handle)`
    pub fn from_handle(handle: RsyncHandle) -> RemoteSync {
        RemoteSync { handle, should_be_removed: false }
    }

    pub fn handle(&self) -> RsyncHandle {
        self.handle
    }

    /// `RemoteSync::teardown()`
    pub fn teardown() {
        RSyncImplementation::instance().release();
    }

    pub fn start_sync(&self, dbsync: DbSyncHandle, start_configuration: &Value, callback: SyncCallback) -> R {
        RSyncImplementation::instance().start_rsync(self.handle, dbsync, start_configuration, &callback)
    }

    pub fn register_sync_id(&self, message_header_id: &[u8], dbsync: DbSyncHandle, sync_configuration: &Value, callback: SyncCallback) -> R {
        RSyncImplementation::instance().register_sync_id(self.handle, message_header_id, dbsync, sync_configuration, callback)
    }

    pub fn push_message(&self, payload: &[u8]) -> R {
        RSyncImplementation::instance().push(self.handle, payload)
    }
}

impl Drop for RemoteSync {
    fn drop(&mut self) {
        if self.should_be_removed {
            if let Err(e) = RSyncImplementation::instance().release_context(self.handle) {
                log_message(e.what());
            }
        }
    }
}

// --------------------------------------------------------------- C API

pub mod capi {
    //! rsync's C API (rsync.cpp's `extern "C"` part).

    use std::sync::Arc;

    use siem_cjson::Json;

    use super::*;
    use crate::capi::to_nlohmann;

    const UNRECOGNIZED: &[u8] = b"Unrecognized error.";

    /// `rsync_initialize(log_function)`
    pub fn rsync_initialize(log_function: impl Fn(&[u8]) + Send + Sync + 'static) {
        initialize(move |m: &[u8]| log_function(m.split(|&c| c == 0).next().unwrap_or_default()));
    }

    /// `rsync_initialize_full_log_function(log_function)`
    pub fn rsync_initialize_full_log_function(f: FullLogFn) {
        initialize_full_log_function(f);
    }

    /// `rsync_teardown()`
    pub fn rsync_teardown() {
        RSyncImplementation::instance().release();
    }

    /// `rsync_create(thread_pool_size, max_queue_size)`
    pub fn rsync_create(thread_pool_size: u32, max_queue_size: usize) -> RsyncHandle {
        RSyncImplementation::instance().create(thread_pool_size, max_queue_size)
    }

    fn c_callback(cb: Arc<dyn Fn(&[u8]) + Send + Sync>) -> SyncCallback {
        // callback(payload.c_str(), payload.size(), user_data)
        cb
    }

    /// `rsync_start_sync(handle, dbsync_handle, start_configuration,
    /// callback_data)`
    pub fn rsync_start_sync(
        handle: RsyncHandle,
        dbsync_handle: DbSyncHandle,
        start_configuration: Option<&Json>,
        callback: Option<Arc<dyn Fn(&[u8]) + Send + Sync>>,
    ) -> i32 {
        let (true, true, Some(cfg), Some(cb)) = (handle != 0, dbsync_handle != 0, start_configuration, callback) else {
            log_message(b"Invalid parameters.");
            return -1;
        };
        let cb = c_callback(cb);
        match to_nlohmann(cfg).and_then(|v| RSyncImplementation::instance().start_rsync(handle, dbsync_handle, &v, &cb)) {
            Ok(()) => 0,
            Err(_) => {
                log_message(UNRECOGNIZED);
                -1
            }
        }
    }

    /// `rsync_register_sync_id(handle, message_header_id, dbsync_handle,
    /// sync_configuration, callback_data)`
    pub fn rsync_register_sync_id(
        handle: RsyncHandle,
        message_header_id: Option<&[u8]>,
        dbsync_handle: DbSyncHandle,
        sync_configuration: Option<&Json>,
        callback: Option<Arc<dyn Fn(&[u8]) + Send + Sync>>,
    ) -> i32 {
        let (Some(header), true, Some(cfg), Some(cb)) = (message_header_id, dbsync_handle != 0, sync_configuration, callback) else {
            log_message(b"Invalid Parameters.");
            return -1;
        };
        let header = header.split(|&c| c == 0).next().unwrap_or_default();
        let cb = c_callback(cb);
        match to_nlohmann(cfg).and_then(|v| RSyncImplementation::instance().register_sync_id(handle, header, dbsync_handle, &v, cb)) {
            Ok(()) => 0,
            Err(_) => {
                log_message(UNRECOGNIZED);
                -1
            }
        }
    }

    /// `rsync_push_message(handle, payload, size)`
    pub fn rsync_push_message(handle: RsyncHandle, payload: Option<&[u8]>) -> i32 {
        let (true, Some(p)) = (handle != 0, payload.filter(|p| !p.is_empty())) else {
            log_message(b"Invalid Parameters.");
            return -1;
        };
        match RSyncImplementation::instance().push(handle, p) {
            Ok(()) => 0,
            Err(_) => {
                log_message(UNRECOGNIZED);
                -1
            }
        }
    }

    /// `rsync_close(handle)`
    pub fn rsync_close(handle: RsyncHandle) -> i32 {
        match RSyncImplementation::instance().release_context(handle) {
            Ok(()) => 0,
            Err(_) => {
                log_message(b"RSYNC invalid context handle.");
                -1
            }
        }
    }
}
