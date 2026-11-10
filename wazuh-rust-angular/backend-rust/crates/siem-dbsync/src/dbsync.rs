//! `DBSyncImplementation` (handles and contexts), the transaction
//! `Pipeline` with its `PipelineFactory`, and the C++ API (`DBSync`,
//! `DBSyncTxn` and the query builders).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use siem_njson::Value;

use crate::engine::{Callback, SqliteDbEngine};
use crate::error::*;
use crate::{DbEngineType, DbManagement, ExclusiveLocking, HostType, ReturnTypeCallback, SharedLocking, SyncMutex};

/// `DBSYNC_HANDLE` (0 is NULL).
pub type DbSyncHandle = u64;
/// `TXN_HANDLE` (0 is NULL).
pub type TxnHandle = u64;

/// A stored result callback (`DbSync::ResultCallback`); it may throw.
pub type ResultCallback = Arc<dyn Fn(ReturnTypeCallback, &Value) -> R + Send + Sync>;

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn new_handle() -> u64 {
    NEXT_HANDLE.fetch_add(1, Ordering::SeqCst)
}

static LOG: OnceLock<Box<dyn Fn(&[u8]) + Send + Sync>> = OnceLock::new();

/// `log_message(msg)` of dbsync.cpp.
pub(crate) fn log_message(msg: &[u8]) {
    if !msg.is_empty() {
        if let Some(f) = LOG.get() {
            f(msg);
        }
    }
}

struct TransactionContext {
    tables: Value,
}

struct DbEngineContext {
    engine: SqliteDbEngine,
    #[allow(dead_code)]
    host_type: HostType,
    #[allow(dead_code)]
    db_type: DbEngineType,
    sync_mutex: SyncMutex,
    transactions: Mutex<BTreeMap<TxnHandle, Arc<TransactionContext>>>,
}

impl DbEngineContext {
    fn transaction_context(&self, handle: TxnHandle) -> R<Arc<TransactionContext>> {
        self.transactions.lock().get(&handle).cloned().ok_or_else(|| Error::dbsync(INVALID_TRANSACTION))
    }
}

/// `DBSyncImplementation::instance()`
pub struct DbSyncImplementation {
    contexts: Mutex<BTreeMap<DbSyncHandle, Arc<DbEngineContext>>>,
}

impl DbSyncImplementation {
    pub fn instance() -> &'static DbSyncImplementation {
        static I: OnceLock<DbSyncImplementation> = OnceLock::new();
        I.get_or_init(|| DbSyncImplementation { contexts: Mutex::new(BTreeMap::new()) })
    }

    fn ctx(&self, handle: DbSyncHandle) -> R<Arc<DbEngineContext>> {
        self.contexts.lock().get(&handle).cloned().ok_or_else(|| Error::dbsync(INVALID_HANDLE))
    }

    /// `initialize(hostType, dbType, path, sqlStatement, dbManagement,
    /// upgradeStatements)`
    pub fn initialize(
        &self,
        host_type: HostType,
        db_type: DbEngineType,
        path: &[u8],
        sql_statement: &[u8],
        db_management: DbManagement,
        upgrade_statements: &[Vec<u8>],
    ) -> R<DbSyncHandle> {
        if db_type != DbEngineType::Sqlite3 {
            return Err(Error::dbsync(FACTORY_INSTANTATION));
        }
        let engine = SqliteDbEngine::new(path, sql_statement, db_management, upgrade_statements)?;
        let ctx = Arc::new(DbEngineContext {
            engine,
            host_type,
            db_type,
            sync_mutex: SyncMutex::new(),
            transactions: Mutex::new(BTreeMap::new()),
        });
        let h = new_handle();
        self.contexts.lock().insert(h, ctx);
        Ok(h)
    }

    /// `release()`
    pub fn release(&self) {
        let old = std::mem::take(&mut *self.contexts.lock());
        drop(old);
    }

    /// `releaseContext(handle)`
    pub fn release_context(&self, handle: DbSyncHandle) {
        let old = self.contexts.lock().remove(&handle);
        drop(old);
    }

    /// `insertBulkData(handle, json)`
    pub fn insert_bulk_data(&self, handle: DbSyncHandle, json: &Value) -> R {
        let ctx = self.ctx(handle)?;
        let _lock = ExclusiveLocking::new(&ctx.sync_mutex);
        // arguments evaluated right to left (gcc)
        let data = j(json.at("data"))?;
        let table = j(j(json.at("table"))?.get_string())?;
        ctx.engine.bulk_insert(&table, data)
    }

    /// `syncRowData(handle, json, callback)`
    pub fn sync_row_data(&self, handle: DbSyncHandle, json: &Value, callback: Callback) -> R {
        let ctx = self.ctx(handle)?;
        let mut lock = ExclusiveLocking::new(&ctx.sync_mutex);
        ctx.engine.sync_table_row_data(json, callback, false, &mut lock)
    }

    /// `syncRowData(handle, txnHandle, json, callback)`
    pub fn sync_row_data_txn(&self, handle: DbSyncHandle, txn: TxnHandle, json: &Value, callback: Callback) -> R {
        let ctx = self.ctx(handle)?;
        let tnx_ctx = ctx.transaction_context(txn)?;
        let table = j(json.at("table"))?;
        if !tnx_ctx.tables.iter().iter().any(|t| t.json_eq(table)) {
            return Err(Error::dbsync(INVALID_TABLE));
        }
        let mut lock = SharedLocking::new(&ctx.sync_mutex);
        ctx.engine.sync_table_row_data(json, callback, true, &mut lock)
    }

    /// `deleteRowsData(handle, json)`
    pub fn delete_rows_data(&self, handle: DbSyncHandle, json: &Value) -> R {
        let ctx = self.ctx(handle)?;
        let _lock = ExclusiveLocking::new(&ctx.sync_mutex);
        let query = j(json.at("query"))?;
        let table = j(j(json.at("table"))?.get_string())?;
        ctx.engine.delete_table_rows_data(&table, query)
    }

    /// `updateSnapshotData(handle, json, callback)`
    pub fn update_snapshot_data(&self, handle: DbSyncHandle, json: &Value, callback: Callback) -> R {
        let ctx = self.ctx(handle)?;
        let mut lock = ExclusiveLocking::new(&ctx.sync_mutex);
        ctx.engine.refresh_table_data(json, callback, &mut lock)
    }

    /// `setMaxRows(handle, table, maxRows)`
    pub fn set_max_rows(&self, handle: DbSyncHandle, table: &[u8], max_rows: i64) -> R {
        let ctx = self.ctx(handle)?;
        let _lock = ExclusiveLocking::new(&ctx.sync_mutex);
        ctx.engine.set_max_rows(table, max_rows)
    }

    /// `createTransaction(handle, json)`
    fn create_transaction(&self, handle: DbSyncHandle, json: &Value) -> R<TxnHandle> {
        let ctx = self.ctx(handle)?;
        let tc = Arc::new(TransactionContext { tables: json.clone() });
        let _lock = ExclusiveLocking::new(&ctx.sync_mutex);
        let h = new_handle();
        ctx.transactions.lock().insert(h, tc.clone());
        ctx.engine.initialize_status_field(&tc.tables)?;
        Ok(h)
    }

    /// `closeTransaction(handle, txnHandle)`
    fn close_transaction(&self, handle: DbSyncHandle, txn: TxnHandle) -> R {
        let ctx = self.ctx(handle)?;
        let tnx_ctx = ctx.transaction_context(txn)?;
        let _lock = ExclusiveLocking::new(&ctx.sync_mutex);
        ctx.engine.delete_rows_by_status_field(&tnx_ctx.tables)?;
        ctx.transactions.lock().remove(&txn);
        Ok(())
    }

    /// `getDeleted(handle, txnHandle, callback)`
    fn get_deleted(&self, handle: DbSyncHandle, txn: TxnHandle, callback: Callback) -> R {
        let ctx = self.ctx(handle)?;
        let tnx_ctx = ctx.transaction_context(txn)?;
        let mut lock = ExclusiveLocking::new(&ctx.sync_mutex);
        ctx.engine.return_rows_marked_for_delete(&tnx_ctx.tables, callback, &mut lock)
    }

    /// `selectData(handle, json, callback)`
    pub fn select_data(&self, handle: DbSyncHandle, json: &Value, callback: Callback) -> R {
        let ctx = self.ctx(handle)?;
        let mut lock = ExclusiveLocking::new(&ctx.sync_mutex);
        let query = j(json.at("query"))?;
        let table = j(j(json.at("table"))?.get_string())?;
        ctx.engine.select_data(&table, query, callback, &mut lock)
    }

    /// `addTableRelationship(handle, json)`
    pub fn add_table_relationship(&self, handle: DbSyncHandle, json: &Value) -> R {
        let ctx = self.ctx(handle)?;
        let _lock = ExclusiveLocking::new(&ctx.sync_mutex);
        ctx.engine.add_table_relationship(json)
    }
}

// --------------------------------------------------------------- pipeline

/// `Pipeline` (dbsyncPipelineFactory.cpp). Its dispatch node is a
/// synchronous `ReadNode` that stops delivering once `getDeleted` ran it
/// down.
struct Pipeline {
    handle: DbSyncHandle,
    txn: TxnHandle,
    callback: ResultCallback,
    /// `m_spDispatchNode` (Some when maxQueueSize != 0): running
    node: Option<Mutex<bool>>,
}

impl Pipeline {
    fn new(handle: DbSyncHandle, tables: &Value, max_queue_size: u32, callback: ResultCallback) -> R<Pipeline> {
        let txn = DbSyncImplementation::instance().create_transaction(handle, tables)?;
        Ok(Pipeline { handle, txn, callback, node: if max_queue_size != 0 { Some(Mutex::new(true)) } else { None } })
    }

    /// `syncRow(value)`
    fn sync_row(&self, value: &Value) -> R {
        let mut push = |t: ReturnTypeCallback, v: &Value| self.push_result(t, v);
        match DbSyncImplementation::instance().sync_row_data_txn(self.handle, self.txn, value, &mut push) {
            Ok(()) => Ok(()),
            Err(Error::MaxRows(_)) => self.push_result(ReturnTypeCallback::MaxRows, value),
            Err(ex) => {
                let mut v = value.clone();
                j(v.set(b"exception", Value::Str(ex.what().to_vec())))?;
                self.push_result(ReturnTypeCallback::DbError, &v)
            }
        }
    }

    /// `getDeleted(callback)`
    fn get_deleted(&self, callback: Callback) -> R {
        if let Some(n) = &self.node {
            *n.lock() = false;
        }
        DbSyncImplementation::instance().get_deleted(self.handle, self.txn, callback)
    }

    /// `pushResult(result)`
    fn push_result(&self, t: ReturnTypeCallback, v: &Value) -> R {
        match &self.node {
            Some(n) => {
                if *n.lock() {
                    self.dispatch_result(t, v)
                } else {
                    Ok(())
                }
            }
            None => self.dispatch_result(t, v),
        }
    }

    /// `dispatchResult(result)`
    fn dispatch_result(&self, t: ReturnTypeCallback, v: &Value) -> R {
        if !v.empty() {
            (self.callback)(t, v)?;
        }
        Ok(())
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        if let Some(n) = &self.node {
            *n.lock() = false;
        }
        let _ = DbSyncImplementation::instance().close_transaction(self.handle, self.txn);
    }
}

/// `PipelineFactory::instance()`
struct PipelineFactory {
    contexts: Mutex<BTreeMap<TxnHandle, Arc<Pipeline>>>,
}

fn pipelines() -> &'static PipelineFactory {
    static I: OnceLock<PipelineFactory> = OnceLock::new();
    I.get_or_init(|| PipelineFactory { contexts: Mutex::new(BTreeMap::new()) })
}

impl PipelineFactory {
    fn release(&self) {
        let old = std::mem::take(&mut *self.contexts.lock());
        drop(old);
    }

    fn create(&self, handle: DbSyncHandle, tables: &Value, max_queue_size: u32, callback: ResultCallback) -> R<TxnHandle> {
        let p = Arc::new(Pipeline::new(handle, tables, max_queue_size, callback)?);
        let h = new_handle();
        self.contexts.lock().insert(h, p);
        Ok(h)
    }

    fn pipeline(&self, h: TxnHandle) -> R<Arc<Pipeline>> {
        self.contexts.lock().get(&h).cloned().ok_or_else(|| Error::dbsync(INVALID_HANDLE))
    }

    fn destroy(&self, h: TxnHandle) -> R {
        let p = self.contexts.lock().remove(&h).ok_or_else(|| Error::dbsync(INVALID_HANDLE))?;
        drop(p);
        Ok(())
    }
}

// -------------------------------------------------------------- C++ API

/// `DBSync::initialize(logFunction)`: the first one stays.
pub fn initialize(log: impl Fn(&[u8]) + Send + Sync + 'static) {
    let _ = LOG.set(Box::new(log));
}

/// `DBSync::teardown()` / `dbsync_teardown()`
pub fn teardown() {
    pipelines().release();
    DbSyncImplementation::instance().release();
}

pub(crate) fn txn_create(handle: DbSyncHandle, tables: &Value, max_queue_size: u32, callback: ResultCallback) -> R<TxnHandle> {
    pipelines().create(handle, tables, max_queue_size, callback)
}

pub(crate) fn txn_destroy(txn: TxnHandle) -> R {
    pipelines().destroy(txn)
}

pub(crate) fn txn_sync_row(txn: TxnHandle, value: &Value) -> R {
    pipelines().pipeline(txn)?.sync_row(value)
}

pub(crate) fn txn_get_deleted(txn: TxnHandle, callback: Callback) -> R {
    pipelines().pipeline(txn)?.get_deleted(callback)
}

/// `DBSync`: a database handle (released on drop when this object
/// created it).
pub struct DBSync {
    handle: DbSyncHandle,
    should_be_removed: bool,
}

impl DBSync {
    /// `DBSync(hostType, dbType, path, sqlStatement, dbManagement,
    /// upgradeStatements)`
    pub fn new(
        host_type: HostType,
        db_type: DbEngineType,
        path: &[u8],
        sql_statement: &[u8],
        db_management: DbManagement,
        upgrade_statements: &[Vec<u8>],
    ) -> R<DBSync> {
        let handle = DbSyncImplementation::instance().initialize(host_type, db_type, path, sql_statement, db_management, upgrade_statements)?;
        Ok(DBSync { handle, should_be_removed: true })
    }

    /// `DBSync(handle)`
    pub fn from_handle(handle: DbSyncHandle) -> DBSync {
        DBSync { handle, should_be_removed: false }
    }

    pub fn handle(&self) -> DbSyncHandle {
        self.handle
    }

    pub fn add_table_relationship(&self, js_input: &Value) -> R {
        DbSyncImplementation::instance().add_table_relationship(self.handle, js_input)
    }

    pub fn insert_data(&self, js_insert: &Value) -> R {
        DbSyncImplementation::instance().insert_bulk_data(self.handle, js_insert)
    }

    pub fn set_table_max_row(&self, table: &[u8], max_rows: i64) -> R {
        DbSyncImplementation::instance().set_max_rows(self.handle, table, max_rows)
    }

    pub fn sync_row(&self, js_input: &Value, callback: Callback) -> R {
        DbSyncImplementation::instance().sync_row_data(self.handle, js_input, callback)
    }

    pub fn select_rows(&self, js_input: &Value, callback: Callback) -> R {
        DbSyncImplementation::instance().select_data(self.handle, js_input, callback)
    }

    pub fn delete_rows(&self, js_input: &Value) -> R {
        DbSyncImplementation::instance().delete_rows_data(self.handle, js_input)
    }

    /// `updateWithSnapshot(jsInput, jsResult)`: {"modified":[..],
    /// "deleted":[..], "inserted":[..]}
    pub fn update_with_snapshot(&self, js_input: &Value, js_result: &mut Value) -> R {
        let mut cb = |t: ReturnTypeCallback, v: &Value| -> R {
            let key: &[u8] = match t {
                ReturnTypeCallback::Modified => b"modified",
                ReturnTypeCallback::Deleted => b"deleted",
                ReturnTypeCallback::Inserted => b"inserted",
                _ => return Err(Error::std("map::at")),
            };
            j(j(js_result.index_mut(key))?.push_back(v.clone()))
        };
        DbSyncImplementation::instance().update_snapshot_data(self.handle, js_input, &mut cb)
    }

    pub fn update_with_snapshot_cb(&self, js_input: &Value, callback: Callback) -> R {
        DbSyncImplementation::instance().update_snapshot_data(self.handle, js_input, callback)
    }
}

impl Drop for DBSync {
    fn drop(&mut self) {
        if self.should_be_removed {
            DbSyncImplementation::instance().release_context(self.handle);
        }
    }
}

/// `DBSyncTxn`: a transaction over some tables of a database.
pub struct DBSyncTxn {
    txn: TxnHandle,
    should_be_removed: bool,
}

impl DBSyncTxn {
    /// `DBSyncTxn(handle, tables, threadNumber, maxQueueSize, callback)`
    pub fn new(handle: DbSyncHandle, tables: &Value, _thread_number: u32, max_queue_size: u32, callback: ResultCallback) -> R<DBSyncTxn> {
        Ok(DBSyncTxn { txn: txn_create(handle, tables, max_queue_size, callback)?, should_be_removed: true })
    }

    /// `DBSyncTxn(handle)`
    pub fn from_handle(txn: TxnHandle) -> DBSyncTxn {
        DBSyncTxn { txn, should_be_removed: false }
    }

    pub fn handle(&self) -> TxnHandle {
        self.txn
    }

    pub fn sync_txn_row(&self, js_input: &Value) -> R {
        txn_sync_row(self.txn, js_input)
    }

    pub fn get_deleted_rows(&self, callback: Callback) -> R {
        txn_get_deleted(self.txn, callback)
    }
}

impl Drop for DBSyncTxn {
    fn drop(&mut self) {
        if self.should_be_removed {
            if let Err(e) = txn_destroy(self.txn) {
                log_message(e.what());
            }
        }
    }
}

/// The query builders (`Query<T>`): `query()` is the JSON input.
#[derive(Default, Clone)]
pub struct Query {
    js_query: Value,
}

impl Query {
    pub fn builder() -> Query {
        Query::default()
    }

    pub fn query(&self) -> &Value {
        &self.js_query
    }

    fn q(&mut self) -> &mut Value {
        self.js_query.index_mut(b"query").expect("object")
    }

    pub fn table(mut self, table: &str) -> Self {
        self.js_query.set(b"table", Value::string(table)).expect("object");
        self
    }

    // SelectQuery
    pub fn column_list(mut self, fields: &[&str]) -> Self {
        let v = Value::Array(fields.iter().map(Value::string).collect());
        self.q().set(b"column_list", v).expect("object");
        self
    }

    pub fn row_filter(mut self, filter: &str) -> Self {
        self.q().set(b"row_filter", Value::string(filter)).expect("object");
        self
    }

    pub fn distinct_opt(mut self, distinct: bool) -> Self {
        self.q().set(b"distinct_opt", Value::Bool(distinct)).expect("object");
        self
    }

    pub fn order_by_opt(mut self, order_by: &str) -> Self {
        self.q().set(b"order_by_opt", Value::string(order_by)).expect("object");
        self
    }

    pub fn count_opt(mut self, count: u32) -> Self {
        self.q().set(b"count_opt", Value::UInt(count as u64)).expect("object");
        self
    }

    pub fn row_filter_bind_text(mut self, value: &str) -> Self {
        let mut p = Value::Null;
        p.set(b"type", Value::string("text")).unwrap();
        p.set(b"value", Value::string(value)).unwrap();
        self.q().index_mut(b"row_filter_params").unwrap().push_back(p).unwrap();
        self
    }

    pub fn row_filter_bind_int(mut self, value: i64) -> Self {
        let mut p = Value::Null;
        p.set(b"type", Value::string("int")).unwrap();
        p.set(b"value", Value::Int(value)).unwrap();
        self.q().index_mut(b"row_filter_params").unwrap().push_back(p).unwrap();
        self
    }

    // DeleteQuery
    pub fn delete_data(mut self, data: Value) -> Self {
        self.q().index_mut(b"data").unwrap().push_back(data).unwrap();
        self
    }

    pub fn delete_row_filter(mut self, filter: &str) -> Self {
        self.q().set(b"where_filter_opt", Value::string(filter)).expect("object");
        self
    }

    pub fn delete_reset(mut self) -> Self {
        self.q().index_mut(b"data").unwrap().clear();
        self
    }

    // InsertQuery / SyncRowQuery
    pub fn data(mut self, data: Value) -> Self {
        self.js_query.index_mut(b"data").unwrap().push_back(data).unwrap();
        self
    }

    pub fn reset(mut self) -> Self {
        self.js_query.index_mut(b"data").unwrap().clear();
        self
    }

    pub fn ignore_column(mut self, column: &str) -> Self {
        let o = self.js_query.index_mut(b"options").unwrap();
        o.index_mut(b"ignore").unwrap().push_back(Value::string(column)).unwrap();
        self
    }

    pub fn return_old_data(mut self) -> Self {
        self.js_query.index_mut(b"options").unwrap().set(b"return_old_data", Value::Bool(true)).unwrap();
        self
    }
}
