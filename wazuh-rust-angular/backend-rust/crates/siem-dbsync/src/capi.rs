//! dbsync's C API (dbsync.cpp's `extern "C"` part): cJSON in, cJSON out
//! (`nlohmann::json::parse(cJSON_Print(x))` and
//! `cJSON_Parse(json.dump())`), errors logged and turned into return
//! values. `None` stands for a NULL pointer.

use std::sync::Arc;

use siem_cjson::Json;
use siem_njson::Value;

use crate::dbsync::{self, log_message, DbSyncHandle, DbSyncImplementation, TxnHandle};
use crate::error::{j, Error, R};
use crate::{DbEngineType, DbManagement, HostType, ReturnTypeCallback};

/// `result_callback_t` + `user_data`
pub type CallbackData = Arc<dyn Fn(ReturnTypeCallback, Option<&Json>) + Send + Sync>;

/// `nlohmann::json::parse(cJSON_Print(js))`
pub(crate) fn to_nlohmann(js: &Json) -> R<Value> {
    let text = js.print_unformatted();
    let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
    j(siem_njson::parse(&text[..end]))
}

/// `cJSON_Parse(json.dump().c_str())`
pub(crate) fn to_cjson(v: &Value) -> R<Option<Json>> {
    let text = j(v.dump())?;
    let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
    Ok(siem_cjson::parse(&text[..end]))
}

fn db_error(e: &Error) -> Vec<u8> {
    [format!("DB error, id: {}. ", if let Error::DbSync { id, .. } = e { *id } else { 0 }).as_bytes(), e.what()].concat()
}

fn json_error(e: &Error) -> Vec<u8> {
    [format!("json error, id: {}. ", e.json_id()).as_bytes(), e.what()].concat()
}

/// Which `catch` clauses a function has.
#[derive(Clone, Copy)]
struct Catches {
    json: bool,
    max_rows: bool,
}

/// The `try`/`catch` of the API functions: the message to log and the
/// return value.
fn catch(r: R, c: Catches) -> (Vec<u8>, i32) {
    match r {
        Ok(()) => (Vec::new(), 0),
        Err(e @ Error::Json(_)) if c.json => (json_error(&e), e.json_id()),
        Err(e @ Error::DbSync { id, .. }) => (db_error(&e), id),
        Err(Error::MaxRows(w)) if c.max_rows => ([b"DB error, ".as_slice(), &w].concat(), -1),
        Err(_) => (b"Unrecognized error.".to_vec(), -1),
    }
}

fn finish(r: R, c: Catches) -> i32 {
    let (msg, ret) = catch(r, c);
    log_message(&msg);
    ret
}

const NO_JSON: Catches = Catches { json: false, max_rows: false };
const JSON: Catches = Catches { json: true, max_rows: false };
const JSON_MAX_ROWS: Catches = Catches { json: true, max_rows: true };

/// `dbsync_initialize(log_function)`
pub fn dbsync_initialize(log_function: impl Fn(&[u8]) + Send + Sync + 'static) {
    dbsync::initialize(move |msg: &[u8]| {
        // log_function(msg.c_str())
        log_function(msg.split(|&c| c == 0).next().unwrap_or_default())
    });
}

fn create(host_type: i32, db_type: i32, path: Option<&[u8]>, sql: Option<&[u8]>, mgmt: DbManagement, upgrade: Option<&[&[u8]]>) -> DbSyncHandle {
    let mut ret = 0;
    let mut msg = Vec::new();
    match (path, sql) {
        (Some(path), Some(sql)) => {
            let upgrade: Vec<Vec<u8>> = upgrade.unwrap_or_default().iter().map(|s| cstr(s).to_vec()).collect();
            let host = if host_type == 1 { HostType::Agent } else { HostType::Manager };
            match DbSyncImplementation::instance().initialize(host, DbEngineType::from_i32(db_type), cstr(path), cstr(sql), mgmt, &upgrade) {
                Ok(h) => ret = h,
                Err(e @ Error::DbSync { .. }) => msg = db_error(&e),
                Err(_) => msg = b"Unrecognized error.".to_vec(),
            }
        }
        _ => msg = b"Invalid path or sql_statement.".to_vec(),
    }
    log_message(&msg);
    ret
}

fn cstr(s: &[u8]) -> &[u8] {
    s.split(|&c| c == 0).next().unwrap_or_default()
}

/// `dbsync_create(host_type, db_type, path, sql_statement)`
pub fn dbsync_create(host_type: i32, db_type: i32, path: Option<&[u8]>, sql_statement: Option<&[u8]>) -> DbSyncHandle {
    create(host_type, db_type, path, sql_statement, DbManagement::Volatile, None)
}

/// `dbsync_create_persistent(host_type, db_type, path, sql_statement,
/// upgrade_statements)`
pub fn dbsync_create_persistent(
    host_type: i32,
    db_type: i32,
    path: Option<&[u8]>,
    sql_statement: Option<&[u8]>,
    upgrade_statements: Option<&[&[u8]]>,
) -> DbSyncHandle {
    create(host_type, db_type, path, sql_statement, DbManagement::Persistent, upgrade_statements)
}

/// `dbsync_teardown()`
pub fn dbsync_teardown() {
    dbsync::teardown();
}

/// `{"inode": n}` → `{"inode": "n"}` (`convert_inode`)
fn convert_inode(obj: &mut Value) -> R {
    if obj.contains("inode") {
        let n = j(j(obj.at("inode"))?.get_u64())?;
        j(obj.set(b"inode", Value::Str(n.to_string().into_bytes())))?;
    }
    Ok(())
}

/// `dbsync_create_txn(handle, tables, thread_number, max_queue_size,
/// callback_data)`
pub fn dbsync_create_txn(
    handle: DbSyncHandle,
    tables: Option<&Json>,
    thread_number: u32,
    max_queue_size: u32,
    callback_data: Option<CallbackData>,
) -> TxnHandle {
    let _ = thread_number;
    let mut txn = 0;
    let msg = match (handle, tables, max_queue_size, callback_data) {
        (h, Some(tables), q, Some(cb)) if h != 0 && q != 0 => {
            let wrapper: crate::ResultCallback = Arc::new(move |t: ReturnTypeCallback, v: &Value| -> R {
                let mut patched = v.clone();
                convert_inode(&mut patched)?;
                if patched.contains("new") {
                    convert_inode(j(patched.index_mut(b"new"))?)?;
                }
                if patched.contains("old") {
                    convert_inode(j(patched.index_mut(b"old"))?)?;
                }
                let c = to_cjson(&patched)?;
                cb(t, c.as_ref());
                Ok(())
            });
            let r = to_nlohmann(tables).and_then(|t| dbsync::txn_create(handle, &t, max_queue_size, wrapper));
            match r {
                Ok(h) => {
                    txn = h;
                    Vec::new()
                }
                Err(e) => catch(Err(e), NO_JSON).0,
            }
        }
        _ => b"Invalid parameters.".to_vec(),
    };
    log_message(&msg);
    txn
}

/// `dbsync_close_txn(txn)`
pub fn dbsync_close_txn(txn: TxnHandle) -> i32 {
    if txn == 0 {
        log_message(b"Invalid txn.");
        return -1;
    }
    finish(dbsync::txn_destroy(txn), NO_JSON)
}

/// `dbsync_sync_txn_row(txn, js_input)`
pub fn dbsync_sync_txn_row(txn: TxnHandle, js_input: Option<&Json>) -> i32 {
    let (Some(js), true) = (js_input, txn != 0) else {
        log_message(b"Invalid txn or json.");
        return -1;
    };
    finish(to_nlohmann(js).and_then(|v| dbsync::txn_sync_row(txn, &v)), NO_JSON)
}

/// `dbsync_add_table_relationship(handle, js_input)`
pub fn dbsync_add_table_relationship(handle: DbSyncHandle, js_input: Option<&Json>) -> i32 {
    let (Some(js), true) = (js_input, handle != 0) else {
        log_message(b"Invalid parameters.");
        return -1;
    };
    finish(to_nlohmann(js).and_then(|v| DbSyncImplementation::instance().add_table_relationship(handle, &v)), JSON)
}

/// `dbsync_insert_data(handle, js_insert)`
pub fn dbsync_insert_data(handle: DbSyncHandle, js_insert: Option<&Json>) -> i32 {
    let (Some(js), true) = (js_insert, handle != 0) else {
        log_message(b"Invalid handle or json.");
        return -1;
    };
    finish(to_nlohmann(js).and_then(|v| DbSyncImplementation::instance().insert_bulk_data(handle, &v)), JSON_MAX_ROWS)
}

/// `dbsync_set_table_max_rows(handle, table, max_rows)`
pub fn dbsync_set_table_max_rows(handle: DbSyncHandle, table: Option<&[u8]>, max_rows: i64) -> i32 {
    let (Some(table), true) = (table, handle != 0) else {
        log_message(b"Invalid parameters.");
        return -1;
    };
    finish(DbSyncImplementation::instance().set_max_rows(handle, cstr(table), max_rows), NO_JSON)
}

/// The callback wrapper of the synchronous functions.
fn plain_wrapper(cb: &CallbackData) -> impl FnMut(ReturnTypeCallback, &Value) -> R + '_ {
    move |t: ReturnTypeCallback, v: &Value| -> R {
        let c = to_cjson(v)?;
        cb(t, c.as_ref());
        Ok(())
    }
}

/// `dbsync_sync_row(handle, js_input, callback_data)`
pub fn dbsync_sync_row(handle: DbSyncHandle, js_input: Option<&Json>, callback_data: Option<CallbackData>) -> i32 {
    let (Some(js), Some(cb), true) = (js_input, callback_data, handle != 0) else {
        log_message(b"Invalid input parameters.");
        return -1;
    };
    let mut w = plain_wrapper(&cb);
    finish(to_nlohmann(js).and_then(|v| DbSyncImplementation::instance().sync_row_data(handle, &v, &mut w)), JSON)
}

/// `dbsync_select_rows(handle, js_data_input, callback_data)`
pub fn dbsync_select_rows(handle: DbSyncHandle, js_data_input: Option<&Json>, callback_data: Option<CallbackData>) -> i32 {
    let (Some(js), Some(cb), true) = (js_data_input, callback_data, handle != 0) else {
        log_message(b"Invalid input parameters.");
        return -1;
    };
    let mut w = plain_wrapper(&cb);
    finish(to_nlohmann(js).and_then(|v| DbSyncImplementation::instance().select_data(handle, &v, &mut w)), JSON)
}

/// `dbsync_delete_rows(handle, js_key_values)`
pub fn dbsync_delete_rows(handle: DbSyncHandle, js_key_values: Option<&Json>) -> i32 {
    let (Some(js), true) = (js_key_values, handle != 0) else {
        log_message(b"Invalid input parameters.");
        return -1;
    };
    finish(to_nlohmann(js).and_then(|v| DbSyncImplementation::instance().delete_rows_data(handle, &v)), JSON)
}

/// `dbsync_get_deleted_rows(txn, callback_data)`
pub fn dbsync_get_deleted_rows(txn: TxnHandle, callback_data: Option<CallbackData>) -> i32 {
    let (Some(cb), true) = (callback_data, txn != 0) else {
        log_message(b"Invalid txn or callback.");
        return -1;
    };
    let mut w = move |t: ReturnTypeCallback, v: &Value| -> R {
        let mut patched = v.clone();
        if patched.contains("inode") {
            let n = j(j(patched.at("inode"))?.get_u64())?;
            j(patched.set(b"inode", Value::Str(n.to_string().into_bytes())))?;
        }
        let c = to_cjson(&patched)?;
        cb(t, c.as_ref());
        Ok(())
    };
    finish(dbsync::txn_get_deleted(txn, &mut w), NO_JSON)
}

/// `dbsync_update_with_snapshot(handle, js_snapshot, js_result)`: the
/// result object, or `None` on error. `Some(None)`, a NULL result, does
/// not happen: "no changes" is the JSON null.
pub fn dbsync_update_with_snapshot(handle: DbSyncHandle, js_snapshot: Option<&Json>, want_result: bool) -> (i32, Option<Option<Json>>) {
    let (Some(js), true, true) = (js_snapshot, want_result, handle != 0) else {
        log_message(b"Invalid input parameter.");
        return (-1, None);
    };
    let mut out = None;
    let r = (|| -> R {
        let v = to_nlohmann(js)?;
        let mut result = Value::Null;
        dbsync::DBSync::from_handle(handle).update_with_snapshot(&v, &mut result)?;
        out = Some(to_cjson(&result)?);
        Ok(())
    })();
    (finish(r, JSON_MAX_ROWS), out)
}

/// `dbsync_update_with_snapshot_cb(handle, js_snapshot, callback_data)`
pub fn dbsync_update_with_snapshot_cb(handle: DbSyncHandle, js_snapshot: Option<&Json>, callback_data: Option<CallbackData>) -> i32 {
    let (Some(js), Some(cb), true) = (js_snapshot, callback_data, handle != 0) else {
        log_message(b"Invalid input parameters.");
        return -1;
    };
    let mut w = plain_wrapper(&cb);
    finish(to_nlohmann(js).and_then(|v| DbSyncImplementation::instance().update_snapshot_data(handle, &v, &mut w)), JSON)
}
