//! `SQLiteDBEngine` (dbsync/src/sqlite/sqlite_dbengine.cpp): the tables'
//! metadata, the statement cache, snapshots through `_TEMP` copies, row
//! diffs, the transaction status field and the row limits.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use siem_njson::Value;
use siem_sqlite::{SQLITE_DONE, SQLITE_ERROR, SQLITE_ROW};

use crate::cconv;
use crate::error::*;
use crate::sqlite::{Connection, Statement, Transaction, SQLITE_FLOAT, SQLITE_INTEGER, SQLITE_TEXT};
use crate::{DbManagement, Locking, ReturnTypeCallback};

pub const TEMP_TABLE_SUBFIX: &[u8] = b"_TEMP";
pub const STATUS_FIELD_NAME: &[u8] = b"db_status_field_dm";
const STATUS_FIELD_TYPE: &[u8] = b"INTEGER";
const CACHE_STMT_LIMIT: usize = 30;
const MAX_TRIES: u8 = 10;

/// The result callback (`DbSync::ResultCallback`); it may throw.
pub type Callback<'a> = &'a mut dyn FnMut(ReturnTypeCallback, &Value) -> R;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ColumnType {
    Unknown = 0,
    Text,
    Integer,
    BigInt,
    UnsignedBigInt,
    Double,
    Blob,
}

/// `ColumnTypeNames`
fn column_type_by_name(name: &[u8]) -> Option<ColumnType> {
    Some(match name {
        b"UNKNOWN" => ColumnType::Unknown,
        b"TEXT" => ColumnType::Text,
        b"INTEGER" => ColumnType::Integer,
        b"BIGINT" => ColumnType::BigInt,
        b"UNSIGNED BIGINT" => ColumnType::UnsignedBigInt,
        b"DOUBLE" => ColumnType::Double,
        b"BLOB" => ColumnType::Blob,
        _ => return None,
    })
}

/// `ColumnData`: (cid, name, type, pk, txn status field)
#[derive(Clone, Debug)]
struct ColumnData {
    cid: i32,
    name: Vec<u8>,
    ty: ColumnType,
    pk: bool,
    status: bool,
}

type TableColumns = Vec<ColumnData>;

/// `TableField`: (type, string, integer, bigint, unsigned bigint, double)
#[derive(Clone, Debug)]
struct TableField {
    ty: ColumnType,
    s: Vec<u8>,
    i: i64,
    bi: i64,
    ubi: u64,
    d: f64,
}

impl TableField {
    fn new(ty: ColumnType) -> TableField {
        TableField { ty, s: Vec::new(), i: 0, bi: 0, ubi: 0, d: 0.0 }
    }
}

/// `Row`: a `std::map` by column name.
type Row = BTreeMap<Vec<u8>, TableField>;

struct MaxRows {
    max_rows: i64,
    current_rows: i64,
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `s = s.substr(0, s.size() - n)`: a shorter string stays whole (the
/// count wraps around).
fn cut(s: &mut Vec<u8>, n: usize) {
    if s.len() >= n {
        s.truncate(s.len() - n);
    }
}

/// `std::string(json)`
fn jstr(v: &Value) -> R<Vec<u8>> {
    j(v.get_string())
}

/// `std::find(array.begin(), array.end(), key)` over a JSON array of names.
fn json_contains_str(arr: &Value, key: &[u8]) -> bool {
    arr.iter().iter().any(|v| matches!(v, Value::Str(s) if s == key))
}

/// The engine (`IDbEngine`).
pub struct SqliteDbEngine {
    table_fields: Mutex<BTreeMap<Vec<u8>, TableColumns>>,
    statements_cache: Mutex<VecDeque<(Vec<u8>, Arc<Statement>)>>,
    conn: Arc<Connection>,
    transaction: Mutex<Option<Transaction>>,
    max_rows: Mutex<HashMap<Vec<u8>, MaxRows>>,
}

impl Drop for SqliteDbEngine {
    fn drop(&mut self) {
        self.statements_cache.lock().clear();
        if let Some(t) = self.transaction.lock().as_mut() {
            let _ = t.commit();
        }
    }
}

impl SqliteDbEngine {
    /// `SQLiteDBEngine(factory, path, tableStmtCreation, dbManagement,
    /// upgradeStatements)`
    pub fn new(path: &[u8], table_stmt_creation: &[u8], db_management: DbManagement, upgrade_statements: &[Vec<u8>]) -> R<SqliteDbEngine> {
        if path.is_empty() {
            return Err(Error::dbengine(EMPTY_DATABASE_PATH));
        }
        let current_version = upgrade_statements.len() + 1;
        let mut engine: Option<SqliteDbEngine> = None;
        let make = |conn: Arc<Connection>| SqliteDbEngine {
            table_fields: Mutex::new(BTreeMap::new()),
            statements_cache: Mutex::new(VecDeque::new()),
            conn,
            transaction: Mutex::new(None),
            max_rows: Mutex::new(HashMap::new()),
        };
        let recreate = |engine: &mut Option<SqliteDbEngine>| -> R {
            clean_db(path)?;
            let e = make(Connection::new(path)?);
            let e = engine.insert(e);
            let queries = split(table_stmt_creation, b';');
            e.conn.execute(b"PRAGMA temp_store = memory;")?;
            e.conn.execute(b"PRAGMA journal_mode = truncate;")?;
            e.conn.execute(b"PRAGMA synchronous = OFF;")?;
            e.conn.execute(format!("PRAGMA user_version = {current_version};").as_bytes())?;
            for q in &queries {
                let stmt = e.get_statement(q)?;
                if stmt.step()? != SQLITE_DONE {
                    return Err(Error::dbengine(STEP_ERROR_CREATE_STMT));
                }
            }
            *e.transaction.lock() = Some(Transaction::new(&e.conn)?);
            Ok(())
        };
        match db_management {
            DbManagement::Persistent => {
                let conn = Connection::new(path)?;
                let db_version = get_db_version(&conn)?;
                if db_version == 0 {
                    drop(conn);
                    recreate(&mut engine)?;
                } else {
                    let e = engine.insert(make(conn));
                    if db_version < current_version {
                        for i in db_version - 1..upgrade_statements.len() {
                            let mut transaction = Transaction::new(&e.conn)?;
                            let stmt = Statement::new(&e.conn, &upgrade_statements[i])?;
                            if stmt.step()? != SQLITE_DONE {
                                return Err(Error::dbengine(STEP_ERROR_UPDATE_STMT));
                            }
                            transaction.commit()?;
                            e.conn.execute(format!("PRAGMA user_version = {};", i + 2).as_bytes())?;
                        }
                        *e.transaction.lock() = Some(Transaction::new(&e.conn)?);
                    }
                }
            }
            DbManagement::Volatile => recreate(&mut engine)?,
        }
        Ok(engine.expect("engine initialized"))
    }

    // ------------------------------------------------------------ public

    /// `setMaxRows(table, maxRows)`
    pub fn set_max_rows(&self, table: &[u8], max_rows: i64) -> R {
        if self.load_table_data(table)? != 0 {
            let mut m = self.max_rows.lock();
            if max_rows < 0 {
                return Err(Error::dbengine(MIN_ROW_LIMIT_BELOW_ZERO));
            } else if max_rows == 0 {
                m.remove(table);
            } else {
                let stmt = self.get_statement(&cat(&[b"SELECT COUNT(*) FROM ", table, b";"]))?;
                if stmt.step()? == SQLITE_ROW {
                    let current_rows = stmt.value_i64(0);
                    m.insert(table.to_vec(), MaxRows { max_rows, current_rows });
                } else {
                    return Err(Error::dbengine(SQL_STMT_ERROR));
                }
            }
            Ok(())
        } else {
            Err(Error::dbengine(EMPTY_TABLE_METADATA))
        }
    }

    /// `bulkInsert(table, data)` (JSON rows)
    pub fn bulk_insert(&self, table: &[u8], data: &Value) -> R {
        if self.load_table_data(table)? != 0 {
            let fields = self.fields(table);
            for element in data.iter() {
                self.insert_element(table, &fields, element, None)?;
            }
            Ok(())
        } else {
            Err(Error::dbengine(EMPTY_TABLE_METADATA))
        }
    }

    /// `refreshTableData(data, callback, lock)`
    pub fn refresh_table_data(&self, data: &Value, callback: Callback, lock: &mut dyn Locking) -> R {
        let t = j(data.at("table"))?;
        let table = if let Value::Str(s) = t { s.clone() } else { Vec::new() };
        if self.create_copy_temp_table(&table)? {
            self.bulk_insert(&cat(&[&table, TEMP_TABLE_SUBFIX]), j(data.at("data"))?)?;
            if self.load_table_data(&table)? != 0 {
                let mut primary_key_list = Vec::new();
                if self.get_primary_keys_from_table(&table, &mut primary_key_list) {
                    if !self.remove_not_exists_rows(&table, &primary_key_list, callback, lock)? {
                        println!("Error during the delete rows update");
                    }
                    if !self.change_modified_rows(&table, &primary_key_list, callback, lock)? {
                        println!("Error during the change of modified rows");
                    }
                    self.insert_new_rows(&table, &primary_key_list, callback, lock)?;
                }
            } else {
                return Err(Error::dbengine(EMPTY_TABLE_METADATA));
            }
        }
        Ok(())
    }

    /// `syncTableRowData(jsInput, callback, inTransaction, lock)`
    pub fn sync_table_row_data(&self, js_input: &Value, callback: Callback, in_transaction: bool, lock: &mut dyn Locking) -> R {
        let table_json = j(js_input.at("table"))?;
        let data = j(js_input.at("data"))?;
        let mut return_old_data = false;
        let mut ignored_columns = Value::Null;
        if let Some(opts) = js_input.find(b"options") {
            if let Some(v) = opts.find(b"return_old_data") {
                if let Value::Bool(b) = v {
                    return_old_data = *b;
                }
            }
            if let Some(v) = opts.find(b"ignore") {
                if v.is_array() {
                    ignored_columns = v.clone();
                }
            }
        }
        // getDataToUpdate
        let get_data_to_update = |primary_key_list: &[Vec<u8>], result: &Value, data_param: &Value| -> R<Value> {
            let mut ret = Value::Null;
            if in_transaction {
                if result.empty() {
                    for pk in primary_key_list {
                        if let Some(v) = data_param.find(pk) {
                            j(ret.set(pk, v.clone()))?;
                        }
                    }
                } else {
                    ret = result.clone();
                }
                j(ret.set(STATUS_FIELD_NAME, Value::Int(1)))?;
            } else if !result.empty() {
                ret = result.clone();
            }
            Ok(ret)
        };
        let mut primary_key_list = Vec::new();
        if self.load_table_data(&jstr(table_json)?)? != 0 {
            let table = jstr(table_json)?;
            if self.get_primary_keys_from_table(&table, &mut primary_key_list) {
                for entry in data.iter() {
                    let mut updated = Value::Null;
                    let mut old_data = Value::Null;
                    let diff_exist = self.get_row_diff(&primary_key_list, &ignored_columns, &table, entry, &mut updated, &mut old_data)?;
                    if diff_exist {
                        let js_data_to_update = get_data_to_update(&primary_key_list, &updated, entry)?;
                        if !js_data_to_update.empty() {
                            self.update_single_row(&table, &js_data_to_update)?;
                            if !updated.empty() {
                                lock.unlock();
                                if return_old_data {
                                    let mut diff = Value::Null;
                                    j(diff.set(b"old", old_data.clone()))?;
                                    j(diff.set(b"new", updated.clone()))?;
                                    callback(ReturnTypeCallback::Modified, &diff)?;
                                } else {
                                    callback(ReturnTypeCallback::Modified, &updated)?;
                                }
                                lock.lock();
                            }
                        }
                    } else {
                        let fields = self.fields(&table);
                        let mut inserted = || -> R {
                            lock.unlock();
                            callback(ReturnTypeCallback::Inserted, entry)?;
                            lock.lock();
                            Ok(())
                        };
                        self.insert_element(&table, &fields, entry, Some(&mut inserted))?;
                    }
                }
            }
            Ok(())
        } else {
            Err(Error::dbengine(EMPTY_TABLE_METADATA))
        }
    }

    /// `initializeStatusField(tableNames)`
    pub fn initialize_status_field(&self, table_names: &Value) -> R {
        for table_value in table_names.iter() {
            let table = jstr(table_value)?;
            if self.load_table_data(&table)? != 0 {
                let fields = self.fields(&table);
                if !fields.iter().any(|c| c.name == STATUS_FIELD_NAME) {
                    self.table_fields.lock().remove(&table);
                    let stmt_add = self.get_statement(&cat(&[
                        b"ALTER TABLE ",
                        &table,
                        b" ADD COLUMN ",
                        STATUS_FIELD_NAME,
                        b" ",
                        STATUS_FIELD_TYPE,
                        b" DEFAULT 1;",
                    ]))?;
                    if stmt_add.step()? == SQLITE_ERROR {
                        return Err(Error::dbengine(STEP_ERROR_UPDATE_STATUS_FIELD));
                    }
                }
                let stmt_init = self.get_statement(&cat(&[b"UPDATE ", &table, b" SET ", STATUS_FIELD_NAME, b"=0;"]))?;
                if stmt_init.step()? == SQLITE_ERROR {
                    return Err(Error::dbengine(STEP_ERROR_ADD_STATUS_FIELD));
                }
            } else {
                return Err(Error::dbengine(EMPTY_TABLE_METADATA));
            }
        }
        Ok(())
    }

    /// `deleteRowsByStatusField(tableNames)`
    pub fn delete_rows_by_status_field(&self, table_names: &Value) -> R {
        for table_value in table_names.iter() {
            let table = jstr(table_value)?;
            if self.load_table_data(&table)? != 0 {
                let stmt = self.get_statement(&cat(&[b"DELETE FROM ", &table, b" WHERE ", STATUS_FIELD_NAME, b"=0;"]))?;
                if stmt.step()? == SQLITE_ERROR {
                    return Err(Error::dbengine(STEP_ERROR_DELETE_STATUS_FIELD));
                }
                self.update_table_row_counter(&table, -self.conn.changes())?;
            } else {
                return Err(Error::dbengine(EMPTY_TABLE_METADATA));
            }
        }
        Ok(())
    }

    /// `returnRowsMarkedForDelete(tableNames, callback, lock)`
    pub fn return_rows_marked_for_delete(&self, table_names: &Value, callback: Callback, lock: &mut dyn Locking) -> R {
        {
            let mut t = self.transaction.lock();
            // m_transaction->commit() on a NULL unique_ptr crashes the C++
            // (a persistent database already at the current version).
            let tr = t.as_mut().expect("dbsync: no open transaction (the C++ dereferences a NULL m_transaction here)");
            tr.commit()?;
            *t = Some(Transaction::new(&self.conn)?);
        }
        for table_value in table_names.iter() {
            let table = jstr(table_value)?;
            if self.load_table_data(&table)? != 0 {
                let table_fields = self.fields(&table);
                let stmt = self.get_statement(&get_select_all_query(&table, &table_fields)?)?;
                while stmt.step()? == SQLITE_ROW {
                    let mut register_fields = Row::new();
                    for (index, field) in table_fields.iter().enumerate() {
                        if !field.status {
                            get_table_data(&stmt, index as i32, field.ty, &field.name, &mut register_fields)?;
                        }
                    }
                    let mut object = Value::Null;
                    for (k, v) in &register_fields {
                        field_to_json(k, v, &mut object)?;
                    }
                    lock.unlock();
                    callback(ReturnTypeCallback::Deleted, &object)?;
                    lock.lock();
                }
            } else {
                return Err(Error::dbengine(EMPTY_TABLE_METADATA));
            }
        }
        Ok(())
    }

    /// `selectData(table, query, callback, lock)`
    pub fn select_data(&self, table: &[u8], query: &Value, callback: Callback, lock: &mut dyn Locking) -> R {
        if self.load_table_data(table)? != 0 {
            let stmt = Statement::new(&self.conn, &build_select_query(table, query)?)?;
            if let Some(params) = query.find(b"row_filter_params") {
                if let Value::Array(params) = params {
                    let mut param_index = 1;
                    for param in params {
                        let ty = j(j(param.at("type"))?.get_ref_str())?;
                        if ty == b"text" {
                            stmt.bind_text(param_index, &jstr(j(param.at("value"))?)?)?;
                        } else if ty == b"int" {
                            stmt.bind_i64(param_index, j(j(param.at("value"))?.get_i64_arith())?)?;
                        } else {
                            return Err(Error::dbengine(INVALID_DATA_BIND));
                        }
                        param_index += 1;
                    }
                }
            }
            while stmt.step()? == SQLITE_ROW {
                let mut object = Value::Null;
                for i in 0..stmt.columns_count() {
                    let name = stmt.column_name(i);
                    if stmt.has_value(i) && name != STATUS_FIELD_NAME {
                        let v = match stmt.column_type(i) {
                            SQLITE_TEXT => Value::Str(stmt.value_string(i)),
                            SQLITE_INTEGER => Value::Int(stmt.value_i64(i)),
                            SQLITE_FLOAT => Value::Float(stmt.value_f64(i)),
                            _ => return Err(Error::dbengine(INVALID_COLUMN_TYPE)),
                        };
                        j(object.set(&name, v))?;
                    }
                }
                if !object.empty() {
                    lock.unlock();
                    callback(ReturnTypeCallback::Selected, &object)?;
                    lock.lock();
                }
            }
            Ok(())
        } else {
            Err(Error::dbengine(EMPTY_TABLE_METADATA))
        }
    }

    /// `deleteTableRowsData(table, jsDeletionData)`
    pub fn delete_table_rows_data(&self, table: &[u8], js_deletion_data: &Value) -> R {
        if self.load_table_data(table)? != 0 {
            let it_data = js_deletion_data.find(b"data");
            let it_filter = js_deletion_data.find(b"where_filter_opt");
            if let Some(d) = it_data.filter(|d| d.size() > 0) {
                self.delete_rows_by_pk(table, d)
            } else if let Some(f) = it_filter.map(jstr).transpose()?.filter(|f| !f.is_empty()) {
                self.conn.execute(&cat(&[b"DELETE FROM ", table, b" WHERE ", &f]))?;
                self.update_table_row_counter(table, -self.conn.changes())
            } else {
                Err(Error::dbengine(INVALID_DELETE_INFO))
            }
        } else {
            Err(Error::dbengine(EMPTY_TABLE_METADATA))
        }
    }

    /// `addTableRelationship(data)`
    pub fn add_table_relationship(&self, data: &Value) -> R {
        let base_table = jstr(j(data.at("base_table"))?)?;
        if self.load_table_data(&base_table)? != 0 {
            let mut primary_keys = Vec::new();
            if self.get_primary_keys_from_table(&base_table, &mut primary_keys) {
                self.conn.execute(&build_delete_relation_trigger(data, &base_table)?)?;
                self.conn.execute(&build_update_relation_trigger(data, &base_table, &primary_keys)?)?;
            }
            Ok(())
        } else {
            Err(Error::dbengine(EMPTY_TABLE_METADATA))
        }
    }

    // ----------------------------------------------------------- private

    /// `m_tableFields[table]` (a copy; empty when unknown)
    fn fields(&self, table: &[u8]) -> TableColumns {
        self.table_fields.lock().get(table).cloned().unwrap_or_default()
    }

    /// `getStatement(sql)`: cached statements are reset and shared.
    fn get_statement(&self, sql: &[u8]) -> R<Arc<Statement>> {
        let mut cache = self.statements_cache.lock();
        if let Some((_, s)) = cache.iter().find(|(q, _)| q == sql) {
            s.reset();
            return Ok(s.clone());
        }
        let st = Arc::new(Statement::new(&self.conn, sql)?);
        cache.push_back((sql.to_vec(), st));
        if CACHE_STMT_LIMIT <= cache.len() {
            cache.pop_front();
        }
        Ok(cache.back().unwrap().1.clone())
    }

    /// `insertElement(table, tableColumns, element, callback)`
    fn insert_element(&self, table: &[u8], fields: &TableColumns, element: &Value, callback: Option<&mut dyn FnMut() -> R>) -> R {
        let stmt = self.get_statement(&self.build_insert_data_sql_query(table, Some(element))?)?;
        let mut index = 1;
        for field in fields {
            if bind_json_data(&stmt, field, element, index)? {
                index += 1;
            }
        }
        self.update_table_row_counter(table, 1)?;
        if stmt.step()? == SQLITE_ERROR {
            self.update_table_row_counter(table, -1)?;
            return Err(Error::dbengine(BIND_FIELDS_DOES_NOT_MATCH));
        }
        if let Some(cb) = callback {
            cb()?;
        }
        Ok(())
    }

    /// `loadTableData(table)`: the number of columns (loading them once).
    fn load_table_data(&self, table: &[u8]) -> R<usize> {
        let n = self.fields(table).len();
        if n == 0 {
            if self.load_field_data(table)? {
                return Ok(self.fields(table).len());
            }
            return Ok(0);
        }
        Ok(n)
    }

    /// `buildInsertDataSqlQuery(table, data)`
    fn build_insert_data_sql_query(&self, table: &[u8], data: Option<&Value>) -> R<Vec<u8>> {
        let mut sql = cat(&[b"INSERT INTO ", table, b" ("]);
        let mut binds = b") VALUES (".to_vec();
        let fields = self.fields(table);
        if fields.is_empty() {
            return Err(Error::dbengine(SQL_STMT_ERROR));
        }
        for field in &fields {
            let take = match data {
                None => true,
                Some(d) => d.empty() || d.find(&field.name).is_some(),
            };
            if take {
                sql.extend_from_slice(&field.name);
                sql.push(b',');
                binds.extend_from_slice(b"?,");
            }
        }
        binds.pop();
        sql.pop();
        binds.extend_from_slice(b");");
        sql.extend_from_slice(&binds);
        Ok(sql)
    }

    /// `loadFieldData(table)`
    fn load_field_data(&self, table: &[u8]) -> R<bool> {
        let ret = !table.is_empty();
        let sql = cat(&[b"PRAGMA table_info(", table, b");"]);
        if ret {
            let mut field_list = Vec::new();
            let stmt = Statement::new(&self.conn, &sql)?;
            while stmt.step()? == SQLITE_ROW {
                let field_name = stmt.value_string(1);
                let status = field_name == STATUS_FIELD_NAME;
                field_list.push(ColumnData {
                    cid: stmt.value_i32(0),
                    name: field_name,
                    ty: column_type_name(&stmt.value_string(2)),
                    pk: stmt.value_i32(5) != 0,
                    status,
                });
            }
            self.table_fields.lock().entry(table.to_vec()).or_insert(field_list);
        }
        Ok(ret)
    }

    /// `createCopyTempTable(table)`
    fn create_copy_temp_table(&self, table: &[u8]) -> R<bool> {
        let mut ret = false;
        let mut query_result = Vec::new();
        self.delete_temp_table(table);
        if self.get_table_create_query(table, &mut query_result)? {
            let from = cat(&[b"CREATE TABLE ", table]);
            let to = cat(&[b"CREATE TEMP TABLE IF NOT EXISTS ", table, b"_TEMP"]);
            if replace_all(&mut query_result, &from, &to) {
                let stmt = self.get_statement(&query_result)?;
                ret = stmt.step()? == SQLITE_DONE;
            }
        }
        Ok(ret)
    }

    /// `deleteTempTable(table)` (errors ignored)
    fn delete_temp_table(&self, table: &[u8]) {
        let _ = self.conn.execute(&cat(&[b"DELETE FROM ", table, TEMP_TABLE_SUBFIX, b";"]));
    }

    /// `getTableCreateQuery(table, resultQuery)`
    fn get_table_create_query(&self, table: &[u8], result_query: &mut Vec<u8>) -> R<bool> {
        let mut ret = false;
        if !table.is_empty() {
            let stmt = self.get_statement(b"SELECT sql FROM sqlite_master WHERE type='table' AND name=?;")?;
            stmt.bind_text(1, table)?;
            while stmt.step()? == SQLITE_ROW {
                result_query.extend_from_slice(&stmt.value_string(0));
                result_query.push(b';');
                ret = true;
            }
        }
        Ok(ret)
    }

    /// `removeNotExistsRows(table, primaryKeyList, callback, lock)`
    fn remove_not_exists_rows(&self, table: &[u8], pks: &[Vec<u8>], callback: Callback, lock: &mut dyn Locking) -> R<bool> {
        let mut row_keys_value = Vec::new();
        if self.get_pk_list_left_only(table, &cat(&[table, TEMP_TABLE_SUBFIX]), pks, &mut row_keys_value)? {
            if self.delete_rows(table, pks, &row_keys_value)? {
                for row in &row_keys_value {
                    let mut object = Value::Null;
                    for (k, v) in row {
                        field_to_json(k, v, &mut object)?;
                    }
                    lock.unlock();
                    callback(ReturnTypeCallback::Deleted, &object)?;
                    lock.lock();
                }
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `getPrimaryKeysFromTable(table, primaryKeyList)`: true when the
    /// table has columns (keys or not).
    fn get_primary_keys_from_table(&self, table: &[u8], primary_key_list: &mut Vec<Vec<u8>>) -> bool {
        let mut ret = false;
        for value in self.fields(table) {
            if value.pk {
                primary_key_list.push(value.name.clone());
            }
            ret = true;
        }
        ret
    }

    /// `getLeftOnly(t1, t2, primaryKeyList, returnRows)`
    fn get_left_only(&self, t1: &[u8], t2: &[u8], pks: &[Vec<u8>], return_rows: &mut Vec<Row>) -> R<bool> {
        let query = build_left_only_query(t1, t2, pks, false);
        if !t1.is_empty() && !query.is_empty() {
            let stmt = self.get_statement(&query)?;
            let table_fields = self.fields(t1);
            while stmt.step()? == SQLITE_ROW {
                let mut register_fields = Row::new();
                for field in &table_fields {
                    get_table_data(&stmt, field.cid, field.ty, &field.name, &mut register_fields)?;
                }
                return_rows.push(register_fields);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// `getPKListLeftOnly(t1, t2, primaryKeyList, returnRows)`
    fn get_pk_list_left_only(&self, t1: &[u8], t2: &[u8], pks: &[Vec<u8>], return_rows: &mut Vec<Row>) -> R<bool> {
        let sql = build_left_only_query(t1, t2, pks, true);
        if !t1.is_empty() && !sql.is_empty() {
            let stmt = self.get_statement(&sql)?;
            let table_fields = self.fields(t1);
            while stmt.step()? == SQLITE_ROW {
                let mut register_fields = Row::new();
                for pk_value in pks {
                    // `auto index { 0ull };` is declared inside the loop in
                    // the C++: every key reads column 0
                    let index = 0;
                    if let Some(f) = table_fields.iter().find(|c| &c.name == pk_value) {
                        get_table_data(&stmt, index, f.ty, &f.name, &mut register_fields)?;
                    }
                }
                return_rows.push(register_fields);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// `deleteRows(table, primaryKeyList, rowsToRemove)`
    fn delete_rows(&self, table: &[u8], pks: &[Vec<u8>], rows_to_remove: &[Row]) -> R<bool> {
        let sql = build_delete_bulk_data_sql_query(table, pks)?;
        if sql.is_empty() {
            return Err(Error::dbengine(SQL_STMT_ERROR));
        }
        let stmt = self.get_statement(&sql)?;
        for row in rows_to_remove {
            let mut index = 1;
            for value in pks {
                let field = row.get(value).ok_or_else(|| Error::std("map::at"))?;
                bind_field_data(&stmt, index, field)?;
                index += 1;
            }
            if stmt.step()? == SQLITE_ERROR {
                return Err(Error::dbengine(BIND_FIELDS_DOES_NOT_MATCH));
            }
            self.update_table_row_counter(table, -self.conn.changes())?;
            stmt.reset();
        }
        Ok(true)
    }

    /// `deleteRowsbyPK(table, data)`
    fn delete_rows_by_pk(&self, table: &[u8], data: &Value) -> R {
        let mut pks = Vec::new();
        if self.get_primary_keys_from_table(table, &mut pks) {
            let table_fields = self.fields(table);
            let stmt = self.get_statement(&build_delete_bulk_data_sql_query(table, &pks)?)?;
            for js_row in data.iter() {
                let mut index = 1;
                for pk_value in &pks {
                    if let Some(f) = table_fields.iter().find(|c| &c.name == pk_value) {
                        if bind_json_data(&stmt, f, js_row, index)? {
                            index += 1;
                        }
                    }
                }
                if stmt.step()? == SQLITE_ERROR {
                    return Err(Error::dbengine(BIND_FIELDS_DOES_NOT_MATCH));
                }
                self.update_table_row_counter(table, -self.conn.changes())?;
                stmt.reset();
            }
        }
        Ok(())
    }

    /// `getRowDiff(primaryKeyList, ignoredColumns, table, data, updatedData,
    /// oldData)`: whether the row exists.
    fn get_row_diff(
        &self,
        pks: &[Vec<u8>],
        ignored_columns: &Value,
        table: &[u8],
        data: &Value,
        updated_data: &mut Value,
        old_data: &mut Value,
    ) -> R<bool> {
        let mut is_modified = false;
        let stmt = self.get_statement(&build_select_matching_pks_sql_query(table, pks)?)?;
        let table_fields = self.fields(table);
        let mut index = 1;
        for pk_value in pks {
            if let Some(f) = table_fields.iter().find(|c| &c.name == pk_value) {
                j(updated_data.set(pk_value, j(data.at_b(pk_value))?.clone()))?;
                j(old_data.set(pk_value, j(data.at_b(pk_value))?.clone()))?;
                bind_json_data(&stmt, f, data, index)?;
                index += 1;
            }
        }
        let diff_exist = stmt.step()? == SQLITE_ROW;
        if diff_exist {
            let mut registry_fields = Row::new();
            for field in &table_fields {
                get_table_data(&stmt, field.cid, field.ty, &field.name, &mut registry_fields)?;
            }
            for (k, v) in &registry_fields {
                let mut object = Value::Null;
                field_to_json(k, v, &mut object)?;
                if let Some(it) = data.find(k) {
                    let current = j(object.at_b(k))?;
                    if !it.json_eq(current) {
                        is_modified = true;
                        j(old_data.set(k, current.clone()))?;
                    }
                    j(updated_data.set(k, it.clone()))?;
                }
            }
        }
        if !is_modified {
            updated_data.clear();
            old_data.clear();
        } else if !ignored_columns.empty() {
            let have_diff_on_non_ignored =
                old_data.items().iter().any(|(k, _)| !json_contains_str(ignored_columns, k) && !pks.iter().any(|p| p == k));
            if !have_diff_on_non_ignored {
                updated_data.clear();
                old_data.clear();
            }
        }
        Ok(diff_exist)
    }

    /// `insertNewRows(table, primaryKeyList, callback, lock)`
    fn insert_new_rows(&self, table: &[u8], pks: &[Vec<u8>], callback: Callback, lock: &mut dyn Locking) -> R<bool> {
        let mut row_values = Vec::new();
        if self.get_left_only(&cat(&[table, TEMP_TABLE_SUBFIX]), table, pks, &mut row_values)? {
            self.bulk_insert_rows(table, &row_values)?;
            for row in &row_values {
                let mut object = Value::Null;
                for (k, v) in row {
                    field_to_json(k, v, &mut object)?;
                }
                lock.unlock();
                callback(ReturnTypeCallback::Inserted, &object)?;
                lock.lock();
            }
        }
        Ok(true)
    }

    /// `bulkInsert(table, rows)`
    fn bulk_insert_rows(&self, table: &[u8], data: &[Row]) -> R {
        let stmt = self.get_statement(&self.build_insert_data_sql_query(table, None)?)?;
        for row in data {
            for value in self.fields(table) {
                if let Some(f) = row.get(&value.name) {
                    bind_field_data(&stmt, value.cid + 1, f)?;
                }
            }
            self.update_table_row_counter(table, 1)?;
            if stmt.step()? == SQLITE_ERROR {
                self.update_table_row_counter(table, -1)?;
                return Err(Error::dbengine(BIND_FIELDS_DOES_NOT_MATCH));
            }
            stmt.reset();
        }
        Ok(())
    }

    /// `changeModifiedRows(table, primaryKeyList, callback, lock)`
    fn change_modified_rows(&self, table: &[u8], pks: &[Vec<u8>], callback: Callback, lock: &mut dyn Locking) -> R<bool> {
        let mut row_keys_value = Vec::new();
        if self.get_rows_to_modify(table, pks, &mut row_keys_value)? {
            if self.update_rows(table, pks, &row_keys_value)? {
                for row in &row_keys_value {
                    let mut object = Value::Null;
                    for (k, v) in row {
                        field_to_json(k, v, &mut object)?;
                    }
                    lock.unlock();
                    callback(ReturnTypeCallback::Modified, &object)?;
                    lock.lock();
                }
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `buildModifiedRowsQuery(t1, t2, primaryKeyList)`
    fn build_modified_rows_query(&self, t1: &[u8], t2: &[u8], pks: &[Vec<u8>]) -> Vec<u8> {
        let mut fields_list = Vec::new();
        let mut on_match_list = Vec::new();
        for value in pks {
            fields_list.extend_from_slice(&cat(&[b"t1.", value, b","]));
            on_match_list.extend_from_slice(&cat(&[b"t1.", value, b"=t2.", value, b" AND "]));
        }
        for value in self.fields(t1) {
            let n = &value.name;
            fields_list.extend_from_slice(&cat(&[
                b"CASE WHEN t1.",
                n,
                b"<>t2.",
                n,
                b" THEN t1.",
                n,
                b" ELSE NULL END AS DIF_",
                n,
                b",",
            ]));
        }
        fields_list.pop();
        cut(&mut on_match_list, 5);
        cat(&[
            b"SELECT ",
            &fields_list,
            b" FROM (select *,'",
            t1,
            b"' as val from ",
            t1,
            b" UNION ALL select *,'",
            t2,
            b"' as val from ",
            t2,
            b") t1 INNER JOIN ",
            t1,
            b" t2 ON ",
            &on_match_list,
            b" WHERE t1.val = '",
            t2,
            b"';",
        ])
    }

    /// `getRowsToModify(table, primaryKeyList, rowKeysValue)`
    fn get_rows_to_modify(&self, table: &[u8], pks: &[Vec<u8>], row_keys_value: &mut Vec<Row>) -> R<bool> {
        let sql = self.build_modified_rows_query(table, &cat(&[table, TEMP_TABLE_SUBFIX]), pks);
        if sql.is_empty() {
            return Err(Error::dbengine(SQL_STMT_ERROR));
        }
        let stmt = self.get_statement(&sql)?;
        while stmt.step()? == SQLITE_ROW {
            let mut data_modified = false;
            let table_fields = self.fields(table);
            let mut register_fields = Row::new();
            let mut index = 0;
            for pk_value in pks {
                if let Some(f) = table_fields.iter().find(|c| &c.name == pk_value) {
                    get_table_data(&stmt, index, f.ty, &cat(&[b"PK_", &f.name]), &mut register_fields)?;
                }
                index += 1;
            }
            for field in &table_fields {
                if !register_fields.contains_key(&field.name) && stmt.has_value(index) {
                    data_modified = true;
                    get_table_data(&stmt, index, field.ty, &field.name, &mut register_fields)?;
                }
                index += 1;
            }
            if data_modified {
                row_keys_value.push(register_fields);
            }
        }
        Ok(true)
    }

    /// `updateSingleRow(table, jsData)`
    fn update_single_row(&self, table: &[u8], js_data: &Value) -> R {
        let mut pks = Vec::new();
        if self.get_primary_keys_from_table(table, &mut pks) {
            let table_fields = self.fields(table);
            let stmt = self.get_statement(&build_update_partial_data_sql_query(table, js_data, &pks)?)?;
            let mut index = 1;
            let items = js_data.items();
            for pass_pk in [false, true] {
                for (k, _) in &items {
                    if pks.iter().any(|p| p == k) == pass_pk {
                        let Some(f) = table_fields.iter().find(|c| &c.name == k) else {
                            return Err(Error::dbengine(BIND_FIELDS_DOES_NOT_MATCH));
                        };
                        bind_json_data(&stmt, f, js_data, index)?;
                        index += 1;
                    }
                }
            }
            if stmt.step()? == SQLITE_ERROR {
                return Err(Error::dbengine(BIND_FIELDS_DOES_NOT_MATCH));
            }
            stmt.reset();
        }
        Ok(())
    }

    /// `updateRows(table, primaryKeyList, rowKeysValue)`
    fn update_rows(&self, table: &[u8], pks: &[Vec<u8>], row_keys_value: &[Row]) -> R<bool> {
        for row in row_keys_value {
            for field in row {
                if !field.0.starts_with(b"PK_") {
                    let sql = build_update_data_sql_query(table, pks, row, field)?;
                    self.conn.execute(&sql)?;
                }
            }
        }
        Ok(true)
    }

    /// `updateTableRowCounter(table, rowModifyCount)`
    fn update_table_row_counter(&self, table: &[u8], row_modify_count: i64) -> R {
        let mut m = self.max_rows.lock();
        if let Some(e) = m.get_mut(table) {
            if e.current_rows + row_modify_count > e.max_rows {
                return Err(Error::MaxRows(MAX_ROWS_ERROR_STRING.as_bytes().to_vec()));
            }
            e.current_rows += row_modify_count;
            if e.current_rows < 0 {
                e.current_rows = 0;
                return Err(Error::dbengine(ERROR_COUNT_MAX_ROWS));
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ helpers

/// `Utils::split(str, delimiter)` (`std::getline`: no trailing empty token)
fn split(s: &[u8], d: u8) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = s.split(|&c| c == d).map(|x| x.to_vec()).collect();
    if s.is_empty() || s.last() == Some(&d) {
        v.pop();
    }
    v
}

/// `Utils::replaceAll(data, toSearch, toReplace)`
pub fn replace_all(data: &mut Vec<u8>, to_search: &[u8], to_replace: &[u8]) -> bool {
    let find = |d: &[u8], from: usize| -> Option<usize> {
        if to_search.is_empty() {
            return if from <= d.len() { Some(from) } else { None };
        }
        d.get(from..)?.windows(to_search.len()).position(|w| w == to_search).map(|p| p + from)
    };
    let mut pos = find(data, 0);
    let ret = pos.is_some();
    while let Some(p) = pos {
        data.splice(p..p + to_search.len(), to_replace.iter().copied());
        pos = find(data, p + to_replace.len());
    }
    ret
}

/// `Utils::replaceFirst(data, toSearch, toReplace)`
pub fn replace_first(data: &mut Vec<u8>, to_search: &[u8], to_replace: &[u8]) -> bool {
    let pos = if to_search.is_empty() { Some(0) } else { data.windows(to_search.len()).position(|w| w == to_search) };
    if let Some(p) = pos {
        data.splice(p..p + to_search.len(), to_replace.iter().copied());
        true
    } else {
        false
    }
}

/// `cleanDB(path)`
fn clean_db(path: &[u8]) -> R {
    if path != b":memory" {
        let cpath = std::ffi::CString::new(path.split(|&c| c == 0).next().unwrap_or_default()).unwrap();
        // std::ifstream(path): opens for reading (directories too on Linux)
        let f = unsafe { libc::fopen(cpath.as_ptr(), b"r\0".as_ptr() as *const libc::c_char) };
        if !f.is_null() {
            unsafe { libc::fclose(f) };
            let remove = || -> (i32, i32) {
                let r = unsafe { libc::remove(cpath.as_ptr()) };
                (r, std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
            };
            let (mut is_removed, mut last_errno) = remove();
            let mut tries = 0u8;
            while tries < MAX_TRIES && is_removed != 0 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                crate::cerr_line(
                    &[
                        b"Failed to delete database file '".as_slice(),
                        path,
                        format!("' (errno: {}). Retry attempt {}/{}.", last_errno, tries + 1, MAX_TRIES).as_bytes(),
                    ]
                    .concat(),
                );
                (is_removed, last_errno) = remove();
                tries += 1;
            }
            if is_removed != 0 {
                crate::cerr_line(
                    &[
                        b"Failed to delete database file '".as_slice(),
                        path,
                        format!("' after {} attempts (errno: {}).", MAX_TRIES, last_errno).as_bytes(),
                    ]
                    .concat(),
                );
                let msg = format!(
                    "Error deleting old db file '{}' after {} attempts (errno: {})",
                    String::from_utf8_lossy(path),
                    MAX_TRIES,
                    last_errno
                );
                return Err(Error::dbengine((DELETE_OLD_DB_ERROR.0, &msg)));
            }
        }
    }
    Ok(())
}

/// `getDbVersion()`
fn get_db_version(conn: &Arc<Connection>) -> R<usize> {
    let stmt = Statement::new(conn, b"PRAGMA user_version;")?;
    let mut version = 0usize;
    if stmt.step()? == SQLITE_ROW {
        version = stmt.value_i32(0) as isize as usize;
    }
    Ok(version)
}

/// `columnTypeName(type)`
fn column_type_name(ty: &[u8]) -> ColumnType {
    let base = match ty.windows(7).position(|w| w == b" HIDDEN") {
        Some(p) => &ty[..p],
        None => ty,
    };
    column_type_by_name(base).unwrap_or(ColumnType::Unknown)
}

/// `bindJsonData(stmt, cd, valueType, cid)`: false when the value has no
/// such field.
fn bind_json_data(stmt: &Statement, cd: &ColumnData, value_type: &Value, cid: i32) -> R<bool> {
    let Some(js) = value_type.find(&cd.name) else {
        return Ok(false);
    };
    let nonempty_str = |v: &Value| -> Option<Vec<u8>> {
        match v {
            Value::Str(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    };
    match cd.ty {
        ColumnType::BigInt => {
            let v = if js.is_number() {
                j(js.get_i64_arith())?
            } else if let Some(s) = nonempty_str(js) {
                cconv::stoll(&s)?
            } else {
                0
            };
            stmt.bind_i64(cid, v)?;
        }
        ColumnType::UnsignedBigInt => {
            let v = if js.is_number_unsigned() {
                j(js.get_u64())?
            } else if let Some(s) = nonempty_str(js) {
                cconv::stoull(&s)?
            } else {
                0
            };
            stmt.bind_u64(cid, v)?;
        }
        ColumnType::Integer => {
            let v = if js.is_number() {
                j(js.get_i64_arith())?
            } else if let Some(s) = nonempty_str(js) {
                cconv::stoi(&s)? as i64
            } else {
                0
            };
            stmt.bind_i64(cid, v)?;
        }
        ColumnType::Text => {
            let v = if let Value::Str(s) = js { s.clone() } else { Vec::new() };
            stmt.bind_text(cid, &v)?;
        }
        ColumnType::Double => {
            let v = if js.is_number_float() {
                j(js.get_f64())?
            } else if let Some(s) = nonempty_str(js) {
                cconv::stod(&s)?
            } else {
                0.0
            };
            stmt.bind_f64(cid, v)?;
        }
        _ => return Err(Error::dbengine(INVALID_COLUMN_TYPE)),
    }
    Ok(true)
}

/// `getTableData(stmt, index, type, fieldName, row)`
fn get_table_data(stmt: &Statement, index: i32, ty: ColumnType, field_name: &[u8], row: &mut Row) -> R {
    let mut f = TableField::new(ty);
    match ty {
        ColumnType::BigInt => f.bi = stmt.value_i64(index),
        ColumnType::UnsignedBigInt => f.ubi = stmt.value_i64(index) as u64,
        ColumnType::Integer => f.i = stmt.value_i64(index),
        ColumnType::Text => f.s = stmt.value_string(index),
        ColumnType::Double => f.d = stmt.value_f64(index),
        _ => return Err(Error::dbengine(INVALID_COLUMN_TYPE)),
    }
    row.insert(field_name.to_vec(), f);
    Ok(())
}

/// `bindFieldData(stmt, index, fieldData)`
fn bind_field_data(stmt: &Statement, index: i32, f: &TableField) -> R {
    match f.ty {
        ColumnType::BigInt => stmt.bind_i64(index, f.bi),
        ColumnType::UnsignedBigInt => stmt.bind_u64(index, f.ubi),
        ColumnType::Integer => stmt.bind_i64(index, f.i),
        ColumnType::Text => stmt.bind_text(index, &f.s),
        ColumnType::Double => stmt.bind_f64(index, f.d),
        _ => Err(Error::dbengine(INVALID_DATA_BIND)),
    }
}

/// `getFieldValueFromTuple(value, object)`
fn field_to_json(name: &[u8], f: &TableField, object: &mut Value) -> R {
    let v = match f.ty {
        ColumnType::BigInt => Value::Int(f.bi),
        ColumnType::UnsignedBigInt => Value::UInt(f.ubi),
        ColumnType::Integer => Value::Int(f.i),
        ColumnType::Text => Value::Str(f.s.clone()),
        ColumnType::Double => Value::Float(f.d),
        _ => return Err(Error::dbengine(DATATYPE_NOT_IMPLEMENTED)),
    };
    j(object.set(name, v))
}

/// `getFieldValueFromTuple(value, resultValue, quotationMarks)`
fn field_to_sql(f: &TableField, out: &mut Vec<u8>, quotation_marks: bool) -> R {
    match f.ty {
        ColumnType::BigInt => out.extend_from_slice(f.bi.to_string().as_bytes()),
        ColumnType::UnsignedBigInt => out.extend_from_slice(f.ubi.to_string().as_bytes()),
        ColumnType::Integer => out.extend_from_slice(f.i.to_string().as_bytes()),
        ColumnType::Text => {
            if quotation_marks {
                out.push(b'\'');
                out.extend_from_slice(&f.s);
                out.push(b'\'');
            } else {
                out.extend_from_slice(&f.s);
            }
        }
        ColumnType::Double => out.extend_from_slice(cconv::double_to_string(f.d).as_bytes()),
        _ => return Err(Error::dbengine(DATATYPE_NOT_IMPLEMENTED)),
    }
    Ok(())
}

/// `buildDeleteBulkDataSqlQuery(table, primaryKeyList)`
fn build_delete_bulk_data_sql_query(table: &[u8], pks: &[Vec<u8>]) -> R<Vec<u8>> {
    let mut sql = cat(&[b"DELETE FROM ", table, b" WHERE "]);
    if pks.is_empty() {
        return Err(Error::dbengine(SQL_STMT_ERROR));
    }
    for v in pks {
        sql.extend_from_slice(v);
        sql.extend_from_slice(b"=? AND ");
    }
    cut(&mut sql, 5);
    sql.push(b';');
    Ok(sql)
}

/// `buildSelectQuery(table, jsQuery)`
fn build_select_query(table: &[u8], js_query: &Value) -> R<Vec<u8>> {
    let columns = j(js_query.at("column_list"))?;
    let it_filter = js_query.find(b"row_filter");
    let it_distinct = js_query.find(b"distinct_opt");
    let it_order_by = js_query.find(b"order_by_opt");
    let it_count = js_query.find(b"count_opt");
    let mut sql = b"SELECT ".to_vec();
    if let Some(d) = it_distinct {
        if j(d.get_bool())? {
            sql.extend_from_slice(b"DISTINCT ");
        }
    }
    for column in columns.iter() {
        sql.extend_from_slice(j(column.get_ref_str())?);
        sql.push(b',');
    }
    sql.pop();
    sql.extend_from_slice(b" FROM ");
    sql.extend_from_slice(table);
    if let Some(f) = it_filter {
        if !jstr(f)?.is_empty() {
            sql.push(b' ');
            sql.extend_from_slice(&jstr(f)?);
        }
    }
    if let Some(o) = it_order_by {
        if !jstr(o)?.is_empty() {
            sql.extend_from_slice(b" ORDER BY ");
            sql.extend_from_slice(&jstr(o)?);
        }
    }
    if let Some(c) = it_count {
        let limit = j(c.get_u32())?;
        sql.extend_from_slice(format!(" LIMIT {limit}").as_bytes());
    }
    sql.push(b';');
    Ok(sql)
}

/// `buildLeftOnlyQuery(t1, t2, primaryKeyList, returnOnlyPKFields)`
fn build_left_only_query(t1: &[u8], t2: &[u8], pks: &[Vec<u8>], return_only_pk_fields: bool) -> Vec<u8> {
    let mut fields_list = Vec::new();
    let mut on_match_list = Vec::new();
    let mut null_filter_list = Vec::new();
    for value in pks {
        if return_only_pk_fields {
            fields_list.extend_from_slice(&cat(&[b"t1.", value, b","]));
        }
        on_match_list.extend_from_slice(&cat(&[b"t1.", value, b"= t2.", value, b" AND "]));
        null_filter_list.extend_from_slice(&cat(&[b"t2.", value, b" IS NULL AND "]));
    }
    if return_only_pk_fields {
        fields_list.pop();
    } else {
        fields_list.push(b'*');
    }
    cut(&mut on_match_list, 5);
    cut(&mut null_filter_list, 5);
    cat(&[b"SELECT ", &fields_list, b" FROM ", t1, b" t1 LEFT JOIN ", t2, b" t2 ON ", &on_match_list, b" WHERE ", &null_filter_list, b";"])
}

/// `buildUpdatePartialDataSqlQuery(table, data, primaryKeyList)`
fn build_update_partial_data_sql_query(table: &[u8], data: &Value, pks: &[Vec<u8>]) -> R<Vec<u8>> {
    let mut sql = cat(&[b"UPDATE ", table, b" SET "]);
    if pks.is_empty() {
        return Err(Error::dbengine(SQL_STMT_ERROR));
    }
    let items = data.items();
    for (k, _) in &items {
        if !pks.iter().any(|p| p == k) {
            sql.extend_from_slice(k);
            sql.extend_from_slice(b"=?,");
        }
    }
    sql.pop();
    sql.extend_from_slice(b" WHERE ");
    for (k, _) in &items {
        if pks.iter().any(|p| p == k) {
            sql.extend_from_slice(k);
            sql.extend_from_slice(b"=? AND ");
        }
    }
    cut(&mut sql, 5);
    sql.push(b';');
    Ok(sql)
}

/// `buildSelectMatchingPKsSqlQuery(table, primaryKeyList)`
fn build_select_matching_pks_sql_query(table: &[u8], pks: &[Vec<u8>]) -> R<Vec<u8>> {
    let mut sql = cat(&[b"SELECT * FROM ", table, b" WHERE "]);
    if pks.is_empty() {
        return Err(Error::dbengine(SQL_STMT_ERROR));
    }
    for v in pks {
        sql.extend_from_slice(v);
        sql.extend_from_slice(b"=? AND ");
    }
    cut(&mut sql, 5);
    sql.push(b';');
    Ok(sql)
}

/// `buildUpdateDataSqlQuery(table, primaryKeyList, row, field)`
fn build_update_data_sql_query(table: &[u8], pks: &[Vec<u8>], row: &Row, field: (&Vec<u8>, &TableField)) -> R<Vec<u8>> {
    let mut sql = cat(&[b"UPDATE ", table, b" SET ", field.0, b"="]);
    field_to_sql(field.1, &mut sql, true)?;
    sql.extend_from_slice(b" WHERE ");
    if pks.is_empty() {
        return Err(Error::dbengine(SQL_STMT_ERROR));
    }
    for value in pks {
        if let Some(f) = row.get(&cat(&[b"PK_", value])) {
            sql.extend_from_slice(value);
            sql.push(b'=');
            field_to_sql(f, &mut sql, true)?;
        } else {
            sql.clear();
            break;
        }
        sql.extend_from_slice(b" AND ");
    }
    cut(&mut sql, 5);
    if !sql.is_empty() {
        sql.push(b';');
    }
    Ok(sql)
}

/// `getSelectAllQuery(table, tableFields)`
fn get_select_all_query(table: &[u8], table_fields: &TableColumns) -> R<Vec<u8>> {
    let mut ret = b"SELECT ".to_vec();
    if !table_fields.is_empty() && !table.is_empty() {
        for field in table_fields {
            if !field.status {
                ret.extend_from_slice(&field.name);
                ret.push(b',');
            }
        }
        ret.pop();
        ret.extend_from_slice(&cat(&[b" FROM ", table, b" WHERE ", STATUS_FIELD_NAME, b"=0;"]));
        Ok(ret)
    } else {
        Err(Error::dbengine(EMPTY_TABLE_METADATA))
    }
}

/// `buildDeleteRelationTrigger(data, baseTable)`
fn build_delete_relation_trigger(data: &Value, base_table: &[u8]) -> R<Vec<u8>> {
    let mut sql = cat(&[b"CREATE TRIGGER IF NOT EXISTS ", base_table, b"_delete BEFORE DELETE ON ", base_table]);
    sql.extend_from_slice(b" BEGIN ");
    for json_value in j(data.at("relationed_tables"))?.iter() {
        sql.extend_from_slice(&cat(&[b"DELETE FROM ", &jstr(j(json_value.at("table"))?)?, b" WHERE "]));
        for (k, v) in j(json_value.at("field_match"))?.items() {
            sql.extend_from_slice(&k);
            sql.extend_from_slice(b" = OLD.");
            sql.extend_from_slice(j(v.get_ref_str())?);
            sql.extend_from_slice(b" AND ");
        }
        cut(&mut sql, 5);
        sql.push(b';');
    }
    sql.extend_from_slice(b"END;");
    Ok(sql)
}

/// `buildUpdateRelationTrigger(data, baseTable, primaryKeys)`
fn build_update_relation_trigger(data: &Value, base_table: &[u8], primary_keys: &[Vec<u8>]) -> R<Vec<u8>> {
    let mut sql = cat(&[b"CREATE TRIGGER IF NOT EXISTS ", base_table, b"_update BEFORE UPDATE OF "]);
    for pk in primary_keys {
        sql.extend_from_slice(pk);
        sql.push(b',');
    }
    sql.pop();
    sql.extend_from_slice(&cat(&[b" ON ", base_table]));
    sql.extend_from_slice(b" BEGIN ");
    for json_value in j(data.at("relationed_tables"))?.iter() {
        sql.extend_from_slice(&cat(&[b"UPDATE ", &jstr(j(json_value.at("table"))?)?, b" SET "]));
        let mut where_ = b" WHERE ".to_vec();
        for (k, v) in j(json_value.at("field_match"))?.items() {
            let s = j(v.get_ref_str())?;
            sql.extend_from_slice(&k);
            sql.extend_from_slice(b" = NEW.");
            sql.extend_from_slice(s);
            sql.push(b',');
            where_.extend_from_slice(&k);
            where_.extend_from_slice(b" = OLD.");
            where_.extend_from_slice(s);
            where_.extend_from_slice(b" AND ");
        }
        sql.pop();
        cut(&mut where_, 5);
        sql.extend_from_slice(&where_);
        sql.push(b';');
    }
    sql.extend_from_slice(b"END;");
    Ok(sql)
}
