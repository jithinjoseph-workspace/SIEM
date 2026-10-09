//! dbsync's SQLite wrapper (`dbsync/src/sqlite/sqlite_wrapper.cpp`):
//! errors become `sqlite_error`s, a statement refuses to step (answers
//! SQLITE_ERROR) until all its parameters are bound, text columns read as
//! C strings.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use siem_sqlite::{Db, Stmt, SQLITE_DONE, SQLITE_ERROR, SQLITE_NULL, SQLITE_OK, SQLITE_ROW};

use crate::error::{Error, R};

pub use siem_sqlite::{SQLITE_FLOAT, SQLITE_INTEGER, SQLITE_TEXT};

const SQLITE_OPEN_READWRITE: i32 = siem_sqlite::SQLITE_OPEN_READWRITE;
const SQLITE_OPEN_CREATE: i32 = siem_sqlite::SQLITE_OPEN_CREATE;

/// `checkSqliteResult`
fn check(rc: i32, msg: impl FnOnce() -> Vec<u8>) -> R {
    if rc != SQLITE_OK {
        return Err(Error::sqlite(rc, &msg()));
    }
    Ok(())
}

/// `openSQLiteDb`
fn open_db(path: &[u8], flags: i32) -> R<Db> {
    let (rc, db) = Db::open_v2(path, flags);
    if rc != SQLITE_OK {
        let mut msg = b"Error opening SQLite database '".to_vec();
        msg.extend_from_slice(path);
        msg.extend_from_slice(format!("' (SQLite error code: {rc})").as_bytes());
        if let Some(d) = &db {
            msg.extend_from_slice(b": ");
            msg.extend_from_slice(&d.errmsg());
        }
        return Err(Error::sqlite(rc, &msg));
    }
    Ok(db.expect("sqlite3_open_v2 gave no connection"))
}

/// `SQLite::Connection`
pub struct Connection {
    db: Db,
}

impl Connection {
    pub fn new(path: &[u8]) -> R<Arc<Connection>> {
        let path = path.split(|&c| c == 0).next().unwrap_or_default();
        #[allow(unused_mut)]
        let mut db = open_db(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)?;
        #[cfg(unix)]
        if path != b":memory:" {
            let p = std::ffi::CString::new(path).unwrap();
            let result = unsafe { libc::chmod(p.as_ptr(), 0o640) };
            if result != 0 {
                return Err(Error::sqlite(result, b"Error changing permissions of SQLite database."));
            }
            db = open_db(path, SQLITE_OPEN_READWRITE)?;
        }
        Ok(Arc::new(Connection { db }))
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    /// `execute(query)`
    pub fn execute(&self, query: &[u8]) -> R {
        let (rc, _) = self.db.exec(query);
        check(rc, || [query, b". ", &self.db.errmsg()].concat())
    }

    /// `changes()`
    pub fn changes(&self) -> i64 {
        self.db.changes() as i64
    }
}

/// `SQLite::Transaction`: BEGIN now, ROLLBACK on drop unless committed.
pub struct Transaction {
    conn: Arc<Connection>,
    rolled_back: bool,
    committed: bool,
}

impl Transaction {
    pub fn new(conn: &Arc<Connection>) -> R<Transaction> {
        conn.execute(b"BEGIN TRANSACTION")?;
        Ok(Transaction { conn: conn.clone(), rolled_back: false, committed: false })
    }

    pub fn commit(&mut self) -> R {
        if !self.rolled_back && !self.committed {
            self.conn.execute(b"COMMIT TRANSACTION")?;
            self.committed = true;
        }
        Ok(())
    }

    pub fn rollback(&mut self) {
        if !self.rolled_back && !self.committed {
            self.rolled_back = true;
            let _ = self.conn.execute(b"ROLLBACK TRANSACTION");
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.rolled_back && !self.committed {
            let _ = self.conn.execute(b"ROLLBACK TRANSACTION");
        }
    }
}

/// `SQLite::Statement` (shared: the engine caches them).
pub struct Statement {
    conn: Arc<Connection>,
    stmt: Stmt,
    bind_parameters_count: i32,
    bind_parameters_index: AtomicI32,
}

impl Statement {
    /// `prepareSQLiteStatement` (`sqlite3_prepare_v2`, the first statement
    /// of `query`; a NULL statement for an empty one).
    pub fn new(conn: &Arc<Connection>, query: &[u8]) -> R<Statement> {
        let (rc, st, _) = conn.db.prepare_v2(query);
        check(rc, || conn.db.errmsg())?;
        let stmt = st.unwrap_or_else(Stmt::null);
        let count = stmt.bind_parameter_count();
        Ok(Statement { conn: conn.clone(), stmt, bind_parameters_count: count, bind_parameters_index: AtomicI32::new(0) })
    }

    fn errmsg(&self) -> Vec<u8> {
        self.conn.db.errmsg()
    }

    /// `step()`
    pub fn step(&self) -> R<i32> {
        let mut ret = SQLITE_ERROR;
        if self.bind_parameters_index.load(Ordering::SeqCst) == self.bind_parameters_count {
            ret = self.stmt.step();
            if ret != SQLITE_ROW && ret != SQLITE_DONE {
                check(ret, || self.errmsg())?;
            }
        }
        Ok(ret)
    }

    /// `reset()`
    pub fn reset(&self) {
        self.stmt.reset();
        self.bind_parameters_index.store(0, Ordering::SeqCst);
    }

    fn bound(&self, rc: i32) -> R {
        check(rc, || self.errmsg())?;
        self.bind_parameters_index.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    pub fn bind_i32(&self, index: i32, v: i32) -> R {
        self.bound(self.stmt.bind_int(index, v))
    }

    pub fn bind_i64(&self, index: i32, v: i64) -> R {
        self.bound(self.stmt.bind_int64(index, v))
    }

    pub fn bind_u64(&self, index: i32, v: u64) -> R {
        self.bound(self.stmt.bind_int64(index, v as i64))
    }

    /// `bind(index, std::string)`: the whole string, embedded NULs too.
    pub fn bind_text(&self, index: i32, v: &[u8]) -> R {
        self.bound(self.stmt.bind_text_len(index, v))
    }

    pub fn bind_f64(&self, index: i32, v: f64) -> R {
        self.bound(self.stmt.bind_double(index, v))
    }

    pub fn columns_count(&self) -> i32 {
        self.stmt.column_count()
    }

    pub fn has_value(&self, i: i32) -> bool {
        self.stmt.column_type(i) != SQLITE_NULL
    }

    pub fn column_type(&self, i: i32) -> i32 {
        self.stmt.column_type(i)
    }

    pub fn column_name(&self, i: i32) -> Vec<u8> {
        self.stmt.column_name(i)
    }

    pub fn value_i32(&self, i: i32) -> i32 {
        self.stmt.column_int(i)
    }

    pub fn value_i64(&self, i: i32) -> i64 {
        self.stmt.column_int64(i)
    }

    pub fn value_f64(&self, i: i32) -> f64 {
        self.stmt.column_double(i)
    }

    /// `value(std::string)`: a C string, "" for NULL.
    pub fn value_string(&self, i: i32) -> Vec<u8> {
        self.stmt.column_text(i).unwrap_or_default()
    }
}
