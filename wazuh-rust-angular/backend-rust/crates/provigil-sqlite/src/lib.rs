//! SQLite for the agent database: connections and statements as the database code uses them,
//! on the one SQLite build the whole workspace shares (`libsqlite3-sys`, bundled).
//!
//! The calls keep SQLite's own conventions, because the database code reasons in them: return
//! codes rather than `Result`s, text that ends at its first zero byte both ways, NULL as `None`.
//!
//! Every connection starts with foreign keys off, SQLite's documented default: the shared build
//! turns them on, and the agent databases rely on them being off unless a layout asks.
//!
//! Thread safety: the build is serialized (`SQLITE_THREADSAFE=1`), so connections and statements
//! may move between threads; the database code locks a connection for each request.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::ptr;

use libsqlite3_sys as ffi;

extern "C" {
    // in the bundled library; the prebuilt bindings leave it out
    fn sqlite3_close_v2(db: *mut ffi::sqlite3) -> c_int;
}

pub const SQLITE_OK: i32 = ffi::SQLITE_OK;
pub const SQLITE_ERROR: i32 = ffi::SQLITE_ERROR;
pub const SQLITE_BUSY: i32 = ffi::SQLITE_BUSY;
pub const SQLITE_CONSTRAINT: i32 = ffi::SQLITE_CONSTRAINT;
pub const SQLITE_MISUSE: i32 = ffi::SQLITE_MISUSE;
pub const SQLITE_ROW: i32 = ffi::SQLITE_ROW;
pub const SQLITE_DONE: i32 = ffi::SQLITE_DONE;

pub const SQLITE_OPEN_READONLY: i32 = ffi::SQLITE_OPEN_READONLY;
pub const SQLITE_OPEN_READWRITE: i32 = ffi::SQLITE_OPEN_READWRITE;
pub const SQLITE_OPEN_CREATE: i32 = ffi::SQLITE_OPEN_CREATE;

pub const SQLITE_INTEGER: i32 = ffi::SQLITE_INTEGER;
pub const SQLITE_FLOAT: i32 = ffi::SQLITE_FLOAT;
pub const SQLITE_TEXT: i32 = ffi::SQLITE_TEXT;
pub const SQLITE_BLOB: i32 = ffi::SQLITE_BLOB;
pub const SQLITE_NULL: i32 = ffi::SQLITE_NULL;

/// `text` up to its first zero byte, with one zero byte added (what SQLite reads).
fn zero_ended(text: &[u8]) -> Vec<u8> {
    let mut v = text[..text.iter().position(|&c| c == 0).unwrap_or(text.len())].to_vec();
    v.push(0);
    v
}

/// A zero-ended string from SQLite, copied (None for a null pointer).
fn copied(p: *const c_char) -> Option<Vec<u8>> {
    // SAFETY: SQLite returns zero-ended strings that live until the next call on the object
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// An error string SQLite allocated: copied, then freed.
fn taken(p: *mut c_char) -> Option<Vec<u8>> {
    let v = copied(p);
    if !p.is_null() {
        // SAFETY: allocated by SQLite for the caller to free
        unsafe { ffi::sqlite3_free(p as *mut c_void) };
    }
    v
}

/// A connection; closed when dropped (it stays open for SQLite until its last statement goes).
pub struct Db {
    raw: *mut ffi::sqlite3,
}

// SAFETY: serialized build (see the module notes)
unsafe impl Send for Db {}
unsafe impl Sync for Db {}

impl Db {
    /// Opens `path` with `flags`. The return code, and the connection (also when opening failed:
    /// it holds the error text) unless SQLite had no memory for it.
    pub fn open_v2(path: &[u8], flags: i32) -> (i32, Option<Db>) {
        let p = zero_ended(path);
        let mut raw = ptr::null_mut();
        // SAFETY: zero-ended path, out pointer valid
        let rc = unsafe { ffi::sqlite3_open_v2(p.as_ptr() as *const c_char, &mut raw, flags, ptr::null()) };
        let db = (!raw.is_null()).then_some(Db { raw });
        if let (SQLITE_OK, Some(d)) = (rc, &db) {
            d.exec(b"PRAGMA foreign_keys = OFF;");
        }
        (rc, db)
    }

    /// The text of the last error.
    pub fn errmsg(&self) -> Vec<u8> {
        // SAFETY: valid connection
        copied(unsafe { ffi::sqlite3_errmsg(self.raw) }).unwrap_or_default()
    }

    pub fn errmsg_str(&self) -> String {
        String::from_utf8_lossy(&self.errmsg()).into_owned()
    }

    /// Rows changed by the last statement.
    pub fn changes(&self) -> i32 {
        unsafe { ffi::sqlite3_changes(self.raw) }
    }

    pub fn last_insert_rowid(&self) -> i64 {
        unsafe { ffi::sqlite3_last_insert_rowid(self.raw) }
    }

    pub fn busy_timeout(&self, ms: i32) -> i32 {
        unsafe { ffi::sqlite3_busy_timeout(self.raw, ms) }
    }

    /// Runs `sql` (several statements allowed): the return code and SQLite's error text.
    pub fn exec(&self, sql: &[u8]) -> (i32, Option<Vec<u8>>) {
        self.exec_rows(sql, |_, _| 0)
    }

    /// [`exec`](Self::exec), calling `f` with each result row's values (NULL as None) and column
    /// names; `f` returns nonzero to stop (the return code is then `SQLITE_ABORT`).
    pub fn exec_rows(&self, sql: &[u8], mut f: impl FnMut(&[Option<&[u8]>], &[&[u8]]) -> i32) -> (i32, Option<Vec<u8>>) {
        type Row<'a> = &'a mut dyn FnMut(&[Option<&[u8]>], &[&[u8]]) -> i32;
        unsafe extern "C" fn row(arg: *mut c_void, n: c_int, values: *mut *mut c_char, names: *mut *mut c_char) -> c_int {
            // SAFETY: `arg` is the `Row` below; SQLite passes `n` zero-ended values and names
            let f = unsafe { &mut *(arg as *mut Row) };
            let n = n as usize;
            let text = |p: *mut c_char| (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes());
            let vs: Vec<Option<&[u8]>> = (0..n).map(|i| text(unsafe { *values.add(i) })).collect();
            let ns: Vec<&[u8]> = (0..n).map(|i| text(unsafe { *names.add(i) }).unwrap_or_default()).collect();
            f(&vs, &ns)
        }
        let s = zero_ended(sql);
        let mut err = ptr::null_mut();
        let mut callback: Row = &mut f;
        // SAFETY: the callback argument outlives the call
        let rc = unsafe { ffi::sqlite3_exec(self.raw, s.as_ptr() as *const c_char, Some(row), &mut callback as *mut Row as *mut c_void, &mut err) };
        (rc, taken(err))
    }

    /// Compiles the first statement of `sql`: the return code, the statement (None on an error or
    /// for SQL with no statement, such as only a comment), and the offset of the rest.
    pub fn prepare_v2(&self, sql: &[u8]) -> (i32, Option<Stmt>, usize) {
        let s = zero_ended(sql);
        let (mut st, mut tail) = (ptr::null_mut(), ptr::null());
        // SAFETY: zero-ended SQL, out pointers valid
        let rc = unsafe { ffi::sqlite3_prepare_v2(self.raw, s.as_ptr() as *const c_char, -1, &mut st, &mut tail) };
        let rest = if tail.is_null() { s.len() - 1 } else { tail as usize - s.as_ptr() as usize };
        (rc, (!st.is_null()).then_some(Stmt { raw: st }), rest)
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        // close_v2: the connection goes when its last statement does
        unsafe { sqlite3_close_v2(self.raw) };
    }
}

/// A compiled statement; finalized when dropped.
pub struct Stmt {
    raw: *mut ffi::sqlite3_stmt,
}

// SAFETY: serialized build; the database code uses a statement under its connection's lock
unsafe impl Send for Stmt {}
unsafe impl Sync for Stmt {}

impl Stmt {
    pub fn step(&self) -> i32 {
        unsafe { ffi::sqlite3_step(self.raw) }
    }

    pub fn reset(&self) -> i32 {
        unsafe { ffi::sqlite3_reset(self.raw) }
    }

    pub fn clear_bindings(&self) -> i32 {
        unsafe { ffi::sqlite3_clear_bindings(self.raw) }
    }

    /// The text of the connection's last error.
    pub fn errmsg(&self) -> Vec<u8> {
        copied(unsafe { ffi::sqlite3_errmsg(ffi::sqlite3_db_handle(self.raw)) }).unwrap_or_default()
    }

    pub fn errmsg_str(&self) -> String {
        String::from_utf8_lossy(&self.errmsg()).into_owned()
    }

    /// The statement's SQL.
    pub fn sql(&self) -> Vec<u8> {
        copied(unsafe { ffi::sqlite3_sql(self.raw) }).unwrap_or_default()
    }

    /// Binds text up to its first zero byte (SQLite copies it); None binds NULL.
    pub fn bind_text(&self, i: i32, v: Option<&[u8]>) -> i32 {
        let s = v.map(zero_ended);
        let p = s.as_ref().map_or(ptr::null(), |s| s.as_ptr() as *const c_char);
        // SAFETY: SQLITE_TRANSIENT makes SQLite copy the value before returning
        unsafe { ffi::sqlite3_bind_text(self.raw, i, p, -1, ffi::SQLITE_TRANSIENT()) }
    }

    pub fn bind_int(&self, i: i32, v: i32) -> i32 {
        unsafe { ffi::sqlite3_bind_int(self.raw, i, v) }
    }

    pub fn bind_int64(&self, i: i32, v: i64) -> i32 {
        unsafe { ffi::sqlite3_bind_int64(self.raw, i, v) }
    }

    pub fn bind_double(&self, i: i32, v: f64) -> i32 {
        unsafe { ffi::sqlite3_bind_double(self.raw, i, v) }
    }

    pub fn bind_null(&self, i: i32) -> i32 {
        unsafe { ffi::sqlite3_bind_null(self.raw, i) }
    }

    /// The index of a named parameter (`:name`, `$name`, ...); 0 when there is none.
    pub fn bind_parameter_index(&self, name: &[u8]) -> i32 {
        let s = zero_ended(name);
        unsafe { ffi::sqlite3_bind_parameter_index(self.raw, s.as_ptr() as *const c_char) }
    }

    pub fn column_count(&self) -> i32 {
        unsafe { ffi::sqlite3_column_count(self.raw) }
    }

    pub fn column_name(&self, i: i32) -> Vec<u8> {
        copied(unsafe { ffi::sqlite3_column_name(self.raw, i) }).unwrap_or_default()
    }

    /// The type of the current row's value (`SQLITE_INTEGER` ... `SQLITE_NULL`).
    pub fn column_type(&self, i: i32) -> i32 {
        unsafe { ffi::sqlite3_column_type(self.raw, i) }
    }

    /// The value as text up to its first zero byte; None for NULL.
    pub fn column_text(&self, i: i32) -> Option<Vec<u8>> {
        copied(unsafe { ffi::sqlite3_column_text(self.raw, i) } as *const c_char)
    }

    pub fn column_int(&self, i: i32) -> i32 {
        unsafe { ffi::sqlite3_column_int(self.raw, i) }
    }

    pub fn column_int64(&self, i: i32) -> i64 {
        unsafe { ffi::sqlite3_column_int64(self.raw, i) }
    }

    pub fn column_double(&self, i: i32) -> f64 {
        unsafe { ffi::sqlite3_column_double(self.raw, i) }
    }
}

impl Drop for Stmt {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_finalize(self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_rows_and_errors() {
        let (rc, db) = Db::open_v2(b":memory:\0ignored", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        assert_eq!(rc, SQLITE_OK);
        let db = db.unwrap();
        // foreign keys start off
        let mut fk = Vec::new();
        db.exec_rows(b"PRAGMA foreign_keys;", |v, _| {
            fk.push(v[0].map(<[u8]>::to_vec));
            0
        });
        assert_eq!(fk, [Some(b"0".to_vec())]);
        assert_eq!(db.exec(b"CREATE TABLE t (a INTEGER, b TEXT, c REAL);").0, SQLITE_OK);
        let (rc, st, _) = db.prepare_v2(b"INSERT INTO t VALUES (?, :b, ?);");
        assert_eq!(rc, SQLITE_OK);
        let st = st.unwrap();
        assert_eq!(st.bind_parameter_index(b":b"), 2);
        st.bind_int(1, 7);
        st.bind_text(2, Some(b"x\0ignored"));
        st.bind_double(3, 1.5);
        assert_eq!(st.step(), SQLITE_DONE);
        assert_eq!(db.last_insert_rowid(), 1);
        st.reset();
        st.clear_bindings();
        st.bind_int64(1, 1 << 40);
        st.bind_text(2, None);
        assert_eq!(st.step(), SQLITE_DONE);
        assert_eq!(db.changes(), 1);
        let (_, q, _) = db.prepare_v2(b"SELECT a, b, c FROM t ORDER BY a;");
        let q = q.unwrap();
        assert_eq!((q.column_count(), q.column_name(1)), (3, b"b".to_vec()));
        assert_eq!(q.step(), SQLITE_ROW);
        assert_eq!((q.column_int(0), q.column_text(1).unwrap(), q.column_double(2)), (7, b"x".to_vec(), 1.5));
        assert_eq!(q.step(), SQLITE_ROW);
        assert_eq!((q.column_int64(0), q.column_text(1), q.column_type(1)), (1 << 40, None, SQLITE_NULL));
        assert_eq!(q.step(), SQLITE_DONE);
        assert_eq!(q.sql(), b"SELECT a, b, c FROM t ORDER BY a;");
        let (rc, err) = db.exec(b"SELECT * FROM nope;");
        assert_eq!((rc, err.unwrap()), (SQLITE_ERROR, b"no such table: nope".to_vec()));
        assert_eq!(db.errmsg_str(), "no such table: nope");
        let (rc, st, rest) = db.prepare_v2(b"  -- c\n");
        assert_eq!((rc, st.is_none(), rest), (SQLITE_OK, true, 7));
        let (_, two, rest) = db.prepare_v2(b"SELECT 1; SELECT 2;");
        assert_eq!((two.is_some(), rest), (true, 9));
        let mut n = 0;
        assert_eq!(db.exec_rows(b"SELECT a FROM t;", |_, _| { n += 1; 1 }).0, ffi::SQLITE_ABORT);
        assert_eq!(n, 1);
        // dbstat is built in (the maintenance code reads it)
        assert_eq!(db.exec(b"SELECT count(*) FROM dbstat;").0, SQLITE_OK);
        let (rc, bad) = Db::open_v2(b"/no/such/dir/x.db", SQLITE_OPEN_READWRITE);
        assert_ne!(rc, SQLITE_OK);
        assert!(!bad.unwrap().errmsg().is_empty());
    }
}
