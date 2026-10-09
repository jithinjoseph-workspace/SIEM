//! `siem-sqlite`: SQLite 3.50.4 (the amalgamation Wazuh 4.14.7 builds from
//! deps v54, compiled with `-DSQLITE_ENABLE_DBSTAT_VTAB=1` like Wazuh's
//! Makefile) behind a thin wrapper of the C API calls wazuh-db makes.
//!
//! The wrapper keeps the C semantics on purpose: return codes instead of
//! `Result`s, `column_text` returning NULL for NULL values, statements that
//! outlive nothing in particular (they are finalized on drop, and
//! `sqlite3_close_v2` keeps a closed connection alive until its last
//! statement goes), so the C code ports one call at a time.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::ptr;

pub const SQLITE_OK: i32 = 0;
pub const SQLITE_ERROR: i32 = 1;
pub const SQLITE_BUSY: i32 = 5;
pub const SQLITE_LOCKED: i32 = 6;
pub const SQLITE_CONSTRAINT: i32 = 19;
pub const SQLITE_MISUSE: i32 = 21;
pub const SQLITE_ROW: i32 = 100;
pub const SQLITE_DONE: i32 = 101;

pub const SQLITE_OPEN_READONLY: i32 = 0x0000_0001;
pub const SQLITE_OPEN_READWRITE: i32 = 0x0000_0002;
pub const SQLITE_OPEN_CREATE: i32 = 0x0000_0004;
pub const SQLITE_OPEN_NOMUTEX: i32 = 0x0000_8000;
pub const SQLITE_OPEN_FULLMUTEX: i32 = 0x0001_0000;

pub const SQLITE_INTEGER: i32 = 1;
pub const SQLITE_FLOAT: i32 = 2;
pub const SQLITE_TEXT: i32 = 3;
pub const SQLITE_BLOB: i32 = 4;
pub const SQLITE_NULL: i32 = 5;

#[repr(C)]
pub struct RawDb {
    _p: [u8; 0],
}
#[repr(C)]
pub struct RawStmt {
    _p: [u8; 0],
}

type Destructor = Option<unsafe extern "C" fn(*mut c_void)>;

extern "C" {
    fn sqlite3_open_v2(filename: *const c_char, db: *mut *mut RawDb, flags: c_int, vfs: *const c_char) -> c_int;
    fn sqlite3_close_v2(db: *mut RawDb) -> c_int;
    fn sqlite3_errmsg(db: *mut RawDb) -> *const c_char;
    fn sqlite3_errcode(db: *mut RawDb) -> c_int;
    fn sqlite3_changes(db: *mut RawDb) -> c_int;
    fn sqlite3_total_changes(db: *mut RawDb) -> c_int;
    fn sqlite3_last_insert_rowid(db: *mut RawDb) -> i64;
    fn sqlite3_get_autocommit(db: *mut RawDb) -> c_int;
    fn sqlite3_busy_timeout(db: *mut RawDb, ms: c_int) -> c_int;
    fn sqlite3_exec(
        db: *mut RawDb,
        sql: *const c_char,
        cb: Option<unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int>,
        arg: *mut c_void,
        errmsg: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_free(p: *mut c_void);
    fn sqlite3_prepare_v2(db: *mut RawDb, sql: *const c_char, n: c_int, stmt: *mut *mut RawStmt, tail: *mut *const c_char) -> c_int;
    fn sqlite3_finalize(stmt: *mut RawStmt) -> c_int;
    fn sqlite3_reset(stmt: *mut RawStmt) -> c_int;
    fn sqlite3_clear_bindings(stmt: *mut RawStmt) -> c_int;
    fn sqlite3_step(stmt: *mut RawStmt) -> c_int;
    fn sqlite3_sql(stmt: *mut RawStmt) -> *const c_char;
    fn sqlite3_expanded_sql(stmt: *mut RawStmt) -> *mut c_char;
    fn sqlite3_db_handle(stmt: *mut RawStmt) -> *mut RawDb;
    fn sqlite3_bind_text(stmt: *mut RawStmt, i: c_int, v: *const c_char, n: c_int, d: Destructor) -> c_int;
    fn sqlite3_bind_int(stmt: *mut RawStmt, i: c_int, v: c_int) -> c_int;
    fn sqlite3_bind_int64(stmt: *mut RawStmt, i: c_int, v: i64) -> c_int;
    fn sqlite3_bind_double(stmt: *mut RawStmt, i: c_int, v: f64) -> c_int;
    fn sqlite3_bind_null(stmt: *mut RawStmt, i: c_int) -> c_int;
    fn sqlite3_bind_parameter_index(stmt: *mut RawStmt, name: *const c_char) -> c_int;
    fn sqlite3_bind_parameter_count(stmt: *mut RawStmt) -> c_int;
    fn sqlite3_column_count(stmt: *mut RawStmt) -> c_int;
    fn sqlite3_column_name(stmt: *mut RawStmt, i: c_int) -> *const c_char;
    fn sqlite3_column_type(stmt: *mut RawStmt, i: c_int) -> c_int;
    fn sqlite3_column_text(stmt: *mut RawStmt, i: c_int) -> *const u8;
    fn sqlite3_column_bytes(stmt: *mut RawStmt, i: c_int) -> c_int;
    fn sqlite3_column_int(stmt: *mut RawStmt, i: c_int) -> c_int;
    fn sqlite3_column_int64(stmt: *mut RawStmt, i: c_int) -> i64;
    fn sqlite3_column_double(stmt: *mut RawStmt, i: c_int) -> f64;
    fn sqlite3_libversion() -> *const c_char;
    fn siem_sqlite_fix_time(unix_secs: i64) -> c_int;
}

/// Pins the time SQLite's date functions see as 'now' (None: the real
/// clock again). For differential tests; see `sqlite/siem_fixed_time.c`.
pub fn fix_time(unix_secs: Option<i64>) -> bool {
    unsafe { siem_sqlite_fix_time(unix_secs.unwrap_or(-1)) == 0 }
}

/// `SQLITE_TRANSIENT`: SQLite copies the bound value.
fn transient() -> Destructor {
    // SAFETY: SQLite defines SQLITE_TRANSIENT as ((sqlite3_destructor_type)-1).
    unsafe { std::mem::transmute::<isize, Destructor>(-1) }
}

fn cbytes(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        None
    } else {
        // SAFETY: SQLite returns NUL-terminated strings.
        Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
    }
}

/// A C string for SQLite: the bytes up to the first NUL (C callers can
/// not pass more), NUL terminated.
fn cstring(b: &[u8]) -> Vec<u8> {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let mut v = Vec::with_capacity(n + 1);
    v.extend_from_slice(&b[..n]);
    v.push(0);
    v
}

/// `sqlite3_libversion()`
pub fn libversion() -> String {
    String::from_utf8_lossy(&cbytes(unsafe { sqlite3_libversion() }).unwrap_or_default()).into_owned()
}

/// A `sqlite3 *` connection, closed (`sqlite3_close_v2`) on drop.
pub struct Db {
    raw: *mut RawDb,
}

// SAFETY: the library is built in serialized mode (SQLITE_THREADSAFE=1).
unsafe impl Send for Db {}
unsafe impl Sync for Db {}

/// The `NULL` connection of C code that keeps using a closed handle
/// (`sqlite3 *db = NULL`): SQLite itself answers (SQLITE_MISUSE from
/// prepare/exec, "out of memory" from errmsg). Never dropped.
pub static NULL_DB: Db = Db { raw: ptr::null_mut() };

impl Db {
    /// `sqlite3_open_v2(path, &db, flags, NULL)`: the return code and the
    /// connection, which is allocated even when the open fails (its
    /// `errmsg` tells why) unless SQLite ran out of memory.
    pub fn open_v2(path: &[u8], flags: i32) -> (i32, Option<Db>) {
        let p = cstring(path);
        let mut raw = ptr::null_mut();
        let rc = unsafe { sqlite3_open_v2(p.as_ptr() as *const c_char, &mut raw, flags, ptr::null()) };
        (rc, if raw.is_null() { None } else { Some(Db { raw }) })
    }

    /// `sqlite3_errmsg`
    pub fn errmsg(&self) -> Vec<u8> {
        cbytes(unsafe { sqlite3_errmsg(self.raw) }).unwrap_or_default()
    }

    /// `sqlite3_errmsg` as text.
    pub fn errmsg_str(&self) -> String {
        String::from_utf8_lossy(&self.errmsg()).into_owned()
    }

    pub fn errcode(&self) -> i32 {
        unsafe { sqlite3_errcode(self.raw) }
    }

    pub fn changes(&self) -> i32 {
        unsafe { sqlite3_changes(self.raw) }
    }

    pub fn total_changes(&self) -> i32 {
        unsafe { sqlite3_total_changes(self.raw) }
    }

    pub fn last_insert_rowid(&self) -> i64 {
        unsafe { sqlite3_last_insert_rowid(self.raw) }
    }

    pub fn get_autocommit(&self) -> bool {
        unsafe { sqlite3_get_autocommit(self.raw) != 0 }
    }

    pub fn busy_timeout(&self, ms: i32) -> i32 {
        unsafe { sqlite3_busy_timeout(self.raw, ms) }
    }

    /// `sqlite3_exec(db, sql, NULL, NULL, &errmsg)`: the return code and
    /// the error message.
    pub fn exec(&self, sql: &[u8]) -> (i32, Option<Vec<u8>>) {
        let s = cstring(sql);
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { sqlite3_exec(self.raw, s.as_ptr() as *const c_char, None, ptr::null_mut(), &mut err) };
        let msg = cbytes(err);
        if !err.is_null() {
            unsafe { sqlite3_free(err as *mut c_void) };
        }
        (rc, msg)
    }

    /// `sqlite3_exec` with a row callback: each row's values (NULL ->
    /// None) and column names; the callback returns nonzero to abort.
    pub fn exec_rows(&self, sql: &[u8], mut f: impl FnMut(&[Option<&[u8]>], &[&[u8]]) -> i32) -> (i32, Option<Vec<u8>>) {
        type F<'a> = &'a mut dyn FnMut(&[Option<&[u8]>], &[&[u8]]) -> i32;
        unsafe extern "C" fn cb(arg: *mut c_void, n: c_int, vals: *mut *mut c_char, names: *mut *mut c_char) -> c_int {
            let f = &mut *(arg as *mut F);
            let n = n as usize;
            let vs: Vec<Option<&[u8]>> = (0..n)
                .map(|i| {
                    let p = *vals.add(i);
                    if p.is_null() {
                        None
                    } else {
                        Some(CStr::from_ptr(p).to_bytes())
                    }
                })
                .collect();
            let ns: Vec<&[u8]> = (0..n).map(|i| CStr::from_ptr(*names.add(i)).to_bytes()).collect();
            f(&vs, &ns)
        }
        let s = cstring(sql);
        let mut err: *mut c_char = ptr::null_mut();
        let mut fr: F = &mut f;
        let rc = unsafe {
            sqlite3_exec(self.raw, s.as_ptr() as *const c_char, Some(cb), &mut fr as *mut F as *mut c_void, &mut err)
        };
        let msg = cbytes(err);
        if !err.is_null() {
            unsafe { sqlite3_free(err as *mut c_void) };
        }
        (rc, msg)
    }

    /// `sqlite3_prepare_v2(db, sql, -1, &stmt, &tail)`: the return code,
    /// the statement (None on error or for an empty/comment-only SQL) and
    /// the offset of the unparsed tail.
    pub fn prepare_v2(&self, sql: &[u8]) -> (i32, Option<Stmt>, usize) {
        let s = cstring(sql);
        let mut st = ptr::null_mut();
        let mut tail: *const c_char = ptr::null();
        let rc = unsafe { sqlite3_prepare_v2(self.raw, s.as_ptr() as *const c_char, -1, &mut st, &mut tail) };
        let off = if tail.is_null() { s.len() - 1 } else { tail as usize - s.as_ptr() as usize };
        (rc, if st.is_null() { None } else { Some(Stmt { raw: st }) }, off)
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe { sqlite3_close_v2(self.raw) };
    }
}

/// A prepared statement (`sqlite3_stmt *`), finalized on drop.
pub struct Stmt {
    raw: *mut RawStmt,
}

// SAFETY: serialized mode; callers serialize use of a statement (wazuh-db
// locks the database for each query).
unsafe impl Send for Stmt {}
unsafe impl Sync for Stmt {}

impl Stmt {
    /// The NULL statement `sqlite3_prepare_v2` gives for an empty or
    /// comment-only SQL: SQLite answers SQLITE_MISUSE to step and binds,
    /// 0 to the counts.
    pub fn null() -> Stmt {
        Stmt { raw: ptr::null_mut() }
    }

    pub fn is_null(&self) -> bool {
        self.raw.is_null()
    }

    pub fn step(&self) -> i32 {
        unsafe { sqlite3_step(self.raw) }
    }

    pub fn reset(&self) -> i32 {
        unsafe { sqlite3_reset(self.raw) }
    }

    pub fn clear_bindings(&self) -> i32 {
        unsafe { sqlite3_clear_bindings(self.raw) }
    }

    /// `sqlite3_errmsg(sqlite3_db_handle(stmt))`
    pub fn errmsg(&self) -> Vec<u8> {
        cbytes(unsafe { sqlite3_errmsg(sqlite3_db_handle(self.raw)) }).unwrap_or_default()
    }

    pub fn errmsg_str(&self) -> String {
        String::from_utf8_lossy(&self.errmsg()).into_owned()
    }

    /// `sqlite3_sql`
    pub fn sql(&self) -> Vec<u8> {
        cbytes(unsafe { sqlite3_sql(self.raw) }).unwrap_or_default()
    }

    /// `sqlite3_expanded_sql`
    pub fn expanded_sql(&self) -> Option<Vec<u8>> {
        let p = unsafe { sqlite3_expanded_sql(self.raw) };
        let r = cbytes(p);
        if !p.is_null() {
            unsafe { sqlite3_free(p as *mut c_void) };
        }
        r
    }

    /// `sqlite3_bind_text(stmt, i, v, -1, SQLITE_TRANSIENT)`; None binds
    /// NULL like a NULL pointer does. The value ends at its first NUL.
    pub fn bind_text(&self, i: i32, v: Option<&[u8]>) -> i32 {
        match v {
            None => unsafe { sqlite3_bind_text(self.raw, i, ptr::null(), -1, transient()) },
            Some(v) => {
                let s = cstring(v);
                unsafe { sqlite3_bind_text(self.raw, i, s.as_ptr() as *const c_char, -1, transient()) }
            }
        }
    }

    /// `sqlite3_bind_text(stmt, i, v, n, SQLITE_TRANSIENT)`: exactly `v`.
    pub fn bind_text_len(&self, i: i32, v: &[u8]) -> i32 {
        unsafe { sqlite3_bind_text(self.raw, i, v.as_ptr() as *const c_char, v.len() as c_int, transient()) }
    }

    pub fn bind_int(&self, i: i32, v: i32) -> i32 {
        unsafe { sqlite3_bind_int(self.raw, i, v) }
    }

    pub fn bind_int64(&self, i: i32, v: i64) -> i32 {
        unsafe { sqlite3_bind_int64(self.raw, i, v) }
    }

    pub fn bind_double(&self, i: i32, v: f64) -> i32 {
        unsafe { sqlite3_bind_double(self.raw, i, v) }
    }

    pub fn bind_null(&self, i: i32) -> i32 {
        unsafe { sqlite3_bind_null(self.raw, i) }
    }

    pub fn bind_parameter_index(&self, name: &[u8]) -> i32 {
        let s = cstring(name);
        unsafe { sqlite3_bind_parameter_index(self.raw, s.as_ptr() as *const c_char) }
    }

    pub fn bind_parameter_count(&self) -> i32 {
        unsafe { sqlite3_bind_parameter_count(self.raw) }
    }

    pub fn column_count(&self) -> i32 {
        unsafe { sqlite3_column_count(self.raw) }
    }

    pub fn column_name(&self, i: i32) -> Vec<u8> {
        cbytes(unsafe { sqlite3_column_name(self.raw, i) }).unwrap_or_default()
    }

    pub fn column_type(&self, i: i32) -> i32 {
        unsafe { sqlite3_column_type(self.raw, i) }
    }

    /// `(char *)sqlite3_column_text(stmt, i)`: None for NULL; the text
    /// ends at its first NUL like a C string.
    pub fn column_text(&self, i: i32) -> Option<Vec<u8>> {
        let p = unsafe { sqlite3_column_text(self.raw, i) };
        if p.is_null() {
            return None;
        }
        Some(unsafe { CStr::from_ptr(p as *const c_char) }.to_bytes().to_vec())
    }

    /// The whole value (`sqlite3_column_text` + `sqlite3_column_bytes`).
    pub fn column_bytes(&self, i: i32) -> Option<Vec<u8>> {
        let p = unsafe { sqlite3_column_text(self.raw, i) };
        if p.is_null() {
            return None;
        }
        let n = unsafe { sqlite3_column_bytes(self.raw, i) } as usize;
        Some(unsafe { std::slice::from_raw_parts(p, n) }.to_vec())
    }

    pub fn column_int(&self, i: i32) -> i32 {
        unsafe { sqlite3_column_int(self.raw, i) }
    }

    pub fn column_int64(&self, i: i32) -> i64 {
        unsafe { sqlite3_column_int64(self.raw, i) }
    }

    pub fn column_double(&self, i: i32) -> f64 {
        unsafe { sqlite3_column_double(self.raw, i) }
    }
}

impl Drop for Stmt {
    fn drop(&mut self) {
        unsafe { sqlite3_finalize(self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        assert_eq!(libversion(), "3.50.4");
        let (rc, db) = Db::open_v2(b":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        assert_eq!(rc, SQLITE_OK);
        let db = db.unwrap();
        assert_eq!(db.exec(b"CREATE TABLE t (a INTEGER, b TEXT);").0, SQLITE_OK);
        let (rc, st, _) = db.prepare_v2(b"INSERT INTO t VALUES (?, ?);");
        assert_eq!(rc, SQLITE_OK);
        let st = st.unwrap();
        st.bind_int(1, 7);
        st.bind_text(2, Some(b"x\0ignored"));
        assert_eq!(st.step(), SQLITE_DONE);
        st.reset();
        st.bind_int(1, 8);
        st.bind_text(2, None);
        assert_eq!(st.step(), SQLITE_DONE);
        assert_eq!(db.changes(), 1);
        let (_, q, _) = db.prepare_v2(b"SELECT a, b FROM t ORDER BY a;");
        let q = q.unwrap();
        assert_eq!(q.step(), SQLITE_ROW);
        assert_eq!(q.column_int(0), 7);
        assert_eq!(q.column_text(1).unwrap(), b"x");
        assert_eq!(q.step(), SQLITE_ROW);
        assert_eq!(q.column_text(1), None);
        assert_eq!(q.column_type(1), SQLITE_NULL);
        assert_eq!(q.step(), SQLITE_DONE);
        let (rc, err) = db.exec(b"SELECT * FROM nope;");
        assert_eq!(rc, SQLITE_ERROR);
        assert_eq!(err.unwrap(), b"no such table: nope");
        let mut rows = Vec::new();
        db.exec_rows(b"SELECT a FROM t;", |v, n| {
            rows.push((v[0].map(|x| x.to_vec()), n[0].to_vec()));
            0
        });
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1, b"a");
        let (rc, st, tail) = db.prepare_v2(b"  -- c\n");
        assert_eq!((rc, st.is_none(), tail), (SQLITE_OK, true, 7));
    }
}
