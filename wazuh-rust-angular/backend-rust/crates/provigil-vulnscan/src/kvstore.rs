//! Key-value store: a directory with one SQLite file `data.sqlite`.
//!
//! Keys and values are bound as SQLite TEXT holding raw bytes (compressed values included).
//! Existing files were written that way, and SQLite orders TEXT and BLOB differently, so binding
//! blobs would break prefix searches and "last key" lookups on them.

use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{params, Connection, OpenFlags, ToSql};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

pub const DEFAULT_COLUMN: &str = "default";
const BATCH_COMMIT_EVERY: usize = 20_000;

/// Binds bytes as TEXT.
struct T<'a>(&'a [u8]);
impl ToSql for T<'_> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(ValueRef::Text(self.0)))
    }
}

fn bytes(v: ValueRef<'_>) -> Vec<u8> {
    match v {
        ValueRef::Text(b) | ValueRef::Blob(b) => b.to_vec(),
        ValueRef::Integer(i) => i.to_string().into_bytes(),
        ValueRef::Real(f) => f.to_string().into_bytes(),
        ValueRef::Null => Vec::new(),
    }
}

struct Inner {
    conn: Connection,
    columns: BTreeSet<String>,
    batch_writes: Option<usize>,
}

pub struct KvStore {
    inner: Mutex<Inner>,
}

pub type KvResult<T> = Result<T, String>;

/// Read and write error texts.
fn rd(e: rusqlite::Error) -> String {
    format!("Error getting data: {e}")
}
fn wr(e: rusqlite::Error) -> String {
    format!("Error putting data: {e}")
}

fn no_column(c: &str) -> String {
    format!("Couldn't find column family: '{c}'")
}

impl KvStore {
    pub fn open(dir: &Path) -> KvResult<KvStore> {
        Self::open_inner(dir).map_err(|e| format!("Failed to open key-value store. Reason: {e}"))
    }

    fn open_inner(dir: &Path) -> Result<KvStore, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let conn = Connection::open_with_flags(dir.join("data.sqlite"), flags).map_err(|e| e.to_string())?;
        conn.busy_timeout(Duration::from_millis(60_000)).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;PRAGMA synchronous=NORMAL;PRAGMA cache_size=-262144;\
             CREATE TABLE IF NOT EXISTS cf(name TEXT PRIMARY KEY) WITHOUT ROWID;\
             CREATE TABLE IF NOT EXISTS kv(cf TEXT NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, PRIMARY KEY(cf, k)) WITHOUT ROWID;\
             INSERT OR IGNORE INTO cf(name) VALUES('default');",
        )
        .map_err(|e| e.to_string())?;
        let mut columns = BTreeSet::new();
        {
            let mut st = conn.prepare("SELECT name FROM cf").map_err(|e| e.to_string())?;
            let mut rows = st.query([]).map_err(|e| e.to_string())?;
            while let Some(r) = rows.next().map_err(|e| e.to_string())? {
                columns.insert(String::from_utf8_lossy(&bytes(r.get_ref(0).map_err(|e| e.to_string())?)).into_owned());
            }
        }
        Ok(KvStore { inner: Mutex::new(Inner { conn, columns, batch_writes: None }) })
    }

    pub fn has_column(&self, c: &str) -> bool {
        self.inner.lock().unwrap().columns.contains(c)
    }

    pub fn create_column(&self, c: &str) -> KvResult<()> {
        if c.is_empty() {
            return Err("Column name is empty".into());
        }
        let mut g = self.inner.lock().unwrap();
        g.conn
            .execute("INSERT OR IGNORE INTO cf(name) VALUES(?1)", params![T(c.as_bytes())])
            .map_err(|e| e.to_string())?;
        g.columns.insert(c.to_string());
        Ok(())
    }

    /// `default` first, then the others sorted by name.
    pub fn columns(&self) -> Vec<String> {
        let g = self.inner.lock().unwrap();
        let mut v = vec![DEFAULT_COLUMN.to_string()];
        v.extend(g.columns.iter().filter(|c| *c != DEFAULT_COLUMN).cloned());
        v
    }

    fn check(g: &Inner, c: &str) -> KvResult<()> {
        if g.columns.contains(c) {
            Ok(())
        } else {
            Err(no_column(c))
        }
    }

    fn count_write(g: &mut Inner) -> KvResult<()> {
        if let Some(n) = g.batch_writes.as_mut() {
            *n += 1;
            if *n >= BATCH_COMMIT_EVERY {
                *n = 0;
                g.conn.execute_batch("COMMIT;BEGIN").map_err(wr)?;
            }
        }
        Ok(())
    }

    pub fn put(&self, c: &str, k: &[u8], v: &[u8]) -> KvResult<()> {
        let mut g = self.inner.lock().unwrap();
        Self::check(&g, c)?;
        g.conn
            .execute("INSERT OR REPLACE INTO kv(cf,k,v) VALUES(?1,?2,?3)", params![T(c.as_bytes()), T(k), T(v)])
            .map_err(|e| format!("Error putting data: {e}"))?;
        Self::count_write(&mut g)?;
        Ok(())
    }

    pub fn get(&self, c: &str, k: &[u8]) -> KvResult<Option<Vec<u8>>> {
        let g = self.inner.lock().unwrap();
        Self::check(&g, c)?;
        let mut st = g
            .conn
            .prepare_cached("SELECT v FROM kv WHERE cf=?1 AND k=?2")
            .map_err(|e| format!("Error getting data: {e}"))?;
        let mut rows = st.query(params![T(c.as_bytes()), T(k)]).map_err(|e| format!("Error getting data: {e}"))?;
        match rows.next().map_err(|e| format!("Error getting data: {e}"))? {
            Some(r) => Ok(Some(bytes(r.get_ref(0).map_err(|e| format!("Error getting data: {e}"))?))),
            None => Ok(None),
        }
    }

    pub fn delete(&self, c: &str, k: &[u8]) -> KvResult<()> {
        let mut g = self.inner.lock().unwrap();
        Self::check(&g, c)?;
        g.conn
            .execute("DELETE FROM kv WHERE cf=?1 AND k=?2", params![T(c.as_bytes()), T(k)])
            .map_err(wr)?;
        Self::count_write(&mut g)?;
        Ok(())
    }

    /// Visits every (key, value) whose key starts with `prefix`, in key order, until `f` says stop.
    pub fn scan(&self, c: &str, prefix: &[u8], mut f: impl FnMut(&[u8], &[u8]) -> bool) -> KvResult<()> {
        let g = self.inner.lock().unwrap();
        Self::check(&g, c)?;
        let mut st = g
            .conn
            .prepare_cached("SELECT k, v FROM kv WHERE cf=?1 AND k>=?2 ORDER BY k")
            .map_err(rd)?;
        let mut rows = st.query(params![T(c.as_bytes()), T(prefix)]).map_err(rd)?;
        while let Some(r) = rows.next().map_err(rd)? {
            let k = bytes(r.get_ref(0).map_err(rd)?);
            if !k.starts_with(prefix) {
                break;
            }
            let v = bytes(r.get_ref(1).map_err(rd)?);
            if !f(&k, &v) {
                break;
            }
        }
        Ok(())
    }

    pub fn prefix(&self, c: &str, prefix: &[u8]) -> KvResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        self.scan(c, prefix, |k, v| {
            out.push((k.to_vec(), v.to_vec()));
            true
        })?;
        Ok(out)
    }

    /// Keys with `prefix` as texts.
    pub fn keys_text(&self, c: &str, prefix: &str) -> KvResult<Vec<String>> {
        let mut out = Vec::new();
        self.scan(c, prefix.as_bytes(), |k, _| {
            out.push(String::from_utf8_lossy(k).into_owned());
            true
        })?;
        Ok(out)
    }

    pub fn get_text(&self, c: &str, k: &str) -> KvResult<Option<String>> {
        Ok(self.get(c, k.as_bytes())?.map(|v| String::from_utf8_lossy(&v).into_owned()))
    }

    pub fn put_text(&self, c: &str, k: &str, v: &str) -> KvResult<()> {
        self.put(c, k.as_bytes(), v.as_bytes())
    }

    pub fn last(&self, c: &str) -> KvResult<(Vec<u8>, Vec<u8>)> {
        let g = self.inner.lock().unwrap();
        Self::check(&g, c)?;
        let mut st = g
            .conn
            .prepare_cached("SELECT k, v FROM kv WHERE cf=?1 ORDER BY k DESC LIMIT 1")
            .map_err(rd)?;
        let mut rows = st.query(params![T(c.as_bytes())]).map_err(rd)?;
        match rows.next().map_err(rd)? {
            Some(r) => Ok((
                bytes(r.get_ref(0).map_err(rd)?),
                bytes(r.get_ref(1).map_err(rd)?),
            )),
            None => Err("Error getting last key-value pair".into()),
        }
    }

    /// Empties every column; the column list stays.
    pub fn delete_all(&self) -> KvResult<()> {
        let g = self.inner.lock().unwrap();
        g.conn.execute("DELETE FROM kv", []).map_err(wr)?;
        Ok(())
    }

    pub fn begin_batch(&self) -> KvResult<()> {
        let mut g = self.inner.lock().unwrap();
        if g.batch_writes.is_none() {
            g.conn.execute_batch("BEGIN").map_err(wr)?;
            g.batch_writes = Some(0);
        }
        Ok(())
    }

    pub fn end_batch(&self) -> KvResult<()> {
        let mut g = self.inner.lock().unwrap();
        if g.batch_writes.take().is_some() {
            g.conn.execute_batch("COMMIT").map_err(wr)?;
        }
        Ok(())
    }
}

impl Drop for KvStore {
    fn drop(&mut self) {
        let _ = self.end_batch();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_and_errors() {
        let d = tempfile::tempdir().unwrap();
        let s = KvStore::open(&d.path().join("a/b")).unwrap();
        assert_eq!(s.put("x", b"k", b"v").unwrap_err(), "Couldn't find column family: 'x'");
        assert_eq!(s.create_column("").unwrap_err(), "Column name is empty");
        s.create_column("x").unwrap();
        for k in ["pkg_CVE-1", "pkg_CVE-2", "pkga_CVE-3", "pkf"] {
            s.put("x", k.as_bytes(), b"1").unwrap();
        }
        assert_eq!(s.keys_text("x", "pkg_CVE").unwrap(), vec!["pkg_CVE-1", "pkg_CVE-2"]);
        assert_eq!(s.last("x").unwrap().0, b"pkga_CVE-3");
        s.delete("x", b"pkg_CVE-1").unwrap();
        assert_eq!(s.get("x", b"pkg_CVE-1").unwrap(), None);
        assert_eq!(s.columns(), vec!["default", "x"]);
        s.delete_all().unwrap();
        assert_eq!(s.last("x").unwrap_err(), "Error getting last key-value pair");
    }

    #[test]
    fn binary_values_round_trip_and_reopen() {
        let d = tempfile::tempdir().unwrap();
        let bin: Vec<u8> = vec![0x78, 0x01, 0x00, 0xff, 0xfe, 0x80, b'a'];
        {
            let s = KvStore::open(d.path()).unwrap();
            s.create_column("c").unwrap();
            s.begin_batch().unwrap();
            s.put("c", b"k\xff", &bin).unwrap();
            s.end_batch().unwrap();
        }
        let s = KvStore::open(d.path()).unwrap();
        assert!(s.has_column("c"));
        assert_eq!(s.get("c", b"k\xff").unwrap().unwrap(), bin);
        // Stored as TEXT, as existing files are.
        let conn = Connection::open(d.path().join("data.sqlite")).unwrap();
        let t: String = conn.query_row("SELECT typeof(v) FROM kv WHERE cf='c'", [], |r| r.get(0)).unwrap();
        assert_eq!(t, "text");
    }
}
