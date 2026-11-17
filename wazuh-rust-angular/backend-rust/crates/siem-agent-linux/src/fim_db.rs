//! Persistent SQLite FIM baseline storage for ProVigil Linux Agent.
//!
//! Stores the baseline in `/opt/provigil-agent/data/fim.db` (with fallback to `data/fim.db`),
//! ensuring that file hashes and POSIX metadata survive service restarts and reboots
//! without triggering re-scan floods.

use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::syscheck::FileRecord;

pub struct FimDb {
    conn: Connection,
}

impl FimDb {
    /// Open or create the SQLite database at `path`.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(15))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS files (
                 path TEXT PRIMARY KEY,
                 sha256 TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 mode INTEGER NOT NULL,
                 uid INTEGER NOT NULL,
                 gid INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    /// Load all stored file records into an in-memory baseline HashMap.
    pub fn load_baseline(&self) -> rusqlite::Result<HashMap<PathBuf, FileRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, sha256, size, mode, uid, gid FROM files")?;
        let rows = stmt.query_map([], |row| {
            let p: String = row.get(0)?;
            let hash: String = row.get(1)?;
            let size: i64 = row.get(2)?;
            let mode: u32 = row.get(3)?;
            let uid: u32 = row.get(4)?;
            let gid: u32 = row.get(5)?;
            Ok((
                PathBuf::from(p),
                FileRecord {
                    hash,
                    size: size.max(0) as u64,
                    mode,
                    uid,
                    gid,
                },
            ))
        })?;

        let mut map = HashMap::new();
        for r in rows {
            if let Ok((path, record)) = r {
                map.insert(path, record);
            }
        }
        Ok(map)
    }

    /// Insert or update records in the SQLite database inside a single transaction.
    pub fn save_records(&mut self, records: &[(&Path, &FileRecord)]) -> rusqlite::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp();
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO files (path, sha256, size, mode, uid, gid, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for (p, r) in records {
                let path_str = p.to_string_lossy();
                stmt.execute(params![
                    path_str,
                    r.hash,
                    r.size as i64,
                    r.mode,
                    r.uid,
                    r.gid,
                    now,
                ])?;
            }
        }
        tx.commit()
    }

    /// Remove a deleted file from the baseline database.
    pub fn delete_record(&mut self, path: &Path) -> rusqlite::Result<bool> {
        let path_str = path.to_string_lossy();
        let deleted = self
            .conn
            .execute("DELETE FROM files WHERE path = ?1", params![path_str])?;
        Ok(deleted > 0)
    }

    /// Clear all stored baseline records.
    #[allow(dead_code)]
    pub fn clear(&mut self) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM files", [])?;
        Ok(())
    }
}

/// Helper to resolve the best SQLite database path for Linux.
pub fn default_fim_db_path() -> PathBuf {
    let opt_dir = Path::new("/opt/provigil-agent/data");
    if opt_dir.is_dir() {
        opt_dir.join("fim.db")
    } else {
        PathBuf::from("data/fim.db")
    }
}
