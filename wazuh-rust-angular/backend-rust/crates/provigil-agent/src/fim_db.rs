//! The file integrity baseline on disk (`data\fim.db`, SQLite): what every monitored file
//! looked like at the last scan, so a restart compares against it instead of reporting
//! every file as new. Only the changed rows are written after a scan, in one transaction
//! (a crash or power loss never leaves a half-written baseline). The registry baseline
//! (`registry.rs`) is a second table in the same file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::fim::FileMetadata;
use crate::registry::{RegEntry, RegId};

const FILE_COLUMNS_ADDED: [&str; 6] = ["md5", "sha1", "owner", "owner_sid", "perms", "attributes"];

pub struct FimDb {
    conn: Connection,
}

impl FimDb {
    pub fn open(path: &Path) -> rusqlite::Result<FimDb> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        // the file and registry monitors each hold a connection to this file
        conn.busy_timeout(std::time::Duration::from_secs(30))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS files (
                 path TEXT PRIMARY KEY,
                 size INTEGER NOT NULL,
                 sha256 TEXT NOT NULL,
                 mtime INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS registry (
                 path TEXT NOT NULL,
                 arch TEXT NOT NULL,
                 is_key INTEGER NOT NULL,
                 value_name TEXT NOT NULL,
                 value_type TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 md5 TEXT NOT NULL,
                 sha1 TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 mtime INTEGER NOT NULL,
                 owner TEXT NOT NULL,
                 perms TEXT NOT NULL,
                 data TEXT,
                 PRIMARY KEY (path, arch, is_key, value_name)
             );",
        )?;
        // columns added after the first release: an older baseline gets them empty (not
        // compared until read once); the error when a column is there already is expected
        for col in FILE_COLUMNS_ADDED {
            let _ = conn.execute_batch(&format!("ALTER TABLE files ADD COLUMN {col} TEXT NOT NULL DEFAULT ''"));
        }
        Ok(FimDb { conn })
    }

    /// The whole baseline.
    pub fn load(&self) -> rusqlite::Result<HashMap<PathBuf, FileMetadata>> {
        let mut st = self.conn.prepare("SELECT path, size, sha256, mtime, md5, sha1, owner, owner_sid, perms, attributes FROM files")?;
        let rows = st.query_map([], |r| {
            Ok((
                PathBuf::from(r.get::<_, String>(0)?),
                FileMetadata {
                    size_bytes: r.get::<_, i64>(1)? as u64,
                    sha256: r.get(2)?,
                    modified_timestamp: r.get(3)?,
                    md5: r.get(4)?,
                    sha1: r.get(5)?,
                    owner: r.get(6)?,
                    owner_sid: r.get(7)?,
                    permissions: r.get(8)?,
                    attributes: r.get(9)?,
                },
            ))
        })?;
        rows.collect()
    }

    /// Writes the files that are new or changed and removes the deleted ones.
    pub fn apply(&mut self, changed: &[(&PathBuf, &FileMetadata)], deleted: &[&PathBuf]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut up = tx.prepare(
                "INSERT OR REPLACE INTO files (path, size, sha256, mtime, md5, sha1, owner, owner_sid, perms, attributes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for (p, m) in changed {
                up.execute(params![
                    p.to_string_lossy(), m.size_bytes as i64, m.sha256, m.modified_timestamp, m.md5, m.sha1, m.owner,
                    m.owner_sid, m.permissions, m.attributes
                ])?;
            }
            let mut del = tx.prepare("DELETE FROM files WHERE path = ?1")?;
            for p in deleted {
                del.execute(params![p.to_string_lossy()])?;
            }
        }
        tx.commit()
    }

    /// The whole registry baseline (keys and values).
    pub fn load_registry(&self) -> rusqlite::Result<HashMap<RegId, RegEntry>> {
        let mut st = self.conn.prepare(
            "SELECT path, arch, is_key, value_name, value_type, size, md5, sha1, sha256, mtime, owner, perms, data FROM registry",
        )?;
        let rows = st.query_map([], |r| {
            let is_key: bool = r.get(2)?;
            Ok((
                (r.get(0)?, r.get(1)?, if is_key { None } else { Some(r.get(3)?) }),
                RegEntry {
                    value_type: r.get(4)?,
                    size: r.get::<_, i64>(5)? as u64,
                    md5: r.get(6)?,
                    sha1: r.get(7)?,
                    sha256: r.get(8)?,
                    mtime: r.get(9)?,
                    owner: r.get(10)?,
                    perms: r.get(11)?,
                    data: r.get(12)?,
                },
            ))
        })?;
        rows.collect()
    }

    /// Writes the registry entries that are new or changed and removes the deleted ones.
    pub fn apply_registry(&mut self, changed: &[(&RegId, &RegEntry)], deleted: &[&RegId]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut up = tx.prepare(
                "INSERT OR REPLACE INTO registry (path, arch, is_key, value_name, value_type, size, md5, sha1, sha256, mtime, owner, perms, data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )?;
            for ((path, arch, name), e) in changed {
                up.execute(params![
                    path, arch, name.is_none(), name.as_deref().unwrap_or(""), e.value_type, e.size as i64,
                    e.md5, e.sha1, e.sha256, e.mtime, e.owner, e.perms, e.data
                ])?;
            }
            let mut del = tx.prepare("DELETE FROM registry WHERE path = ?1 AND arch = ?2 AND is_key = ?3 AND value_name = ?4")?;
            for (path, arch, name) in deleted {
                del.execute(params![path, arch, name.is_none(), name.as_deref().unwrap_or("")])?;
            }
        }
        tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_baseline_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join("fim.db");
        let (a, b) = (PathBuf::from(r"C:\x\a.txt"), PathBuf::from(r"C:\x\b.txt"));
        let m = |s: &str| FileMetadata { size_bytes: 3, sha256: s.into(), modified_timestamp: 7, owner_sid: "S-1-5-18".into(), ..Default::default() };
        {
            let mut db = FimDb::open(&path).unwrap();
            assert!(db.load().unwrap().is_empty());
            db.apply(&[(&a, &m("h1")), (&b, &m("h2"))], &[]).unwrap();
            db.apply(&[(&a, &m("h3"))], &[&b]).unwrap();
        }
        let db = FimDb::open(&path).unwrap();
        let base = db.load().unwrap();
        assert_eq!(base.len(), 1);
        assert_eq!(base[&a].sha256, "h3");
        assert_eq!(base[&a].owner_sid, "S-1-5-18");
    }

    /// A `fim.db` from before the hashes and security columns: rows kept, the columns added,
    /// and the first scan records them without reporting anything.
    #[test]
    fn migrates_the_old_files_table() {
        let dir = tempfile::tempdir().unwrap();
        let (watched, path) = (dir.path().join("w"), dir.path().join("fim.db"));
        std::fs::create_dir_all(&watched).unwrap();
        let file = watched.join("a.txt");
        std::fs::write(&file, "abc").unwrap();
        let now = crate::fim::read_file(&file).unwrap();
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE files (path TEXT PRIMARY KEY, size INTEGER NOT NULL, sha256 TEXT NOT NULL, mtime INTEGER NOT NULL)").unwrap();
            c.execute(
                "INSERT INTO files VALUES (?1, ?2, ?3, ?4)",
                params![file.to_string_lossy(), now.size_bytes as i64, now.sha256, now.modified_timestamp],
            )
            .unwrap();
        }
        let base = FimDb::open(&path).unwrap().load().unwrap();
        assert_eq!(base[&file].sha256, now.sha256);
        assert_eq!(base[&file].md5, "");

        let mut s = crate::fim::FimScanner::new(vec![watched]).with_database(&path);
        assert!(s.scan("1", "n").is_empty(), "migrated baseline reported changes");
        drop(s);
        let base = FimDb::open(&path).unwrap().load().unwrap();
        assert_eq!(base[&file], now, "new fields recorded");
    }

    #[test]
    fn registry_table_keeps_keys_and_default_values_apart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fim.db");
        let key: RegId = (r"HKEY_CURRENT_USER\Software\X".into(), "[x64]".into(), None);
        let default_value: RegId = (key.0.clone(), key.1.clone(), Some(String::new()));
        let e = |t: &str| RegEntry { value_type: t.into(), data: Some("d".into()), ..Default::default() };
        {
            let mut db = FimDb::open(&path).unwrap();
            db.apply_registry(&[(&key, &e("")), (&default_value, &e("REG_SZ"))], &[]).unwrap();
        }
        let mut db = FimDb::open(&path).unwrap();
        let base = db.load_registry().unwrap();
        assert_eq!(base.len(), 2);
        assert_eq!(base[&default_value].value_type, "REG_SZ");
        db.apply_registry(&[], &[&default_value]).unwrap();
        assert_eq!(db.load_registry().unwrap().keys().collect::<Vec<_>>(), vec![&key]);
    }
}
