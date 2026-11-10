//! What the manager last got from this agent (`data\sent.db`, SQLite), so a configuration
//! assessment scan or an inventory sends only what changed. Written when the events are queued:
//! one lost on the way shows at the manager as a hash that differs, and it asks for a full send.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection};

pub fn file() -> PathBuf {
    PathBuf::from("data").join("sent.db")
}

/// The splay of a first send when `full_send_splay_secs` is not set: an install shows its data
/// within half a minute; a mass install that sends too much at once gets "busy, retry" from the
/// gateway, so nothing is lost.
pub const FIRST_SPLAY: u64 = 30;
/// The splay of a later full send when it is not set: a fleet asked at once spreads over an hour.
pub const LATER_SPLAY: u64 = 3600;

/// A random wait of 0 to the splay before a full send; `first`: nothing was sent yet.
pub fn splay(setting: Option<u64>, first: bool) -> Duration {
    let max = setting.unwrap_or(if first { FIRST_SPLAY } else { LATER_SPLAY });
    Duration::from_secs((uuid::Uuid::new_v4().as_u128() % (u128::from(max) + 1)) as u64)
}

/// Waits a full send's splay; false when the agent stopped meanwhile (nothing is then sent).
pub fn wait_splay(setting: Option<u64>, first: bool) -> bool {
    let d = splay(setting, first);
    if !d.is_zero() {
        tracing::info!(seconds = d.as_secs(), "Full send in a moment (full_send_splay_secs)");
        crate::nap(d, crate::collecting);
    }
    crate::collecting()
}

pub struct Sent {
    conn: Connection,
}

impl Sent {
    pub fn open(path: &Path) -> rusqlite::Result<Sent> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        // the configuration assessment and inventory loops each open this file
        conn.busy_timeout(Duration::from_secs(30))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS sca (
                 agent TEXT NOT NULL,
                 policy TEXT NOT NULL,
                 policy_hash TEXT NOT NULL,
                 check_id INTEGER NOT NULL,
                 result TEXT NOT NULL,
                 PRIMARY KEY (agent, policy, check_id)
             );
             CREATE TABLE IF NOT EXISTS inventory (
                 agent TEXT NOT NULL,
                 part TEXT NOT NULL,
                 item TEXT NOT NULL,
                 hash TEXT NOT NULL,
                 PRIMARY KEY (agent, part, item)
             );
             CREATE TABLE IF NOT EXISTS times (
                 agent TEXT NOT NULL,
                 name TEXT NOT NULL,
                 at INTEGER NOT NULL,
                 PRIMARY KEY (agent, name)
             );",
        )?;
        Ok(Sent { conn })
    }

    /// The check results last sent for this text of the policy (empty: none, a full send).
    pub fn sca(&self, agent: &str, policy: &str, policy_hash: &str) -> rusqlite::Result<HashMap<u32, String>> {
        let mut st = self.conn.prepare_cached("SELECT check_id, result FROM sca WHERE agent = ?1 AND policy = ?2 AND policy_hash = ?3")?;
        let rows = st.query_map(params![agent, policy, policy_hash], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    pub fn save_sca(&mut self, agent: &str, policy: &str, policy_hash: &str, results: &[(u32, &str)]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM sca WHERE agent = ?1 AND policy = ?2", params![agent, policy])?;
        {
            let mut st = tx.prepare_cached("INSERT OR REPLACE INTO sca VALUES (?1, ?2, ?3, ?4, ?5)")?;
            for (id, result) in results {
                st.execute(params![agent, policy, policy_hash, id, result])?;
            }
        }
        tx.commit()
    }

    /// Whether any check result was sent for this agent.
    pub fn has_sca(&self, agent: &str) -> bool {
        self.conn.query_row("SELECT 1 FROM sca WHERE agent = ?1 LIMIT 1", params![agent], |_| Ok(())).is_ok()
    }

    /// A part's items last sent: key -> hash.
    pub fn items(&self, agent: &str, part: &str) -> rusqlite::Result<HashMap<String, String>> {
        let mut st = self.conn.prepare_cached("SELECT item, hash FROM inventory WHERE agent = ?1 AND part = ?2")?;
        let rows = st.query_map(params![agent, part], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    /// Replaces the items of the parts given, in one transaction.
    pub fn save_items(&mut self, agent: &str, parts: &BTreeMap<&str, Vec<(&str, &str)>>) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        for (part, items) in parts {
            tx.execute("DELETE FROM inventory WHERE agent = ?1 AND part = ?2", params![agent, part])?;
            let mut st = tx.prepare_cached("INSERT OR REPLACE INTO inventory VALUES (?1, ?2, ?3, ?4)")?;
            for (item, hash) in items {
                st.execute(params![agent, part, item, hash])?;
            }
        }
        tx.commit()
    }

    /// When `name` last happened (Unix seconds).
    pub fn at(&self, agent: &str, name: &str) -> Option<i64> {
        self.conn.query_row("SELECT at FROM times WHERE agent = ?1 AND name = ?2", params![agent, name], |r| r.get(0)).ok()
    }

    pub fn set_at(&self, agent: &str, name: &str, at: i64) -> rusqlite::Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO times VALUES (?1, ?2, ?3)", params![agent, name, at]).map(|_| ())
    }

    /// A new enrollment starts empty at the manager, also when it gives the same id back.
    pub fn clear(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch("DELETE FROM sca; DELETE FROM inventory; DELETE FROM times;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_per_agent_policy_text_and_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join("sent.db");
        let mut s = Sent::open(&path).unwrap();
        s.save_sca("001", "p", "h1", &[(1, "passed"), (2, "failed")]).unwrap();
        s.save_items("001", &BTreeMap::from([("packages", vec![("a", "1"), ("b", "2")])])).unwrap();
        s.set_at("001", "inventory", 7).unwrap();
        drop(s);

        let mut s = Sent::open(&path).unwrap();
        assert_eq!(s.sca("001", "p", "h1").unwrap().len(), 2, "over a restart");
        assert!(s.sca("001", "p", "h2").unwrap().is_empty(), "the policy text changed");
        assert!(s.sca("002", "p", "h1").unwrap().is_empty(), "another agent id");
        s.save_sca("001", "p", "h2", &[(1, "failed")]).unwrap();
        assert_eq!(s.sca("001", "p", "h2").unwrap()[&1], "failed");
        assert!(s.sca("001", "p", "h1").unwrap().is_empty(), "replaced");

        s.save_items("001", &BTreeMap::from([("packages", vec![("a", "9")])])).unwrap();
        assert_eq!(s.items("001", "packages").unwrap(), HashMap::from([("a".to_string(), "9".to_string())]));
        assert_eq!((s.at("001", "inventory"), s.at("001", "other"), s.at("002", "inventory")), (Some(7), None, None));

        s.clear().unwrap();
        assert!(s.sca("001", "p", "h2").unwrap().is_empty() && s.items("001", "packages").unwrap().is_empty());
        assert_eq!(s.at("001", "inventory"), None);
    }

    #[test]
    fn full_sends_spread() {
        let draws = |setting, first| (0..400).map(|_| splay(setting, first).as_secs()).collect::<Vec<_>>();
        let first = draws(None, true);
        assert!(first.iter().all(|s| *s <= FIRST_SPLAY) && first.iter().any(|s| *s > FIRST_SPLAY / 2), "a new install: within half a minute");
        let later = draws(None, false);
        assert!(later.iter().all(|s| *s <= LATER_SPLAY) && later.iter().any(|s| *s > FIRST_SPLAY));
        let set = draws(Some(20_000), true);
        assert!(set.iter().all(|s| *s <= 20_000) && set.iter().any(|s| *s > LATER_SPLAY), "the setting widens it");
        assert!(draws(Some(0), false).iter().all(|s| *s == 0));
        assert!(wait_splay(Some(0), true));
    }
}
