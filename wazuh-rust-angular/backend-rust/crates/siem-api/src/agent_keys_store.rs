//! The agents' secret keys (`etc/client.keys` lines) kept in ClickHouse
//! (`ndr.agent_keys`), encrypted with AES-256-GCM under a key derived from
//! `AGENT_KEYS_SECRET`. ClickHouse is the master copy: it is loaded at
//! start and `etc/client.keys` (what remoted reads) is written from it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clickhouse::Row;
use provigil_agent_server::keys;
use ring::aead::LessSafeKey;
use serde::{Deserialize, Serialize};

use siem_crypto::keys::KeyStore;
use tracing::{info, warn};

use crate::tenancy::DEFAULT_DB;
use crate::AppState;

/// Bumped by `provigil_manager::save_keys`: the sync writes the keystore when it moves.
pub static VERSION: AtomicU64 = AtomicU64::new(0);
/// Wakes the sync as soon as a key is added or removed (not on its next 5 s check).
pub static CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();

#[derive(Row, Serialize, Deserialize)]
struct KeyRow {
    agent_id: String,
    key_enc: String,
    deleted: u8,
    updated_at: u64,
}

pub(crate) fn cipher() -> Option<LessSafeKey> {
    keys::cipher(&std::env::var("AGENT_KEYS_SECRET").ok().filter(|s| !s.trim().is_empty())?)
}

pub use provigil_agent_server::keys::{decrypt, encrypt};

async fn ensure_table(state: &AppState) -> bool {
    let q = format!(
        "CREATE TABLE IF NOT EXISTS `{DEFAULT_DB}`.agent_keys (
            agent_id String,
            key_enc String,
            deleted UInt8,
            updated_at UInt64
        ) ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY agent_id"
    );
    state.db.root().query(&q).execute().await.map_err(|e| warn!("agent_keys: {e}")).is_ok()
}

/// Adds the stored keys to the platform keystore; returns the stored keys by agent id
/// (None: ClickHouse or AGENT_KEYS_SECRET unavailable, the file stays the only copy).
pub async fn load(state: &AppState) -> Option<BTreeMap<String, String>> {
    if !state.db.is_connected() {
        return None;
    }
    let Some(c) = cipher() else {
        warn!("AGENT_KEYS_SECRET is not set: agent keys are kept only in etc/client.keys");
        return None;
    };
    if !ensure_table(state).await {
        return None;
    }
    let rows = match state
        .db
        .root()
        .query(&format!("SELECT ?fields FROM `{DEFAULT_DB}`.agent_keys FINAL WHERE deleted = 0"))
        .fetch_all::<KeyRow>()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("agent_keys: {e}");
            return None;
        }
    };
    let mut stored = BTreeMap::new();
    let mut added = 0;
    {
        let mut ks = state.auth_keystore.write().unwrap();
        for r in &rows {
            let Some(line) = decrypt(&c, &r.key_enc) else {
                warn!("agent_keys: cannot decrypt the key of agent {} (AGENT_KEYS_SECRET changed?)", r.agent_id);
                continue;
            };
            if let Some(k) = KeyStore::parse_line(&line) {
                if ks.find_by_id(&k.id).is_none() {
                    ks.add_key(k);
                    added += 1;
                }
            }
            stored.insert(r.agent_id.clone(), line);
        }
    }
    info!("Loaded {} agent keys from ClickHouse ({added} not in memory yet)", rows.len());
    Some(stored)
}

/// The keys to write and the agents to mark deleted, to bring `stored` to `current`.
fn changes<'a>(stored: &'a BTreeMap<String, String>, current: &'a BTreeMap<String, String>) -> (Vec<(&'a String, &'a String)>, Vec<&'a String>) {
    let changed = current.iter().filter(|(id, line)| stored.get(*id) != Some(line)).collect();
    let gone = stored.keys().filter(|id| !current.contains_key(*id)).collect();
    (changed, gone)
}

/// Writes the keys that changed since `stored` (a change costs its own key, not the fleet's).
async fn save(state: &AppState, c: &LessSafeKey, stored: &mut BTreeMap<String, String>) -> bool {
    let at = chrono::Utc::now().timestamp_millis() as u64;
    let current: BTreeMap<String, String> = state.auth_keystore.read().unwrap().keys.iter().map(|k| (k.id.clone(), k.to_key_line())).collect();
    let (changed, gone) = changes(stored, &current);
    let mut rows = Vec::with_capacity(changed.len() + gone.len());
    for (id, line) in changed {
        let Some(enc) = encrypt(c, line) else { return false };
        rows.push(KeyRow { agent_id: id.clone(), key_enc: enc, deleted: 0, updated_at: at });
    }
    rows.extend(gone.into_iter().map(|id| KeyRow { agent_id: id.clone(), key_enc: String::new(), deleted: 1, updated_at: at }));
    if rows.is_empty() {
        return true;
    }
    let client = state.db.root().clone().with_database(DEFAULT_DB);
    let mut ins = match client.insert("agent_keys") {
        Ok(i) => i,
        Err(e) => {
            warn!("agent_keys: {e}");
            return false;
        }
    };
    for r in &rows {
        if let Err(e) = ins.write(r).await {
            warn!("agent_keys: {e}");
            return false;
        }
    }
    if let Err(e) = ins.end().await {
        warn!("agent_keys: {e}");
        return false;
    }
    *stored = current;
    true
}

/// Writes the keystore to ClickHouse when it changed: right away (`CHANGED`), checked every
/// 5 s too (a failed write is retried), and once at start.
pub fn spawn_sync(state: AppState, mut stored: BTreeMap<String, String>) {
    let Some(c) = cipher() else { return };
    tokio::spawn(async move {
        let mut saved = None;
        loop {
            // a git merge or a cleanup can delete etc/client.keys: write it back from the keystore
            if crate::provigil_manager::keys_file_missing() {
                warn!("etc/client.keys is missing: rewriting it from the stored keys");
                crate::provigil_manager::save_keys(&state);
            }
            let v = VERSION.load(Ordering::SeqCst);
            if saved != Some(v) && save(&state, &c, &mut stored).await {
                saved = Some(v);
                // ClickHouse has every key now: an old etc/client.keys is not needed any more
                crate::provigil_manager::forget_keys_file();
            }
            if tokio::time::timeout(Duration::from_secs(5), CHANGED.notified()).await.is_ok() {
                // a mass enrollment: one insert for many keys, not one ClickHouse part per key
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_touches_only_its_own_key() {
        let map = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<BTreeMap<_, _>>();
        let stored = map(&[("001", "001 a any k1"), ("002", "002 b any k2"), ("003", "003 c any k3")]);
        let current = map(&[("001", "001 a any k1"), ("002", "002 b any NEW"), ("004", "004 d any k4")]);
        let (changed, gone) = changes(&stored, &current);
        assert_eq!(changed.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), ["002", "004"]);
        assert_eq!(gone, ["003"]);
        let (changed, gone) = changes(&current, &current);
        assert!(changed.is_empty() && gone.is_empty());
    }

    #[test]
    fn roundtrip() {
        let c = keys::cipher("test-secret").unwrap();
        let line = "001 web any 0123456789abcdef";
        let e = encrypt(&c, line).unwrap();
        assert!(!e.contains("web"));
        assert_ne!(e, encrypt(&c, line).unwrap());
        assert_eq!(decrypt(&c, &e).as_deref(), Some(line));
        let c2 = keys::cipher("other").unwrap();
        assert_eq!(decrypt(&c2, &e), None);
    }
}
