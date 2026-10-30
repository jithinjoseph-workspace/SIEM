//! The agents' secret keys (`etc/client.keys` lines) kept in ClickHouse
//! (`ndr.agent_keys`), encrypted with AES-256-GCM under a key derived from
//! `AGENT_KEYS_SECRET`. ClickHouse is the master copy: it is loaded at
//! start and `etc/client.keys` (what remoted reads) is written from it.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clickhouse::Row;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use siem_crypto::keys::KeyStore;
use tracing::{info, warn};

use crate::tenancy::DEFAULT_DB;
use crate::AppState;

/// Bumped by `wazuh_manager::save_keys`: the sync writes the keystore when it moves.
pub static VERSION: AtomicU64 = AtomicU64::new(0);

#[derive(Row, Serialize, Deserialize)]
struct KeyRow {
    agent_id: String,
    key_enc: String,
    deleted: u8,
    updated_at: u64,
}

pub(crate) fn cipher() -> Option<LessSafeKey> {
    let secret = std::env::var("AGENT_KEYS_SECRET").ok().filter(|s| !s.trim().is_empty())?;
    let k = Sha256::digest(secret.trim().as_bytes());
    Some(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).ok()?))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// nonce || ciphertext+tag, hex
pub fn encrypt(c: &LessSafeKey, plain: &str) -> Option<String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).ok()?;
    let mut buf = plain.as_bytes().to_vec();
    c.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf).ok()?;
    Some(format!("{}{}", hex(&nonce), hex(&buf)))
}

pub fn decrypt(c: &LessSafeKey, enc: &str) -> Option<String> {
    let raw = unhex(enc)?;
    if raw.len() < NONCE_LEN {
        return None;
    }
    let (n, ct) = raw.split_at(NONCE_LEN);
    let mut buf = ct.to_vec();
    let plain = c.open_in_place(Nonce::try_assume_unique_for_key(n).ok()?, Aad::empty(), &mut buf).ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

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

/// Adds the stored keys to the platform keystore; returns the stored agent ids
/// (None: ClickHouse or AGENT_KEYS_SECRET unavailable, the file stays the only copy).
pub async fn load(state: &AppState) -> Option<BTreeSet<String>> {
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
    let mut ids = BTreeSet::new();
    let mut added = 0;
    {
        let mut ks = state.auth_keystore.write().unwrap();
        for r in &rows {
            let Some(line) = decrypt(&c, &r.key_enc) else {
                warn!("agent_keys: cannot decrypt the key of agent {} (AGENT_KEYS_SECRET changed?)", r.agent_id);
                continue;
            };
            ids.insert(r.agent_id.clone());
            if let Some(k) = KeyStore::parse_line(&line) {
                if ks.find_by_id(&k.id).is_none() {
                    ks.add_key(k);
                    added += 1;
                }
            }
        }
    }
    info!("Loaded {} agent keys from ClickHouse ({added} not in memory yet)", rows.len());
    Some(ids)
}

async fn save(state: &AppState, c: &LessSafeKey, stored: &mut BTreeSet<String>) -> bool {
    let at = chrono::Utc::now().timestamp_millis() as u64;
    let lines: Vec<(String, String)> = state.auth_keystore.read().unwrap().keys.iter().map(|k| (k.id.clone(), k.to_key_line())).collect();
    let current: BTreeSet<String> = lines.iter().map(|(id, _)| id.clone()).collect();
    let mut rows = Vec::new();
    for (id, line) in &lines {
        let Some(enc) = encrypt(c, line) else { return false };
        rows.push(KeyRow { agent_id: id.clone(), key_enc: enc, deleted: 0, updated_at: at });
    }
    rows.extend(stored.difference(&current).map(|id| KeyRow { agent_id: id.clone(), key_enc: String::new(), deleted: 1, updated_at: at }));
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

/// Writes the keystore to ClickHouse when it changed (checked every 5 s, and once at start).
pub fn spawn_sync(state: AppState, mut stored: BTreeSet<String>) {
    let Some(c) = cipher() else { return };
    tokio::spawn(async move {
        let mut saved = None;
        loop {
            // a git merge or a cleanup can delete etc/client.keys: write it back from the keystore
            if crate::wazuh_manager::keys_file_missing() {
                warn!("etc/client.keys is missing: rewriting it from the stored keys");
                crate::wazuh_manager::save_keys(&state);
            }
            let v = VERSION.load(Ordering::SeqCst);
            if saved != Some(v) && save(&state, &c, &mut stored).await {
                saved = Some(v);
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let k = Sha256::digest(b"test-secret");
        let c = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap());
        let line = "001 web any 0123456789abcdef";
        let e = encrypt(&c, line).unwrap();
        assert!(!e.contains("web"));
        assert_ne!(e, encrypt(&c, line).unwrap());
        assert_eq!(decrypt(&c, &e).as_deref(), Some(line));
        let k2 = Sha256::digest(b"other");
        let c2 = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k2).unwrap());
        assert_eq!(decrypt(&c2, &e), None);
    }
}
