//! Secrets kept in ClickHouse (SOAR integration credentials, AI provider keys), one format for
//! every ProVigil service: sealed with `AGENT_KEYS_SECRET` (AES-256-GCM, key = SHA-256 of the
//! secret, the agent keys' cipher) and stored as `enc:v1:<hex nonce||ciphertext+tag>`.
//! Values written before sealing existed (plain text) are still read as they are.
//! siem-api seals what it stores; the NDR engine opens what it reads, so both use the same
//! integrations. siem-api's test `sealed_values_match_the_agent_keys_cipher` pins this format to
//! provigil-agent-server's `keys` (the same cipher, kept apart to keep this crate's users light).

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::warn;

pub const PREFIX: &str = "enc:v1:";

/// Integration config keys that hold secrets.
pub const INTEGRATION_SECRET_KEYS: [&str; 9] = [
    "api_key",
    "routing_key",
    "smtp_pass",
    "bot_token",
    "password",
    "token",
    "community",
    "aws_secret_access_key",
    "secret",
];

pub fn cipher_from(secret: &str) -> Option<LessSafeKey> {
    let k = Sha256::digest(secret.trim().as_bytes());
    Some(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).ok()?))
}

/// The cipher of `AGENT_KEYS_SECRET`, or None when it is not set.
pub fn cipher() -> Option<LessSafeKey> {
    cipher_from(&std::env::var("AGENT_KEYS_SECRET").ok().filter(|s| !s.trim().is_empty())?)
}

fn encrypt(c: &LessSafeKey, plain: &str) -> Option<String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).ok()?;
    let mut buf = plain.as_bytes().to_vec();
    c.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf).ok()?;
    Some(nonce.iter().chain(buf.iter()).map(|b| format!("{b:02x}")).collect())
}

fn decrypt(c: &LessSafeKey, enc: &str) -> Option<String> {
    let raw: Vec<u8> = (0..enc.len()).step_by(2).map(|i| u8::from_str_radix(enc.get(i..i + 2)?, 16).ok()).collect::<Option<_>>()?;
    if raw.len() < NONCE_LEN {
        return None;
    }
    let (n, ct) = raw.split_at(NONCE_LEN);
    let mut buf = ct.to_vec();
    let plain = c.open_in_place(Nonce::try_assume_unique_for_key(n).ok()?, Aad::empty(), &mut buf).ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

pub fn seal_with(c: Option<&LessSafeKey>, plain: &str) -> String {
    if plain.is_empty() || plain.starts_with(PREFIX) {
        return plain.to_string();
    }
    match c.and_then(|c| encrypt(c, plain)) {
        Some(e) => format!("{PREFIX}{e}"),
        None => plain.to_string(),
    }
}

pub fn open_with(c: Option<&LessSafeKey>, stored: &str) -> String {
    let Some(enc) = stored.strip_prefix(PREFIX) else { return stored.to_string() };
    match c.and_then(|c| decrypt(c, enc)) {
        Some(p) => p,
        None => {
            warn!("a stored secret cannot be decrypted (AGENT_KEYS_SECRET changed or unset)");
            String::new()
        }
    }
}

/// The value as it is stored: sealed when `AGENT_KEYS_SECRET` is set.
pub fn seal(plain: &str) -> String {
    seal_with(cipher().as_ref(), plain)
}

/// The value as stored, opened ("" when it cannot be: AGENT_KEYS_SECRET changed or unset).
pub fn open(stored: &str) -> String {
    open_with(cipher().as_ref(), stored)
}

/// The secret fields of a config, sealed or opened.
pub fn seal_config(cfg: &Value, keys: &[&str]) -> Value {
    map(cfg, keys, seal)
}

pub fn open_config(cfg: &Value, keys: &[&str]) -> Value {
    map(cfg, keys, open)
}

fn map(cfg: &Value, keys: &[&str], f: fn(&str) -> String) -> Value {
    let mut c = cfg.clone();
    if let Some(o) = c.as_object_mut() {
        for k in keys {
            if let Some(Value::String(v)) = o.get(*k) {
                let nv = f(v);
                o.insert((*k).to_string(), Value::String(nv));
            }
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sealed_and_opened() {
        let k = cipher_from("test-secret-for-sealing").unwrap();
        let s = seal_with(Some(&k), "pa$$word");
        assert!(s.starts_with(PREFIX) && !s.contains("pa$$word"));
        assert_eq!(open_with(Some(&k), &s), "pa$$word");
        assert_ne!(seal_with(Some(&k), "pa$$word"), s, "a fresh nonce each time");
        assert_eq!(open_with(Some(&k), "old plain value"), "old plain value", "values stored before still read");
        assert_eq!(seal_with(Some(&k), ""), "");
        assert_eq!(seal_with(None, "x"), "x", "no secret configured: kept as it is");
        assert_eq!(open_with(Some(&cipher_from("another-secret").unwrap()), &s), "", "a changed secret opens nothing (no garbage)");
        assert_eq!(open_with(None, &s), "");
        assert_eq!(open_with(Some(&k), "enc:v1:zz"), "", "damaged values open to nothing");
    }

    #[test]
    fn configs_seal_only_their_secrets() {
        let cfg = json!({ "host": "10.0.0.1", "api_key": "k-123", "port": 443 });
        // without AGENT_KEYS_SECRET in the test environment the config is unchanged either way
        let sealed = seal_config(&cfg, &["api_key", "password"]);
        assert_eq!(sealed["host"], "10.0.0.1");
        assert_eq!(open_config(&sealed, &["api_key", "password"]), cfg);
    }
}
