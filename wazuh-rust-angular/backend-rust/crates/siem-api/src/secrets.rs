//! Secrets kept in ClickHouse (SOAR integration credentials, AI provider keys) are sealed
//! with `AGENT_KEYS_SECRET` (AES-256-GCM, the agent keys' cipher): stored as `enc:v1:<hex>`.
//! Values written before (plain text) are still read, and re-sealed at start (`reseal_all`).

use serde_json::Value;
use tracing::warn;

const PREFIX: &str = "enc:v1:";

use ring::aead::LessSafeKey;

/// The value as it is stored: sealed when `AGENT_KEYS_SECRET` is set.
pub fn seal(plain: &str) -> String {
    seal_with(crate::agent_keys_store::cipher().as_ref(), plain)
}

/// The value as stored, opened ("" when it cannot be: AGENT_KEYS_SECRET changed or unset).
pub fn open(stored: &str) -> String {
    open_with(crate::agent_keys_store::cipher().as_ref(), stored)
}

fn seal_with(c: Option<&LessSafeKey>, plain: &str) -> String {
    if plain.is_empty() || plain.starts_with(PREFIX) {
        return plain.to_string();
    }
    match c.and_then(|c| crate::agent_keys_store::encrypt(c, plain)) {
        Some(e) => format!("{PREFIX}{e}"),
        None => plain.to_string(),
    }
}

fn open_with(c: Option<&LessSafeKey>, stored: &str) -> String {
    let Some(enc) = stored.strip_prefix(PREFIX) else { return stored.to_string() };
    match c.and_then(|c| crate::agent_keys_store::decrypt(c, enc)) {
        Some(p) => p,
        None => {
            warn!("a stored secret cannot be decrypted (AGENT_KEYS_SECRET changed or unset)");
            String::new()
        }
    }
}

/// Whether secrets can be sealed at all.
pub fn available() -> bool {
    crate::agent_keys_store::cipher().is_some()
}

/// The secret fields of an integration config, sealed or opened.
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

/// At start: every stored integration and AI provider whose secrets are still plain text is
/// written again sealed, and the old versions are merged away.
pub async fn reseal_all(state: &crate::AppState) {
    if !available() {
        warn!("AGENT_KEYS_SECRET is not set: integration credentials and AI keys are stored unencrypted");
        return;
    }
    let st = crate::soar::store(state);
    for t in crate::predictions::tenant_ids(state) {
        let Ok(list) = st.integrations(&t).await else { continue };
        let plain: Vec<&Value> = list.iter().filter(|i| crate::soar::SECRET_KEYS.iter().any(|k| i["raw_config"][*k].as_str().is_some_and(|v| !v.is_empty() && !v.starts_with(PREFIX)))).collect();
        for i in &plain {
            let _ = st
                .put_integration(&t, i["id"].as_str().unwrap_or(""), i["name"].as_str().unwrap_or(""), i["type"].as_str().unwrap_or(""), &i["config"], i["enabled"].as_bool().unwrap_or(true))
                .await;
        }
        if !plain.is_empty() {
            let _ = state.db.tenant_client(&t).query("OPTIMIZE TABLE soar_integrations FINAL").execute().await;
            tracing::info!("sealed the credentials of {} SOAR integration(s) of tenant '{t}'", plain.len());
        }
    }
    let n = crate::ai_assist::reseal_provider_keys(state).await;
    if n > 0 {
        tracing::info!("sealed {n} AI provider key(s)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(secret: &str) -> LessSafeKey {
        use sha2::Digest;
        let k = sha2::Sha256::digest(secret.as_bytes());
        LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &k).unwrap())
    }

    #[test]
    fn sealed_and_opened() {
        let k = key("test-secret-for-sealing");
        let s = seal_with(Some(&k), "pa$$word");
        assert!(s.starts_with(PREFIX) && !s.contains("pa$$word"));
        assert_eq!(open_with(Some(&k), &s), "pa$$word");
        assert_ne!(seal_with(Some(&k), "pa$$word"), s, "a fresh nonce each time");
        assert_eq!(open_with(Some(&k), "old plain value"), "old plain value", "values stored before still read");
        assert_eq!(seal_with(Some(&k), ""), "");
        assert_eq!(seal_with(None, "x"), "x", "no secret configured: kept as it is");
        assert_eq!(open_with(Some(&key("another-secret")), &s), "", "a changed secret opens nothing (no garbage)");
        assert_eq!(open_with(None, &s), "");
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
