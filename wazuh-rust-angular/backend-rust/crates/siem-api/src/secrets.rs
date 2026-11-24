//! Secrets kept in ClickHouse (SOAR integration credentials, AI provider keys): sealed with
//! `AGENT_KEYS_SECRET` as `enc:v1:<hex>`, the one format every ProVigil service reads
//! (provigil_common::secrets: the NDR engine opens the integrations siem-api seals).
//! Values written before (plain text) are still read, and re-sealed at start (`reseal_all`).

use serde_json::Value;
use tracing::warn;

pub use provigil_common::secrets::{open, open_config, seal, seal_config, PREFIX};

/// Whether secrets can be sealed at all.
pub fn available() -> bool {
    provigil_common::secrets::cipher().is_some()
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
    use provigil_common::secrets::{cipher_from, open_with, seal_with, PREFIX};

    /// The shared format must stay the agent keys' cipher (provigil-agent-server's `keys`): a value
    /// sealed by one opens with the other.
    #[test]
    fn sealed_values_match_the_agent_keys_cipher() {
        let shared = cipher_from("same-secret").unwrap();
        let agent = provigil_agent_server::keys::cipher("same-secret").unwrap();
        let enc = crate::agent_keys_store::encrypt(&agent, "pa$$word").unwrap();
        assert_eq!(open_with(Some(&shared), &format!("{PREFIX}{enc}")), "pa$$word");
        let sealed = seal_with(Some(&shared), "token-123");
        assert_eq!(crate::agent_keys_store::decrypt(&agent, sealed.strip_prefix(PREFIX).unwrap()).as_deref(), Some("token-123"));
    }
}
