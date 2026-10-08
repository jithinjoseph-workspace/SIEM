use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{info, warn};

use crate::threat_intel::{
    ThreatIntelEntry,
    FEED_CISA_KEV, FEED_ABUSEIPDB, FEED_OTX, FEED_EMERGING_THREATS,
    FEED_FEODO, FEED_URLHAUS, FEED_THREATFOX,
    FEED_SPAMHAUS_DROP, FEED_SPAMHAUS_EDROP,
    feeds::{parse_cisa_kev, parse_abuseipdb, parse_otx, parse_emerging_threats,
            parse_feodo, parse_urlhaus, parse_threatfox, parse_spamhaus_drop},
};

// ── Storage abstraction ───────────────────────────────────────────────────────
//
// Both ndr-engine and siem-engine implement this on their storage types.
// The collector holds a &dyn ThreatCollectorStore and never imports engine internals.

#[async_trait::async_trait]
pub trait ThreatCollectorStore: Send + Sync {
    /// Load all currently stored (source, ioc_value) pairs so duplicates are skipped.
    async fn fetch_existing_iocs(&self) -> HashSet<(String, String)>;
    /// Return (abuseipdb_api_key, otx_api_key) — may come from DB settings, env vars, etc.
    async fn get_api_keys(&self) -> (String, String);
    /// Persist new IOC entries, skipping any already in `existing`. Returns count inserted.
    async fn insert_ioc_entries(
        &self,
        existing: &HashSet<(String, String)>,
        entries: Vec<ThreatIntelEntry>,
    ) -> usize;
}

// ── Spawner ───────────────────────────────────────────────────────────────────

pub fn spawn_collector(store: Arc<dyn ThreatCollectorStore>) {
    tokio::spawn(async move {
        loop {
            info!("Threat intel collection starting");
            collect_all(store.as_ref()).await;
            info!("Threat intel collection done — next run in 6 hours");
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });
}

// ── Main collection cycle ─────────────────────────────────────────────────────

pub async fn collect_all(store: &dyn ThreatCollectorStore) {
    let existing = Arc::new(store.fetch_existing_iocs().await);
    let (abuseipdb_key, otx_key) = store.get_api_keys().await;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("NDR-Engine/1.0")
        .build()
        .unwrap_or_default();

    tokio::join!(
        run_feed_cisa_kev(&http, store, &existing),
        run_feed_abuseipdb(&http, store, &abuseipdb_key, &existing),
        run_feed_otx(&http, store, &otx_key, &existing),
        run_feed_emerging_threats(&http, store, &existing),
        run_feed_feodo(&http, store, &existing),
        run_feed_urlhaus(&http, store, &existing),
        run_feed_threatfox(&http, store, &existing),
        run_feed_spamhaus(&http, store, &existing),
    );
}

// ── Feed runners ──────────────────────────────────────────────────────────────

async fn run_feed_cisa_kev(
    http: &reqwest::Client,
    store: &dyn ThreatCollectorStore,
    existing: &HashSet<(String, String)>,
) {
    let Ok(resp) = http.get(FEED_CISA_KEV).send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_cisa_kev(&data);
    let n = store.insert_ioc_entries(existing, entries).await;
    info!("CISA KEV: {} recent vulns collected", n);
}

async fn run_feed_abuseipdb(
    http: &reqwest::Client,
    store: &dyn ThreatCollectorStore,
    api_key: &str,
    existing: &HashSet<(String, String)>,
) {
    if api_key.is_empty() {
        warn!("abuseipdb_api_key not configured — skipping");
        return;
    }
    let Ok(resp) = http.get(FEED_ABUSEIPDB)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_abuseipdb(&data);
    let n = entries.len();
    store.insert_ioc_entries(existing, entries).await;
    info!("AbuseIPDB: {} malicious IPs collected", n);
}

async fn run_feed_otx(
    http: &reqwest::Client,
    store: &dyn ThreatCollectorStore,
    api_key: &str,
    existing: &HashSet<(String, String)>,
) {
    if api_key.is_empty() {
        warn!("otx_api_key not configured — skipping");
        return;
    }
    let Ok(resp) = http.get(FEED_OTX)
        .header("X-OTX-API-KEY", api_key)
        .send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_otx(&data);
    let n = entries.len();
    store.insert_ioc_entries(existing, entries).await;
    info!("OTX: {} IOCs collected", n);
}

async fn run_feed_emerging_threats(
    http: &reqwest::Client,
    store: &dyn ThreatCollectorStore,
    existing: &HashSet<(String, String)>,
) {
    let Ok(resp) = http.get(FEED_EMERGING_THREATS).send().await else { return };
    let Ok(text) = resp.text().await else { return };
    let entries = parse_emerging_threats(&text);
    let n = entries.len();
    store.insert_ioc_entries(existing, entries).await;
    info!("Emerging Threats: {} attack categories", n);
}

async fn run_feed_feodo(
    http: &reqwest::Client,
    store: &dyn ThreatCollectorStore,
    existing: &HashSet<(String, String)>,
) {
    let Ok(resp) = http.get(FEED_FEODO).send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_feodo(&data);
    let n = store.insert_ioc_entries(existing, entries).await;
    info!("Feodo Tracker: {} botnet C2 IPs collected", n);
}

async fn run_feed_urlhaus(
    http: &reqwest::Client,
    store: &dyn ThreatCollectorStore,
    existing: &HashSet<(String, String)>,
) {
    let Ok(resp) = http.get(FEED_URLHAUS).send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_urlhaus(&data);
    let n = store.insert_ioc_entries(existing, entries).await;
    info!("URLhaus: {} malware distribution IOCs collected", n);
}

async fn run_feed_threatfox(
    http: &reqwest::Client,
    store: &dyn ThreatCollectorStore,
    existing: &HashSet<(String, String)>,
) {
    let body = serde_json::json!({ "query": "get_iocs", "days": 3 });
    let Ok(resp) = http.post(FEED_THREATFOX)
        .json(&body)
        .send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_threatfox(&data);
    let n = store.insert_ioc_entries(existing, entries).await;
    info!("ThreatFox: {} malware family IOCs collected", n);
}

async fn run_feed_spamhaus(
    http: &reqwest::Client,
    store: &dyn ThreatCollectorStore,
    existing: &HashSet<(String, String)>,
) {
    let (drop_res, edrop_res) = tokio::join!(
        http.get(FEED_SPAMHAUS_DROP).send(),
        http.get(FEED_SPAMHAUS_EDROP).send(),
    );

    let mut all_entries = Vec::new();
    if let Ok(r) = drop_res {
        if let Ok(text) = r.text().await { all_entries.extend(parse_spamhaus_drop(&text, "DROP")); }
    }
    if let Ok(r) = edrop_res {
        if let Ok(text) = r.text().await { all_entries.extend(parse_spamhaus_drop(&text, "EDROP")); }
    }

    let n = store.insert_ioc_entries(existing, all_entries).await;
    info!("Spamhaus DROP+EDROP: {} criminal CIDR blocks collected", n);
}
