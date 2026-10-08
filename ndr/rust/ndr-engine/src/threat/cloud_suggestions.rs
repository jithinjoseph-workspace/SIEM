use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

use crate::ai::provider::{generate, UseCase};
use crate::storage::ClickhouseStorage;

const SUGGESTION_KEY: &str = "trusted_cloud_suggestions";
const REJECTED_KEY:   &str = "trusted_cloud_rejected";

/// Spawn background task: every 6h scan traffic for unknown high-volume orgs,
/// ask AI if they are legitimate cloud/CDN providers, store suggestions in ndr.settings.
pub fn spawn_suggestion_scanner(ch: Arc<ClickhouseStorage>, is_leader: Arc<std::sync::atomic::AtomicBool>) {
    tokio::spawn(async move {
        // Initial delay — let the engine fully start before first scan
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        loop {
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                run_scan(&ch).await;
            }
            // Check every 15 min so new unknown providers appear in admin page quickly
            tokio::time::sleep(std::time::Duration::from_secs(900)).await;
        }
    });
}

async fn run_scan(ch: &Arc<ClickhouseStorage>) {
    info!("cloud_suggestions: starting ASN scan");

    // Read current trusted keywords and already-rejected orgs to skip them
    let keywords_str = ch.get_global_setting("trusted_cloud_asn_keywords").await
        .unwrap_or_default();
    let rejected_str = ch.get_global_setting(REJECTED_KEY).await
        .unwrap_or_default();
    let current_keywords: Vec<String> = keywords_str.split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();
    let rejected: Vec<String> = rejected_str.split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    // Load existing suggestions so we don't re-ask AI about orgs already pending
    let existing_suggestions = load_suggestions(ch).await;
    let already_suggested: Vec<String> = existing_suggestions.keys()
        .map(|k| k.to_uppercase())
        .collect();

    // Get top clean dst IPs from last 24h across ALL active tenants
    let tenant_ids = ch.get_all_tenants().await.unwrap_or_else(|_| vec!["default".to_string()]);
    let sem = Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
    let mut handles = Vec::with_capacity(tenant_ids.len());
    for tid in tenant_ids {
        let ch2  = Arc::clone(ch);
        let sem2 = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            if !ch2.get_tenant_ai_enabled(&tid).await { return None; }
            match ch2.get_high_volume_clean_dst_ips(&tid, 24, 30).await {
                Ok(v) => Some(v),
                Err(e) => { warn!("cloud_suggestions: query failed for tenant {} — {}", tid, e); None }
            }
        }));
    }
    let mut combined: HashMap<String, u64> = HashMap::new();
    for handle in futures_util::future::join_all(handles).await {
        if let Ok(Some(v)) = handle {
            for (ip, cnt) in v {
                *combined.entry(ip).or_default() += cnt;
            }
        }
    }
    if combined.is_empty() { return; }
    let ip_counts: Vec<(String, u64)> = combined.into_iter().collect();

    // ASN lookup — group IPs by org
    let asn_db = crate::enrichment::AsnLookup::open("data/GeoLite2-ASN.mmdb");
    let mut org_hits: HashMap<String, u64> = HashMap::new();
    if let Ok(db) = &asn_db {
        for (ip, cnt) in &ip_counts {
            if let Some(info) = db.lookup(ip) {
                if !info.org.is_empty() {
                    *org_hits.entry(info.org.clone()).or_default() += cnt;
                }
            }
        }
    } else {
        warn!("cloud_suggestions: ASN db not available");
        return;
    }

    // Filter: skip already trusted, rejected, or already suggested
    let candidates: Vec<(String, u64)> = org_hits.into_iter()
        .filter(|(org, _)| {
            let up = org.to_uppercase();
            !current_keywords.iter().any(|kw| up.contains(kw.as_str()))
                && !rejected.iter().any(|r| up.contains(r.as_str()))
                && !already_suggested.iter().any(|s| up.contains(s.as_str()))
        })
        .collect();

    if candidates.is_empty() {
        info!("cloud_suggestions: no new candidates found");
        return;
    }

    info!("cloud_suggestions: {} candidates to evaluate", candidates.len());

    // For each candidate ask AI
    let mut new_suggestions = existing_suggestions;

    for (org, hits) in candidates.iter().take(10) {
        let is_cloud = ask_ai_is_cloud(ch, org, *hits).await;
        if is_cloud {
            info!("cloud_suggestions: AI flagged '{}' as trusted cloud ({} hits)", org, hits);
            new_suggestions.insert(org.clone(), *hits);
        } else {
            info!("cloud_suggestions: AI rejected '{}' as trusted cloud", org);
        }
        // Small delay between AI calls
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    save_suggestions(ch, &new_suggestions).await;
}

async fn ask_ai_is_cloud(ch: &Arc<ClickhouseStorage>, org: &str, hits: u64) -> bool {
    let system = "You are a network security analyst. Answer ONLY with JSON.";
    let prompt = format!(
        "Is the following ASN organization a legitimate public cloud provider, CDN, or major internet service (like AWS, Google, Microsoft, Cloudflare, Akamai, Meta/WhatsApp, Apple, etc.)?\n\
         Organization: \"{org}\"\n\
         Context: Seen {hits} outbound connections in 24h, zero threat-intel hits, zero IDS alerts.\n\
         Respond ONLY with JSON: {{\"trusted\": true/false, \"reason\": \"one sentence\"}}"
    );

    let raw = generate(ch, UseCase::ThreatPrediction, system, &prompt).await;

    // Parse JSON response
    let trimmed = raw.trim();
    let json_start = trimmed.find('{').unwrap_or(0);
    let json_end   = trimmed.rfind('}').map(|i| i + 1).unwrap_or(trimmed.len());
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&trimmed[json_start..json_end]) {
        return v.get("trusted").and_then(|t| t.as_bool()).unwrap_or(false);
    }
    // If we can't parse, default to not trusted (safe)
    false
}

// ── Suggestion persistence ────────────────────────────────────────────────────

pub async fn load_suggestions(ch: &Arc<ClickhouseStorage>) -> HashMap<String, u64> {
    let raw = ch.get_global_setting(SUGGESTION_KEY).await.unwrap_or_default();
    if raw.is_empty() { return HashMap::new(); }
    serde_json::from_str::<HashMap<String, u64>>(&raw).unwrap_or_default()
}

async fn save_suggestions(ch: &Arc<ClickhouseStorage>, suggestions: &HashMap<String, u64>) {
    let json = serde_json::to_string(suggestions).unwrap_or_default();
    if let Err(e) = ch.set_global_setting(SUGGESTION_KEY, &json).await {
        warn!("cloud_suggestions: failed to save suggestions — {}", e);
    }
}

/// Approve a suggestion: move org keyword into trusted_cloud_asn_keywords, remove from suggestions.
pub async fn approve_suggestion(
    ch: &Arc<ClickhouseStorage>,
    org: &str,
    trusted: &Arc<tokio::sync::RwLock<crate::threat::cloud_trust::TrustedRanges>>,
) -> anyhow::Result<()> {
    // Add to active keyword list
    let current = ch.get_global_setting("trusted_cloud_asn_keywords").await
        .unwrap_or_default();
    let keyword = extract_keyword(org);
    let updated = if current.is_empty() {
        keyword.clone()
    } else if current.split(',').any(|k| k.trim().eq_ignore_ascii_case(&keyword)) {
        current // already present
    } else {
        format!("{},{}", current, keyword)
    };
    ch.set_global_setting("trusted_cloud_asn_keywords", &updated).await?;

    // Remove from suggestions
    let mut suggestions = load_suggestions(ch).await;
    suggestions.retain(|k, _| !k.eq_ignore_ascii_case(org));
    save_suggestions(ch, &suggestions).await;

    // Hot-reload TrustedRanges in memory without waiting for next 23h cycle
    {
        let mut guard = trusted.write().await;
        guard.add_asn_keyword(&keyword);
    }

    info!("cloud_suggestions: approved '{}' → keyword '{}'", org, keyword);
    Ok(())
}

/// Reject a suggestion: remove from suggestions, add to rejected list so AI won't re-suggest.
pub async fn reject_suggestion(ch: &Arc<ClickhouseStorage>, org: &str) -> anyhow::Result<()> {
    let mut suggestions = load_suggestions(ch).await;
    suggestions.retain(|k, _| !k.eq_ignore_ascii_case(org));
    save_suggestions(ch, &suggestions).await;

    // Add to rejected list
    let current = ch.get_global_setting(REJECTED_KEY).await.unwrap_or_default();
    let keyword = extract_keyword(org);
    let updated = if current.is_empty() { keyword.clone() }
                  else { format!("{},{}", current, keyword) };
    ch.set_global_setting(REJECTED_KEY, &updated).await?;

    info!("cloud_suggestions: rejected '{}'", org);
    Ok(())
}

/// Extract the most useful keyword from a full org name.
/// "ORACLE CLOUD INFRASTRUCTURE" → "ORACLE"
fn extract_keyword(org: &str) -> String {
    let up = org.to_uppercase();
    // Known multi-word brands to preserve
    for multi in &["DIGITAL OCEAN", "HETZNER", "LINODE", "VULTR", "OVH", "LEASEWEB"] {
        if up.contains(multi) { return multi.replace(' ', ""); }
    }
    // Otherwise take the first meaningful word (skip AS numbers like "AS12345")
    up.split_whitespace()
        .find(|w| !w.starts_with("AS") || !w[2..].chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(&up)
        .to_string()
}
