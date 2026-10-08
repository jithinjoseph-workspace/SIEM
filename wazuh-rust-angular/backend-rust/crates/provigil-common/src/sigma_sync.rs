// Common Sigma community rule sync — SigmaHQ GitHub → ndr.sigma_rules
// Used by both NDR engine and SIEM engine so SIEM-only deployments get rules too.
// License: Apache-2.0

use std::collections::HashSet;
use std::time::Duration;
use clickhouse::Client;
use tracing::{info, warn};

use crate::detection::parse_rule_content;

const GITHUB_NETWORK_API: &str =
    "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/network";
const GITHUB_LINUX_API: &str =
    "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/linux";
const GITHUB_WINDOWS_API: &str =
    "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows";

/// Rules permanently blocked from import regardless of DB state.
pub const GLOBAL_RULE_BLOCKLIST: &[&str] = &[
    "1fc0809e-06bf-4de3-ad52-25e5263b7623", // Publicly Accessible RDP Service (noisy)
];

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the weekly Sigma background sync.
/// `on_saved` is called with the number of newly saved rules — use it to trigger
/// an in-memory engine reload in whichever engine calls this.
pub fn spawn_sigma_sync<F>(ch: Client, rules_dir: String, on_saved: F)
where
    F: Fn(usize) + Send + 'static,
{
    tokio::spawn(async move {
        // First run 1 hour after engine start so startup is not delayed.
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        loop {
            info!("sigma_sync: checking SigmaHQ for new rules…");
            match fetch_and_save(&ch, &rules_dir).await {
                Ok(0)     => info!("sigma_sync: no new rules fetched"),
                Ok(count) => {
                    info!("sigma_sync: {} new rules saved", count);
                    on_saved(count);
                }
                Err(e) => warn!("sigma_sync: fetch failed — {e}"),
            }
            tokio::time::sleep(Duration::from_secs(7 * 24 * 3_600)).await;
        }
    });
}

/// Immediate sync — used by admin "Sync Now" buttons in both engines.
/// Returns the number of newly saved rules.
pub async fn sync_now(ch: &Client, rules_dir: &str) -> anyhow::Result<usize> {
    fetch_and_save(ch, rules_dir).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Core fetch + save logic
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch network, linux, and windows rules from SigmaHQ; save new ones to
/// `ndr.sigma_rules` (tenant_id='*', source='community').
/// Skips rules already in DB to preserve admin enable/disable state.
pub async fn fetch_and_save(ch: &Client, rules_dir: &str) -> anyhow::Result<usize> {
    let client = reqwest::Client::builder()
        .user_agent("PromaSecure-Engine/1.0 (SigmaHQ community rules sync)")
        .timeout(Duration::from_secs(30))
        .build()?;

    std::fs::create_dir_all(rules_dir)?;

    let mut all_urls: Vec<(String, String)> = Vec::new();
    for (category, api_url) in &[
        ("network", GITHUB_NETWORK_API),
        ("linux",   GITHUB_LINUX_API),
        ("windows", GITHUB_WINDOWS_API),
    ] {
        match collect_yaml_urls(&client, api_url).await {
            Ok(urls) => {
                info!("sigma_sync: {} {} rules found on SigmaHQ", urls.len(), category);
                for (name, url) in urls {
                    all_urls.push((format!("{}_{}", category, name), url));
                }
            }
            Err(e) => warn!("sigma_sync: failed fetching {} rules — {}", category, e),
        }
    }

    if all_urls.is_empty() {
        return Err(anyhow::anyhow!(
            "GitHub API returned no items — possible rate-limit or network issue"
        ));
    }

    let existing_ids = get_community_rule_ids(ch).await.unwrap_or_default();
    let mut saved = 0usize;

    for (filename, url) in &all_urls {
        let content = match client.get(url).send().await {
            Ok(r) => match r.text().await { Ok(t) => t, Err(_) => continue },
            Err(_) => continue,
        };

        let rule = match parse_rule_content(&content) {
            Ok(r)  => r,
            Err(e) => { warn!("sigma_sync: skipping {} — {}", filename, e); continue; }
        };

        if GLOBAL_RULE_BLOCKLIST.contains(&rule.id.as_str()) { continue; }
        if existing_ids.contains(&rule.id) { continue; }

        let dest = format!("{}/community_{}", rules_dir, filename);
        let _ = std::fs::write(&dest, &content);

        match save_community_rule(ch, &rule.id, &rule.title, &content).await {
            Ok(_)  => saved += 1,
            Err(e) => warn!("sigma_sync: CH insert failed for {} — {}", filename, e),
        }
    }

    Ok(saved)
}

// ─────────────────────────────────────────────────────────────────────────────
// ClickHouse helpers — operate directly on ndr.sigma_rules (global shared table)
// ─────────────────────────────────────────────────────────────────────────────

async fn get_community_rule_ids(ch: &Client) -> anyhow::Result<HashSet<String>> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct Row { id: String }
    let rows: Vec<Row> = ch
        .query("SELECT DISTINCT id FROM ndr.sigma_rules FINAL WHERE source = 'community'")
        .fetch_all()
        .await?;
    Ok(rows.into_iter().map(|r| r.id).collect())
}

async fn save_community_rule(
    ch:      &Client,
    id:      &str,
    title:   &str,
    content: &str,
) -> anyhow::Result<()> {
    // Check if already exists; if so update, else insert
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct Exists { cnt: u64 }
    let e: Exists = ch
        .query("SELECT count() AS cnt FROM ndr.sigma_rules FINAL WHERE id = ?")
        .bind(id)
        .fetch_one()
        .await?;

    if e.cnt > 0 {
        // Update (ReplacingMergeTree — insert a new version)
        ch.query(
            "INSERT INTO ndr.sigma_rules (id, name, content, tenant_id, source, enabled, updated_at) \
             SELECT id, ?, ?, tenant_id, source, enabled, now() \
             FROM ndr.sigma_rules FINAL WHERE id = ?"
        )
        .bind(title)
        .bind(content)
        .bind(id)
        .execute()
        .await?;
    } else {
        ch.query(
            "INSERT INTO ndr.sigma_rules \
             (id, name, content, tenant_id, source, enabled, created_at, updated_at) \
             VALUES (?, ?, ?, '*', 'community', 1, now(), now())"
        )
        .bind(id)
        .bind(title)
        .bind(content)
        .execute()
        .await?;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// GitHub directory walker
// ─────────────────────────────────────────────────────────────────────────────

async fn collect_yaml_urls(
    client:  &reqwest::Client,
    api_url: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    let resp = client.get(api_url)
        .header("Accept", "application/vnd.github.v3+json")
        .send().await?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("GitHub API returned {}", resp.status()));
    }

    let entries: Vec<serde_json::Value> = resp.json().await?;
    let mut results = Vec::new();

    for entry in &entries {
        let typ  = entry["type"].as_str().unwrap_or("");
        let name = entry["name"].as_str().unwrap_or("");

        if typ == "file" && (name.ends_with(".yml") || name.ends_with(".yaml")) {
            if let Some(url) = entry["download_url"].as_str() {
                if !url.is_empty() {
                    results.push((name.to_string(), url.to_string()));
                }
            }
        } else if typ == "dir" {
            if let Some(subdir_url) = entry["url"].as_str() {
                if let Ok(r) = client.get(subdir_url)
                    .header("Accept", "application/vnd.github.v3+json")
                    .send().await
                {
                    if let Ok(sub_entries) = r.json::<Vec<serde_json::Value>>().await {
                        for sub in &sub_entries {
                            let sname = sub["name"].as_str().unwrap_or("");
                            if sname.ends_with(".yml") || sname.ends_with(".yaml") {
                                if let Some(url) = sub["download_url"].as_str() {
                                    if !url.is_empty() {
                                        results.push((
                                            format!("{}_{}", name, sname),
                                            url.to_string(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}
