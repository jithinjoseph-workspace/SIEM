// SIGMA community rules auto-updater — delegates to provigil_common::sigma_sync.
// NDR engine re-exports GLOBAL_RULE_BLOCKLIST and sync_now for the admin API.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use super::DetectionEngine;
pub use provigil_common::sigma_sync::GLOBAL_RULE_BLOCKLIST;

/// Spawn the weekly Sigma sync using the shared provigil-common implementation.
/// On new rules, reloads the in-memory DetectionEngine and signals other instances via Redis.
pub fn spawn_sigma_updater(
    rules_dir: String,
    redis_url: String,
    engine:    Arc<RwLock<DetectionEngine>>,
    ch:        Arc<crate::storage::ClickhouseStorage>,
) {
    let ch_client = ch.client.clone();
    let rd        = rules_dir.clone();
    let ru        = redis_url.clone();
    let eng       = engine.clone();
    let ch2       = ch.clone();

    provigil_common::sigma_sync::spawn_sigma_sync(
        ch_client,
        rules_dir,
        move |_count| {
            let rd2  = rd.clone();
            let ru2  = ru.clone();
            let eng2 = eng.clone();
            let ch3  = ch2.clone();
            tokio::spawn(async move {
                reload_engine(&rd2, &ru2, &eng2, &ch3).await;
            });
        },
    );
}

/// Called by the admin API to trigger an immediate sync.
pub async fn sync_now(
    rules_dir: &str,
    redis_url: &str,
    engine:    &Arc<RwLock<DetectionEngine>>,
    ch:        &Arc<crate::storage::ClickhouseStorage>,
) -> anyhow::Result<usize> {
    let count = provigil_common::sigma_sync::sync_now(&ch.client.clone(), rules_dir).await?;
    if count > 0 {
        reload_engine(rules_dir, redis_url, engine, ch).await;
    }
    Ok(count)
}

// ── Internal ──────────────────────────────────────────────────────────────────

async fn reload_engine(
    rules_dir: &str,
    redis_url: &str,
    engine:    &Arc<RwLock<DetectionEngine>>,
    ch:        &Arc<crate::storage::ClickhouseStorage>,
) {
    let (new_rules, overrides) = crate::api::load_rules_from_clickhouse(ch, rules_dir).await;
    let count                  = new_rules.len();
    engine.write().await.set_rules(new_rules, overrides);
    info!("sigma_sync: NDR engine reloaded with {} rules", count);

    if let Ok(client) = redis::Client::open(redis_url) {
        if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg("system:reload_rules")
                .arg("sigma_updater")
                .query_async(&mut conn)
                .await;
        }
    }
}

