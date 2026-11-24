// SIEM Correlation Engine — Module Entry Point
// Declares all sub-modules, runs DDL migrations, builds shared handles,
// and spawns the Kafka consumer + genome scheduler background tasks.
// License: Apache-2.0

pub mod types;
pub mod engine;
pub mod consumer;
pub mod dedup;
pub mod suppression;
pub mod ueba;
pub mod alerts;
pub mod sla;
pub mod genome;
pub mod corroboration;
pub mod sigma_eval;

use std::sync::Arc;
use clickhouse::Client;
use anyhow::Result;

use engine::RuleEngine;
use suppression::SuppressionCache;

// ─────────────────────────────────────────────────────────────────────────────
// Entry point called from main.rs
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise the correlation engine subsystem.
///
/// 1. Run DDL migrations (idempotent CREATE TABLE IF NOT EXISTS).
/// 2. Build the rule engine and suppression cache.
/// 3. Spawn the Kafka consumer task.
/// 4. Spawn the SLA breach-checker task.
/// 5. Spawn the Living Genome scorer task.
/// 6. Spawn the rule engine state sweeper.
pub async fn start(
    kafka_brokers: String,
    clickhouse_url: String,
    valkey_url: String,
) -> Result<()> {
    tracing::info!("SIEM Correlation Engine: initialising");

    // Build ClickHouse client
    let ch = build_ch_client(&clickhouse_url);

    // Run DDL migrations for SIEM-specific tables
    run_migrations(&ch).await;

    // Build shared rule engine
    let engine = Arc::new(RuleEngine::new());

    // Load enabled/disabled rule overrides from ClickHouse (best-effort)
    load_rule_overrides(&ch, &engine).await;

    // Spawn rule override refresh every 5 min
    {
        let ch_ref = ch.clone();
        let eng    = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                ticker.tick().await;
                load_rule_overrides(&ch_ref, &eng).await;
            }
        });
    }

    // Build and warm suppression cache
    let suppression = Arc::new(SuppressionCache::new(ch.clone()));
    suppression.refresh().await;
    SuppressionCache::spawn_refresh_loop(Arc::clone(&suppression));

    // Spawn rule engine state sweeper (every 5 min)
    {
        let eng = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                ticker.tick().await;
                eng.sweep_expired().await;
            }
        });
    }

    // Spawn Kafka consumer
    consumer::spawn_consumer(
        kafka_brokers.clone(),
        ch.clone(),
        valkey_url.clone(),
        Arc::clone(&engine),
        Arc::clone(&suppression),
    );

    // Spawn SLA breach checker
    sla::spawn_sla_checker(ch.clone(), valkey_url.clone());

    // Spawn Living Genome scorer
    genome::spawn_genome_scorer(ch.clone(), valkey_url.clone());

    // Spawn NDR↔SIEM cross-corroboration (safe no-op if NDR not running or IP_TOKEN_KEY unset)
    corroboration::spawn_corroboration(ch.clone());

    // Spawn Sigma community rules sync — keeps ndr.sigma_rules populated for SIEM-only deployments
    let rules_dir = std::env::var("RULES_DIR").unwrap_or_else(|_| "/tmp/sigma_rules".to_string());
    provigil_common::sigma_sync::spawn_sigma_sync(ch.clone(), rules_dir, |count| {
        tracing::info!("sigma_sync: SIEM engine notified — {} new community rules saved", count);
    });

    // Spawn Sigma scheduled evaluator — queries siem_logs every 5 min, writes siem_alerts
    sigma_eval::spawn_sigma_evaluator(ch.clone());

    tracing::info!("SIEM Correlation Engine: all subsystems started");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ClickHouse client builder
// ─────────────────────────────────────────────────────────────────────────────

pub fn build_ch_client(url: &str) -> Client {
    let db   = std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "ndr".to_string());
    let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "ndr".to_string());
    let pass = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();

    Client::default()
        .with_url(url)
        .with_database(&db)
        .with_user(&user)
        .with_password(&pass)
}

// ─────────────────────────────────────────────────────────────────────────────
// DDL Migrations — idempotent, run at startup
// ─────────────────────────────────────────────────────────────────────────────

/// Run CREATE TABLE IF NOT EXISTS for all SIEM-owned tables that are NOT
/// already in init.sql (unified_alerts IS in init.sql and is not re-created here).
async fn run_migrations(ch: &Client) {
    let migrations: &[(&str, &str)] = &[
        // ── siem_suppression_rules ───────────────────────────────────────────
        (
            "siem_suppression_rules",
            r#"CREATE TABLE IF NOT EXISTS ndr.siem_suppression_rules ON CLUSTER ndr_cluster
            (
                id               String  DEFAULT toString(generateUUIDv4()),
                tenant_id        String,
                rule_id          String  DEFAULT '',
                hostname_pattern String  DEFAULT '',
                username_pattern String  DEFAULT '',
                reason           String  DEFAULT '',
                created_by       String  DEFAULT '',
                enabled          UInt8   DEFAULT 1,
                created_at       DateTime DEFAULT now(),
                updated_at       DateTime DEFAULT now()
            )
            ENGINE = ReplicatedReplacingMergeTree(
                '/clickhouse/tables/{shard}/ndr/siem_suppression_rules', '{replica}', updated_at
            )
            ORDER BY (tenant_id, id)"#,
        ),
        // ── siem_rules (correlation rule metadata + enable/disable) ──────────
        (
            "siem_rules",
            r#"CREATE TABLE IF NOT EXISTS ndr.siem_rules ON CLUSTER ndr_cluster
            (
                id          String,
                name        String,
                description String  DEFAULT '',
                severity    String  DEFAULT 'MEDIUM',
                enabled     UInt8   DEFAULT 1,
                tenant_id   String  DEFAULT '*',
                created_at  DateTime DEFAULT now(),
                updated_at  DateTime DEFAULT now()
            )
            ENGINE = ReplicatedReplacingMergeTree(
                '/clickhouse/tables/{shard}/ndr/siem_rules', '{replica}', updated_at
            )
            ORDER BY (tenant_id, id)"#,
        ),
        // ── siem_rule_fitness (Living Genome output) ─────────────────────────
        (
            "siem_rule_fitness",
            r#"CREATE TABLE IF NOT EXISTS ndr.siem_rule_fitness ON CLUSTER ndr_cluster
            (
                rule_id              String,
                tenant_id            String,
                fitness_score        Float32 DEFAULT 0,
                true_positive_rate   Float32 DEFAULT 0,
                suppression_rate     Float32 DEFAULT 0,
                avg_resolve_minutes  Float32 DEFAULT 0,
                alert_count          UInt64  DEFAULT 0,
                scored_at            DateTime DEFAULT now()
            )
            ENGINE = ReplicatedReplacingMergeTree(
                '/clickhouse/tables/{shard}/ndr/siem_rule_fitness', '{replica}', scored_at
            )
            ORDER BY (tenant_id, rule_id, scored_at)
            TTL scored_at + INTERVAL 180 DAY"#,
        ),
    ];

    for (table_name, ddl) in migrations {
        // Try with ON CLUSTER first (works on the VM's 2-node cluster).
        // On a single-node install without cluster macros, fall back to local DDL.
        match ch.query(ddl).execute().await {
            Ok(_)  => {
                tracing::info!("DDL: table ndr.{} ready (cluster)", table_name);
            }
            Err(e) => {
                tracing::warn!(
                    "DDL cluster create failed for ndr.{}: {} — retrying without ON CLUSTER",
                    table_name, e
                );
                // Fallback: strip ON CLUSTER clause for standalone installs
                let local_ddl = ddl.replace(" ON CLUSTER ndr_cluster", "");
                match ch.query(&local_ddl).execute().await {
                    Ok(_)  => tracing::info!("DDL: table ndr.{} ready (local)", table_name),
                    Err(e2) => tracing::warn!(
                        "DDL: ndr.{} migration failed (may already exist): {}", table_name, e2
                    ),
                }
            }
        }
    }

    // Seed the 10 OOTB rules into siem_rules if the table is empty
    seed_ootb_rules(ch).await;
}

/// Insert the 10 OOTB rule rows into ndr.siem_rules (idempotent).
async fn seed_ootb_rules(ch: &Client) {
    let rules = RuleEngine::rule_catalog();
    for rule in rules {
        let sql = format!(
            "INSERT INTO ndr.siem_rules (id, name, description, severity, enabled, tenant_id) \
             SELECT '{}', '{}', '{}', '{}', 1, '*' \
             WHERE NOT EXISTS (SELECT 1 FROM ndr.siem_rules FINAL WHERE id = '{}')",
            rule.id, escape(&rule.name), escape(&rule.description), rule.severity, rule.id
        );
        if let Err(e) = ch.query(&sql).execute().await {
            tracing::warn!("Seed rule '{}' failed (may already exist): {}", rule.id, e);
        }
    }
    tracing::info!("SIEM OOTB rules seeded into ndr.siem_rules");
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule override loader
// ─────────────────────────────────────────────────────────────────────────────

async fn load_rule_overrides(ch: &Client, engine: &RuleEngine) {
    use std::collections::HashMap;

    let sql = "SELECT id, enabled FROM ndr.siem_rules FINAL WHERE tenant_id = '*'";

    #[derive(serde::Deserialize, clickhouse::Row)]
    struct RuleRow { id: String, enabled: u8 }

    match ch.query(sql).fetch_all::<RuleRow>().await {
        Ok(rows) => {
            let map: HashMap<String, bool> = rows
                .into_iter()
                .map(|r| (r.id, r.enabled != 0))
                .collect();
            engine.set_enabled_rules(map).await;
            tracing::debug!("Rule override map refreshed");
        }
        Err(e) => {
            tracing::warn!("Could not load rule overrides (table may not exist yet): {}", e);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
