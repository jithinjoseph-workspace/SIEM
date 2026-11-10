// Common ClickHouse migrations — shared tables that must exist regardless of
// which engine starts first (NDR-only, SIEM-only, or both).
//
// Both NDR engine and SIEM engine call `run_common_migrations()` at startup.
// All statements are idempotent (CREATE TABLE IF NOT EXISTS / ALTER ADD COLUMN IF NOT EXISTS).
// Tries ON CLUSTER first; falls back to local DDL for single-node installs.
// License: Apache-2.0

use clickhouse::Client;

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run all shared-table migrations.  Call once at engine startup, before any
/// queries against these tables.
pub async fn run_common_migrations(ch: &Client) {
    tracing::info!("common_migrations: starting shared-table DDL pass");

    // Create the ndr database first
    run(ch, "ndr_database",
        "CREATE DATABASE IF NOT EXISTS ndr ON CLUSTER ndr_cluster").await;

    for (name, ddl) in SHARED_TABLES {
        run(ch, name, ddl).await;
    }

    for (name, ddl) in ALTER_STATEMENTS {
        run_warn(ch, name, ddl).await;
    }

    tracing::info!("common_migrations: done");
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared table DDLs — ndr.* only (not per-tenant ndr_{t}.* tables)
// ─────────────────────────────────────────────────────────────────────────────

const SHARED_TABLES: &[(&str, &str)] = &[

    // ── Auth & tenancy ───────────────────────────────────────────────────────

    ("ndr.users", r#"
CREATE TABLE IF NOT EXISTS ndr.users ON CLUSTER ndr_cluster (
    username    String,
    password    String,
    role        LowCardinality(String) DEFAULT 'analyst',
    tenant_id   LowCardinality(String) DEFAULT 'default',
    permissions String DEFAULT '',
    active      UInt8  DEFAULT 1,
    gmail       String DEFAULT '',
    secret_code String DEFAULT '',
    created_at  DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/users', '{replica}', created_at
)
ORDER BY username
SETTINGS index_granularity = 8192"#),

    ("ndr.tenants", r#"
CREATE TABLE IF NOT EXISTS ndr.tenants ON CLUSTER ndr_cluster (
    id         String,
    name       String,
    active     UInt8    DEFAULT 1,
    ai_enabled UInt8    DEFAULT 1,
    features   String   DEFAULT '',
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/tenants', '{replica}', updated_at
)
ORDER BY id
SETTINGS index_granularity = 8192"#),

    // ── Settings ────────────────────────────────────────────────────────────

    ("ndr.settings", r#"
CREATE TABLE IF NOT EXISTS ndr.settings ON CLUSTER ndr_cluster (
    key        String,
    value      String,
    updated_at DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/settings', '{replica}', updated_at
)
ORDER BY key
SETTINGS index_granularity = 8192"#),

    // ── Sigma rules (global community rules, synced from SigmaHQ) ───────────

    ("ndr.sigma_rules", r#"
CREATE TABLE IF NOT EXISTS ndr.sigma_rules ON CLUSTER ndr_cluster (
    id         String,
    name       String,
    content    String,
    enabled    UInt8  DEFAULT 1,
    tenant_id  String DEFAULT 'default',
    source     String DEFAULT 'custom',
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/sigma_rules', '{replica}', updated_at
)
ORDER BY id
SETTINGS index_granularity = 8192"#),

    // ── SIEM rules (correlation engine rule definitions) ─────────────────────
    // Uses rule_id (not id) — matches the schema created by init.sql and
    // used by ndr-engine storage layer.

    ("ndr.siem_rules", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_rules ON CLUSTER ndr_cluster (
    rule_id           String,
    tenant_id         LowCardinality(String),
    name              String,
    description       String   DEFAULT '',
    rule_type         LowCardinality(String) DEFAULT 'custom',
    condition_json    String,
    event_classes     Array(String),
    severity          LowCardinality(String) DEFAULT 'MEDIUM',
    mitre_tactics     Array(String),
    mitre_techniques  Array(String),
    enabled           UInt8    DEFAULT 1,
    created_at        DateTime DEFAULT now(),
    updated_at        DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_rules', '{replica}', updated_at
)
ORDER BY (tenant_id, rule_id)
SETTINGS index_granularity = 8192"#),

    // ── rules_state (per-tenant enable/disable overrides for any rule) ───────

    ("ndr.rules_state", r#"
CREATE TABLE IF NOT EXISTS ndr.rules_state ON CLUSTER ndr_cluster (
    id        String,
    enabled   UInt8    DEFAULT 1,
    updated   DateTime DEFAULT now(),
    tenant_id String   DEFAULT 'default'
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/rules_state', '{replica}', updated
)
ORDER BY id
SETTINGS index_granularity = 8192"#),

    // ── SIEM suppression rules ───────────────────────────────────────────────

    ("ndr.siem_suppression_rules", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_suppression_rules ON CLUSTER ndr_cluster (
    id               String   DEFAULT toString(generateUUIDv4()),
    tenant_id        String,
    rule_id          String   DEFAULT '',
    hostname_pattern String   DEFAULT '',
    username_pattern String   DEFAULT '',
    reason           String   DEFAULT '',
    created_by       String   DEFAULT '',
    enabled          UInt8    DEFAULT 1,
    created_at       DateTime DEFAULT now(),
    updated_at       DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_suppression_rules', '{replica}', updated_at
)
ORDER BY (tenant_id, id)
SETTINGS index_granularity = 8192"#),

    // ── SIEM rule fitness (Living Genome output) ─────────────────────────────

    ("ndr.siem_rule_fitness", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_rule_fitness ON CLUSTER ndr_cluster (
    rule_id              String,
    tenant_id            String,
    fitness_score        Float32 DEFAULT 0,
    true_positive_rate   Float32 DEFAULT 0,
    suppression_rate     Float32 DEFAULT 0,
    avg_resolve_minutes  Float32 DEFAULT 0,
    alert_count          UInt64  DEFAULT 0,
    scored_at            DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_rule_fitness', '{replica}', scored_at
)
ORDER BY (tenant_id, rule_id, scored_at)
TTL scored_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192"#),

    // ── SIEM SLA config ──────────────────────────────────────────────────────

    ("ndr.siem_sla_config", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_sla_config ON CLUSTER ndr_cluster (
    tenant_id      LowCardinality(String),
    critical_hours UInt16   DEFAULT 1,
    high_hours     UInt16   DEFAULT 4,
    medium_hours   UInt16   DEFAULT 24,
    low_hours      UInt32   DEFAULT 72,
    updated_at     DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_sla_config', '{replica}', updated_at
)
ORDER BY tenant_id
SETTINGS index_granularity = 8192"#),

    // ── SIEM ingest keys ─────────────────────────────────────────────────────

    ("ndr.siem_ingest_keys", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_ingest_keys ON CLUSTER ndr_cluster (
    key_hash   String,
    tenant_id  LowCardinality(String),
    source_id  String,
    name       String,
    active     UInt8    DEFAULT 1,
    created_at DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_ingest_keys', '{replica}', created_at
)
ORDER BY (tenant_id, key_hash)
SETTINGS index_granularity = 8192"#),

    // ── SIEM audit trail ─────────────────────────────────────────────────────

    ("ndr.siem_audit_trail", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_audit_trail ON CLUSTER ndr_cluster (
    audit_id      String,
    tenant_id     LowCardinality(String),
    action        LowCardinality(String),
    actor         String,
    target_id     String,
    previous_hash String   DEFAULT '',
    current_hash  String   DEFAULT '',
    detail_json   String   DEFAULT '{}',
    created_at    DateTime DEFAULT now()
) ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_audit_trail', '{replica}'
)
ORDER BY (tenant_id, created_at)
TTL created_at + INTERVAL 365 DAY
SETTINGS index_granularity = 8192"#),

    // ── SIEM baselines ───────────────────────────────────────────────────────

    ("ndr.siem_baselines", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_baselines ON CLUSTER ndr_cluster (
    entity_id      String,
    tenant_id      LowCardinality(String),
    entity_type    LowCardinality(String),
    baseline_data  String,
    peer_group     String   DEFAULT '',
    computed_at    DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_baselines', '{replica}', computed_at
)
ORDER BY (tenant_id, entity_id, entity_type)
SETTINGS index_granularity = 8192"#),

    // ── SIEM parsers ─────────────────────────────────────────────────────────

    ("ndr.siem_parsers", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_parsers ON CLUSTER ndr_cluster (
    parser_id       String,
    tenant_id       LowCardinality(String),
    source_type     LowCardinality(String),
    name            String,
    ocsf_mapping    String   DEFAULT '{}',
    sandbox_passed  UInt8    DEFAULT 0,
    sandbox_samples UInt16   DEFAULT 0,
    status          LowCardinality(String) DEFAULT 'draft',
    approved_by     String   DEFAULT '',
    approved_at     DateTime DEFAULT now(),
    created_at      DateTime DEFAULT now(),
    updated_at      DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_parsers', '{replica}', updated_at
)
ORDER BY (tenant_id, parser_id)
SETTINGS index_granularity = 8192"#),

    // ── SIEM tenant profiles ─────────────────────────────────────────────────

    ("ndr.siem_tenant_profiles", r#"
CREATE TABLE IF NOT EXISTS ndr.siem_tenant_profiles ON CLUSTER ndr_cluster (
    tenant_id    LowCardinality(String),
    profile_data String   DEFAULT '{}',
    updated_at   DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/siem_tenant_profiles', '{replica}', updated_at
)
ORDER BY tenant_id
SETTINGS index_granularity = 8192"#),

    // ── Unified alerts (corroboration output — per-tenant, but table in ndr too for default tenant)

    ("ndr.unified_alerts", r#"
CREATE TABLE IF NOT EXISTS ndr.unified_alerts ON CLUSTER ndr_cluster (
    alert_id             String,
    tenant_id            LowCardinality(String),
    severity             LowCardinality(String),
    rule_id              String   DEFAULT '',
    rule_name            String   DEFAULT '',
    title                String,
    description          String   DEFAULT '',
    source               LowCardinality(String),
    affected_hosts       Array(String),
    mitre_techniques     Array(String),
    mitre_sources        Array(String),
    mitre_confidences    Array(Float32),
    status               LowCardinality(String) DEFAULT 'New',
    linked_ndr_event_ids Array(String),
    linked_siem_log_ids  Array(String),
    corroborated_at      DateTime DEFAULT toDateTime(0),
    correlation_status   LowCardinality(String) DEFAULT 'pending',
    sla_started_at       Nullable(DateTime),
    sla_breached_at      Nullable(DateTime),
    created_at           DateTime DEFAULT now(),
    updated_at           DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/unified_alerts', '{replica}', updated_at
)
ORDER BY (tenant_id, alert_id)
TTL created_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192"#),

    // ── AI provider registry (super admin — shared across all tenants) ──────

    ("ndr.ai_providers", r#"
CREATE TABLE IF NOT EXISTS ndr.ai_providers ON CLUSTER ndr_cluster (
    name          String,
    provider_type String   DEFAULT 'custom',
    api_key       String   DEFAULT '',
    model         String   DEFAULT '',
    base_url      String   DEFAULT '',
    endpoint_path String   DEFAULT '/v1/chat/completions',
    msg_format    String   DEFAULT 'openai',
    use_case      String   DEFAULT 'all',
    priority      UInt8    DEFAULT 10,
    enabled       UInt8    DEFAULT 1,
    created_at    DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/ndr/ai_providers', '{replica}', created_at
)
ORDER BY name
SETTINGS index_granularity = 8192"#),

    // ── Threat intel (global IOC feed) ───────────────────────────────────────

    ("ndr.threat_intel", r#"
CREATE TABLE IF NOT EXISTS ndr.threat_intel ON CLUSTER ndr_cluster (
    attack_type   String,
    collected_at  DateTime DEFAULT now(),
    src_ip        String   DEFAULT '',
    threat_intel  UInt8    DEFAULT 0,
    confidence    Float32  DEFAULT 0,
    country       String   DEFAULT '',
    asn            String  DEFAULT '',
    tags          Array(String)
) ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/ndr/threat_intel', '{replica}'
)
ORDER BY (attack_type, collected_at)
TTL collected_at + INTERVAL 90 DAY
SETTINGS index_granularity = 8192"#),
];

// ─────────────────────────────────────────────────────────────────────────────
// ALTER TABLE statements — add columns to existing tables (safe if col exists)
// ─────────────────────────────────────────────────────────────────────────────

const ALTER_STATEMENTS: &[(&str, &str)] = &[
    ("ndr.users.gmail",
     "ALTER TABLE ndr.users ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS gmail String DEFAULT ''"),
    ("ndr.users.secret_code",
     "ALTER TABLE ndr.users ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS secret_code String DEFAULT ''"),
    ("ndr.tenants.ai_enabled",
     "ALTER TABLE ndr.tenants ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS ai_enabled UInt8 DEFAULT 1"),
    ("ndr.sigma_rules.tenant_id",
     "ALTER TABLE ndr.sigma_rules ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'"),
    ("ndr.sigma_rules.source",
     "ALTER TABLE ndr.sigma_rules ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS source String DEFAULT 'custom'"),
    ("ndr.rules_state.tenant_id",
     "ALTER TABLE ndr.rules_state ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'"),
    // siem_parsers — columns needed by the AI parser runtime
    ("ndr.siem_parsers.source_id",
     "ALTER TABLE ndr.siem_parsers ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS source_id String DEFAULT ''"),
    ("ndr.siem_parsers.version",
     "ALTER TABLE ndr.siem_parsers ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS version UInt32 DEFAULT 1"),
    ("ndr.siem_parsers.event_class",
     "ALTER TABLE ndr.siem_parsers ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS event_class String DEFAULT 'unknown'"),
    ("ndr.siem_parsers.rollback_version",
     "ALTER TABLE ndr.siem_parsers ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS rollback_version UInt32 DEFAULT 0"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Run a DDL statement — ON CLUSTER first, fall back to local for single-node.
async fn run(ch: &Client, label: &str, ddl: &str) {
    match ch.query(ddl.trim()).execute().await {
        Ok(_) => {
            tracing::debug!("common_migrations: {} ready (cluster)", label);
        }
        Err(e) => {
            tracing::warn!(
                "common_migrations: {} cluster DDL failed ({}) — retrying local",
                label, e
            );
            let local = ddl.replace(" ON CLUSTER ndr_cluster", "");
            match ch.query(local.trim()).execute().await {
                Ok(_) => tracing::debug!("common_migrations: {} ready (local)", label),
                Err(e2) => tracing::warn!(
                    "common_migrations: {} failed (may already exist): {}", label, e2
                ),
            }
        }
    }
}

/// Run a DDL statement but only warn on failure (used for ALTER ADD COLUMN).
async fn run_warn(ch: &Client, label: &str, ddl: &str) {
    if let Err(e) = ch.query(ddl.trim()).execute().await {
        let local = ddl.replace(" ON CLUSTER ndr_cluster", "");
        if let Err(e2) = ch.query(local.trim()).execute().await {
            tracing::debug!("common_migrations: {} skipped ({})", label, e2);
            let _ = e;
        }
    }
}
