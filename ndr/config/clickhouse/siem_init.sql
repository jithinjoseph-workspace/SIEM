-- SIEM engine schema — created ONLY when siem profile is active
-- Run by siem-engine on startup via HTTP POST to ClickHouse
-- All tables live in the per-tenant database ndr_{tenant_id}
-- For the default tenant the database is "ndr"
-- Placeholder __DB__ is substituted by siem-engine at runtime

-- ─── Database (idempotent — safe to run even if NDR init already created it) ──
CREATE DATABASE IF NOT EXISTS __DB__;

-- ─── Core ingest table ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_logs ON CLUSTER ndr_cluster (
    log_id            String,
    source_id         LowCardinality(String),
    source_type       LowCardinality(String),  -- wec | syslog | firewall_cef | generic | aws_cloudtrail
    event_class       LowCardinality(String),  -- OCSF class: authentication | network_activity | ...
    severity          LowCardinality(String),  -- CRITICAL | HIGH | MEDIUM | LOW | INFO
    timestamp         DateTime64(3, 'UTC'),
    raw_log           String,
    parsed_json       String,                  -- OCSF-normalised fields as JSON
    ip_tokens         Array(String),           -- HMAC-SHA256 tokens replacing raw IPs
    threat_match_json String DEFAULT '{}',     -- ThreatMatch JSON if IOC found
    ingested_at       DateTime DEFAULT now(),
    INDEX idx_log_id     log_id     TYPE bloom_filter GRANULARITY 1,
    INDEX idx_source_id  source_id  TYPE bloom_filter GRANULARITY 1,
    INDEX idx_event_class event_class TYPE set(20)   GRANULARITY 1,
    INDEX idx_severity   severity   TYPE set(10)     GRANULARITY 1
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/__DB__/siem_logs', '{replica}')
PARTITION BY toYYYYMM(timestamp)
ORDER BY (source_type, event_class, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ─── Log sources registry ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_sources ON CLUSTER ndr_cluster (
    source_id      String,
    tenant_id      LowCardinality(String),
    name           String,
    source_type    LowCardinality(String),   -- wec | syslog | cef | rest | aws_cloudtrail
    parser_id      String DEFAULT '',        -- linked AI parser (empty = OOTB parser)
    config_json    String DEFAULT '{}',      -- connection config (host, port, protocol, etc.)
    status         LowCardinality(String) DEFAULT 'active',  -- active | paused | error
    last_seen_at   DateTime DEFAULT toDateTime(0),
    created_at     DateTime DEFAULT now(),
    INDEX idx_tenant tenant_id TYPE set(100) GRANULARITY 1
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/__DB__/siem_sources', '{replica}', created_at)
ORDER BY (tenant_id, source_id)
SETTINGS index_granularity = 8192;

-- ─── Global ingest key lookup (always ndr schema, shared across all tenants) ─
-- key_hash is SHA-256(raw_key) — raw_key returned once to UI and never stored.
CREATE DATABASE IF NOT EXISTS ndr;
CREATE TABLE IF NOT EXISTS ndr.siem_ingest_keys ON CLUSTER ndr_cluster (
    key_hash   String,
    tenant_id  LowCardinality(String),
    source_id  String,
    name       String DEFAULT '',
    active     UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/siem_ingest_keys', '{replica}', created_at)
ORDER BY key_hash
SETTINGS index_granularity = 8192;

-- ─── AI-generated parsers ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_parsers ON CLUSTER ndr_cluster (
    parser_id        String,
    tenant_id        LowCardinality(String),
    source_type      LowCardinality(String),
    name             String,
    -- OCSF mapping proposal from Claude API as JSON
    ocsf_mapping     String,
    -- sandbox test results
    sandbox_passed   UInt8 DEFAULT 0,
    sandbox_samples  UInt16 DEFAULT 0,
    -- admin approval
    status           LowCardinality(String) DEFAULT 'pending',  -- pending | approved | rejected
    approved_by      String DEFAULT '',
    approved_at      DateTime DEFAULT toDateTime(0),
    created_at       DateTime DEFAULT now(),
    updated_at       DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/__DB__/siem_parsers', '{replica}', updated_at)
ORDER BY (tenant_id, parser_id)
SETTINGS index_granularity = 8192;

-- ─── Correlation rules ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_rules ON CLUSTER ndr_cluster (
    rule_id          String,
    tenant_id        LowCardinality(String),
    name             String,
    description      String DEFAULT '',
    -- OOTB-01..OOTB-10 or custom
    rule_type        LowCardinality(String) DEFAULT 'custom',
    -- Sigma-compatible condition JSON
    condition_json   String,
    -- OCSF event classes this rule applies to
    event_classes    Array(String),
    severity         LowCardinality(String) DEFAULT 'MEDIUM',
    mitre_tactics    Array(String),
    mitre_techniques Array(String),
    enabled          UInt8 DEFAULT 1,
    created_at       DateTime DEFAULT now(),
    updated_at       DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/__DB__/siem_rules', '{replica}', updated_at)
ORDER BY (tenant_id, rule_id)
SETTINGS index_granularity = 8192;

-- ─── Rule fitness history ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_rule_fitness ON CLUSTER ndr_cluster (
    date               Date,
    rule_id            String,
    tenant_id          LowCardinality(String),
    fitness_score      Float32 DEFAULT 0,
    tp_count           UInt32  DEFAULT 0,
    fp_count           UInt32  DEFAULT 0,
    sample_count       UInt32  DEFAULT 0,
    adversarial_test_run UInt8 DEFAULT 0
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/__DB__/siem_rule_fitness', '{replica}')
ORDER BY (tenant_id, rule_id, date)
TTL date + INTERVAL 2 YEAR
SETTINGS index_granularity = 8192;

-- ─── Alert suppression rules ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_suppression_rules ON CLUSTER ndr_cluster (
    rule_id          String,
    tenant_id        LowCardinality(String),
    rule_type        LowCardinality(String),  -- ip_token | rule_id | host | user
    scope            String,
    expiry           DateTime,
    suppressed_count UInt64 DEFAULT 0,
    created_by       String DEFAULT '',
    created_at       DateTime DEFAULT now()
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/__DB__/siem_suppression_rules', '{replica}')
ORDER BY (tenant_id, rule_id)
SETTINGS index_granularity = 8192;

-- ─── UEBA baselines ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_baselines ON CLUSTER ndr_cluster (
    entity_id       String,
    tenant_id       LowCardinality(String),
    entity_type     LowCardinality(String),  -- user | host | service
    baseline_data   String,                  -- JSON: normal hours, peer group, patterns
    peer_group      String DEFAULT '',
    computed_at     DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/__DB__/siem_baselines', '{replica}', computed_at)
ORDER BY (tenant_id, entity_id)
TTL computed_at + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ─── Tenant profiles (RAG Layer 2) ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_tenant_profiles ON CLUSTER ndr_cluster (
    tenant_id       LowCardinality(String),
    profile_data    String,   -- JSON: asset inventory, business hours, critical assets
    updated_at      DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/__DB__/siem_tenant_profiles', '{replica}', updated_at)
ORDER BY tenant_id
SETTINGS index_granularity = 8192;

-- ─── Investigation cases ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_cases ON CLUSTER ndr_cluster (
    case_id          String,
    tenant_id        LowCardinality(String),
    title            String,
    status           LowCardinality(String) DEFAULT 'open',  -- open | investigating | closed
    assignee         String DEFAULT '',
    legal_hold       UInt8 DEFAULT 0,
    linked_alert_ids Array(String),
    created_at       DateTime DEFAULT now(),
    updated_at       DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/__DB__/siem_cases', '{replica}', updated_at)
ORDER BY (tenant_id, case_id)
SETTINGS index_granularity = 8192;

-- ─── Case evidence ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_case_evidence ON CLUSTER ndr_cluster (
    evidence_id   String,
    case_id       String,
    tenant_id     LowCardinality(String),
    sha256        String,
    scan_result   LowCardinality(String) DEFAULT 'pending',
    legal_hold    UInt8 DEFAULT 0,
    added_at      DateTime DEFAULT now()
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/__DB__/siem_case_evidence', '{replica}')
ORDER BY (tenant_id, case_id, evidence_id)
SETTINGS index_granularity = 8192;

-- ─── Compliance events ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.compliance_events ON CLUSTER ndr_cluster (
    event_id    String,
    tenant_id   LowCardinality(String),
    framework   LowCardinality(String),  -- PCI_DSS | HIPAA | SOC2 | ISO27001 | NIST | GDPR
    control_id  String,
    log_id      String,
    timestamp   DateTime64(3, 'UTC'),
    ingested_at DateTime DEFAULT now()
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/__DB__/compliance_events', '{replica}')
ORDER BY (tenant_id, framework, timestamp)
TTL ingested_at + INTERVAL 7 YEAR
SETTINGS index_granularity = 8192;

-- ─── AI decisions audit ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.ai_decisions ON CLUSTER ndr_cluster (
    ai_decision_id       String,
    tenant_id            LowCardinality(String),
    alert_id             String,
    provider             LowCardinality(String),  -- claude | groq | ollama
    model                String,
    qdrant_results_count UInt16 DEFAULT 0,
    tokens               UInt32 DEFAULT 0,
    confidence           Float32 DEFAULT 0,
    decision_json        String DEFAULT '{}',
    created_at           DateTime DEFAULT now()
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/__DB__/ai_decisions', '{replica}')
ORDER BY (tenant_id, alert_id, created_at)
SETTINGS index_granularity = 8192;

-- ─── Immutable audit trail (hash chain) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_audit_trail ON CLUSTER ndr_cluster (
    audit_id       String,
    tenant_id      LowCardinality(String),
    action         LowCardinality(String),
    actor          String,
    target_id      String DEFAULT '',
    previous_hash  String,
    current_hash   String,
    detail_json    String DEFAULT '{}',
    created_at     DateTime DEFAULT now()
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/__DB__/siem_audit_trail', '{replica}')
ORDER BY (tenant_id, created_at)
TTL created_at + INTERVAL 7 YEAR
SETTINGS index_granularity = 8192;

-- ─── SLA config ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_sla_config ON CLUSTER ndr_cluster (
    tenant_id      LowCardinality(String),
    critical_hours UInt16 DEFAULT 1,
    high_hours     UInt16 DEFAULT 4,
    medium_hours   UInt16 DEFAULT 24,
    low_hours      UInt32 DEFAULT 168,
    updated_at     DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/__DB__/siem_sla_config', '{replica}', updated_at)
ORDER BY tenant_id
SETTINGS index_granularity = 8192;

-- ─── SIEM correlation alerts ──────────────────────────────────────────────────
-- SIEM rule engine writes here (source = 'siem').
-- Corroboration writes to ndr.unified_alerts (source = 'corroborated') separately.

CREATE TABLE IF NOT EXISTS __DB__.siem_alerts ON CLUSTER ndr_cluster (
    alert_id          String,
    tenant_id         LowCardinality(String),
    severity          LowCardinality(String),   -- CRITICAL | HIGH | MEDIUM | LOW | INFO
    rule_id           String,
    rule_name         String,
    title             String,
    description       String,
    affected_hosts    Array(String),
    mitre_techniques  Array(String),
    mitre_sources     Array(String),
    mitre_confidences Array(Float32),
    status            LowCardinality(String) DEFAULT 'New',
    linked_siem_log_ids Array(String),
    sla_started_at    Nullable(DateTime),
    sla_breached_at   Nullable(DateTime),
    created_at        DateTime DEFAULT now(),
    updated_at        DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/__DB__/siem_alerts', '{replica}', updated_at
)
ORDER BY (tenant_id, alert_id)
TTL created_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ─── Parse errors ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS __DB__.siem_parse_errors ON CLUSTER ndr_cluster (
    error_id      String,
    source_id     LowCardinality(String),
    raw_log       String,
    error_message String,
    parser_id     String DEFAULT '',
    created_at    DateTime DEFAULT now()
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/__DB__/siem_parse_errors', '{replica}')
ORDER BY (source_id, created_at)
TTL created_at + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
