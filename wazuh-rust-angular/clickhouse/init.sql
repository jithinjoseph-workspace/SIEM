-- ClickHouse Unified XDR Schema (NDR + SIEM Auto-Provisioning)
CREATE DATABASE IF NOT EXISTS wazuh_siem;

-- 1. Raw Telemetry Events Table
CREATE TABLE IF NOT EXISTS wazuh_siem.siem_events (
    id String,
    timestamp UInt64,
    agent_id LowCardinality(String),
    source LowCardinality(String),
    location String CODEC(ZSTD),
    message String CODEC(ZSTD),
    raw_metadata String CODEC(ZSTD)
) ENGINE = MergeTree()
ORDER BY (timestamp, agent_id);

-- 2. Correlated Security Alerts Table
CREATE TABLE IF NOT EXISTS wazuh_siem.siem_alerts (
    id String,
    timestamp UInt64,
    agent_id LowCardinality(String),
    agent_name LowCardinality(String),
    agent_ip String,
    rule_id UInt32,
    rule_level UInt8,
    rule_description String CODEC(ZSTD),
    mitre_id LowCardinality(String),
    mitre_tactic LowCardinality(String),
    mitre_technique LowCardinality(String),
    full_log String CODEC(ZSTD),
    src_ip String,
    dst_ip String,
    user String,
    location String
) ENGINE = MergeTree()
ORDER BY (rule_level, timestamp);

-- 3. Agent Inventory & Heartbeats (ReplacingMergeTree deduplicates per agent)
CREATE TABLE IF NOT EXISTS wazuh_siem.siem_agents (
    id String,
    name String,
    ip String,
    os String,
    version String,
    status LowCardinality(String),
    last_keepalive DateTime64(3, 'UTC'),
    os_type LowCardinality(String)
) ENGINE = ReplacingMergeTree(last_keepalive)
ORDER BY (id);

-- 4. Active Response Remediation Audit Trail
CREATE TABLE IF NOT EXISTS wazuh_siem.siem_active_responses (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3, 'UTC'),
    agent_id LowCardinality(String),
    action LowCardinality(String),
    target String,
    success UInt8,
    reverted UInt8 DEFAULT 0
) ENGINE = MergeTree()
ORDER BY (timestamp, agent_id);

-- 5. NDR Network Flows (Zeek / Suricata / eBPF flow logs)
CREATE TABLE IF NOT EXISTS wazuh_siem.ndr_network_flows (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3, 'UTC'),
    proto LowCardinality(String),
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    bytes_in UInt64,
    bytes_out UInt64,
    duration_ms UInt32,
    service LowCardinality(String),
    app_proto LowCardinality(String),
    INDEX idx_src (src_ip) TYPE bloom_filter GRANULARITY 1,
    INDEX idx_dst (dst_ip) TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- 6. NDR Network Threat Detections (C2 beaconing, port scanning, DNS tunneling, IDS alerts)
CREATE TABLE IF NOT EXISTS wazuh_siem.ndr_threats (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3, 'UTC'),
    signature String,
    category LowCardinality(String),
    severity UInt8,
    src_ip String,
    dst_ip String,
    dst_port UInt16,
    proto LowCardinality(String),
    mitre_id LowCardinality(String),
    payload_snippet String CODEC(ZSTD),
    INDEX idx_src (src_ip) TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (severity, timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 180 DAY;

-- 7. Unified XDR Correlated Incidents (Fusing NDR network threat + SIEM endpoint event)
CREATE TABLE IF NOT EXISTS wazuh_siem.xdr_incidents (
    incident_id String,
    timestamp UInt64,
    title String,
    severity LowCardinality(String),
    host_ip String,
    agent_id LowCardinality(String),
    agent_name LowCardinality(String),
    attacker_ip String,
    ndr_threat_id String,
    siem_alert_id String,
    ndr_signature String,
    siem_rule_description String,
    status LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (timestamp, host_ip);

-- 8. Multi-Tenant Auth & Users (Shared auth-service)
CREATE DATABASE IF NOT EXISTS ndr;

CREATE TABLE IF NOT EXISTS ndr.users (
    id String DEFAULT generateUUIDv4(),
    username String,
    password_hash String,
    role LowCardinality(String) DEFAULT 'analyst',
    tenant_id LowCardinality(String) DEFAULT 'default',
    permissions String DEFAULT 'dashboard,alerts,siem,ndr,rules,agents,sources',
    active UInt8 DEFAULT 1,
    gmail String DEFAULT '',
    secret_code String DEFAULT '',
    created_at DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(created_at)
ORDER BY username;

CREATE TABLE IF NOT EXISTS ndr.tenants (
    id String,
    name String,
    plan String DEFAULT 'enterprise',
    features String DEFAULT 'siem,ndr',
    active UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(created_at)
ORDER BY id;

-- Pre-seed default organization & analyst user
INSERT INTO ndr.tenants (id, name, plan, features, active) VALUES
    ('default', 'Default Organization', 'enterprise', 'siem,ndr', 1);

INSERT INTO ndr.users (id, username, password_hash, role, tenant_id, permissions, active) VALUES
    ('u-admin', 'admin', '$2b$12$qB5uFqakHidExby4EbdH6.tFvW34sj7CAQFZdUCzk5YSi/kV3S09.', 'super_admin', 'default', 'dashboard,alerts,siem,ndr,rules,agents,sources,users,settings', 1),
    ('u-analyst', 'analyst', '$2b$12$wi15kWc0KGLG6FEtIysJHuqRfT7PDvOoW2IC3oT3hfoQmtmygZ5h6', 'analyst', 'default', 'dashboard,alerts,siem,ndr,rules,agents', 1);
