CREATE DATABASE IF NOT EXISTS ndr ON CLUSTER ndr_cluster;

CREATE TABLE IF NOT EXISTS ndr.ndr_events ON CLUSTER ndr_cluster (
    timestamp    DateTime,
    source       LowCardinality(String),
    src_ip       String,
    dst_ip       String,
    src_port     UInt16,
    dst_port     UInt16,
    proto        LowCardinality(String),
    event_type   LowCardinality(String),
    community_id String,
    raw          String,
    tenant_id    LowCardinality(String) DEFAULT 'default',
    sensor_id    LowCardinality(String) DEFAULT '',
    INDEX idx_sensor_id sensor_id TYPE bloom_filter GRANULARITY 1,
    PROJECTION proj_by_sensor (SELECT * ORDER BY (tenant_id, sensor_id, timestamp))
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/ndr_events', '{replica}')
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ndr.ndr_hits ON CLUSTER ndr_cluster (
    timestamp           DateTime,
    community_id        String,
    src_ip              String,
    dst_ip              String,
    score               Float32,
    severity            LowCardinality(String),
    tags                Array(String),
    sigma_hits          Array(String),
    threat_intel        UInt8,
    src_country         String,
    dst_country         String,
    tenant_id           LowCardinality(String) DEFAULT 'default',
    correlation_status  LowCardinality(String) DEFAULT 'agent_z_only',
    agent_z_details     String DEFAULT '{}',
    agent_s_details     String DEFAULT '{}',
    corroborated_at     DateTime DEFAULT toDateTime(0),
    agent_s_rule_id     String DEFAULT '',
    agent_s_category    String DEFAULT '',
    updated_at          DateTime DEFAULT now(),
    sensor_id           String DEFAULT '',
    INDEX idx_sensor_id sensor_id TYPE bloom_filter GRANULARITY 1,
    PROJECTION proj_by_sensor (SELECT * ORDER BY (tenant_id, sensor_id, timestamp))
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/ndr_hits', '{replica}', updated_at)
ORDER BY (tenant_id, community_id)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192, deduplicate_merge_projection_mode = 'rebuild';

-- Migration: add sensor_id index and projection to existing tables
-- (CREATE TABLE above has these inline for fresh installs;
--  these ALTER statements are idempotent and handle existing tables)
ALTER TABLE ndr.ndr_events ON CLUSTER ndr_cluster ADD INDEX IF NOT EXISTS idx_sensor_id sensor_id TYPE bloom_filter GRANULARITY 1;
ALTER TABLE ndr.ndr_events ON CLUSTER ndr_cluster ADD PROJECTION IF NOT EXISTS proj_by_sensor (SELECT * ORDER BY (tenant_id, sensor_id, timestamp));
ALTER TABLE ndr.ndr_hits ON CLUSTER ndr_cluster MODIFY SETTING deduplicate_merge_projection_mode = 'rebuild';
ALTER TABLE ndr.ndr_hits ON CLUSTER ndr_cluster ADD INDEX IF NOT EXISTS idx_sensor_id sensor_id TYPE bloom_filter GRANULARITY 1;
ALTER TABLE ndr.ndr_hits ON CLUSTER ndr_cluster ADD PROJECTION IF NOT EXISTS proj_by_sensor (SELECT * ORDER BY (tenant_id, sensor_id, timestamp));

CREATE TABLE IF NOT EXISTS ndr.ndr_baselines ON CLUSTER ndr_cluster (
    tenant_id   String,
    src_ip      String,
    metric      String,
    value_f     Float64  DEFAULT 0,
    value_s     String   DEFAULT '',
    window_ts   DateTime,
    updated_at  DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/ndr_baselines', '{replica}', updated_at)
ORDER BY (tenant_id, src_ip, metric, window_ts)
TTL window_ts + INTERVAL 35 DAY;

CREATE TABLE IF NOT EXISTS ndr.entity_scores ON CLUSTER ndr_cluster (
    src_ip            String,
    tenant_id         String,
    accumulated_score Float64  DEFAULT 0,
    alert_count       UInt64   DEFAULT 0,
    top_severity      String   DEFAULT '',
    top_tags          Array(String) DEFAULT [],
    last_seen         DateTime DEFAULT now(),
    updated_at        DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/entity_scores', '{replica}', updated_at)
ORDER BY (tenant_id, src_ip)
TTL updated_at + INTERVAL 90 DAY;


CREATE TABLE IF NOT EXISTS ndr.rules_state ON CLUSTER ndr_cluster (
    id      String,
    enabled UInt8    DEFAULT 1,
    updated DateTime DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/rules_state', '{replica}', updated)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.settings ON CLUSTER ndr_cluster
(
    key        String,
    value      String,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/settings', '{replica}', updated_at)
ORDER BY key;

-- Active IP blocks — created by SOAR playbooks or manual action; revoked from UI
CREATE TABLE IF NOT EXISTS ndr.active_blocks ON CLUSTER ndr_cluster
(
    id               String,
    src_ip           String,
    src_port         UInt16   DEFAULT 0,
    dst_ip           String   DEFAULT '',
    dst_port         UInt16   DEFAULT 0,
    community_id     String   DEFAULT '',
    triggered_by     String   DEFAULT 'manual',   -- playbook name or 'manual'
    sensor_id        String   DEFAULT '',
    firewall_type    String   DEFAULT '',          -- pfsense/fortinet/panos/cisco/opnsense/none
    firewall_rule_id String   DEFAULT '',          -- rule ID returned by firewall API for cleanup
    rst_injected     UInt8    DEFAULT 0,
    duration_hours   UInt16   DEFAULT 24,
    expires_at       DateTime,
    status           String   DEFAULT 'active',   -- active / revoked / expired
    reason           String   DEFAULT '',
    tenant_id        String   DEFAULT 'default',
    created_at       DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/active_blocks', '{replica}', created_at)
ORDER BY (id, tenant_id);

-- Trusted domains — shared (tenant_id='') and per-tenant allowlists for DNS beaconing / threat intel
CREATE TABLE IF NOT EXISTS ndr.trusted_domains ON CLUSTER ndr_cluster
(
    domain      String,
    category    String,   -- 'dns_beacon', 'threat_intel', or 'both'
    tenant_id   String,   -- '' = global/shared; specific value = that tenant only
    note        String,
    added_by    String,
    added_at    DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/trusted_domains', '{replica}', added_at)
ORDER BY (domain, tenant_id, category);

-- Global seed: high-volume legitimate domains that would otherwise trigger DNS beaconing alerts.
-- Only inserted once (guard: no global rows exist yet).
INSERT INTO ndr.trusted_domains (domain, category, tenant_id, note, added_by)
SELECT tupleElement(d, 1), tupleElement(d, 2), '', tupleElement(d, 3), 'system'
FROM (
    SELECT arrayJoin([
        ('googleapis.com',         'dns_beacon', 'Google APIs'),
        ('google.com',             'dns_beacon', 'Google'),
        ('gstatic.com',            'dns_beacon', 'Google Static CDN'),
        ('googleusercontent.com',  'dns_beacon', 'Google User Content'),
        ('googlevideo.com',        'dns_beacon', 'Google Video'),
        ('microsoft.com',          'dns_beacon', 'Microsoft'),
        ('windows.net',            'dns_beacon', 'Azure'),
        ('microsoftonline.com',    'dns_beacon', 'Microsoft Online'),
        ('windowsupdate.com',      'dns_beacon', 'Windows Update'),
        ('update.microsoft.com',   'dns_beacon', 'Windows Update'),
        ('office.com',             'dns_beacon', 'Microsoft Office'),
        ('office365.com',          'dns_beacon', 'Microsoft 365'),
        ('azure.com',              'dns_beacon', 'Azure'),
        ('live.com',               'dns_beacon', 'Microsoft Live'),
        ('amazonaws.com',          'dns_beacon', 'AWS'),
        ('cloudfront.net',         'dns_beacon', 'AWS CloudFront'),
        ('apple.com',              'dns_beacon', 'Apple'),
        ('icloud.com',             'dns_beacon', 'iCloud'),
        ('mzstatic.com',           'dns_beacon', 'Apple CDN'),
        ('cloudflare.com',         'dns_beacon', 'Cloudflare'),
        ('cloudflare-dns.com',     'dns_beacon', 'Cloudflare DNS'),
        ('akamai.net',             'dns_beacon', 'Akamai'),
        ('akamaiedge.net',         'dns_beacon', 'Akamai Edge'),
        ('akamaitechnologies.com', 'dns_beacon', 'Akamai Technologies'),
        ('fastly.net',             'dns_beacon', 'Fastly CDN'),
        ('facebook.com',           'dns_beacon', 'Meta/Facebook'),
        ('fbcdn.net',              'dns_beacon', 'Facebook CDN'),
        ('whatsapp.net',           'dns_beacon', 'WhatsApp'),
        ('ocsp.digicert.com',      'dns_beacon', 'DigiCert OCSP'),
        ('ocsp.pki.goog',          'dns_beacon', 'Google OCSP'),
        ('crl.microsoft.com',      'dns_beacon', 'Microsoft CRL'),
        ('ctldl.windowsupdate.com','dns_beacon', 'Windows CTL Download'),
        ('time.windows.com',       'dns_beacon', 'Windows NTP'),
        ('pool.ntp.org',           'dns_beacon', 'NTP Pool'),
        ('time.google.com',        'dns_beacon', 'Google NTP'),
        ('safebrowsing.googleapis.com', 'dns_beacon', 'Google Safe Browsing')
    ]) AS d
)
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.trusted_domains FINAL WHERE tenant_id = '' LIMIT 1
);

-- Default thresholds
INSERT INTO ndr.settings (key, value)
SELECT 'store_threshold', '10'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'store_threshold'
);

INSERT INTO ndr.settings (key, value)
SELECT 'alert_threshold', '75'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'alert_threshold'
);

INSERT INTO ndr.settings (key, value)
SELECT 'critical_threshold', '90'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'critical_threshold'
);

INSERT INTO ndr.settings (key, value)
SELECT 'soar_threshold', '75'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'soar_threshold'
);

-- AI provider configuration (super_admin configurable)
INSERT INTO ndr.settings (key, value)
SELECT 'ai_provider', 'openai'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'ai_provider'
);

INSERT INTO ndr.settings (key, value)
SELECT 'ai_api_key', ''
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'ai_api_key'
);

INSERT INTO ndr.settings (key, value)
SELECT 'ai_model', ''
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'ai_model'
);

INSERT INTO ndr.settings (key, value)
SELECT 'ai_base_url', ''
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'ai_base_url'
);

INSERT INTO ndr.settings (key, value)
SELECT 'ai_endpoint_path', ''
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'ai_endpoint_path'
);

INSERT INTO ndr.settings (key, value)
SELECT 'ai_msg_format', 'openai'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'ai_msg_format'
);

INSERT INTO ndr.settings (key, value)
SELECT 'sensitive_countries', 'AM,AZ,BY,CN,CU,DZ,GE,HK,IL,IN,IQ,IR,KG,KP,KZ,LY,MD,MO,PK,RU,SD,SS,SY,TJ,TM,TW,UA,UZ'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'sensitive_countries'
);

CREATE TABLE IF NOT EXISTS ndr.soar_config ON CLUSTER ndr_cluster
(
    key        String,
    value      String,
    tenant_id  String DEFAULT 'default',
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/soar_config', '{replica}', updated_at)
ORDER BY key;

CREATE TABLE IF NOT EXISTS ndr.soar_playbooks ON CLUSTER ndr_cluster
(
    id          String,
    name        String,
    description String,
    trigger     String,
    action_type String,
    config      String,
    enabled     UInt8 DEFAULT 1,
    runs        UInt64 DEFAULT 0,
    tenant_id   String DEFAULT 'default',
    created_at  DateTime DEFAULT now(),
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/soar_playbooks', '{replica}', updated_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.soar_integrations ON CLUSTER ndr_cluster
(
    id          String,
    name        String,
    type        String,
    config      String,
    enabled     UInt8 DEFAULT 1,
    tenant_id   String DEFAULT 'default',
    created_at  DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/soar_integrations', '{replica}', created_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.users ON CLUSTER ndr_cluster
(
    id            String DEFAULT toString(generateUUIDv4()),
    username      String,
    password_hash  String,
    role          String DEFAULT 'analyst',
    tenant_id     String DEFAULT 'default',
    permissions   String DEFAULT 'dashboard,alerts',
    active        UInt8 DEFAULT 1,
    created_at    DateTime DEFAULT now(),
    last_login    DateTime DEFAULT now(),
    gmail         String DEFAULT '',
    secret_code   String DEFAULT ''
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/users', '{replica}', created_at)
ORDER BY username;

-- Migration: add gmail + secret_code columns for existing deployments (idempotent)
ALTER TABLE ndr.users ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS gmail       String DEFAULT '';
ALTER TABLE ndr.users ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS secret_code String DEFAULT '';

-- Seed default users — INSERT is idempotent because ndr.users uses ReplacingMergeTree
-- which deduplicates on ORDER BY (username). Running this multiple times is safe.
-- Password: ndr@admin123
INSERT INTO ndr.users (username, password_hash, role, tenant_id)
SELECT 'admin', '$2b$12$qB5uFqakHidExby4EbdH6.tFvW34sj7CAQFZdUCzk5YSi/kV3S09.', 'super_admin', 'default'
WHERE (SELECT count() FROM ndr.users FINAL WHERE username = 'admin') = 0;

-- Password: ndr@tenant123  (customer must change on first login)
INSERT INTO ndr.users (username, password_hash, role, tenant_id, permissions)
SELECT 'tenant-admin', '$2b$12$wi15kWc0KGLG6FEtIysJHuqRfT7PDvOoW2IC3oT3hfoQmtmygZ5h6', 'tenant_admin', 'default', 'dashboard,alerts,sensors,users,soar'
WHERE (SELECT count() FROM ndr.users FINAL WHERE username = 'tenant-admin') = 0;

CREATE TABLE IF NOT EXISTS ndr.tenants ON CLUSTER ndr_cluster
(
    id         String,
    name       String,
    active     UInt8 DEFAULT 1,
    ai_enabled UInt8 DEFAULT 1,
    updated_at DateTime DEFAULT now(),
    created_at DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/tenants', '{replica}', updated_at)
ORDER BY id;

ALTER TABLE ndr.tenants ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS ai_enabled UInt8 DEFAULT 1;

INSERT INTO ndr.tenants (id, name, active)
SELECT 'default', 'Default Organization', 1
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.tenants FINAL WHERE id = 'default'
);

CREATE TABLE IF NOT EXISTS ndr.announcements ON CLUSTER ndr_cluster
(
    id             String,
    title          String,
    message        String,
    announcement_type String DEFAULT 'info',
    audience       String DEFAULT 'all',
    status         String DEFAULT 'draft',
    target_roles   Array(String),
    target_tenants Array(String),
    start_at       DateTime DEFAULT now(),
    end_at         Nullable(DateTime),
    created_by     String,
    created_at     DateTime DEFAULT now(),
    updated_at     DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/announcements', '{replica}', updated_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.announcement_reads ON CLUSTER ndr_cluster
(
    announcement_id String,
    username        String,
    read_at         DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/announcement_reads', '{replica}', read_at)
ORDER BY (announcement_id, username);

CREATE TABLE IF NOT EXISTS ndr.sigma_rules ON CLUSTER ndr_cluster
(
    id          String,
    name        String,
    content     String,
    enabled     UInt8 DEFAULT 1,
    tenant_id   String DEFAULT 'default',
    source      String DEFAULT 'custom',
    created_at  DateTime DEFAULT now(),
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/sigma_rules', '{replica}', updated_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.sensor_keys ON CLUSTER ndr_cluster
(
    id          String DEFAULT toString(generateUUIDv4()),
    key_hash    String,
    key_prefix  String,
    tenant_id   String,
    name        String,
    hostname    String DEFAULT '',
    interface_name String DEFAULT '',
    os_name     String DEFAULT '',
    agent_z_status String DEFAULT 'unknown',
    agent_s_status String DEFAULT 'unknown',
    vector_status String DEFAULT 'unknown',
    arkime_status String DEFAULT 'unknown',
    arkime_url  String DEFAULT '',
    arkime_pass String DEFAULT '',
    active      UInt8 DEFAULT 1,
    created_at  DateTime DEFAULT now(),
    last_seen   DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/sensor_keys', '{replica}', last_seen)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.pcap_sessions ON CLUSTER ndr_cluster
(
    session_id   String,
    community_id String,
    src_ip       String,
    dst_ip       String,
    src_port     UInt16,
    dst_port     UInt16,
    proto        String,
    start_time   DateTime DEFAULT now(),
    end_time     DateTime DEFAULT now(),
    bytes        UInt64 DEFAULT 0,
    packets      UInt64 DEFAULT 0,
    arkime_url   String DEFAULT '',
    tenant_id    String DEFAULT 'default',
    sensor_host  String DEFAULT '',
    file_path    String DEFAULT ''
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/pcap_sessions', '{replica}', start_time)
ORDER BY (tenant_id, session_id)
TTL start_time + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ndr.pcap_pending ON CLUSTER ndr_cluster
(
    community_id      String,
    tenant_id         String   DEFAULT 'default',
    requested_at      DateTime DEFAULT now(),
    fulfilled         UInt8    DEFAULT 0,
    fulfilled_at      DateTime DEFAULT toDateTime(0),
    retry_count       UInt8    DEFAULT 0,
    last_retry        DateTime DEFAULT toDateTime(0),
    error_message     String   DEFAULT '',
    upload_size_bytes UInt64   DEFAULT 0,
    severity          String   DEFAULT 'MEDIUM'
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/pcap_pending', '{replica}', requested_at)
ORDER BY (tenant_id, community_id)
TTL requested_at + INTERVAL 2 DAY;

CREATE TABLE IF NOT EXISTS ndr.ai_suppressions ON CLUSTER ndr_cluster
(
    id             String            DEFAULT toString(generateUUIDv4()),
    tenant_id      String            DEFAULT 'default',
    signature_id   UInt64            DEFAULT 0,
    signature_name String            DEFAULT '',
    suppress_type  String            DEFAULT 'by_dst',
    suppress_ip    String            DEFAULT '',
    src_ip         String            DEFAULT '',
    dst_ip         String            DEFAULT '',
    community_id   String            DEFAULT '',
    ai_reason      String            DEFAULT '',
    ai_confidence  UInt8             DEFAULT 0,
    sensor_id      String            DEFAULT '',
    active         UInt8             DEFAULT 1,
    created_at     DateTime          DEFAULT now(),
    expires_at     Nullable(DateTime) DEFAULT NULL,
    suppress_scope String            DEFAULT 'individual'
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/ai_suppressions', '{replica}', created_at)
ORDER BY (tenant_id, signature_id, suppress_type, suppress_ip, signature_name, community_id)
TTL created_at + INTERVAL 90 DAY;

ALTER TABLE ndr.ai_suppressions ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS expires_at Nullable(DateTime) DEFAULT NULL;
ALTER TABLE ndr.ai_suppressions ON CLUSTER ndr_cluster ADD COLUMN IF NOT EXISTS suppress_scope String DEFAULT 'individual';

CREATE TABLE IF NOT EXISTS ndr.sensor_commands ON CLUSTER ndr_cluster
(
    id          String DEFAULT toString(generateUUIDv4()),
    tenant_id   String,
    sensor_id   String DEFAULT '',
    command     String,
    status      String DEFAULT 'pending',
    created_at  DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/sensor_commands', '{replica}', created_at)
ORDER BY (tenant_id, sensor_id, created_at);

CREATE TABLE IF NOT EXISTS ndr.support_messages ON CLUSTER ndr_cluster
(
    id              String DEFAULT toString(generateUUIDv4()),
    tenant_id       String,
    sender_username String,
    sender_role     String,
    subject         String,
    category        String DEFAULT 'General',
    message         String,
    status          String DEFAULT 'open',
    admin_reply     String DEFAULT '',
    replied_by      String DEFAULT '',
    forwarded       UInt8 DEFAULT 0,
    forwarded_by    String DEFAULT '',
    deleted         UInt8 DEFAULT 0,
    created_at      DateTime DEFAULT now(),
    updated_at      DateTime DEFAULT now(),
    replied_at      Nullable(DateTime),
    forwarded_at    Nullable(DateTime)
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/support_messages', '{replica}', updated_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.soar_cases ON CLUSTER ndr_cluster
(
    id           String DEFAULT toString(generateUUIDv4()),
    case_number  String DEFAULT '',
    priority     String DEFAULT 'P2',
    title        String,
    description  String DEFAULT '',
    severity     String DEFAULT 'MEDIUM',
    status       String DEFAULT 'New',
    assigned_to  String DEFAULT '',
    src_ip       String DEFAULT '',
    dst_ip       String DEFAULT '',
    community_id String DEFAULT '',
    hit_ids      Array(String) DEFAULT [],
    tags         Array(String) DEFAULT [],
    created_at   DateTime DEFAULT now(),
    updated_at   DateTime DEFAULT now(),
    closed_at    Nullable(DateTime),
    tenant_id    String DEFAULT 'default'
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/soar_cases', '{replica}', updated_at)
ORDER BY (tenant_id, created_at);

CREATE TABLE IF NOT EXISTS ndr.soar_case_comments ON CLUSTER ndr_cluster
(
    id         String DEFAULT toString(generateUUIDv4()),
    case_id    String,
    author     String,
    comment    String,
    created_at DateTime DEFAULT now(),
    tenant_id  String DEFAULT 'default'
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/soar_case_comments', '{replica}')
ORDER BY (tenant_id, case_id, created_at)
TTL created_at + INTERVAL 730 DAY;

CREATE TABLE IF NOT EXISTS ndr.soar_native_playbooks ON CLUSTER ndr_cluster
(
    id           String DEFAULT toString(generateUUIDv4()),
    name         String,
    description  String DEFAULT '',
    enabled      UInt8 DEFAULT 1,
    cond_field   String,
    cond_op      String,
    cond_value   String,
    action_type  String,
    action_config String,
    run_count    UInt64 DEFAULT 0,
    last_run     Nullable(DateTime),
    created_at   DateTime DEFAULT now(),
    updated_at   DateTime DEFAULT now(),
    tenant_id    String DEFAULT 'default'
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/soar_native_playbooks', '{replica}', updated_at)
ORDER BY (tenant_id, id);

CREATE TABLE IF NOT EXISTS ndr.soar_playbook_runs ON CLUSTER ndr_cluster
(
    id            String DEFAULT toString(generateUUIDv4()),
    playbook_id   String,
    playbook_name String,
    hit_id        String,
    status        String,
    detail        String,
    created_at    DateTime DEFAULT now(),
    tenant_id     String DEFAULT 'default'
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/soar_playbook_runs', '{replica}')
ORDER BY (tenant_id, created_at)
TTL created_at + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS ndr.evidence_log ON CLUSTER ndr_cluster
(
    id              String DEFAULT generateUUIDv4(),
    community_id    String,
    bundle_id       String DEFAULT '',
    action          String,
    performed_by    String,
    performed_at    DateTime DEFAULT now(),
    severity        String DEFAULT '',
    src_ip          String DEFAULT '',
    dst_ip          String DEFAULT '',
    case_id         String DEFAULT '',
    notes           String DEFAULT '',
    ip_address      String DEFAULT ''
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/evidence_log', '{replica}')
ORDER BY (community_id, performed_at)
TTL performed_at + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS ndr.evidence_bundles ON CLUSTER ndr_cluster
(
    id              String DEFAULT generateUUIDv4(),
    community_id    String,
    file_path       String,
    sha256          String,
    size_bytes      UInt64 DEFAULT 0,
    auto_captured   UInt8 DEFAULT 0,
    captured_at     DateTime DEFAULT now(),
    expires_at      DateTime DEFAULT now() + INTERVAL 90 DAY,
    status          String DEFAULT 'ready',
    legal_hold      UInt8 DEFAULT 0,
    hold_reason     String DEFAULT '',
    hold_set_by     String DEFAULT '',
    src_ip          String DEFAULT '',
    dst_ip          String DEFAULT '',
    severity        String DEFAULT '',
    alert_id        String DEFAULT ''
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/evidence_bundles', '{replica}', captured_at)
ORDER BY (community_id, id)
TTL expires_at WHERE legal_hold = 0;

CREATE TABLE IF NOT EXISTS ndr.evidence_annotations ON CLUSTER ndr_cluster
(
    id              String DEFAULT generateUUIDv4(),
    bundle_id       String,
    community_id    String,
    author          String,
    note            String,
    tag             String DEFAULT '',
    created_at      DateTime DEFAULT now()
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/evidence_annotations', '{replica}')
ORDER BY (bundle_id, created_at);

CREATE TABLE IF NOT EXISTS ndr.ioc_hits ON CLUSTER ndr_cluster
(
    timestamp    DateTime DEFAULT now(),
    community_id String,
    src_ip       String,
    dst_ip       String,
    matched_ip   String,
    ioc_type     String   DEFAULT 'ip',
    feed_source  String   DEFAULT 'feodo'
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/ioc_hits', '{replica}')
ORDER BY (timestamp, community_id, matched_ip)
TTL timestamp + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS ndr.shared_iocs ON CLUSTER ndr_cluster
(
    id                  String DEFAULT generateUUIDv4(),
    ioc_value           String,
    ioc_type            String,
    confidence          UInt8 DEFAULT 50,
    first_seen          DateTime DEFAULT now(),
    last_seen           DateTime DEFAULT now(),
    tenant_hash         String DEFAULT '',
    tags                String DEFAULT '',
    description         String DEFAULT ''
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/shared_iocs', '{replica}', last_seen)
ORDER BY (ioc_type, ioc_value);

CREATE TABLE IF NOT EXISTS ndr.assets ON CLUSTER ndr_cluster
(
    ip             String,
    mac            String DEFAULT '',
    hostname       String DEFAULT '',
    vendor         String DEFAULT '',
    os_guess       String DEFAULT '',
    device_type    LowCardinality(String) DEFAULT 'unknown',
    custom_name    String DEFAULT '',
    tenant_id      String DEFAULT 'default',
    first_seen     DateTime DEFAULT now(),
    last_seen      DateTime DEFAULT now(),
    ip_history     String DEFAULT '[]',
    trusted        UInt8  DEFAULT 0,
    threat_flagged UInt8  DEFAULT 0,
    role           String DEFAULT '',
    criticality    UInt8  DEFAULT 0,
    open_ports     String DEFAULT '[]',
    subnet_role    String DEFAULT '',
    ja3_os         String DEFAULT ''
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/assets', '{replica}', last_seen)
ORDER BY (tenant_id, ip);

CREATE TABLE IF NOT EXISTS ndr.passive_dns ON CLUSTER ndr_cluster
(
    ip          String,
    domain      String,
    hit_count   SimpleAggregateFunction(sum, UInt64) DEFAULT 1,
    first_seen  SimpleAggregateFunction(min, DateTime) DEFAULT now(),
    last_seen   SimpleAggregateFunction(max, DateTime) DEFAULT now()
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/ndr/passive_dns', '{replica}')
ORDER BY (ip, domain)
TTL last_seen + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS ndr.ipam_subnets ON CLUSTER ndr_cluster
(
    tenant_id  String   DEFAULT 'default',
    interface  String   DEFAULT '',
    cidr       String,
    local_ip   String   DEFAULT '',
    gateway    String   DEFAULT '',
    sensor_id  String   DEFAULT '',
    first_seen DateTime DEFAULT now(),
    last_seen  DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/ipam_subnets', '{replica}', last_seen)
ORDER BY (tenant_id, cidr);

-- ── Threat Prediction Engine tables ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ndr.threat_intel ON CLUSTER ndr_cluster
(
    id           String   DEFAULT generateUUIDv4(),
    source       String,
    attack_type  String,
    severity     String   DEFAULT 'MEDIUM',
    ioc_type     String   DEFAULT '',
    ioc_value    String   DEFAULT '',
    description  String   DEFAULT '',
    raw          String   DEFAULT '{}',
    collected_at DateTime DEFAULT now(),
    expires_at   DateTime DEFAULT now() + INTERVAL 7 DAY
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/threat_intel', '{replica}')
ORDER BY (attack_type, collected_at)
TTL collected_at + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ndr.exposure_profile ON CLUSTER ndr_cluster
(
    id               String   DEFAULT generateUUIDv4(),
    tenant_id        String,
    snapshot_at      DateTime DEFAULT now(),
    rdp_exposed      UInt8    DEFAULT 0,
    smb_exposed      UInt8    DEFAULT 0,
    ssh_exposed      UInt8    DEFAULT 0,
    http_exposed     UInt8    DEFAULT 0,
    dns_anomalies    UInt64   DEFAULT 0,
    port_scans       UInt64   DEFAULT 0,
    failed_logins    UInt64   DEFAULT 0,
    lateral_movement UInt64   DEFAULT 0,
    c2_beacons       UInt64   DEFAULT 0,
    data_exfil_bytes UInt64   DEFAULT 0,
    brute_force_attempts UInt64 DEFAULT 0,
    unique_src_ips   UInt64   DEFAULT 0,
    raw              String   DEFAULT '{}'
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/exposure_profile', '{replica}')
ORDER BY (tenant_id, snapshot_at)
TTL snapshot_at + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS ndr.threat_predictions ON CLUSTER ndr_cluster
(
    id                  String   DEFAULT generateUUIDv4(),
    tenant_id           String,
    predicted_at        DateTime DEFAULT now(),
    attack_type         String,
    probability         Float32,
    confidence          Float32,
    trend               String,
    trend_delta         Float32,
    intel_signal_count  UInt32   DEFAULT 0,
    exposure_score      Float32  DEFAULT 0.0,
    internal_hit_count  UInt32   DEFAULT 0,
    explanation         String   DEFAULT '',
    recommendations     String   DEFAULT '[]',
    aria_briefing       String   DEFAULT '',
    alert_level         String   DEFAULT 'info',
    notified            UInt8    DEFAULT 0
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/threat_predictions', '{replica}')
ORDER BY (tenant_id, predicted_at, attack_type)
TTL predicted_at + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS ndr.ioc_watchlist ON CLUSTER ndr_cluster
(
    id          String   DEFAULT generateUUIDv4(),
    tenant_id   String,
    ioc_type    String,
    ioc_value   String,
    source      String,
    attack_type String,
    added_at    DateTime DEFAULT now(),
    expires_at  DateTime DEFAULT now() + INTERVAL 7 DAY,
    active      UInt8    DEFAULT 1
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/ioc_watchlist', '{replica}', added_at)
ORDER BY (tenant_id, ioc_value)
TTL expires_at;

-- ── Pattern Matching Engine ───────────────────────────────────────────────────

ALTER TABLE ndr.threat_intel ON CLUSTER ndr_cluster
    ADD COLUMN IF NOT EXISTS threat_pattern String DEFAULT '';

ALTER TABLE ndr.threat_predictions ON CLUSTER ndr_cluster
    ADD COLUMN IF NOT EXISTS ai_model String DEFAULT '';

ALTER TABLE ndr.threat_predictions ON CLUSTER ndr_cluster
    ADD COLUMN IF NOT EXISTS source String DEFAULT 'predictor';

ALTER TABLE ndr.ioc_watchlist ON CLUSTER ndr_cluster
    ADD COLUMN IF NOT EXISTS attacker_group String DEFAULT '';

-- MITRE ATT&CK technique definitions
CREATE TABLE IF NOT EXISTS ndr.attack_patterns ON CLUSTER ndr_cluster
(
    technique_id     String,
    technique_name   String,
    tactic           String   DEFAULT '',
    description      String   DEFAULT '',
    detection        String   DEFAULT '',
    platforms        String   DEFAULT '',
    kill_chain_phase UInt8    DEFAULT 0,
    severity         String   DEFAULT 'MEDIUM',
    updated_at       DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/attack_patterns', '{replica}', updated_at)
ORDER BY technique_id;

-- Ordered attack chain definitions (ransomware, APT, credential, etc.)
CREATE TABLE IF NOT EXISTS ndr.attack_chains ON CLUSTER ndr_cluster
(
    chain_id               String,
    chain_name             String,
    threat_actor           String   DEFAULT '',
    attack_type            String,
    description            String   DEFAULT '',
    severity               String   DEFAULT 'HIGH',
    steps                  String   DEFAULT '[]',
    typical_duration_hours UInt8    DEFAULT 24,
    source                 String   DEFAULT 'builtin',
    created_at             DateTime DEFAULT now(),
    mitre_group_id         String   DEFAULT '',
    mitre_campaign_id      String   DEFAULT '',
    is_dynamic             UInt8    DEFAULT 0
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/attack_chains', '{replica}')
ORDER BY (attack_type, chain_id);

-- Live pattern match detections — when your traffic follows a known chain
CREATE TABLE IF NOT EXISTS ndr.pattern_matches ON CLUSTER ndr_cluster
(
    id                  String   DEFAULT generateUUIDv4(),
    tenant_id           String,
    chain_id            String,
    chain_name          String,
    attack_type         String,
    steps_observed      UInt8    DEFAULT 0,
    steps_total         UInt8    DEFAULT 0,
    completion_pct      Float32  DEFAULT 0,
    evidence            String   DEFAULT '[]',
    next_step           String   DEFAULT '',
    predicted_eta_hours Float32  DEFAULT 0,
    src_ip              String   DEFAULT '',
    severity            String   DEFAULT 'HIGH',
    confidence          Float32  DEFAULT 0,
    first_seen          DateTime DEFAULT now(),
    last_updated        DateTime DEFAULT now(),
    status              String   DEFAULT 'active',
    ai_assessment       String   DEFAULT '',
    recommendations     String   DEFAULT '[]'
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/pattern_matches', '{replica}', last_updated)
ORDER BY (tenant_id, chain_id, src_ip)
TTL first_seen + INTERVAL 7 DAY;

-- AI provider registry — multiple providers per tenant, tried in priority order
CREATE TABLE IF NOT EXISTS ndr.ai_providers ON CLUSTER ndr_cluster
(
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
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/ai_providers', '{replica}', created_at)
ORDER BY name;

CREATE TABLE IF NOT EXISTS ndr.user_sensor_assignments ON CLUSTER ndr_cluster
(
    user_id    String,
    sensor_id  String,
    tenant_id  String,
    created_at DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/user_sensor_assignments', '{replica}', created_at)
ORDER BY (tenant_id, user_id, sensor_id);

-- Device isolations — ARP spoofing, switch VLAN quarantine, cloud firewall deny
CREATE TABLE IF NOT EXISTS ndr.device_isolations ON CLUSTER ndr_cluster
(
    id                 String   DEFAULT toString(generateUUIDv4()),
    tenant_id          String   DEFAULT 'default',
    target_ip          String,
    gateway_ip         String   DEFAULT '',
    method             LowCardinality(String)   DEFAULT 'arp',       -- arp / switch_vlan / cloud_firewall
    enforcement        LowCardinality(String)   DEFAULT 'arp',       -- arp / unifi / cisco / aruba / snmp / aws_sg / azure_nsg / gcp_vpc
    enforcement_detail String   DEFAULT '{}',        -- JSON: switch IP, rule ID, port, VLAN, etc.
    triggered_by       String   DEFAULT 'manual',    -- playbook name or 'manual'
    sensor_id          String   DEFAULT '',
    reason             String   DEFAULT '',
    status             LowCardinality(String)   DEFAULT 'active',    -- active / restored / expired
    created_at         DateTime DEFAULT now(),
    updated_at         DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/device_isolations', '{replica}', updated_at)
ORDER BY (tenant_id, id)
TTL created_at + INTERVAL 180 DAY;

-- Attack incidents — lateral movement chains grouped into a single story
CREATE TABLE IF NOT EXISTS ndr.ndr_incidents ON CLUSTER ndr_cluster
(
    id              String   DEFAULT toString(generateUUIDv4()),
    tenant_id       String   DEFAULT 'default',
    title           String,
    severity        LowCardinality(String) DEFAULT 'MEDIUM',
    status          LowCardinality(String) DEFAULT 'active',   -- active / contained / resolved
    affected_ips    Array(String),
    attack_chain    String   DEFAULT '[]',  -- JSON: [{src_ip,dst_ip,timestamp,severity,rule_name,community_id}]
    alert_ids       Array(String),
    first_seen      DateTime DEFAULT now(),
    last_seen       DateTime DEFAULT now(),
    created_at      DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/ndr_incidents', '{replica}', last_seen)
ORDER BY (tenant_id, id)
TTL created_at + INTERVAL 90 DAY;

-- JARM TLS fingerprint observations — known C2 framework detection by TLS stack
CREATE TABLE IF NOT EXISTS ndr.jarm_observations ON CLUSTER ndr_cluster
(
    id          String   DEFAULT toString(generateUUIDv4()),
    tenant_id   String   DEFAULT 'default',
    server_ip   String,
    server_port UInt16,
    fingerprint String,
    c2_match    String   DEFAULT '',
    first_seen  DateTime DEFAULT now(),
    created_at  DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/jarm_observations', '{replica}', first_seen)
ORDER BY (tenant_id, server_ip, server_port)
TTL created_at + INTERVAL 90 DAY;

-- ── Retention TTL migrations (idempotent — safe to re-run on existing tables) ──
-- Applied here so already-deployed clusters pick up TTLs without a manual ALTER.
ALTER TABLE ndr.ioc_hits ON CLUSTER ndr_cluster MODIFY TTL timestamp + INTERVAL 90 DAY;
ALTER TABLE ndr.soar_playbook_runs ON CLUSTER ndr_cluster MODIFY TTL created_at + INTERVAL 90 DAY;
ALTER TABLE ndr.evidence_log ON CLUSTER ndr_cluster MODIFY TTL performed_at + INTERVAL 90 DAY;
ALTER TABLE ndr.soar_case_comments ON CLUSTER ndr_cluster MODIFY TTL created_at + INTERVAL 730 DAY;


-- ── Unified Alerts — ONE table for ALL alert sources (NDR + SIEM + corroborated) ──
-- ndr-engine writes here with source='ndr'; siem-engine with source='siem';
-- correlation engine writes corroborated alerts with source='corroborated'.
CREATE TABLE IF NOT EXISTS ndr.unified_alerts ON CLUSTER ndr_cluster
(
    alert_id             String   DEFAULT toString(generateUUIDv4()),
    tenant_id            String,
    source               LowCardinality(String),   -- ndr / siem / corroborated / threat_intel
    severity             LowCardinality(String),   -- CRITICAL / HIGH / MEDIUM / LOW / INFO
    rule_id              String   DEFAULT '',
    rule_name            String   DEFAULT '',
    title                String,
    description          String   DEFAULT '',
    affected_hosts       Array(String),
    mitre_techniques     Array(String),
    mitre_sources        Array(String),
    mitre_confidences    Array(Float32),
    status               LowCardinality(String)   DEFAULT 'New',  -- New / Investigating / Escalated / Resolved / Closed
    assignee_id          Nullable(String),
    linked_alert_ids     Array(String),
    linked_ndr_event_ids Array(String),
    linked_siem_log_ids  Array(String),
    ai_summary           Nullable(String),
    ai_provider          Nullable(String),
    qdrant_refs          Array(String),
    threat_intel_matches Array(String),
    is_fp                Nullable(UInt8),
    sla_started_at       Nullable(DateTime),
    sla_breached_at      Nullable(DateTime),
    legal_hold           UInt8    DEFAULT 0,
    created_at           DateTime DEFAULT now(),
    updated_at           DateTime DEFAULT now()
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/ndr/unified_alerts', '{replica}', updated_at)
ORDER BY (tenant_id, alert_id)
TTL created_at + INTERVAL 365 DAY;
