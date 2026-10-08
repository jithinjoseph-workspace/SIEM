// Multi-flow correlator — detects attack patterns that span multiple network flows.
//
// Three background loops:
//   Tier 1/2 (every 60 s)  — short/medium window: port scan, cred stuffing, lateral movement,
//                             DNS beaconing, slow scan, internal recon, data staging
//   Tier 3a (every 24 h)   — baseline refresh: pre-aggregates per-IP daily stats into ndr_baselines
//   Tier 3b (every 5 min)  — anomaly detection: volume spike, new external contact

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use chrono::{Utc, Timelike};
use clickhouse::Row;
use serde::{Deserialize, Serialize};

use crate::leader::LeaderElection;
use crate::storage::ClickhouseStorage;
use crate::storage::clickhouse::{
    NdrHit,
    tenant_db_pub as db_for,
    sql_escape_pub as esc,
};

/// Returns a SQL fragment like `AND src_ip NOT IN ('x','y') AND dst_ip NOT IN ('x','y')`
/// excluding the NDR host machine itself and well-known public DNS servers from all detections.
fn host_exclusion_clause() -> String {
    let mut ips: Vec<String> = vec![
        // Well-known public DNS resolvers — their return traffic looks like slow-scan/beaconing
        "8.8.8.8".to_string(), "8.8.4.4".to_string(),
        "1.1.1.1".to_string(), "1.0.0.1".to_string(),
        "9.9.9.9".to_string(), "149.112.112.112".to_string(),
    ];
    // NDR host machine's own IP — its traffic floods every detection
    if let Ok(host) = std::env::var("HOST_IP") {
        let h = host.trim().to_string();
        if !h.is_empty() && !ips.contains(&h) {
            ips.push(h);
        }
    }
    let list = ips.iter().map(|ip| format!("'{}'", ip)).collect::<Vec<_>>().join(",");
    format!(" AND src_ip NOT IN ({list}) AND dst_ip NOT IN ({list})")
}

// Suppression windows — how long after an alert fires before the same
// (pattern, tenant, src_ip) is allowed to fire again.
const SUP_PORT_SCAN:   Duration = Duration::from_secs(1800); // 30 min
const SUP_CRED_STUFF:  Duration = Duration::from_secs(1800);
const SUP_LATERAL:     Duration = Duration::from_secs(1800);
const SUP_DNS_BEACON:  Duration = Duration::from_secs(3600); // 60 min
const SUP_SLOW_SCAN:   Duration = Duration::from_secs(3600);
const SUP_RECON:       Duration = Duration::from_secs(1800);
const SUP_STAGING:     Duration = Duration::from_secs(3600);
const SUP_VOL_ANOMALY:    Duration = Duration::from_secs(3600);
const SUP_NEW_CONTACT:    Duration = Duration::from_secs(86400); // 24 h — new contact once per day per pair
const SUP_ICMP_FLOOD:     Duration = Duration::from_secs(1800);
const SUP_ABNORMAL_HOURS: Duration = Duration::from_secs(3600);
const SUP_NXDOMAIN:       Duration = Duration::from_secs(1800);
const SUP_DNS_TUNNEL:     Duration = Duration::from_secs(3600);
const SUP_TLS_CERT:       Duration = Duration::from_secs(3600);
const SUP_PROTO_MISUSE:   Duration = Duration::from_secs(1800);
const SUP_LARGE_EXFIL:    Duration = Duration::from_secs(3600);

// In-memory suppression cache: key = (pattern, tenant, identifier), value = Instant of last emit.
// Wrapped in a Mutex (instead of a plain &mut passed around) because tenants are now
// scanned concurrently within a Tier 1/2 or Tier 3 cycle and all share this one map.
type SuppressMap = HashMap<(String, String, String), Instant>;
type SharedSuppressMap = Arc<tokio::sync::Mutex<SuppressMap>>;

async fn is_suppressed(map: &SharedSuppressMap, pattern: &str, tenant: &str, key: &str, window: Duration) -> bool {
    let k = (pattern.to_string(), tenant.to_string(), key.to_string());
    let mut map = map.lock().await;
    if let Some(last) = map.get(&k) {
        if last.elapsed() < window {
            return true;
        }
    }
    map.insert(k, Instant::now());
    false
}

// Evict entries older than 24 h to prevent unbounded memory growth.
async fn evict_old(map: &SharedSuppressMap) {
    map.lock().await.retain(|_, v| v.elapsed() < Duration::from_secs(86400));
}

// Issues 7 & 8 fix: load recent multiflow hits from ClickHouse into the SuppressMap.
// Called once at startup so suppression state survives engine restarts and leader re-elections.
// Composite keys (dns-beaconing, new-contact, tls-cert, proto-misuse) are reconstructed
// from src_ip + dst_ip — consistent with how they are keyed during detection.
async fn load_suppressions_from_db(ch: &ClickhouseStorage) -> SuppressMap {
    static PATTERNS: &[(&str, &str, u64)] = &[
        ("portscan",      "port-scan",              1800),
        ("credstuff",     "credential-stuffing",    1800),
        ("lateral",       "lateral-movement",       1800),
        ("dnsbeacon",     "dns-beaconing",          3600),
        ("slowscan",      "slow-scan",              3600),
        ("recon",         "internal-recon",         1800),
        ("staging",       "data-staging",           3600),
        ("volanom",       "volume-anomaly",         3600),
        ("newcontact",    "new-external-contact",   86400),
        ("icmpflood",     "icmp-flood",             1800),
        ("tlscert",       "tls-cert-anomaly",       3600),
        ("protomisuse",   "protocol-misuse",        1800),
        ("largeexfil",    "large-volume-exfil",     3600),
        ("abnormalhours", "abnormal-hours",         3600),
        ("nxdomain",      "nxdomain-flood",         1800),
        ("dnstunnel",     "dns-tunneling",          3600),
    ];

    let tag_list = PATTERNS.iter()
        .map(|(_, tag, _)| format!("'{}'", tag))
        .collect::<Vec<_>>().join(",");

    let mut map = SuppressMap::new();
    let now_secs = chrono::Utc::now().timestamp() as u64;
    let tenants = ch.get_all_tenants().await.unwrap_or_default();

    for tenant in &tenants {
        let db = db_for(tenant);
        let t   = esc(tenant);
        let q   = format!(
            "SELECT src_ip, dst_ip, tags, timestamp \
             FROM {db}.ndr_hits FINAL \
             WHERE timestamp > now() - INTERVAL 86400 SECOND \
               AND tenant_id = '{t}' \
               AND hasAny(tags, [{tag_list}])"
        );

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct HitRow {
            src_ip:    String,
            dst_ip:    String,
            tags:      Vec<String>,
            timestamp: u32,
        }

        let rows: Vec<HitRow> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
        for row in rows {
            let elapsed_secs = now_secs.saturating_sub(row.timestamp as u64);
            for (pattern, tag, window) in PATTERNS {
                if elapsed_secs >= *window { continue; }
                if !row.tags.iter().any(|t| t == *tag) { continue; }
                let identifier = match *pattern {
                    "dnsbeacon" | "newcontact" | "tlscert" | "protomisuse"
                        if !row.dst_ip.is_empty() =>
                        format!("{}:{}", row.src_ip, row.dst_ip),
                    _ => row.src_ip.clone(),
                };
                let k = (pattern.to_string(), tenant.clone(), identifier);
                let elapsed = Duration::from_secs(elapsed_secs);
                let last = Instant::now().checked_sub(elapsed).unwrap_or_else(Instant::now);
                map.entry(k).or_insert(last);
            }
        }
    }
    map
}

// ── Query result row types ────────────────────────────────────────────────────

#[derive(Row, Serialize, Deserialize)]
struct TwoCount {
    src_ip: String,
    cnt_a:  u64,
    cnt_b:  u64,
}

#[derive(Row, Serialize, Deserialize)]
struct OneCount {
    src_ip: String,
    cnt:    u64,
}

#[allow(dead_code)]
#[derive(Row, Serialize, Deserialize)]
struct PairCount {
    src_ip: String,
    dst_ip: String,
    cnt:    u64,
    span:   i64,
}

#[derive(Row, Serialize, Deserialize)]
struct DnsBeaconRow {
    src_ip: String,
    domain: String,
    cnt:    u64,
    span:   i64,
}

#[derive(Row, Deserialize)]
struct DomainRow {
    domain: String,
}

#[derive(Row, Serialize, Deserialize)]
struct BRow {
    src_ip:  String,
    value_f: f64,
    value_s: String,
}

#[derive(Row, Serialize, Deserialize)]
struct NewContact {
    src_ip: String,
    dst_ip: String,
}

#[derive(Row, Serialize, Deserialize)]
struct VolAnomaly {
    src_ip:      String,
    today_cnt:   u64,
    avg_hourly:  f64,
}

#[derive(Row, Serialize)]
struct NdrBaseline {
    tenant_id:  String,
    src_ip:     String,
    metric:     String,
    value_f:    f64,
    value_s:    String,
    window_ts:  u32,
    updated_at: u32,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn spawn(ch: Arc<ClickhouseStorage>, election: Arc<LeaderElection>) {
    // Tier 1+2 — every 60 s, only on elected leader
    {
        let ch  = ch.clone();
        let el  = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            // Issues 7 & 8 fix: seed from DB so recent suppressions survive restarts.
            let sup: SharedSuppressMap = Arc::new(tokio::sync::Mutex::new(load_suppressions_from_db(&ch).await));
            let mut evict_tick = 0u32;
            loop {
                if el.is_leader() {
                    run_tier12(&ch, &sup).await;
                    evict_tick += 1;
                    if evict_tick % 60 == 0 { evict_old(&sup).await; }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
        });
    }
    // Tier 3a — baseline refresh every 24 h, only on elected leader
    {
        let ch = ch.clone();
        let el = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;
            loop {
                if el.is_leader() {
                    run_baseline_refresh(&ch).await;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;
            }
        });
    }
    // Tier 3b — anomaly detection every 5 min, only on elected leader
    {
        let ch = ch.clone();
        let el = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            let sup: SharedSuppressMap = Arc::new(tokio::sync::Mutex::new(load_suppressions_from_db(&ch).await));
            loop {
                if el.is_leader() {
                    run_tier3(&ch, &sup).await;
                    evict_old(&sup).await;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            }
        });
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_ts() -> u32 {
    Utc::now().timestamp() as u32
}

fn severity_label(score: f32) -> &'static str {
    match score as u32 {
        0..=49  => "low",
        50..=69 => "medium",
        70..=84 => "high",
        _       => "critical",
    }
}

// Unique community_id for a new alert row — includes timestamp so each
// suppression-allowed emit is a distinct row (not an update of the previous one).
fn make_cid(pattern: &str, tenant: &str, key: &str) -> String {
    format!("mf:{}:{}:{}:{}", pattern, tenant, key, now_ts())
}

// Look up the sensor that most recently saw src_ip for this tenant.
// Returns empty string on miss so the hit is still written without a sensor tag.
async fn sensor_for(ch: &ClickhouseStorage, db: &str, tenant: &str, src_ip: &str) -> String {
    #[derive(Row, Serialize, Deserialize)]
    struct SRow { sensor_id: String }
    let q = format!(
        "SELECT sensor_id FROM {db}.ndr_events \
         WHERE tenant_id = '{t}' AND src_ip = '{ip}' AND sensor_id != '' \
         ORDER BY timestamp DESC LIMIT 1",
        db = db, t = esc(tenant), ip = esc(src_ip)
    );
    ch.client.query(&q).fetch_all::<SRow>().await
        .unwrap_or_default()
        .into_iter()
        .next()
        .map(|r| r.sensor_id)
        .unwrap_or_default()
}

async fn emit(
    ch:        &ClickhouseStorage,
    tenant:    &str,
    cid:       &str,
    src_ip:    &str,
    dst_ip:    &str,
    score:     f32,
    tags:      Vec<String>,
    sensor_id: &str,
) {
    let now = now_ts();
    let hit = NdrHit {
        timestamp:          now,
        community_id:       cid.to_string(),
        src_ip:             src_ip.to_string(),
        dst_ip:             dst_ip.to_string(),
        score,
        severity:           severity_label(score).to_string(),
        tags,
        sigma_hits:         vec![],
        threat_intel:       0,
        src_country:        String::new(),
        dst_country:        String::new(),
        tenant_id:          tenant.to_string(),
        correlation_status: "multiflow".to_string(),
        agent_z_details:    "{}".to_string(),
        agent_s_details:    "{}".to_string(),
        corroborated_at:    0,
        agent_s_rule_id:    String::new(),
        agent_s_category:   String::new(),
        updated_at:         now,
        sensor_id:          sensor_id.to_string(),
    };
    if let Err(e) = ch.insert_hit_for_tenant(hit, tenant).await {
        tracing::warn!("multiflow emit failed [{}/{}]: {}", tenant, cid, e);
    }
}

// Private IP range SQL fragment for a named column.
// Covers IPv4 RFC-1918, IPv4 loopback, IPv6 ULA (fc00::/7), IPv6 link-local (fe80::/10),
// and IPv6 loopback (::1) so multiflow detectors work correctly on dual-stack networks.
fn is_private(col: &str) -> String {
    // ClickHouse evaluates isIPAddressInRange over the whole column block before
    // combining with other WHERE conditions (no short-circuit on `dst_ip != ''`
    // guards elsewhere in the query), so a single empty-string row throws
    // CANNOT_PARSE_TEXT and aborts the whole query. Guard the argument itself.
    let safe = format!("if({c} = '', '0.0.0.0', {c})", c = col);
    format!(
        "(isIPAddressInRange({safe},'10.0.0.0/8') \
          OR isIPAddressInRange({safe},'192.168.0.0/16') \
          OR isIPAddressInRange({safe},'172.16.0.0/12') \
          OR isIPAddressInRange({safe},'127.0.0.0/8') \
          OR isIPAddressInRange({safe},'fc00::/7') \
          OR isIPAddressInRange({safe},'fe80::/10') \
          OR isIPAddressInRange({safe},'ff00::/8') \
          OR isIPAddressInRange({safe},'224.0.0.0/4') \
          OR isIPAddressInRange({safe},'169.254.0.0/16') \
          OR {c} = '::1')",
        safe = safe,
        c = col
    )
}

// ── Tier 1 + 2: short / medium window ─────────────────────────────────────────

async fn run_tier12(ch: &ClickhouseStorage, sup: &SharedSuppressMap) {
    let tenants = match ch.get_all_tenants().await {
        Ok(t) => t,
        Err(e) => { tracing::warn!("multiflow: get_all_tenants: {}", e); return; }
    };
    // Bounded concurrency across tenants — this cycle runs every 60s, so a fully
    // sequential loop of 13 detectors x N tenants can fall behind at real tenant
    // counts. Each tenant's own 13 detectors still run sequentially within its task.
    let sem = Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
    let mut handles = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let ch2  = ch.clone();
        let sup2 = Arc::clone(sup);
        let sem2 = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            detect_port_scan(&ch2, &tenant, &sup2).await;
            detect_credential_stuffing(&ch2, &tenant, &sup2).await;
            detect_lateral_movement(&ch2, &tenant, &sup2).await;
            detect_dns_beaconing(&ch2, &tenant, &sup2).await;
            detect_slow_scan(&ch2, &tenant, &sup2).await;
            detect_internal_recon(&ch2, &tenant, &sup2).await;
            detect_data_staging(&ch2, &tenant, &sup2).await;
            detect_icmp_flood(&ch2, &tenant, &sup2).await;
            detect_nxdomain_flood(&ch2, &tenant, &sup2).await;
            detect_dns_tunneling(&ch2, &tenant, &sup2).await;
            detect_tls_cert_anomaly(&ch2, &tenant, &sup2).await;
            detect_protocol_misuse(&ch2, &tenant, &sup2).await;
            detect_large_volume_exfil(&ch2, &tenant, &sup2).await;
        }));
    }
    futures_util::future::join_all(handles).await;
}

// Port scan: >15 distinct ports OR >20 distinct hosts from one src in 5 min
async fn detect_port_scan(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, \
                count(DISTINCT dst_port) AS cnt_a, \
                count(DISTINCT dst_ip)   AS cnt_b \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 5 MINUTE \
           AND tenant_id = '{t}' AND src_ip != '' \
           AND event_type IN ('conn', 'flow') \
         GROUP BY src_ip \
         HAVING cnt_a > 15 OR cnt_b > 20"
    );
    let rows: Vec<TwoCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "portscan", tenant, &r.src_ip, SUP_PORT_SCAN).await { continue; }
        tracing::info!("multiflow[port-scan] {}/{}: {} ports {} targets",
            tenant, r.src_ip, r.cnt_a, r.cnt_b);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("portscan", tenant, &r.src_ip),
            &r.src_ip, "", 65.0,
            vec!["port-scan".into(), "t:discovery".into()], &sid).await;
    }
}

// Credential stuffing / password spray: >20 auth-related events from one src in 10 min.
// Four signal layers (any one is sufficient):
//   1. Suricata alert events (when Suricata is deployed)
//   2. Zeek HTTP 401/403/407/429 response codes
//   3. Zeek SSH auth_success = false
//   4. Zeek FTP 530/430/332 reply codes
//   5. Zeek conn.log connections to auth ports (22, 389, 445, 636, 3389, 5985, 5986)
//      — covers RDP, LDAP, SMB, WinRM and SSH on non-standard ports where
//        Zeek doesn't decode auth results but high connection rate is the signal
async fn detect_credential_stuffing(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, count() AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 10 MINUTE \
           AND tenant_id = '{t}' AND src_ip != '' \
           AND ( \
             JSONExtractUInt(raw, 'status_code') IN (401, 403, 407, 429) \
             OR (event_type = 'ssh'  AND JSONExtractString(raw, 'auth_success') = 'false') \
             OR JSONExtractUInt(raw, 'reply_code') IN (530, 430, 332) \
             OR (event_type IN ('conn', 'flow') \
                 AND dst_port IN (22, 389, 445, 636, 3389, 5985, 5986)) \
           ) \
         GROUP BY src_ip \
         HAVING cnt > 20"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "credstuff", tenant, &r.src_ip, SUP_CRED_STUFF).await { continue; }
        tracing::info!("multiflow[cred-stuffing] {}/{}: {} alert flows",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("credstuff", tenant, &r.src_ip),
            &r.src_ip, "", 75.0,
            vec!["credential-stuffing".into(), "t:credential-access".into()], &sid).await;
    }
}

// Lateral movement: internal src hitting >3 distinct internal hosts on high-risk
// admin/protocol ports in 10 min.
//
// Scoped to lateral-movement-specific ports only:
//   22=SSH, 135=RPC, 139=NetBIOS-ssn, 445=SMB, 3389=RDP,
//   5985/5986=WinRM, 1433=MSSQL, 3306=MySQL, 5432=Postgres
//
// Excludes port 53/5353 (DNS) — internal resolvers query dozens of hosts per minute
// and would flood this detector. Excludes ports 80/443 — developers deploy to many
// hosts over HTTP, not a lateral movement signal.
async fn detect_lateral_movement(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_src = is_private("src_ip");
    let prv_dst = is_private("dst_ip");
    let q = format!(
        "SELECT src_ip, count(DISTINCT dst_ip) AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 10 MINUTE \
           AND tenant_id = '{t}' \
           AND {prv_src} AND {prv_dst} \
           AND src_ip != '' \
           AND event_type IN ('conn', 'flow') \
           AND dst_port IN (22, 135, 139, 445, 3389, 5985, 5986, 1433, 3306, 5432) \
         GROUP BY src_ip \
         HAVING cnt > 3"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "lateral", tenant, &r.src_ip, SUP_LATERAL).await { continue; }
        tracing::info!("multiflow[lateral] {}/{}: {} internal targets",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("lateral", tenant, &r.src_ip),
            &r.src_ip, "", 80.0,
            vec!["lateral-movement".into(), "t:lateral-movement".into()], &sid).await;
    }
}

// DNS beaconing: >150 DNS queries for the same domain in 30 min, grouped by queried domain.
// Trusted domains are loaded per-run from ndr.trusted_domains (global shared + tenant-specific).
async fn detect_dns_beaconing(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);

    // Load trusted domains: global (tenant_id='') + this tenant's own additions
    let trusted_q = format!(
        "SELECT domain FROM ndr.trusted_domains FINAL \
         WHERE category IN ('dns_beacon', 'both') \
           AND (tenant_id = '' OR tenant_id = '{t}')"
    );
    let trusted: std::collections::HashSet<String> = ch.client.query(&trusted_q)
        .fetch_all::<DomainRow>().await
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.domain.to_lowercase())
        .collect();

    let excl = host_exclusion_clause();
    let q = format!(
        "SELECT src_ip, \
                JSONExtractString(raw, 'query') AS domain, \
                count() AS cnt, \
                dateDiff('second', min(timestamp), max(timestamp)) AS span \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 30 MINUTE \
           AND tenant_id = '{t}' \
           AND event_type = 'dns' \
           AND src_ip != '' \
           AND JSONExtractString(raw, 'query') != '' \
           {excl} \
         GROUP BY src_ip, domain \
         HAVING cnt > 150 AND span > 60"
    );
    let rows: Vec<DnsBeaconRow> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        // Skip globally shared and tenant-specific trusted domains (exact or subdomain match)
        let d = r.domain.to_lowercase();
        if trusted.iter().any(|t| d == *t || d.ends_with(&format!(".{}", t))) { continue; }

        let key = format!("{}_{}", r.src_ip, r.domain);
        if is_suppressed(sup, "dnsbeacon", tenant, &key, SUP_DNS_BEACON).await { continue; }
        tracing::info!("multiflow[dns-beacon] {}/{}: {} queries/{}s for {}",
            tenant, r.src_ip, r.cnt, r.span, r.domain);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("dnsbeacon", tenant, &key),
            &r.src_ip, &r.domain, 65.0,
            vec!["dns-beaconing".into(), "t:command-and-control".into()], &sid).await;
    }
}

// Slow scan: >100 distinct ports AND >50 distinct hosts over 24 hours (AND prevents false positives
// from normal hosts that simply talk to many ports over a day, or DNS resolvers with many targets)
async fn detect_slow_scan(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db   = db_for(tenant);
    let t    = esc(tenant);
    let excl = host_exclusion_clause();
    let q = format!(
        "SELECT src_ip, \
                count(DISTINCT dst_port) AS cnt_a, \
                count(DISTINCT dst_ip)   AS cnt_b \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 24 HOUR \
           AND tenant_id = '{t}' AND src_ip != '' \
           {excl} \
         GROUP BY src_ip \
         HAVING cnt_a > 100 AND cnt_b > 50"
    );
    let rows: Vec<TwoCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "slowscan", tenant, &r.src_ip, SUP_SLOW_SCAN).await { continue; }
        tracing::info!("multiflow[slow-scan] {}/{}: {} ports {} targets/24h",
            tenant, r.src_ip, r.cnt_a, r.cnt_b);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("slowscan", tenant, &r.src_ip),
            &r.src_ip, "", 70.0,
            vec!["slow-scan".into(), "t:discovery".into()], &sid).await;
    }
}

// Internal recon: private src hitting >30 distinct internal hosts in 2 hours
async fn detect_internal_recon(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_src = is_private("src_ip");
    let q = format!(
        "SELECT src_ip, count(DISTINCT dst_ip) AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 2 HOUR \
           AND tenant_id = '{t}' \
           AND {prv_src} AND src_ip != '' \
         GROUP BY src_ip \
         HAVING cnt > 30"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "recon", tenant, &r.src_ip, SUP_RECON).await { continue; }
        tracing::info!("multiflow[internal-recon] {}/{}: {} targets/2h",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("recon", tenant, &r.src_ip),
            &r.src_ip, "", 75.0,
            vec!["internal-recon".into(), "t:discovery".into()], &sid).await;
    }
}

// Data staging + exfil: src with >100MB to internal destinations AND >50MB to
// external destinations in same 30-min window. Uses actual byte volume from
// Zeek orig_bytes (conn.log); events without byte field contribute 0.
async fn detect_data_staging(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_dst = is_private("dst_ip");
    let q = format!(
        "WITH staging AS ( \
           SELECT src_ip, \
                  sum(JSONExtractUInt(raw, 'orig_bytes')) AS internal_bytes \
           FROM {db}.ndr_events \
           WHERE timestamp > now() - INTERVAL 30 MINUTE \
             AND tenant_id = '{t}' AND {prv_dst} AND src_ip != '' \
           GROUP BY src_ip \
           HAVING internal_bytes > 104857600 \
         ) \
         SELECT e.src_ip, \
                toUInt64(sum(JSONExtractUInt(e.raw, 'orig_bytes'))) AS cnt_a, \
                toUInt64(0) AS cnt_b \
         FROM {db}.ndr_events e \
         INNER JOIN staging s ON e.src_ip = s.src_ip \
         WHERE e.timestamp > now() - INTERVAL 30 MINUTE \
           AND e.tenant_id = '{t}' \
           AND NOT {prv_dst} \
           AND e.dst_ip != '' AND e.src_ip != '' \
         GROUP BY e.src_ip \
         HAVING cnt_a > 52428800"
    );
    let rows: Vec<TwoCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "staging", tenant, &r.src_ip, SUP_STAGING).await { continue; }
        tracing::info!("multiflow[data-staging] {}/{}: {} ext events after internal burst",
            tenant, r.src_ip, r.cnt_a);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("staging", tenant, &r.src_ip),
            &r.src_ip, "", 88.0,
            vec!["data-staging".into(), "t:exfiltration".into()], &sid).await;
    }
}

// ── Tier 3a: baseline refresh ─────────────────────────────────────────────────

async fn run_baseline_refresh(ch: &ClickhouseStorage) {
    let tenants = match ch.get_all_tenants().await {
        Ok(t) => t,
        Err(e) => { tracing::warn!("multiflow baseline: get_all_tenants: {}", e); return; }
    };
    for tenant in &tenants {
        refresh_baselines(ch, tenant).await;
    }
}

async fn refresh_baselines(ch: &ClickhouseStorage, tenant: &str) {
    tracing::info!("multiflow: refreshing baselines for {}", tenant);
    let db      = db_for(tenant);
    let t       = esc(tenant);
    // Midnight UTC of yesterday — the window we're summarising
    let midnight = {
        let now = Utc::now();
        let yest = now.date_naive().pred_opt().unwrap_or(now.date_naive());
        yest.and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_utc().timestamp() as u32)
            .unwrap_or(0)
    };

    // 1. DNS query count per IP yesterday
    baseline_compute(ch, tenant, &db, &t, "dns_count", midnight,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' AND event_type = 'dns' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    // 2. Distinct external destinations per IP yesterday
    let prv = is_private("dst_ip");
    baseline_compute(ch, tenant, &db, &t, "ext_dst_count", midnight,
        &format!(
            "SELECT src_ip, toFloat64(count(DISTINCT dst_ip)) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' \
               AND NOT {prv} AND dst_ip != '' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    // 3. Total event count per IP yesterday (activity level)
    baseline_compute(ch, tenant, &db, &t, "event_count", midnight,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    // 4. Known external contacts — one row per (src_ip, ext_dst_ip) seen yesterday
    //    value_s = dst_ip so we can anti-join for new-contact detection
    let prv2 = is_private("dst_ip");
    baseline_compute(ch, tenant, &db, &t, "ext_contact", midnight,
        &format!(
            "SELECT src_ip, toFloat64(1) AS value_f, dst_ip AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' \
               AND NOT {prv2} AND dst_ip != '' AND src_ip != '' \
             GROUP BY src_ip, dst_ip"
        )
    ).await;

    // 5. Off-hours event count per IP yesterday (23:00–05:00 UTC)
    baseline_compute(ch, tenant, &db, &t, "off_hours_count", midnight,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' AND src_ip != '' \
               AND (toHour(timestamp) >= 23 OR toHour(timestamp) < 5) \
             GROUP BY src_ip"
        )
    ).await;

    tracing::info!("multiflow: baseline refresh done for {}", tenant);
}

// Bootstrap baselines for a brand-new tenant using the last 24h of available
// data. Called once (in a spawned task) when run_tier3 finds zero baseline rows
// but events already exist — prevents the first-24h blind spot.
async fn bootstrap_baselines(ch: ClickhouseStorage, tenant: String) {
    tracing::info!("multiflow: bootstrapping baselines for {} (rolling 24h)", tenant);
    let db     = db_for(&tenant);
    let t      = esc(&tenant);
    let window = now_ts();

    baseline_compute(&ch, &tenant, &db, &t, "dns_count", window,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 24 HOUR \
               AND tenant_id = '{t}' AND event_type = 'dns' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    let prv = is_private("dst_ip");
    baseline_compute(&ch, &tenant, &db, &t, "ext_dst_count", window,
        &format!(
            "SELECT src_ip, toFloat64(count(DISTINCT dst_ip)) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 24 HOUR \
               AND tenant_id = '{t}' \
               AND NOT {prv} AND dst_ip != '' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    baseline_compute(&ch, &tenant, &db, &t, "event_count", window,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 24 HOUR \
               AND tenant_id = '{t}' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    let prv2 = is_private("dst_ip");
    baseline_compute(&ch, &tenant, &db, &t, "ext_contact", window,
        &format!(
            "SELECT src_ip, toFloat64(1) AS value_f, dst_ip AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 24 HOUR \
               AND tenant_id = '{t}' \
               AND NOT {prv2} AND dst_ip != '' AND src_ip != '' \
             GROUP BY src_ip, dst_ip"
        )
    ).await;

    baseline_compute(&ch, &tenant, &db, &t, "off_hours_count", window,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 24 HOUR \
               AND tenant_id = '{t}' AND src_ip != '' \
               AND (toHour(timestamp) >= 23 OR toHour(timestamp) < 5) \
             GROUP BY src_ip"
        )
    ).await;

    tracing::info!("multiflow: baseline bootstrap done for {}", tenant);
}

async fn baseline_compute(
    ch:      &ClickhouseStorage,
    tenant:  &str,
    db:      &str,
    _t:      &str,
    metric:  &str,
    window:  u32,
    query:   &str,
) {
    let rows: Vec<BRow> = match ch.client.query(query).fetch_all().await {
        Ok(r)  => r,
        Err(e) => {
            tracing::warn!("multiflow baseline [{}/{}]: {}", tenant, metric, e);
            return;
        }
    };
    if rows.is_empty() { return; }

    let table = format!("{}.ndr_baselines", db);
    let now   = now_ts();
    let mut insert = match ch.client.insert(&table) {
        Ok(i)  => i,
        Err(e) => { tracing::warn!("multiflow baseline insert open [{}/{}]: {}", tenant, metric, e); return; }
    };
    for row in rows {
        let b = NdrBaseline {
            tenant_id:  tenant.to_string(),
            src_ip:     row.src_ip,
            metric:     metric.to_string(),
            value_f:    row.value_f,
            value_s:    row.value_s,
            window_ts:  window,
            updated_at: now,
        };
        if let Err(e) = insert.write(&b).await {
            tracing::warn!("multiflow baseline write [{}/{}]: {}", tenant, metric, e);
        }
    }
    if let Err(e) = insert.end().await {
        tracing::warn!("multiflow baseline end [{}/{}]: {}", tenant, metric, e);
    }
}

// ── Tier 3b: anomaly detection against baselines ──────────────────────────────

async fn run_tier3(ch: &ClickhouseStorage, sup: &SharedSuppressMap) {
    let tenants = match ch.get_all_tenants().await {
        Ok(t) => t,
        Err(e) => { tracing::warn!("multiflow tier3: get_all_tenants: {}", e); return; }
    };
    let sem = Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
    let mut handles = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let ch2  = ch.clone();
        let sup2 = Arc::clone(sup);
        let sem2 = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            let db = db_for(&tenant);
            let t  = esc(&tenant);
            // Skip Tier 3 for tenants with no baseline yet — avoids alert storms on
            // day-zero deployments where every connection looks "new" or "anomalous".
            let baseline_rows: u64 = ch2.client
                .query(&format!(
                    "SELECT count() FROM {db}.ndr_baselines WHERE tenant_id = '{t}'"
                ))
                .fetch_one::<u64>().await.unwrap_or(0);
            if baseline_rows == 0 {
                let has_events: u64 = ch2.client
                    .query(&format!(
                        "SELECT count() FROM {db}.ndr_events \
                         WHERE tenant_id = '{t}' AND timestamp >= now() - INTERVAL 24 HOUR"
                    ))
                    .fetch_one::<u64>().await.unwrap_or(0);
                if has_events > 0 {
                    tracing::info!("multiflow tier3: no baselines for {} — triggering bootstrap", tenant);
                    let ch_cl = ch2.clone();
                    let t_cl  = tenant.clone();
                    tokio::spawn(async move { bootstrap_baselines(ch_cl, t_cl).await; });
                } else {
                    tracing::debug!("multiflow tier3: skipping {} — no events yet", tenant);
                }
                return;
            }
            detect_volume_anomaly(&ch2, &tenant, &sup2).await;
            detect_new_external_contact(&ch2, &tenant, &sup2).await;
            detect_abnormal_hours(&ch2, &tenant, &sup2).await;
        }));
    }
    futures_util::future::join_all(handles).await;
}

// Volume anomaly: last-hour event count far above the host's own 7-day hourly average.
//
// It counts log EVENTS, not bytes, so it says nothing about data leaving the network. It used to fire
// at HIGH (75) as "t:exfiltration" on any 3x jump against an average of just over 10 events an hour,
// with no minimum history: a fresh sensor's first apt upgrade or download produced a HIGH
// "exfiltration" alert with no destination. Now: at least 3 days of baseline, at least 5x the
// average, at least 300 events, and LOW without the exfiltration tag.
pub(crate) fn volume_anomaly_query(db: &str, t: &str) -> String {
    format!(
        "SELECT e.src_ip, \
                toUInt64(count()) AS today_cnt, \
                avg(b.value_f / 24.0) AS avg_hourly \
         FROM {db}.ndr_events e \
         LEFT JOIN ( \
             SELECT src_ip, avg(value_f) AS value_f, count() AS n_windows \
             FROM {db}.ndr_baselines \
             WHERE metric = 'event_count' \
               AND window_ts >= now() - INTERVAL 7 DAY \
               AND tenant_id = '{t}' \
             GROUP BY src_ip \
         ) b ON e.src_ip = b.src_ip \
         WHERE e.timestamp > now() - INTERVAL 1 HOUR \
           AND e.tenant_id = '{t}' AND e.src_ip != '' \
         GROUP BY e.src_ip \
         HAVING today_cnt > 5 * avg_hourly AND avg_hourly > 10 AND today_cnt >= 300 \
                AND max(b.n_windows) >= 3"
    )
}

async fn detect_volume_anomaly(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = volume_anomaly_query(&db, &t);
    let rows: Vec<VolAnomaly> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "volanom", tenant, &r.src_ip, SUP_VOL_ANOMALY).await { continue; }
        tracing::info!("multiflow[vol-anomaly] {}/{}: {} events vs avg {:.1}/hr",
            tenant, r.src_ip, r.today_cnt, r.avg_hourly);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("volanom", tenant, &r.src_ip),
            &r.src_ip, "", 40.0,
            vec!["volume-anomaly".into()], &sid).await;
    }
}

// New external contact: (src_ip, dst_ip) pair seen in last hour
// that has NO entry in the 30-day ext_contact baseline
async fn detect_new_external_contact(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db  = db_for(tenant);
    let t   = esc(tenant);
    let prv = is_private("e.dst_ip");
    let q = format!(
        "SELECT DISTINCT e.src_ip, e.dst_ip \
         FROM {db}.ndr_events e \
         WHERE e.timestamp > now() - INTERVAL 1 HOUR \
           AND e.tenant_id = '{t}' \
           AND NOT {prv} \
           AND e.dst_ip != '' AND e.src_ip != '' \
           AND (e.src_ip, e.dst_ip) NOT IN ( \
               SELECT src_ip, value_s \
               FROM {db}.ndr_baselines \
               WHERE metric = 'ext_contact' \
                 AND tenant_id = '{t}' \
           ) \
         LIMIT 50"
    );
    let rows: Vec<NewContact> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        let key = format!("{}_{}", r.src_ip, r.dst_ip);
        if is_suppressed(sup, "newcontact", tenant, &key, SUP_NEW_CONTACT).await { continue; }
        tracing::info!("multiflow[new-contact] {}/{} → {} (first seen in 30d)",
            tenant, r.src_ip, r.dst_ip);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        // A first-seen destination is context, not evidence: laptops and servers
        // reach new update mirrors, CDNs and SaaS hosts every day. This used to
        // score 65 (MEDIUM) and carry "t:command-and-control", which also made
        // each one count as stage 6 of an attack chain (threat/patterns.rs).
        // Now LOW and untagged as C2; real C2 still raises its own alerts
        // (dns-beaconing, dga, doh-evasion, threat intel) that carry that tag.
        emit(ch, tenant, &make_cid("newcontact", tenant, &key),
            &r.src_ip, &r.dst_ip, 25.0,
            vec!["new-external-contact".into()], &sid).await;
    }
}

// ICMP flood: >500 ICMP events from one source in 5 min
// Covers ping floods, ICMP tunneling probe bursts, and smurf-style amplification attempts.
async fn detect_icmp_flood(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, count() AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 5 MINUTE \
           AND tenant_id = '{t}' \
           AND proto = 'icmp' AND src_ip != '' \
         GROUP BY src_ip \
         HAVING cnt > 500"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "icmpflood", tenant, &r.src_ip, SUP_ICMP_FLOOD).await { continue; }
        tracing::info!("multiflow[icmp-flood] {}/{}: {} ICMP events/5min",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("icmpflood", tenant, &r.src_ip),
            &r.src_ip, "", 70.0,
            vec!["icmp-flood".into(), "t:impact".into()], &sid).await;
    }
}

// ETA: TLS certificate anomaly — self-signed, expired, or untrusted chain
#[derive(Row, Serialize, Deserialize)]
struct TlsCertRow {
    src_ip:            String,
    dst_ip:            String,
    cnt:               u64,
    validation_status: String,
}

async fn detect_tls_cert_anomaly(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, dst_ip, count() AS cnt, \
                any(JSONExtractString(raw, 'validation_status')) AS validation_status \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 10 MINUTE \
           AND tenant_id = '{t}' \
           AND log_source = 'ssl' \
           AND JSONExtractString(raw, 'validation_status') IN (\
               'self signed certificate', \
               'certificate expired', \
               'self signed certificate in certificate chain', \
               'unable to get local issuer certificate') \
           AND src_ip != '' AND dst_ip != '' \
         GROUP BY src_ip, dst_ip"
    );
    let rows: Vec<TlsCertRow> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        let key = format!("{}-{}", r.src_ip, r.dst_ip);
        if is_suppressed(sup, "tlscert", tenant, &key, SUP_TLS_CERT).await { continue; }
        tracing::info!("multiflow[tls-cert] {}/{}->{}: {} ({} events/10min)",
            tenant, r.src_ip, r.dst_ip, r.validation_status, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("tlscert", tenant, &key),
            &r.src_ip, &r.dst_ip, 70.0,
            vec!["tls-cert-anomaly".into(), "encrypted-traffic-analysis".into(),
                 "t:command-and-control".into()], &sid).await;
    }
}

// ETA: Protocol misuse — TLS on port 80 or plain HTTP on port 443
#[derive(Row, Serialize, Deserialize)]
struct ProtoMisuseRow {
    src_ip:   String,
    dst_ip:   String,
    dst_port: u16,
    cnt:      u64,
}

async fn detect_protocol_misuse(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, dst_ip, dst_port, count() AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 10 MINUTE \
           AND tenant_id = '{t}' \
           AND src_ip != '' AND dst_ip != '' \
           AND (\
               (log_source = 'ssl' AND dst_port = 80) \
               OR (log_source = 'http' AND dst_port = 443)\
           ) \
         GROUP BY src_ip, dst_ip, dst_port \
         HAVING cnt > 3"
    );
    let rows: Vec<ProtoMisuseRow> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        let key = format!("{}-{}", r.src_ip, r.dst_port);
        if is_suppressed(sup, "protomisuse", tenant, &key, SUP_PROTO_MISUSE).await { continue; }
        let desc = if r.dst_port == 80 { "TLS-on-port-80" } else { "HTTP-on-port-443" };
        tracing::info!("multiflow[proto-misuse] {}/{}->{}: {} ({} events/10min)",
            tenant, r.src_ip, r.dst_ip, desc, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("protomisuse", tenant, &key),
            &r.src_ip, &r.dst_ip, 65.0,
            vec!["protocol-misuse".into(), "encrypted-traffic-analysis".into(),
                 "t:defense-evasion".into()], &sid).await;
    }
}

// Large-volume direct exfil: >1 GB sent to external destinations in 30 min,
// no internal staging precondition — catches bulk DB dumps over HTTPS etc.
#[derive(Row, Serialize, Deserialize)]
struct LargeExfilRow {
    src_ip: String,
    bytes:  u64,
}

async fn detect_large_volume_exfil(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_dst = is_private("dst_ip");
    let q = format!(
        "SELECT src_ip, toUInt64(sum(JSONExtractUInt(raw, 'orig_bytes'))) AS bytes \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 30 MINUTE \
           AND tenant_id = '{t}' \
           AND NOT {prv_dst} \
           AND src_ip != '' AND dst_ip != '' \
         GROUP BY src_ip \
         HAVING bytes > 1073741824"
    );
    let rows: Vec<LargeExfilRow> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "largeexfil", tenant, &r.src_ip, SUP_LARGE_EXFIL).await { continue; }
        tracing::info!("multiflow[large-exfil] {}/{}: {:.1} GB to external in 30min",
            tenant, r.src_ip, r.bytes as f64 / 1_073_741_824.0);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("largeexfil", tenant, &r.src_ip),
            &r.src_ip, "", 85.0,
            vec!["large-volume-exfil".into(), "t:exfiltration".into()], &sid).await;
    }
}

// Abnormal hours: internal IP active during 23:00–05:00 UTC with events
// exceeding 3× its 7-day off-hours baseline. Only runs during off-hours.
#[derive(Row, Serialize, Deserialize)]
struct OffHoursRow {
    src_ip:      String,
    current_cnt: u64,
    avg_baseline: f64,
}

async fn detect_abnormal_hours(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let hour = chrono::Utc::now().hour();
    // Only fire during off-hours (23:00–04:59 UTC)
    if hour >= 5 && hour < 23 { return; }

    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_src = is_private("e.src_ip");
    let q = format!(
        "SELECT e.src_ip, \
                toUInt64(count()) AS current_cnt, \
                coalesce(avg(b.value_f), 0.0) AS avg_baseline \
         FROM {db}.ndr_events e \
         LEFT JOIN ( \
             SELECT src_ip, avg(value_f) AS value_f \
             FROM {db}.ndr_baselines \
             WHERE metric = 'off_hours_count' \
               AND window_ts >= now() - INTERVAL 7 DAY \
               AND tenant_id = '{t}' \
             GROUP BY src_ip \
         ) b ON e.src_ip = b.src_ip \
         WHERE e.timestamp > now() - INTERVAL 2 HOUR \
           AND e.tenant_id = '{t}' \
           AND {prv_src} AND e.src_ip != '' \
         GROUP BY e.src_ip \
         HAVING current_cnt > 3 * avg_baseline AND avg_baseline > 5"
    );
    let rows: Vec<OffHoursRow> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "abnormalhours", tenant, &r.src_ip, SUP_ABNORMAL_HOURS).await { continue; }
        tracing::info!("multiflow[abnormal-hours] {}/{}: {} events vs avg {:.1} off-hours baseline",
            tenant, r.src_ip, r.current_cnt, r.avg_baseline);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("abnormalhours", tenant, &r.src_ip),
            &r.src_ip, "", 72.0,
            vec!["abnormal-hours".into(), "insider-threat".into(), "t:initial-access".into()], &sid).await;
    }
}

// NXDOMAIN flood: >50 NXDOMAIN responses to one src in 5 min.
// Indicates automated C2 domain generation (DGA) or failed fast-flux resolution.
async fn detect_nxdomain_flood(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, count() AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 5 MINUTE \
           AND tenant_id = '{t}' \
           AND event_type = 'dns' AND src_ip != '' \
           AND JSONExtractString(raw, 'rcode_name') = 'NXDOMAIN' \
         GROUP BY src_ip \
         HAVING cnt > 50"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "nxdomain", tenant, &r.src_ip, SUP_NXDOMAIN).await { continue; }
        tracing::info!("multiflow[nxdomain-flood] {}/{}: {} NXDOMAIN/5min",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("nxdomain", tenant, &r.src_ip),
            &r.src_ip, "", 72.0,
            vec!["nxdomain-flood".into(), "dga".into(), "t:command-and-control".into()], &sid).await;
    }
}

// DNS tunneling: >20 DNS queries with average query length >50 chars in 10 min.
// Long encoded subdomain labels (base64/hex) are the hallmark of DNS tunnel clients
// (iodine, dnscat2, etc.). Combined threshold avoids false-positives from CDN names.
#[derive(Row, Serialize, Deserialize)]
struct DnsTunnelRow {
    src_ip:   String,
    cnt:      u64,
    avg_qlen: f64,
}

async fn detect_dns_tunneling(ch: &ClickhouseStorage, tenant: &str, sup: &SharedSuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, \
                count() AS cnt, \
                avg(length(JSONExtractString(raw, 'query'))) AS avg_qlen \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 10 MINUTE \
           AND tenant_id = '{t}' \
           AND event_type = 'dns' AND src_ip != '' \
           AND length(JSONExtractString(raw, 'query')) > 40 \
         GROUP BY src_ip \
         HAVING cnt > 20 AND avg_qlen > 50"
    );
    let rows: Vec<DnsTunnelRow> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "dnstunnel", tenant, &r.src_ip, SUP_DNS_TUNNEL).await { continue; }
        tracing::info!("multiflow[dns-tunnel] {}/{}: {} queries avg {:.0} chars/10min",
            tenant, r.src_ip, r.cnt, r.avg_qlen);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("dnstunnel", tenant, &r.src_ip),
            &r.src_ip, "", 80.0,
            vec!["dns-tunneling".into(), "t:exfiltration".into(), "t:command-and-control".into()], &sid).await;
    }
}


#[cfg(test)]
mod volume_tests {
    use super::*;

    // Against a real ClickHouse (a throwaway database, dropped at the end):
    //   cargo test -p ndr-engine volume_anomaly -- --ignored
    #[tokio::test]
    #[ignore]
    async fn only_a_real_spike_against_a_mature_baseline_is_reported() {
        let ch = ClickhouseStorage::new();
        let db = "ndr_zz_voltest";
        let x = |q: String| { let c = ch.client.clone(); async move { c.query(&q).execute().await.unwrap() } };
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
        x(format!("CREATE DATABASE {db}")).await;
        x(format!("CREATE TABLE {db}.ndr_events (tenant_id String, src_ip String, timestamp DateTime) ENGINE = MergeTree ORDER BY timestamp")).await;
        x(format!("CREATE TABLE {db}.ndr_baselines (tenant_id String, src_ip String, metric String, window_ts DateTime, value_f Float64, value_s String) ENGINE = MergeTree ORDER BY window_ts")).await;

        // baseline: value_f is a DAILY count (the query divides by 24): 480/day = 20 events an hour
        let baseline = |ip: &'static str, days: u32| { let x = &x; async move {
            for d in 1..=days { x(format!("INSERT INTO {db}.ndr_baselines VALUES ('t','{ip}','event_count', now() - INTERVAL {d} DAY, 480, '')")).await; }
        } };
        let events = |ip: &'static str, n: u32| { let x = &x; async move {
            x(format!("INSERT INTO {db}.ndr_events SELECT 't', '{ip}', now() - number FROM numbers({n})")).await;
        } };
        // 10.0.0.1: mature baseline, 2000 events this hour (100x)                -> reported
        baseline("10.0.0.1", 5).await; events("10.0.0.1", 2000).await;
        // 10.0.0.2: brand-new host, 1 day of baseline, same 2000 events          -> NOT reported (the bug)
        baseline("10.0.0.2", 1).await; events("10.0.0.2", 2000).await;
        // 10.0.0.3: mature baseline but only 3.5x (70 events)                    -> NOT reported
        baseline("10.0.0.3", 5).await; events("10.0.0.3", 70).await;
        // 10.0.0.4: mature baseline, 6x but only 120 events (below the floor)    -> NOT reported
        baseline("10.0.0.4", 5).await; events("10.0.0.4", 120).await;

        let rows: Vec<(String, u64, f64)> = ch.client.query(&volume_anomaly_query(db, "t")).fetch_all().await.unwrap();
        let ips: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(ips, vec!["10.0.0.1"], "only the mature-baseline 100x spike: {rows:?}");
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
    }
}
