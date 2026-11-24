use tracing::info;

use crate::storage::clickhouse::tenant_db_pub;

// Validate values before interpolating into SQL IN clauses.
// These values come from Zeek logs (which parse real packets) but an attacker
// could craft logs with unexpected strings, so we validate before injection.

fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn is_valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

fn is_valid_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64 | 128)
        && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn sql_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[derive(Debug, Clone)]
pub struct IocMatch {
    pub ip:                  String,
    #[allow(dead_code)]
    pub ioc_type:            String,
    pub source:              String,
    pub attack_type:         String,
    #[allow(dead_code)]
    pub severity:            String,
    pub description:         String,
    pub direction:           String,
}

/// Cross-reference IPs seen in tenant traffic against ndr.threat_intel.
/// Returns matched IPs with full threat context, excluding trusted cloud IPs.
pub async fn match_iocs(
    ch:        &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    trusted:   &super::cloud_trust::TrustedRanges,
) -> Vec<IocMatch> {
    let db = tenant_db_pub(tenant_id);

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct TrafficIp { ip: String, direction: String }

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct IntelIp {
        ioc_value:   String,
        source:      String,
        attack_type: String,
        severity:    String,
        description: String,
    }

    // 1. Collect unique IPs from last 6h of tenant traffic
    let traffic_q = format!(
        "SELECT src_ip as ip, 'src' as direction FROM {db}.ndr_events \
         WHERE timestamp >= now() - INTERVAL 6 HOUR AND src_ip != '' AND src_ip != '-' \
         UNION ALL \
         SELECT dst_ip as ip, 'dst' as direction FROM {db}.ndr_events \
         WHERE timestamp >= now() - INTERVAL 6 HOUR AND dst_ip != '' AND dst_ip != '-'",
        db = db
    );

    let traffic_ips = ch.client.query(&traffic_q)
        .fetch_all::<TrafficIp>().await.unwrap_or_default();

    if traffic_ips.is_empty() { return vec![]; }

    // 2. Build IN clause of unique IPs — validate each to prevent injection
    let unique_ips: std::collections::HashSet<String> = traffic_ips.iter()
        .filter(|r| is_valid_ip(&r.ip))
        .map(|r| sql_quote(&r.ip))
        .collect();
    let ip_list = unique_ips.into_iter().collect::<Vec<_>>().join(",");

    // 3. Find which of those IPs appear in threat intel
    let intel_q = format!(
        "SELECT ioc_value, source, attack_type, severity, description \
         FROM ndr.threat_intel \
         WHERE ioc_type = 'ip' AND ioc_value IN ({}) \
         AND collected_at >= now() - INTERVAL 7 DAY \
         GROUP BY ioc_value, source, attack_type, severity, description",
        ip_list
    );

    let intel_rows = ch.client.query(&intel_q)
        .fetch_all::<IntelIp>().await.unwrap_or_default();

    // 4. Build a lookup: ip → direction from traffic
    let direction_map: std::collections::HashMap<String, String> =
        traffic_ips.into_iter().map(|r| (r.ip, r.direction)).collect();

    // 5. Merge IP matches — skip IPs in trusted cloud
    let mut matches: Vec<IocMatch> = intel_rows.into_iter()
        .filter(|r| !trusted.is_trusted_ip(&r.ioc_value))
        .map(|r| {
            let dir = direction_map.get(&r.ioc_value).cloned().unwrap_or_else(|| "dst".into());
            IocMatch {
                ip:          r.ioc_value,
                ioc_type:    "ip".into(),
                source:      r.source,
                attack_type: r.attack_type,
                severity:    r.severity,
                description: r.description,
                direction:   dir,
            }
        }).collect();

    info!("IOC match: {} malicious IPs found in tenant {} traffic", matches.len(), tenant_id);

    // 6. Domain matching — DNS query names and TLS SNI vs threat_intel
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct DomainRow { domain: String }

    let dns_domains: Vec<DomainRow> = ch.client
        .query(&format!(
            "SELECT DISTINCT lower(JSONExtractString(raw, 'query')) AS domain \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 6 HOUR \
               AND event_type = 'dns' AND domain != '' AND domain != '-'"
        ))
        .fetch_all().await.unwrap_or_default();

    let sni_domains: Vec<DomainRow> = ch.client
        .query(&format!(
            "SELECT DISTINCT lower(JSONExtractString(raw, 'server_name')) AS domain \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 6 HOUR \
               AND log_source = 'ssl' AND domain != '' AND domain != '-'"
        ))
        .fetch_all().await.unwrap_or_default();

    let unique_domains: std::collections::HashSet<String> = dns_domains.into_iter()
        .chain(sni_domains)
        .map(|r| r.domain)
        .filter(|d| is_valid_domain(d))
        .collect();

    if !unique_domains.is_empty() {
        let domain_list = unique_domains.iter()
            .map(|d| sql_quote(d))
            .collect::<Vec<_>>().join(",");
        let domain_intel: Vec<IntelIp> = ch.client
            .query(&format!(
                "SELECT ioc_value, source, attack_type, severity, description \
                 FROM ndr.threat_intel \
                 WHERE ioc_type IN ('domain','hostname') \
                   AND ioc_value IN ({domain_list}) \
                   AND collected_at >= now() - INTERVAL 7 DAY \
                 GROUP BY ioc_value, source, attack_type, severity, description"
            ))
            .fetch_all().await.unwrap_or_default();
        let domain_hit_count = domain_intel.len();
        for r in domain_intel {
            matches.push(IocMatch {
                ip:          r.ioc_value,
                ioc_type:    "domain".into(),
                source:      r.source,
                attack_type: r.attack_type,
                severity:    r.severity,
                description: r.description,
                direction:   "dst".into(),
            });
        }
        if domain_hit_count > 0 {
            info!("IOC match: {} domain IOCs matched for tenant {}", domain_hit_count, tenant_id);
        }
    }

    // 7. Hash matching — file SHA256/MD5 vs threat_intel
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HashRow { hash: String }

    let sha256_hashes: Vec<HashRow> = ch.client
        .query(&format!(
            "SELECT DISTINCT lower(JSONExtractString(raw, 'sha256')) AS hash \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 6 HOUR \
               AND length(JSONExtractString(raw, 'sha256')) = 64 AND hash != ''"
        ))
        .fetch_all().await.unwrap_or_default();

    let md5_hashes: Vec<HashRow> = ch.client
        .query(&format!(
            "SELECT DISTINCT lower(JSONExtractString(raw, 'md5')) AS hash \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 6 HOUR \
               AND length(JSONExtractString(raw, 'md5')) = 32 AND hash != ''"
        ))
        .fetch_all().await.unwrap_or_default();

    let unique_hashes: std::collections::HashSet<String> = sha256_hashes.into_iter()
        .chain(md5_hashes)
        .map(|r| r.hash)
        .filter(|h| is_valid_hash(h))
        .collect();

    if !unique_hashes.is_empty() {
        let hash_list = unique_hashes.iter()
            .map(|h| sql_quote(h))
            .collect::<Vec<_>>().join(",");
        let hash_intel: Vec<IntelIp> = ch.client
            .query(&format!(
                "SELECT ioc_value, source, attack_type, severity, description \
                 FROM ndr.threat_intel \
                 WHERE ioc_type IN ('hash','md5','sha256','sha1') \
                   AND ioc_value IN ({hash_list}) \
                   AND collected_at >= now() - INTERVAL 7 DAY \
                 GROUP BY ioc_value, source, attack_type, severity, description"
            ))
            .fetch_all().await.unwrap_or_default();
        let hash_hit_count = hash_intel.len();
        for r in hash_intel {
            matches.push(IocMatch {
                ip:          r.ioc_value,
                ioc_type:    "hash".into(),
                source:      r.source,
                attack_type: r.attack_type,
                severity:    r.severity,
                description: r.description,
                direction:   "dst".into(),
            });
        }
        if hash_hit_count > 0 {
            info!("IOC match: {} hash IOCs matched for tenant {}", hash_hit_count, tenant_id);
        }
    }

    matches
}

#[derive(clickhouse::Row, serde::Deserialize, Debug, Default)]
struct ExposureRow {
    rdp_exposed:          u64,
    smb_exposed:          u64,
    ssh_exposed:          u64,
    http_exposed:         u64,
    dns_anomalies:        u64,
    port_scans:           u64,
    failed_logins:        u64,
    lateral_movement:     u64,
    c2_beacons:           u64,
    data_exfil_bytes:     u64,
    brute_force_attempts: u64,
    unique_src_ips:       u64,
}

pub async fn build_exposure(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
) -> anyhow::Result<ExposureProfile> {
    let db = tenant_db_pub(tenant_id);

    let q = format!(
        "SELECT \
           countIf(lower(event_type) IN ('rdp','ms-rdp') OR src_port = 3389)                                                as rdp_exposed, \
           countIf(lower(event_type) = 'smb' OR src_port IN (445, 139))                                                    as smb_exposed, \
           countIf(lower(event_type) = 'ssh' OR src_port = 22)                                                             as ssh_exposed, \
           countIf(lower(event_type) IN ('http','http2') OR dst_port IN (80, 8080))                                        as http_exposed, \
           countIf(lower(event_type) = 'dns' AND upper(JSONExtractString(raw,'qtype')) IN ('TXT','ANY','16','255'))         as dns_anomalies, \
           countIf(lower(event_type) = 'scan' OR lower(source) LIKE '%scan%' OR lower(JSONExtractString(raw,'notice')) LIKE '%scan%') as port_scans, \
           countIf(lower(JSONExtractString(raw,'auth_success')) = 'false' OR lower(JSONExtractString(raw,'success')) = 'false') as failed_logins, \
           countIf(lower(event_type) = 'lateral_movement' OR lower(JSONExtractString(raw,'notice')) LIKE '%lateral%')      as lateral_movement, \
           countIf(lower(JSONExtractString(raw,'notice')) LIKE '%c2%' OR lower(JSONExtractString(raw,'category')) LIKE '%c2%' OR lower(JSONExtractString(raw,'category')) LIKE '%beacon%') as c2_beacons, \
           toUInt64(sum(JSONExtractUInt(raw,'orig_bytes')))                                                                 as data_exfil_bytes, \
           countIf(lower(JSONExtractString(raw,'notice')) LIKE '%brute%' OR lower(JSONExtractString(raw,'service')) LIKE '%brute%') as brute_force_attempts, \
           uniqExact(src_ip)                                                                                                as unique_src_ips \
         FROM {db}.ndr_events \
         WHERE tenant_id = '{tid}' \
           AND timestamp >= now() - INTERVAL 6 HOUR",
        db  = db,
        tid = tenant_id,
    );

    let rows = ch.client.query(&q).fetch_all::<ExposureRow>().await?;

    let profile = if let Some(r) = rows.into_iter().next() {
        ExposureProfile {
            tenant_id:            tenant_id.to_string(),
            rdp_exposed:          r.rdp_exposed,
            smb_exposed:          r.smb_exposed,
            ssh_exposed:          r.ssh_exposed,
            http_exposed:         r.http_exposed,
            dns_anomalies:        r.dns_anomalies,
            port_scans:           r.port_scans,
            failed_logins:        r.failed_logins,
            lateral_movement:     r.lateral_movement,
            c2_beacons:           r.c2_beacons,
            data_exfil_bytes:     r.data_exfil_bytes,
            brute_force_attempts: r.brute_force_attempts,
            unique_src_ips:       r.unique_src_ips,
        }
    } else {
        ExposureProfile { tenant_id: tenant_id.to_string(), ..Default::default() }
    };

    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);

    // One snapshot per tenant per day is sufficient — skip if already recorded today.
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CountRow { count: u64 }
    let already_today: u64 = ch.client
        .query(&format!(
            "SELECT count() as count FROM {db}.exposure_profile \
             WHERE tenant_id = '{tid}' AND toDate(snapshot_at) = today()",
            db = db, tid = profile.tenant_id
        ))
        .fetch_all::<CountRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .next()
        .map(|r| r.count)
        .unwrap_or(0);

    if already_today == 0 {
        let insert = format!(
            "INSERT INTO {db}.exposure_profile \
             (tenant_id, rdp_exposed, smb_exposed, ssh_exposed, http_exposed, \
              dns_anomalies, port_scans, failed_logins, lateral_movement, c2_beacons, \
              data_exfil_bytes, brute_force_attempts, unique_src_ips) \
             VALUES ('{tid}',{rdp},{smb},{ssh},{http},{dns},{ps},{fl},{lm},{c2},{de},{bf},{us})",
            db = db,
            tid = profile.tenant_id,
            rdp = profile.rdp_exposed as u8, smb = profile.smb_exposed as u8,
            ssh = profile.ssh_exposed as u8, http = profile.http_exposed as u8,
            dns = profile.dns_anomalies, ps = profile.port_scans,
            fl = profile.failed_logins, lm = profile.lateral_movement,
            c2 = profile.c2_beacons, de = profile.data_exfil_bytes,
            bf = profile.brute_force_attempts, us = profile.unique_src_ips,
        );
        ch.client.query(&insert).execute().await?;
        tracing::debug!("Exposure profile saved for tenant {}", tenant_id);
    } else {
        tracing::debug!("Exposure profile already recorded today for tenant {} — skipping insert", tenant_id);
    }
    Ok(profile)
}

#[derive(Debug, Default, Clone)]
pub struct ExposureProfile {
    pub tenant_id:           String,
    pub rdp_exposed:         u64,
    pub smb_exposed:         u64,
    pub ssh_exposed:         u64,
    pub http_exposed:        u64,
    pub dns_anomalies:       u64,
    pub port_scans:          u64,
    pub failed_logins:       u64,
    pub lateral_movement:    u64,
    pub c2_beacons:          u64,
    pub data_exfil_bytes:    u64,
    pub brute_force_attempts:u64,
    pub unique_src_ips:      u64,
}

impl ExposureProfile {
    pub fn exposure_score(&self) -> f32 {
        let mut score: f32 = 0.0;
        score += (self.rdp_exposed          > 0) as u8 as f32 * 15.0;
        score += (self.smb_exposed          > 0) as u8 as f32 * 15.0;
        score += (self.c2_beacons           > 0) as u8 as f32 * 25.0;
        score += (self.lateral_movement     > 0) as u8 as f32 * 20.0;
        score += (self.brute_force_attempts > 5) as u8 as f32 * 10.0;
        score += (self.port_scans           > 10) as u8 as f32 * 8.0;
        score += (self.data_exfil_bytes > 100_000_000) as u8 as f32 * 20.0;
        score += (self.failed_logins        > 20) as u8 as f32 * 5.0;
        score.min(100.0)
    }

    pub fn as_json_context(&self) -> String {
        serde_json::json!({
            "rdp_exposed":          self.rdp_exposed > 0,
            "smb_exposed":          self.smb_exposed > 0,
            "ssh_exposed":          self.ssh_exposed > 0,
            "http_exposed":         self.http_exposed > 0,
            "dns_anomalies":        self.dns_anomalies,
            "port_scans":           self.port_scans,
            "failed_logins":        self.failed_logins,
            "lateral_movement":     self.lateral_movement,
            "c2_beacons":           self.c2_beacons,
            "data_exfil_bytes":     self.data_exfil_bytes,
            "brute_force_attempts": self.brute_force_attempts,
            "unique_src_ips":       self.unique_src_ips,
            "exposure_score":       self.exposure_score(),
        }).to_string()
    }
}
