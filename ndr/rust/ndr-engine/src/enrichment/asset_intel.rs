// Asset Intelligence — background enrichment task
// Runs every 15 min per tenant: detects device role, criticality score,
// open ports, subnet role, and JA3-based OS fingerprint.

use std::sync::Arc;
use tokio::time::Duration;
use tracing::{info, warn};

use crate::storage::ClickhouseStorage;

pub fn spawn_asset_intel(ch: Arc<ClickhouseStorage>, is_leader: Arc<std::sync::atomic::AtomicBool>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(180)).await;
        loop {
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                info!("asset_intel: starting enrichment cycle");
                let tenants = ch.get_all_tenants().await.unwrap_or_else(|_| vec!["default".to_string()]);
                // Bounded concurrency (TENANT_SCAN_CONCURRENCY) instead of one
                // tenant at a time - at real tenant counts, sequential asset
                // enrichment can push this well past its own 15-min cadence.
                let sem = Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
                let mut handles = Vec::with_capacity(tenants.len());
                for tenant_id in tenants {
                    let ch2  = Arc::clone(&ch);
                    let sem2 = Arc::clone(&sem);
                    handles.push(tokio::spawn(async move {
                        let _permit = sem2.acquire().await;
                        if let Err(e) = enrich_tenant_assets(&ch2, &tenant_id).await {
                            warn!("asset_intel: failed for tenant {} — {}", tenant_id, e);
                        }
                    }));
                }
                futures_util::future::join_all(handles).await;
                info!("asset_intel: cycle complete — next run in 15 min");
            }
            tokio::time::sleep(Duration::from_secs(900)).await;
        }
    });
}


async fn enrich_tenant_assets(
    ch:        &Arc<ClickhouseStorage>,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let assets = ch.get_assets_by_tenant(tenant_id).await?;
    if assets.is_empty() { return Ok(()); }

    let subnet_roles = ch.get_subnet_roles(tenant_id).await;

    for asset in &assets {
        if asset.ip.is_empty() || asset.ip == "0.0.0.0" { continue; }

        let profile = match ch.get_asset_traffic_profile(tenant_id, &asset.ip, 24).await {
            Ok(p) => p,
            Err(e) => {
                warn!("asset_intel: profile query failed for {} — {}", asset.ip, e);
                continue;
            }
        };

        let role        = detect_role(&profile, &asset.device_type);
        let criticality = compute_criticality(&profile, asset.threat_flagged);
        let ja3_os      = ch.get_ja3_os_for_ip(tenant_id, &asset.ip).await;
        let subnet_role = find_subnet_role(&asset.ip, &subnet_roles);
        let ports_json  = serde_json::to_string(&profile.open_ports).unwrap_or_else(|_| "[]".into());

        if let Err(e) = ch.update_asset_intel(
            tenant_id, &asset.ip, &role, criticality, &ports_json, &subnet_role, &ja3_os,
        ).await {
            warn!("asset_intel: update failed for {} — {}", asset.ip, e);
        }
    }
    Ok(())
}

fn detect_role(profile: &AssetTrafficProfile, device_type: &str) -> String {
    if device_type == "router" || device_type == "gateway" || device_type == "firewall" {
        return "Gateway / Router".to_string();
    }

    let ports = &profile.open_ports;
    let inbound = profile.inbound_conn_count;
    let is_server = inbound > 5 || profile.unique_src_ips > 3;

    let has_dns  = ports.iter().any(|&p| p == 53);
    let has_mail = ports.iter().any(|&p| matches!(p, 25|110|143|587|993|995));
    let has_db   = ports.iter().any(|&p| matches!(p, 3306|5432|1433|27017|6379|5984));
    let has_smb  = ports.iter().any(|&p| matches!(p, 445|139));
    let has_web  = ports.iter().any(|&p| matches!(p, 80|443|8080|8443|8000|3000));
    let has_rdp  = ports.iter().any(|&p| p == 3389);
    let has_ssh  = ports.iter().any(|&p| p == 22);
    let has_ldap = ports.iter().any(|&p| matches!(p, 389|636|3268|3269));
    let has_ntp  = ports.iter().any(|&p| p == 123);
    let has_dhcp = ports.iter().any(|&p| matches!(p, 67|68));

    if has_dhcp               { return "DHCP Server".to_string(); }
    if has_ldap  && is_server { return "Directory Server (LDAP/AD)".to_string(); }
    if has_dns   && is_server { return "DNS Server".to_string(); }
    if has_mail               { return "Mail Server".to_string(); }
    if has_db    && is_server { return "Database Server".to_string(); }
    if has_smb   && is_server { return "File Server".to_string(); }
    if has_web   && is_server { return "Web Server".to_string(); }
    if has_rdp                { return "Remote Desktop Host".to_string(); }
    if has_ssh   && is_server { return "SSH Server".to_string(); }
    if has_ntp                { return "NTP Server".to_string(); }

    if profile.protocol_count <= 2 && profile.total_conn_count < 30 {
        return "IoT / Embedded Device".to_string();
    }

    if profile.total_conn_count > 0 {
        return "Workstation".to_string();
    }

    String::new()
}

fn compute_criticality(profile: &AssetTrafficProfile, threat_flagged: u8) -> u8 {
    let mut score: i32 = 10;

    if profile.inbound_conn_count > 500 { score += 35; }
    else if profile.inbound_conn_count > 100 { score += 25; }
    else if profile.inbound_conn_count > 10  { score += 15; }

    if profile.unique_src_ips > 50  { score += 25; }
    else if profile.unique_src_ips > 10 { score += 15; }
    else if profile.unique_src_ips > 3  { score += 8;  }

    let port_count = profile.open_ports.len() as i32;
    score += (port_count * 4).min(20);

    if profile.total_conn_count > 5000 { score += 10; }

    if threat_flagged != 0 { score += 20; }

    score.clamp(0, 100) as u8
}

fn find_subnet_role(ip: &str, subnet_roles: &[(String, String)]) -> String {
    let ip_num = match ip_to_u32(ip) {
        Some(n) => n,
        None    => return String::new(),
    };
    for (cidr, role) in subnet_roles {
        if cidr_contains(cidr, ip_num) {
            return role.clone();
        }
    }
    String::new()
}

fn ip_to_u32(ip: &str) -> Option<u32> {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 { return None; }
    Some(((parts[0] as u32) << 24) | ((parts[1] as u32) << 16) | ((parts[2] as u32) << 8) | parts[3] as u32)
}

fn cidr_contains(cidr: &str, ip_num: u32) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return false; }
    let prefix: u32 = parts[1].parse().unwrap_or(0);
    let net_num = match ip_to_u32(parts[0]) {
        Some(n) => n,
        None    => return false,
    };
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    (ip_num & mask) == (net_num & mask)
}

// ── Public helpers called from storage layer ─────────────────────────────────

pub struct AssetTrafficProfile {
    pub total_conn_count:   u64,
    pub inbound_conn_count: u64,
    pub unique_src_ips:     u64,
    pub protocol_count:     u64,
    pub open_ports:         Vec<u16>,
}

// JA3 fingerprint → OS label (common client fingerprints)
pub fn ja3_lookup(hash: &str) -> Option<&'static str> {
    match hash {
        "e6573e91e6eb777c0933c5b8f97f10cd" => Some("Windows 10 / Chrome"),
        "f4febc55ea12b31ae17cfb7e614afda8" => Some("Windows 10 / Firefox"),
        "b32309a26951912be7dba376398d2d3f" => Some("macOS / Safari"),
        "a0e9f5d64349fb13191bc781f81f42e1" => Some("iOS / Safari"),
        "17273789fe53e5a891c5a83a0e86ce8e" => Some("Android / Chrome"),
        "3b5074b1b5d032e5620f69f9d4d68c13" => Some("Linux / OpenSSL"),
        "d4e5b18d6b55c71db18b8e4a24d6d5a7" => Some("Windows 11 / Edge"),
        "6734f37431670b3ab4292b8f60f29984" => Some("Java / Gradle"),
        "9e10692f1b7f78228b2d4e424db3a98c" => Some("Python / requests"),
        "a5b4fbbbf7ced2a2e3a8c85f72d14a3e" => Some("Go / net/http"),
        "c4f1aba0b9d7f9e3c1e8b2f6a5d3c7e9" => Some("macOS / Chrome"),
        "2ad958bfcf37e5b3ec68bdbf5a9e7f0a" => Some("Windows / IE 11"),
        "5e034bed8e3c06a1c9e9d50a5fcdbde1" => Some("Linux / Firefox"),
        _ => None,
    }
}
