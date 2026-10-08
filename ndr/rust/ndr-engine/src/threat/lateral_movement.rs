/// Lateral Movement Detector — builds attack stories from alert chains.
///
/// When a compromised host (dst of alert A) turns attacker (src of alert B)
/// within 60 minutes, the two alerts form a lateral movement chain.
/// This detector groups such chains into incident records so analysts can
/// see the full attack story in one view.

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

use crate::storage::ClickhouseStorage;

const SCAN_INTERVAL_SECS: u64 = 300; // every 5 minutes
const CHAIN_WINDOW_MINS:  u32  = 60;  // max gap between hops

pub fn spawn_lateral_movement_detector(ch: Arc<ClickhouseStorage>, is_leader: Arc<std::sync::atomic::AtomicBool>) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        loop {
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                if let Err(e) = run_scan(&ch).await {
                    warn!("lateral_movement: scan error — {}", e);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(SCAN_INTERVAL_SECS)).await;
        }
    });
}

async fn run_scan(ch: &Arc<ClickhouseStorage>) -> anyhow::Result<()> {
    let tenants = ch.get_all_tenants().await
        .unwrap_or_else(|_| vec!["default".to_string()]);
    // Bounded concurrency (TENANT_SCAN_CONCURRENCY) instead of one tenant at
    // a time - at real tenant counts, sequential scanning can push this well
    // past its own 5-min cadence (SCAN_INTERVAL_SECS).
    let sem = Arc::new(tokio::sync::Semaphore::new(super::tenant_scan_concurrency()));
    let mut handles = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let ch2  = Arc::clone(ch);
        let sem2 = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            if let Err(e) = scan_tenant(&ch2, &tenant).await {
                warn!("lateral_movement: tenant {} failed — {}", tenant, e);
            }
        }));
    }
    futures_util::future::join_all(handles).await;
    Ok(())
}

#[derive(clickhouse::Row, serde::Deserialize, Clone)]
struct AlertEdge {
    community_id: String,
    src_ip:       String,
    dst_ip:       String,
    severity:     String,
    rule_name:    String,
    ts:           u32,
}

async fn scan_tenant(ch: &Arc<ClickhouseStorage>, tenant_id: &str) -> anyhow::Result<()> {
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);

    // Fetch recent high/medium alerts as edges
    let edges: Vec<AlertEdge> = ch.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip, severity, \
                arrayElement(sigma_hits, 1) as rule_name, \
                toUnixTimestamp(timestamp) as ts \
         FROM {db}.ndr_hits FINAL \
         WHERE timestamp >= now() - INTERVAL 2 HOUR \
           AND src_ip != '' AND dst_ip != '' \
           AND src_ip != dst_ip \
           AND severity IN ('HIGH', 'MEDIUM', 'CRITICAL') \
         ORDER BY timestamp ASC \
         LIMIT 2000",
    )).fetch_all::<AlertEdge>().await?;

    if edges.is_empty() {
        return Ok(());
    }

    // Build adjacency: dst_ip → list of outgoing edges from that ip
    let mut out_edges: HashMap<String, Vec<AlertEdge>> = HashMap::new();
    for edge in &edges {
        out_edges.entry(edge.src_ip.clone()).or_default().push(edge.clone());
    }

    // Find chains: start from each edge, follow dst → src links
    let mut chains: Vec<Vec<AlertEdge>> = Vec::new();
    let mut visited_cids: HashSet<String> = HashSet::new();

    for start in &edges {
        if visited_cids.contains(&start.community_id) { continue; }

        let mut chain = vec![start.clone()];
        let mut current = start.clone();

        loop {
            // Look for an edge that starts at current.dst_ip within CHAIN_WINDOW_MINS
            let next = out_edges
                .get(&current.dst_ip)
                .and_then(|candidates| {
                    candidates.iter().find(|e| {
                        e.ts > current.ts
                            && e.ts <= current.ts + (CHAIN_WINDOW_MINS as u32 * 60)
                            && !visited_cids.contains(&e.community_id)
                            // avoid circular chains
                            && !chain.iter().any(|c| c.src_ip == e.dst_ip)
                    })
                })
                .cloned();

            match next {
                Some(n) => {
                    visited_cids.insert(n.community_id.clone());
                    chain.push(n.clone());
                    current = n;
                }
                None => break,
            }
        }

        // Only save chains with 2+ hops (true lateral movement)
        if chain.len() >= 2 {
            for e in &chain { visited_cids.insert(e.community_id.clone()); }
            chains.push(chain);
        }
    }

    if chains.is_empty() { return Ok(()); }

    info!("lateral_movement: {} chains found for tenant {}", chains.len(), tenant_id);

    for chain in chains {
        let alert_ids: Vec<String> = chain.iter().map(|e| e.community_id.clone()).collect();

        // Skip if an incident already covers these alerts
        if ch.incident_exists_for_alerts(tenant_id, &alert_ids).await { continue; }

        // Collect all unique IPs in order of appearance
        let mut seen_ips: HashSet<String> = HashSet::new();
        let mut affected_ips: Vec<String> = Vec::new();
        for e in &chain {
            if seen_ips.insert(e.src_ip.clone()) { affected_ips.push(e.src_ip.clone()); }
            if seen_ips.insert(e.dst_ip.clone()) { affected_ips.push(e.dst_ip.clone()); }
        }

        // Build title: "Lateral Movement: .71 → .72 → .73"
        let ip_trail = affected_ips.join(" → ");
        let title = format!("Lateral Movement: {}", ip_trail);

        let severity = chain.iter()
            .map(|e| e.severity.as_str())
            .max_by_key(|s| match *s { "CRITICAL" => 3, "HIGH" => 2, _ => 1 })
            .unwrap_or("MEDIUM")
            .to_string();

        // Build attack chain JSON
        let chain_json = serde_json::to_string(
            &chain.iter().map(|e| serde_json::json!({
                "src_ip":       e.src_ip,
                "dst_ip":       e.dst_ip,
                "timestamp":    e.ts,
                "severity":     e.severity,
                "rule_name":    e.rule_name,
                "community_id": e.community_id,
            })).collect::<Vec<_>>()
        ).unwrap_or_else(|_| "[]".to_string());

        let first_seen = chain.first().map(|e| e.ts as i64).unwrap_or(0);
        let last_seen  = chain.last().map(|e| e.ts as i64).unwrap_or(0);
        let id = uuid::Uuid::new_v4().to_string();

        if let Err(e) = ch.save_incident(
            tenant_id, &id, &title, &severity,
            &affected_ips, &chain_json, &alert_ids,
            first_seen, last_seen,
        ).await {
            warn!("lateral_movement: failed to save incident — {}", e);
        } else {
            info!("lateral_movement: saved incident '{}' ({} hops) for tenant {}", title, chain.len(), tenant_id);
        }
    }

    Ok(())
}
