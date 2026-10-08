use std::sync::Arc;
use tracing::{info, warn};

use crate::ai::provider::{generate, UseCase};
use crate::storage::clickhouse::tenant_db_pub;

pub fn spawn_correlator(ch: Arc<crate::storage::ClickhouseStorage>, is_leader: Arc<std::sync::atomic::AtomicBool>) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(900)).await;
        loop {
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                match ch.get_all_tenants().await {
                    Ok(tenants) => {
                        // Bounded concurrency (TENANT_SCAN_CONCURRENCY) - this
                        // makes an AI call per tenant, so sequential processing
                        // at real tenant counts could take hours for one pass.
                        let sem = Arc::new(tokio::sync::Semaphore::new(super::tenant_scan_concurrency()));
                        let mut handles = Vec::with_capacity(tenants.len());
                        for tenant_id in tenants {
                            let ch2  = Arc::clone(&ch);
                            let sem2 = Arc::clone(&sem);
                            handles.push(tokio::spawn(async move {
                                let _permit = sem2.acquire().await;
                                let ai_enabled = ch2.get_tenant_ai_enabled(&tenant_id).await;
                                if let Err(e) = run_correlation(&ch2, &tenant_id, ai_enabled).await {
                                    warn!("Correlation failed for {}: {}", tenant_id, e);
                                }
                            }));
                        }
                        futures_util::future::join_all(handles).await;
                    }
                    Err(e) => warn!("correlator: failed to get tenants: {}", e),
                }
                info!("Correlation cycle complete — next run in 6 hours");
            }
            tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
        }
    });
}

async fn run_correlation(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    ai_enabled: bool,
) -> anyhow::Result<()> {
    let db = tenant_db_pub(tenant_id);

    // ── 1. Fetch real network IOCs (IPs, domains, hashes) — CVEs excluded ────
    // CVEs have no direct network indicator so they can't be matched against logs.
    // Only IOCs with actual network presence (IP, domain, hash) are correlated.

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct ThreatRow {
        ioc_type:                String,
        ioc_value:               String,
        attack_type:             String,
        severity:                String,
        description:             String,
        #[allow(dead_code)]
        threat_pattern:          String,
    }

    let threat_rows = ch.client
        .query("SELECT ioc_type, ioc_value, attack_type, severity, description, threat_pattern \
                FROM ndr.threat_intel \
                WHERE collected_at >= now() - INTERVAL 24 HOUR \
                  AND ioc_type IN ('ip','ip4','ip6','domain','hostname','url','hash','md5','sha256','sha1') \
                  AND ioc_value != '' \
                ORDER BY collected_at DESC LIMIT 200")
        .fetch_all::<ThreatRow>().await
        .unwrap_or_default();

    if threat_rows.is_empty() {
        info!("correlator: no network IOCs in threat_intel for tenant {} — skipping", tenant_id);
        return Ok(());
    }

    info!("correlator: {} network IOCs to correlate for tenant {}", threat_rows.len(), tenant_id);

    // ── 2. Match each IOC against real log data ───────────────────────────────
    // Probability is derived from ACTUAL log evidence, not AI estimation.

    let mut matched: Vec<MatchedThreat> = vec![];

    for row in &threat_rows {
        let (hit_count, evidence) = match row.ioc_type.as_str() {

            // IP IOC: count how many times this IP appeared in src or dst
            "ip" | "ip4" | "ip6" => {
                let val = esc(&row.ioc_value);
                let cnt: u64 = ch.client
                    .query(&format!(
                        "SELECT count() FROM {db}.ndr_events \
                         WHERE timestamp >= now() - INTERVAL 6 HOUR \
                           AND (src_ip = '{val}' OR dst_ip = '{val}')"
                    ))
                    .fetch_one::<u64>().await.unwrap_or(0);
                let ev = if cnt > 0 {
                    format!("{} log entries with IP {}", cnt, row.ioc_value)
                } else { String::new() };
                (cnt, ev)
            }

            // Domain/hostname IOC: check DNS queries and TLS SNI
            "domain" | "hostname" | "url" => {
                let domain = row.ioc_value.trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .split('/').next().unwrap_or(&row.ioc_value);
                let val = esc(domain);
                let cnt: u64 = ch.client
                    .query(&format!(
                        "SELECT count() FROM {db}.ndr_events \
                         WHERE timestamp >= now() - INTERVAL 6 HOUR \
                           AND (JSONExtractString(raw, 'query') LIKE '%{val}%' \
                             OR JSONExtractString(raw, 'server_name') LIKE '%{val}%' \
                             OR JSONExtractString(raw, 'host') LIKE '%{val}%')"
                    ))
                    .fetch_one::<u64>().await.unwrap_or(0);
                let ev = if cnt > 0 {
                    format!("{} DNS/TLS/HTTP log entries matching domain {}", cnt, domain)
                } else { String::new() };
                (cnt, ev)
            }

            // Hash IOC: check file hashes in Zeek files.log
            "hash" | "md5" | "sha256" | "sha1" => {
                let val = esc(&row.ioc_value);
                let cnt: u64 = ch.client
                    .query(&format!(
                        "SELECT count() FROM {db}.ndr_events \
                         WHERE timestamp >= now() - INTERVAL 6 HOUR \
                           AND (JSONExtractString(raw, 'md5') = '{val}' \
                             OR JSONExtractString(raw, 'sha256') = '{val}' \
                             OR JSONExtractString(raw, 'sha1') = '{val}')"
                    ))
                    .fetch_one::<u64>().await.unwrap_or(0);
                let ev = if cnt > 0 {
                    format!("{} file log entries with hash {}", cnt, row.ioc_value)
                } else { String::new() };
                (cnt, ev)
            }

            _ => (0, String::new()),
        };

        // No log evidence = no match = skip
        if hit_count == 0 { continue; }

        // Probability from actual hit count:
        // 1 hit = 30%, 5 hits = 50%, 20+ hits = 90% (capped)
        let probability = match hit_count {
            1..=2   => 0.30,
            3..=5   => 0.45,
            6..=19  => 0.60,
            20..=49 => 0.75,
            _       => 0.90,
        };

        matched.push(MatchedThreat {
            ioc_type:    row.ioc_type.clone(),
            ioc_value:   row.ioc_value.clone(),
            attack_type: row.attack_type.clone(),
            severity:    row.severity.clone(),
            description: row.description.clone(),
            hit_count,
            evidence,
            probability,
        });
    }

    if matched.is_empty() {
        info!("correlator: no IOC matches found in logs for tenant {}", tenant_id);
        return Ok(());
    }

    info!("correlator: {} IOCs matched in logs for tenant {}", matched.len(), tenant_id);

    // ── 3. Use AI only to generate human-readable briefing for real matches ───
    // Probability is already calculated from logs — AI just explains the match.

    for m in &matched {
        let system = format!(
            "You are ARIA, an NDR threat analyst for tenant {}. \
             A malicious {} ({}) was found in network logs {} times. \
             Write a 2-sentence briefing: what this threat does and what the network team should do. \
             Be specific and concise. No hallucinations — only describe what is confirmed.",
            tenant_id, m.ioc_type, m.ioc_value, m.hit_count
        );

        let prompt = format!(
            "Confirmed log evidence: {}\n\
             Threat description: {}\n\
             Attack type: {} | Severity: {}\n\n\
             Write briefing (2 sentences max): what this IOC does + recommended action.",
            m.evidence, m.description, m.attack_type, m.severity
        );

        let briefing = if ai_enabled {
            let raw = generate(ch, UseCase::ThreatPrediction, &system, &prompt).await;
            if raw.is_empty() {
                format!(
                    "Confirmed: {} {} appeared {} time(s) in network logs in the last 6 hours. \
                     Investigate and block this {} immediately.",
                    m.ioc_type, m.ioc_value, m.hit_count, m.ioc_type
                )
            } else {
                raw.chars().take(500).collect::<String>()
            }
        } else {
            format!(
                "Confirmed: {} {} appeared {} time(s) in network logs in the last 6 hours. \
                 Investigate and block this {} immediately.",
                m.ioc_type, m.ioc_value, m.hit_count, m.ioc_type
            )
        };

        let alert_level = if m.probability >= 0.75     { "critical" }
                          else if m.probability >= 0.50 { "high" }
                          else if m.probability >= 0.30 { "medium" }
                          else                           { "info" };

        let explanation = format!(
            "IOC {} ({}) found {} time(s) in logs — {} severity threat",
            m.ioc_value, m.ioc_type, m.hit_count, m.severity
        );
        let recs_json = serde_json::to_string(&[
            format!("Block {} {} at firewall/DNS level", m.ioc_type, m.ioc_value),
            format!("Investigate all systems that communicated with {}", m.ioc_value),
        ]).unwrap_or_else(|_| "[]".into());

        let db  = tenant_db_pub(tenant_id);
        let q = format!(
            "INSERT INTO {db}.threat_predictions \
             (tenant_id, attack_type, probability, confidence, trend, trend_delta, \
              intel_signal_count, exposure_score, internal_hit_count, \
              explanation, recommendations, aria_briefing, alert_level) \
             VALUES ('{tid}','{at}',{prob:.4},{conf:.4},'stable',0.0,1,0.0,{hits},\
                     '{exp}','{recs}','{briefing}','{al}')",
            db       = db,
            tid      = esc(tenant_id),
            at       = esc(&m.attack_type),
            prob     = m.probability,
            conf     = (m.probability * 0.85).min(0.95),
            hits     = m.hit_count,
            exp      = esc(&explanation),
            recs     = esc(&recs_json),
            briefing = esc(&briefing),
            al       = alert_level,
        );
        if let Err(e) = ch.client.query(&q).execute().await {
            warn!("correlator: failed to store match for {}: {}", m.ioc_value, e);
        } else {
            info!("correlator: stored match — {} ({}) hits={} prob={:.0}%",
                m.ioc_value, m.attack_type, m.hit_count, m.probability * 100.0);
        }
    }

    info!("AI correlation complete for tenant {}", tenant_id);
    Ok(())
}

struct MatchedThreat {
    ioc_type:    String,
    ioc_value:   String,
    attack_type: String,
    severity:    String,
    description: String,
    hit_count:   u64,
    evidence:    String,
    probability: f32,
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
