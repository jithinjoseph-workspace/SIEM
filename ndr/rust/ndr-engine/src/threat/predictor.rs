use std::sync::Arc;
use tokio::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::ai::provider::{generate, UseCase};
use super::analyzer::{build_exposure, match_iocs, ExposureProfile, IocMatch};
use super::cloud_trust::TrustedRanges;

pub fn spawn_predictor(
    ch:        Arc<crate::storage::ClickhouseStorage>,
    trusted:   Arc<RwLock<TrustedRanges>>,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(300)).await;
        loop {
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                info!("Threat predictor: generating predictions");
                'work: {
                    let Ok(tenants) = ch.get_all_tenants().await else {
                        break 'work;
                    };
                    // Bounded concurrency (TENANT_SCAN_CONCURRENCY) instead of
                    // one tenant at a time - previously held a single trusted
                    // read-lock guard across the whole sequential loop, which
                    // also would have blocked a concurrent version outright
                    // (one guard can't be shared across spawned tasks); each
                    // task now takes its own short-lived read() instead -
                    // TrustedRanges reads are cheap and RwLock allows many
                    // concurrent readers, so this doesn't add contention.
                    let sem = Arc::new(tokio::sync::Semaphore::new(super::tenant_scan_concurrency()));
                    let mut handles = Vec::with_capacity(tenants.len());
                    for tenant_id in tenants {
                        let ch2      = Arc::clone(&ch);
                        let trusted2 = Arc::clone(&trusted);
                        let sem2     = Arc::clone(&sem);
                        handles.push(tokio::spawn(async move {
                            let _permit = sem2.acquire().await;
                            if !ch2.get_tenant_ai_enabled(&tenant_id).await {
                                return;
                            }
                            let trusted_snap = trusted2.read().await;
                            if let Err(e) = run_prediction(&ch2, &tenant_id, &trusted_snap).await {
                                warn!("Prediction failed for {}: {}", tenant_id, e);
                            }
                        }));
                    }
                    futures_util::future::join_all(handles).await;
                    info!("Threat predictor: cycle complete — next run in 6 hours");
                }
            }
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });
}

#[derive(Debug, Clone)]
struct ActivePatternMatch {
    chain_name:     String,
    attack_type:    String,
    steps_observed: u8,
    steps_total:    u8,
    completion_pct: f32,
    evidence:       String,
    next_step:      String,
    src_ip:         String,
    ai_assessment:  String,
}

#[derive(Debug, Clone)]
struct MitreTechnique {
    technique_id:   String,
    technique_name: String,
    tactic:         String,
    severity:       String,
}

async fn fetch_active_pattern_matches(
    ch:               &crate::storage::ClickhouseStorage,
    tenant_id:        &str,
    trusted:          &TrustedRanges,
    trusted_asset_ips: &[String],
) -> Vec<ActivePatternMatch> {
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        chain_name:     String,
        attack_type:    String,
        steps_observed: u8,
        steps_total:    u8,
        completion_pct: f32,
        evidence:       String,
        next_step:      String,
        src_ip:         String,
        ai_assessment:  String,
    }

    let sensor_ip = std::env::var("HOST_IP").unwrap_or_default();
    let rows = ch.client.query(&format!(
        "SELECT chain_name, attack_type, steps_observed, steps_total, \
         completion_pct, evidence, next_step, src_ip, ai_assessment \
         FROM {db}.pattern_matches \
         WHERE status = 'active' \
         AND last_updated >= now() - INTERVAL 24 HOUR \
         ORDER BY completion_pct DESC \
         LIMIT 50",
        db = db
    ))
    .fetch_all::<Row>().await.unwrap_or_default();

    rows.into_iter()
    .filter(|r| {
        if let Ok(addr) = r.src_ip.parse::<std::net::Ipv4Addr>() {
            if addr.is_multicast() { return false; }
        }
        if !sensor_ip.is_empty() && r.src_ip == sensor_ip { return false; }
        if trusted.is_trusted_ip(&r.src_ip) { return false; }
        if trusted_asset_ips.contains(&r.src_ip) { return false; }
        true
    })
    .map(|r| ActivePatternMatch {
        chain_name:     r.chain_name,
        attack_type:    r.attack_type,
        steps_observed: r.steps_observed,
        steps_total:    r.steps_total,
        completion_pct: r.completion_pct,
        evidence:       r.evidence,
        next_step:      r.next_step,
        src_ip:         r.src_ip,
        ai_assessment:  r.ai_assessment,
    }).collect()
}

/// Extract technique IDs from evidence JSON and look up full MITRE details
async fn fetch_mitre_techniques(
    ch: &crate::storage::ClickhouseStorage,
    patterns: &[&ActivePatternMatch],
) -> Vec<MitreTechnique> {
    let mut tech_ids: Vec<String> = Vec::new();
    for pm in patterns {
        let steps: Vec<serde_json::Value> =
            serde_json::from_str(&pm.evidence).unwrap_or_default();
        for step in steps {
            if let Some(tid) = step["technique"].as_str() {
                if !tid.is_empty() && tid.starts_with('T') {
                    tech_ids.push(format!("'{}'", tid.replace('\'', "\\'")));
                }
            }
        }
    }
    if tech_ids.is_empty() { return vec![]; }
    tech_ids.dedup();

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        technique_id:   String,
        technique_name: String,
        tactic:         String,
        severity:       String,
    }

    ch.client.query(&format!(
        "SELECT technique_id, technique_name, tactic, severity \
         FROM ndr.attack_patterns \
         WHERE technique_id IN ({}) LIMIT 30",
        tech_ids.join(",")
    ))
    .fetch_all::<Row>().await.unwrap_or_default()
    .into_iter().map(|r| MitreTechnique {
        technique_id:   r.technique_id,
        technique_name: r.technique_name,
        tactic:         r.tactic,
        severity:       r.severity,
    }).collect()
}

/// Build a map of IP → human label from the assets table for enriching predictions.
async fn build_asset_map(
    ch:        &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    ips:       &[String],
) -> std::collections::HashMap<String, String> {
    if ips.is_empty() { return Default::default(); }
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    let ip_list = ips.iter()
        .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
        .map(|ip| format!("'{}'", ip))
        .collect::<Vec<_>>().join(",");
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { ip: String, hostname: String, custom_name: String, device_type: String }
    let rows = ch.client.query(&format!(
        "SELECT ip, hostname, custom_name, device_type FROM {db}.assets FINAL \
         WHERE ip IN ({ip_list}) AND tenant_id = '{tid}'",
        db = db, ip_list = ip_list, tid = tenant_id
    )).fetch_all::<Row>().await.unwrap_or_default();

    rows.into_iter().map(|r| {
        let label = if !r.custom_name.is_empty() {
            format!("{} [{}]", r.custom_name, r.device_type)
        } else if !r.hostname.is_empty() {
            format!("{} [{}]", r.hostname, r.device_type)
        } else {
            r.device_type.clone()
        };
        (r.ip, label)
    }).collect()
}

async fn run_prediction(
    ch:        &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    trusted:   &TrustedRanges,
) -> anyhow::Result<()> {
    // 0. Sensor health check — skip if no events in last 2 hours (sensor offline/not deployed)
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    let recent_count: u64 = ch.client
        .query(&format!(
            "SELECT count() FROM {db}.ndr_events WHERE timestamp >= now() - INTERVAL 2 HOUR",
            db = db
        ))
        .fetch_one::<u64>().await.unwrap_or(0);
    if recent_count == 0 {
        info!("Predictor: no sensor data in last 2 hours for tenant {} — skipping cycle (sensor offline?)", tenant_id);
        return Ok(());
    }

    // 1. Exposure profile
    let exposure = build_exposure(ch, tenant_id).await?;

    // 1b. Trusted assets — treated like trusted cloud IPs, excluded from scoring
    let trusted_asset_ips = ch.get_trusted_asset_ips(tenant_id).await;

    // 2. Active MITRE chain matches — trusted IPs filtered out immediately
    let all_patterns = fetch_active_pattern_matches(ch, tenant_id, trusted, &trusted_asset_ips).await;

    // 3. IOC IP matches — trusted IPs filtered out immediately
    let ioc_matches = match_iocs(ch, tenant_id, trusted).await;
    let ioc_matches: Vec<_> = ioc_matches.into_iter()
        .filter(|m| !trusted_asset_ips.contains(&m.ip))
        .collect();

    // 3b. Asset enrichment map: IP → label (e.g. "DESKTOP-ABC [Windows PC]")
    let all_ips: Vec<String> = {
        let mut v: Vec<String> = all_patterns.iter().map(|p| p.src_ip.clone()).collect();
        v.extend(ioc_matches.iter().map(|m| m.ip.clone()));
        v.sort(); v.dedup(); v
    };
    let asset_map = build_asset_map(ch, tenant_id, &all_ips).await;

    // 4. Recent threat intel signals — CVEs excluded (no network indicator, cause hallucinations)
    let intel_rows = ch.client
        .query("SELECT source, attack_type, severity, ioc_type, ioc_value, description \
                FROM ndr.threat_intel \
                WHERE collected_at >= now() - INTERVAL 6 HOUR \
                  AND ioc_type IN ('ip','ip4','ip6','domain','hostname','url','hash','md5','sha256','sha1') \
                ORDER BY collected_at DESC LIMIT 50")
        .fetch_all::<(String,String,String,String,String,String)>()
        .await?;

    let mut intel_by_type: std::collections::HashMap<String, u32> = Default::default();
    let mut intel_context: Vec<String> = Vec::new();
    for (src, at, sev, it, _iv, desc) in &intel_rows {
        *intel_by_type.entry(at.clone()).or_insert(0) += 1;
        if intel_context.len() < 10 {
            intel_context.push(format!("[{}] {} ({} {}) — {}", src, at, sev, it, desc));
        }
    }

    // 5. Historical trend
    let trend_db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    let prev_prob: std::collections::HashMap<String, f32> = ch.client
        .query(&format!(
            "SELECT attack_type, avg(probability), count() \
             FROM {}.threat_predictions \
             WHERE predicted_at >= now() - INTERVAL 24 HOUR \
             GROUP BY attack_type",
            trend_db
        ))
        .fetch_all::<(String, f32, u64)>().await.unwrap_or_default()
        .into_iter().map(|(at, p, _)| (at, p)).collect();

    // 6. Group by attack_type
    let mut ioc_by_type:     std::collections::HashMap<String, Vec<&IocMatch>>             = Default::default();
    let mut patterns_by_type: std::collections::HashMap<String, Vec<&ActivePatternMatch>>  = Default::default();
    for m  in &ioc_matches   { ioc_by_type.entry(m.attack_type.clone()).or_default().push(m); }
    for pm in &all_patterns  { patterns_by_type.entry(pm.attack_type.clone()).or_default().push(pm); }

    // 7. Build attack type set — ONLY from real signals (no zero-signal noise)
    let mut attack_types: std::collections::HashSet<String> = Default::default();
    for at in patterns_by_type.keys() { attack_types.insert(at.clone()); }
    for at in ioc_by_type.keys()      { attack_types.insert(at.clone()); }
    if exposure.c2_beacons           > 0           { attack_types.insert("c2_communication".into()); }
    if exposure.lateral_movement     > 0           { attack_types.insert("lateral_movement".into()); }
    if exposure.brute_force_attempts > 5           { attack_types.insert("credential_attack".into()); }
    if exposure.data_exfil_bytes     > 50_000_000  { attack_types.insert("data_exfiltration".into()); }

    if attack_types.is_empty() {
        info!("Predictor: no real signal for tenant {} — skipping cycle", tenant_id);
        return Ok(());
    }

    let exposure_score = exposure.exposure_score();

    // 8. Predict for each attack type
    for attack_type in &attack_types {
        let matched_patterns = patterns_by_type.get(attack_type.as_str()).cloned().unwrap_or_default();
        let matched_iocs     = ioc_by_type.get(attack_type.as_str()).cloned().unwrap_or_default();
        let signal_count     = *intel_by_type.get(attack_type.as_str()).unwrap_or(&0);

        // Fetch MITRE technique details for all matched chain steps
        let techniques = fetch_mitre_techniques(ch, &matched_patterns).await;

        let max_completion = matched_patterns.iter()
            .map(|pm| pm.completion_pct)
            .fold(0.0f32, f32::max);

        // Skip generic attack types with no real chain evidence (prevents noise from vague patterns)
        if attack_type == "general_threat" && max_completion < 30.0 && matched_iocs.is_empty() {
            info!("Predictor: skipping general_threat — no chain evidence (completion={:.0}%)", max_completion);
            continue;
        }

        let probability = compute_probability(
            &exposure, attack_type, signal_count, exposure_score,
            matched_iocs.len() as u32, max_completion,
        );

        let prev       = *prev_prob.get(attack_type.as_str()).unwrap_or(&0.0);
        let trend_delta = probability - prev;
        let trend      = if trend_delta > 0.05 { "rising" }
                         else if trend_delta < -0.05 { "falling" }
                         else { "stable" };
        let alert_level = if probability > 0.75 { "critical" }
                          else if probability > 0.5 { "high" }
                          else if probability > 0.25 { "medium" }
                          else { "info" };

        let (aria_briefing, recommendations) = generate_aria_briefing(
            ch, tenant_id, attack_type, probability,
            &exposure, &intel_context,
            &matched_iocs, &matched_patterns, &techniques, &asset_map,
        ).await;

        let explanation = build_explanation(
            attack_type, &matched_patterns, &techniques, &matched_iocs, max_completion, &asset_map,
        );

        let db       = crate::storage::clickhouse::tenant_db_pub(tenant_id);
        let recs_json = serde_json::to_string(&recommendations).unwrap_or_else(|_| "[]".into());
        let confidence = (0.4 + (matched_patterns.len() as f32 * 0.15) + (signal_count as f32 * 0.02)).min(0.95);

        // Dedup: skip if same attack_type was already predicted within the 6-hour predictor interval
        let already: u64 = ch.client
            .query(&format!(
                "SELECT count() FROM {db}.threat_predictions \
                 WHERE attack_type = '{at}' AND tenant_id = '{tid}' \
                 AND predicted_at >= now() - INTERVAL 6 HOUR",
                db  = db,
                at  = esc(attack_type),
                tid = tenant_id,
            ))
            .fetch_one::<u64>().await.unwrap_or(0);
        if already > 0 { continue; }

        let q = format!(
            "INSERT INTO {db}.threat_predictions \
             (tenant_id, attack_type, probability, confidence, trend, trend_delta, \
              intel_signal_count, exposure_score, internal_hit_count, \
              explanation, recommendations, aria_briefing, alert_level) \
             VALUES ('{tid}','{at}',{prob:.4},{conf:.4},'{trend}',{td:.4},{sc},{es:.2},{ihc},\
                     '{expl}','{recs}','{briefing}','{al}')",
            db       = db,
            tid      = tenant_id,
            at       = esc(attack_type),
            prob     = probability,
            conf     = confidence,
            trend    = trend,
            td       = trend_delta,
            sc       = signal_count,
            es       = exposure_score,
            ihc      = matched_patterns.len() as u32,
            expl     = esc(&explanation),
            recs     = esc(&recs_json),
            briefing = esc(&aria_briefing),
            al       = alert_level,
        );
        let _ = ch.client.query(&q).execute().await;

        // Mark involved asset IPs as threat_flagged in the assets table
        let flagged_ips: Vec<String> = matched_patterns.iter().map(|p| p.src_ip.clone())
            .chain(matched_iocs.iter().map(|m| m.ip.clone()))
            .filter(|ip| !ip.is_empty())
            .collect::<std::collections::HashSet<_>>().into_iter().collect();
        let _ = ch.mark_assets_threat_flagged(tenant_id, &flagged_ips).await;
    }

    // Retain only last 30 days — prevents unbounded table growth
    let retention_db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    let _ = ch.client.query(&format!(
        "DELETE FROM {db}.threat_predictions WHERE predicted_at < now() - INTERVAL 30 DAY",
        db = retention_db
    )).execute().await;

    info!("Predictions saved for tenant {} ({} attack types)", tenant_id, attack_types.len());
    Ok(())
}

fn compute_probability(
    exp: &ExposureProfile,
    attack_type: &str,
    signal_count: u32,
    exposure_score: f32,
    ioc_match_count: u32,
    pattern_completion_pct: f32,
) -> f32 {
    let mut p: f32 = 0.05;

    // MITRE chain completion is the primary signal
    p += (pattern_completion_pct / 100.0) * 0.50;

    // IOC confirmed malicious IPs in live traffic
    p += (ioc_match_count as f32 * 0.12).min(0.35);

    // Threat intel feed signals
    p += (signal_count as f32 * 0.08).min(0.30);

    // Attack-type specific exposure boosts
    match attack_type {
        "ransomware" => {
            p += (exp.rdp_exposed > 0) as u8 as f32 * 0.20;
            p += (exp.smb_exposed > 0) as u8 as f32 * 0.15;
            p += exposure_score / 100.0 * 0.25;
        }
        "credential_attack" => {
            p += (exp.failed_logins > 20) as u8 as f32 * 0.20;
            p += (exp.brute_force_attempts > 5) as u8 as f32 * 0.25;
            p += (exp.ssh_exposed > 0) as u8 as f32 * 0.10;
        }
        "lateral_movement" => {
            p += (exp.lateral_movement > 0) as u8 as f32 * 0.30;
            p += (exp.smb_exposed > 0) as u8 as f32 * 0.15;
        }
        "c2_communication" => {
            p += (exp.c2_beacons > 0) as u8 as f32 * 0.35;
            p += exposure_score / 100.0 * 0.20;
        }
        "data_exfiltration" => {
            p += (exp.data_exfil_bytes > 100_000_000) as u8 as f32 * 0.30;
            p += (exp.c2_beacons > 0) as u8 as f32 * 0.15;
        }
        "exploitation" => {
            p += (exp.http_exposed > 0) as u8 as f32 * 0.10;
            p += exposure_score / 100.0 * 0.20;
        }
        _ => {
            p += exposure_score / 100.0 * 0.15;
        }
    }
    p.min(0.98)
}

/// Extract kill chain stage info from pattern ai_assessment JSON snippet.
/// chain_matcher stores: "... | KCS:6:Command & Control:Actions ..."
fn extract_kill_chain(patterns: &[&ActivePatternMatch]) -> Option<(u8, String, String)> {
    for pm in patterns {
        // Look for KCS marker written by chain_matcher into ai_assessment
        if let Some(start) = pm.ai_assessment.find("KCS:") {
            let rest = &pm.ai_assessment[start + 4..];
            let parts: Vec<&str> = rest.splitn(4, ':').collect();
            if parts.len() >= 3 {
                if let Ok(stage) = parts[0].trim().parse::<u8>() {
                    return Some((
                        stage,
                        parts[1].trim().to_string(),
                        parts.get(2).unwrap_or(&"").trim().to_string(),
                    ));
                }
            }
        }
    }
    None
}

/// Build human-readable explanation showing kill chain stage + matched chains + MITRE techniques
fn build_explanation(
    attack_type: &str,
    patterns: &[&ActivePatternMatch],
    techniques: &[MitreTechnique],
    iocs: &[&IocMatch],
    max_completion: f32,
    asset_map: &std::collections::HashMap<String, String>,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Kill chain stage — most prominent info, shown first
    if let Some((stage, stage_name, next_stage)) = extract_kill_chain(patterns) {
        let next = if next_stage.is_empty() {
            "Actions on Objectives".to_string()
        } else {
            next_stage
        };
        parts.push(format!(
            "Kill Chain Stage {}/7 — {} | Next: {}",
            stage, stage_name, next
        ));
    }

    if !patterns.is_empty() {
        let chain_list: Vec<String> = patterns.iter().map(|pm| {
            let ip_label = asset_map.get(&pm.src_ip)
                .map(|l| format!("{} ({})", pm.src_ip, l))
                .unwrap_or_else(|| pm.src_ip.clone());
            format!("\"{}\" {}/{} steps ({:.0}%) from {}",
                pm.chain_name, pm.steps_observed, pm.steps_total,
                pm.completion_pct, ip_label)
        }).collect();
        parts.push(format!("MITRE chains matched: {}", chain_list.join("; ")));

        if !techniques.is_empty() {
            let tech_list: Vec<String> = techniques.iter().map(|t| {
                format!("{} {} [{}]", t.technique_id, t.technique_name, t.tactic)
            }).collect();
            parts.push(format!("Techniques: {}", tech_list.join(", ")));
        }

        let next_steps: Vec<String> = patterns.iter()
            .filter(|pm| !pm.next_step.is_empty())
            .map(|pm| format!("{} → {}", pm.chain_name, pm.next_step))
            .collect();
        if !next_steps.is_empty() {
            parts.push(format!("Predicted next: {}", next_steps.join("; ")));
        }
    }

    if !iocs.is_empty() {
        let ip_list: Vec<String> = iocs.iter().map(|m| {
            if let Some(label) = asset_map.get(&m.ip) {
                format!("{} — {} ({})", m.ip, label, m.source)
            } else {
                format!("{} ({})", m.ip, m.source)
            }
        }).collect();
        parts.push(format!("Malicious IPs confirmed: {}", ip_list.join(", ")));
    }

    if parts.is_empty() {
        format!("Exposure-based {} signal — {:.0}% chain completion", attack_type, max_completion)
    } else {
        parts.join(" | ")
    }
}

async fn generate_aria_briefing(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    attack_type: &str,
    probability: f32,
    exposure: &ExposureProfile,
    intel_context: &[String],
    matched_iocs: &[&IocMatch],
    matched_patterns: &[&ActivePatternMatch],
    techniques: &[MitreTechnique],
    asset_map: &std::collections::HashMap<String, String>,
) -> (String, Vec<String>) {
    let exposure_ctx  = exposure.as_json_context();
    let intel_summary = intel_context.join("\n");

    let ioc_section = if matched_iocs.is_empty() {
        "No confirmed IOC matches.".to_string()
    } else {
        let lines: Vec<String> = matched_iocs.iter().map(|m| {
            let asset_label = asset_map.get(&m.ip).map(|l| format!(" — Asset: {}", l)).unwrap_or_default();
            format!("  {}{} ({} traffic) — {} [{}] | {}", m.ip, asset_label, m.direction, m.attack_type, m.source, m.description)
        }).collect();
        format!("Confirmed malicious IPs ({} matched):\n{}", matched_iocs.len(), lines.join("\n"))
    };

    let pattern_section = if matched_patterns.is_empty() {
        "No active MITRE chain matches.".to_string()
    } else {
        let lines: Vec<String> = matched_patterns.iter().map(|pm| {
            let asset_label = asset_map.get(&pm.src_ip).map(|l| format!(" ({})", l)).unwrap_or_default();
            format!("  Chain: {} | {:.0}% complete ({}/{} steps) | src_ip: {}{} | next expected: {}",
                pm.chain_name, pm.completion_pct, pm.steps_observed, pm.steps_total,
                pm.src_ip, asset_label,
                if pm.next_step.is_empty() { "chain may be complete" } else { &pm.next_step })
        }).collect();
        format!("Active MITRE attack chains:\n{}", lines.join("\n"))
    };

    let technique_section = if techniques.is_empty() {
        String::new()
    } else {
        let lines: Vec<String> = techniques.iter().map(|t| {
            format!("  {} {} | tactic: {} | severity: {}", t.technique_id, t.technique_name, t.tactic, t.severity)
        }).collect();
        format!("Matched MITRE ATT&CK techniques:\n{}", lines.join("\n"))
    };

    let system = format!(
        "You are ARIA, an NDR threat prediction engine. \
         Analyze MITRE ATT&CK chain matches, confirmed IOC IPs, \
         and network exposure to produce concise, actionable threat predictions. \
         Reference specific chain names, technique IDs, and IPs from the data. \
         Tenant: {}. Date: {}.",
        tenant_id,
        chrono::Utc::now().format("%Y-%m-%d")
    );

    let prompt = format!(
        "Attack type: {}\nProbability: {:.0}%\n\n\
         {}\n\n\
         {}\n\n\
         {}\n\n\
         Exposure profile:\n{}\n\n\
         Threat intel signals:\n{}\n\n\
         Produce exactly:\n\
         BRIEFING: <2 sentences referencing specific chain names, MITRE technique IDs, and src IPs>\n\
         RECOMMENDATIONS:\n- <action 1>\n- <action 2>\n- <action 3>",
        attack_type, probability * 100.0,
        pattern_section, technique_section, ioc_section,
        exposure_ctx, intel_summary
    );

    let response = generate(ch, UseCase::ThreatPrediction, &system, &prompt).await;
    if response.is_empty() {
        warn!("AI returned empty for threat prediction ({})", attack_type);
        return (default_briefing(attack_type, probability, exposure), default_recs(attack_type));
    }
    parse_aria_response(&response)
}

fn parse_aria_response(text: &str) -> (String, Vec<String>) {
    let mut briefing = String::new();
    let mut recs     = Vec::new();
    for line in text.lines() {
        if line.starts_with("BRIEFING:") {
            briefing = line.trim_start_matches("BRIEFING:").trim().to_string();
        } else if line.starts_with("- ") {
            recs.push(line.trim_start_matches("- ").trim().to_string());
        }
    }
    if briefing.is_empty() { briefing = text.chars().take(200).collect(); }
    (briefing, recs)
}

fn default_briefing(attack_type: &str, probability: f32, exp: &ExposureProfile) -> String {
    let pct   = (probability * 100.0) as u32;
    let label = match attack_type {
        "ransomware"        => "ransomware attack",
        "credential_attack" => "credential-based attack",
        "c2_communication"  => "command-and-control activity",
        "lateral_movement"  => "lateral movement",
        "data_exfiltration" => "data exfiltration",
        "exploitation"      => "exploitation attempt",
        _                   => "threat activity",
    };
    format!(
        "Network telemetry indicates a {}% probability of {} in the next 6 hours. \
         Exposure score is {:.0}/100.",
        pct, label, exp.exposure_score()
    )
}

fn default_recs(attack_type: &str) -> Vec<String> {
    match attack_type {
        "ransomware" => vec![
            "Disable RDP/SMB on internet-facing hosts".into(),
            "Verify offline backup integrity".into(),
            "Patch all unpatched CVEs flagged by CISA KEV".into(),
        ],
        "credential_attack" => vec![
            "Enable MFA on all remote access endpoints".into(),
            "Review and block IPs with >10 failed login attempts".into(),
            "Rotate credentials for privileged accounts".into(),
        ],
        "c2_communication" => vec![
            "Isolate hosts showing beacon-like traffic patterns".into(),
            "Block detected C2 IOCs at perimeter firewall".into(),
            "Capture full PCAP on suspected hosts for forensics".into(),
        ],
        "lateral_movement" => vec![
            "Segment network to limit east-west traffic".into(),
            "Audit SMB shares and disable unnecessary file sharing".into(),
            "Review privilege levels and remove unnecessary admin rights".into(),
        ],
        "data_exfiltration" => vec![
            "Block large outbound transfers to unknown destinations".into(),
            "Enable DLP policies on sensitive data stores".into(),
            "Investigate high-volume outbound connections immediately".into(),
        ],
        _ => vec![
            "Review alert queue for related incidents".into(),
            "Update IDS/IPS signatures".into(),
            "Increase logging verbosity on border devices".into(),
        ],
    }
}

fn esc(s: &str) -> String {
    s.replace('\'', "\\'").replace('\\', "\\\\")
}
