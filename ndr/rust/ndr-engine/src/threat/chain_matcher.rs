use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{info, warn};
use serde_json::Value;

use crate::ai::provider::{generate, UseCase};
use crate::storage::clickhouse::tenant_db_pub;
use super::cloud_trust::TrustedRanges;

pub fn spawn_chain_matcher(
    ch:        Arc<crate::storage::ClickhouseStorage>,
    trigger:   Arc<Notify>,
    trusted:   Arc<tokio::sync::RwLock<TrustedRanges>>,
    asn:       Arc<Option<crate::enrichment::AsnLookup>>,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        loop {
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                match ch.get_all_tenants().await {
                    Ok(tenants) => {
                        // Bounded concurrency (TENANT_SCAN_CONCURRENCY) - this
                        // makes AI calls per tenant (see run_matching), so
                        // sequential processing at real tenant counts could
                        // take hours for one sweep.
                        let sem = Arc::new(tokio::sync::Semaphore::new(super::tenant_scan_concurrency()));
                        let mut handles = Vec::with_capacity(tenants.len());
                        for tenant_id in tenants {
                            let ch2      = Arc::clone(&ch);
                            let trusted2 = Arc::clone(&trusted);
                            let asn2     = Arc::clone(&asn);
                            let sem2     = Arc::clone(&sem);
                            handles.push(tokio::spawn(async move {
                                let _permit = sem2.acquire().await;
                                if !ch2.get_tenant_ai_enabled(&tenant_id).await { return; }
                                run_matching(Arc::clone(&ch2), &tenant_id, &trusted2, &asn2).await;
                            }));
                        }
                        futures_util::future::join_all(handles).await;
                    }
                    Err(e) => warn!("chain_matcher: failed to get tenants: {}", e),
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(1800)) => {
                    info!("chain_matcher: scheduled 30-min sweep");
                }
                _ = trigger.notified() => {
                    info!("chain_matcher: new patterns downloaded — running immediate sweep");
                }
            }
        }
    });
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct HitRow {
    ts:        String,
    src_ip:    String,
    dst_ip:    String,
    tags_str:  String,
    sigma_str: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct BeaconPairRow {
    src_ip: String,
    dst_ip: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct SessionRow {
    community_id: String,
    event_type:   String,
    detail:       String,
    src_ip:       String,
    dst_ip:       String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct ChainRow {
    chain_id:    String,
    chain_name:  String,
    attack_type: String,
    steps:       String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct ThreatIntelRow {
    ioc_type:    String,
    ioc_value:   String,
    attack_type: String,
    severity:    String,
    description: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct AttackPatternRow {
    technique_id:   String,
    technique_name: String,
    tactic:         String,
}

async fn fetch_filtered_hits(
    client:  &clickhouse::Client,
    db:      &str,
    trusted: &TrustedRanges,
    asn:     &Option<crate::enrichment::AsnLookup>,
    beacons: &std::collections::HashSet<String>,
) -> Vec<String> {
    let rows = client
        .query(&format!(
            "SELECT \
             formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as ts, \
             src_ip, dst_ip, \
             arrayStringConcat(tags, ' ')       as tags_str, \
             arrayStringConcat(sigma_hits, ' ') as sigma_str \
             FROM {db}.ndr_hits \
             WHERE timestamp >= now() - INTERVAL 6 HOUR \
               AND NOT (severity = 'INFO' AND length(tags) = 0) \
               AND NOT (arrayStringConcat(tags, ' ') = 'agent-s-internal' AND severity = 'INFO') \
             ORDER BY timestamp ASC \
             LIMIT 1000",
            db = db
        ))
        .fetch_all::<HitRow>()
        .await
        .unwrap_or_default();

    let sensor_ip = std::env::var("HOST_IP").unwrap_or_default();

    rows.into_iter()
        .filter(|r| {
            // Drop multicast/broadcast — never real attackers, always protocol noise
            if is_multicast_or_broadcast(&r.dst_ip) || is_multicast_or_broadcast(&r.src_ip) {
                return false;
            }
            // Drop sensor's own trusted outbound traffic
            if !sensor_ip.is_empty() && r.src_ip == sensor_ip
                && trusted.is_trusted(&r.dst_ip, "", asn) {
                return false;
            }
            let key = format!("{}→{}", r.src_ip, r.dst_ip);
            if beacons.contains(&key) { return true; }
            if crate::enrichment::is_private_ip(&r.src_ip) && trusted.is_trusted(&r.dst_ip, "", asn) {
                return false;
            }
            !trusted.is_trusted(&r.dst_ip, "", asn)
        })
        .map(|r| {
            let signal = format!("{} {}", r.tags_str, r.sigma_str).trim().to_string();
            format!("[{}] {} → {}  tags={}", r.ts, r.src_ip, r.dst_ip, signal)
        })
        .collect()
}

async fn fetch_beacon_pairs(
    client: &clickhouse::Client,
    db:     &str,
) -> std::collections::HashSet<String> {
    let q = format!(
        "SELECT src_ip, dst_ip \
         FROM {db}.ndr_events \
         WHERE timestamp >= now() - INTERVAL 6 HOUR \
         GROUP BY src_ip, dst_ip \
         HAVING count() >= 8 \
           AND avg(toUInt64OrZero(JSONExtractString(raw, 'orig_bytes'))) < 4096 \
           AND (max(toUnixTimestamp(timestamp)) - min(toUnixTimestamp(timestamp))) > 300 \
           AND toFloat64(count()) / \
               ((max(toUnixTimestamp(timestamp)) - min(toUnixTimestamp(timestamp))) / 60.0) \
               BETWEEN 0.5 AND 10",
        db = db,
    );
    client
        .query(&q)
        .fetch_all::<BeaconPairRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| format!("{}→{}", r.src_ip, r.dst_ip))
        .collect()
}

async fn fetch_all_sessions(
    client:  &clickhouse::Client,
    db:      &str,
    trusted: &TrustedRanges,
    asn:     &Option<crate::enrichment::AsnLookup>,
    beacons: &std::collections::HashSet<String>,
) -> Vec<String> {
    let rows = client
        .query(&format!(
            "SELECT community_id, event_type, \
             multiIf( \
               event_type = 'dns',  JSONExtractString(raw, 'query'), \
               event_type = 'http', concat(JSONExtractString(raw, 'method'), ' ', JSONExtractString(raw, 'uri')), \
               event_type IN ('ssl', 'tls'), JSONExtractString(raw, 'server_name'), \
               event_type = 'files', concat(JSONExtractString(raw, 'filename'), ' md5:', JSONExtractString(raw, 'md5')), \
               '' \
             ) as detail, \
             src_ip, dst_ip \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 6 HOUR \
               AND event_type IN ('dns', 'http', 'ssl', 'tls', 'files') \
             LIMIT 500",
            db = db
        ))
        .fetch_all::<SessionRow>()
        .await
        .unwrap_or_default();

    rows.into_iter()
        .filter(|r| {
            let d = r.detail.trim();
            if d.is_empty() || d == " " { return false; }
            let sni = if r.event_type == "ssl" || r.event_type == "tls" { r.detail.trim() } else { "" };
            let key = format!("{}→{}", r.src_ip, r.dst_ip);
            if beacons.contains(&key) { return true; } // beacon pattern always kept
            // Internal src → trusted cloud = sensor/engine own traffic, never an attacker
            if crate::enrichment::is_private_ip(&r.src_ip) && trusted.is_trusted(&r.dst_ip, sni, asn) {
                return false;
            }
            !trusted.is_trusted(&r.dst_ip, sni, asn)
        })
        .map(|r| {
            let cid_short = &r.community_id[..r.community_id.len().min(16)];
            format!("{}:{}  (cid:{})", r.event_type, r.detail.trim(), cid_short)
        })
        .collect()
}

async fn fetch_threat_intel(client: &clickhouse::Client) -> Vec<String> {
    client
        .query(
            "SELECT ioc_type, ioc_value, attack_type, severity, description \
             FROM ndr.threat_intel \
             WHERE expires_at > now() AND ioc_value != '' \
               AND ioc_type IN ('ip', 'ip4', 'ip6', 'domain', 'hostname', 'url', 'hash', 'md5', 'sha256', 'sha1') \
             ORDER BY collected_at DESC \
             LIMIT 3000",
        )
        .fetch_all::<ThreatIntelRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            let desc = if r.description.is_empty() {
                String::new()
            } else {
                format!(" — {}", &r.description[..r.description.len().min(60)])
            };
            format!("{}:{}  [{}/{}]{}", r.ioc_type, r.ioc_value, r.attack_type, r.severity, desc)
        })
        .collect()
}

async fn fetch_attack_patterns(client: &clickhouse::Client) -> Vec<String> {
    client
        .query(
            "SELECT technique_id, technique_name, tactic \
             FROM ndr.attack_patterns \
             ORDER BY kill_chain_phase ASC",
        )
        .fetch_all::<AttackPatternRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| format!("{} {} ({})", r.technique_id, r.technique_name, r.tactic))
        .collect()
}

async fn run_matching(
    ch:        Arc<crate::storage::ClickhouseStorage>,
    tenant_id: &str,
    trusted:   &Arc<tokio::sync::RwLock<TrustedRanges>>,
    asn:       &Arc<Option<crate::enrichment::AsnLookup>>,
) {
    let db = tenant_db_pub(tenant_id);

    let chains = ch
        .client
        .query("SELECT chain_id, chain_name, attack_type, steps FROM ndr.attack_chains")
        .fetch_all::<ChainRow>()
        .await
        .unwrap_or_default();

    if chains.is_empty() {
        return;
    }

    // Beacon detection: (src,dst) pairs with regular cadence + small bytes = C2 even on trusted cloud
    let beacons = fetch_beacon_pairs(&ch.client, &db).await;
    if !beacons.is_empty() {
        info!("chain_matcher: {} beacon pairs for tenant {}", beacons.len(), tenant_id);
    }

    let t = trusted.read().await;
    let (hits, sessions, iocs, techniques) = tokio::join!(
        fetch_filtered_hits(&ch.client, &db, &*t, &**asn, &beacons),
        fetch_all_sessions(&ch.client, &db, &*t, &**asn, &beacons),
        fetch_threat_intel(&ch.client),
        fetch_attack_patterns(&ch.client),
    );
    drop(t); // release read lock before long-running AI calls

    if hits.is_empty() && sessions.is_empty() {
        info!("chain_matcher: no hits or sessions for tenant {} in last 6h", tenant_id);
        return;
    }

    info!(
        "chain_matcher: tenant={} hits={} sessions={} iocs={} techniques={} chains={}",
        tenant_id, hits.len(), sessions.len(), iocs.len(), techniques.len(), chains.len()
    );

    // Compact chain descriptions for AI
    let chains_items: Vec<String> = chains.iter().map(|c| {
        let steps: Vec<Value> = serde_json::from_str(&c.steps).unwrap_or_default();
        let step_names: Vec<String> = steps.iter().map(|s| {
            let t = s["technique"].as_str().unwrap_or("");
            let n = s["name"].as_str().unwrap_or("");
            if t.is_empty() { n.to_string() } else { format!("{} ({})", n, t) }
        }).collect();
        format!("{} [{}]: {}", c.chain_name, c.attack_type, step_names.join(" → "))
    }).collect();

    // Merge hits + sessions into one log stream — sessions prefixed for AI context
    let mut all_logs: Vec<String> = hits;
    all_logs.extend(sessions.into_iter().map(|s| format!("[SESSION] {}", s)));

    const LOG_BATCH:   usize = 500;  // ~3 batches for 1500 combined logs
    const INTEL_BATCH: usize = 500;  // ~6 IOC batches, ~2 tech batches

    let log_batches:  Vec<Vec<String>> = all_logs.chunks(LOG_BATCH).map(|c| c.to_vec()).collect();
    let ioc_batches:  Vec<Vec<String>> = iocs.chunks(INTEL_BATCH).map(|c| c.to_vec()).collect();
    let tech_batches: Vec<Vec<String>> = techniques.chunks(INTEL_BATCH).map(|c| c.to_vec()).collect();

    // Total calls: log_batches × (tech_batches + ioc_batches)
    // chains folded into each behavioral call → no separate chain call
    let total_calls = log_batches.len() * (tech_batches.len() + ioc_batches.len());
    info!(
        "chain_matcher: {} log-batches × ({} behavioral + {} ioc-batches) = {} total AI calls",
        log_batches.len(), tech_batches.len(), ioc_batches.len(), total_calls
    );

    type Fut = std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>;
    let mut all_futures: Vec<Fut> = vec![];

    for lb in &log_batches {
        // Behavioral: chains + each technique batch in one prompt
        for tb in &tech_batches {
            let ch2 = Arc::clone(&ch); let tid = tenant_id.to_string();
            let logs = lb.clone(); let tb2 = tb.clone(); let ci = chains_items.clone();
            all_futures.push(Box::pin(async move {
                ask_ai_behavioral_batch(&ch2, &tid, &ci, &tb2, &logs).await
            }));
        }
        // IOC matching: IPs, domains, hashes directly against log lines
        for ib in &ioc_batches {
            let ch2 = Arc::clone(&ch); let tid = tenant_id.to_string();
            let logs = lb.clone(); let ib2 = ib.clone();
            all_futures.push(Box::pin(async move {
                ask_ai_batch(&ch2, &tid, "iocs", &ib2, &logs, &[]).await
            }));
        }
    }

    info!("chain_matcher: dispatching {} parallel AI calls for tenant {}", all_futures.len(), tenant_id);
    let results = futures_util::future::join_all(all_futures).await;

    // Parse all results
    let mut all_matches: Vec<Value> = vec![];
    for raw in &results {
        if raw.is_empty() { continue; }
        let json_str = if let (Some(s), Some(e)) = (raw.find('{'), raw.rfind('}')) {
            &raw[s..=e]
        } else {
            raw.as_str()
        };
        if let Ok(parsed) = serde_json::from_str::<Value>(json_str) {
            if let Some(arr) = parsed["matches"].as_array() {
                all_matches.extend(arr.iter().cloned());
            }
        }
    }

    if all_matches.is_empty() {
        info!("chain_matcher: no matches found for tenant {}", tenant_id);
        return;
    }

    let matches = consolidate_matches(all_matches);
    let mut stored = 0u32;

    for m in &matches {
        let probability = m["probability"].as_f64().unwrap_or(0.0) as f32;
        if probability < 0.2 { continue; }

        let chain_name  = m["chain_name"].as_str().unwrap_or("unknown");
        let attack_type = m["attack_type"].as_str().unwrap_or("general_threat");
        let next_step   = m["next_step"].as_str().unwrap_or("");
        let explanation = m["explanation"].as_str().unwrap_or("");

        let suspicious_ips = m["suspicious_ips"]
            .as_array()
            .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
            .unwrap_or_default();

        let matched_steps: Vec<String> = m["matched_steps"]
            .as_array()
            .map(|v| v.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let steps_observed = matched_steps.len() as u8;

        let matched_chain = chains.iter().find(|c| c.chain_name == chain_name);
        let chain_id      = matched_chain.map(|c| c.chain_id.as_str()).unwrap_or("unknown");

        let steps_total = matched_chain
            .map(|c| {
                let s: Vec<Value> = serde_json::from_str(&c.steps).unwrap_or_default();
                s.len() as u8
            })
            .unwrap_or(steps_observed);

        let completion_pct = probability * 100.0;

        let severity = if probability >= 0.7      { "CRITICAL" }
                       else if probability >= 0.5 { "HIGH" }
                       else if probability >= 0.3 { "MEDIUM" }
                       else                       { "LOW" };

        let evidence_json = matched_chain
            .map(|c| c.steps.clone())
            .unwrap_or_else(|| serde_json::to_string(&matched_steps).unwrap_or_default());

        let recs      = default_recs_for_chain(attack_type);
        let recs_json = serde_json::to_string(&recs).unwrap_or_default();

        let kill_chain_stage = m["kill_chain_stage"].as_u64().unwrap_or(0) as u8;
        let kill_chain_name  = m["kill_chain_name"].as_str().unwrap_or("").to_string();
        let kill_chain_next  = m["kill_chain_next"].as_str().unwrap_or("").to_string();

        let kcs_marker = if kill_chain_stage > 0 {
            format!(" | KCS:{}:{}:{}", kill_chain_stage, kill_chain_name, kill_chain_next)
        } else {
            String::new()
        };

        let ai_summary = format!(
            "{} | Suspicious IPs: {} | Next: {}{}",
            explanation,
            if suspicious_ips.is_empty() { "none identified".to_string() } else { suspicious_ips.clone() },
            if next_step.is_empty()      { "chain may be complete" }        else { next_step },
            kcs_marker
        );

        // Dedup: skip if same chain already active for this tenant within the sweep window
        let already: u64 = ch.client
            .query(&format!(
                "SELECT count() FROM {db}.pattern_matches \
                 WHERE chain_id = '{cid}' AND tenant_id = '{tid}' AND status = 'active' \
                 AND last_updated >= now() - INTERVAL 6 HOUR",
                db  = db,
                cid = esc(chain_id),
                tid = esc(tenant_id),
            ))
            .fetch_one::<u64>().await.unwrap_or(0);
        if already > 0 { continue; }

        let q = format!(
            "INSERT INTO {db}.pattern_matches \
             (tenant_id, chain_id, chain_name, attack_type, \
              steps_observed, steps_total, completion_pct, \
              evidence, next_step, predicted_eta_hours, \
              src_ip, severity, confidence, status, \
              ai_assessment, recommendations) \
             VALUES ('{tid}','{cid}','{cn}','{at}',{so},{st},{cp:.1},\
                     '{ev}','{ns}',0,'{src}','{sev}',{conf:.3},'active',\
                     '{ai}','{recs}')",
            db   = db,
            tid  = esc(tenant_id),
            cid  = esc(chain_id),
            cn   = esc(chain_name),
            at   = esc(attack_type),
            so   = steps_observed,
            st   = steps_total,
            cp   = completion_pct,
            ev   = esc(&evidence_json),
            ns   = esc(next_step),
            src  = esc(&suspicious_ips),
            sev  = esc(severity),
            conf = probability,
            ai   = esc(&ai_summary),
            recs = esc(&recs_json),
        );

        if let Err(e) = ch.client.query(&q).execute().await {
            warn!("chain_matcher: failed to store pattern match {}: {}", chain_name, e);
        } else {
            stored += 1;
        }
    }

    if stored > 0 {
        info!("chain_matcher: stored {} pattern matches for tenant {}", stored, tenant_id);
    } else {
        info!("chain_matcher: no significant patterns (all below threshold) for tenant {}", tenant_id);
    }
}

const KILL_CHAIN_CONTEXT: &str = "\
CYBER KILL CHAIN STAGES (Lockheed Martin):\n\
  Stage 1 - Reconnaissance:    attacker gathers info (scanning, OSINT)\n\
  Stage 2 - Weaponization:     builds exploit or malware payload\n\
  Stage 3 - Delivery:          sends phishing, exploit, malicious file\n\
  Stage 4 - Exploitation:      code executes on victim system\n\
  Stage 5 - Installation:      malware installs, establishes persistence\n\
  Stage 6 - Command & Control: attacker connects back to C2 server\n\
  Stage 7 - Actions:           data theft, ransomware, destruction\n";

/// Behavioral scan: chains + techniques combined in one prompt vs a raw log batch.
/// Chains (all 82) + one technique batch (500) → single AI call per log batch.
async fn ask_ai_behavioral_batch(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    chains: &[String],
    techniques: &[String],
    logs: &[String],
) -> String {
    let system = format!(
        "You are ARIA, a network threat detection AI for tenant {}. \
         Analyze raw network logs against attack chain campaigns AND MITRE ATT&CK techniques. \
         Match behavioral patterns, attack sequences, tags, ports, protocols. \
         Identify the Cyber Kill Chain stage for each match. \
         Respond with valid JSON only.",
        tenant_id
    );

    let logs_text = if logs.len() > 200 {
        logs[logs.len() - 200..].join("\n")
    } else {
        logs.join("\n")
    };

    let prompt = format!(
        "{kill_chain}\n\
         KNOWN ATTACK CHAINS (match step sequences in temporal order):\n{chains}\n\n\
         MITRE ATT&CK TECHNIQUES (match tags, ports, protocols, behaviors):\n{techs}\n\n\
         RAW NETWORK LOGS (hits + [SESSION] DNS/HTTP/TLS — last 6h):\n{logs}\n\n\
         Instructions:\n\
         - Match logs against chains: check if step sequences appear in order\n\
         - Match logs against techniques: tags like 'half-open-scan'=T1046, beacon intervals=T1071\n\
         - Identify suspicious IPs and behaviors from actual log data\n\
         - Assign Kill Chain stage per match\n\
         - Only include probability >= 0.2\n\
         - If nothing matches return {{\"matches\": [], \"overall_threat\": \"none\"}}\n\n\
         Respond ONLY with this JSON:\n\
         {{\"matches\": [\
           {{\"chain_name\": \"chain or technique name\",\
             \"attack_type\": \"...\",\
             \"probability\": 0.0,\
             \"alert_level\": \"info|medium|high|critical\",\
             \"kill_chain_stage\": 1,\
             \"kill_chain_name\": \"Reconnaissance\",\
             \"kill_chain_next\": \"Weaponization\",\
             \"matched_steps\": [\"evidence with ts and IP\"],\
             \"next_step\": \"likely next attacker action\",\
             \"suspicious_ips\": [\"ip\"],\
             \"matched_iocs\": [],\
             \"matched_techniques\": [\"T-id\"],\
             \"explanation\": \"one sentence\"\
           }}\
         ], \"overall_threat\": \"none|low|medium|high|critical\"}}",
        kill_chain = KILL_CHAIN_CONTEXT,
        chains     = chains.join("\n"),
        techs      = techniques.join("\n"),
        logs       = logs_text,
    );

    generate(ch, UseCase::ThreatPrediction, &system, &prompt).await
}

/// IOC scan: raw log batch vs one IOC batch (IPs, domains, hashes).
async fn ask_ai_batch(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    batch_type: &str,
    items: &[String],
    logs: &[String],
    _sessions: &[String],
) -> String {
    let system = format!(
        "You are ARIA, a network threat detection AI for tenant {}. \
         Check if any IOC (IP, domain, hash, URL) from the provided list appears in the raw network logs. \
         Match source IPs, dest IPs, DNS queries, HTTP hosts, TLS server names, file hashes. \
         Identify the Cyber Kill Chain stage for each match. \
         Respond with valid JSON only.",
        tenant_id
    );

    let logs_text = if logs.len() > 200 {
        logs[logs.len() - 200..].join("\n")
    } else {
        logs.join("\n")
    };

    let _ = batch_type; // always "iocs" now — kept for call-site compatibility

    let prompt = format!(
        "{kill_chain}\n\
         KNOWN MALICIOUS IOCs (IPs, domains, hashes, URLs):\n{items}\n\n\
         RAW NETWORK LOGS (hits + [SESSION] DNS/HTTP/TLS — last 6h):\n{logs}\n\n\
         Check if any IOC value appears as a source IP, dest IP, DNS query domain, \
         HTTP host, TLS server_name, or file hash in the logs above.\n\
         Compute probability (0.0–1.0) per match. Include matches >= 0.2.\n\
         If nothing matches return {{\"matches\": [], \"overall_threat\": \"none\"}}.\n\n\
         Respond ONLY with this JSON:\n\
         {{\"matches\": [\
           {{\"chain_name\": \"IOC match description\",\
             \"attack_type\": \"...\",\
             \"probability\": 0.0,\
             \"alert_level\": \"info|medium|high|critical\",\
             \"kill_chain_stage\": 1,\
             \"kill_chain_name\": \"stage name\",\
             \"kill_chain_next\": \"next stage\",\
             \"matched_steps\": [\"log line evidence\"],\
             \"next_step\": \"likely next attacker action\",\
             \"suspicious_ips\": [\"ip\"],\
             \"matched_iocs\": [\"ioc value\"],\
             \"matched_techniques\": [],\
             \"explanation\": \"one sentence\"\
           }}\
         ], \"overall_threat\": \"none|low|medium|high|critical\"}}",
        kill_chain = KILL_CHAIN_CONTEXT,
        items      = items.join("\n"),
        logs       = if logs_text.is_empty() { "none".to_string() } else { logs_text },
    );

    generate(ch, UseCase::ThreatPrediction, &system, &prompt).await
}

fn consolidate_matches(raw: Vec<Value>) -> Vec<Value> {
    use std::collections::HashMap;
    let mut map: HashMap<String, Value> = HashMap::new();

    for m in raw {
        let prob = m["probability"].as_f64().unwrap_or(0.0);
        if prob < 0.2 { continue; }

        let key = m["attack_type"].as_str().unwrap_or("general_threat").to_string();
        let entry = map.entry(key).or_insert_with(|| m.clone());

        let existing_prob  = entry["probability"].as_f64().unwrap_or(0.0);
        let existing_stage = entry["kill_chain_stage"].as_u64().unwrap_or(0);
        let new_stage      = m["kill_chain_stage"].as_u64().unwrap_or(0);

        if prob > existing_prob || (prob == existing_prob && new_stage > existing_stage) {
            let merge_fields = ["matched_steps", "suspicious_ips", "matched_iocs", "matched_techniques"];
            let mut new_entry = m.clone();
            for field in &merge_fields {
                let mut combined: Vec<Value> = new_entry[field].as_array().cloned().unwrap_or_default();
                if let Some(old_arr) = entry[field].as_array() {
                    combined.extend(old_arr.iter().cloned());
                }
                combined.dedup_by(|a, b| a.as_str() == b.as_str() && !a.as_str().unwrap_or("").is_empty());
                new_entry[field] = Value::Array(combined);
            }
            *entry = new_entry;
        } else {
            let merge_fields = ["matched_steps", "suspicious_ips", "matched_iocs", "matched_techniques"];
            for field in &merge_fields {
                let mut combined: Vec<Value> = entry[field].as_array().cloned().unwrap_or_default();
                if let Some(new_arr) = m[field].as_array() {
                    combined.extend(new_arr.iter().cloned());
                }
                combined.dedup_by(|a, b| a.as_str() == b.as_str() && !a.as_str().unwrap_or("").is_empty());
                entry[field] = Value::Array(combined);
            }
        }
    }

    let mut out: Vec<Value> = map.into_values().collect();
    out.sort_by(|a, b| {
        b["probability"].as_f64().unwrap_or(0.0)
            .partial_cmp(&a["probability"].as_f64().unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn default_recs_for_chain(attack_type: &str) -> Vec<String> {
    match attack_type {
        "ransomware" => vec![
            "Immediately isolate affected hosts from network".into(),
            "Block RDP and SMB at perimeter firewall".into(),
            "Verify backup integrity before ransomware reaches file servers".into(),
        ],
        "credential_attack" => vec![
            "Block source IP at firewall now".into(),
            "Enable MFA on all remote access endpoints".into(),
            "Audit accounts that logged in successfully after failures".into(),
        ],
        "c2_communication" => vec![
            "Isolate hosts showing beacon patterns".into(),
            "Block C2 IPs at DNS and firewall level".into(),
            "Capture PCAP on affected hosts for forensics".into(),
        ],
        "data_exfiltration" => vec![
            "Block large outbound transfers immediately".into(),
            "Identify and isolate the exfiltrating host".into(),
            "Preserve network logs for incident response".into(),
        ],
        _ => vec![
            "Review and correlate related alerts".into(),
            "Increase logging on affected segments".into(),
            "Escalate to incident response team".into(),
        ],
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn is_multicast_or_broadcast(ip: &str) -> bool {
    if ip == "255.255.255.255" { return true; }
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        return addr.is_multicast(); // covers 224.0.0.0/4 including 239.255.255.250
    }
    false
}
