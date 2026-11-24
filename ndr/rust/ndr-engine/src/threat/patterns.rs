use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{info, warn};

pub fn spawn_pattern_sync(
    ch: Arc<crate::storage::ClickhouseStorage>,
    chain_trigger: Arc<Notify>,
    redis: Arc<redis::Client>,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
            sync_mitre_attack(&ch, &redis).await;
            chain_trigger.notify_one();
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(7 * 24 * 3600)).await;
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                sync_mitre_attack(&ch, &redis).await;
                chain_trigger.notify_one();
            }
        }
    });
}

pub async fn sync_mitre_attack(ch: &crate::storage::ClickhouseStorage, redis: &redis::Client) {
    info!("Syncing MITRE ATT&CK patterns...");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent("NDR-Engine/1.0")
        .build()
        .unwrap_or_default();

    let url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

    let resp = match http.get(url).send().await {
        Ok(r) => r,
        Err(e) => { warn!("Failed to fetch MITRE ATT&CK: {}", e); build_attack_chains(ch, redis).await; return; }
    };

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(e) => { warn!("Failed to parse MITRE ATT&CK JSON: {}", e); build_attack_chains(ch, redis).await; return; }
    };

    let objects = data["objects"].as_array().cloned().unwrap_or_default();
    let mut count = 0u32;

    for obj in &objects {
        if obj["type"].as_str() != Some("attack-pattern") { continue; }
        if obj["x_mitre_deprecated"].as_bool().unwrap_or(false) { continue; }

        let name = obj["name"].as_str().unwrap_or("").to_string();

        let technique_id = obj["external_references"]
            .as_array().unwrap_or(&vec![])
            .iter()
            .find(|r| r["source_name"].as_str() == Some("mitre-attack"))
            .and_then(|r| r["external_id"].as_str())
            .unwrap_or("")
            .to_string();

        if technique_id.is_empty() || !technique_id.starts_with('T') { continue; }

        let tactic = obj["kill_chain_phases"]
            .as_array().unwrap_or(&vec![])
            .iter()
            .filter_map(|p| p["phase_name"].as_str())
            .collect::<Vec<_>>()
            .join(",");

        let description = obj["description"].as_str().unwrap_or("")
            .chars().take(500).collect::<String>();

        let detection = obj["x_mitre_detection"].as_str().unwrap_or("")
            .chars().take(300).collect::<String>();

        let platforms = obj["x_mitre_platforms"]
            .as_array().unwrap_or(&vec![])
            .iter()
            .filter_map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(",");

        let phase = tactic_to_phase(&tactic);
        let severity = match phase {
            6 | 7 => "CRITICAL",
            4 | 5 => "HIGH",
            _     => "MEDIUM",
        };

        let q = format!(
            "INSERT INTO ndr.attack_patterns \
             (technique_id, technique_name, tactic, description, detection, platforms, kill_chain_phase, severity) \
             VALUES ('{}','{}','{}','{}','{}','{}',{},'{}')",
            esc(&technique_id), esc(&name), esc(&tactic),
            esc(&description), esc(&detection), esc(&platforms),
            phase, severity
        );
        let _ = ch.client.query(&q).execute().await;
        count += 1;
    }

    info!("MITRE ATT&CK: {} techniques synced", count);
    build_attack_chains(ch, redis).await;
    build_dynamic_chains_from_mitre(ch, &objects, redis).await;
}

fn tactic_to_phase(tactic: &str) -> u8 {
    if tactic.contains("reconnaissance")       { 1 }
    else if tactic.contains("resource-development") { 2 }
    else if tactic.contains("initial-access")  { 3 }
    else if tactic.contains("execution")       { 4 }
    else if tactic.contains("persistence")
        || tactic.contains("privilege-escalation")
        || tactic.contains("defense-evasion")
        || tactic.contains("credential-access")
        || tactic.contains("lateral-movement") { 5 }
    else if tactic.contains("command-and-control") { 6 }
    else if tactic.contains("exfiltration")
        || tactic.contains("impact")           { 7 }
    else                                       { 3 }
}

async fn build_attack_chains(ch: &crate::storage::ClickhouseStorage, redis: &redis::Client) {
    // Distributed seed lock — only one engine runs DELETE+INSERT at a time.
    // SET NX PX: atomically set only if not exists, expire after 60s.
    // If another engine holds the lock, skip; it will seed the correct data.
    if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
        let acquired: bool = redis::cmd("SET")
            .arg("ndr:seed_lock:attack_chains_builtin")
            .arg("1")
            .arg("NX")
            .arg("PX").arg(60_000u64)
            .query_async(&mut conn)
            .await
            .unwrap_or(false);
        if !acquired {
            tracing::debug!("attack_chains builtin seed locked by another engine — skipping");
            return;
        }
    }

    // Delete old builtin chains and rebuild. mutations_sync=1 replaces a fixed
    // 2s sleep that was standing in for "wait until the async delete is
    // actually applied" - a guess, not a guarantee, and slower than necessary
    // whenever the mutation finishes sooner.
    let _ = ch.client.query("ALTER TABLE ndr.attack_chains DELETE WHERE source = 'builtin' SETTINGS mutations_sync=1")
        .execute().await;

    let chains: &[(&str, &str, &str, &str, u8, &str, serde_json::Value)] = &[
        (
            "ransomware_deployment",
            "Ransomware Deployment",
            "ransomware",
            "LockBit/Conti/BlackCat",
            24,
            "CRITICAL",
            serde_json::json!([
                {"step":1,"technique":"T1595","name":"Active Scanning",         "signal":"port_scan",          "required":true},
                {"step":2,"technique":"T1190","name":"Exploit Public App",       "signal":"exploitation_alert", "required":false},
                {"step":3,"technique":"T1133","name":"External Remote Services", "signal":"rdp_or_vpn_auth",    "required":true},
                {"step":4,"technique":"T1059","name":"Command Scripting",        "signal":"script_execution",   "required":false},
                {"step":5,"technique":"T1021","name":"SMB Lateral Movement",     "signal":"smb_lateral",        "required":true},
                {"step":6,"technique":"T1486","name":"Data Encrypted for Impact","signal":"ransomware_activity","required":true}
            ]),
        ),
        (
            "credential_to_takeover",
            "Credential Attack → Account Takeover",
            "credential_attack",
            "Generic/APT28",
            12,
            "HIGH",
            serde_json::json!([
                {"step":1,"technique":"T1110",    "name":"Brute Force",           "signal":"failed_logins",              "required":true},
                {"step":2,"technique":"T1110.003","name":"Password Spraying",     "signal":"spray_pattern",              "required":false},
                {"step":3,"technique":"T1078",    "name":"Valid Accounts",         "signal":"successful_login_after_fail","required":true},
                {"step":4,"technique":"T1098",    "name":"Account Manipulation",  "signal":"privilege_change",           "required":false},
                {"step":5,"technique":"T1548",    "name":"Abuse Elevation Control","signal":"privilege_escalation",      "required":false}
            ]),
        ),
        (
            "apt_intrusion",
            "APT Slow Intrusion",
            "c2_communication",
            "APT generic",
            168,
            "CRITICAL",
            serde_json::json!([
                {"step":1,"technique":"T1566","name":"Phishing",              "signal":"phishing_alert",  "required":false},
                {"step":2,"technique":"T1204","name":"User Execution",        "signal":"script_execution","required":false},
                {"step":3,"technique":"T1071","name":"C2 Communication",      "signal":"c2_beacon",       "required":true},
                {"step":4,"technique":"T1082","name":"System Discovery",      "signal":"recon_internal",  "required":false},
                {"step":5,"technique":"T1021","name":"Remote Services",       "signal":"smb_lateral",     "required":true},
                {"step":6,"technique":"T1041","name":"Exfiltration Over C2",  "signal":"large_outbound",  "required":true}
            ]),
        ),
        (
            "data_exfiltration",
            "Data Theft and Exfiltration",
            "data_exfiltration",
            "Generic",
            48,
            "CRITICAL",
            serde_json::json!([
                {"step":1,"technique":"T1083","name":"File and Dir Discovery",   "signal":"recon_internal", "required":false},
                {"step":2,"technique":"T1071","name":"C2 / Staging Channel",     "signal":"c2_beacon",      "required":false},
                {"step":3,"technique":"T1560","name":"Archive Collected Data",   "signal":"compression",    "required":false},
                {"step":4,"technique":"T1041","name":"Exfiltration Over C2",     "signal":"large_outbound", "required":true}
            ]),
        ),
        (
            "supply_chain_attack",
            "Supply Chain Compromise",
            "supply_chain",
            "SolarWinds-style",
            240, // capped at u8 max range; actual attacks span months
            "CRITICAL",
            serde_json::json!([
                {"step":1,"technique":"T1195","name":"Supply Chain Compromise",    "signal":"new_external_connection","required":true},
                {"step":2,"technique":"T1036","name":"Masquerading",              "signal":"unusual_process",        "required":false},
                {"step":3,"technique":"T1071","name":"C2 via Legitimate Protocol","signal":"dns_c2_pattern",         "required":true},
                {"step":4,"technique":"T1530","name":"Data from Cloud Storage",   "signal":"large_outbound",         "required":false}
            ]),
        ),
    ];

    for (chain_id, name, attack_type, actor, duration, severity, steps) in chains {
        let steps_str = serde_json::to_string(steps).unwrap_or_default();
        let q = format!(
            "INSERT INTO ndr.attack_chains \
             (chain_id, chain_name, attack_type, threat_actor, severity, \
              typical_duration_hours, steps, source) \
             VALUES ('{}','{}','{}','{}','{}',{},'{}','builtin')",
            esc(chain_id), esc(name), esc(attack_type), esc(actor), severity,
            duration, esc(&steps_str)
        );
        let _ = ch.client.query(&q).execute().await;
    }
    info!("Built {} attack chain definitions", chains.len());
}

/// Build attack chains dynamically from real MITRE APT group TTPs.
/// Each APT group that uses ≥3 techniques gets its own chain, ordered
/// by kill-chain phase so steps are in realistic attack sequence.
async fn build_dynamic_chains_from_mitre(
    ch: &crate::storage::ClickhouseStorage,
    objects: &[serde_json::Value],
    redis: &redis::Client,
) {
    // Distributed seed lock — same pattern as build_attack_chains
    if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
        let acquired: bool = redis::cmd("SET")
            .arg("ndr:seed_lock:attack_chains_mitre")
            .arg("1")
            .arg("NX")
            .arg("PX").arg(120_000u64) // 2 min — dynamic build takes longer
            .query_async(&mut conn)
            .await
            .unwrap_or(false);
        if !acquired {
            tracing::debug!("attack_chains mitre_cti seed locked by another engine — skipping");
            return;
        }
    }

    // Delete stale dynamic chains before rebuilding. mutations_sync=1 replaces
    // the same fixed-sleep-as-a-guess pattern as the builtin-chains delete above.
    let _ = ch.client
        .query("ALTER TABLE ndr.attack_chains DELETE WHERE source = 'mitre_cti' SETTINGS mutations_sync=1")
        .execute().await;

    // Map: STIX ID (attack-pattern) → T-number (e.g. "T1071")
    let mut stix_to_technique: std::collections::HashMap<String, String> = Default::default();
    for obj in objects {
        if obj["type"].as_str() != Some("attack-pattern") { continue; }
        let stix_id = obj["id"].as_str().unwrap_or("").to_string();
        let t_id = obj["external_references"]
            .as_array().unwrap_or(&vec![])
            .iter()
            .find(|r| r["source_name"].as_str() == Some("mitre-attack"))
            .and_then(|r| r["external_id"].as_str())
            .unwrap_or("").to_string();
        if !stix_id.is_empty() && !t_id.is_empty() {
            stix_to_technique.insert(stix_id, t_id);
        }
    }

    // Map: STIX ID (intrusion-set) → (group_name, mitre_group_id e.g. "G0007")
    let mut groups: std::collections::HashMap<String, (String, String)> = Default::default();
    for obj in objects {
        if obj["type"].as_str() != Some("intrusion-set") { continue; }
        let stix_id  = obj["id"].as_str().unwrap_or("").to_string();
        let name     = obj["name"].as_str().unwrap_or("").to_string();
        let group_id = obj["external_references"]
            .as_array().unwrap_or(&vec![])
            .iter()
            .find(|r| r["source_name"].as_str() == Some("mitre-attack"))
            .and_then(|r| r["external_id"].as_str())
            .unwrap_or("").to_string();
        if !stix_id.is_empty() && !name.is_empty() {
            groups.insert(stix_id, (name, group_id));
        }
    }

    // Collect techniques per group via "uses" relationships
    let mut group_techniques: std::collections::HashMap<String, Vec<String>> = Default::default();
    for obj in objects {
        if obj["type"].as_str() != Some("relationship") { continue; }
        if obj["relationship_type"].as_str() != Some("uses") { continue; }
        let source = obj["source_ref"].as_str().unwrap_or("").to_string();
        let target = obj["target_ref"].as_str().unwrap_or("").to_string();
        if !groups.contains_key(&source) { continue; }
        if let Some(t_id) = stix_to_technique.get(&target) {
            group_techniques.entry(source).or_default().push(t_id.clone());
        }
    }

    let mut chains_built = 0u32;

    for (group_stix_id, mut techniques) in group_techniques {
        if techniques.len() < 3 { continue; }

        let Some((group_name, group_id)) = groups.get(&group_stix_id) else { continue };

        // Deduplicate and sort by kill-chain phase — recon first, impact last
        techniques.dedup();
        techniques.sort_by_key(|t| technique_phase(t));
        techniques.truncate(8);

        // Build steps JSON — techniques in phase order
        let steps: Vec<serde_json::Value> = techniques.iter().enumerate().map(|(i, t_id)| {
            let signal   = technique_to_signal(t_id);
            let required = technique_phase(t_id) >= 5; // execution and beyond = required
            serde_json::json!({
                "step":      i + 1,
                "technique": t_id,
                "name":      t_id,  // chain_matcher looks up full name via attack_patterns
                "signal":    signal,
                "required":  required,
            })
        }).collect();

        let attack_type = determine_attack_type(&techniques);
        let chain_id    = format!("dynamic_{}", group_id.to_lowercase().replace('-', "_"));
        let steps_json  = serde_json::to_string(&steps).unwrap_or_default();
        let chain_name  = format!("{} TTPs", group_name);

        let q = format!(
            "INSERT INTO ndr.attack_chains \
             (chain_id, chain_name, attack_type, threat_actor, severity, \
              typical_duration_hours, steps, source, mitre_group_id, is_dynamic) \
             VALUES ('{}','{}','{}','{}','HIGH',168,'{}','mitre_cti','{}',1)",
            esc(&chain_id),
            esc(&chain_name),
            attack_type,
            esc(group_name),
            esc(&steps_json),
            esc(group_id),
        );
        let _ = ch.client.query(&q).execute().await;
        chains_built += 1;

        if chains_built >= 30 { break; } // cap to avoid noise
    }

    info!("Built {} dynamic chains from MITRE group TTPs", chains_built);
}

/// Kill-chain phase for a technique prefix — used to sort steps in attack order
fn technique_phase(t: &str) -> u8 {
    if      t.starts_with("T1595") || t.starts_with("T1590") || t.starts_with("T1589") { 1 }
    else if t.starts_with("T1585") || t.starts_with("T1586") || t.starts_with("T1583") { 2 }
    else if t.starts_with("T1566") || t.starts_with("T1190") || t.starts_with("T1133")
         || t.starts_with("T1195") || t.starts_with("T1091") { 3 }
    else if t.starts_with("T1059") || t.starts_with("T1204") || t.starts_with("T1203") { 4 }
    else if t.starts_with("T1547") || t.starts_with("T1053") || t.starts_with("T1078")
         || t.starts_with("T1021") || t.starts_with("T1570") || t.starts_with("T1110")
         || t.starts_with("T1003") || t.starts_with("T1548") { 5 }
    else if t.starts_with("T1071") || t.starts_with("T1095") || t.starts_with("T1102")
         || t.starts_with("T1008") || t.starts_with("T1105") { 6 }
    else if t.starts_with("T1041") || t.starts_with("T1048") || t.starts_with("T1486")
         || t.starts_with("T1485") || t.starts_with("T1498") { 7 }
    else { 4 }
}

/// Map a MITRE technique prefix to a chain-matcher signal keyword
fn technique_to_signal(t_id: &str) -> &'static str {
    if      t_id.starts_with("T1595") || t_id.starts_with("T1046") { "port_scan" }
    else if t_id.starts_with("T1566")                               { "phishing_alert" }
    else if t_id.starts_with("T1190") || t_id.starts_with("T1203") { "exploitation_alert" }
    else if t_id.starts_with("T1059") || t_id.starts_with("T1204") { "script_execution" }
    else if t_id.starts_with("T1071") || t_id.starts_with("T1095") { "c2_beacon" }
    else if t_id.starts_with("T1021")                               { "smb_lateral" }
    else if t_id.starts_with("T1110") || t_id.starts_with("T1078") { "failed_logins" }
    else if t_id.starts_with("T1003")                               { "failed_logins" }
    else if t_id.starts_with("T1041") || t_id.starts_with("T1048") { "large_outbound" }
    else if t_id.starts_with("T1486") || t_id.starts_with("T1485") { "ransomware_activity" }
    else if t_id.starts_with("T1547") || t_id.starts_with("T1053") { "privilege_escalation" }
    else if t_id.starts_with("T1082") || t_id.starts_with("T1083") { "recon_internal" }
    else                                                             { "suspicious" }
}

/// Determine the primary attack type for a group based on their technique set
fn determine_attack_type(techniques: &[String]) -> &'static str {
    let has_ransom  = techniques.iter().any(|t| t.starts_with("T1486") || t.starts_with("T1490"));
    let has_exfil   = techniques.iter().any(|t| t.starts_with("T1041") || t.starts_with("T1048"));
    let has_c2      = techniques.iter().any(|t| t.starts_with("T1071") || t.starts_with("T1095"));
    let has_creds   = techniques.iter().any(|t| t.starts_with("T1110") || t.starts_with("T1003"));
    let has_lateral = techniques.iter().any(|t| t.starts_with("T1021") || t.starts_with("T1570"));

    if has_ransom                        { "ransomware" }
    else if has_exfil && has_c2         { "data_exfiltration" }
    else if has_c2 && has_lateral       { "c2_communication" }
    else if has_creds                   { "credential_attack" }
    else if has_c2                      { "c2_communication" }
    else                                { "general_threat" }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
