use crate::ai::provider::{generate, UseCase};
use crate::storage::clickhouse::{sql_escape_pub as esc, tenant_db_pub};
use crate::storage::ClickhouseStorage;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AriaVerdict {
    pub verdict:            String, // TRUE_POSITIVE | FALSE_POSITIVE | SUSPICIOUS
    pub confidence:         u8,     // 0-100
    pub reasoning:          String,
    pub recommended_action: String,
    pub mitre_techniques:   Vec<String>,
    pub generated_at:       String,
}

/// Auto-investigate an evidence bundle by community_id.
/// Queries ClickHouse for all available evidence, builds a security prompt,
/// calls the AI via the priority-ordered provider system, and returns a structured verdict.
pub async fn auto_investigate(
    ch:           &ClickhouseStorage,
    tenant_id:    &str,
    community_id: &str,
) -> anyhow::Result<AriaVerdict> {
    info!("aria_investigate: starting for community_id={} tenant={}", community_id, tenant_id);

    let context = gather_context(ch, tenant_id, community_id).await;

    let system = r#"You are a senior SOC analyst with 15 years of experience.
Analyze the provided network security evidence and determine if this is a real attack.

Respond ONLY with a valid JSON object — no prose, no markdown, no code fences:
{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "SUSPICIOUS",
  "confidence": <integer 0-100>,
  "reasoning": "<2-3 sentences explaining your conclusion based on the evidence>",
  "recommended_action": "<one specific, actionable next step>",
  "mitre_techniques": ["T1234", "T5678"]
}

Verdict definitions:
- TRUE_POSITIVE: clear indicators of malicious activity (known-bad IPs, exploit signatures, suspicious behaviour patterns)
- FALSE_POSITIVE: evidence points to legitimate/benign traffic (scanners, monitoring tools, internal probes)
- SUSPICIOUS: ambiguous evidence — could be either; needs more investigation

Base your reasoning ONLY on the provided evidence. Never invent IPs, domains, or event details."#;

    let prompt = format!(
        "Investigate this network security event and return your verdict as JSON.\n\nEVIDENCE:\n{}\n\nJSON verdict:",
        context
    );

    let raw = generate(ch, UseCase::ThreatPrediction, system, &prompt).await;

    match parse_verdict(&raw) {
        Ok(v) => {
            info!(
                "aria_investigate: verdict={} confidence={} for community_id={}",
                v.verdict, v.confidence, community_id
            );
            Ok(v)
        }
        Err(e) => {
            warn!(
                "aria_investigate: failed to parse AI response for {}: {} — raw: {}",
                community_id, e, &raw[..raw.len().min(200)]
            );
            // Return a safe fallback rather than propagating an error
            Ok(AriaVerdict {
                verdict:            "SUSPICIOUS".to_string(),
                confidence:         30,
                reasoning:          "AI investigation inconclusive — response could not be parsed. Manual review required.".to_string(),
                recommended_action: "Review the evidence bundle manually and escalate if needed.".to_string(),
                mitre_techniques:   vec![],
                generated_at:       now_iso(),
            })
        }
    }
}

/// Collect all ClickHouse evidence for this community_id into a text block.
async fn gather_context(
    ch:           &ClickhouseStorage,
    tenant_id:    &str,
    community_id: &str,
) -> String {
    let db  = tenant_db_pub(tenant_id);
    let cid = esc(community_id);
    let mut ctx = String::with_capacity(2048);

    // ── 1. NDR hits (alerts) for this community_id ───────────────────────────
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HitRow {
        rule_name: String,
        severity:  String,
        score:     f64,
        tags:      String,
        src_ip:    String,
        dst_ip:    String,
        timestamp: String,
    }
    if let Ok(hits) = ch.client.query(&format!(
        "SELECT arrayElement(sigma_hits, 1) as rule_name, severity, score,
         arrayStringConcat(tags, ', ') as tags, src_ip, dst_ip,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp
         FROM {db}.ndr_hits
         WHERE community_id = '{cid}'
         ORDER BY timestamp DESC LIMIT 10",
        db = db, cid = cid
    )).fetch_all::<HitRow>().await {
        ctx.push_str("=== ALERTS ===\n");
        if hits.is_empty() {
            ctx.push_str("No alert records found for this community_id.\n");
        }
        for h in &hits {
            ctx.push_str(&format!(
                "[{}] {} severity={} score={:.0} rule=\"{}\" tags={} {} -> {}\n",
                h.timestamp, h.severity, h.severity, h.score,
                h.rule_name, h.tags, h.src_ip, h.dst_ip
            ));
        }
        ctx.push('\n');

        // ── 2. Threat intel check on IPs seen in hits ────────────────────────
        let ips: Vec<String> = hits.iter()
            .flat_map(|h| [h.src_ip.clone(), h.dst_ip.clone()])
            .filter(|ip| !ip.is_empty() && ip != "0.0.0.0")
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if !ips.is_empty() {
            let ip_list = ips.iter()
                .map(|ip| format!("'{}'", esc(ip)))
                .collect::<Vec<_>>()
                .join(",");

            #[derive(clickhouse::Row, serde::Deserialize)]
            struct IntelRow {
                ioc_value:   String,
                attack_type: String,
                severity:    String,
                description: String,
            }
            if let Ok(intel) = ch.client.query(&format!(
                "SELECT ioc_value, attack_type, severity, description
                 FROM ndr.threat_intel
                 WHERE ioc_value IN ({ip_list})
                 AND ioc_type IN ('ip','ip4','ip6')
                 LIMIT 10",
                ip_list = ip_list
            )).fetch_all::<IntelRow>().await {
                if !intel.is_empty() {
                    ctx.push_str("=== THREAT INTEL MATCHES ===\n");
                    for i in &intel {
                        ctx.push_str(&format!(
                            "KNOWN-BAD IP {} — attack_type={} severity={} description={}\n",
                            i.ioc_value, i.attack_type, i.severity, i.description
                        ));
                    }
                    ctx.push('\n');
                }
            }
        }
    }

    // ── 3. Raw network events for this community_id ──────────────────────────
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EventRow {
        source:     String,
        event_type: String,
        src_ip:     String,
        dst_ip:     String,
        src_port:   u16,
        dst_port:   u16,
        proto:      String,
    }
    if let Ok(events) = ch.client.query(&format!(
        "SELECT source, event_type, src_ip, dst_ip, src_port, dst_port, proto
         FROM {db}.ndr_events
         WHERE community_id = '{cid}'
         ORDER BY timestamp DESC LIMIT 20",
        db = db, cid = cid
    )).fetch_all::<EventRow>().await {
        ctx.push_str("=== NETWORK EVENTS ===\n");
        if events.is_empty() {
            ctx.push_str("No raw network events found for this community_id.\n");
        }
        for e in &events {
            ctx.push_str(&format!(
                "source={} type={} {}:{} -> {}:{} proto={}\n",
                e.source, e.event_type,
                e.src_ip, e.src_port,
                e.dst_ip, e.dst_port,
                e.proto
            ));
        }
        ctx.push('\n');
    }

    // ── 4. Evidence bundle metadata ──────────────────────────────────────────
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct BundleRow {
        severity:   String,
        src_ip:     String,
        dst_ip:     String,
        captured_at: String,
    }
    if let Ok(bundles) = ch.client.query(&format!(
        "SELECT severity, src_ip, dst_ip,
         formatDateTime(captured_at, '%Y-%m-%dT%H:%i:%SZ') as captured_at
         FROM {db}.evidence_bundles FINAL
         WHERE community_id = '{cid}'
         LIMIT 1",
        db = db, cid = cid
    )).fetch_all::<BundleRow>().await {
        if let Some(b) = bundles.first() {
            ctx.push_str("=== EVIDENCE BUNDLE ===\n");
            ctx.push_str(&format!(
                "captured_at={} severity={} {} -> {}\n\n",
                b.captured_at, b.severity, b.src_ip, b.dst_ip
            ));
        }
    }

    if ctx.trim().is_empty() {
        ctx.push_str("No evidence found in ClickHouse for this community_id.\n");
    }

    ctx
}

/// Parse the AI JSON response into an AriaVerdict.
fn parse_verdict(raw: &str) -> anyhow::Result<AriaVerdict> {
    // Strip potential markdown code fences the AI might add
    let cleaned = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    // Find the first '{' ... last '}' block
    let start = cleaned.find('{')
        .ok_or_else(|| anyhow::anyhow!("no JSON object found in AI response"))?;
    let end = cleaned.rfind('}')
        .ok_or_else(|| anyhow::anyhow!("no closing brace found in AI response"))?;
    let json_str = &cleaned[start..=end];

    let v: serde_json::Value = serde_json::from_str(json_str)?;

    let verdict = match v["verdict"].as_str().unwrap_or("SUSPICIOUS") {
        "TRUE_POSITIVE"  => "TRUE_POSITIVE",
        "FALSE_POSITIVE" => "FALSE_POSITIVE",
        _                => "SUSPICIOUS",
    }.to_string();

    let confidence = v["confidence"].as_u64().unwrap_or(50).min(100) as u8;

    let reasoning = v["reasoning"]
        .as_str()
        .unwrap_or("No reasoning provided.")
        .to_string();

    let recommended_action = v["recommended_action"]
        .as_str()
        .unwrap_or("Review manually.")
        .to_string();

    let mitre_techniques = v["mitre_techniques"]
        .as_array()
        .map(|a| a.iter().filter_map(|t| t.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    Ok(AriaVerdict {
        verdict,
        confidence,
        reasoning,
        recommended_action,
        mitre_techniques,
        generated_at: now_iso(),
    })
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple ISO 8601 UTC — full chrono is unnecessary here
    let (y, mo, d, h, mi, s) = epoch_to_parts(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

fn epoch_to_parts(epoch: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s   = epoch % 60;
    let mi  = (epoch / 60) % 60;
    let h   = (epoch / 3600) % 24;
    let days = epoch / 86400;
    // Days since 1970-01-01
    let (y, mo, d) = days_to_ymd(days);
    (y, mo, d, h, mi, s)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year: u64 = 1970;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = if leap {
        [31,29,31,30,31,30,31,31,30,31,30,31]
    } else {
        [31,28,31,30,31,30,31,31,30,31,30,31]
    };
    let mut month: u64 = 1;
    for &md in &month_days {
        if days < md { break; }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
