use crate::ai::provider::{generate, UseCase};
use crate::storage::clickhouse::{sql_escape_pub as esc, tenant_db_pub};
use crate::storage::ClickhouseStorage;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AriaVerdict {
    pub verdict:            String, // TRUE_POSITIVE | FALSE_POSITIVE | SUSPICIOUS
    pub confidence:         u8,     // 0-100
    pub reasoning:          String,
    pub recommended_action: String,
    pub mitre_techniques:   Vec<String>,
    pub generated_at:       String,
}

/// What the stored evidence itself says, independent of the AI's opinion. Used to check the verdict.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EvidenceFacts {
    pub alerts:      usize,
    /// Raw network events stored for the session.
    pub events:      usize,
    pub max_score:   f64,
    /// An address in the session is in the threat-intel feed.
    pub intel_match: bool,
    /// Every alert is chatter (trusted service, or below the chatter score).
    pub all_chatter: bool,
}

/// Score from which an alert counts as more than chatter (same line the briefing uses).
const STRONG_SCORE: f64 = 60.0;

impl EvidenceFacts {
    pub fn has_evidence(&self) -> bool { self.alerts > 0 || self.events > 0 }
}

/// What to say when nothing is stored for the session. The AI is not asked: with no evidence it tends to
/// answer "no alerts, so benign", which is the opposite of an honest "I cannot tell".
pub fn no_evidence_verdict() -> AriaVerdict {
    AriaVerdict {
        verdict:            "SUSPICIOUS".to_string(),
        confidence:         10,
        reasoning:          "No alerts or network events are stored for this session any more, so it cannot be judged. This is not a sign that it was harmless.".to_string(),
        recommended_action: "Check the original alert or the evidence bundle if one was kept.".to_string(),
        mitre_techniques:   vec![],
        generated_at:       now_iso(),
    }
}

/// The AI's verdict must not go further than the evidence allows, in either direction:
/// - TRUE_POSITIVE needs a threat-intel match or a strong, non-chatter detection;
/// - FALSE_POSITIVE is never allowed when an address is in the threat-intel feed.
/// A verdict that is pulled back becomes SUSPICIOUS (an analyst decides) and says why.
pub fn guard(mut v: AriaVerdict, e: &EvidenceFacts) -> AriaVerdict {
    if v.verdict == "TRUE_POSITIVE" && !e.intel_match && (e.all_chatter || e.max_score < STRONG_SCORE) {
        v.verdict = "SUSPICIOUS".to_string();
        v.confidence = v.confidence.min(55);
        v.reasoning = format!("{} [Checked against the evidence: no threat-intel match and no strong detection, so this is not called a confirmed attack.]", v.reasoning);
    } else if v.verdict == "FALSE_POSITIVE" && e.intel_match {
        v.verdict = "SUSPICIOUS".to_string();
        v.confidence = v.confidence.min(55);
        v.reasoning = format!("{} [Checked against the evidence: an address in this session is in the threat-intel feed, so it is not dismissed as a false positive.]", v.reasoning);
    }
    v
}

/// The AI's answer as a verdict. An empty answer means no provider is configured or none responded:
/// that is an error, not a verdict, so nothing is stored.
fn verdict_from_reply(raw: &str, community_id: &str) -> anyhow::Result<AriaVerdict> {
    if raw.trim().is_empty() {
        anyhow::bail!("No AI provider answered. Add or fix one in Settings > AI Configuration.");
    }
    match parse_verdict(raw) {
        Ok(v) => Ok(v),
        Err(e) => {
            warn!(
                "aria_investigate: failed to parse AI response for {}: {} — raw: {}",
                community_id, e, &raw[..raw.len().min(200)]
            );
            // A safe fallback rather than an error: the model did answer, just not in the expected shape
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

/// Auto-investigate an evidence bundle by community_id.
/// Queries ClickHouse for all available evidence, builds a security prompt,
/// calls the AI via the priority-ordered provider system, and returns a structured verdict.
pub async fn auto_investigate(
    ch:           &ClickhouseStorage,
    tenant_id:    &str,
    community_id: &str,
) -> anyhow::Result<AriaVerdict> {
    info!("aria_investigate: starting for community_id={} tenant={}", community_id, tenant_id);

    let (context, evidence) = gather_context(ch, tenant_id, community_id).await;
    if !evidence.has_evidence() {
        info!("aria_investigate: no stored evidence for community_id={} — not asking the AI", community_id);
        return Ok(no_evidence_verdict());
    }

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

    let v = guard(verdict_from_reply(&raw, community_id)?, &evidence);
    info!("aria_investigate: verdict={} confidence={} for community_id={}", v.verdict, v.confidence, community_id);

    // Fire-and-forget: the embedding call (~1-2s) and Qdrant upsert are never a reason to make
    // the analyst wait longer for their verdict. Indexing is best-effort either way (see
    // index_for_similarity's doc comment), so there is nothing the caller needs to await here.
    let (ch_bg, tenant_bg, cid_bg, v_bg) = (ch.clone(), tenant_id.to_string(), community_id.to_string(), v.clone());
    tokio::spawn(async move {
        if let Err(e) = index_for_similarity(&ch_bg, &tenant_bg, &cid_bg, &v_bg).await {
            warn!("aria_investigate: similarity indexing skipped for {}: {}", cid_bg, e);
        }
    });

    Ok(v)
}

/// Embeds this verdict and stores it in this tenant's RAG collection, so a future
/// investigation can be told "this looked like these N past cases, here's how those went".
async fn index_for_similarity(
    ch: &ClickhouseStorage,
    tenant_id: &str,
    community_id: &str,
    v: &AriaVerdict,
) -> anyhow::Result<()> {
    let rows = ch.session_alert_rows(tenant_id, &[], community_id).await;
    let top = rows.iter()
        .max_by(|a, b| a["score"].as_f64().unwrap_or(0.0).partial_cmp(&b["score"].as_f64().unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));
    let inv = crate::ai::rag::IndexedInvestigation {
        community_id: community_id.to_string(),
        verdict:      v.verdict.clone(),
        confidence:   v.confidence,
        severity:     top.and_then(|r| r["severity"].as_str()).unwrap_or("").to_string(),
        src_ip:       top.and_then(|r| r["src_ip"].as_str()).unwrap_or("").to_string(),
        dst_ip:       top.and_then(|r| r["dst_ip"].as_str()).unwrap_or("").to_string(),
        reasoning:    v.reasoning.clone(),
        sensor_id:    top.and_then(|r| r["sensor_id"].as_str()).unwrap_or("").to_string(),
        generated_at: v.generated_at.clone(),
    };
    crate::ai::rag::index_investigation(&ch.client, tenant_id, &inv).await
}

/// What to search the RAG index with for "incidents similar to this one": the stored verdict's
/// own reasoning when this session already has one (richest signal), otherwise a short
/// description built from its stored alerts. `None` only when nothing at all is stored for the
/// session — callers treat that as "nothing to compare, no similar incidents to show".
pub async fn similarity_query_text(ch: &ClickhouseStorage, tenant_id: &str, community_id: &str) -> Option<String> {
    if let Some(v) = ch.get_aria_verdict(tenant_id, community_id).await {
        let verdict = v["verdict"].as_str().unwrap_or("");
        let reasoning = v["reasoning"].as_str().unwrap_or("");
        if !reasoning.is_empty() {
            return Some(format!("{community_id} verdict={verdict} — {reasoning}"));
        }
    }
    let rows = ch.session_alert_rows(tenant_id, &[], community_id).await;
    let top = rows.iter()
        .max_by(|a, b| a["score"].as_f64().unwrap_or(0.0).partial_cmp(&b["score"].as_f64().unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal))?;
    let tags = top["tags"].as_array().map(|a| a.iter().filter_map(|t| t.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    Some(format!(
        "{} -> {} severity={} tags={}",
        top["src_ip"].as_str().unwrap_or(""), top["dst_ip"].as_str().unwrap_or(""),
        top["severity"].as_str().unwrap_or(""), tags
    ))
}

/// Collect all ClickHouse evidence for this community_id into a text block.
async fn gather_context(
    ch:           &ClickhouseStorage,
    tenant_id:    &str,
    community_id: &str,
) -> (String, EvidenceFacts) {
    let db  = tenant_db_pub(tenant_id);
    let cid = esc(community_id);
    let mut ctx = String::with_capacity(2048);
    let mut facts = EvidenceFacts::default();

    // ── 1. NDR hits (alerts) for this community_id ───────────────────────────
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HitRow {
        rule_name: String,
        severity:  String,
        score:     f64,
        tags:      String, // comma-joined
        src_ip:    String,
        dst_ip:    String,
        timestamp: String,
    }
    if let Ok(hits) = ch.client.query(&format!(
        "SELECT arrayElement(sigma_hits, 1) as rule_name, severity, toFloat64(score) AS score,
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
        facts.alerts = hits.len();
        facts.max_score = hits.iter().map(|h| h.score).fold(0.0, f64::max);
        facts.all_chatter = !hits.is_empty()
            && hits.iter().all(|h| h.tags.contains("trusted-cloud") || h.score < STRONG_SCORE - 20.0);

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
                    facts.intel_match = true;
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
        facts.events = events.len();
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

    (ctx, facts)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v(verdict: &str, confidence: u8) -> AriaVerdict {
        AriaVerdict { verdict: verdict.into(), confidence, reasoning: "because".into(),
            recommended_action: "act".into(), mitre_techniques: vec![], generated_at: "t".into() }
    }
    fn ev(intel: bool, max: f64, chatter: bool) -> EvidenceFacts {
        EvidenceFacts { alerts: 3, events: 0, max_score: max, intel_match: intel, all_chatter: chatter }
    }

    #[test]
    fn a_confirmed_attack_needs_evidence_to_stand() {
        // the AI says TRUE_POSITIVE 95% about DNS chatter: pulled back and explained
        let g = guard(v("TRUE_POSITIVE", 95), &ev(false, 20.0, true));
        assert_eq!((g.verdict.as_str(), g.confidence), ("SUSPICIOUS", 55));
        assert!(g.reasoning.contains("not called a confirmed attack"));
        // a weak score alone is not enough either
        assert_eq!(guard(v("TRUE_POSITIVE", 90), &ev(false, 45.0, false)).verdict, "SUSPICIOUS");
        // a strong detection stands
        assert_eq!(guard(v("TRUE_POSITIVE", 90), &ev(false, 85.0, false)).verdict, "TRUE_POSITIVE");
        // a threat-intel match stands even at a low score
        assert_eq!(guard(v("TRUE_POSITIVE", 90), &ev(true, 30.0, false)).verdict, "TRUE_POSITIVE");
    }

    #[test]
    fn a_session_with_a_known_bad_address_is_never_dismissed() {
        let g = guard(v("FALSE_POSITIVE", 99), &ev(true, 80.0, false));
        assert_eq!((g.verdict.as_str(), g.confidence), ("SUSPICIOUS", 55));
        assert!(g.reasoning.contains("threat-intel feed"));
        // without an intel match a false-positive verdict stands
        assert_eq!(guard(v("FALSE_POSITIVE", 80), &ev(false, 20.0, true)).verdict, "FALSE_POSITIVE");
        // SUSPICIOUS is never changed
        assert_eq!(guard(v("SUSPICIOUS", 40), &ev(true, 90.0, false)), v("SUSPICIOUS", 40));
    }

    #[test]
    fn a_session_with_nothing_stored_is_inconclusive_never_benign() {
        assert!(!EvidenceFacts::default().has_evidence());
        assert!(EvidenceFacts { events: 1, ..Default::default() }.has_evidence());
        let v = no_evidence_verdict();
        assert_eq!((v.verdict.as_str(), v.confidence), ("SUSPICIOUS", 10));
        assert!(v.reasoning.contains("not a sign that it was harmless"));
    }

    #[test]
    fn no_answer_from_the_ai_is_an_error_not_a_fake_verdict() {
        let e = verdict_from_reply("   ", "1:abc").unwrap_err().to_string();
        assert!(e.contains("Settings > AI Configuration"), "{e}");
        // an answer in the wrong shape is inconclusive, never confident
        let odd = verdict_from_reply("I think it is fine", "1:abc").unwrap();
        assert_eq!((odd.verdict.as_str(), odd.confidence), ("SUSPICIOUS", 30));
        // a proper answer is used, with the model's fields clamped
        let ok = verdict_from_reply(r#"```json
{"verdict":"FALSE_POSITIVE","confidence":250,"reasoning":"ISP DNS","recommended_action":"none","mitre_techniques":["T1071"]}
```"#, "1:abc").unwrap();
        assert_eq!((ok.verdict.as_str(), ok.confidence, ok.mitre_techniques.len()), ("FALSE_POSITIVE", 100, 1));
        // an unknown verdict word becomes SUSPICIOUS
        assert_eq!(verdict_from_reply(r#"{"verdict":"DEFINITELY_BAD","confidence":90}"#, "c").unwrap().verdict, "SUSPICIOUS");
    }

    // Against a real ClickHouse (a throwaway tenant database that is dropped at the end):
    //   CLICKHOUSE_URL=... CLICKHOUSE_USER=... CLICKHOUSE_PASSWORD=... \
    //   cargo test -p ndr-engine investigator_evidence -- --ignored
    #[tokio::test]
    #[ignore]
    async fn investigator_evidence_facts_come_from_the_stored_alerts() {
        let ch = ClickhouseStorage::new();
        let tenant = "zz_investest";
        let db = tenant_db_pub(tenant);
        let run = |q: String| { let c = ch.client.clone(); async move { c.query(&q).execute().await.unwrap() } };
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
        run(format!("CREATE DATABASE {db}")).await;
        run(format!("CREATE TABLE {db}.ndr_hits (community_id String, src_ip String, dst_ip String, severity String, score Float64, \
             tags Array(String), sigma_hits Array(String), timestamp DateTime) ENGINE = MergeTree ORDER BY timestamp")).await;
        // session A: DNS chatter to a trusted service; session B: a strong detection
        for i in 0..3 {
            run(format!("INSERT INTO {db}.ndr_hits VALUES ('A','10.0.2.15','192.0.2.53','LOW',20,['trusted-cloud'],['dns'],now() - {i})")).await;
        }
        run(format!("INSERT INTO {db}.ndr_hits VALUES ('B','10.0.9.9','192.0.2.99','HIGH',85,['ids-alert'],['et-trojan'],now())")).await;
        run(format!("INSERT INTO {db}.ndr_hits VALUES ('B','10.0.9.9','192.0.2.99','LOW',20,['trusted-cloud'],['dns'],now())")).await;

        let (ctx_a, a) = gather_context(&ch, tenant, "A").await;
        assert_eq!((a.alerts, a.max_score, a.all_chatter, a.intel_match), (3, 20.0, true, false));
        assert!(ctx_a.contains("=== ALERTS ==="));
        let (_, b) = gather_context(&ch, tenant, "B").await;
        assert_eq!((b.alerts, b.max_score, b.all_chatter), (2, 85.0, false), "one strong alert in the session means it is not all chatter");
        let (ctx_none, none) = gather_context(&ch, tenant, "nope").await;
        assert_eq!(none, EvidenceFacts::default());
        assert!(!none.has_evidence(), "an unknown session has no evidence, so the AI is never asked");
        assert_eq!(a.events, 0);
        assert!(ctx_none.contains("No alert records found"));
        // and the guard turns the AI's over-confident claim about chatter into a plain suspicion
        assert_eq!(guard(v("TRUE_POSITIVE", 95), &a).verdict, "SUSPICIOUS");
        assert_eq!(guard(v("TRUE_POSITIVE", 95), &b).verdict, "TRUE_POSITIVE");
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
    }
}
