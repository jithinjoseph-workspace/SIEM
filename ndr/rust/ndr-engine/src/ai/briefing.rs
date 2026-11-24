//! The AI Briefing on the AI Activity page: a short "what happened and what needs attention" note.
//!
//! The numbers and names in it are FACTS read from this tenant's own data (`gather`). The AI only
//! phrases them. Its answer is checked against those facts (`compose`): a reply that mentions an
//! address the facts do not contain, or an alarming word the facts do not support, is thrown away
//! and the plain fact summary is shown instead. With no AI provider configured the page still
//! gets the fact summary, so it is never empty.
//!
//! The finished briefing is cached in Valkey for a few minutes, so all engines share one copy and one AI call.
//!
//! Alerts that are only chatter (low score, or traffic to a trusted service) are left out of the
//! "hosts to look at" and "rules" lists. They still count in the severity totals.

use crate::ai::provider::UseCase;
use crate::storage::clickhouse::{sensor_filter_pub, tenant_db_pub};
use crate::storage::ClickhouseStorage;
use provigil_common::ai::{generate_with_providers, AiProvider};
use serde::Serialize;
use redis::aio::MultiplexedConnection;

/// Score below which an alert is treated as chatter when ranking hosts and rules.
pub const MEANINGFUL_SCORE: u32 = 40;
const CACHE_SECS: u64 = 180;
const FORCE_MIN_AGE_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HostFact {
    pub ip: String,
    pub alerts: u64,
    pub top_severity: String,
    pub max_score: u32,
    pub destinations: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RuleFact {
    pub rule: String,
    pub alerts: u64,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct Facts {
    pub window_hours: u32,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub total_alerts: u64,
    pub meaningful_alerts: u64,
    pub top_hosts: Vec<HostFact>,
    pub top_rules: Vec<RuleFact>,
    pub ai_analyses: u64,
    pub open_cases: u64,
    pub active_suppressions: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Briefing {
    pub text: String,
    /// "ai" when the AI's wording was used, "facts" for the plain fact summary.
    pub source: &'static str,
    /// Why the plain summary was used: "not_configured", "disabled", "rejected" or "".
    pub reason: &'static str,
    pub facts: Facts,
    pub generated_at: String,
}

// ── Facts ────────────────────────────────────────────────────────────────────

/// The queries behind `gather`, one string each so a test can run them against a real database.
pub fn severity_query(db: &str, sf: &str, hours: u32) -> String {
    format!(
        "SELECT severity, count() FROM {db}.ndr_hits \
         WHERE timestamp >= now() - INTERVAL {hours} HOUR{sf} GROUP BY severity"
    )
}

fn meaningful(db: &str, sf: &str, hours: u32) -> String {
    format!(
        "FROM {db}.ndr_hits WHERE timestamp >= now() - INTERVAL {hours} HOUR{sf} \
         AND score >= {MEANINGFUL_SCORE} AND NOT has(tags, 'trusted-cloud')"
    )
}

pub fn hosts_query(db: &str, sf: &str, hours: u32) -> String {
    format!(
        "SELECT src_ip, count(), argMax(severity, score), toUInt32(max(score)), uniqExact(dst_ip) {} \
         AND src_ip != '' GROUP BY src_ip ORDER BY max(score) DESC, count() DESC LIMIT 5",
        meaningful(db, sf, hours)
    )
}

pub fn rules_query(db: &str, sf: &str, hours: u32) -> String {
    format!(
        "SELECT arrayElement(sigma_hits, 1) AS rule, count() {} \
         AND rule != '' GROUP BY rule ORDER BY count() DESC LIMIT 5",
        meaningful(db, sf, hours)
    )
}

pub fn meaningful_count_query(db: &str, sf: &str, hours: u32) -> String {
    format!("SELECT count() {}", meaningful(db, sf, hours))
}

pub async fn gather(ch: &ClickhouseStorage, tenant_id: &str, sensor_ids: &[String], hours: u32) -> Facts {
    let db = tenant_db_pub(tenant_id);
    let sf = sensor_filter_pub(sensor_ids);
    let mut f = Facts { window_hours: hours, ..Default::default() };

    let by_sev: Vec<(String, u64)> = ch.client.query(&severity_query(&db, &sf, hours))
        .fetch_all().await.unwrap_or_default();
    for (sev, n) in by_sev {
        match sev.to_uppercase().as_str() {
            "CRITICAL" => f.critical += n,
            "HIGH" => f.high += n,
            "MEDIUM" => f.medium += n,
            _ => f.low += n,
        }
        f.total_alerts += n;
    }
    f.meaningful_alerts = ch.client.query(&meaningful_count_query(&db, &sf, hours))
        .fetch_one::<u64>().await.unwrap_or(0);
    f.top_hosts = ch.client.query(&hosts_query(&db, &sf, hours))
        .fetch_all::<(String, u64, String, u32, u64)>().await.unwrap_or_default()
        .into_iter()
        .map(|(ip, alerts, top_severity, max_score, destinations)| HostFact { ip, alerts, top_severity, max_score, destinations })
        .collect();
    f.top_rules = ch.client.query(&rules_query(&db, &sf, hours))
        .fetch_all::<(String, u64)>().await.unwrap_or_default()
        .into_iter().map(|(rule, alerts)| RuleFact { rule, alerts }).collect();
    f.ai_analyses = ch.client.query(&format!(
        "SELECT uniqExact(community_id) FROM {db}.evidence_annotations \
         WHERE tag = 'ai_analysis' AND created_at >= now() - INTERVAL {hours} HOUR"
    )).fetch_one::<u64>().await.unwrap_or(0);
    f.open_cases = ch.client.query(&format!(
        "SELECT count() FROM {db}.soar_cases FINAL WHERE lower(status) NOT IN ('closed', 'resolved')"
    )).fetch_one::<u64>().await.unwrap_or(0);
    f.active_suppressions = ch.count_ai_suppressions(tenant_id).await.1;
    f
}

// ── Text ─────────────────────────────────────────────────────────────────────

pub const SYSTEM_PROMPT: &str = "You are a SOC analyst writing a short shift briefing for a colleague.\n\
Use ONLY the facts you are given. Never invent hosts, addresses, attacks, causes or numbers.\n\
If the facts do not show an attack, say there is no sign of one. Do not call anything compromised, \
a breach or malware unless the facts say so.\n\
Alerts marked as chatter are excluded from the host and rule lists on purpose; do not treat them as threats.\n\
Write at most 120 words of plain text: one sentence on the overall picture, then up to 3 short bullets \
on what to look at first. No markdown headings.";

fn window_label(hours: u32) -> String {
    if hours % 24 == 0 && hours >= 24 { format!("{} day(s)", hours / 24) } else { format!("{hours} hour(s)") }
}

/// The facts as plain lines (also what the fallback and the reply check work from).
pub fn facts_text(f: &Facts) -> String {
    let mut s = format!(
        "Window: last {}.\nAlerts: {} total ({} critical, {} high, {} medium, {} low). {} of them are above chatter level.\n\
         AI analyses written: {}. Open cases: {}. Active AI suppressions: {}.\n",
        window_label(f.window_hours), f.total_alerts, f.critical, f.high, f.medium, f.low,
        f.meaningful_alerts, f.ai_analyses, f.open_cases, f.active_suppressions
    );
    if f.top_hosts.is_empty() {
        s.push_str("Hosts to look at: none above chatter level.\n");
    } else {
        s.push_str("Hosts to look at (most serious first):\n");
        for h in &f.top_hosts {
            s.push_str(&format!("- {}: {} alerts, top severity {}, highest score {}, {} destination(s)\n",
                h.ip, h.alerts, h.top_severity, h.max_score, h.destinations));
        }
    }
    if !f.top_rules.is_empty() {
        s.push_str("Most frequent detections:\n");
        for r in &f.top_rules { s.push_str(&format!("- {}: {} alerts\n", r.rule, r.alerts)); }
    }
    s
}

pub fn user_prompt(f: &Facts) -> String {
    format!("FACTS:\n{}\nWrite the briefing.", facts_text(f))
}

/// What the page shows when the AI is unavailable or its answer was rejected.
pub fn fallback_text(f: &Facts) -> String {
    let mut s = format!(
        "In the last {}: {} alerts ({} critical, {} high). ",
        window_label(f.window_hours), f.total_alerts, f.critical, f.high
    );
    match f.top_hosts.first() {
        Some(h) => s.push_str(&format!(
            "The host to look at first is {} ({} alerts, top severity {}). ", h.ip, h.alerts, h.top_severity)),
        None if f.total_alerts > 0 => s.push_str(
            "Everything seen is at chatter level: no host stands out. "),
        None => s.push_str("Nothing to report. "),
    }
    s.push_str(&format!("{} open case(s), {} AI analyses written, {} active suppression(s).",
        f.open_cases, f.ai_analyses, f.active_suppressions));
    s
}

const ALARM_WORDS: [&str; 6] = ["compromis", "breach", "ransomware", "exfiltrat", "malware", "backdoor"];

fn ipv4s(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}

/// Is the AI's wording safe to show? It must not add addresses or alarming claims of its own.
pub fn reply_is_grounded(reply: &str, f: &Facts) -> bool {
    let reply = reply.trim();
    if reply.is_empty() || reply.chars().count() > 1500 { return false; }
    let facts = facts_text(f);
    if ipv4s(reply).iter().any(|ip| !facts.contains(ip.as_str())) { return false; }
    let (r, ft) = (reply.to_lowercase(), facts.to_lowercase());
    !ALARM_WORDS.iter().any(|w| r.contains(w) && !ft.contains(w))
}

/// Chooses between the AI's reply and the plain summary. `ai_state` explains an empty reply.
pub fn compose(facts: Facts, ai_reply: &str, ai_state: &'static str) -> Briefing {
    let generated_at = chrono::Utc::now().to_rfc3339();
    if ai_state.is_empty() && !ai_reply.trim().is_empty() {
        if reply_is_grounded(ai_reply, &facts) {
            return Briefing { text: ai_reply.trim().to_string(), source: "ai", reason: "", facts, generated_at };
        }
        return Briefing { text: fallback_text(&facts), source: "facts", reason: "rejected", facts, generated_at };
    }
    let reason = if ai_state.is_empty() { "not_configured" } else { ai_state };
    Briefing { text: fallback_text(&facts), source: "facts", reason, facts, generated_at }
}

/// Asks the given providers (priority order) to word the facts. Empty when none answers.
pub async fn ask(providers: &[AiProvider], f: &Facts) -> String {
    generate_with_providers(providers, SYSTEM_PROMPT, &user_prompt(f)).await
}

// ── Cache: one briefing per tenant / scope / window, shared by every engine through Valkey ──

/// Key for one briefing. Tenant and sensor scope are part of it, so one tenant never gets another's.
pub fn cache_key(tenant_id: &str, sensor_ids: &[String], hours: u32, ai_allowed: bool) -> String {
    let mut sensors = sensor_ids.to_vec();
    sensors.sort();
    format!("ndr:briefing:{}|{}|{}|{}", tenant_id, sensors.join(","), hours, ai_allowed)
}

/// A stored briefing is `{"at": <unix seconds>, "b": <briefing>}`. `force` (the Refresh button) only
/// bypasses a copy that is at least FORCE_MIN_AGE_SECS old, so the button cannot be used to hammer the AI.
pub fn usable(at: u64, now: u64, force: bool) -> bool {
    let age = now.saturating_sub(at);
    age < if force { FORCE_MIN_AGE_SECS } else { CACHE_SECS }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

async fn cache_get(redis: &mut MultiplexedConnection, key: &str, force: bool) -> Option<serde_json::Value> {
    let raw: Option<String> = redis::cmd("GET").arg(key).query_async(redis).await.ok().flatten();
    let v: serde_json::Value = serde_json::from_str(&raw?).ok()?;
    usable(v["at"].as_u64()?, now_secs(), force).then(|| v["b"].clone())
}

async fn cache_put(redis: &mut MultiplexedConnection, key: &str, b: &serde_json::Value) {
    let wrapped = serde_json::json!({ "at": now_secs(), "b": b }).to_string();
    let _: Result<(), _> = redis::cmd("SET").arg(key).arg(wrapped).arg("EX").arg(CACHE_SECS).query_async(redis).await;
}

/// The briefing for a tenant. `ai_allowed` is false when the tenant has AI switched off.
/// If Valkey is unreachable the briefing is simply built each time (nothing is lost, only re-done).
pub async fn briefing(
    ch: &ClickhouseStorage,
    redis: &mut MultiplexedConnection,
    tenant_id: &str,
    sensor_ids: &[String],
    hours: u32,
    ai_allowed: bool,
    force: bool,
) -> serde_json::Value {
    let key = cache_key(tenant_id, sensor_ids, hours, ai_allowed);
    if let Some(hit) = cache_get(redis, &key, force).await {
        return hit;
    }
    let facts = gather(ch, tenant_id, sensor_ids, hours).await;
    let b = if !ai_allowed {
        compose(facts, "", "disabled")
    } else {
        let providers = provigil_common::ai::get_ai_providers(&ch.client, UseCase::AriaChatResponse.tag()).await;
        let reply = if providers.is_empty() { String::new() } else { ask(&providers, &facts).await };
        compose(facts, &reply, "")
    };
    let v = serde_json::json!(b);
    cache_put(redis, &key, &v).await;
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn facts() -> Facts {
        Facts {
            window_hours: 24, critical: 1, high: 3, medium: 1, low: 145, total_alerts: 150, meaningful_alerts: 4,
            top_hosts: vec![
                HostFact { ip: "10.0.5.5".into(), alerts: 1, top_severity: "CRITICAL".into(), max_score: 95, destinations: 1 },
                HostFact { ip: "10.0.9.9".into(), alerts: 3, top_severity: "HIGH".into(), max_score: 85, destinations: 3 },
            ],
            top_rules: vec![RuleFact { rule: "et-trojan-beacon".into(), alerts: 3 }],
            ai_analyses: 2, open_cases: 2, active_suppressions: 1,
        }
    }

    #[test]
    fn a_reply_that_sticks_to_the_facts_is_used() {
        let b = compose(facts(), "Two hosts stand out: 10.0.5.5 (critical) and 10.0.9.9 (high, 3 alerts).", "");
        assert_eq!((b.source, b.reason), ("ai", ""));
        assert!(b.text.contains("10.0.5.5"));
    }

    #[test]
    fn a_reply_with_an_address_the_facts_do_not_contain_is_thrown_away() {
        let b = compose(facts(), "Look at 10.0.5.5 and also 203.0.113.9 which is beaconing.", "");
        assert_eq!((b.source, b.reason), ("facts", "rejected"));
        assert!(!b.text.contains("203.0.113.9"), "the invented address must not reach the page");
        assert!(b.text.contains("10.0.5.5"), "the fact summary is shown instead");
    }

    #[test]
    fn alarming_words_need_support_in_the_facts() {
        // "malware" appears nowhere in the facts, so it is the AI's own claim
        assert_eq!(compose(facts(), "The host 10.0.5.5 is compromised by malware.", "").reason, "rejected");
        // "trojan" is in a rule name, "beacon" too; the word "beaconing" is not an alarm word, so this passes
        assert_eq!(compose(facts(), "Rule et-trojan-beacon fired 3 times from 10.0.9.9.", "").source, "ai");
        // an alarm word that IS in the facts is fine
        let mut f = facts();
        f.top_rules[0].rule = "malware-c2".into();
        assert_eq!(compose(f, "The malware-c2 rule fired 3 times.", "").source, "ai");
    }

    #[test]
    fn empty_or_huge_replies_are_not_used() {
        assert_eq!(compose(facts(), "   ", "").reason, "not_configured");
        assert_eq!(compose(facts(), &"x".repeat(2000), "").reason, "rejected");
    }

    #[test]
    fn without_an_ai_the_page_still_gets_a_summary_and_says_why() {
        assert_eq!(compose(facts(), "", "").reason, "not_configured");
        let d = compose(facts(), "", "disabled");
        assert_eq!((d.source, d.reason), ("facts", "disabled"));
        assert!(d.text.contains("10.0.5.5") && d.text.contains("2 open case"));
        let quiet = compose(Facts { window_hours: 24, ..Default::default() }, "", "");
        assert!(quiet.text.contains("Nothing to report"));
        let chatter = compose(Facts { window_hours: 24, total_alerts: 145, low: 145, ..Default::default() }, "", "");
        assert!(chatter.text.contains("chatter level"), "chatter alone never reads as a threat: {}", chatter.text);
    }

    #[test]
    fn the_prompt_carries_the_facts_and_the_guardrails() {
        assert!(SYSTEM_PROMPT.contains("ONLY the facts"));
        let p = user_prompt(&facts());
        assert!(p.contains("10.0.9.9: 3 alerts") && p.contains("et-trojan-beacon") && p.contains("last 1 day(s)"));
    }

    // Against a real ClickHouse (a throwaway tenant database that is dropped at the end):
    //   CLICKHOUSE_URL=... CLICKHOUSE_USER=... CLICKHOUSE_PASSWORD=... \
    //   cargo test -p ndr-engine briefing_facts -- --ignored
    #[tokio::test]
    #[ignore]
    async fn briefing_facts_ignore_chatter_and_follow_the_sensor_scope() {
        let ch = ClickhouseStorage::new();
        let tenant = "zz_briefingtest";
        let db = tenant_db_pub(tenant);
        let run = |q: String| { let c = ch.client.clone(); async move { c.query(&q).execute().await.unwrap() } };
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
        run(format!("CREATE DATABASE {db}")).await;
        run(format!("CREATE TABLE {db}.ndr_hits (community_id String, src_ip String, dst_ip String, severity String, score Float32, \
             tags Array(String), sigma_hits Array(String), sensor_id String, timestamp DateTime) ENGINE = MergeTree ORDER BY timestamp")).await;
        run(format!("CREATE TABLE {db}.soar_cases (id String, status String, updated_at DateTime DEFAULT now()) \
             ENGINE = ReplacingMergeTree(updated_at) ORDER BY id")).await;
        run(format!("CREATE TABLE {db}.evidence_annotations (community_id String, tag String, created_at DateTime) ENGINE = MergeTree ORDER BY created_at")).await;

        // the real pattern from the hosted site: a sensor VM sending DNS to 8.8.8.8, all trusted-cloud, score 20
        for i in 0..145 {
            run(format!("INSERT INTO {db}.ndr_hits VALUES ('c{i}','10.0.2.15','8.8.8.8','LOW',20,['trusted-cloud'],['dns'],'s2',now() - {i})")).await;
        }
        // trusted-cloud with a high score is still chatter for ranking
        run(format!("INSERT INTO {db}.ndr_hits VALUES ('t1','10.0.7.7','52.0.0.1','MEDIUM',50,['trusted-cloud'],['tls'],'s2',now())")).await;
        for d in 0..3 {
            run(format!("INSERT INTO {db}.ndr_hits VALUES ('h{d}','10.0.9.9','198.51.100.{d}','HIGH',85,['ids-alert'],['et-trojan-beacon'],'s1',now())")).await;
        }
        run(format!("INSERT INTO {db}.ndr_hits VALUES ('k1','10.0.5.5','203.0.113.5','CRITICAL',95,['threat-intel'],['ti-c2'],'s2',now())")).await;
        // older than the window: must not count
        run(format!("INSERT INTO {db}.ndr_hits VALUES ('o1','10.0.6.6','203.0.113.6','CRITICAL',95,[],['old'],'s2',now() - INTERVAL 3 DAY)")).await;
        run(format!("INSERT INTO {db}.soar_cases (id, status) VALUES ('a','New'),('b','In Progress'),('c','Closed'),('d','Resolved')")).await;
        run(format!("INSERT INTO {db}.evidence_annotations VALUES ('h0','ai_analysis',now()),('h0','ai_analysis',now()),('k1','ai_analysis',now()),('x','other',now())")).await;

        let f = gather(&ch, tenant, &[], 24).await;
        assert_eq!((f.critical, f.high, f.medium, f.low, f.total_alerts), (1, 3, 1, 145, 150), "totals count everything in the window");
        assert_eq!(f.meaningful_alerts, 4, "only the 3 HIGH + 1 CRITICAL are above chatter level");
        let ips: Vec<&str> = f.top_hosts.iter().map(|h| h.ip.as_str()).collect();
        assert_eq!(ips, vec!["10.0.5.5", "10.0.9.9"], "chatter hosts (10.0.2.15, 10.0.7.7) and the 3-day-old alert never appear");
        assert_eq!((f.top_hosts[1].alerts, f.top_hosts[1].destinations, f.top_hosts[1].max_score), (3, 3, 85));
        assert_eq!(f.top_rules, vec![RuleFact { rule: "et-trojan-beacon".into(), alerts: 3 }, RuleFact { rule: "ti-c2".into(), alerts: 1 }]);
        assert_eq!(f.open_cases, 2, "New + In Progress are open; Closed and Resolved are not");
        assert_eq!(f.ai_analyses, 2, "distinct sessions with an AI analysis: h0 (twice) and k1");

        let scoped = gather(&ch, tenant, &["s1".to_string()], 24).await;
        assert_eq!(scoped.total_alerts, 3, "a sensor-scoped user only sees their own sensor's alerts");
        assert_eq!(scoped.top_hosts.len(), 1);
        assert_eq!(scoped.top_hosts[0].ip, "10.0.9.9");

        // the whole page text built from these real facts never names a chatter host
        let b = compose(f, "", "");
        assert!(!b.text.contains("10.0.2.15") && b.text.contains("10.0.5.5"));
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
    }

    // A local OpenAI-compatible server stands in for the provider: the real HTTP path is used.
    #[tokio::test]
    async fn the_provider_is_called_with_the_facts_and_the_next_one_is_tried_when_one_fails() {
        use std::sync::Arc;
        let seen: Arc<Mutex<Vec<(String, serde_json::Value)>>> = Arc::new(Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route("/bad/v1/chat/completions", axum::routing::post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "oops") }))
            .route("/good/v1/chat/completions", axum::routing::post({
                let seen = seen.clone();
                move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<serde_json::Value>| {
                    let seen = seen.clone();
                    async move {
                        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                        seen.lock().unwrap().push((auth, body));
                        axum::Json(serde_json::json!({"choices": [{"message": {"content": "  Look at 10.0.5.5 first.  "}}]}))
                    }
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let p = |name: &str, path: &str, key: &str, prio: u8| AiProvider {
            name: name.into(), provider_type: "openai".into(), api_key: key.into(), model: "test-model".into(),
            base_url: format!("{base}/{path}"), endpoint_path: String::new(), msg_format: String::new(), priority: prio,
        };
        let providers = vec![p("bad", "bad", "k-bad", 1), p("nokey", "good", "", 2), p("good", "good", "k-good", 3)];
        let reply = ask(&providers, &facts()).await;
        assert_eq!(reply, "Look at 10.0.5.5 first.", "trimmed answer from the first provider that works");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the failing provider is skipped and the one without a key is never called");
        assert_eq!(seen[0].0, "Bearer k-good");
        assert_eq!(seen[0].1["model"], "test-model");
        let sent = seen[0].1["messages"].to_string();
        assert!(sent.contains("ONLY the facts") && sent.contains("10.0.9.9: 3 alerts"), "system rules and the real facts are what the AI is given");
        assert!(ask(&[], &facts()).await.is_empty(), "no providers: empty, so compose falls back to the facts");
    }

    #[test]
    fn the_cache_key_separates_tenants_scopes_windows_and_ai_state() {
        let k = |t: &str, s: &[&str], h, ai| cache_key(t, &s.iter().map(|x| x.to_string()).collect::<Vec<_>>(), h, ai);
        let base = k("a", &["s1", "s2"], 24, true);
        assert_eq!(base, k("a", &["s2", "s1"], 24, true), "sensor order does not matter");
        for other in [k("b", &["s1", "s2"], 24, true), k("a", &["s1"], 24, true), k("a", &[], 24, true),
                      k("a", &["s1", "s2"], 168, true), k("a", &["s1", "s2"], 24, false)] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn refresh_cannot_bypass_a_copy_younger_than_a_minute() {
        assert!(usable(1000, 1100, false), "normal read: a 100 s old copy is used");
        assert!(!usable(1000, 1000 + CACHE_SECS, false), "a copy at the cache limit is expired");
        assert!(usable(1000, 1030, true), "refresh within a minute still gets the cached copy");
        assert!(!usable(1000, 1061, true), "refresh after a minute rebuilds");
        assert!(usable(2000, 1000, true), "a clock that went backwards does not force a rebuild");
    }

    // Against the real Valkey (two connections stand in for two engines):
    //   VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ndr-engine briefing_shared -- --ignored
    #[tokio::test]
    #[ignore]
    async fn briefing_shared_between_engines_through_valkey() {
        let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = redis::Client::open(url).unwrap();
        let mut engine1 = client.get_multiplexed_async_connection().await.unwrap();
        let mut engine2 = client.get_multiplexed_async_connection().await.unwrap();
        let key = cache_key("zz_cachetest", &[], 24, true);
        let _: () = redis::cmd("DEL").arg(&key).query_async(&mut engine1).await.unwrap();

        assert!(cache_get(&mut engine1, &key, false).await.is_none(), "empty to start with");
        let b = serde_json::json!({"text": "hello", "source": "ai"});
        cache_put(&mut engine1, &key, &b).await;
        assert_eq!(cache_get(&mut engine2, &key, false).await, Some(b.clone()), "engine 2 sees what engine 1 stored");
        assert_eq!(cache_get(&mut engine2, &key, true).await, Some(b.clone()), "Refresh inside a minute reuses it");
        let ttl: i64 = redis::cmd("TTL").arg(&key).query_async(&mut engine1).await.unwrap();
        assert!(ttl > 0 && ttl <= CACHE_SECS as i64, "it expires by itself: {ttl}");

        // an old copy: Refresh rebuilds, a normal read still uses it
        let old = serde_json::json!({"at": now_secs() - 120, "b": b}).to_string();
        let _: () = redis::cmd("SET").arg(&key).arg(old).arg("EX").arg(60).query_async(&mut engine1).await.unwrap();
        assert!(cache_get(&mut engine2, &key, true).await.is_none(), "Refresh on a 2-minute-old copy rebuilds");
        assert!(cache_get(&mut engine2, &key, false).await.is_some());
        // garbage in the key is a miss, not a crash
        let _: () = redis::cmd("SET").arg(&key).arg("not json").arg("EX").arg(60).query_async(&mut engine1).await.unwrap();
        assert!(cache_get(&mut engine1, &key, false).await.is_none());
        let _: () = redis::cmd("DEL").arg(&key).query_async(&mut engine1).await.unwrap();
    }
}
