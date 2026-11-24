//! "Ask your history": a question answered only from this tenant's own past investigations.
//!
//! The question is embedded and matched against the RAG index (`rag::search_similar`), the
//! closest past investigations are attached with how their cases ended (`incident_outcomes`),
//! and the AI is asked to answer from exactly those records. Its answer is checked before it is
//! shown: every session it cites must be one of the records it was given, otherwise the plain
//! list of records is shown instead. With no comparable records there is no AI call at all.

use serde::Serialize;

use crate::ai::provider::UseCase;
use crate::ai::rag::SimilarIncident;
use provigil_common::ai::{generate_with_providers, AiProvider};

pub const MAX_QUESTION_CHARS: usize = 300;
pub const MAX_RECORDS: usize = 5;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Source {
    pub community_id: String,
    pub verdict: String,
    pub reasoning: String,
    pub outcome: Option<String>,
    pub score: f32,
    pub src_ip: String,
    pub dst_ip: String,
    pub sensor_id: String,
    pub generated_at: String,
    /// "investigation" (a verdict), "analysis" (an AI analysis of an alert session), or "case".
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Answer {
    pub answer: String,
    /// "ai" when the AI's wording was used, "records" for the plain list.
    pub source: &'static str,
    /// Why the plain list was used: "no_records", "not_configured", "rejected", or "" for AI.
    pub reason: &'static str,
    pub sources: Vec<Source>,
}

pub fn sources_from(hits: &[SimilarIncident], outcomes: &std::collections::HashMap<String, (String, String)>) -> Vec<Source> {
    hits.iter().take(MAX_RECORDS).map(|h| Source {
        community_id: h.investigation.community_id.clone(),
        verdict: h.investigation.verdict.clone(),
        reasoning: h.investigation.reasoning.clone(),
        outcome: outcomes.get(&h.investigation.community_id).map(|o| o.0.clone()),
        score: h.score,
        src_ip: h.investigation.src_ip.clone(),
        dst_ip: h.investigation.dst_ip.clone(),
        sensor_id: h.investigation.sensor_id.clone(),
        generated_at: h.investigation.generated_at.clone(),
        kind: "investigation".to_string(),
    }).collect()
}

pub const SYSTEM_PROMPT: &str = "You answer a SOC analyst's question using ONLY the past investigation records given. \
Never add facts, hosts, addresses or outcomes that are not in the records. Cite the community_id of each record \
you rely on, exactly as written. If the records do not answer the question, say so in one sentence. \
Use all relevant supplied records and give a concise, direct answer. At most 180 words, plain text.";

pub fn user_prompt(question: &str, sources: &[Source]) -> String {
    let mut s = format!("QUESTION: {question}\n\nRECORDS:\n");
    for r in sources {
        let outcome = match r.outcome.as_deref() {
            Some("true_positive") => "closed as a confirmed attack",
            Some("false_positive") => "closed as a false positive",
            Some("closed_unknown") => "closed, no verdict recorded",
            _ => "no outcome recorded yet",
        };
        s.push_str(&format!(
            "- community_id {} | {} -> {} | sensor {} | AI verdict {} | {} | {}\n  reasoning: {}\n",
            r.community_id, r.src_ip, r.dst_ip, r.sensor_id, r.verdict, outcome, r.generated_at, r.reasoning
        ));
    }
    s.push_str("\nAnswer the question from these records only.");
    s
}

/// Every session id the answer cites must be one of the records. An answer citing anything else
/// is not grounded in what was retrieved, so it is not shown.
pub fn answer_is_grounded(answer: &str, sources: &[Source]) -> bool {
    let a = answer.trim();
    if a.is_empty() || a.chars().count() > 1200 { return false; }
    let re = regex::Regex::new(r"1:[A-Za-z0-9+/]{20,}={0,2}").unwrap();
    let cited: Vec<&str> = re.find_iter(a).map(|m| m.as_str()).collect();
    cited.iter().all(|c| sources.iter().any(|s| s.community_id == *c))
}

pub fn compose(question: &str, sources: Vec<Source>, ai_reply: &str, ai_state: &'static str) -> Answer {
    if sources.is_empty() {
        return Answer {
            answer: format!("No comparable past investigations found for \"{}\".", question.trim()),
            source: "records", reason: "no_records", sources,
        };
    }
    if ai_state.is_empty() && answer_is_grounded(ai_reply, &sources) {
        return Answer { answer: ai_reply.trim().to_string(), source: "ai", reason: "", sources };
    }
    let reason = if !ai_state.is_empty() { ai_state } else if ai_reply.trim().is_empty() { "no_ai_answer" } else { "rejected" };
    let answer = format!("{} comparable past investigation(s), listed below with how each ended.", sources.len());
    Answer { answer, source: "records", reason, sources }
}

/// Asks the providers (priority order) to answer from the records. Empty when none answers.
pub async fn ask(providers: &[AiProvider], question: &str, sources: &[Source]) -> String {
    generate_with_providers(providers, SYSTEM_PROMPT, &user_prompt(question, sources)).await
}

pub fn clean_question(q: &str) -> String {
    q.trim().chars().take(MAX_QUESTION_CHARS).collect()
}

pub async fn providers(ch: &clickhouse::Client) -> Vec<AiProvider> {
    provigil_common::ai::get_ai_providers(ch, UseCase::AriaChatResponse.tag()).await
}

/// What a question is asking for. Read from the wording, so it can be tested without a database.
#[derive(Debug, Clone, PartialEq)]
pub enum Intent {
    /// "the last incident", "the last 4 incidents", "newest alert": the most recent records, by time.
    /// `summarize` when the question also asks for a summary of them.
    Latest { summarize: bool, count: usize },
    /// A case number (INC-2026-0005) or a session id (1:...): that one record.
    Incident(String),
    /// "summarize the last 7 days": facts and a grounded summary for a period.
    Summary { hours: u32 },
    /// "how many cases are open": a count, answered from the records directly — no AI call, so
    /// there is nothing for it to get wrong.
    Stats,
    /// Anything else: the records most similar in meaning.
    Topic,
}

pub fn detect_intent(question: &str) -> Intent {
    let q = question.trim();
    let lower = q.to_lowercase();
    if let Some(m) = regex::Regex::new(r"(?i)INC-\d{4}-\d{4}").unwrap().find(q) {
        return Intent::Incident(m.as_str().to_uppercase());
    }
    if let Some(m) = regex::Regex::new(r"1:[A-Za-z0-9+/]{20,}={0,2}").unwrap().find(q) {
        return Intent::Incident(m.as_str().to_string());
    }
    // A count of cases/alerts, not a count of something about one session (like its ports).
    const STATS_WORDS: [&str; 6] = [
        "how many case", "how many incident", "how many alert", "case count",
        "cases are open", "cases are closed",
    ];
    if STATS_WORDS.iter().any(|w| lower.contains(w)) {
        return Intent::Stats;
    }
    const SUMMARY_WORDS: [&str; 5] = ["summar", "overview", "what happened", "digest", "recap"];
    const LATEST_WORDS: [&str; 17] = [
        "last ", "latest", "newest", "most recent", "recent",
        "new incident", "new case", "new alert",
        "past incident", "previous incident", "incident history",
        "past case", "previous case", "case history",
        "past investigation", "previous investigation", "past alert",
    ];
    let summarize = SUMMARY_WORDS.iter().any(|w| lower.contains(w));
    let latest = LATEST_WORDS.iter().any(|w| lower.contains(w));
    // A named period ("last 7 days") makes it a period summary. Otherwise "last" means the newest record.
    if summarize && names_period(&lower) {
        return Intent::Summary { hours: hours_in(&lower) };
    }
    if latest {
        return Intent::Latest { summarize, count: latest_count(&lower) };
    }
    if summarize {
        return Intent::Summary { hours: 24 };
    }
    Intent::Topic
}

/// How many records a "last …" question asks for: a number if it names one ("the last 4
/// incidents" → 4, clamped to 10), one if it names its noun in the singular ("the last incident",
/// "the newest alert"), or MAX_RECORDS otherwise ("the latest alerts").
fn latest_count(lower: &str) -> usize {
    const PREFIX: &str = r"(?:last|latest|newest|most recent|recent)";
    if let Some(c) = regex::Regex::new(&format!(r"{PREFIX}\s+(\d+)")).unwrap().captures(lower)
        .or_else(|| regex::Regex::new(r"(\d+)\s+(?:incidents?|cases?|alerts?|records?)").unwrap().captures(lower))
    {
        return c[1].parse::<usize>().unwrap_or(MAX_RECORDS).clamp(1, 10);
    }
    if regex::Regex::new(&format!(r"{PREFIX}\s+(?:incident|case|alert|record)\b")).unwrap().is_match(lower) {
        return 1;
    }
    MAX_RECORDS
}

fn names_period(lower: &str) -> bool {
    lower.contains("today") || lower.contains("week") || lower.contains("last hour")
        || regex::Regex::new(r"\d+\s*(hour|hr|day|week)").unwrap().is_match(lower)
}

/// Appends a real port count to a record's reasoning, so a question about ports is answered from
/// a number that was actually counted, not guessed.
pub fn with_port_note(reasoning: &str, distinct_dst_ports: usize) -> String {
    if distinct_dst_ports == 0 {
        return reasoning.to_string();
    }
    format!("{reasoning} | {distinct_dst_ports} distinct destination port(s) contacted, from the session's own events.")
}

/// Appends what kind of traffic the session's own events actually were — "collect the evidence"
/// answered from a real count of event types and protocols, not a guess from the case title.
pub fn with_event_mix(reasoning: &str, event_types: &[(String, u64)], protocols: &[(String, u64)]) -> String {
    if event_types.is_empty() {
        return reasoning.to_string();
    }
    let fmt = |v: &[(String, u64)]| v.iter().map(|(k, n)| format!("{k} x{n}")).collect::<Vec<_>>().join(", ");
    format!("{reasoning} | Events: {}. Protocols: {}.", fmt(event_types), fmt(protocols))
}

/// Appends what evidence was actually collected and kept for the session — so "collect the evidence"
/// states real counts of what is in storage, not what the case description happens to say.
pub fn with_evidence_counts(reasoning: &str, bundles: usize, pcap_sessions: usize) -> String {
    if bundles == 0 && pcap_sessions == 0 {
        return format!("{reasoning} | No evidence bundle or PCAP session is stored for this session.");
    }
    format!("{reasoning} | Evidence on file: {bundles} evidence bundle(s), {pcap_sessions} PCAP session(s).")
}

/// What is actually known about why a hit was scored and classified as it was — read back from the
/// hit itself, not reconstructed after the fact.
pub struct HitDetail {
    pub score: f32,
    pub severity: String,
    pub tags: Vec<String>,
    pub sigma_hits: Vec<String>,
    pub reasons: Vec<String>,
}

/// Appends the real score, severity and the reasons that were actually computed for the hit, so a
/// question like "why is this HIGH" or "what is its score" is answered from numbers that were
/// actually stored, not guessed from the case title.
pub fn with_hit_detail(reasoning: &str, d: &HitDetail) -> String {
    let mut s = format!("{reasoning} | Score {:.0} ({})", d.score, d.severity);
    if !d.reasons.is_empty() {
        s.push_str(&format!(". Why: {}", d.reasons.join("; ")));
    }
    if !d.sigma_hits.is_empty() {
        s.push_str(&format!(". Sigma: {}", d.sigma_hits.join(", ")));
    }
    if !d.tags.is_empty() {
        s.push_str(&format!(". Tags: {}", d.tags.join(", ")));
    }
    s
}

/// How many turns of conversation are folded into the prompt, so the AI can read a word like "it" or
/// "that session" the way a person reading the chat would — not by matching the wording in code.
pub const MAX_HISTORY_TURNS: usize = 4;

/// The question, with the last few turns of conversation ahead of it. The AI reads the whole thing
/// and decides for itself what a pronoun or "this session" refers to.
pub fn question_with_history(question: &str, history: &[(String, String)]) -> String {
    if history.is_empty() {
        return question.to_string();
    }
    let mut s = String::from("Earlier in this conversation:\n");
    for (role, text) in history.iter().rev().take(MAX_HISTORY_TURNS).collect::<Vec<_>>().into_iter().rev() {
        let clipped: String = text.chars().take(240).collect();
        s.push_str(&format!("{role}: {clipped}\n"));
    }
    s.push_str(&format!("\nNEW QUESTION: {}", question.trim()));
    s
}

/// The period a question names, in hours. Defaults to the last 24 hours.
pub fn hours_in(lower: &str) -> u32 {
    if lower.contains("today") { return 24; }
    if lower.contains("last hour") { return 1; }
    if let Some(c) = regex::Regex::new(r"(\d+)\s*(hour|hr|day|week)").unwrap().captures(lower) {
        let n: u32 = c[1].parse().unwrap_or(1).clamp(1, 365);
        return match &c[2] { "hour" | "hr" => n, "day" => n * 24, _ => n * 168 }.min(24 * 365);
    }
    if lower.contains("week") { return 168; }
    24
}

/// Sort key for a record time: RFC 3339, or ClickHouse's "YYYY-MM-DD HH:MM:SS". Unknown formats sort last.
pub fn when(s: &str) -> i64 {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) { return t.timestamp(); }
    if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") { return t.and_utc().timestamp(); }
    0
}

pub fn sort_newest_first(sources: &mut [Source]) {
    sources.sort_by_key(|r| std::cmp::Reverse(when(&r.generated_at)));
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// AI analyses (newest first, as the query returns them) as records. They carry no verdict outcome.
pub fn sources_from_analyses(rows: &[serde_json::Value]) -> Vec<Source> {
    let text = |r: &serde_json::Value, k: &str| r[k].as_str().unwrap_or("").to_string();
    rows.iter().take(MAX_RECORDS).map(|r| Source {
        community_id: text(r, "community_id"),
        verdict: text(r, "severity"),
        reasoning: clip(&text(r, "analysis"), 600),
        outcome: None,
        score: 1.0,
        src_ip: text(r, "src_ip"),
        dst_ip: text(r, "dst_ip"),
        sensor_id: String::new(),
        generated_at: text(r, "created_at"),
        kind: "analysis".to_string(),
    }).collect()
}

/// SOAR cases as records. A case's own status is what it says happened, so it is shown as its reasoning.
pub fn sources_from_cases(rows: &[serde_json::Value]) -> Vec<Source> {
    let text = |r: &serde_json::Value, k: &str| r[k].as_str().unwrap_or("").to_string();
    rows.iter().take(MAX_RECORDS).map(|r| {
        let created = r["created_at"].as_i64()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();
        Source {
            community_id: text(r, "community_id"),
            verdict: text(r, "severity"),
            reasoning: clip(&format!("{} ({}, priority {}): {}. {}",
                text(r, "case_number"), text(r, "status"), text(r, "priority"),
                text(r, "title"), text(r, "description")), 600),
            outcome: None,
            score: 1.0,
            src_ip: text(r, "src_ip"),
            dst_ip: text(r, "dst_ip"),
            sensor_id: String::new(),
            generated_at: created,
            kind: "case".to_string(),
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(cid: &str, outcome: Option<&str>) -> Source {
        Source {
            community_id: cid.into(), verdict: "SUSPICIOUS".into(), reasoning: "r".into(),
            outcome: outcome.map(|s| s.into()), score: 0.8, src_ip: "10.0.0.5".into(),
            dst_ip: "203.0.113.9".into(), sensor_id: "s1".into(), generated_at: "t".into(),
            kind: "investigation".into(),
        }
    }

    #[test]
    fn an_answer_may_only_cite_the_records_it_was_given() {
        let s = vec![src("1:AAAAAAAAAAAAAAAAAAAAAAAA=", None)];
        assert!(answer_is_grounded("Yes, see 1:AAAAAAAAAAAAAAAAAAAAAAAA= which was a false positive.", &s));
        assert!(!answer_is_grounded("Yes, see 1:INVENTEDINVENTEDINVENTED= for details.", &s), "an invented citation is rejected");
        assert!(!answer_is_grounded("   ", &s), "an empty answer is rejected");
        assert!(answer_is_grounded("No matching record answers this.", &s), "an honest 'no' with no citation is fine");
    }

    #[test]
    fn no_records_means_no_ai_call_and_an_honest_message() {
        let a = compose("have we seen DNS tunneling?", vec![], "should never be used", "");
        assert_eq!((a.source, a.reason), ("records", "no_records"));
        assert!(a.answer.contains("No comparable past investigations"));
        assert!(a.sources.is_empty());
    }

    #[test]
    fn a_grounded_ai_answer_is_shown_and_an_ungrounded_one_is_not() {
        let s = vec![src("1:AAAAAAAAAAAAAAAAAAAAAAAA=", Some("false_positive"))];
        let good = compose("q", s.clone(), "Yes: 1:AAAAAAAAAAAAAAAAAAAAAAAA= was a false positive.", "");
        assert_eq!(good.source, "ai");
        let bad = compose("q", s.clone(), "Yes: 1:MADEUPMADEUPMADEUPMADEUP= was an attack.", "");
        assert_eq!((bad.source, bad.reason), ("records", "rejected"), "the list is shown instead");
        assert_eq!(bad.sources.len(), 1, "the records are still there to read");
        let none = compose("q", s, "", "not_configured");
        assert_eq!((none.source, none.reason), ("records", "not_configured"));
    }

    #[test]
    fn the_prompt_contains_only_the_records_and_the_outcome_in_words() {
        let p = user_prompt("what happened?", &[src("1:AAAAAAAAAAAAAAAAAAAAAAAA=", Some("true_positive"))]);
        assert!(p.contains("1:AAAAAAAAAAAAAAAAAAAAAAAA=") && p.contains("closed as a confirmed attack"));
        assert!(SYSTEM_PROMPT.contains("ONLY the past investigation records"));
    }

    #[test]
    fn long_questions_are_cut() {
        assert_eq!(clean_question(&"x".repeat(1000)).chars().count(), MAX_QUESTION_CHARS);
    }

    #[test]
    fn the_wording_decides_what_is_asked_for() {
        assert_eq!(detect_intent("what is the last incident and summarize it"), Intent::Latest { summarize: true, count: 1 });
        assert_eq!(detect_intent("what is the last incident?"), Intent::Latest { summarize: false, count: 1 });
        assert_eq!(detect_intent("show me the newest alert"), Intent::Latest { summarize: false, count: 1 });
        assert_eq!(detect_intent("past incidents"), Intent::Latest { summarize: false, count: MAX_RECORDS });
        assert_eq!(detect_intent("is there any past incidents"), Intent::Latest { summarize: false, count: MAX_RECORDS });
        assert_eq!(detect_intent("show incident history"), Intent::Latest { summarize: false, count: MAX_RECORDS });
        assert_eq!(detect_intent("show previous cases"), Intent::Latest { summarize: false, count: MAX_RECORDS });
        assert_eq!(detect_intent("show me the latest alerts"), Intent::Latest { summarize: false, count: MAX_RECORDS }, "plural, no number: the usual few");
        assert_eq!(detect_intent("what were the last 4 incidents"), Intent::Latest { summarize: false, count: 4 });
        assert_eq!(detect_intent("show me the last 20 cases"), Intent::Latest { summarize: false, count: 10 }, "clamped to 10");
        assert_eq!(detect_intent("what happened in the last 7 days"), Intent::Summary { hours: 168 });
        assert_eq!(detect_intent("summarize today"), Intent::Summary { hours: 24 });
        assert_eq!(detect_intent("give me a summary"), Intent::Summary { hours: 24 });
        assert_eq!(detect_intent("tell me about INC-2026-0005"), Intent::Incident("INC-2026-0005".into()));
        assert_eq!(detect_intent("explain 1:9Rz1A0f/82grK2YyMtFIb1VQj9c="), Intent::Incident("1:9Rz1A0f/82grK2YyMtFIb1VQj9c=".into()));
        assert_eq!(detect_intent("have we seen DNS tunneling before?"), Intent::Topic);
        assert_eq!(detect_intent("how many cases are open right now"), Intent::Stats);
        assert_eq!(detect_intent("how many cases are closed"), Intent::Stats);
        assert_eq!(detect_intent("how many ports does it access"), Intent::Topic, "a count about a session, not cases");
        assert_eq!(detect_intent("list out new incidents and its details"), Intent::Latest { summarize: false, count: MAX_RECORDS });
    }

    #[test]
    fn a_port_count_is_only_added_when_there_is_one() {
        assert_eq!(with_port_note("auto-created", 0), "auto-created");
        assert!(with_port_note("auto-created", 3).contains("3 distinct destination port"));
    }

    #[test]
    fn the_hit_detail_states_the_real_score_and_its_own_computed_reasons() {
        let d = HitDetail {
            score: 92.0, severity: "CRITICAL".into(),
            tags: vec!["threat-intel".into(), "ids-alert".into()],
            sigma_hits: vec!["ET SCAN Possible Nmap User-Agent Observed".into()],
            reasons: vec!["IP matches threat intel feed (abuse.ch)".into(), "Suricata: ET SCAN (attempted-recon)".into()],
        };
        let note = with_hit_detail("auto-created", &d);
        assert!(note.contains("Score 92 (CRITICAL)"));
        assert!(note.contains("IP matches threat intel feed") && note.contains("Suricata: ET SCAN"));
        assert!(note.contains("ET SCAN Possible Nmap"));
        assert!(note.contains("threat-intel, ids-alert"));
    }

    #[test]
    fn the_event_mix_states_real_counted_types_or_nothing_at_all() {
        assert_eq!(with_event_mix("auto-created", &[], &[]), "auto-created");
        let note = with_event_mix("auto-created", &[("dns".into(), 12), ("conn".into(), 3)], &[("udp".into(), 12), ("tcp".into(), 3)]);
        assert!(note.contains("dns x12") && note.contains("conn x3") && note.contains("udp x12"));
    }

    #[test]
    fn evidence_counts_say_so_honestly_when_there_is_none() {
        assert!(with_evidence_counts("auto-created", 0, 0).contains("No evidence bundle or PCAP session"));
        let note = with_evidence_counts("auto-created", 2, 14);
        assert!(note.contains("2 evidence bundle") && note.contains("14 PCAP session"));
    }

    #[test]
    fn a_hit_detail_with_no_computed_reasons_still_states_the_score() {
        let d = HitDetail { score: 25.0, severity: "LOW".into(), tags: vec![], sigma_hits: vec![], reasons: vec![] };
        assert_eq!(with_hit_detail("auto-created", &d), "auto-created | Score 25 (LOW)");
    }

    #[test]
    fn the_question_carries_only_its_own_recent_turns() {
        assert_eq!(question_with_history("does it?", &[]), "does it?", "nothing to fold in");
        let h: Vec<(String, String)> = (1..=6).map(|i| ("user".to_string(), format!("turn {i}"))).collect();
        let q = question_with_history("does it?", &h);
        assert!(q.contains("turn 3") && q.contains("turn 6"), "the most recent turns are kept");
        assert!(!q.contains("turn 1") && !q.contains("turn 2"), "older turns are dropped");
        assert!(q.ends_with("NEW QUESTION: does it?"));
    }

    #[test]
    fn periods_are_read_in_hours_days_and_weeks() {
        assert_eq!(hours_in("last 6 hours"), 6);
        assert_eq!(hours_in("last 3 days"), 72);
        assert_eq!(hours_in("last 2 weeks"), 336);
        assert_eq!(hours_in("this week"), 168);
        assert_eq!(hours_in("something else"), 24);
        assert_eq!(hours_in("last 99999 days"), 24 * 365, "clamped to one year");
        assert_eq!(hours_in("the last hour"), 1);
    }

    #[test]
    fn rows_become_records_and_the_newest_comes_first() {
        let analyses = vec![serde_json::json!({
            "community_id": "1:AAAAAAAAAAAAAAAAAAAAAAAA=", "severity": "HIGH", "analysis": "beaconing",
            "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "created_at": "2026-10-05 09:00:00"
        })];
        let cases = vec![serde_json::json!({
            "community_id": "1:BBBBBBBBBBBBBBBBBBBBBBBB=", "severity": "CRITICAL", "case_number": "INC-2026-0005",
            "status": "Open", "priority": "P1", "title": "Exfil", "description": "", "src_ip": "10.0.0.7",
            "dst_ip": "198.51.100.4", "created_at": 1_791_250_000i64
        })];
        let mut all = sources_from_analyses(&analyses);
        all.extend(sources_from_cases(&cases));
        sort_newest_first(&mut all);
        assert_eq!(all[0].kind, "case", "the case was created after the analysis");
        assert!(all[0].reasoning.starts_with("INC-2026-0005 (Open, priority P1): Exfil"));
        assert_eq!(all[1].kind, "analysis");
        assert!(when("2026-10-05 09:00:00") > 0 && when("not a time") == 0);
    }
}
