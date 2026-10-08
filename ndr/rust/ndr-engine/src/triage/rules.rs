//! Alert triage - the pure logic: grouping, deterministic false-positive rules,
//! the AI reply parser, the AI call budget and the merge of a fresh run into
//! what was stored before. No I/O here so all of it is unit-tested.
//!
//! Order of decisions for a group of alerts (see `classify`):
//!   1. guard rails   -> SUSPICIOUS, never recommended for suppression, AI not asked
//!   2. known-benign  -> BENIGN by rule (multicast, own cloud endpoint, known
//!                       update servers, trusted cloud scored low)
//!   3. everything else is UNKNOWN and may be sent to the AI (budgeted, see mod.rs)

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Labels the scoring stage puts on many harmless alerts. They say nothing
/// about *what* happened, so they are never the group's name when a more
/// specific tag exists.
const GENERIC_TAGS: &[&str] = &["trusted-cloud", "compromised-host", "risky-host"];

/// Any of these on an alert means a person should look, whatever else is true.
/// ("compromised-host" is deliberately not here: it is a scoring label that sits
/// on ~90% of the low-severity noise.)
const ALARM_TAGS: &[&str] = &[
    "c2", "cnc", "dga", "doh-evasion", "dns-tunneling", "dns-beaconing", "beaconing",
    "malicious-domain", "lateral-movement", "credential-stuffing", "data-staging",
    "large-volume-exfil", "port-scan", "arp-spoofing", "ip-conflict", "threat-intel",
    "ransomware", "malware",
];

/// An AI "benign" below this confidence is not trusted enough to recommend.
pub const MIN_AI_CONFIDENCE: u8 = 70;

// ── Alert rows and groups ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AlertRow {
    pub src_ip:       String,
    pub dst_ip:       String,
    pub severity:     String, // upper-case
    pub score:        f32,
    pub tags:         Vec<String>,
    pub sigma_hits:   Vec<String>,
    pub threat_intel: bool,
    pub timestamp:    u64,
    /// Sensor the alert came from (the key prefix). Empty for alerts stored before it was recorded.
    pub sensor_id:    String,
}

impl AlertRow {
    pub fn from_json(v: &Value) -> Option<AlertRow> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let list = |k: &str| -> Vec<String> {
            v.get(k).and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|t| t.as_str().map(str::to_string)).collect())
                .unwrap_or_default()
        };
        let src_ip = s("src_ip");
        if src_ip.is_empty() {
            return None;
        }
        Some(AlertRow {
            src_ip,
            dst_ip:       s("dst_ip"),
            severity:     s("severity").to_uppercase(),
            score:        v.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32,
            tags:         list("tags"),
            sigma_hits:   list("sigma_hits"),
            threat_intel: v.get("threat_intel").map(|x| x.as_u64().unwrap_or(0) > 0 || x.as_bool() == Some(true)).unwrap_or(false),
            timestamp:    v.get("timestamp").and_then(|x| x.as_u64()).unwrap_or(0),
            sensor_id:    s("sensor_id"),
        })
    }
}

/// IPv6 arrives in both short and zero-padded long form (`ff02::fb` and
/// `ff02:0000:...:00fb`), which would split one conversation into two groups
/// and defeat address matching. Canonicalise anything that parses as an IP.
pub fn canon_ip(s: &str) -> String {
    let t = s.trim();
    IpAddr::from_str(t).map(|ip| ip.to_string()).unwrap_or_else(|_| t.to_string())
}

/// The tag that names a group (and the tag a suppression would use). It must be
/// one the alerts really carry, because the server hides alerts by matching it.
pub fn primary_tag(tags: &[String], sigma_hits: &[String]) -> String {
    if let Some(t) = tags.iter().find(|t| !GENERIC_TAGS.contains(&t.as_str()) && !t.starts_with("t:")) {
        return t.clone();
    }
    if let Some(t) = GENERIC_TAGS.iter().find(|g| tags.iter().any(|t| t == *g)) {
        return (*t).to_string();
    }
    if let Some(t) = sigma_hits.first() {
        return t.clone();
    }
    "alert".to_string()
}

#[derive(Debug, Clone)]
pub struct Group {
    pub key:          String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub tag:          String,
    pub count:        u32,
    pub max_score:    f32,
    pub severities:   BTreeMap<String, u32>,
    pub tags:         BTreeSet<String>,
    pub sigma_hits:   BTreeSet<String>,
    pub threat_intel: bool,
    pub first_seen:   u64,
    pub last_seen:    u64,
    /// Every sensor that contributed an alert to this group ("" = sensor not recorded).
    pub sensors:      BTreeSet<String>,
}

impl Group {
    fn max_severity_rank(&self) -> u8 {
        self.severities.keys().map(|s| severity_rank(s)).max().unwrap_or(0)
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 4,
        "HIGH"     => 3,
        "MEDIUM"   => 2,
        "LOW"      => 1,
        _          => 0, // INFO and anything unknown
    }
}

/// One group per (source, destination, naming tag). Grouping is what keeps AI
/// calls low: 100+ alerts from one host to one server become one question.
pub fn group_alerts(rows: &[AlertRow]) -> Vec<Group> {
    let mut map: BTreeMap<String, Group> = BTreeMap::new();
    for r in rows {
        let src = canon_ip(&r.src_ip);
        let dst = canon_ip(&r.dst_ip);
        let tag = primary_tag(&r.tags, &r.sigma_hits);
        let key = format!("{src}|{dst}|{tag}");
        let g = map.entry(key.clone()).or_insert_with(|| Group {
            key, src_ip: src, dst_ip: dst, tag,
            count: 0, max_score: 0.0,
            severities: BTreeMap::new(), tags: BTreeSet::new(), sigma_hits: BTreeSet::new(),
            threat_intel: false, first_seen: u64::MAX, last_seen: 0, sensors: BTreeSet::new(),
        });
        g.sensors.insert(r.sensor_id.clone());
        g.count += 1;
        if r.score > g.max_score { g.max_score = r.score; }
        *g.severities.entry(r.severity.clone()).or_insert(0) += 1;
        g.tags.extend(r.tags.iter().cloned());
        g.sigma_hits.extend(r.sigma_hits.iter().cloned());
        g.threat_intel |= r.threat_intel;
        if r.timestamp > 0 {
            g.first_seen = g.first_seen.min(r.timestamp);
            g.last_seen  = g.last_seen.max(r.timestamp);
        }
    }
    map.into_values()
        .map(|mut g| { if g.first_seen == u64::MAX { g.first_seen = 0; } g })
        .collect()
}

// ── Deterministic classification ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict { Benign, Suspicious, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source { Rule, Ai }

#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict:    Verdict,
    pub source:     Source,
    pub confidence: u8,
    pub reason:     String,
}

/// What the rules know about "harmless" destinations.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Addresses of this platform's own endpoint (what a sensor reports to).
    pub own_ips:     HashSet<IpAddr>,
    /// Networks known to be routine infrastructure, with a label for the reason.
    pub benign_nets: Vec<(IpNetwork, String)>,
}

impl Context {
    /// Small built-in list. Kept short on purpose - lists like this go stale;
    /// extend it per deployment with TRIAGE_BENIGN_CIDRS instead of editing code.
    pub fn builtin() -> Context {
        let mut c = Context::default();
        for (cidr, label) in [
            ("91.189.88.0/21",  "Ubuntu (Canonical) update, time and snap servers"),
            ("185.125.188.0/22", "Ubuntu (Canonical) update, time and snap servers"),
            // Canonical's IPv6 block (ARIN NET6-2620-2D-4000-1, "Canonical USA Inc."): the same servers
            // over IPv6. Without it a dual-stack host's Ubuntu updates were never recognised.
            ("2620:2d:4000::/44", "Ubuntu (Canonical) update, time and snap servers"),
        ] {
            if let Ok(n) = IpNetwork::from_str(cidr) {
                c.benign_nets.push((n, label.to_string()));
            }
        }
        c
    }
}

/// `TRIAGE_BENIGN_CIDRS="203.0.113.0/24=Corp proxy,198.51.100.7/32=Monitoring"`.
/// Bad entries are skipped, not fatal.
pub fn parse_benign_cidrs(s: &str) -> Vec<(IpNetwork, String)> {
    s.split(',')
        .filter_map(|item| {
            let item = item.trim();
            if item.is_empty() { return None; }
            let (cidr, label) = item.split_once('=').unwrap_or((item, "operator-defined known-good network"));
            IpNetwork::from_str(cidr.trim()).ok().map(|n| (n, label.trim().to_string()))
        })
        .collect()
}

/// Multicast, loopback, link-local, broadcast: traffic that never leaves the
/// local segment, so it can't be an "external contact".
pub fn is_local_chatter(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_multicast() || v.is_loopback() || v.is_link_local()
                         || v.is_broadcast() || v.is_unspecified(),
        IpAddr::V6(v) => v.is_multicast() || v.is_loopback() || v.is_unspecified()
                         || (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub fn classify(g: &Group, ctx: &Context) -> Decision {
    let suspicious = |why: String| Decision {
        verdict: Verdict::Suspicious, source: Source::Rule, confidence: 100, reason: why,
    };

    // 1. Guard rails: nothing below may talk a person out of looking at these.
    if g.threat_intel {
        return suspicious("Matches a threat-intelligence feed.".into());
    }
    if !g.sigma_hits.is_empty() {
        return suspicious(format!("A detection rule fired ({}).", g.sigma_hits.iter().take(2).cloned().collect::<Vec<_>>().join(", ")));
    }
    if g.max_severity_rank() >= 3 {
        return suspicious("High or critical severity - kept for a person to review.".into());
    }
    if let Some(t) = g.tags.iter().chain(std::iter::once(&g.tag)).find(|t| ALARM_TAGS.contains(&t.as_str())) {
        return suspicious(format!("Carries the '{t}' tag."));
    }

    // 2. Known-benign, by rule.
    let benign = |why: String| Decision {
        verdict: Verdict::Benign, source: Source::Rule, confidence: 95, reason: why,
    };
    if let Ok(dst) = IpAddr::from_str(&g.dst_ip) {
        if is_local_chatter(dst) {
            return benign("Destination is a multicast or link-local address - local network chatter, not an external host.".into());
        }
        if ctx.own_ips.contains(&dst) {
            return benign("Destination is this platform's own cloud endpoint - the sensor reporting to its own server.".into());
        }
        if let Some((_, label)) = ctx.benign_nets.iter().find(|(n, _)| n.contains(dst)) {
            return benign(format!("Destination belongs to known routine infrastructure: {label}."));
        }
    }
    if g.tags.contains("trusted-cloud") && g.max_severity_rank() <= 1 {
        return benign("Trusted cloud provider traffic that was already scored low.".into());
    }

    Decision { verdict: Verdict::Unknown, source: Source::Rule, confidence: 0, reason: String::new() }
}

// ── AI question and answer ────────────────────────────────────────────────────

pub const AI_SYSTEM: &str = "You are a network security analyst helping triage alerts from a \
network detection system. Decide whether a GROUP of similar alerts is most likely harmless. \
Reply with ONLY one JSON object, no markdown: \
{\"verdict\":\"benign\"|\"suspicious\"|\"unknown\",\"confidence\":0-100,\"reason\":\"one short sentence\"}. \
Use \"benign\" only when the traffic is clearly routine (operating-system updates, well-known \
CDNs or SaaS, local discovery protocols, the monitoring system talking to its own server). \
When unsure, answer \"unknown\". Never guess benign for anything that could be command-and-control, \
scanning, credential abuse or data theft.";

pub fn build_prompt(g: &Group) -> String {
    let sev = g.severities.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ");
    let tags = g.tags.iter().cloned().collect::<Vec<_>>().join(", ");
    format!(
        "Alert group:\n\
         source: {src} ({src_scope})\n\
         destination: {dst} ({dst_scope})\n\
         alert count: {count}\n\
         severities: {sev}\n\
         highest score: {score}\n\
         tags: {tags}\n\
         Is this group most likely harmless?",
        src = g.src_ip, dst = g.dst_ip, count = g.count, score = g.max_score,
        src_scope = scope(&g.src_ip), dst_scope = scope(&g.dst_ip),
    )
}

fn scope(ip: &str) -> &'static str {
    match IpAddr::from_str(ip) {
        Ok(a) if is_local_chatter(a) => "local segment",
        Ok(IpAddr::V4(v)) if v.is_private() => "private/internal",
        Ok(IpAddr::V6(v)) if (v.segments()[0] & 0xfe00) == 0xfc00 => "private/internal",
        Ok(_) => "public/external",
        Err(_) => "not an IP address",
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AiAnswer { pub verdict: Verdict, pub confidence: u8, pub reason: String }

/// Models wrap JSON in prose or code fences; take the outermost object.
/// Anything that isn't a clear answer becomes None (treated as "no decision").
pub fn parse_ai_reply(reply: &str) -> Option<AiAnswer> {
    let start = reply.find('{')?;
    let end = reply.rfind('}')?;
    if end <= start { return None; }
    let v: Value = serde_json::from_str(&reply[start..=end]).ok()?;
    let verdict = match v.get("verdict")?.as_str()?.to_lowercase().as_str() {
        "benign"     => Verdict::Benign,
        "suspicious" => Verdict::Suspicious,
        "unknown"    => Verdict::Unknown,
        _ => return None,
    };
    let confidence = v.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0).clamp(0.0, 100.0) as u8;
    let reason = v.get("reason").and_then(|r| r.as_str()).unwrap_or("").chars().take(300).collect();
    Some(AiAnswer { verdict, confidence, reason })
}

/// Turn an AI answer into a stored decision. A weak "benign" is not trusted.
pub fn decision_from_ai(a: AiAnswer) -> Decision {
    if a.verdict == Verdict::Benign && a.confidence < MIN_AI_CONFIDENCE {
        return Decision {
            verdict: Verdict::Unknown, source: Source::Ai, confidence: a.confidence,
            reason: format!("AI leaned benign but with low confidence ({}%): {}", a.confidence, a.reason),
        };
    }
    Decision { verdict: a.verdict, source: Source::Ai, confidence: a.confidence, reason: a.reason }
}

// ── AI call budget ────────────────────────────────────────────────────────────

/// Calls made in the current clock hour. Stored with the tenant's triage state
/// so a restart or a change of leader doesn't reset it to zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AiBudget { pub hour: u64, pub calls: u32 }

impl AiBudget {
    pub fn used(&self, now_hour: u64) -> u32 {
        if self.hour == now_hour { self.calls } else { 0 }
    }
    pub fn remaining(&self, now_hour: u64, limit: u32) -> u32 {
        limit.saturating_sub(self.used(now_hour))
    }
    pub fn note_call(&mut self, now_hour: u64) {
        if self.hour != now_hour { self.hour = now_hour; self.calls = 0; }
        self.calls += 1;
    }
}

// ── Stored recommendations and merging ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id:         String,
    pub key:        String,
    pub src_ip:     String,
    pub dst_ip:     String,
    pub tag:        String,
    pub verdict:    Verdict,
    pub source:     Source,
    pub confidence: u8,
    pub reason:     String,
    pub alert_count: u32,
    pub max_score:  f32,
    pub severities: BTreeMap<String, u32>,
    pub first_seen: u64,
    pub last_seen:  u64,
    /// "pending" | "applied" | "dismissed"
    pub status:     String,
    pub updated_at: u64,
    /// Sensors the group's alerts came from; used to show a group only to an analyst who is
    /// assigned to ALL of them. Absent in state saved before this existed.
    #[serde(default)]
    pub sensors:    Vec<String>,
}

/// Can a user restricted to `allowed` sensors see a group built from `rec_sensors`?
/// No restriction (empty `allowed`, e.g. a tenant admin) sees everything. A restricted user sees a
/// group only when EVERY contributing sensor is theirs: a group that mixes in another sensor's
/// alerts would reveal that sensor's counts, and a group whose sensor is unknown cannot be
/// verified, so both are hidden.
pub fn visible_to(rec_sensors: &[String], allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    !rec_sensors.is_empty() && rec_sensors.iter().all(|s| allowed.contains(s))
}

impl Recommendation {
    pub fn from_group(g: &Group, d: &Decision, now: u64) -> Recommendation {
        Recommendation {
            id: uuid::Uuid::new_v4().to_string(),
            key: g.key.clone(), src_ip: g.src_ip.clone(), dst_ip: g.dst_ip.clone(), tag: g.tag.clone(),
            verdict: d.verdict, source: d.source, confidence: d.confidence, reason: d.reason.clone(),
            alert_count: g.count, max_score: g.max_score, severities: g.severities.clone(),
            first_seen: g.first_seen, last_seen: g.last_seen,
            status: "pending".into(), updated_at: now,
            sensors: g.sensors.iter().cloned().collect(),
        }
    }
}

const KEEP_DECIDED_SECS: u64 = 30 * 24 * 3600;
const MAX_RECS: usize = 300;

/// Fold a fresh run into what was stored:
///  - a group seen before keeps its id and its applied/dismissed status;
///  - an earlier AI verdict is reused when the rules still have no opinion, so
///    the same group is never sent to the AI twice (this is the decision cache);
///  - pending groups that produced no alerts this run are dropped;
///  - applied/dismissed entries are kept 30 days as a record.
pub fn merge(prev: &[Recommendation], fresh: Vec<Recommendation>, now: u64) -> Vec<Recommendation> {
    let prev_by_key: BTreeMap<&str, &Recommendation> = prev.iter().map(|p| (p.key.as_str(), p)).collect();
    let mut out: Vec<Recommendation> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for mut f in fresh {
        if let Some(p) = prev_by_key.get(f.key.as_str()) {
            f.id = p.id.clone();
            f.status = p.status.clone();
            if f.source == Source::Rule && f.verdict == Verdict::Unknown && p.source == Source::Ai {
                f.verdict = p.verdict; f.source = p.source;
                f.confidence = p.confidence; f.reason = p.reason.clone();
            }
        }
        seen.insert(f.key.clone());
        out.push(f);
    }
    for p in prev {
        if !seen.contains(&p.key) && p.status != "pending" && now.saturating_sub(p.updated_at) < KEEP_DECIDED_SECS {
            out.push(p.clone());
        }
    }

    let rank = |r: &Recommendation| match r.verdict { Verdict::Suspicious => 0, Verdict::Unknown => 1, Verdict::Benign => 2 };
    out.sort_by(|a, b| rank(a).cmp(&rank(b))
        .then(b.max_score.partial_cmp(&a.max_score).unwrap_or(std::cmp::Ordering::Equal))
        .then(b.alert_count.cmp(&a.alert_count)));
    out.truncate(MAX_RECS);
    out
}

/// The most recent AI verdict already stored for this group, if any.
pub fn cached_ai<'a>(prev: &'a [Recommendation], key: &str) -> Option<&'a Recommendation> {
    prev.iter().find(|p| p.key == key && p.source == Source::Ai)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn row(src: &str, dst: &str, sev: &str, score: f32, tags: &[&str]) -> AlertRow {
        AlertRow {
            src_ip: src.into(), dst_ip: dst.into(), severity: sev.into(), score,
            tags: tags.iter().map(|t| t.to_string()).collect(), sigma_hits: vec![],
            threat_intel: false, timestamp: 1_000, sensor_id: String::new(),
        }
    }
    fn on_sensor(mut r: AlertRow, sensor: &str) -> AlertRow { r.sensor_id = sensor.into(); r }
    fn one(r: AlertRow) -> Group { group_alerts(&[r]).remove(0) }
    fn ctx_with_own(ip: &str) -> Context {
        let mut c = Context::builtin();
        c.own_ips.insert(IpAddr::from_str(ip).unwrap());
        c
    }

    // Addresses below are the real ones from the acm tenant's alert list.

    #[test]
    fn the_sensors_own_tunnel_traffic_is_benign() {
        let g = one(row("172.25.86.150", "13.204.33.47", "INFO", 10.0, &["trusted-cloud", "compromised-host"]));
        let d = classify(&g, &ctx_with_own("13.204.33.47"));
        assert_eq!(d.verdict, Verdict::Benign);
        assert!(d.reason.contains("own cloud endpoint"));
    }

    #[test]
    fn trusted_cloud_scored_low_is_benign_even_without_knowing_the_host() {
        let g = one(row("172.25.86.150", "3.6.30.85", "LOW", 20.0, &["connection-reset", "trusted-cloud", "compromised-host"]));
        assert_eq!(classify(&g, &Context::builtin()).verdict, Verdict::Benign);
    }

    #[test]
    fn ubuntu_update_servers_are_benign() {
        for dst in ["91.189.91.81", "185.125.190.81", "185.125.189.188"] {
            let g = one(row("172.25.86.150", dst, "MEDIUM", 65.0, &["new-external-contact", "t:command-and-control"]));
            assert_eq!(classify(&g, &Context::builtin()).verdict, Verdict::Benign, "{dst}");
        }
    }

    #[test]
    fn ipv6_multicast_is_benign_in_short_and_long_form() {
        for dst in ["ff02::2", "ff02:0000:0000:0000:0000:0000:0000:00fb", "224.0.0.251"] {
            let g = one(row("fe80::215:5dff:fe3f:b17e", dst, "MEDIUM", 65.0, &["new-external-contact"]));
            assert_eq!(classify(&g, &Context::builtin()).verdict, Verdict::Benign, "{dst}");
        }
    }

    #[test]
    fn the_arp_conflict_stays_for_a_human() {
        let g = one(row("82:13:23:ba:19:a8", "172.17.0.2", "HIGH", 85.0, &["ip-conflict", "arp-spoofing"]));
        let d = classify(&g, &Context::builtin());
        assert_eq!(d.verdict, Verdict::Suspicious);
    }

    #[test]
    fn a_first_contact_with_an_unknown_public_host_is_left_unknown() {
        let g = one(row("172.25.86.150", "104.20.45.190", "MEDIUM", 65.0, &["new-external-contact"]));
        assert_eq!(classify(&g, &Context::builtin()).verdict, Verdict::Unknown);
    }

    #[test]
    fn guard_rails_beat_every_benign_rule() {
        // threat intel on a destination that is otherwise "own endpoint"
        let mut r = row("172.25.86.150", "13.204.33.47", "INFO", 10.0, &["trusted-cloud"]);
        r.threat_intel = true;
        assert_eq!(classify(&one(r), &ctx_with_own("13.204.33.47")).verdict, Verdict::Suspicious);
        // a detection rule fired on multicast traffic
        let mut r = row("fe80::1", "ff02::2", "LOW", 30.0, &["agent-s-internal"]);
        r.sigma_hits = vec!["SOME RULE".into()];
        assert_eq!(classify(&one(r), &Context::builtin()).verdict, Verdict::Suspicious);
        // high severity to a Canonical address
        let g = one(row("10.0.0.5", "91.189.91.81", "HIGH", 80.0, &["new-external-contact"]));
        assert_eq!(classify(&g, &Context::builtin()).verdict, Verdict::Suspicious);
        // an alarm tag on trusted-cloud traffic
        let g = one(row("10.0.0.5", "13.204.33.47", "LOW", 20.0, &["dga", "trusted-cloud"]));
        assert_eq!(classify(&g, &Context::builtin()).verdict, Verdict::Suspicious);
    }

    #[test]
    fn compromised_host_label_alone_is_not_an_alarm() {
        let g = one(row("172.25.86.150", "3.6.122.107", "INFO", 10.0, &["trusted-cloud", "compromised-host"]));
        assert_ne!(classify(&g, &Context::builtin()).verdict, Verdict::Suspicious);
    }

    #[test]
    fn grouping_merges_short_and_long_ipv6_and_counts() {
        let rows = vec![
            row("fe80::5f04", "ff02::fb", "INFO", 10.0, &["protocol:mdns", "risky-host"]),
            row("fe80:0000:0000:0000:0000:0000:0000:5f04", "ff02:0000:0000:0000:0000:0000:0000:00fb", "INFO", 12.0, &["protocol:mdns"]),
            row("172.25.86.150", "3.6.122.107", "INFO", 10.0, &["trusted-cloud", "compromised-host"]),
            row("172.25.86.150", "3.6.122.107", "LOW", 22.0, &["trusted-cloud", "compromised-host"]),
            row("172.25.86.150", "3.6.122.107", "INFO", 10.0, &["trusted-cloud", "compromised-host"]),
        ];
        let mut gs = group_alerts(&rows);
        gs.sort_by_key(|g| g.count);
        assert_eq!(gs.len(), 2);
        assert_eq!(gs[0].count, 2);                      // the two mDNS rows are one group
        assert_eq!(gs[1].count, 3);
        assert_eq!(gs[1].max_score, 22.0);
        assert_eq!(gs[1].severities.get("INFO"), Some(&2));
    }

    #[test]
    fn group_name_is_a_tag_the_alerts_really_carry() {
        assert_eq!(primary_tag(&["half-open".into(), "trusted-cloud".into(), "compromised-host".into()], &[]), "half-open");
        assert_eq!(primary_tag(&["trusted-cloud".into(), "compromised-host".into()], &[]), "trusted-cloud");
        assert_eq!(primary_tag(&["t:command-and-control".into(), "new-external-contact".into()], &[]), "new-external-contact");
        assert_eq!(primary_tag(&[], &["SURICATA X".into()]), "SURICATA X");
        assert_eq!(primary_tag(&[], &[]), "alert");
    }

    #[test]
    fn ai_reply_parsing_handles_fences_prose_and_junk() {
        let a = parse_ai_reply("```json\n{\"verdict\":\"benign\",\"confidence\":92,\"reason\":\"Ubuntu updates\"}\n```").unwrap();
        assert_eq!((a.verdict, a.confidence), (Verdict::Benign, 92));
        assert!(parse_ai_reply("Sure! {\"verdict\":\"Suspicious\",\"confidence\":250,\"reason\":\"x\"} hope that helps").unwrap().confidence == 100);
        assert!(parse_ai_reply("I think it is fine").is_none());
        assert!(parse_ai_reply("{\"verdict\":\"maybe\"}").is_none());
        assert!(parse_ai_reply("").is_none());
    }

    #[test]
    fn a_weak_ai_benign_is_not_trusted() {
        let d = decision_from_ai(AiAnswer { verdict: Verdict::Benign, confidence: 55, reason: "looks ok".into() });
        assert_eq!(d.verdict, Verdict::Unknown);
        let d = decision_from_ai(AiAnswer { verdict: Verdict::Benign, confidence: 90, reason: "cdn".into() });
        assert_eq!(d.verdict, Verdict::Benign);
        assert_eq!(d.source, Source::Ai);
    }

    #[test]
    fn budget_counts_per_hour_and_resets() {
        let mut b = AiBudget::default();
        assert_eq!(b.remaining(100, 3), 3);
        b.note_call(100); b.note_call(100);
        assert_eq!(b.remaining(100, 3), 1);
        b.note_call(100);
        assert_eq!(b.remaining(100, 3), 0);
        assert_eq!(b.remaining(101, 3), 3); // next hour: fresh
        b.note_call(101);
        assert_eq!((b.hour, b.calls), (101, 1));
    }

    #[test]
    fn merge_keeps_status_reuses_ai_and_drops_stale_pending() {
        let g = one(row("172.25.86.150", "104.20.45.190", "MEDIUM", 65.0, &["new-external-contact"]));
        let unknown = Decision { verdict: Verdict::Unknown, source: Source::Rule, confidence: 0, reason: String::new() };

        let mut old = Recommendation::from_group(&g, &decision_from_ai(AiAnswer { verdict: Verdict::Benign, confidence: 88, reason: "CDN".into() }), 10);
        old.status = "dismissed".into();
        let gone = Recommendation::from_group(&one(row("1.1.1.1", "2.2.2.2", "LOW", 20.0, &["x"])), &unknown, 10);
        let old_applied = { let mut r = Recommendation::from_group(&one(row("3.3.3.3", "4.4.4.4", "LOW", 20.0, &["y"])), &unknown, 10); r.status = "applied".into(); r };

        let fresh = vec![Recommendation::from_group(&g, &unknown, 500)];
        let out = merge(&[old.clone(), gone, old_applied.clone()], fresh, 500);

        let m = out.iter().find(|r| r.key == g.key).unwrap();
        assert_eq!(m.id, old.id);                       // same identity
        assert_eq!(m.status, "dismissed");              // decision preserved
        assert_eq!((m.verdict, m.source), (Verdict::Benign, Source::Ai)); // AI answer reused, no second call
        assert!(!out.iter().any(|r| r.src_ip == "1.1.1.1")); // stale pending dropped
        assert!(out.iter().any(|r| r.key == old_applied.key)); // applied kept as a record
    }

    #[test]
    fn benign_cidr_env_parsing_skips_bad_entries() {
        let v = parse_benign_cidrs("203.0.113.0/24=Corp proxy, junk, 198.51.100.7/32, 2001:db8::/32=Lab");
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].1, "Corp proxy");
    }

    #[test]
    fn sorting_puts_suspicious_first_then_unknown_then_benign() {
        let ctx = Context::builtin();
        let s = one(row("10.0.0.1", "8.8.8.8", "HIGH", 85.0, &["arp-spoofing"]));
        let u = one(row("10.0.0.2", "104.20.45.190", "MEDIUM", 65.0, &["new-external-contact"]));
        let b = one(row("10.0.0.3", "91.189.91.81", "MEDIUM", 65.0, &["new-external-contact"]));
        let recs: Vec<_> = [&b, &u, &s].iter().map(|g| Recommendation::from_group(g, &classify(g, &ctx), 1)).collect();
        let out = merge(&[], recs, 1);
        let order: Vec<Verdict> = out.iter().map(|r| r.verdict).collect();
        assert_eq!(order, vec![Verdict::Suspicious, Verdict::Unknown, Verdict::Benign]);
    }

    // ── sensor assignment ────────────────────────────────────────────────────
    fn ids(v: &[&str]) -> Vec<String> { v.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn a_group_records_every_sensor_that_contributed() {
        let g = group_alerts(&[
            on_sensor(row("10.0.0.5", "8.8.8.8", "LOW", 20.0, &["new-external-contact"]), "S-A"),
            on_sensor(row("10.0.0.5", "8.8.8.8", "LOW", 20.0, &["new-external-contact"]), "S-B"),
        ]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].sensors.iter().cloned().collect::<Vec<_>>(), ids(&["S-A", "S-B"]));
    }

    #[test]
    fn an_unrestricted_user_sees_every_group() {
        assert!(visible_to(&ids(&["S-A"]), &[]));
        assert!(visible_to(&ids(&["S-B", "S-C"]), &[]));
        assert!(visible_to(&[], &[]), "even a group with no recorded sensor");
    }

    #[test]
    fn a_restricted_analyst_sees_only_groups_made_entirely_of_their_sensors() {
        let mine = ids(&["S-A"]);
        assert!(visible_to(&ids(&["S-A"]), &mine));
        assert!(!visible_to(&ids(&["S-B"]), &mine), "another sensor's group is hidden");
        assert!(!visible_to(&ids(&["S-A", "S-B"]), &mine), "a group that mixes in another sensor would leak its counts");
        assert!(!visible_to(&ids(&[""]), &mine), "alerts with no recorded sensor cannot be verified");
        assert!(!visible_to(&[], &mine), "state saved before sensors were recorded stays hidden until the next run");
        assert!(visible_to(&ids(&["S-A", "S-C"]), &ids(&["S-A", "S-C", "S-D"])), "several assigned sensors");
    }

    #[test]
    fn saved_state_from_before_this_change_still_loads() {
        let old = r#"{"id":"x","key":"a|b|t","src_ip":"a","dst_ip":"b","tag":"t","verdict":"benign","source":"rule",
            "confidence":95,"reason":"r","alert_count":1,"max_score":1.0,"severities":{},"first_seen":0,"last_seen":0,
            "status":"pending","updated_at":0}"#;
        let r: Recommendation = serde_json::from_str(old).expect("old stored recommendation");
        assert!(r.sensors.is_empty());
    }

    #[test]
    fn ubuntu_updates_over_ipv6_are_benign() {
        // a real alert from the hosted site: INFO, abnormal-rst + flagged-host, to Canonical's IPv6 range
        let g = one(row("fd17:625c:f037:2:4b31:3944:19c2:e15c", "2620:2d:4002:1::1061", "INFO", 17.0, &["abnormal-rst", "flagged-host"]));
        let d = classify(&g, &Context::builtin());
        assert_eq!(d.verdict, Verdict::Benign, "{d:?}");
        assert!(d.reason.contains("Ubuntu"), "{}", d.reason);
        // an address next to the block is NOT covered
        let other = one(row("fd17:625c:f037:2:4b31:3944:19c2:e15c", "2620:2d:4010::1", "INFO", 17.0, &["abnormal-rst"]));
        assert_eq!(classify(&other, &Context::builtin()).verdict, Verdict::Unknown);
        // and the guard rails still win: a threat-intel match to that range is not hidden
        let mut ti = one(row("fd17:625c:f037:2:4b31:3944:19c2:e15c", "2620:2d:4002:1::1061", "INFO", 17.0, &["abnormal-rst"]));
        ti.threat_intel = true;
        assert_eq!(classify(&ti, &Context::builtin()).verdict, Verdict::Suspicious);
    }
}
