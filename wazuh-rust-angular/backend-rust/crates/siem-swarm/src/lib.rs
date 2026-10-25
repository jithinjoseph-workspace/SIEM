//! Federated, privacy-preserving threat swarm.
//!
//! Independent AETHER deployments share **anonymous attack fingerprints**
//! through a hub, never raw logs:
//!
//! - what is shared: an attacker's *public* IP, a malicious file hash, an
//!   ordered chain of MITRE techniques, the Wazuh rule ids (a public ruleset),
//!   a severity bucket, the day, and a sighting count with Laplace noise;
//! - what is never shared: log lines, host names, users, internal (private)
//!   addresses, agent or tenant identities;
//! - indicators are keyed hashes (HMAC-SHA256 with the community key the
//!   members share): the hub counts tokens without knowing what they are, and
//!   a member can only recognise an indicator it has seen itself;
//! - k-anonymity: the hub publishes a fingerprint when at least `k`
//!   organisations reported it (critical ones may be fast-tracked, and are
//!   labelled with the number of organisations);
//! - a match is a signal (threat intel), never an automatic block, so one
//!   member cannot make the others block something by reporting it.
//!
//! Federated model updates are not part of this: the SIEM's detection is the
//! Wazuh ruleset plus LLM providers, not a locally trained model.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

pub const DEFAULT_EPSILON: f64 = 1.0;
pub const DEFAULT_K: u32 = 2;
/// Alerts from this level up give indicators (lower levels are mostly noise).
pub const MIN_LEVEL: u32 = 7;
pub const MIN_CHAIN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ExternalIp,
    FileHash,
    TechniqueChain,
}

/// One anonymous fingerprint, as a member sends it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub kind: Kind,
    /// HMAC-SHA256(community key, kind | value), 32 hex characters.
    pub token: String,
    /// MITRE technique ids seen with it (public ATT&CK ids).
    pub techniques: Vec<String>,
    /// Wazuh rule ids (the public ruleset).
    pub rule_ids: Vec<u32>,
    /// 0 low, 1 medium, 2 high, 3 critical
    pub severity: u8,
    /// Days since 1970 (no time of day).
    pub day: u32,
    /// Sightings with Laplace noise (at least 1).
    pub sightings: u32,
    /// The reporting organisation, opaque (a keyed hash of the tenant, never its name).
    pub org: String,
}

/// What was seen locally, before anonymizing (never leaves the deployment).
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub kind: Kind,
    /// The IP, the hash, or the chain ("T1566>T1059>T1003").
    pub value: String,
    pub techniques: BTreeSet<String>,
    pub rule_ids: BTreeSet<u32>,
    pub max_level: u32,
    pub count: u32,
    pub day: u32,
}

pub fn severity_bucket(level: u32) -> u8 {
    match level {
        12.. => 3,
        8..=11 => 2,
        4..=7 => 1,
        _ => 0,
    }
}

/// A routable public address (no private, loopback, link-local, CGNAT, documentation...).
pub fn is_public_ip(s: &str) -> bool {
    match s.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => {
            let o = v.octets();
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_broadcast() || v.is_multicast() || v.is_unspecified() || o[0] == 0 || (o[0] == 100 && (o[1] & 0xc0) == 64) || o[0] >= 240)
        }
        Ok(IpAddr::V6(v)) => {
            let s = v.segments();
            !(v.is_loopback() || v.is_multicast() || v.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80)
        }
        Err(_) => false,
    }
}

fn is_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// The keyed token of an indicator.
pub fn token(key: &[u8], kind: Kind, value: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(format!("{kind:?}|{}", value.trim().to_lowercase()).as_bytes());
    m.finalize().into_bytes().iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// The opaque organisation id of a tenant (the deployment's own secret, so the
/// hub can count organisations without learning which they are).
pub fn org_id(deployment_secret: &[u8], tenant: &str) -> String {
    token(deployment_secret, Kind::ExternalIp, &format!("org:{tenant}"))
}

/// A Wazuh alert (JSON) as one alert's indicators: the public source IP and
/// malicious file hashes of alerts from [`MIN_LEVEL`].
pub fn indicators(alert: &Value) -> Vec<(Kind, String)> {
    let level = alert["rule"]["level"].as_u64().unwrap_or(0) as u32;
    let mut out = Vec::new();
    let vt_malicious = alert["data"]["virustotal"]["malicious"].as_str() == Some("1");
    if level < MIN_LEVEL && !vt_malicious {
        return out;
    }
    for ip in [&alert["data"]["srcip"], &alert["decoded"]["src_ip"]] {
        if let Some(s) = ip.as_str().filter(|s| is_public_ip(s)) {
            out.push((Kind::ExternalIp, s.trim().to_string()));
        }
    }
    if vt_malicious {
        for h in ["sha1", "md5", "sha256"] {
            if let Some(s) = alert["data"]["virustotal"]["source"][h].as_str().filter(|s| is_hash(s)) {
                out.push((Kind::FileHash, s.to_lowercase()));
            }
        }
    }
    if level >= 12 {
        for h in ["sha256_after", "sha1_after", "md5_after"] {
            if let Some(s) = alert["syscheck"][h].as_str().filter(|s| is_hash(s)) {
                out.push((Kind::FileHash, s.to_lowercase()));
                break;
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn techniques_of(alert: &Value) -> Vec<String> {
    let m = &alert["rule"]["mitre"];
    let mut v: Vec<String> = m["id"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    if let Some(s) = m["id"].as_str() {
        v.extend(s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()));
    }
    v
}

/// Observations from a tenant's alerts (JSON, any order): indicators, and each
/// host's ordered chain of distinct techniques (hosts are not kept).
pub fn observe(alerts: &[Value], day: u32) -> Vec<Observation> {
    let mut by: BTreeMap<(Kind, String), Observation> = BTreeMap::new();
    let mut chains: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for a in alerts {
        let level = a["rule"]["level"].as_u64().unwrap_or(0) as u32;
        let rule: Option<u32> = a["rule"]["id"].as_str().and_then(|s| s.parse().ok()).or(a["rule"]["id"].as_u64().map(|n| n as u32));
        let techs = techniques_of(a);
        for (kind, value) in indicators(a) {
            let o = by.entry((kind, value.clone())).or_insert_with(|| Observation { kind, value, techniques: BTreeSet::new(), rule_ids: BTreeSet::new(), max_level: 0, count: 0, day });
            o.count += 1;
            o.max_level = o.max_level.max(level);
            o.techniques.extend(techs.iter().cloned());
            o.rule_ids.extend(rule);
        }
        let host = a["agent"]["id"].as_str().unwrap_or("").to_string();
        let ts = a["timestamp"].as_str().unwrap_or("").to_string();
        for t in techs {
            chains.entry(host.clone()).or_default().push((ts.clone(), t));
        }
    }
    for (_, mut steps) in chains {
        steps.sort();
        let mut seen = Vec::<String>::new();
        for (_, t) in steps {
            if !seen.contains(&t) {
                seen.push(t);
            }
        }
        if seen.len() >= MIN_CHAIN {
            let value = seen.join(">");
            let o = by.entry((Kind::TechniqueChain, value.clone())).or_insert_with(|| Observation { kind: Kind::TechniqueChain, value, techniques: seen.iter().cloned().collect(), rule_ids: BTreeSet::new(), max_level: 0, count: 0, day });
            o.count += 1;
        }
    }
    by.into_values().collect()
}

/// Laplace noise (scale 1/epsilon) on a count; at least 1.
pub fn noisy_count(count: u32, epsilon: f64, rng: &mut impl rand::Rng) -> u32 {
    let u: f64 = rng.gen_range(-0.5..0.5);
    let b = 1.0 / epsilon.max(0.01);
    let noise = -b * u.signum() * (1.0 - 2.0 * u.abs()).ln();
    ((count as f64 + noise).round()).max(1.0) as u32
}

/// An observation as the fingerprint that may leave the deployment.
pub fn anonymize(o: &Observation, key: &[u8], org: &str, epsilon: f64, rng: &mut impl rand::Rng) -> Fingerprint {
    Fingerprint {
        kind: o.kind,
        token: token(key, o.kind, &o.value),
        techniques: o.techniques.iter().cloned().collect(),
        rule_ids: o.rule_ids.iter().copied().collect(),
        severity: severity_bucket(o.max_level),
        day: o.day,
        sightings: noisy_count(o.count, epsilon, rng),
        org: org.to_string(),
    }
}

/// A fingerprint the hub has published.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedEntry {
    pub kind: Kind,
    pub token: String,
    pub techniques: Vec<String>,
    pub rule_ids: Vec<u32>,
    pub severity: u8,
    /// Distinct organisations that reported it.
    pub orgs: u32,
    pub sightings: u32,
    pub first_day: u32,
    pub last_day: u32,
    /// Published with one organisation because it is critical.
    pub fast_tracked: bool,
}

/// The hub: the published feed from all reports (`k` organisations, or one for
/// a critical fingerprint when `fast_track_critical`).
pub fn aggregate(reports: &[Fingerprint], k: u32, fast_track_critical: bool) -> Vec<FeedEntry> {
    let mut by: BTreeMap<String, (Fingerprint, BTreeSet<String>, u32, u32, u32, BTreeSet<String>, BTreeSet<u32>, u8)> = BTreeMap::new();
    for r in reports {
        let e = by.entry(r.token.clone()).or_insert_with(|| (r.clone(), BTreeSet::new(), 0, u32::MAX, 0, BTreeSet::new(), BTreeSet::new(), 0));
        e.1.insert(r.org.clone());
        e.2 += r.sightings;
        e.3 = e.3.min(r.day);
        e.4 = e.4.max(r.day);
        e.5.extend(r.techniques.iter().cloned());
        e.6.extend(r.rule_ids.iter().copied());
        e.7 = e.7.max(r.severity);
    }
    by.into_values()
        .filter_map(|(f, orgs, sightings, first, last, techs, rules, sev)| {
            let n = orgs.len() as u32;
            let fast = n < k && fast_track_critical && sev >= 3;
            (n >= k || fast).then(|| FeedEntry { kind: f.kind, token: f.token, techniques: techs.into_iter().collect(), rule_ids: rules.into_iter().collect(), severity: sev, orgs: n, sightings, first_day: first, last_day: last, fast_tracked: fast })
        })
        .collect()
}

/// A local alert's indicators that are in the feed.
pub fn matches<'a>(alert: &Value, key: &[u8], feed: &'a BTreeMap<String, FeedEntry>) -> Vec<(Kind, String, &'a FeedEntry)> {
    indicators(alert).into_iter().filter_map(|(k, v)| feed.get(&token(key, k, &v)).map(|e| (k, v, e))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use serde_json::json;

    const KEY: &[u8] = b"community-key";

    fn alert(level: u32, src: &str, agent: &str, ts: &str, mitre: &[&str]) -> Value {
        json!({ "timestamp": ts, "rule": { "level": level, "id": "5712", "mitre": { "id": mitre } }, "agent": { "id": agent, "name": "web-01" }, "data": { "srcip": src }, "full_log": "secret log line with user alice" })
    }

    #[test]
    fn only_public_ips_from_real_alerts_are_indicators() {
        assert_eq!(indicators(&alert(10, "203.0.113.9", "001", "t", &[])), vec![(Kind::ExternalIp, "203.0.113.9".into())]);
        assert!(indicators(&alert(10, "10.0.0.5", "001", "t", &[])).is_empty(), "private");
        assert!(indicators(&alert(10, "100.64.1.1", "001", "t", &[])).is_empty(), "CGNAT");
        assert!(indicators(&alert(3, "203.0.113.9", "001", "t", &[])).is_empty(), "low level");
        let vt = json!({ "rule": { "level": 12, "id": "87105" }, "data": { "virustotal": { "malicious": "1", "source": { "sha1": "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3", "md5": "bad" } } } });
        assert_eq!(indicators(&vt), vec![(Kind::FileHash, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3".into())]);
    }

    #[test]
    fn fingerprints_carry_no_raw_data() {
        let alerts = vec![
            alert(10, "203.0.113.9", "agent-77", "2026-10-25T01:00:00", &["T1566"]),
            alert(10, "203.0.113.9", "agent-77", "2026-10-25T02:00:00", &["T1059.001"]),
            alert(12, "203.0.113.9", "agent-77", "2026-10-25T03:00:00", &["T1003.001"]),
        ];
        let obs = observe(&alerts, 20385);
        let ip = obs.iter().find(|o| o.kind == Kind::ExternalIp).unwrap();
        assert_eq!((ip.count, ip.max_level), (3, 12));
        let chain = obs.iter().find(|o| o.kind == Kind::TechniqueChain).unwrap();
        assert_eq!(chain.value, "T1566>T1059.001>T1003.001");
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let fp = anonymize(ip, KEY, "org-a", 1.0, &mut rng);
        let s = serde_json::to_string(&fp).unwrap();
        for secret in ["203.0.113.9", "web-01", "alice", "agent-77", "secret log"] {
            assert!(!s.contains(secret), "{secret} leaked: {s}");
        }
        assert_eq!(fp.token.len(), 32);
        assert_eq!(fp.token, token(KEY, Kind::ExternalIp, " 203.0.113.9 "), "same indicator, same token");
        assert_ne!(fp.token, token(b"other-key", Kind::ExternalIp, "203.0.113.9"), "another community cannot match");
        assert_eq!(fp.severity, 3);
    }

    #[test]
    fn laplace_noise_hides_exact_counts_on_average_unbiased() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let v: Vec<u32> = (0..5000).map(|_| noisy_count(20, 1.0, &mut rng)).collect();
        let mean = v.iter().map(|&x| x as f64).sum::<f64>() / v.len() as f64;
        assert!((mean - 20.0).abs() < 0.3, "{mean}");
        assert!(v.iter().any(|&x| x != 20), "noisy");
        assert!(v.iter().all(|&x| x >= 1));
    }

    #[test]
    fn hub_publishes_after_k_orgs_or_fast_tracks_critical() {
        let fp = |tok: &str, org: &str, sev: u8, day: u32| Fingerprint { kind: Kind::ExternalIp, token: tok.into(), techniques: vec!["T1110".into()], rule_ids: vec![5712], severity: sev, day, sightings: 3, org: org.into() };
        let reports = vec![fp("a", "o1", 2, 10), fp("a", "o1", 2, 11), fp("b", "o1", 2, 10), fp("b", "o2", 1, 12), fp("c", "o3", 3, 12)];
        let feed = aggregate(&reports, 2, true);
        let get = |t: &str| feed.iter().find(|e| e.token == t);
        assert!(get("a").is_none(), "one org twice is still one org");
        let b = get("b").unwrap();
        assert_eq!((b.orgs, b.first_day, b.last_day, b.severity, b.fast_tracked), (2, 10, 12, 2, false));
        assert!(get("c").unwrap().fast_tracked);
        assert!(aggregate(&reports, 2, false).iter().all(|e| e.token != "c"));
    }

    #[test]
    fn a_member_recognises_only_what_it_sees() {
        let feed: BTreeMap<String, FeedEntry> = [(token(KEY, Kind::ExternalIp, "198.51.100.7"), FeedEntry { kind: Kind::ExternalIp, token: String::new(), techniques: vec![], rule_ids: vec![], severity: 2, orgs: 3, sightings: 9, first_day: 1, last_day: 2, fast_tracked: false })].into();
        assert_eq!(matches(&alert(9, "198.51.100.7", "001", "t", &[]), KEY, &feed).len(), 1);
        assert!(matches(&alert(9, "198.51.100.8", "001", "t", &[]), KEY, &feed).is_empty());
        assert_ne!(org_id(b"s", "acme"), org_id(b"s", "globex"));
        assert!(!org_id(b"s", "acme").contains("acme"));
    }
}
