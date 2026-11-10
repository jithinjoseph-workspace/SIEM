//! Organizational security memory: what the tenant's analysts decided before,
//! and why, found again when similar activity comes back.
//!
//! A [`Lesson`] is written when a case is closed or a triage group is decided:
//! what it was (rules, MITRE techniques, rule groups, the hosts, source IPs and
//! users involved), the outcome, the rationale, who decided and when. New
//! activity is a [`Probe`]; [`similar`] scores the stored lessons the way SOC
//! platforms find "similar incidents": same detection rule, same technique,
//! shared entities, similar wording, each with the reason shown.
//!
//! Memory is context, never a verdict: the same rule can be noise once and an
//! attack the next time, so nothing is hidden or closed because of a precedent.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Kept 7 years (the usual retention of incident records in regulated sectors).
pub const RETENTION_DAYS: u32 = 7 * 365;
/// The score from which a lesson is shown as a precedent.
pub const MIN_SCORE: u32 = 30;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Lesson {
    /// `case:<id>` / `triage:<id>`: one lesson per decided thing (a later decision replaces it).
    pub id: String,
    /// "case" | "triage"
    pub kind: String,
    pub title: String,
    pub rule_ids: Vec<u32>,
    pub techniques: Vec<String>,
    pub groups: Vec<String>,
    pub hosts: Vec<String>,
    pub src_ips: Vec<String>,
    pub users: Vec<String>,
    /// "false_positive" | "true_positive" | "benign" | "kept_for_review" | "resolved"
    pub outcome: String,
    /// Why: the triage reason, the case's comments.
    pub rationale: String,
    /// Response that worked (playbooks / actions), if any.
    pub actions: Vec<String>,
    pub decided_by: String,
    /// Unix seconds.
    pub decided_at: u64,
    /// The case number / rule shown in links.
    pub reference: String,
}

impl Lesson {
    /// Hosts, IPs and users, normalized, for the store's prefilter.
    pub fn entities(&self) -> Vec<String> {
        let mut e: BTreeSet<String> = BTreeSet::new();
        for (p, list) in [("host:", &self.hosts), ("ip:", &self.src_ips), ("user:", &self.users)] {
            for x in list.iter().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()) {
                e.insert(format!("{p}{x}"));
            }
        }
        e.into_iter().collect()
    }

    /// The text searched by the memory page.
    pub fn text(&self) -> String {
        format!("{} {} {} {} {}", self.title, self.rationale, self.groups.join(" "), self.techniques.join(" "), self.actions.join(" "))
    }
}

/// New activity to find precedents for (a triage group, a case, an alert).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Probe {
    #[serde(default)]
    pub rule_ids: Vec<u32>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub src_ips: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub text: String,
    /// Leave this lesson out (the probe's own).
    #[serde(default)]
    pub exclude_id: String,
}

impl Probe {
    pub fn entities(&self) -> Vec<String> {
        Lesson { hosts: self.hosts.clone(), src_ips: self.src_ips.clone(), users: self.users.clone(), ..Default::default() }.entities()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Precedent {
    pub lesson: Lesson,
    /// 0..100
    pub score: u32,
    /// Why it matched, in words.
    pub reasons: Vec<String>,
}

fn words(s: &str) -> BTreeSet<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 4)
        .map(String::from)
        .collect()
}

fn lower(v: &[String]) -> BTreeSet<String> {
    v.iter().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect()
}

/// How similar a lesson is to the probe, and why.
pub fn score(p: &Probe, l: &Lesson) -> (u32, Vec<String>) {
    let mut s = 0u32;
    let mut why = Vec::new();
    if let Some(r) = p.rule_ids.iter().find(|r| l.rule_ids.contains(r)) {
        s += 40;
        why.push(format!("same rule {r}"));
    }
    let (pt, lt) = (lower(&p.techniques), lower(&l.techniques));
    if let Some(t) = pt.intersection(&lt).next() {
        s += 20;
        why.push(format!("same MITRE technique {}", t.to_uppercase()));
    }
    for (label, a, b, w) in [("source IP", &p.src_ips, &l.src_ips, 25), ("host", &p.hosts, &l.hosts, 15), ("user", &p.users, &l.users, 15)] {
        if let Some(x) = lower(a).intersection(&lower(b)).next() {
            s += w;
            why.push(format!("same {label} {x}"));
        }
    }
    let g = lower(&p.groups).intersection(&lower(&l.groups)).count() as u32;
    if g > 0 {
        s += (g * 3).min(9);
        why.push(format!("{g} rule group(s) in common"));
    }
    let (pw, lw) = (words(&p.text), words(&l.text()));
    if !pw.is_empty() && !lw.is_empty() {
        let common = pw.intersection(&lw).count() as f64;
        let jac = common / pw.union(&lw).count() as f64;
        let t = (jac * 30.0).round() as u32;
        if t >= 3 {
            s += t;
            why.push("similar wording".into());
        }
    }
    (s.min(100), why)
}

/// The precedents for a probe, best first (at most `limit`).
pub fn similar(p: &Probe, lessons: &[Lesson], limit: usize) -> Vec<Precedent> {
    let mut out: Vec<Precedent> = lessons
        .iter()
        .filter(|l| l.id != p.exclude_id)
        .map(|l| {
            let (score, reasons) = score(p, l);
            Precedent { lesson: l.clone(), score, reasons }
        })
        .filter(|x| x.score >= MIN_SCORE)
        .collect();
    out.sort_by(|a, b| b.score.cmp(&a.score).then(b.lesson.decided_at.cmp(&a.lesson.decided_at)));
    out.truncate(limit);
    out
}

/// A case's status as a memory outcome (`None` while it is still open).
pub fn case_outcome(status: &str) -> Option<&'static str> {
    match status {
        "False Positive" => Some("false_positive"),
        "Resolved" => Some("true_positive"),
        "Closed" => Some("resolved"),
        _ => None,
    }
}

/// What the outcome means, for the analyst.
pub fn outcome_label(o: &str) -> &'static str {
    match o {
        "false_positive" => "False positive",
        "true_positive" => "Confirmed incident",
        "benign" => "Hidden as benign noise",
        "kept_for_review" => "Kept for review",
        _ => "Closed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lesson(id: &str, rule: u32, host: &str, ip: &str, outcome: &str, why: &str, at: u64) -> Lesson {
        Lesson {
            id: id.into(),
            kind: "case".into(),
            title: "SSH brute force".into(),
            rule_ids: vec![rule],
            techniques: vec!["T1110".into()],
            groups: vec!["sshd".into(), "authentication_failed".into()],
            hosts: vec![host.into()],
            src_ips: vec![ip.into()],
            outcome: outcome.into(),
            rationale: why.into(),
            decided_by: "priya".into(),
            decided_at: at,
            ..Default::default()
        }
    }

    #[test]
    fn same_rule_and_entities_rank_first_with_reasons() {
        let ls = vec![
            lesson("case:1", 5710, "backup-01", "10.0.0.9", "false_positive", "nightly rsync job from the backup server", 100),
            lesson("case:2", 5710, "web-01", "203.0.113.9", "true_positive", "brute force from the internet, blocked", 200),
            lesson("case:3", 31101, "web-02", "198.51.100.1", "resolved", "web scan", 300),
        ];
        let p = Probe { rule_ids: vec![5710], techniques: vec!["t1110".into()], hosts: vec!["WEB-01".into()], src_ips: vec!["203.0.113.9".into()], ..Default::default() };
        let r = similar(&p, &ls, 5);
        assert_eq!(r.iter().map(|x| x.lesson.id.as_str()).collect::<Vec<_>>(), ["case:2", "case:1"]);
        assert_eq!(r[0].score, 100);
        assert!(r[0].reasons.contains(&"same source IP 203.0.113.9".to_string()) && r[0].reasons.contains(&"same host web-01".to_string()));
        assert!(r[0].reasons.iter().any(|w| w == "same MITRE technique T1110"));
        // web scan shares nothing that matters: not a precedent
        assert!(r.iter().all(|x| x.lesson.id != "case:3"));
    }

    #[test]
    fn wording_alone_can_match_and_own_lesson_is_left_out() {
        let ls = vec![lesson("triage:9", 1, "h", "1.1.1.1", "benign", "nightly rsync backup job copies files", 5)];
        let p = Probe { text: "rsync backup job nightly copies".into(), ..Default::default() };
        let (s, why) = score(&p, &ls[0]);
        assert!(s >= 10 && why.contains(&"similar wording".to_string()), "{s} {why:?}");
        let p2 = Probe { rule_ids: vec![1], src_ips: vec!["1.1.1.1".into()], exclude_id: "triage:9".into(), ..Default::default() };
        assert!(similar(&p2, &ls, 5).is_empty());
    }

    #[test]
    fn outcomes_and_entities() {
        assert_eq!((case_outcome("False Positive"), case_outcome("Resolved"), case_outcome("In Progress")), (Some("false_positive"), Some("true_positive"), None));
        let l = lesson("x", 1, " Web-01 ", "10.0.0.1", "", "", 0);
        assert_eq!(l.entities(), vec!["host:web-01".to_string(), "ip:10.0.0.1".to_string()]);
    }
}
