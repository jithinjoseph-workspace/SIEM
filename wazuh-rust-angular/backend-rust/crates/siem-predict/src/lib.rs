//! Threat predictions for the SIEM: which attack stage is likely next.
//!
//! Wazuh rules carry MITRE ATT&CK tactics. For each agent, the tactics of its
//! recent alerts in time order show how far an attack has progressed along the
//! kill chain (initial access -> execution -> ... -> impact). An agent that has
//! moved through several stages in order is likely to reach the next one; the
//! next stage across all agents is one prediction ("Lateral Movement likely").
//!
//! The model is deterministic and every prediction says why (`explanation`).
//! AI only writes the optional briefing. The JSON is the NDR threat
//! prediction's, so the same pages show it.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// MITRE ATT&CK Enterprise tactics in kill-chain order.
pub const TACTICS: [&str; 14] = [
    "reconnaissance",
    "resource development",
    "initial access",
    "execution",
    "persistence",
    "privilege escalation",
    "defense evasion",
    "credential access",
    "discovery",
    "lateral movement",
    "collection",
    "command and control",
    "exfiltration",
    "impact",
];

/// "Credential Access", "credential-access" -> its index in [`TACTICS`].
pub fn tactic_index(t: &str) -> Option<usize> {
    let n = t.trim().to_lowercase().replace(['-', '_'], " ");
    TACTICS.iter().position(|x| *x == n)
}

fn title(t: &str) -> String {
    t.split(' ').map(|w| {
        let mut c = w.chars();
        c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
    }).collect::<Vec<_>>().join(" ")
}

/// One alert (a `siem_alerts` row).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AlertRow {
    pub timestamp: u64,
    pub agent_id: String,
    pub agent_name: String,
    pub rule_id: u32,
    pub rule_level: u32,
    #[serde(default)]
    pub mitre_tactic: String,
    #[serde(default)]
    pub mitre_id: String,
}

/// What one agent's alerts show.
#[derive(Debug, Clone)]
pub struct AgentChain {
    pub agent_id: String,
    pub agent_name: String,
    /// Tactic index -> first time seen.
    pub first_seen: BTreeMap<usize, u64>,
    /// Longest run of stages seen in kill-chain order (by first time seen).
    pub chain: Vec<usize>,
    pub techniques: BTreeSet<String>,
    pub max_level: u32,
    pub alerts: u32,
}

impl AgentChain {
    /// The next stage not seen yet after the furthest one reached.
    pub fn next_stage(&self) -> Option<usize> {
        let furthest = *self.first_seen.keys().max()?;
        (furthest + 1..TACTICS.len()).find(|i| !self.first_seen.contains_key(i))
    }

    /// 0..0.95: stages passed in order, how severe, how many techniques.
    pub fn probability(&self) -> f64 {
        let chain = self.chain.len() as f64;
        let level = if self.max_level >= 12 { 0.15 } else if self.max_level >= 8 { 0.08 } else { 0.0 };
        let tech = 0.04 * (self.techniques.len().min(5) as f64);
        (0.18 * chain - 0.1 + level + tech).clamp(0.0, 0.95)
    }
}

/// Longest increasing subsequence of stages, by first-seen time.
fn ordered_chain(first_seen: &BTreeMap<usize, u64>) -> Vec<usize> {
    let mut by_time: Vec<(u64, usize)> = first_seen.iter().map(|(s, t)| (*t, *s)).collect();
    by_time.sort();
    let stages: Vec<usize> = by_time.into_iter().map(|(_, s)| s).collect();
    let n = stages.len();
    let mut best = vec![1usize; n];
    let mut prev = vec![usize::MAX; n];
    for i in 0..n {
        for j in 0..i {
            if stages[j] < stages[i] && best[j] + 1 > best[i] {
                best[i] = best[j] + 1;
                prev[i] = j;
            }
        }
    }
    let Some(mut i) = (0..n).max_by_key(|&i| best[i]) else { return Vec::new() };
    let mut out = vec![stages[i]];
    while prev[i] != usize::MAX {
        i = prev[i];
        out.push(stages[i]);
    }
    out.reverse();
    out
}

pub fn chains(rows: &[AlertRow]) -> Vec<AgentChain> {
    let mut by: BTreeMap<String, AgentChain> = BTreeMap::new();
    for r in rows {
        let c = by.entry(r.agent_id.clone()).or_insert_with(|| AgentChain {
            agent_id: r.agent_id.clone(),
            agent_name: r.agent_name.clone(),
            first_seen: BTreeMap::new(),
            chain: Vec::new(),
            techniques: BTreeSet::new(),
            max_level: 0,
            alerts: 0,
        });
        let mut any = false;
        for t in r.mitre_tactic.split(',') {
            if let Some(i) = tactic_index(t) {
                any = true;
                let e = c.first_seen.entry(i).or_insert(r.timestamp);
                *e = (*e).min(r.timestamp);
            }
        }
        if any {
            c.alerts += 1;
            c.max_level = c.max_level.max(r.rule_level);
            for id in r.mitre_id.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                c.techniques.insert(id.to_string());
            }
        }
    }
    let mut out: Vec<AgentChain> = by.into_values().filter(|c| !c.first_seen.is_empty()).collect();
    for c in out.iter_mut() {
        c.chain = ordered_chain(&c.first_seen);
    }
    out
}

/// What to do before the predicted stage happens.
pub fn recommendations(stage: usize, agents: &[String]) -> Vec<String> {
    let hosts = agents.join(", ");
    let mut r: Vec<String> = match TACTICS[stage] {
        "execution" => vec!["Review new processes and scripts started on the affected hosts".into(), "Check FIM for new binaries in system and temp folders".into()],
        "persistence" => vec!["Check new services, scheduled tasks, cron jobs and run keys".into(), "Review FIM changes to startup locations".into()],
        "privilege escalation" => vec!["Review sudo / admin group changes and new privileged accounts".into(), "Patch the critical vulnerabilities on these hosts first".into()],
        "defense evasion" => vec!["Watch for disabled security tools and cleared logs (rules 592, 593)".into(), "Confirm the Wazuh agents still report".into()],
        "credential access" => vec!["Force password resets for accounts used on these hosts".into(), "Look for LSASS access and credential dumping tools".into()],
        "discovery" => vec!["Look for network and account enumeration commands".into()],
        "lateral movement" => vec!["Restrict RDP/SMB/SSH from these hosts to the rest of the network".into(), "Consider isolating them with an active response".into()],
        "collection" => vec!["Look for archives and large file copies on these hosts".into()],
        "command and control" => vec!["Block unknown outbound destinations from these hosts".into(), "Check DNS and proxy logs for beaconing".into()],
        "exfiltration" => vec!["Review large outbound transfers and cloud uploads".into(), "Block outbound traffic from these hosts if confirmed".into()],
        "impact" => vec!["Verify backups are current and offline".into(), "Prepare to isolate these hosts (ransomware / wiper risk)".into()],
        _ => vec!["Review the recent alerts of these hosts".into()],
    };
    r.push(format!("Hosts: {hosts}"));
    r
}

/// One prediction (the fields of the NDR's `threat_predictions`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub id: String,
    pub attack_type: String,
    /// 0..1
    pub probability: f64,
    /// 0..1
    pub confidence: f64,
    /// "rising" | "stable" | "falling"
    pub trend: String,
    pub trend_delta: f64,
    pub intel_signal_count: u32,
    /// Share of the tenant's agents involved, 0..100.
    pub exposure_score: f64,
    /// Alerts the prediction is based on.
    pub internal_hit_count: u32,
    pub explanation: String,
    pub recommendations: Vec<String>,
    pub aria_briefing: String,
    pub ai_model: String,
    /// "critical" | "high" | "medium" | "low"
    pub alert_level: String,
    pub predicted_at: String,
    pub agents: Vec<String>,
}

pub fn alert_level(p: f64) -> &'static str {
    if p >= 0.75 {
        "critical"
    } else if p >= 0.5 {
        "high"
    } else if p >= 0.25 {
        "medium"
    } else {
        "low"
    }
}

/// Predictions for one tenant. `previous` = the last probability of each
/// attack type (for the trend); `total_agents` = the tenant's agent count.
pub fn predict(rows: &[AlertRow], previous: &BTreeMap<String, f64>, total_agents: usize, predicted_at: &str) -> Vec<Prediction> {
    let mut by_stage: BTreeMap<usize, Vec<AgentChain>> = BTreeMap::new();
    for c in chains(rows) {
        if c.chain.len() < 2 {
            continue; // one stage alone is not a progression
        }
        if let Some(s) = c.next_stage() {
            by_stage.entry(s).or_default().push(c);
        }
    }
    let mut out = Vec::new();
    for (stage, cs) in by_stage {
        // the chance that at least one of these agents reaches the stage
        let p = 1.0 - cs.iter().map(|c| 1.0 - c.probability()).product::<f64>();
        if p < 0.1 {
            continue;
        }
        let hits: u32 = cs.iter().map(|c| c.alerts).sum();
        let attack_type = title(TACTICS[stage]);
        let delta = previous.get(&attack_type).map(|prev| p - prev).unwrap_or(0.0);
        let names: Vec<String> = cs.iter().map(|c| if c.agent_name.is_empty() { c.agent_id.clone() } else { c.agent_name.clone() }).collect();
        let lead = cs.iter().max_by(|a, b| a.probability().partial_cmp(&b.probability()).unwrap_or(std::cmp::Ordering::Equal)).unwrap();
        let path = lead.chain.iter().map(|i| title(TACTICS[*i])).collect::<Vec<_>>().join(" -> ");
        out.push(Prediction {
            id: uuid::Uuid::new_v4().to_string(),
            attack_type: attack_type.clone(),
            probability: (p * 1000.0).round() / 1000.0,
            confidence: (0.3 + 0.1 * (hits.max(1) as f64).log2()).clamp(0.3, 0.95),
            trend: if delta > 0.05 { "rising" } else if delta < -0.05 { "falling" } else { "stable" }.into(),
            trend_delta: (delta * 1000.0).round() / 1000.0,
            intel_signal_count: 0,
            exposure_score: if total_agents == 0 { 0.0 } else { (100.0 * cs.len() as f64 / total_agents as f64).min(100.0) },
            internal_hit_count: hits,
            explanation: format!(
                "{} host(s) went through {} stage(s) in order; the furthest, {}, went {}. {} is the next stage not seen yet.",
                cs.len(),
                lead.chain.len(),
                if lead.agent_name.is_empty() { &lead.agent_id } else { &lead.agent_name },
                path,
                attack_type
            ),
            recommendations: recommendations(stage, &names),
            aria_briefing: String::new(),
            ai_model: String::new(),
            alert_level: alert_level(p).into(),
            predicted_at: predicted_at.into(),
            agents: names,
        });
    }
    out.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// The AI briefing prompt for a prediction (the AI only explains it).
pub fn briefing_prompt(p: &Prediction) -> String {
    format!(
        "Write a 3-sentence briefing for a SOC analyst. Prediction: {} is the likely next attack stage (probability {:.0}%). Evidence: {} Recommended actions: {}. Be factual; do not invent details.",
        p.attack_type,
        p.probability * 100.0,
        p.explanation,
        p.recommendations.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(agent: &str, ts: u64, tactic: &str, level: u32) -> AlertRow {
        AlertRow { timestamp: ts, agent_id: agent.into(), agent_name: format!("host-{agent}"), rule_id: 1, rule_level: level, mitre_tactic: tactic.into(), mitre_id: format!("T{ts}") }
    }

    #[test]
    fn tactic_names() {
        assert_eq!(tactic_index("Credential Access"), Some(7));
        assert_eq!(tactic_index("lateral-movement"), Some(9));
        assert_eq!(tactic_index("nonsense"), None);
    }

    #[test]
    fn chain_follows_time_order() {
        // execution, then credential access, then (back) persistence: the ordered run is 2 long
        let c = &chains(&[row("1", 10, "Execution", 5), row("1", 20, "Credential Access", 8), row("1", 30, "Persistence", 5)])[0];
        assert_eq!(c.chain.len(), 2);
        assert_eq!(c.next_stage(), Some(8), "after credential access: discovery");
    }

    #[test]
    fn predicts_the_next_stage_with_a_reason() {
        let rows = vec![
            row("1", 10, "Initial Access", 6),
            row("1", 20, "Execution", 7),
            row("1", 30, "Credential Access", 10),
            row("2", 15, "Discovery", 3), // a single stage: no prediction
        ];
        let prev: BTreeMap<String, f64> = [("Discovery".to_string(), 0.2)].into();
        let ps = predict(&rows, &prev, 4, "2026-10-23T08:00:00Z");
        assert_eq!(ps.len(), 1);
        let p = &ps[0];
        assert_eq!(p.attack_type, "Discovery");
        assert!(p.probability > 0.5 && p.probability <= 0.95, "{}", p.probability);
        assert_eq!(p.trend, "rising");
        assert_eq!((p.agents.clone(), p.exposure_score), (vec!["host-1".to_string()], 25.0));
        assert!(p.explanation.contains("Initial Access -> Execution -> Credential Access"), "{}", p.explanation);
        assert!(!p.recommendations.is_empty());
    }
}
