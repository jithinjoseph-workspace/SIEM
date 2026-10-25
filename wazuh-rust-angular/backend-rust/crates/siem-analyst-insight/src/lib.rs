//! Analyst cognitive load & trust calibration for the SIEM.
//!
//! From what each analyst does on the triage page (views, opening the alerts of
//! a group, hiding or keeping AI and rule suggestions) and from what happened
//! afterwards (did a host whose alerts they hid later raise a critical alert?),
//! it estimates:
//!
//! - **workload**: decisions per hour, hours active without a break, groups waiting;
//! - **trust**: over-reliance (accepting AI "benign" almost always, fast, without
//!   looking, or hiding something that later turned critical) or under-use
//!   (rejecting nearly all of them);
//! - **explanation depth**: detailed for new analysts and over-reliance, brief
//!   for experienced analysts under load.
//!
//! The adjustments only ever make the AI *more* careful (look at the alerts
//! first, AI verdict shown after looking); AI never gets more autonomy than
//! "recommend only". It is an estimate from behaviour, shown to the analyst
//! themself and their tenant admin, meant to help, not to rate people.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

/// Minimum decisions (7 days) before trust is judged.
pub const MIN_DECISIONS: u32 = 10;
/// An accept within this many seconds of opening the page, without opening the alerts.
pub const FAST_ACCEPT_SECS: u64 = 10;
/// A gap longer than this ends a working stretch.
pub const BREAK_SECS: u64 = 45 * 60;
pub const NEW_ANALYST_DECISIONS: u32 = 30;
pub const EXPERIENCED_DECISIONS: u32 = 200;

/// One logged action of an analyst.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Action {
    /// Unix seconds.
    pub ts: u64,
    pub user: String,
    /// "view" (opened triage) | "inspect" (opened a group's alerts) | "apply" (hid it) |
    /// "dismiss" (kept it) | "suppress" | "unsuppress"
    pub action: String,
    /// The triage recommendation (empty for "view").
    pub rec_id: String,
    /// The suggestion's verdict: "benign" | "unknown" | "suspicious".
    pub verdict: String,
    /// "ai" | "rule" | ""
    pub source: String,
    pub confidence: u8,
}

/// A suppression an analyst created, and the critical alerts the same host raised afterwards.
#[derive(Debug, Clone, Default)]
pub struct HiddenOutcome {
    pub user: String,
    pub later_critical: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Metrics {
    pub user: String,
    /// apply + dismiss, 7 days
    pub decisions_7d: u32,
    pub decisions_last_hour: u32,
    /// Length of the current working stretch (no break over 45 min), hours.
    pub active_hours: f64,
    pub ai_benign_suggestions: u32,
    pub ai_benign_accepted: u32,
    pub ai_benign_rejected: u32,
    pub applies: u32,
    /// Applies preceded by opening that group's alerts.
    pub applies_inspected: u32,
    /// Applies within FAST_ACCEPT_SECS of opening triage, without opening the alerts.
    pub fast_accepts: u32,
    /// Seconds from opening triage to deciding (median).
    pub median_decision_secs: u64,
    /// Hosts this analyst hid alerts of that later raised a critical alert.
    pub hidden_later_critical: u32,
    pub last_active: u64,
}

impl Metrics {
    pub fn acceptance(&self) -> Option<f64> {
        (self.ai_benign_suggestions > 0).then(|| self.ai_benign_accepted as f64 / self.ai_benign_suggestions as f64)
    }

    pub fn inspect_rate(&self) -> Option<f64> {
        (self.applies > 0).then(|| self.applies_inspected as f64 / self.applies as f64)
    }

    pub fn fast_rate(&self) -> Option<f64> {
        (self.applies > 0).then(|| self.fast_accepts as f64 / self.applies as f64)
    }
}

/// Per-user metrics from the actions of the last 7 days (any order).
pub fn metrics(actions: &[Action], outcomes: &[HiddenOutcome], now: u64) -> BTreeMap<String, Metrics> {
    let mut by_user: HashMap<&str, Vec<&Action>> = HashMap::new();
    for a in actions.iter().filter(|a| now.saturating_sub(a.ts) <= 7 * 86400) {
        by_user.entry(a.user.as_str()).or_default().push(a);
    }
    let mut out = BTreeMap::new();
    for (user, mut acts) in by_user {
        acts.sort_by_key(|a| a.ts);
        let mut m = Metrics { user: user.to_string(), ..Default::default() };
        let mut last_view: Option<u64> = None;
        let mut inspected: HashMap<&str, u64> = HashMap::new();
        let mut decision_secs = Vec::new();
        for a in &acts {
            match a.action.as_str() {
                "view" => last_view = Some(a.ts),
                "inspect" => {
                    inspected.insert(a.rec_id.as_str(), a.ts);
                }
                "apply" | "dismiss" => {
                    m.decisions_7d += 1;
                    if now.saturating_sub(a.ts) <= 3600 {
                        m.decisions_last_hour += 1;
                    }
                    let since_view = last_view.map(|v| a.ts.saturating_sub(v));
                    if let Some(s) = since_view {
                        decision_secs.push(s);
                    }
                    let looked = inspected.get(a.rec_id.as_str()).is_some_and(|t| a.ts.saturating_sub(*t) <= 86400);
                    if a.source == "ai" && a.verdict == "benign" {
                        m.ai_benign_suggestions += 1;
                        if a.action == "apply" {
                            m.ai_benign_accepted += 1;
                        } else {
                            m.ai_benign_rejected += 1;
                        }
                    }
                    if a.action == "apply" {
                        m.applies += 1;
                        if looked {
                            m.applies_inspected += 1;
                        } else if since_view.is_some_and(|s| s <= FAST_ACCEPT_SECS) {
                            m.fast_accepts += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        decision_secs.sort();
        m.median_decision_secs = decision_secs.get(decision_secs.len() / 2).copied().unwrap_or(0);
        m.last_active = acts.last().map(|a| a.ts).unwrap_or(0);
        // the working stretch that ends at the last action (if it is recent)
        if now.saturating_sub(m.last_active) <= BREAK_SECS {
            let mut start = m.last_active;
            for w in acts.windows(2).rev() {
                if w[1].ts.saturating_sub(w[0].ts) > BREAK_SECS {
                    break;
                }
                start = w[0].ts;
            }
            m.active_hours = ((m.last_active - start) as f64 / 3600.0 * 10.0).round() / 10.0;
        }
        m.hidden_later_critical = outcomes.iter().filter(|o| o.user == user).map(|o| o.later_critical).sum();
        out.insert(user.to_string(), m);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Workload {
    Normal,
    High,
    Overload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    InsufficientData,
    Calibrated,
    OverReliance,
    UnderUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Depth {
    Brief,
    Standard,
    Detailed,
}

/// How the triage page adapts for one analyst.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Calibration {
    pub workload: Workload,
    pub trust: Trust,
    pub depth: Depth,
    /// "Hide" works only after opening the group's alerts.
    pub require_inspect: bool,
    /// The AI's verdict is shown after opening the alerts (no anchoring).
    pub hide_ai_verdict_until_inspect: bool,
    /// Show summaries and the largest groups first.
    pub summaries_first: bool,
    /// Plain-language reasons, for the analyst.
    pub notes: Vec<String>,
    pub metrics: Metrics,
}

/// `pending_per_analyst`: groups waiting for review divided by active analysts.
pub fn calibrate(m: &Metrics, pending_per_analyst: f64) -> Calibration {
    let mut notes = Vec::new();
    let workload = if m.decisions_last_hour > 120 || m.active_hours >= 10.0 {
        Workload::Overload
    } else if m.decisions_last_hour > 60 || m.active_hours >= 8.0 || pending_per_analyst > 200.0 {
        Workload::High
    } else {
        Workload::Normal
    };
    match workload {
        Workload::Overload => notes.push(format!("Workload looks very high ({} decisions in the last hour, {} h without a long break). Consider a break or sharing the queue.", m.decisions_last_hour, m.active_hours)),
        Workload::High => notes.push("Workload looks high: summaries and the largest groups are shown first.".into()),
        Workload::Normal => {}
    }

    let acc = m.acceptance();
    let trust = if m.decisions_7d < MIN_DECISIONS {
        Trust::InsufficientData
    } else if m.hidden_later_critical > 0
        || (acc.is_some_and(|a| a >= 0.9) && m.ai_benign_suggestions >= 5 && (m.fast_rate().is_some_and(|f| f >= 0.5) || m.inspect_rate().is_some_and(|i| i < 0.2)))
    {
        Trust::OverReliance
    } else if acc.is_some_and(|a| a < 0.3) && m.ai_benign_suggestions >= MIN_DECISIONS {
        Trust::UnderUse
    } else {
        Trust::Calibrated
    };
    match trust {
        Trust::OverReliance => {
            if m.hidden_later_critical > 0 {
                notes.push(format!("{} host(s) whose alerts you hid later raised a critical alert. Open a group's alerts before hiding it.", m.hidden_later_critical));
            } else {
                notes.push("You accept almost every AI suggestion, often within seconds and without opening the alerts. The AI verdict now shows after you open them.".into());
            }
        }
        Trust::UnderUse => notes.push("You reject most AI \"likely benign\" suggestions. If they are wrong, tell your tenant admin; if not, they can save you time.".into()),
        Trust::InsufficientData => notes.push(format!("Not enough decisions yet ({} of {MIN_DECISIONS}) to judge how you use AI suggestions.", m.decisions_7d)),
        Trust::Calibrated => {}
    }

    let depth = if trust == Trust::OverReliance || m.decisions_7d < NEW_ANALYST_DECISIONS {
        Depth::Detailed
    } else if m.decisions_7d >= EXPERIENCED_DECISIONS && workload != Workload::Normal {
        Depth::Brief
    } else {
        Depth::Standard
    };

    Calibration {
        workload,
        trust,
        depth,
        require_inspect: trust == Trust::OverReliance,
        hide_ai_verdict_until_inspect: trust == Trust::OverReliance,
        summaries_first: workload != Workload::Normal,
        notes,
        metrics: m.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn act(ts: u64, action: &str, rec: &str, verdict: &str, source: &str) -> Action {
        Action { ts, user: "ana".into(), action: action.into(), rec_id: rec.into(), verdict: verdict.into(), source: source.into(), confidence: 80 }
    }

    const NOW: u64 = 1_000_000;

    #[test]
    fn counts_decisions_inspection_and_fast_accepts() {
        let a = vec![
            act(NOW - 100, "view", "", "", ""),
            act(NOW - 95, "apply", "r1", "benign", "ai"),   // fast, not inspected
            act(NOW - 60, "inspect", "r2", "", ""),
            act(NOW - 50, "apply", "r2", "benign", "ai"),   // inspected
            act(NOW - 40, "dismiss", "r3", "benign", "ai"), // rejected AI
        ];
        let m = &metrics(&a, &[], NOW)["ana"];
        assert_eq!((m.decisions_7d, m.applies, m.applies_inspected, m.fast_accepts), (3, 2, 1, 1));
        assert_eq!((m.ai_benign_suggestions, m.ai_benign_accepted, m.ai_benign_rejected), (3, 2, 1));
        assert_eq!(m.median_decision_secs, 50);
    }

    #[test]
    fn working_stretch_breaks_on_long_gaps() {
        // a break before NOW-7200, then activity every 30 min
        let a: Vec<Action> = [20_000, 7200, 5400, 3600, 1800, 60].iter().map(|s| act(NOW - s, "view", "", "", "")).collect();
        assert_eq!(metrics(&a, &[], NOW)["ana"].active_hours, 2.0);
        let idle = vec![act(NOW - 10_000, "view", "", "", "")];
        assert_eq!(metrics(&idle, &[], NOW)["ana"].active_hours, 0.0);
    }

    fn many(n: u64, inspect: bool) -> Vec<Action> {
        let mut a = Vec::new();
        for i in 0..n {
            let t = NOW - 3000 + i * 20;
            a.push(act(t, "view", "", "", ""));
            if inspect {
                a.push(act(t + 5, "inspect", &format!("r{i}"), "", ""));
            }
            a.push(act(t + 8, "apply", &format!("r{i}"), "benign", "ai"));
        }
        a
    }

    #[test]
    fn over_reliance_makes_the_ai_more_careful() {
        let m = &metrics(&many(12, false), &[], NOW)["ana"];
        let c = calibrate(m, 0.0);
        assert_eq!(c.trust, Trust::OverReliance);
        assert!(c.require_inspect && c.hide_ai_verdict_until_inspect);
        assert_eq!(c.depth, Depth::Detailed);
        // the same decisions after opening the alerts are calibrated
        let m2 = &metrics(&many(12, true), &[], NOW)["ana"];
        assert_eq!(calibrate(m2, 0.0).trust, Trust::Calibrated);
        // hiding something that later turned critical is over-reliance too
        let m3 = &metrics(&many(12, true), &[HiddenOutcome { user: "ana".into(), later_critical: 1 }], NOW)["ana"];
        assert_eq!(calibrate(m3, 0.0).trust, Trust::OverReliance);
    }

    #[test]
    fn under_use_workload_and_insufficient_data() {
        let mut a = Vec::new();
        for i in 0..12 {
            a.push(act(NOW - 2000 + i * 30, "dismiss", &format!("r{i}"), "benign", "ai"));
        }
        assert_eq!(calibrate(&metrics(&a, &[], NOW)["ana"], 0.0).trust, Trust::UnderUse);
        let few = metrics(&many(3, true), &[], NOW);
        let c = calibrate(&few["ana"], 250.0);
        assert_eq!((c.trust, c.workload, c.summaries_first), (Trust::InsufficientData, Workload::High, true));
        // never more autonomy: no flag ever turns checks off
        assert!(!c.require_inspect);
    }
}
