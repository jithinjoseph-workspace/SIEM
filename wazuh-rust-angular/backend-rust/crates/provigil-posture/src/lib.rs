//! Security posture: a score from 0 to 100 (100 = strongest) per tenant and per host, made of
//! five components, the reasons behind it, and a forecast for the next day with a confidence
//! range taken from the real errors of past forecasts. No I/O: the caller loads the data.
//! Spec: `specs/provigil-posture.md`.

use serde::{Deserialize, Serialize};

/// Component weights in percent (they sum to 100).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Weights {
    pub threat: f64,
    pub vulnerabilities: f64,
    pub hardening: f64,
    pub progression: f64,
    pub hygiene: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Weights { threat: 30.0, vulnerabilities: 25.0, hardening: 20.0, progression: 15.0, hygiene: 10.0 }
    }
}

// ---------------------------------------------------------------- inputs

/// One day's alerts of one host and rule (real agents only).
#[derive(Clone, Debug)]
pub struct AlertCount {
    pub agent_id: String,
    pub agent_name: String,
    pub rule_id: u32,
    pub level: u8,
    pub description: String,
    pub count: u64,
}

/// One host's open vulnerabilities.
#[derive(Clone, Debug, Default)]
pub struct HostVulns {
    pub agent_id: String,
    pub agent_name: String,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    /// known exploited (CISA KEV)
    pub kev: u32,
}

/// One host's configuration assessment.
#[derive(Clone, Debug, Default)]
pub struct HostSca {
    pub agent_id: String,
    pub passed: u32,
    pub failed: u32,
}

/// The strongest attack signal: an intent dossier or a threat prediction.
#[derive(Clone, Debug, Default)]
pub struct Progression {
    pub agent_name: String,
    pub intent: String,
    /// 0..1
    pub probability: f64,
    /// 0..1 of the kill chain
    pub progress: f64,
    pub accelerating: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Hygiene {
    pub agents: u32,
    pub active: u32,
    /// critical or high cases open for more than 24 hours
    pub stale_cases: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Inputs {
    /// today's alerts (last 24 h)
    pub alerts: Vec<AlertCount>,
    /// the alert load (see [`alert_load`]) of each earlier day, oldest first; `None` = no data
    pub load_history: Vec<Option<f64>>,
    pub vulns: Vec<HostVulns>,
    pub sca: Vec<HostSca>,
    pub progression: Vec<Progression>,
    pub hygiene: Hygiene,
}

// ---------------------------------------------------------------- output

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Components {
    pub threat: f64,
    pub vulnerabilities: f64,
    pub hardening: f64,
    pub progression: f64,
    pub hygiene: f64,
}

/// A reason: the points it costs (negative) and what it is.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Driver {
    pub component: String,
    pub points: f64,
    pub text: String,
    pub agent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HostScore {
    pub agent_id: String,
    pub agent_name: String,
    pub score: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Posture {
    pub score: f64,
    pub band: String,
    pub components: Components,
    pub drivers: Vec<Driver>,
    pub hosts: Vec<HostScore>,
    /// today's alert load, kept in the history for baselines and forecasts
    pub alert_load: f64,
    pub notes: Vec<String>,
}

pub fn band(score: f64) -> &'static str {
    match score {
        s if s >= 80.0 => "Good",
        s if s >= 60.0 => "Fair",
        s if s >= 40.0 => "At Risk",
        _ => "Critical",
    }
}

// ---------------------------------------------------------------- scoring

/// One alert at this level, in load points: critical alerts weigh most, routine ones nothing.
fn level_weight(level: u8) -> f64 {
    match level {
        12.. => 10.0,
        7..=11 => 3.0,
        4..=6 => 0.5,
        _ => 0.0,
    }
}

/// One rule on one host counts at most this many times a day: a single noisy rule cannot
/// dominate the score.
pub const RULE_CAP: u64 = 20;

/// The day's severity-weighted alert load per active host.
pub fn alert_load(alerts: &[AlertCount], active_hosts: u32) -> f64 {
    let total: f64 = alerts.iter().map(|a| a.count.min(RULE_CAP) as f64 * level_weight(a.level)).sum();
    total / active_hosts.max(1) as f64
}

/// Median and median absolute deviation of the days with data.
pub fn median_mad(xs: &[f64]) -> Option<(f64, f64)> {
    if xs.is_empty() {
        return None;
    }
    let med = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.total_cmp(b));
        let n = v.len();
        if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
    };
    let mut v = xs.to_vec();
    let m = med(&mut v);
    let mut dev: Vec<f64> = xs.iter().map(|x| (x - m).abs()).collect();
    Some((m, med(&mut dev)))
}

/// Days with data, values beyond 5 MAD capped (a load test or a flood day does not move the baseline).
pub fn robust_history(history: &[Option<f64>]) -> Vec<f64> {
    let have: Vec<f64> = history.iter().flatten().copied().collect();
    let Some((m, mad)) = median_mad(&have) else { return have };
    let limit = m + 5.0 * (1.4826 * mad).max(1.0);
    have.into_iter().map(|x| x.min(limit)).collect()
}

/// Threat component from today's load: an absolute curve, minus a penalty when today is well
/// above this tenant's own normal (only with at least 3 earlier days of data).
pub fn threat_score(load: f64, history: &[Option<f64>]) -> f64 {
    let absolute = 100.0 * (-load / 150.0).exp();
    let hist = robust_history(history);
    let penalty = match median_mad(&hist) {
        Some((m, mad)) if hist.len() >= 3 => ((load - m) / (1.4826 * mad).max(1.0)).clamp(0.0, 5.0) * 6.0,
        _ => 0.0,
    };
    (absolute - penalty).clamp(0.0, 100.0)
}

fn vuln_exposure(v: &HostVulns) -> f64 {
    v.critical as f64 * 10.0 + v.high as f64 * 4.0 + v.medium as f64 + v.low as f64 * 0.2 + v.kev as f64 * 15.0
}

/// A host's vulnerability component: 100 with nothing open, 50 at an exposure of 500 points.
pub fn host_vuln_score(v: &HostVulns) -> f64 {
    100.0 / (1.0 + vuln_exposure(v) / 500.0)
}

fn host_sca_score(s: &HostSca) -> Option<f64> {
    let n = s.passed + s.failed;
    (n > 0).then(|| 100.0 * s.passed as f64 / n as f64)
}

fn mean(xs: impl Iterator<Item = f64>) -> Option<f64> {
    let (sum, n) = xs.fold((0.0, 0u32), |(s, n), x| (s + x, n + 1));
    (n > 0).then(|| sum / n as f64)
}

/// The strongest attack signal as risk 0..1 (intent probability times how far it got).
fn progression_risk(p: &Progression) -> f64 {
    (p.probability * (0.4 + 0.6 * p.progress) * if p.accelerating { 1.15 } else { 1.0 }).clamp(0.0, 1.0)
}

pub fn score(i: &Inputs, w: &Weights) -> Posture {
    let mut notes = Vec::new();
    // per enrolled host, the same measure as the history days
    let load = alert_load(&i.alerts, i.hygiene.agents);
    let threat = threat_score(load, &i.load_history);
    if i.load_history.iter().flatten().count() < 3 {
        notes.push("Less than 3 days of alert history: the threat score uses the absolute scale only.".into());
    }
    let vulnerabilities = mean(i.vulns.iter().map(host_vuln_score)).unwrap_or(100.0);
    let hardening = mean(i.sca.iter().filter_map(host_sca_score)).unwrap_or_else(|| {
        notes.push("No configuration assessment results yet.".into());
        50.0
    });
    let top = i.progression.iter().max_by(|a, b| progression_risk(a).total_cmp(&progression_risk(b)));
    let progression = 100.0 * (1.0 - top.map(progression_risk).unwrap_or(0.0));
    let hygiene = if i.hygiene.agents == 0 {
        notes.push("No agents enrolled.".into());
        0.0
    } else {
        (100.0 * i.hygiene.active as f64 / i.hygiene.agents as f64 - 10.0 * i.hygiene.stale_cases as f64).clamp(0.0, 100.0)
    };
    let c = Components { threat, vulnerabilities, hardening, progression, hygiene };
    let total = combine(&c, w);

    // reasons: what each component costs, with its biggest cause
    let mut drivers = Vec::new();
    let cost = |s: f64, wt: f64| -((100.0 - s) * wt / 100.0);
    if threat < 100.0 {
        let worst = i.alerts.iter().max_by(|a, b| (a.count.min(RULE_CAP) as f64 * level_weight(a.level)).total_cmp(&(b.count.min(RULE_CAP) as f64 * level_weight(b.level))));
        let crit: u64 = i.alerts.iter().filter(|a| a.level >= 12).map(|a| a.count).sum();
        let text = match worst {
            Some(a) => format!("{crit} critical alerts in 24 h; most weight: rule {} \"{}\" on {} ({} times)", a.rule_id, a.description, a.agent_name, a.count),
            None => "Alert activity above this tenant's normal".into(),
        };
        drivers.push(Driver { component: "threat".into(), points: cost(threat, w.threat), text, agent: worst.map(|a| a.agent_name.clone()) });
    }
    if vulnerabilities < 100.0 {
        let worst = i.vulns.iter().max_by(|a, b| vuln_exposure(a).total_cmp(&vuln_exposure(b)));
        let (crit, kev): (u32, u32) = i.vulns.iter().fold((0, 0), |(c, k), v| (c + v.critical, k + v.kev));
        let text = match worst {
            Some(v) => format!("{crit} critical and {kev} known-exploited CVEs open; most on {} ({} critical, {} high)", v.agent_name, v.critical, v.high),
            None => String::new(),
        };
        drivers.push(Driver { component: "vulnerabilities".into(), points: cost(vulnerabilities, w.vulnerabilities), text, agent: worst.map(|v| v.agent_name.clone()) });
    }
    if hardening < 100.0 {
        let (p, f) = i.sca.iter().fold((0, 0), |(p, f), s| (p + s.passed, f + s.failed));
        drivers.push(Driver { component: "hardening".into(), points: cost(hardening, w.hardening), text: format!("Configuration checks: {p} passed, {f} failed ({hardening:.0} % pass rate)"), agent: None });
    }
    if let Some(t) = top.filter(|_| progression < 100.0) {
        drivers.push(Driver {
            component: "progression".into(),
            points: cost(progression, w.progression),
            text: format!("{} on {}: {:.0} % likely, {:.0} % through the kill chain{}", t.intent, t.agent_name, t.probability * 100.0, t.progress * 100.0, if t.accelerating { ", accelerating" } else { "" }),
            agent: Some(t.agent_name.clone()),
        });
    }
    if hygiene < 100.0 && i.hygiene.agents > 0 {
        drivers.push(Driver {
            component: "hygiene".into(),
            points: cost(hygiene, w.hygiene),
            text: format!("{} of {} agents active; {} critical/high cases open over 24 h", i.hygiene.active, i.hygiene.agents, i.hygiene.stale_cases),
            agent: None,
        });
    }
    drivers.sort_by(|a, b| a.points.total_cmp(&b.points));

    // per host: the parts that belong to a host (alerts, vulnerabilities, configuration)
    let mut hosts: Vec<HostScore> = i
        .vulns
        .iter()
        .map(|v| {
            let host_alerts: Vec<AlertCount> = i.alerts.iter().filter(|a| a.agent_id == v.agent_id).cloned().collect();
            let t = threat_score(alert_load(&host_alerts, 1), &[]);
            let s = i.sca.iter().find(|s| s.agent_id == v.agent_id).and_then(host_sca_score).unwrap_or(50.0);
            HostScore { agent_id: v.agent_id.clone(), agent_name: v.agent_name.clone(), score: round1((t * 0.4 + host_vuln_score(v) * 0.35 + s * 0.25).clamp(0.0, 100.0)) }
        })
        .collect();
    hosts.sort_by(|a, b| a.score.total_cmp(&b.score));

    Posture {
        score: round1(total),
        band: band(total).into(),
        components: Components { threat: round1(c.threat), vulnerabilities: round1(c.vulnerabilities), hardening: round1(c.hardening), progression: round1(c.progression), hygiene: round1(c.hygiene) },
        drivers: drivers.into_iter().map(|d| Driver { points: round1(d.points), ..d }).collect(),
        hosts,
        alert_load: load,
        notes,
    }
}

pub fn combine(c: &Components, w: &Weights) -> f64 {
    let sum = w.threat + w.vulnerabilities + w.hardening + w.progression + w.hygiene;
    ((c.threat * w.threat + c.vulnerabilities * w.vulnerabilities + c.hardening * w.hardening + c.progression * w.progression + c.hygiene * w.hygiene)
        / sum.max(1.0))
    .clamp(0.0, 100.0)
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

// ---------------------------------------------------------------- forecast

/// Holt's linear exponential smoothing: the next value of a series (days with data only).
pub fn holt_next(xs: &[f64], alpha: f64, beta: f64) -> Option<f64> {
    let (&first, rest) = xs.split_first()?;
    let (mut level, mut trend) = (first, 0.0);
    for &x in rest {
        let prev = level;
        level = alpha * x + (1.0 - alpha) * (level + trend);
        trend = beta * (level - prev) + (1.0 - beta) * trend;
    }
    Some((level + trend).max(0.0))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Forecast {
    pub score: f64,
    pub low: f64,
    pub high: f64,
    pub band: String,
    pub components: Components,
    /// "learning" (under 3 days of data), "trend" or "weekly" (14+ days, same weekday)
    pub model: String,
    /// mean absolute error of the past forecasts, when there are some
    pub accuracy_mae: Option<f64>,
}

/// Tomorrow: the threat component from the alert-load trend (a weekly pattern after 14 days),
/// the rest carried from today (they change with configuration and patching, not by the day).
/// `past_errors`: actual minus forecast of earlier days.
pub fn forecast(today: &Posture, load_history: &[Option<f64>], w: &Weights, past_errors: &[f64]) -> Forecast {
    let mut series = robust_history(load_history);
    series.push(today.alert_load);
    let (model, next_load) = if series.len() < 3 {
        ("learning", today.alert_load)
    } else if let Some(week_ago) = load_history.len().checked_sub(6).filter(|_| load_history.len() >= 14).and_then(|i| load_history[i]) {
        // tomorrow's weekday last week (6 days before today; today is not in the history),
        // moved by the recent trend
        let trend = holt_next(&series, 0.5, 0.3).unwrap_or(today.alert_load);
        ("weekly", 0.5 * week_ago + 0.5 * trend)
    } else {
        ("trend", holt_next(&series, 0.5, 0.3).unwrap_or(today.alert_load))
    };
    let mut hist_with_today = load_history.to_vec();
    hist_with_today.push(Some(today.alert_load));
    let c = Components { threat: threat_score(next_load, &hist_with_today), ..today.components.clone() };
    let score = combine(&c, w);
    let accuracy_mae = mean(past_errors.iter().map(|e| e.abs()));
    // 80 % band from the spread of past errors; wide while there are few
    let spread = if past_errors.len() >= 3 {
        let m = mean(past_errors.iter().copied()).unwrap_or(0.0);
        (past_errors.iter().map(|e| (e - m).powi(2)).sum::<f64>() / (past_errors.len() - 1) as f64).sqrt() * 1.28
    } else {
        10.0
    }
    .max(2.0);
    Forecast {
        score: round1(score),
        low: round1((score - spread).max(0.0)),
        high: round1((score + spread).min(100.0)),
        band: band(score).into(),
        components: Components { threat: round1(c.threat), ..c },
        model: model.into(),
        accuracy_mae: accuracy_mae.map(round1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(agent: &str, rule: u32, level: u8, count: u64) -> AlertCount {
        AlertCount { agent_id: agent.into(), agent_name: format!("pc-{agent}"), rule_id: rule, level, description: format!("rule {rule}"), count }
    }

    fn quiet() -> Inputs {
        Inputs { hygiene: Hygiene { agents: 2, active: 2, stale_cases: 0 }, sca: vec![HostSca { agent_id: "1".into(), passed: 90, failed: 10 }], ..Default::default() }
    }

    #[test]
    fn a_quiet_hardened_fleet_is_good_and_a_noisy_rule_is_capped() {
        let p = score(&quiet(), &Weights::default());
        assert_eq!(p.band, "Good", "{p:?}");
        let mut flood = quiet();
        flood.alerts = vec![alert("1", 5, 12, 100_000)];
        let mut few = quiet();
        few.alerts = vec![alert("1", 5, 12, RULE_CAP)];
        assert_eq!(score(&flood, &Weights::default()).components.threat, score(&few, &Weights::default()).components.threat, "one rule on one host counts at most RULE_CAP times");
    }

    #[test]
    fn critical_vulnerabilities_and_kev_lower_the_score_and_name_the_host() {
        let mut i = quiet();
        i.vulns = vec![HostVulns { agent_id: "1".into(), agent_name: "pc-1".into(), critical: 23, high: 248, medium: 195, low: 37, kev: 2 }];
        let p = score(&i, &Weights::default());
        assert!(p.components.vulnerabilities < 40.0, "{:?}", p.components);
        let d = p.drivers.iter().find(|d| d.component == "vulnerabilities").unwrap();
        assert!(d.text.contains("pc-1") && d.text.contains("2 known-exploited") && d.points < 0.0, "{d:?}");
        assert_eq!(p.hosts[0].agent_name, "pc-1");
    }

    #[test]
    fn a_spike_day_does_not_move_the_baseline_and_gaps_are_skipped() {
        let hist = vec![Some(10.0), None, Some(12.0), Some(11.0), Some(9_000.0), None, Some(10.0)];
        let r = robust_history(&hist);
        assert_eq!(r.len(), 5, "no-data days skipped");
        assert!(r.iter().all(|x| *x < 100.0), "the flood day is capped: {r:?}");
        // today at the normal level: no penalty; well above it: lower
        assert!(threat_score(10.0, &hist) > threat_score(60.0, &hist) + 20.0);
    }

    #[test]
    fn the_forecast_follows_a_rising_alert_trend_and_its_band_comes_from_past_errors() {
        let w = Weights::default();
        let hist: Vec<Option<f64>> = (1..=6).map(|d| Some(d as f64 * 10.0)).collect();
        let mut i = quiet();
        i.load_history = hist.clone();
        i.alerts = vec![alert("1", 7, 12, 14)]; // 140 load points on 2 hosts = 70
        let today = score(&i, &w);
        let f = forecast(&today, &hist, &w, &[]);
        assert_eq!(f.model, "trend");
        assert!(f.components.threat < today.components.threat, "a rising load forecasts a weaker threat score: {f:?} vs {:?}", today.components);
        assert_eq!((f.high - f.low).round(), 20.0, "no past errors: the wide default band");
        let tight = forecast(&today, &hist, &w, &[1.0, -1.0, 0.5, -0.5]);
        assert!(tight.high - tight.low < 10.0 && tight.accuracy_mae == Some(0.8), "{tight:?}");
    }

    #[test]
    fn under_three_days_the_forecast_is_learning() {
        let i = quiet();
        let p = score(&i, &Weights::default());
        let f = forecast(&p, &[Some(5.0)], &Weights::default(), &[]);
        assert_eq!(f.model, "learning");
        assert!(p.notes.iter().any(|n| n.contains("3 days")));
    }

    #[test]
    fn holt_continues_a_linear_series() {
        let next = holt_next(&[10.0, 20.0, 30.0, 40.0, 50.0], 0.8, 0.8).unwrap();
        assert!((next - 60.0).abs() < 5.0, "{next}");
    }
}

#[cfg(test)]
mod weekly_tests {
    use super::*;

    #[test]
    fn with_two_weeks_the_forecast_uses_tomorrows_weekday_last_week() {
        // a weekly pattern: one busy day a week; history ends the day before today
        let hist: Vec<Option<f64>> = (0..14).map(|d| Some(if d % 7 == 8 % 7 { 300.0 } else { 10.0 })).collect();
        let mut p = score(&Inputs { hygiene: Hygiene { agents: 1, active: 1, stale_cases: 0 }, ..Default::default() }, &Weights::default());
        p.alert_load = 10.0;
        let f = forecast(&p, &hist, &Weights::default(), &[]);
        assert_eq!(f.model, "weekly");
        assert!(f.components.threat < 60.0, "tomorrow is the busy weekday: {f:?}");
    }
}
