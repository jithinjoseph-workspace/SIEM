use chrono::Utc;
use siem_core::Alert;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::models::{
    BusinessProcessDefinition, BusinessTimeWindow, ProcessRiskStat, RiskEvaluationRequest,
    RiskFabricConfig, RiskFabricScore, RiskFabricSummary,
};
use crate::storage;

#[derive(Clone)]
pub struct RiskFabricEngine {
    processes: Arc<RwLock<Vec<BusinessProcessDefinition>>>,
    time_windows: Arc<RwLock<Vec<BusinessTimeWindow>>>,
    config_path: PathBuf,
}

impl RiskFabricEngine {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        let path = config_path.into();
        let cfg = storage::load_config(&path).unwrap_or_else(storage::default_config);
        storage::save_config(&path, &cfg);

        Self {
            processes: Arc::new(RwLock::new(cfg.processes)),
            time_windows: Arc::new(RwLock::new(cfg.time_windows)),
            config_path: path,
        }
    }

    /// Persist current configuration state to disk
    pub fn save(&self) {
        let cfg = RiskFabricConfig {
            processes: self.processes.read().unwrap().clone(),
            time_windows: self.time_windows.read().unwrap().clone(),
        };
        storage::save_config(&self.config_path, &cfg);
    }

    /// Evaluates an alert and injects the score into `alert.data["risk_fabric"]`
    pub fn evaluate_alert(&self, alert: &mut Alert) -> RiskFabricScore {
        let agent_name = alert.agent.name.to_lowercase();
        let agent_ip = alert.agent.ip.to_lowercase();
        let location = alert.location.to_lowercase();
        let user = alert.decoded.user.as_deref().unwrap_or("").to_lowercase();
        let rule_level = alert.rule.level;
        let rule_desc = &alert.rule.description;

        let processes = self.processes.read().unwrap();
        let time_windows = self.time_windows.read().unwrap();

        // 1. Resolve matching Business Process
        let mut matched_proc: Option<BusinessProcessDefinition> = None;
        for p in processes.iter().filter(|p| p.enabled) {
            let matches_asset = p.asset_patterns.iter().any(|pattern| {
                matches_pattern(pattern, &agent_name)
                    || matches_pattern(pattern, &agent_ip)
                    || matches_pattern(pattern, &location)
            });
            if matches_asset {
                if let Some(ref current) = matched_proc {
                    if p.asset_weight > current.asset_weight {
                        matched_proc = Some(p.clone());
                    }
                } else {
                    matched_proc = Some(p.clone());
                }
            }
        }

        let (bp_id, bp_name, bp_criticality, asset_weight, base_impact_template) =
            if let Some(p) = matched_proc {
                (p.id, p.name, p.criticality, p.asset_weight, p.impact_template)
            } else {
                (
                    "bp-general".to_string(),
                    "Standard Corporate Infrastructure".to_string(),
                    "Medium".to_string(),
                    1.0,
                    "General endpoint security event requiring standard SOC operational review.".to_string(),
                )
            };

        // 2. Resolve Identity Criticality Weight
        let mut identity_weight = 1.0;
        if !user.is_empty() {
            for p in processes.iter() {
                if p.identity_patterns.iter().any(|pat| matches_pattern(pat, &user)) {
                    if p.identity_weight > identity_weight {
                        identity_weight = p.identity_weight;
                    }
                }
            }
        }

        // 3. Resolve Active Business Time Window Multipliers
        let mut time_multiplier = 1.0;
        let mut active_window_name: Option<String> = None;
        for w in time_windows.iter().filter(|w| w.active) {
            if w.target_processes.is_empty() || w.target_processes.contains(&bp_id) {
                time_multiplier *= w.multiplier;
                active_window_name = Some(w.name.clone());
                break;
            }
        }

        // 4. Compute Unified Dynamic Risk Score (0 - 100)
        let tech_base = ((rule_level as f64) * 6.67).clamp(5.0, 100.0);
        let raw_score = tech_base * asset_weight * identity_weight * time_multiplier;
        let dynamic_risk_score = raw_score.round().clamp(1.0, 100.0) as u8;

        let dynamic_risk_tier = match dynamic_risk_score {
            85..=100 => "Catastrophic",
            70..=84 => "Critical",
            45..=69 => "High",
            25..=44 => "Medium",
            _ => "Low",
        }
        .to_string();

        // 5. Synthesize Executive-Ready Impact Narrative
        let window_note = if let Some(ref w_name) = active_window_name {
            format!(" Active temporal context: [{w_name} (Priority Multiplier: {time_multiplier:.2}x)].")
        } else {
            String::new()
        };

        let user_note = if !user.is_empty() {
            format!(" Involves identity '{user}' (Identity Weight: {identity_weight:.1}x).")
        } else {
            String::new()
        };

        let executive_impact = format!(
            "[{bp_name} / {bp_criticality}] Alert on host '{}': {rule_desc}. {base_impact_template}{user_note}{window_note}",
            alert.agent.name
        );

        let evaluated_at = Utc::now();
        let score = RiskFabricScore {
            business_process: bp_name,
            process_criticality: bp_criticality,
            asset_weight,
            identity_weight,
            time_window_multiplier: time_multiplier,
            active_window_name,
            technical_severity: rule_level,
            dynamic_risk_score,
            dynamic_risk_tier,
            executive_impact,
            evaluated_at,
        };

        // Attach dynamically to `alert.data["risk_fabric"]` without requiring core struct changes
        if let Ok(val) = serde_json::to_value(&score) {
            alert.data.insert("risk_fabric".to_string(), val);
        }

        score
    }

    /// Extracts the RiskFabricScore from an Alert's data map if present
    pub fn get_score(alert: &Alert) -> Option<RiskFabricScore> {
        alert
            .data
            .get("risk_fabric")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Evaluates simulation payload without altering active alerts
    pub fn simulate(&self, req: &RiskEvaluationRequest) -> RiskFabricScore {
        let mut dummy_alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: req.rule_id.unwrap_or(100101),
                level: req.rule_level,
                description: req.rule_description.clone().unwrap_or_else(|| "Simulated Security Event".into()),
                groups: vec!["simulation".into()],
                mitre: None,
            },
            agent: siem_core::AgentAlertInfo {
                id: "sim-001".into(),
                name: req.agent_name.clone(),
                ip: req.agent_ip.clone(),
            },
            manager: None,
            decoder: None,
            full_log: "Simulated log payload".into(),
            decoded: siem_core::DecodedFields {
                user: req.user.clone(),
                ..Default::default()
            },
            location: format!("/var/log/{}", req.agent_name),
            data: HashMap::new(),
        };

        self.evaluate_alert(&mut dummy_alert)
    }

    /// Summarizes live risk fabric metrics across a set of active alerts
    pub fn get_summary(&self, alerts: &[Alert]) -> RiskFabricSummary {
        let processes = self.processes.read().unwrap();
        let time_windows = self.time_windows.read().unwrap();

        let active_windows = time_windows.iter().filter(|w| w.active).count();
        let total_procs = processes.len();

        let mut catastrophic = 0;
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut total_score: u64 = 0;
        let mut proc_counts: HashMap<String, (String, usize, u8)> = HashMap::new();

        for a in alerts {
            if let Some(rf) = Self::get_score(a) {
                total_score += rf.dynamic_risk_score as u64;
                match rf.dynamic_risk_tier.as_str() {
                    "Catastrophic" => catastrophic += 1,
                    "Critical" => critical += 1,
                    "High" => high += 1,
                    "Medium" => medium += 1,
                    _ => low += 1,
                }

                let entry = proc_counts.entry(rf.business_process.clone()).or_insert((
                    rf.process_criticality.clone(),
                    0,
                    0,
                ));
                entry.1 += 1;
                if rf.dynamic_risk_score > entry.2 {
                    entry.2 = rf.dynamic_risk_score;
                }
            }
        }

        let avg_score = if !alerts.is_empty() {
            (total_score as f64) / (alerts.len() as f64)
        } else {
            0.0
        };

        let mut top_procs: Vec<ProcessRiskStat> = proc_counts
            .into_iter()
            .map(|(name, (crit, cnt, max_s))| ProcessRiskStat {
                name,
                criticality: crit,
                alerts_count: cnt,
                max_risk_score: max_s,
            })
            .collect();
        top_procs.sort_by(|a, b| b.max_risk_score.cmp(&a.max_risk_score));

        RiskFabricSummary {
            total_processes: total_procs,
            active_time_windows: active_windows,
            average_dynamic_risk: (avg_score * 10.0).round() / 10.0,
            catastrophic_alerts_count: catastrophic,
            critical_alerts_count: critical,
            high_alerts_count: high,
            medium_alerts_count: medium,
            low_alerts_count: low,
            top_critical_processes: top_procs,
        }
    }

    pub fn get_processes(&self) -> Vec<BusinessProcessDefinition> {
        self.processes.read().unwrap().clone()
    }

    pub fn add_or_update_process(&self, proc: BusinessProcessDefinition) {
        let mut list = self.processes.write().unwrap();
        if let Some(pos) = list.iter().position(|p| p.id == proc.id) {
            list[pos] = proc;
        } else {
            list.push(proc);
        }
        drop(list);
        self.save();
    }

    pub fn delete_process(&self, id: &str) -> bool {
        let mut list = self.processes.write().unwrap();
        let len_before = list.len();
        list.retain(|p| p.id != id);
        let removed = list.len() < len_before;
        drop(list);
        if removed {
            self.save();
        }
        removed
    }

    pub fn get_windows(&self) -> Vec<BusinessTimeWindow> {
        self.time_windows.read().unwrap().clone()
    }

    pub fn add_or_update_window(&self, win: BusinessTimeWindow) {
        let mut list = self.time_windows.write().unwrap();
        if let Some(pos) = list.iter().position(|w| w.id == win.id) {
            list[pos] = win;
        } else {
            list.push(win);
        }
        drop(list);
        self.save();
    }

    pub fn delete_window(&self, id: &str) -> bool {
        let mut list = self.time_windows.write().unwrap();
        let len_before = list.len();
        list.retain(|w| w.id != id);
        let removed = list.len() < len_before;
        drop(list);
        if removed {
            self.save();
        }
        removed
    }
}

/// Simple pattern matcher supporting prefix/suffix wildcards: "*foo*", "*foo", "foo*", or exact
pub fn matches_pattern(pattern: &str, target: &str) -> bool {
    let p = pattern.trim().to_lowercase();
    let t = target.trim().to_lowercase();

    if p == "*" || p.is_empty() {
        return true;
    }
    if p.starts_with('*') && p.ends_with('*') && p.len() > 2 {
        let sub = &p[1..p.len() - 1];
        return t.contains(sub);
    }
    if p.starts_with('*') && p.len() > 1 {
        let sub = &p[1..];
        return t.ends_with(sub);
    }
    if p.ends_with('*') && p.len() > 1 {
        let sub = &p[..p.len() - 1];
        return t.starts_with(sub);
    }
    t == p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("*pay*", "srv-payment-01"));
        assert!(matches_pattern("*pos*", "pos-terminal-04"));
        assert!(matches_pattern("admin*", "administrator"));
        assert!(matches_pattern("*dc*", "hq-dc-01"));
        assert!(matches_pattern("192.168.10.15", "192.168.10.15"));
        assert!(!matches_pattern("*pay*", "srv-dev-01"));
    }

    #[test]
    fn test_dynamic_risk_scoring() {
        let temp_file = std::env::temp_dir().join(format!("test_rf_{}.json", uuid::Uuid::new_v4()));
        let engine = RiskFabricEngine::new(&temp_file);
        let req = RiskEvaluationRequest {
            rule_level: 10,
            rule_id: Some(100101),
            rule_description: Some("Brute Force Detection".into()),
            agent_name: "srv-prod-ubuntu-01".into(),
            agent_ip: "192.168.10.15".into(),
            user: Some("administrator".into()),
        };
        let score = engine.simulate(&req);
        assert!(score.dynamic_risk_score >= 85);
        assert_eq!(score.dynamic_risk_tier, "Catastrophic");
        assert!(score.executive_impact.contains("PCI-DSS"));
        let _ = std::fs::remove_file(temp_file);
    }
}
