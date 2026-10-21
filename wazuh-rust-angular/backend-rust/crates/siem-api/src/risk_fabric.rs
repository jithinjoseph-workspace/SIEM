use chrono::Utc;
use serde::{Deserialize, Serialize};
use siem_core::{Alert, BusinessProcessDefinition, BusinessTimeWindow, RiskFabricScore};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFabricConfig {
    pub processes: Vec<BusinessProcessDefinition>,
    pub time_windows: Vec<BusinessTimeWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessRiskStat {
    pub name: String,
    pub criticality: String,
    pub alerts_count: usize,
    pub max_risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskFabricSummary {
    pub total_processes: usize,
    pub active_time_windows: usize,
    pub average_dynamic_risk: f64,
    pub catastrophic_alerts_count: usize,
    pub critical_alerts_count: usize,
    pub high_alerts_count: usize,
    pub medium_alerts_count: usize,
    pub low_alerts_count: usize,
    pub top_critical_processes: Vec<ProcessRiskStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvaluationRequest {
    pub rule_level: u8,
    pub rule_id: Option<u32>,
    pub rule_description: Option<String>,
    pub agent_name: String,
    pub agent_ip: String,
    pub user: Option<String>,
}

#[derive(Clone)]
pub struct RiskFabricEngine {
    processes: Arc<RwLock<Vec<BusinessProcessDefinition>>>,
    time_windows: Arc<RwLock<Vec<BusinessTimeWindow>>>,
    config_path: PathBuf,
}

impl RiskFabricEngine {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        let engine = Self {
            processes: Arc::new(RwLock::new(Vec::new())),
            time_windows: Arc::new(RwLock::new(Vec::new())),
            config_path: config_path.into(),
        };
        engine.load_or_seed();
        engine
    }

    /// Load configuration from disk or seed enterprise defaults
    pub fn load_or_seed(&self) {
        if self.config_path.exists() {
            if let Ok(content) = fs::read_to_string(&self.config_path) {
                if let Ok(cfg) = serde_json::from_str::<RiskFabricConfig>(&content) {
                    *self.processes.write().unwrap() = cfg.processes;
                    *self.time_windows.write().unwrap() = cfg.time_windows;
                    info!(
                        "Loaded Business-Process Risk Fabric: {} processes, {} time windows from {:?}",
                        self.processes.read().unwrap().len(),
                        self.time_windows.read().unwrap().len(),
                        self.config_path
                    );
                    return;
                }
            }
        }

        // Seed comprehensive enterprise out-of-the-box defaults
        let default_processes = vec![
            BusinessProcessDefinition {
                id: "bp-pci-payment".to_string(),
                name: "Payment Settlement & Gateway (PCI-DSS)".to_string(),
                description: "Critical cardholder data environment, checkout APIs, and financial transaction settlement.".to_string(),
                criticality: "Mission-Critical".to_string(),
                asset_weight: 2.4,
                identity_weight: 1.8,
                asset_patterns: vec![
                    "*pay*".into(),
                    "*swift*".into(),
                    "*pos*".into(),
                    "*checkout*".into(),
                    "192.168.10.15".into(),
                    "srv-prod-ubuntu-01".into(),
                ],
                identity_patterns: vec![
                    "*cashier*".into(),
                    "*finance*".into(),
                    "*settlement*".into(),
                    "*pci*".into(),
                    "admin*".into(),
                ],
                impact_template: "Direct threat to payment settlement pipeline; elevated risk of transaction manipulation, wire redirection, or PCI-DSS cardholder data compromise.".to_string(),
                enabled: true,
            },
            BusinessProcessDefinition {
                id: "bp-core-iam".to_string(),
                name: "Core Active Directory & IAM Authority".to_string(),
                description: "Central identity provider, Kerberos domain controllers, and privileged credential vaults.".to_string(),
                criticality: "Mission-Critical".to_string(),
                asset_weight: 2.5,
                identity_weight: 2.0,
                asset_patterns: vec![
                    "*dc*".into(),
                    "*ad*".into(),
                    "*iam*".into(),
                    "*auth*".into(),
                    "*ldap*".into(),
                    "*vault*".into(),
                    "*kerberos*".into(),
                ],
                identity_patterns: vec![
                    "administrator".into(),
                    "admin*".into(),
                    "root".into(),
                    "svc_*".into(),
                    "*ciso*".into(),
                    "*cio*".into(),
                    "*secops*".into(),
                ],
                impact_template: "Core identity authority or privileged account impacted; high potential for domain-wide golden ticket creation, privilege escalation, and lateral movement.".to_string(),
                enabled: true,
            },
            BusinessProcessDefinition {
                id: "bp-dmz-web".to_string(),
                name: "Customer-Facing Ingress & Web DMZ".to_string(),
                description: "Public reverse proxies, web application servers, and external API gateways.".to_string(),
                criticality: "High".to_string(),
                asset_weight: 1.6,
                identity_weight: 1.2,
                asset_patterns: vec![
                    "dmz-web-nginx".into(),
                    "*web*".into(),
                    "*nginx*".into(),
                    "*apache*".into(),
                    "*ingress*".into(),
                    "*api*".into(),
                    "*portal*".into(),
                ],
                identity_patterns: vec![
                    "www-data".into(),
                    "nginx".into(),
                    "apache".into(),
                    "*app*".into(),
                ],
                impact_template: "Perimeter service exploit or unauthorized ingress activity; threat to customer service availability and potential perimeter foothold.".to_string(),
                enabled: true,
            },
            BusinessProcessDefinition {
                id: "bp-corp-erp".to_string(),
                name: "Corporate ERP & Supply Chain".to_string(),
                description: "Enterprise resource planning, relational databases, supply chain logistics, and HR databases.".to_string(),
                criticality: "High".to_string(),
                asset_weight: 1.5,
                identity_weight: 1.3,
                asset_patterns: vec![
                    "*erp*".into(),
                    "*sap*".into(),
                    "*crm*".into(),
                    "*database*".into(),
                    "*sql*".into(),
                    "*postgres*".into(),
                ],
                identity_patterns: vec![
                    "*operator*".into(),
                    "*dba*".into(),
                    "*erp*".into(),
                ],
                impact_template: "Corporate ERP or backend database impacted; potential disruption to supply chain logistics or unauthorized business records access.".to_string(),
                enabled: true,
            },
            BusinessProcessDefinition {
                id: "bp-dev-sandbox".to_string(),
                name: "Non-Production Dev & Lab Sandbox".to_string(),
                description: "Software development staging nodes, QA clusters, and test environments.".to_string(),
                criticality: "Low".to_string(),
                asset_weight: 0.4,
                identity_weight: 0.8,
                asset_patterns: vec![
                    "*dev*".into(),
                    "*test*".into(),
                    "*stage*".into(),
                    "*qa*".into(),
                    "*sandbox*".into(),
                    "*lab*".into(),
                ],
                identity_patterns: vec![
                    "*tester*".into(),
                    "*intern*".into(),
                    "*dev*".into(),
                ],
                impact_template: "Isolated development or QA asset activity; low enterprise operational risk, suppressed from high-urgency SOC response.".to_string(),
                enabled: true,
            },
        ];

        let default_windows = vec![
            BusinessTimeWindow {
                id: "tw-financial-close".to_string(),
                name: "Month-End Financial Close Window".to_string(),
                description: "Heightened scrutiny period for accounting, banking, and payment systems during reconciliation.".to_string(),
                multiplier: 1.45,
                window_type: "recurring_schedule".to_string(),
                start_date: None,
                end_date: None,
                active: true,
                target_processes: vec!["bp-pci-payment".into(), "bp-corp-erp".into()],
            },
            BusinessTimeWindow {
                id: "tw-maintenance-window".to_string(),
                name: "Scheduled Infrastructure Maintenance".to_string(),
                description: "Authorized patching and vulnerability assessment window; technical alerts de-escalated to reduce alarm fatigue.".to_string(),
                multiplier: 0.40,
                window_type: "recurring_schedule".to_string(),
                start_date: None,
                end_date: None,
                active: false,
                target_processes: vec![],
            },
            BusinessTimeWindow {
                id: "tw-off-hours".to_string(),
                name: "Unattended Off-Hours Operations".to_string(),
                description: "Night-time and weekend operations when physical offices are unoccupied and SOC staffing is lean.".to_string(),
                multiplier: 1.25,
                window_type: "business_hours".to_string(),
                start_date: None,
                end_date: None,
                active: true,
                target_processes: vec![],
            },
        ];

        *self.processes.write().unwrap() = default_processes;
        *self.time_windows.write().unwrap() = default_windows;
        self.save_to_disk();
        info!("Seeded default Business-Process Risk Fabric configuration");
    }

    /// Persist current configuration to disk
    pub fn save_to_disk(&self) {
        if let Some(parent) = self.config_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let cfg = RiskFabricConfig {
            processes: self.processes.read().unwrap().clone(),
            time_windows: self.time_windows.read().unwrap().clone(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&cfg) {
            let _ = fs::write(&self.config_path, json);
        }
    }

    /// Evaluates incoming alert through the Business-Process Risk Fabric
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
        // Wazuh level is 0..15. Baseline technical severity is (level * 6.67) clamped to 100
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

        // Attach to Alert struct and data map
        alert.risk_fabric = Some(score.clone());
        if let Ok(val) = serde_json::to_value(&score) {
            alert.data.insert("risk_fabric".to_string(), val);
        }

        score
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
            risk_fabric: None,
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
            if let Some(ref rf) = a.risk_fabric {
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
        self.save_to_disk();
    }

    pub fn delete_process(&self, id: &str) -> bool {
        let mut list = self.processes.write().unwrap();
        let len_before = list.len();
        list.retain(|p| p.id != id);
        let removed = list.len() < len_before;
        drop(list);
        if removed {
            self.save_to_disk();
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
        self.save_to_disk();
    }

    pub fn delete_window(&self, id: &str) -> bool {
        let mut list = self.time_windows.write().unwrap();
        let len_before = list.len();
        list.retain(|w| w.id != id);
        let removed = list.len() < len_before;
        drop(list);
        if removed {
            self.save_to_disk();
        }
        removed
    }
}

/// Simple pattern matcher supporting prefix/suffix wildcards: "*foo*", "*foo", "foo*", or exact
fn matches_pattern(pattern: &str, target: &str) -> bool {
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
        let temp_file = std::env::temp_dir().join("test_risk_fabric.json");
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
        // Level 10 * 6.67 = 66.7
        // Asset weight = 2.4, Identity weight = 2.0, Time window (Month-End Close active) = 1.45
        // Total score exceeds 85 -> Catastrophic tier
        assert!(score.dynamic_risk_score >= 85);
        assert_eq!(score.dynamic_risk_tier, "Catastrophic");
        assert!(score.executive_impact.contains("PCI-DSS"));
        let _ = std::fs::remove_file(temp_file);
    }
}
