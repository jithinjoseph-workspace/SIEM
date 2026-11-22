use chrono::{Datelike, Local, NaiveDate, TimeZone, Timelike, Utc};
use siem_core::Alert;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use crate::models::{
    BusinessProcessDefinition, BusinessTimeWindow, FleetAgentMeta, ProcessRiskStat,
    RiskEvaluationRequest, RiskFabricConfig, RiskFabricScore, RiskFabricSummary,
};
use crate::storage;

/// Settings key of the shared settings a tenant starts from (stored as `risk_fabric`).
pub const SHARED: &str = "";

#[derive(Clone)]
pub struct RiskFabricEngine {
    /// The settings a tenant without its own starts from: those stored before settings were
    /// per tenant, else the defaults
    shared: Arc<RwLock<Arc<RiskFabricConfig>>>,
    /// Each tenant's own business processes and time windows, once it changed them
    tenants: Arc<RwLock<HashMap<String, Arc<RiskFabricConfig>>>>,
    fleet: Arc<RwLock<HashMap<String, FleetAgentMeta>>>,
    /// Settings changed since siem-api last stored them (ClickHouse, `engine_docs`)
    changed: Arc<Mutex<HashSet<String>>>,
    /// The settings file of an earlier version, until its content is stored
    legacy_file: Arc<Mutex<Option<PathBuf>>>,
}

impl RiskFabricEngine {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        let path = config_path.into();
        let old = storage::load_config(&path);
        let had_file = old.is_some();
        let cfg = old.unwrap_or_else(storage::default_config);
        let changed: HashSet<String> = if had_file { [SHARED.to_string()].into() } else { HashSet::new() };

        Self {
            shared: Arc::new(RwLock::new(Arc::new(cfg))),
            tenants: Arc::new(RwLock::new(HashMap::new())),
            fleet: Arc::new(RwLock::new(HashMap::new())),
            changed: Arc::new(Mutex::new(changed)),
            legacy_file: Arc::new(Mutex::new(had_file.then_some(path))),
        }
    }

    /// The tenant's settings: its own, else the shared ones.
    pub fn config(&self, tenant: &str) -> Arc<RiskFabricConfig> {
        if let Some(c) = self.tenants.read().unwrap().get(tenant) {
            return c.clone();
        }
        self.shared.read().unwrap().clone()
    }

    /// Changes the tenant's own settings (a copy of the shared ones the first time).
    fn change<R>(&self, tenant: &str, f: impl FnOnce(&mut RiskFabricConfig) -> R) -> R {
        let mut map = self.tenants.write().unwrap();
        let cur = map.get(tenant).cloned().unwrap_or_else(|| self.shared.read().unwrap().clone());
        let mut cfg = (*cur).clone();
        let r = f(&mut cfg);
        map.insert(tenant.to_string(), Arc::new(cfg));
        drop(map);
        self.changed.lock().unwrap().insert(tenant.to_string());
        r
    }

    /// Synchronizes live enrolled agent fleet metadata using tuples
    pub fn sync_fleet(&self, fleet: &[(String, String, String, Option<String>)]) {
        let mut map = self.fleet.write().unwrap();
        map.clear();
        for (id, name, ip, os) in fleet {
            // the agent's real groups are not known here (sync_fleet_meta has them): none are guessed from its name
            let groups = Vec::new();
            map.insert(
                id.clone(),
                FleetAgentMeta {
                    id: id.clone(),
                    name: name.clone(),
                    ip: ip.clone(),
                    os_type: os.clone(),
                    groups,
                },
            );
        }
    }

    /// Synchronizes live enrolled agent fleet with rich metadata including agent groups
    pub fn sync_fleet_meta(&self, fleet: &[FleetAgentMeta]) {
        let mut map = self.fleet.write().unwrap();
        map.clear();
        for meta in fleet {
            map.insert(meta.id.clone(), meta.clone());
        }
    }

    /// The changed settings since the last call, `(tenant, document)` (`SHARED` for the shared
    /// settings), for siem-api to store.
    pub fn take_changed(&self) -> Vec<(String, String)> {
        let keys: Vec<String> = self.changed.lock().unwrap().drain().collect();
        keys.into_iter()
            .filter_map(|t| {
                let cfg = if t == SHARED { self.shared.read().unwrap().clone() } else { self.config(&t) };
                serde_json::to_string(&*cfg).ok().map(|d| (t, d))
            })
            .collect()
    }

    /// Not stored: it stays changed.
    pub fn store_failed(&self, tenant: &str) {
        self.changed.lock().unwrap().insert(tenant.to_string());
    }

    /// Stored: the settings file of an earlier version is not needed any more.
    pub fn stored(&self, tenant: &str) {
        if tenant == SHARED {
            if let Some(p) = self.legacy_file.lock().unwrap().take() {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    /// A stored document, at start: the shared settings (`SHARED`) or a tenant's own.
    pub fn load(&self, tenant: &str, doc: &str) {
        if let Ok(mut c) = serde_json::from_str::<RiskFabricConfig>(doc) {
            let retired = storage::retire_old_defaults(&mut c.processes);
            if tenant == SHARED {
                *self.shared.write().unwrap() = Arc::new(c);
            } else {
                self.tenants.write().unwrap().insert(tenant.to_string(), Arc::new(c));
            }
            if retired {
                self.changed.lock().unwrap().insert(tenant.to_string());
            }
        }
    }

    /// Evaluates an alert and injects the score into `alert.data["risk_fabric"]`
    pub fn evaluate_alert(&self, tenant: &str, alert: &mut Alert) -> RiskFabricScore {
        let agent_name = alert.agent.name.to_lowercase();
        let agent_id = alert.agent.id.to_lowercase();
        let agent_ip = alert.agent.ip.to_lowercase();
        let location = alert.location.to_lowercase();
        let user = resolve_alert_user(alert);
        let rule_level = alert.rule.level;
        let rule_desc = &alert.rule.description;

        // Resolve fleet registry OS and groups if available
        let (fleet_os, fleet_groups) = {
            let f = self.fleet.read().unwrap();
            if let Some(agent_meta) = f.get(&alert.agent.id) {
                (
                    agent_meta.os_type.clone().unwrap_or_default().to_lowercase(),
                    agent_meta.groups.iter().map(|g| g.to_lowercase()).collect::<Vec<_>>(),
                )
            } else {
                (String::new(), Vec::new())
            }
        };

        let cfg = self.config(tenant);
        let processes = &cfg.processes;
        let time_windows = &cfg.time_windows;

        // 1. Resolve matching Business Process
        let mut matched_proc: Option<BusinessProcessDefinition> = None;
        for p in processes.iter().filter(|p| p.enabled) {
            let matches_asset = p.asset_patterns.iter().any(|pattern| {
                matches_pattern(pattern, &agent_name)
                    || matches_pattern(pattern, &agent_id)
                    || matches_pattern(pattern, &agent_ip)
                    || matches_pattern(pattern, &location)
                    || (!fleet_os.is_empty() && matches_pattern(pattern, &fleet_os))
                    || fleet_groups.iter().any(|g| matches_pattern(pattern, g))
            }) || p.group_patterns.iter().any(|gp| {
                fleet_groups.iter().any(|g| matches_pattern(gp, g))
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
                let is_win = agent_name.contains("win") || location.contains("c:\\") || fleet_os.contains("windows");
                let is_linux = agent_name.contains("linux") || location.contains("/var") || fleet_os.contains("linux");
                if is_win {
                    (
                        "bp-win-corp".to_string(),
                        "Corporate Windows Workstations & Fleet".to_string(),
                        "High".to_string(),
                        2.1,
                        "Windows domain host security event detected; potential active lateral pivot, credential access, or defense evasion.".to_string(),
                    )
                } else if is_linux {
                    (
                        "bp-linux-prod".to_string(),
                        "Enterprise Linux Workload Infrastructure".to_string(),
                        "High".to_string(),
                        2.0,
                        "Linux host telemetry alert; elevated potential for privilege escalation, root compromise, or daemon abuse.".to_string(),
                    )
                } else {
                    (
                        "bp-general".to_string(),
                        format!("Monitored Fleet Node ({})", alert.agent.name),
                        "Medium".to_string(),
                        1.2,
                        "Endpoint telemetry event requiring standard SOC operational triage and verification.".to_string(),
                    )
                }
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
            // Privileged accounts elevation across Windows and Linux
            if user == "root"
                || user == "administrator"
                || user == "system"
                || user == "domain admins"
                || user == "enterprise admins"
                || user == "wheel"
            {
                identity_weight = identity_weight.max(2.0);
            } else if user.starts_with("svc_")
                || user.starts_with("nt authority")
                || user == "www-data"
                || user == "nginx"
                || user == "postgres"
            {
                identity_weight = identity_weight.max(1.5);
            }
        }

        // 3. Resolve Real-Time Clock & Temporal Window Multipliers
        let mut time_multiplier = 1.0;
        let mut active_window_names = Vec::new();
        let now = Local::now();

        for w in time_windows.iter() {
            let applies_to_proc = w.target_processes.is_empty() || w.target_processes.contains(&bp_id);
            if applies_to_proc {
                let (is_active, mult) = evaluate_temporal_window(w, &now);
                if is_active && (mult - 1.0).abs() > 0.001 {
                    time_multiplier *= mult;
                    active_window_names.push(format!("{} ({:.2}x)", w.name, mult));
                }
            }
        }
        time_multiplier = time_multiplier.clamp(0.35, 2.85);

        let active_window_name = if !active_window_names.is_empty() {
            Some(active_window_names.join(", "))
        } else {
            None
        };

        // 4. Factor in MITRE Tactic Progression Weight
        let mitre_boost = if let Some(ref m) = alert.rule.mitre {
            match m.tactic.to_lowercase().as_str() {
                "impact" | "exfiltration" => 1.35,
                "lateral_movement" | "command_and_control" => 1.25,
                "credential_access" | "privilege_escalation" => 1.15,
                "persistence" | "defense_evasion" => 1.10,
                _ => 1.0,
            }
        } else {
            1.0
        };

        // 5. Compute Unified Dynamic Risk Score (1 - 100)
        let tech_base = ((rule_level as f64) * 6.67).clamp(5.0, 100.0) * mitre_boost;
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

        // 6. Synthesize Executive-Ready Impact Narrative
        let window_note = if let Some(ref w_name) = active_window_name {
            format!(" Temporal Context: [{w_name}].")
        } else {
            String::new()
        };

        let user_note = if !user.is_empty() {
            format!(" Identity: '{user}' (Weight: {identity_weight:.1}x).")
        } else {
            String::new()
        };

        let mitre_note = if let Some(ref m) = alert.rule.mitre {
            format!(" MITRE: [{}: {}].", m.tactic, m.technique)
        } else {
            String::new()
        };

        let executive_impact = format!(
            "[{bp_name} / {bp_criticality}] Host '{}': {rule_desc}. {base_impact_template}{mitre_note}{user_note}{window_note}",
            alert.agent.name
        );

        let evaluated_at = Utc::now();
        let score = RiskFabricScore {
            business_process: bp_name,
            process_criticality: bp_criticality,
            asset_weight,
            identity_weight,
            time_window_multiplier: (time_multiplier * 100.0).round() / 100.0,
            active_window_name,
            technical_severity: rule_level,
            dynamic_risk_score,
            dynamic_risk_tier,
            executive_impact,
            evaluated_at,
        };

        // Attach dynamically to `alert.data["risk_fabric"]`
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
    pub fn simulate(&self, tenant: &str, req: &RiskEvaluationRequest) -> RiskFabricScore {
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
            location: match req.os_type.as_deref() {
                Some("windows") => r"C:\Windows\System32\Security.evtx".to_string(),
                _ if req.agent_name.to_lowercase().contains("win") => r"C:\Windows\System32\Security.evtx".to_string(),
                _ => format!("/var/log/{}", req.agent_name),
            },
            data: HashMap::new(),
        };

        if let Some(ref os) = req.os_type {
            dummy_alert.data.insert("agent_os".to_string(), serde_json::Value::String(os.clone()));
        }
        if let Some(ref u) = req.user {
            dummy_alert.data.insert("win.eventdata.targetUserName".to_string(), serde_json::Value::String(u.clone()));
            dummy_alert.data.insert("dstuser".to_string(), serde_json::Value::String(u.clone()));
        }

        self.evaluate_alert(tenant, &mut dummy_alert)
    }

    /// Summarizes live risk fabric metrics across a set of active alerts
    pub fn get_summary(&self, tenant: &str, alerts: &[Alert]) -> RiskFabricSummary {
        let cfg = self.config(tenant);
        let processes = &cfg.processes;
        let now = Local::now();
        // windows in effect now, not merely switched on
        let active_windows = cfg.time_windows.iter().filter(|w| evaluate_temporal_window(w, &now).0).count();
        let total_procs = processes.len();

        let mut catastrophic = 0;
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut total_score: u64 = 0;
        let mut evaluated_count: usize = 0;
        let mut proc_counts: HashMap<String, (String, usize, u8)> = HashMap::new();

        for a in alerts {
            // Skip synthetic Red Swarm validation alerts from live business risk summaries
            if a.rule.groups.iter().any(|g| g == "redswarm_simulation") {
                continue;
            }
            evaluated_count += 1;

            // Check attached score or dynamically evaluate on the fly
            let score = Self::get_score(a).unwrap_or_else(|| {
                let mut cloned = a.clone();
                self.evaluate_alert(tenant, &mut cloned)
            });

            total_score += score.dynamic_risk_score as u64;
            match score.dynamic_risk_tier.as_str() {
                "Catastrophic" => catastrophic += 1,
                "Critical" => critical += 1,
                "High" => high += 1,
                "Medium" => medium += 1,
                _ => low += 1,
            }

            let entry = proc_counts.entry(score.business_process.clone()).or_insert((
                score.process_criticality.clone(),
                0,
                0,
            ));
            entry.1 += 1;
            if score.dynamic_risk_score > entry.2 {
                entry.2 = score.dynamic_risk_score;
            }
        }

        let avg_score = if evaluated_count > 0 {
            (total_score as f64) / (evaluated_count as f64)
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

    pub fn get_processes(&self, tenant: &str) -> Vec<BusinessProcessDefinition> {
        self.config(tenant).processes.clone()
    }

    pub fn add_or_update_process(&self, tenant: &str, proc: BusinessProcessDefinition) -> Result<(), String> {
        check_process(&proc)?;
        self.change(tenant, |c| match c.processes.iter().position(|p| p.id == proc.id) {
            Some(pos) => c.processes[pos] = proc,
            None => c.processes.push(proc),
        });
        Ok(())
    }

    pub fn delete_process(&self, tenant: &str, id: &str) -> bool {
        if !self.config(tenant).processes.iter().any(|p| p.id == id) {
            return false;
        }
        self.change(tenant, |c| c.processes.retain(|p| p.id != id));
        true
    }

    pub fn get_windows(&self, tenant: &str) -> Vec<BusinessTimeWindow> {
        self.config(tenant).time_windows.clone()
    }

    pub fn add_or_update_window(&self, tenant: &str, win: BusinessTimeWindow) -> Result<(), String> {
        check_window(&win)?;
        self.change(tenant, |c| match c.time_windows.iter().position(|w| w.id == win.id) {
            Some(pos) => c.time_windows[pos] = win,
            None => c.time_windows.push(win),
        });
        Ok(())
    }

    pub fn delete_window(&self, tenant: &str, id: &str) -> bool {
        if !self.config(tenant).time_windows.iter().any(|w| w.id == id) {
            return false;
        }
        self.change(tenant, |c| c.time_windows.retain(|w| w.id != id));
        true
    }
}

fn check_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err("The id must be 1-64 letters, digits, '-', '_' or '.'".into());
    }
    Ok(())
}

fn check_patterns(what: &str, list: &[String]) -> Result<(), String> {
    if list.len() > 200 {
        return Err(format!("At most 200 {what} patterns"));
    }
    if list.iter().any(|p| p.trim().is_empty() || p.len() > 128) {
        return Err(format!("Each {what} pattern must be 1-128 characters"));
    }
    Ok(())
}

/// A business process an admin saves: a name, sensible weights and usable patterns.
pub fn check_process(p: &BusinessProcessDefinition) -> Result<(), String> {
    check_id(&p.id)?;
    if p.name.trim().is_empty() || p.name.len() > 120 {
        return Err("The business process needs a name (at most 120 characters)".into());
    }
    for (what, w) in [("asset", p.asset_weight), ("identity", p.identity_weight)] {
        if !w.is_finite() || !(0.1..=5.0).contains(&w) {
            return Err(format!("The {what} weight must be between 0.1 and 5"));
        }
    }
    check_patterns("asset", &p.asset_patterns)?;
    check_patterns("group", &p.group_patterns)?;
    check_patterns("identity", &p.identity_patterns)?;
    if p.asset_patterns.is_empty() && p.group_patterns.is_empty() {
        return Err("Name at least one asset or group pattern, or the process matches no computer".into());
    }
    Ok(())
}

/// A time window an admin saves: a name, a sensible multiplier, and readable dates for a date range.
pub fn check_window(w: &BusinessTimeWindow) -> Result<(), String> {
    check_id(&w.id)?;
    if w.name.trim().is_empty() || w.name.len() > 120 {
        return Err("The time window needs a name (at most 120 characters)".into());
    }
    if !w.multiplier.is_finite() || !(0.1..=3.0).contains(&w.multiplier) {
        return Err("The multiplier must be between 0.1 and 3".into());
    }
    match w.window_type.as_str() {
        "recurring_schedule" | "business_hours" => Ok(()),
        "date_range" => match (w.start_date.as_deref().and_then(parse_day), w.end_date.as_deref().and_then(parse_day)) {
            (Some(s), Some(e)) if s <= e => Ok(()),
            _ => Err("A date range needs a start and an end date (YYYY-MM-DD), the start first".into()),
        },
        _ => Err("The window type must be recurring_schedule, business_hours or date_range".into()),
    }
}

/// A day from `YYYY-MM-DD` or a full RFC 3339 time.
fn parse_day(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
        .ok()
        .or_else(|| chrono::DateTime::parse_from_rfc3339(s.trim()).ok().map(|d| d.date_naive()))
}

/// Dynamically resolves the user identity across Windows EventData and Linux Syslog/Auditd payloads
pub fn resolve_alert_user(alert: &Alert) -> String {
    // 1. Check decoded user
    if let Some(ref u) = alert.decoded.user {
        let trimmed = u.trim();
        if !trimmed.is_empty() && trimmed != "-" && trimmed != "(unknown)" {
            return clean_username(trimmed);
        }
    }

    // 2. Windows EventData checks (Security EventID 4624, 4625, 4672, 4720, Sysmon EventID 1)
    for key in &[
        "win.eventdata.targetUserName",
        "win.eventdata.subjectUserName",
        "win.eventdata.user",
        "Event.EventData.TargetUserName",
        "Event.EventData.SubjectUserName",
        "TargetUserName",
        "SubjectUserName",
    ] {
        if let Some(val) = alert.data.get(*key).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            // Exclude machine accounts ending in $ (e.g. DC01$)
            if !trimmed.is_empty() && trimmed != "-" && !trimmed.ends_with('$') {
                return clean_username(trimmed);
            }
        }
    }

    // 3. Linux auth / sudo / auditd checks
    for key in &[
        "dstuser",
        "srcuser",
        "audit.auid",
        "audit.uid",
        "pam.user",
        "user",
    ] {
        if let Some(val) = alert.data.get(*key).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            if !trimmed.is_empty() && trimmed != "-" {
                return clean_username(trimmed);
            }
        }
    }

    String::new()
}

/// Normalizes usernames by stripping Windows domain prefixes (e.g. "CORP\admin" -> "admin")
pub fn clean_username(user: &str) -> String {
    let lower = user.to_lowercase();
    if let Some(pos) = lower.find('\\') {
        lower[pos + 1..].to_string()
    } else if let Some(pos) = lower.find('@') {
        lower[..pos].to_string()
    } else {
        lower
    }
}

/// Whether a business time window is in effect at `now` (the server's local time: office hours
/// and month-end are local), and its multiplier.
pub fn evaluate_temporal_window<Tz: TimeZone>(w: &BusinessTimeWindow, now: &chrono::DateTime<Tz>) -> (bool, f64) {
    if !w.active {
        return (false, 1.0);
    }
    let on = |yes: bool| if yes { (true, w.multiplier) } else { (false, 1.0) };
    match w.window_type.as_str() {
        "business_hours" => {
            let weekday = now.weekday().number_from_monday(); // 1 = Mon, 7 = Sun
            let hour = now.hour();
            let is_off_hours = weekday >= 6 || hour < 8 || hour >= 18;

            let name_lower = w.name.to_lowercase();
            let id_lower = w.id.to_lowercase();
            let off_hours_window = id_lower.contains("off-hours")
                || name_lower.contains("off-hour")
                || name_lower.contains("night")
                || name_lower.contains("unattended");
            on(if off_hours_window { is_off_hours } else { !is_off_hours })
        }
        "recurring_schedule" => {
            let name_lower = w.name.to_lowercase();
            let id_lower = w.id.to_lowercase();
            if id_lower.contains("financial") || name_lower.contains("financial") || name_lower.contains("month-end") {
                // the last days of the month and the first: outside them the window is not in effect
                let day = now.day();
                on(day >= 27 || day == 1)
            } else {
                // switched on by an admin (a maintenance window): in effect while on
                on(true)
            }
        }
        "date_range" => match (w.start_date.as_deref().and_then(parse_day), w.end_date.as_deref().and_then(parse_day)) {
            (Some(s), Some(e)) => {
                let today = now.date_naive();
                on(s <= today && today <= e)
            }
            // dates that cannot be read: never in effect (it used to apply always)
            _ => (false, 1.0),
        },
        _ => (false, 1.0),
    }
}

/// Simple pattern matcher supporting prefix/suffix wildcards: "*foo*", "*foo", "foo*", or exact
pub fn matches_pattern(pattern: &str, target: &str) -> bool {
    let p = pattern.trim().to_lowercase();
    let t = target.trim().to_lowercase();

    if p.is_empty() {
        // an empty entry names nothing (it used to match every alert)
        return false;
    }
    if p == "*" {
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
            // a payment server by its name (no fixed test address)
            agent_name: "srv-payment-01".into(),
            agent_ip: "10.20.30.40".into(),
            user: Some("administrator".into()),
            os_type: Some("linux".into()),
        };
        let score = engine.simulate("default", &req);
        assert!(score.dynamic_risk_score >= 85);
        assert_eq!(score.dynamic_risk_tier, "Catastrophic");
        assert!(score.executive_impact.contains("PCI-DSS"));
        let _ = std::fs::remove_file(temp_file);
    }

    #[test]
    fn test_cross_platform_identity_resolution() {
        let mut alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: 60100,
                level: 12,
                description: "Windows logon failure".into(),
                groups: vec!["windows".into()],
                mitre: None,
            },
            agent: siem_core::AgentAlertInfo {
                id: "017".into(),
                name: "win-node-dc10".into(),
                ip: "192.168.1.10".into(),
            },
            manager: None,
            decoder: None,
            full_log: "".into(),
            decoded: siem_core::DecodedFields::default(), // empty decoded.user
            location: r"C:\Windows\System32\Winevt\Security.evtx".into(),
            data: HashMap::new(),
        };

        // Case 1: Windows EventData with Domain prefix
        alert.data.insert("win.eventdata.targetUserName".into(), serde_json::Value::String(r"CORP\Administrator".into()));
        assert_eq!(resolve_alert_user(&alert), "administrator");

        // Case 2: Machine account excluded
        alert.data.insert("win.eventdata.targetUserName".into(), serde_json::Value::String(r"CORP\DC10$".into()));
        alert.data.insert("win.eventdata.subjectUserName".into(), serde_json::Value::String(r"svc_backup".into()));
        assert_eq!(resolve_alert_user(&alert), "svc_backup");

        // Case 3: Linux sudo dstuser
        alert.data.clear();
        alert.data.insert("dstuser".into(), serde_json::Value::String("root".into()));
        assert_eq!(resolve_alert_user(&alert), "root");
    }

    #[test]
    fn test_summary_excludes_redswarm_simulations() {
        let temp_file = std::env::temp_dir().join(format!("test_rf_sum_{}.json", uuid::Uuid::new_v4()));
        let engine = RiskFabricEngine::new(&temp_file);

        let sim_alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: 99001,
                level: 14,
                description: "Red Swarm simulated attack".into(),
                groups: vec!["redswarm_simulation".into(), "attack".into()],
                mitre: None,
            },
            agent: siem_core::AgentAlertInfo {
                id: "001".into(),
                name: "srv-payment-01".into(),
                ip: "192.168.10.15".into(),
            },
            manager: None,
            decoder: None,
            full_log: "".into(),
            decoded: siem_core::DecodedFields::default(),
            location: "redswarm".into(),
            data: HashMap::new(),
        };

        let real_alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: 1001,
                level: 3,
                description: "Routine notice".into(),
                groups: vec!["syslog".into()],
                mitre: None,
            },
            agent: siem_core::AgentAlertInfo {
                id: "002".into(),
                name: "wks-generic-01".into(),
                ip: "10.0.0.55".into(),
            },
            manager: None,
            decoder: None,
            full_log: "".into(),
            decoded: siem_core::DecodedFields::default(),
            location: "/var/log/syslog".into(),
            data: HashMap::new(),
        };

        let summary = engine.get_summary("default", &[sim_alert, real_alert]);
        assert_eq!(summary.catastrophic_alerts_count, 0);
        assert_eq!(summary.critical_alerts_count, 0);
        let total_counted = summary.catastrophic_alerts_count
            + summary.critical_alerts_count
            + summary.high_alerts_count
            + summary.medium_alerts_count
            + summary.low_alerts_count;
        assert_eq!(total_counted, 1);

        let _ = std::fs::remove_file(temp_file);
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use chrono::FixedOffset;

    fn window(id: &str, name: &str, kind: &str, start: Option<&str>, end: Option<&str>) -> BusinessTimeWindow {
        BusinessTimeWindow {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            multiplier: 1.45,
            window_type: kind.into(),
            start_date: start.map(Into::into),
            end_date: end.map(Into::into),
            active: true,
            target_processes: vec![],
        }
    }

    fn at(s: &str) -> chrono::DateTime<FixedOffset> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap()
    }

    #[test]
    fn each_tenant_has_its_own_settings() {
        let e = RiskFabricEngine::new("no-such-file.json");
        let mut p = e.get_processes("acme")[0].clone();
        p.asset_patterns = vec!["zz-audit-*".into()];
        e.add_or_update_process("acme", p.clone()).unwrap();
        assert!(e.get_processes("acme").iter().any(|x| x.id == p.id && x.asset_patterns == ["zz-audit-*"]));
        assert!(!e.get_processes("globex").iter().any(|x| x.asset_patterns == ["zz-audit-*"]), "another tenant's change does not reach this one");
        assert!(e.delete_process("acme", &p.id));
        assert_eq!(e.get_processes("globex").len(), storage::default_config().processes.len());
        assert!(!e.delete_process("globex", "no-such-process"));
        assert!(e.take_changed().iter().all(|(t, _)| t == "acme"), "a refused delete stores nothing");
    }

    #[test]
    fn bad_settings_are_refused() {
        let e = RiskFabricEngine::new("no-such-file.json");
        let good = e.get_processes("t")[0].clone();
        let mut p = good.clone();
        p.name = "  ".into();
        assert!(e.add_or_update_process("t", p).is_err(), "no name");
        let mut p = good.clone();
        p.asset_weight = 50.0;
        assert!(e.add_or_update_process("t", p).is_err(), "weight out of range");
        let mut p = good.clone();
        p.asset_patterns = vec![];
        p.group_patterns = vec![];
        assert!(e.add_or_update_process("t", p).is_err(), "matches nothing");
        let mut p = good.clone();
        p.id = "".into();
        assert!(e.add_or_update_process("t", p).is_err(), "no id");
        assert!(e.take_changed().is_empty(), "nothing refused is stored");
        assert!(e.add_or_update_window("t", window("w", "Freeze", "date_range", Some("2026-12-31"), Some("2026-12-01"))).is_err());
        assert!(e.add_or_update_window("t", window("w", "Freeze", "date_range", Some("soon"), None)).is_err());
        let mut w = window("w", "Freeze", "recurring_schedule", None, None);
        w.multiplier = 9.0;
        assert!(e.add_or_update_window("t", w).is_err());
        assert!(e.add_or_update_window("t", window("w", "Freeze", "date_range", Some("2026-12-01"), Some("2026-12-31"))).is_ok());
    }

    #[test]
    fn month_end_window_applies_only_at_month_end() {
        let w = window("tw-financial-close", "Month-End Financial Close Window", "recurring_schedule", None, None);
        assert_eq!(evaluate_temporal_window(&w, &at("2026-11-22T10:00:00+05:30")), (false, 1.0));
        assert_eq!(evaluate_temporal_window(&w, &at("2026-11-28T10:00:00+05:30")), (true, 1.45));
        assert_eq!(evaluate_temporal_window(&w, &at("2026-12-01T10:00:00+05:30")), (true, 1.45));
    }

    #[test]
    fn office_hours_are_local_time() {
        let w = window("tw-off-hours", "Unattended Off-Hours Operations", "business_hours", None, None);
        // Monday 10:00 in India is office time (it is 04:30 UTC, which used to count as night)
        assert_eq!(evaluate_temporal_window(&w, &at("2026-11-23T10:00:00+05:30")).0, false);
        assert_eq!(evaluate_temporal_window(&w, &at("2026-11-23T22:00:00+05:30")).0, true);
        assert_eq!(evaluate_temporal_window(&w, &at("2026-11-22T10:00:00+05:30")).0, true, "Sunday");
    }

    #[test]
    fn date_ranges_apply_inside_and_unreadable_ones_never() {
        let w = window("tw-freeze", "Change freeze", "date_range", Some("2026-12-01"), Some("2026-12-31"));
        assert!(evaluate_temporal_window(&w, &at("2026-12-15T10:00:00+05:30")).0);
        assert!(!evaluate_temporal_window(&w, &at("2026-11-30T10:00:00+05:30")).0);
        let bad = window("tw-freeze", "Change freeze", "date_range", Some("next week"), None);
        assert_eq!(evaluate_temporal_window(&bad, &at("2026-12-15T10:00:00+05:30")), (false, 1.0));
    }

    #[test]
    fn an_empty_pattern_matches_nothing() {
        assert!(!matches_pattern("", "win-node-e296"));
        assert!(!matches_pattern("  ", "win-node-e296"));
        assert!(matches_pattern("*", "win-node-e296"));
    }

    #[test]
    fn alerts_score_with_their_tenants_settings() {
        let e = RiskFabricEngine::new("no-such-file.json");
        let req = RiskEvaluationRequest {
            rule_level: 10,
            rule_id: None,
            rule_description: None,
            agent_name: "build-agent-7".into(),
            agent_ip: "10.0.0.7".into(),
            user: None,
            os_type: Some("linux".into()),
        };
        let before = e.simulate("acme", &req).business_process;
        let mut p = e.get_processes("acme").into_iter().find(|p| p.id == "bp-pci-payment").unwrap();
        p.asset_patterns.push("build-agent-*".into());
        e.add_or_update_process("acme", p).unwrap();
        assert!(e.simulate("acme", &req).business_process.contains("PCI-DSS"));
        assert_eq!(e.simulate("globex", &req).business_process, before);
    }
}

#[cfg(test)]
mod stored_tests {
    use super::*;

    #[test]
    fn changes_are_handed_over_once_and_load_back() {
        let e = RiskFabricEngine::new("no-such-file.json");
        assert!(e.take_changed().is_empty());
        e.delete_window("acme", "tw-off-hours");
        let changed = e.take_changed();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].0, "acme");
        assert!(e.take_changed().is_empty());
        let fresh = RiskFabricEngine::new("no-such-file.json");
        fresh.load("acme", &changed[0].1);
        assert!(fresh.take_changed().is_empty(), "loading is not a change");
        assert!(!fresh.get_windows("acme").iter().any(|w| w.id == "tw-off-hours"));
        assert!(fresh.get_windows("other").iter().any(|w| w.id == "tw-off-hours"));
    }
}
