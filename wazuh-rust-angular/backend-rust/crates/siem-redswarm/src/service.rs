use crate::audit::AuditStore;
use crate::catalog::{find_technique_for, get_curated_catalog, log_source};

/// A round's alerts come back from the analysis engine within seconds: they are looked for this
/// long (tries x delay), in a window this wide.
const VERIFY_WINDOW_SECS: i64 = 60;
const VERIFY_TRIES: usize = 20;
const VERIFY_DELAY_MS: u64 = 500;
use crate::executor::SwarmExecutor;
use crate::models::{
    AttackTechnique, CommandPayload, DetectionVerdict, ExecutionRecord, FleetAgentTarget,
    RulesOfEngagement, SwarmCampaign, SwarmExecutionMode, SwarmStatusReport,
};
use crate::safety::SafetyGatekeeper;
use crate::synthesizer::RuleSynthesizer;
use crate::verifier::PurpleLoopVerifier;
use chrono::Utc;
use siem_core::{Alert, RawEvent};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{info, warn};

/// Autonomous Red Swarm Engine and Background Orchestrator
pub struct RedSwarmService {
    safety: Arc<SafetyGatekeeper>,
    audit: Arc<AuditStore>,
    executor: Arc<SwarmExecutor>,
    campaigns: RwLock<Vec<SwarmCampaign>>,
    running: AtomicBool,
    /// Tenants whose admin engaged their own kill switch (the global one stops every tenant).
    halted_tenants: RwLock<HashSet<String>>,
    /// Whether a computer sends a log (agent id, source): None when not known.
    source_check: RwLock<Option<SourceCheck>>,
}

/// What an admin set and must survive a restart: the campaigns (paused or not, their counts)
/// and the kill switches. Saved by siem-api (`redswarm_store.rs`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SwarmControlState {
    pub campaigns: Vec<SwarmCampaign>,
    pub kill_switch: bool,
    pub halted_tenants: Vec<String>,
}

/// `(agent id, log source) -> Some(sent lately) / None (not known)`.
pub type SourceCheck = Arc<dyn Fn(&str, &str) -> Option<bool> + Send + Sync>;

impl Default for RedSwarmService {
    fn default() -> Self {
        Self::new()
    }
}

impl RedSwarmService {
    pub fn new() -> Self {
        let safety = Arc::new(SafetyGatekeeper::new());
        let audit = Arc::new(AuditStore::new());
        let executor = Arc::new(SwarmExecutor::new(safety.clone()));

        // Default Production Campaign: SafeTelemetryOnly (Zero-Risk Default)
        let default_campaign = SwarmCampaign {
            id: "default-safe-swarm".into(),
            name: "Continuous attack simulation (safe)".into(),
            description: "Every 15 minutes, one attack's events go through the analysis engine as a computer's own: is it caught by the rules that check the real events? Nothing runs on the computer."
                .into(),
            mode: SwarmExecutionMode::SafeTelemetryOnly,
            enabled: true,
            // the whole catalog (15 attacks) about every 4 hours; each round is a few events
            interval_seconds: 900,
            roe: RulesOfEngagement::default(),
            owner: "admin".into(),
            tenant_id: String::new(),
            approved_by: Some("admin".into()),
            approval_expires_at: None,
            last_run_at: None,
            total_executed: 0,
            total_defended: 0,
            total_gaps: 0,
        };

        Self {
            safety,
            audit,
            executor,
            campaigns: RwLock::new(vec![default_campaign]),
            running: AtomicBool::new(false),
            halted_tenants: RwLock::new(HashSet::new()),
            source_check: RwLock::new(None),
        }
    }

    /// Engage or release one tenant's kill switch.
    pub fn set_tenant_halted(&self, tenant_id: &str, halted: bool) {
        let mut set = self.halted_tenants.write().unwrap();
        if halted {
            set.insert(tenant_id.to_string());
        } else {
            set.remove(tenant_id);
        }
    }

    /// Whether Red Swarm is stopped for the tenant (its own kill switch or the global one).
    pub fn is_tenant_halted(&self, tenant_id: &str) -> bool {
        SafetyGatekeeper::is_kill_switch_engaged() || self.halted_tenants.read().unwrap().contains(tenant_id)
    }

    /// The campaigns and kill switches, to save.
    pub fn control_state(&self) -> SwarmControlState {
        let mut halted: Vec<String> = self.halted_tenants.read().unwrap().iter().cloned().collect();
        halted.sort();
        SwarmControlState { campaigns: self.get_campaigns(), kill_switch: SafetyGatekeeper::is_kill_switch_engaged(), halted_tenants: halted }
    }

    /// Puts back the saved campaigns and kill switches (at start, before the loop runs).
    pub fn restore_control_state(&self, s: SwarmControlState) {
        if !s.campaigns.is_empty() {
            *self.campaigns.write().unwrap() = s.campaigns;
        }
        SafetyGatekeeper::set_kill_switch(s.kill_switch);
        *self.halted_tenants.write().unwrap() = s.halted_tenants.into_iter().collect();
    }

    /// How to tell whether a computer sends a log (siem-api reads its stored events).
    pub fn set_source_check(&self, check: SourceCheck) {
        *self.source_check.write().unwrap() = Some(check);
    }

    /// A Defended round whose computer does not send the attack's log is NotCollected: the rules
    /// catch it, the real computer would not report it.
    fn check_collection(&self, technique: &AttackTechnique, record: &mut ExecutionRecord) {
        let Some(source) = log_source(technique) else { return };
        let check = self.source_check.read().unwrap().clone();
        let sent = check.and_then(|c| c(&record.target_agent_id, &source));
        if record.verification.verdict == DetectionVerdict::Defended && sent == Some(false) {
            record.verification.verdict = DetectionVerdict::NotCollected;
            record.verification.reason = format!(
                "The rules catch this attack, but {} has sent no '{source}' events in the last 7 days: on the real computer it would go unseen. Collect that log on the computer and this round passes.",
                record.target_agent_name
            );
        }
        record.verification.evaluated_signals.push(match sent {
            Some(true) => format!("log source '{source}': collected from this computer"),
            Some(false) => format!("log source '{source}': NOT collected from this computer"),
            None => format!("log source '{source}': collection not known"),
        });
    }

    pub fn safety(&self) -> Arc<SafetyGatekeeper> {
        self.safety.clone()
    }

    pub fn audit(&self) -> Arc<AuditStore> {
        self.audit.clone()
    }

    /// Retrieve full operational status
    pub fn get_status(&self) -> SwarmStatusReport {
        let (total, defended, _, _) = self.audit.get_stats();
        let open_gaps = self.audit.get_pending_gaps().len();
        let approved_rules = self
            .audit
            .get_history(500)
            .iter()
            .filter(|r| {
                r.draft_rule
                    .as_ref()
                    .map(|d| d.status == crate::models::DraftRuleStatus::ApprovedAndDeployed)
                    .unwrap_or(false)
            })
            .count();

        let defense_rate = if total > 0 {
            ((defended as f64 / total as f64) * 100.0 * 10.0).round() / 10.0
        } else {
            100.0
        };

        let (used_budget, max_budget) = self.safety.get_current_budget_usage();
        let campaigns = self.campaigns.read().unwrap();
        let active_count = campaigns.iter().filter(|c| c.enabled).count();

        SwarmStatusReport {
            running: self.running.load(Ordering::SeqCst),
            kill_switch_active: SafetyGatekeeper::is_kill_switch_engaged(),
            default_mode: SwarmExecutionMode::SafeTelemetryOnly,
            active_campaigns_count: active_count,
            attacks_last_24h: total,
            defense_rate_percent: defense_rate,
            open_gaps_count: open_gaps,
            approved_rules_count: approved_rules,
            current_risk_budget_used: used_budget,
            max_risk_budget_per_hour: max_budget,
        }
    }

    /// List configured campaigns
    pub fn get_campaigns(&self) -> Vec<SwarmCampaign> {
        self.campaigns.read().unwrap().clone()
    }

    /// Toggle a campaign active / paused
    pub fn toggle_campaign(&self, id: &str) -> Result<bool, String> {
        let mut list = self.campaigns.write().unwrap();
        if let Some(c) = list.iter_mut().find(|c| c.id == id) {
            c.enabled = !c.enabled;
            return Ok(c.enabled);
        }
        Err(format!("Campaign {} not found", id))
    }

    /// Add or update a campaign
    pub fn upsert_campaign(&self, campaign: SwarmCampaign) {
        let mut list = self.campaigns.write().unwrap();
        if let Some(pos) = list.iter().position(|c| c.id == campaign.id) {
            list[pos] = campaign;
        } else {
            list.push(campaign);
        }
    }

    /// Count a round on the live campaign (not on a copy that may predate a pause or an edit).
    fn record_campaign_round(&self, id: &str, defended: Option<bool>) {
        if let Some(c) = self.campaigns.write().unwrap().iter_mut().find(|c| c.id == id) {
            c.total_executed += 1;
            c.last_run_at = Some(Utc::now());
            match defended {
                Some(true) => c.total_defended += 1,
                Some(false) => c.total_gaps += 1,
                None => {}
            }
        }
    }

    /// Execute a single controlled technique round on demand
    pub async fn run_single_round<F, C>(
        &self,
        technique_id: Option<&str>,
        target_agent_id: &str,
        target_agent_name: &str,
        target_agent_ip: &str,
        target_os: &str,
        target_tags: &[String],
        mode: Option<SwarmExecutionMode>,
        tenant_id: &str,
        inject_telemetry_fn: F,
        dispatch_command_fn: C,
        get_alerts_fn: impl Fn() -> Vec<Alert>,
    ) -> Result<ExecutionRecord, String>
    where
        F: FnOnce(&[RawEvent]),
        C: Fn(&str, &CommandPayload) -> Result<String, String>,
    {
        if self.is_tenant_halted(tenant_id) {
            return Err("Red Swarm is stopped for this tenant: the kill switch is engaged".into());
        }

        // 1. Resolve technique
        let technique = if let Some(id) = technique_id {
            find_technique_for(id, target_os).ok_or_else(|| format!("Technique {} not found in catalog", id))?
        } else {
            // A curated technique for the target's OS, varied from one run to the next
            let catalog = get_curated_catalog();
            let fits: Vec<&AttackTechnique> = catalog.iter().filter(|t| t.platforms.iter().any(|p| p.eq_ignore_ascii_case(target_os))).collect();
            let pool = if fits.is_empty() { catalog.iter().collect() } else { fits };
            pool.get(Utc::now().timestamp_subsec_nanos() as usize % pool.len().max(1))
                .map(|t| (*t).clone())
                .ok_or_else(|| "Technique catalog is empty".to_string())?
        };

        let exec_mode = mode.unwrap_or(SwarmExecutionMode::SafeTelemetryOnly);
        let roe = RulesOfEngagement::default();

        // 2. Dispatch execution
        let mut record = self
            .executor
            .execute_round(
                "manual-run-once",
                tenant_id,
                exec_mode,
                &technique,
                target_agent_id,
                target_agent_name,
                target_agent_ip,
                target_os,
                target_tags,
                &roe,
                inject_telemetry_fn,
                dispatch_command_fn,
            )
            .await;

        if record.execution_success {
            // 3. Multi-signal Purple verification check with retries
            // only the alerts of this round's own events count, never the computer's real ones
            let round = format!("redswarm/{}/", record.id);
            let own = || get_alerts_fn().into_iter().filter(|a| a.location.starts_with(&round)).collect::<Vec<_>>();
            let verification = PurpleLoopVerifier::verify_with_retries(&technique, "", record.timestamp, VERIFY_WINDOW_SECS, VERIFY_TRIES, VERIFY_DELAY_MS, own).await;
            record.verification = verification;
            self.check_collection(&technique, &mut record);

            // 4. On Hard Gap or Soft Gap -> Auto-synthesize draft rule (Pending Approval), once per open gap
            if is_rule_gap(&record) && !self.audit.drafting_held(tenant_id, &technique.id) {
                let sample_log = technique
                    .sample_raw_logs
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format!("Simulated evasion for {}", technique.id));
                let draft = RuleSynthesizer::synthesize_draft_rule(
                    record.id,
                    &technique,
                    &sample_log,
                );
                record.draft_rule = Some(draft);
            }
        }

        // 5. Commit to immutable audit trail
        self.audit.record_execution(record.clone());

        Ok(record)
    }

    /// Background autonomous loop: Runs continuously and tests techniques
    pub fn start_background_loop<F, C, A, G>(
        self: Arc<Self>,
        inject_fn: F,
        dispatch_fn: C,
        alerts_fn: A,
        get_agents_fn: G,
    ) where
        F: Fn(&[RawEvent]) + Send + Sync + 'static,
        C: Fn(&str, &CommandPayload) -> Result<String, String> + Send + Sync + 'static,
        A: Fn() -> Vec<Alert> + Send + Sync + 'static,
        G: Fn() -> Vec<FleetAgentTarget> + Send + Sync + 'static,
    {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Red Swarm background loop is already active.");
            return;
        }

        info!("Starting ProVigil Continuous Red Agent Swarm autonomous engine...");

        tokio::spawn(async move {
            let mut round_counter: usize = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                if SafetyGatekeeper::is_kill_switch_engaged() {
                    continue;
                }

                let campaigns = self.campaigns.read().unwrap().clone();
                let catalog = get_curated_catalog();
                let fleet = get_agents_fn();

                for campaign in campaigns {
                    if !campaign.enabled || catalog.is_empty() || !is_due(&campaign, Utc::now()) {
                        continue;
                    }

                    // The campaign's tenants' agents (all, for a platform campaign), less halted tenants
                    let fleet: Vec<FleetAgentTarget> = fleet
                        .iter()
                        .filter(|a| {
                            let t = target_tenant(a);
                            (campaign.tenant_id.is_empty() || campaign.tenant_id == t) && !self.is_tenant_halted(t)
                        })
                        .cloned()
                        .collect();

                    // Dynamically resolve available endpoints from the active fleet
                    let active_agents: Vec<FleetAgentTarget> = fleet
                        .iter()
                        .filter(|a| a.status.eq_ignore_ascii_case("active"))
                        .cloned()
                        .collect();

                    let usable_fleet = if !active_agents.is_empty() { active_agents } else { fleet };

                    if usable_fleet.is_empty() {
                        warn!("Red Swarm: No registered or active agents in fleet. Standing by for endpoint connection.");
                        continue;
                    }

                    // Discover what operating systems are currently present in the monitored fleet
                    let fleet_platforms: std::collections::HashSet<String> = usable_fleet
                        .iter()
                        .map(|a| a.os_type.to_lowercase())
                        .collect();

                    // Filter catalog to techniques applicable to the actual endpoints in the fleet
                    let applicable_techniques: Vec<&AttackTechnique> = catalog
                        .iter()
                        .filter(|t| {
                            t.platforms.iter().any(|p| fleet_platforms.contains(&p.to_lowercase()))
                        })
                        .collect();

                    if applicable_techniques.is_empty() {
                        warn!(
                            "Red Swarm: No catalog techniques match currently connected fleet platforms ({:?}).",
                            fleet_platforms
                        );
                        continue;
                    }

                    // An agent of the technique's platform (every tenant's agents get tested)
                    let technique = applicable_techniques[round_counter % applicable_techniques.len()];
                    let candidates: Vec<&FleetAgentTarget> = usable_fleet
                        .iter()
                        .filter(|a| technique.platforms.iter().any(|p| p.eq_ignore_ascii_case(&a.os_type)))
                        .collect();
                    let target_agent = if candidates.is_empty() {
                        &usable_fleet[0]
                    } else {
                        candidates[target_index(round_counter, applicable_techniques.len(), candidates.len())]
                    };
                    round_counter += 1;
                    let tenant = target_tenant(target_agent);

                    let target_id = &target_agent.id;
                    let target_name = &target_agent.name;
                    let target_ip = &target_agent.ip;
                    let target_os = &target_agent.os_type;
                    let target_tags = if target_agent.tags.is_empty() {
                        vec!["lab".into(), "redteam-allowed".into()]
                    } else {
                        target_agent.tags.clone()
                    };

                    info!(
                        "Continuous Red Swarm Tick: Campaign '{}' executing {} ({}) on live target {} ({} - {}) in {:?}",
                        campaign.name, technique.id, technique.name, target_name, target_id, target_os, campaign.mode
                    );

                    let mut record = self
                        .executor
                        .execute_round(
                            &campaign.id,
                            tenant,
                            campaign.mode,
                            technique,
                            target_id,
                            target_name,
                            target_ip,
                            target_os,
                            &target_tags,
                            &campaign.roe,
                            |events| inject_fn(events),
                            |ag_id, cmd| dispatch_fn(ag_id, cmd),
                        )
                        .await;

                    let mut defended = None;
                    if record.execution_success {
                        let round = format!("redswarm/{}/", record.id);
                        let own = || alerts_fn().into_iter().filter(|a| a.location.starts_with(&round)).collect::<Vec<_>>();
                        let verification = PurpleLoopVerifier::verify_with_retries(technique, "", record.timestamp, VERIFY_WINDOW_SECS, VERIFY_TRIES, VERIFY_DELAY_MS, own).await;
                        record.verification = verification;
                        self.check_collection(technique, &mut record);

                        if is_rule_gap(&record) {
                            if !self.audit.drafting_held(tenant, &technique.id) {
                                let sample_log = technique
                                    .sample_raw_logs
                                    .first()
                                    .cloned()
                                    .unwrap_or_default();
                                let draft = RuleSynthesizer::synthesize_draft_rule(
                                    record.id,
                                    technique,
                                    &sample_log,
                                );
                                record.draft_rule = Some(draft);
                            }
                        }
                        defended = Some(record.verification.verdict == DetectionVerdict::Defended);
                    }

                    self.record_campaign_round(&campaign.id, defended);
                    self.audit.record_execution(record);
                }
            }
        });
    }
}

/// The computer of round `k`: the next one after each pass over the attacks, so every attack is
/// tried on every computer (moving both by one each round tied an attack to one computer).
fn target_index(k: usize, attacks: usize, computers: usize) -> usize {
    (k / attacks.max(1)) % computers.max(1)
}

/// Only a rules gap gets a drafted rule: a NotCollected round needs the log, not a rule.
fn is_rule_gap(r: &ExecutionRecord) -> bool {
    matches!(r.verification.verdict, DetectionVerdict::SoftGap | DetectionVerdict::HardGap)
}

fn target_tenant(a: &FleetAgentTarget) -> &str {
    if a.tenant_id.is_empty() { "default" } else { &a.tenant_id }
}

/// Whether the campaign's interval has passed since its last round (the loop ticks every 60 s).
fn is_due(c: &SwarmCampaign, now: chrono::DateTime<Utc>) -> bool {
    c.last_run_at.map_or(true, |t| (now - t).num_seconds() >= c.interval_seconds as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_waits_for_its_interval() {
        let svc = RedSwarmService::new();
        let mut c = svc.get_campaigns().remove(0);
        let now = Utc::now();
        assert!(is_due(&c, now)); // never ran
        c.interval_seconds = 3600;
        c.last_run_at = Some(now - chrono::Duration::seconds(120));
        assert!(!is_due(&c, now));
        c.last_run_at = Some(now - chrono::Duration::seconds(3600));
        assert!(is_due(&c, now));
    }

    #[test]
    fn round_counts_land_on_the_live_campaign() {
        let svc = RedSwarmService::new();
        let id = svc.get_campaigns()[0].id.clone();
        svc.toggle_campaign(&id).unwrap(); // paused while a round runs
        svc.record_campaign_round(&id, Some(false));
        let c = &svc.get_campaigns()[0];
        assert!(!c.enabled, "the pause survives the round");
        assert_eq!((c.total_executed, c.total_gaps), (1, 1));
    }

    #[test]
    fn every_attack_reaches_every_computer() {
        for (attacks, computers) in [(8, 2), (8, 4), (7, 3), (15, 5), (1, 3), (5, 1)] {
            let mut seen = HashSet::new();
            for k in 0..attacks * computers {
                seen.insert((k % attacks, target_index(k, attacks, computers)));
            }
            assert_eq!(seen.len(), attacks * computers, "{attacks} attacks on {computers} computers");
        }
    }

    #[test]
    fn control_state_comes_back_after_a_restart() {
        let before = RedSwarmService::new();
        let id = before.get_campaigns()[0].id.clone();
        before.toggle_campaign(&id).unwrap();
        before.record_campaign_round(&id, Some(true));
        before.set_tenant_halted("acme", true);
        let saved = serde_json::to_string(&before.control_state()).unwrap();

        let after = RedSwarmService::new(); // a restart
        after.restore_control_state(serde_json::from_str(&saved).unwrap());
        let c = &after.get_campaigns()[0];
        assert!(!c.enabled, "still paused");
        assert_eq!(c.total_defended, 1);
        assert!(after.is_tenant_halted("acme") && !after.is_tenant_halted("globex"));
        assert_eq!(serde_json::to_string(&after.control_state()).unwrap(), saved);
    }

    #[tokio::test]
    async fn a_round_on_a_computer_without_the_log_is_not_collected() {
        // the alert the engine gives a round's events (siem-api sends them under redswarm/<round>/<id>)
        let alert = |round: String| Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: 5763,
                level: 10,
                description: "sshd: brute force".into(),
                groups: vec!["sshd".into()],
                mitre: Some(siem_core::MitreAttack { id: "T1110".into(), tactic: String::new(), technique: String::new() }),
            },
            agent: siem_core::AgentAlertInfo { id: "001".into(), name: "a".into(), ip: String::new() },
            manager: None,
            decoder: None,
            full_log: String::new(),
            decoded: Default::default(),
            location: format!("redswarm/{round}/T1110.001"),
            data: Default::default(),
        };
        let run = |sent: Option<bool>| {
            let svc = RedSwarmService::new();
            svc.set_source_check(Arc::new(move |agent: &str, src: &str| {
                assert_eq!((agent, src), ("001", "sshd"));
                sent
            }));
            let round = Arc::new(RwLock::new(String::new()));
            let r2 = round.clone();
            async move {
                svc.run_single_round(Some("T1110.001"), "001", "a", "10.0.0.1", "linux", &[], None, "t",
                    move |ev| *r2.write().unwrap() = ev[0].metadata["redswarm_round"].clone(),
                    |_, _| Err(String::new()),
                    move || vec![alert(round.read().unwrap().clone())])
                .await
                .unwrap()
            }
        };
        assert_eq!(run(Some(true)).await.verification.verdict, DetectionVerdict::Defended);
        assert_eq!(run(None).await.verification.verdict, DetectionVerdict::Defended, "unknown is not a gap");
        let blind = run(Some(false)).await;
        assert_eq!(blind.verification.verdict, DetectionVerdict::NotCollected);
        assert!(blind.verification.reason.contains("'sshd'"), "{}", blind.verification.reason);
        assert!(blind.draft_rule.is_none(), "the rules are fine: no rule is drafted");
    }

    #[tokio::test]
    async fn a_tenant_kill_switch_stops_only_that_tenant() {
        let svc = RedSwarmService::new();
        svc.set_tenant_halted("acme", true);
        assert!(svc.is_tenant_halted("acme") && !svc.is_tenant_halted("globex"));
        let run = |tenant: &'static str| {
            svc.run_single_round(Some("T1110.001"), "001", "a", "10.0.0.1", "linux", &[], None, tenant, |_| {}, |_, _| Err(String::new()), Vec::new)
        };
        assert!(run("acme").await.is_err());
        assert!(run("globex").await.is_ok());
        svc.set_tenant_halted("acme", false);
        assert!(run("acme").await.is_ok());
    }
}
