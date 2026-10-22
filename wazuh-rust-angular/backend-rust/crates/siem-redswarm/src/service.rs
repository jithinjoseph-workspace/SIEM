use crate::audit::AuditStore;
use crate::catalog::{find_technique, get_curated_catalog};
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
}

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
            name: "Continuous MITRE Adversarial Simulation (Safe)".into(),
            description: "Continuous telemetry-based adversarial simulation against active detection rules."
                .into(),
            mode: SwarmExecutionMode::SafeTelemetryOnly,
            enabled: true,
            interval_seconds: 60,
            roe: RulesOfEngagement::default(),
            owner: "admin".into(),
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
        }
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
        // 1. Resolve technique
        let technique = if let Some(id) = technique_id {
            find_technique(id).ok_or_else(|| format!("Technique {} not found in catalog", id))?
        } else {
            // Pick random curated technique
            let catalog = get_curated_catalog();
            catalog
                .first()
                .cloned()
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
            let verification = PurpleLoopVerifier::verify_with_retries(
                &technique,
                target_agent_id,
                record.timestamp,
                15,
                3,
                300,
                &get_alerts_fn,
            ).await;
            record.verification = verification;

            // 4. On Hard Gap or Soft Gap -> Auto-synthesize draft rule (Pending Approval)
            if record.verification.verdict != DetectionVerdict::Defended {
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

                for mut campaign in campaigns {
                    if !campaign.enabled || catalog.is_empty() {
                        continue;
                    }

                    // Dynamically resolve available endpoints from the active fleet
                    let active_agents: Vec<FleetAgentTarget> = fleet
                        .iter()
                        .filter(|a| a.status.eq_ignore_ascii_case("active"))
                        .cloned()
                        .collect();

                    let usable_fleet = if !active_agents.is_empty() {
                        active_agents
                    } else if !fleet.is_empty() {
                        fleet.clone()
                    } else {
                        Vec::new()
                    };

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

                    // Select technique from applicable set for the available platforms
                    let technique = applicable_techniques[round_counter % applicable_techniques.len()];
                    round_counter += 1;

                    // Dynamically pick an agent that matches this technique's platform
                    let target_agent = usable_fleet
                        .iter()
                        .find(|a| technique.platforms.iter().any(|p| p.eq_ignore_ascii_case(&a.os_type)))
                        .or_else(|| usable_fleet.first())
                        .unwrap();

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
                            "default",
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

                    if record.execution_success {
                        let verification = PurpleLoopVerifier::verify_with_retries(
                            technique,
                            target_id,
                            record.timestamp,
                            15,
                            3,
                            300,
                            &alerts_fn,
                        ).await;
                        record.verification = verification;

                        if record.verification.verdict != DetectionVerdict::Defended {
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
                            campaign.total_gaps += 1;
                        } else {
                            campaign.total_defended += 1;
                        }
                    }

                    campaign.total_executed += 1;
                    campaign.last_run_at = Some(Utc::now());
                    self.upsert_campaign(campaign);
                    self.audit.record_execution(record);
                }
            }
        });
    }
}
