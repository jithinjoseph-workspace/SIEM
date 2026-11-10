use crate::models::{AttackTechnique, RiskLevel, RulesOfEngagement, SwarmExecutionMode};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::RwLock;

/// Thread-safe global kill switch
static KILL_SWITCH_ENGAGED: AtomicBool = AtomicBool::new(false);

/// Safety gatekeeper enforcing the Non-Negotiable Rules of Engagement
pub struct SafetyGatekeeper {
    risk_window_start: RwLock<DateTime<Utc>>,
    risk_actions_count: RwLock<u32>,
    active_live_executions: AtomicUsize,
    agent_last_probe: RwLock<HashMap<String, DateTime<Utc>>>,
    campaign_hourly_records: RwLock<HashMap<String, Vec<DateTime<Utc>>>>,
}

impl Default for SafetyGatekeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyGatekeeper {
    pub fn new() -> Self {
        Self {
            risk_window_start: RwLock::new(Utc::now()),
            risk_actions_count: RwLock::new(0),
            active_live_executions: AtomicUsize::new(0),
            agent_last_probe: RwLock::new(HashMap::new()),
            campaign_hourly_records: RwLock::new(HashMap::new()),
        }
    }

    /// Check if the emergency global kill-switch is engaged
    pub fn is_kill_switch_engaged() -> bool {
        KILL_SWITCH_ENGAGED.load(Ordering::SeqCst)
    }

    /// Engage or disengage the global kill-switch
    pub fn set_kill_switch(engaged: bool) {
        KILL_SWITCH_ENGAGED.store(engaged, Ordering::SeqCst);
    }

    /// Validates an execution request against all safety constraints:
    /// 1. Global kill switch
    /// 2. Campaign mode vs technique risk level
    /// 3. Reversibility & cleanup guarantee
    /// 4. Target agent allow-list / deny-list / tags
    /// 5. Banned technique lists
    /// 6. Hourly risk budget
    /// 7. Max concurrent live executions
    /// 8. Per-agent cooldown rate limit
    /// 9. Per-campaign hourly rate limit
    pub fn evaluate_execution(
        &self,
        campaign_id: &str,
        mode: SwarmExecutionMode,
        technique: &AttackTechnique,
        target_agent_id: &str,
        target_agent_tags: &[String],
        roe: &RulesOfEngagement,
    ) -> Result<(), String> {
        // 1. Global kill-switch check
        if Self::is_kill_switch_engaged() {
            return Err("Execution BLOCKED: Global Red Swarm Kill-Switch is ACTIVE.".into());
        }

        // 2. Banned technique check
        if roe.banned_techniques.contains(&technique.id) {
            return Err(format!("Execution BLOCKED: Technique {} is explicitly banned by ROE.", technique.id));
        }

        // 3. Tactic allow-list check
        if !roe.allowed_tactics.iter().any(|t| t.eq_ignore_ascii_case(&technique.tactic)) {
            return Err(format!("Execution BLOCKED: Tactic '{}' is not in the allowed ROE tactics.", technique.tactic));
        }

        // 4. SafeTelemetryOnly Mode: Injects into engine only, always safe
        if mode == SwarmExecutionMode::SafeTelemetryOnly {
            return Ok(());
        }

        // ── LIVE EXECUTION CONSTRAINTS (ControlledLive & FullLive) ──

        // 5. Max Concurrent Live Executions
        let current_active = self.active_live_executions.load(Ordering::SeqCst);
        if current_active >= roe.max_concurrent_live_executions {
            return Err(format!(
                "Execution BLOCKED: Max concurrent live executions reached ({}/{}).",
                current_active, roe.max_concurrent_live_executions
            ));
        }

        // 6. Target Agent Deny-List
        if roe.denied_agent_ids.contains(&target_agent_id.to_string()) {
            return Err(format!("Execution BLOCKED: Agent {} is in the denied target list.", target_agent_id));
        }

        // 7. Target Agent Tag Allow-List (Must have 'redteam-allowed' or 'lab')
        let has_allowed_tag = target_agent_tags.iter().any(|tag| {
            roe.allowed_agent_tags.iter().any(|allowed| allowed.eq_ignore_ascii_case(tag))
        });
        if !has_allowed_tag {
            return Err(format!(
                "Execution BLOCKED: Target agent {} does not have required authorization tags ({:?}). Found tags: {:?}",
                target_agent_id, roe.allowed_agent_tags, target_agent_tags
            ));
        }

        // 8. Per-Agent Rate Limit / Cooldown
        let now = Utc::now();
        {
            let mut agent_map = self.agent_last_probe.write().unwrap();
            if let Some(last_time) = agent_map.get(target_agent_id) {
                let elapsed_secs = (now - *last_time).num_seconds().max(0) as u64;
                if elapsed_secs < roe.per_agent_cooldown_seconds {
                    return Err(format!(
                        "Execution BLOCKED: Agent {} is in cooldown window (last probe was {}s ago, required cooldown is {}s).",
                        target_agent_id, elapsed_secs, roe.per_agent_cooldown_seconds
                    ));
                }
            }
            agent_map.insert(target_agent_id.to_string(), now);
        }

        // 9. Per-Campaign Hourly Rate Limit
        {
            let mut campaign_records = self.campaign_hourly_records.write().unwrap();
            let entries = campaign_records.entry(campaign_id.to_string()).or_default();
            // Prune entries older than 1 hour
            entries.retain(|t| now - *t < Duration::hours(1));
            if entries.len() >= roe.max_attacks_per_hour as usize {
                return Err(format!(
                    "Execution BLOCKED: Campaign {} exceeded hourly rate limit ({} / {} executed).",
                    campaign_id, entries.len(), roe.max_attacks_per_hour
                ));
            }
            entries.push(now);
        }

        // 10. Non-negotiable Reversibility Check
        if !technique.reversible || !technique.cleanup_guaranteed {
            return Err(format!(
                "Execution BLOCKED: Technique {} is non-reversible. Live execution strictly prohibited by safety policy.",
                technique.id
            ));
        }

        // 11. ControlledLive Restrictions
        if mode == SwarmExecutionMode::ControlledLive {
            if technique.banned_in_controlled_live {
                return Err(format!(
                    "Execution BLOCKED: Technique {} is prohibited in ControlledLive mode.",
                    technique.id
                ));
            }
            if technique.risk_level > roe.max_risk_level || technique.risk_level == RiskLevel::Critical {
                return Err(format!(
                    "Execution BLOCKED: Technique risk {:?} exceeds maximum allowed {:?} for ControlledLive.",
                    technique.risk_level, roe.max_risk_level
                ));
            }
        }

        // 12. Risk Budget Check (Rolling hourly limit)
        self.check_and_increment_risk_budget(roe.max_attacks_per_hour)?;

        Ok(())
    }

    /// Acquire live execution permit
    pub fn acquire_live_permit(&self) {
        self.active_live_executions.fetch_add(1, Ordering::SeqCst);
    }

    /// Release live execution permit
    pub fn release_live_permit(&self) {
        let _ = self.active_live_executions.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
            Some(val.saturating_sub(1))
        });
    }

    fn check_and_increment_risk_budget(&self, max_per_hour: u32) -> Result<(), String> {
        let now = Utc::now();
        let mut window_start = self.risk_window_start.write().unwrap();
        let mut count = self.risk_actions_count.write().unwrap();

        // Reset budget if window expired (> 1 hour)
        if now - *window_start > Duration::hours(1) {
            *window_start = now;
            *count = 0;
        }

        if *count >= max_per_hour {
            return Err(format!(
                "Execution BLOCKED: Hourly risk budget exceeded ({} / {} actions executed this hour).",
                *count, max_per_hour
            ));
        }

        *count += 1;
        Ok(())
    }

    pub fn get_current_budget_usage(&self) -> (u32, u32) {
        let now = Utc::now();
        let mut window_start = self.risk_window_start.write().unwrap();
        let mut count = self.risk_actions_count.write().unwrap();

        if now - *window_start > Duration::hours(1) {
            *window_start = now;
            *count = 0;
        }

        (*count, 60)
    }
}
