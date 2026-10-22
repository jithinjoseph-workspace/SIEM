use crate::models::{
    AttackTechnique, CleanupStatus, CommandPayload, ExecutionRecord, RulesOfEngagement,
    SwarmExecutionMode, VerificationEvidence, DetectionVerdict,
};
use crate::safety::SafetyGatekeeper;
use chrono::Utc;
use siem_core::{EventSource, RawEvent};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct SwarmExecutor {
    safety: Arc<SafetyGatekeeper>,
}

impl SwarmExecutor {
    pub fn new(safety: Arc<SafetyGatekeeper>) -> Self {
        Self { safety }
    }

    /// Primary execution dispatcher:
    /// - Evaluates ROE & Safety Guardrails
    /// - Dispatches either SafeTelemetryOnly or ControlledLive
    /// - For live mode: manages concurrency permits and executes mandatory immediate cleanup
    /// - On cleanup failure: marks execution failed and triggers emergency auto-kill-switch
    pub async fn execute_round<F, C>(
        &self,
        campaign_id: &str,
        tenant_id: &str,
        mode: SwarmExecutionMode,
        technique: &AttackTechnique,
        target_agent_id: &str,
        target_agent_name: &str,
        target_agent_ip: &str,
        target_os: &str,
        target_tags: &[String],
        roe: &RulesOfEngagement,
        inject_telemetry_fn: F,
        dispatch_command_fn: C,
    ) -> ExecutionRecord
    where
        F: FnOnce(&[RawEvent]),
        C: Fn(&str, &CommandPayload) -> Result<String, String>,
    {
        let record_id = Uuid::new_v4();
        let now = Utc::now();

        // 1. Safety check
        if let Err(block_reason) = self.safety.evaluate_execution(
            campaign_id,
            mode,
            technique,
            target_agent_id,
            target_tags,
            roe,
        ) {
            warn!("Red Swarm safety gatekeeper blocked execution: {}", block_reason);
            return ExecutionRecord {
                id: record_id,
                campaign_id: campaign_id.to_string(),
                tenant_id: tenant_id.to_string(),
                timestamp: now,
                technique_id: technique.id.clone(),
                technique_name: technique.name.clone(),
                tactic: technique.tactic.clone(),
                mode,
                target_agent_id: target_agent_id.to_string(),
                target_agent_name: target_agent_name.to_string(),
                target_agent_ip: target_agent_ip.to_string(),
                target_os: target_os.to_string(),
                execution_success: false,
                execution_output: format!("Safety Block: {}", block_reason),
                cleanup_status: CleanupStatus::NotApplicable,
                cleanup_output: None,
                verification: VerificationEvidence {
                    verdict: DetectionVerdict::HardGap,
                    matched_alert_id: None,
                    matched_rule_id: None,
                    matched_rule_description: None,
                    matched_alert: None,
                    retry_count: 0,
                    evaluated_signals: vec!["safety_gatekeeper_blocked".into()],
                    reason: format!("Execution blocked before launch: {}", block_reason),
                    latency_ms: 0,
                },
                draft_rule: None,
            };
        }

        // 2. Dispatch based on mode
        match mode {
            SwarmExecutionMode::SafeTelemetryOnly => {
                info!(
                    "Executing Red Swarm in SafeTelemetryOnly mode: Technique {} ({}) on target {} ({})",
                    technique.id, technique.name, target_agent_name, target_agent_id
                );

                // Construct realistic raw events from technique samples
                let mut events = Vec::new();
                for sample in &technique.sample_raw_logs {
                    let source = if sample.contains("EventID") || sample.contains("Microsoft-Windows") {
                        EventSource::WindowsEvent
                    } else if sample.contains("auditd") || sample.contains("type=SYSCALL") {
                        EventSource::Auth
                    } else if sample.contains("ossec: File") || sample.contains("syscheck") {
                        EventSource::Fim
                    } else {
                        EventSource::Syslog
                    };

                    let mut ev = RawEvent::new(
                        target_agent_id,
                        source,
                        format!("redswarm/{}", technique.id),
                        sample.clone(),
                    );
                    ev.metadata.insert("tenant_id".into(), tenant_id.to_string());
                    ev.metadata.insert("redswarm_simulation".into(), "true".to_string());
                    ev.metadata.insert("technique_id".into(), technique.id.clone());
                    events.push(ev);
                }

                // Inject into correlation engine pipeline
                inject_telemetry_fn(&events);

                ExecutionRecord {
                    id: record_id,
                    campaign_id: campaign_id.to_string(),
                    tenant_id: tenant_id.to_string(),
                    timestamp: now,
                    technique_id: technique.id.clone(),
                    technique_name: technique.name.clone(),
                    tactic: technique.tactic.clone(),
                    mode,
                    target_agent_id: target_agent_id.to_string(),
                    target_agent_name: target_agent_name.to_string(),
                    target_agent_ip: target_agent_ip.to_string(),
                    target_os: target_os.to_string(),
                    execution_success: true,
                    execution_output: format!(
                        "SafeTelemetryOnly: Injected {} attack telemetry events into engine for technique {}.",
                        events.len(), technique.id
                    ),
                    cleanup_status: CleanupStatus::NotApplicable,
                    cleanup_output: Some("Telemetry-only injection; zero endpoint artifacts created.".into()),
                    verification: VerificationEvidence {
                        verdict: DetectionVerdict::HardGap, // Populated by verifier next
                        matched_alert_id: None,
                        matched_rule_id: None,
                        matched_rule_description: None,
                        matched_alert: None,
                        retry_count: 0,
                        evaluated_signals: vec!["safe_telemetry_injected".into()],
                        reason: "Pending verification window correlation.".into(),
                        latency_ms: 0,
                    },
                    draft_rule: None,
                }
            }

            SwarmExecutionMode::ControlledLive | SwarmExecutionMode::FullLive => {
                info!(
                    "Executing Red Swarm in LIVE mode ({:?}): Technique {} on target {} ({})",
                    mode, technique.id, target_agent_name, target_agent_id
                );

                self.safety.acquire_live_permit();

                // A. Run Attack Payload on Agent
                let exec_result = dispatch_command_fn(target_agent_id, &technique.execution);
                let (mut exec_success, exec_output) = match exec_result {
                    Ok(out) => (true, out),
                    Err(err) => (false, format!("Command dispatch failed: {}", err)),
                };

                // B. Mandatory Immediate Cleanup
                let cleanup_result = dispatch_command_fn(target_agent_id, &technique.cleanup);
                let (cleanup_status, cleanup_out) = match cleanup_result {
                    Ok(out) => (CleanupStatus::Succeeded, Some(out)),
                    Err(err) => {
                        error!(
                            "CRITICAL SAFETY ALERT: Cleanup command failed on agent {} for technique {}: {}",
                            target_agent_id, technique.id, err
                        );
                        // Failure Handling: Mark execution failed and trigger emergency kill-switch
                        exec_success = false;
                        SafetyGatekeeper::set_kill_switch(true);
                        error!(
                            "EMERGENCY SHUTDOWN: Global Red Swarm Kill-Switch auto-engaged due to cleanup failure on agent {}",
                            target_agent_id
                        );
                        (CleanupStatus::Failed, Some(format!("CRITICAL: CLEANUP FAILED: {}. Emergency Kill-Switch Engaged.", err)))
                    }
                };

                self.safety.release_live_permit();

                ExecutionRecord {
                    id: record_id,
                    campaign_id: campaign_id.to_string(),
                    tenant_id: tenant_id.to_string(),
                    timestamp: now,
                    technique_id: technique.id.clone(),
                    technique_name: technique.name.clone(),
                    tactic: technique.tactic.clone(),
                    mode,
                    target_agent_id: target_agent_id.to_string(),
                    target_agent_name: target_agent_name.to_string(),
                    target_agent_ip: target_agent_ip.to_string(),
                    target_os: target_os.to_string(),
                    execution_success: exec_success,
                    execution_output: exec_output,
                    cleanup_status,
                    cleanup_output: cleanup_out,
                    verification: VerificationEvidence {
                        verdict: DetectionVerdict::HardGap,
                        matched_alert_id: None,
                        matched_rule_id: None,
                        matched_rule_description: None,
                        matched_alert: None,
                        retry_count: 0,
                        evaluated_signals: vec!["live_command_executed".into()],
                        reason: "Pending live telemetry correlation.".into(),
                        latency_ms: 0,
                    },
                    draft_rule: None,
                }
            }
        }
    }
}
