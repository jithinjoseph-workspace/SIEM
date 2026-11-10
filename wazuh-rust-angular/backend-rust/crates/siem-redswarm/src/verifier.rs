use crate::models::{AttackTechnique, DetectionVerdict, VerificationEvidence};
use chrono::{DateTime, Duration, Utc};
use siem_core::Alert;
use tracing::info;

pub struct PurpleLoopVerifier;

impl PurpleLoopVerifier {
    /// Multi-signal detection verification with configurable retry attempts:
    /// Correlates alerts triggered within the window against:
    /// 1. Direct MITRE ATT&CK ID & Sub-technique matches
    /// 2. Related rule group classifications
    /// 3. Expected IOCs / process / log indicators
    /// 4. Closest candidate alert capture
    ///
    /// Classifies into:
    /// - Defended: Strong matching alert with proper MITRE / high-fidelity rule
    /// - Soft Gap: Generic alert fired without precise MITRE classification
    /// - Hard Gap: Zero detection within the window
    pub async fn verify_with_retries<F>(
        technique: &AttackTechnique,
        target_agent_id: &str,
        execution_time: DateTime<Utc>,
        window_seconds: i64,
        max_retries: usize,
        retry_delay_ms: u64,
        alerts_provider: F,
    ) -> VerificationEvidence
    where
        F: Fn() -> Vec<Alert>,
    {
        let mut attempts = 0;
        let mut final_evidence = Self::evaluate_signals(
            technique,
            target_agent_id,
            execution_time,
            window_seconds,
            &alerts_provider(),
            0,
        );

        while final_evidence.verdict == DetectionVerdict::HardGap && attempts < max_retries {
            attempts += 1;
            tokio::time::sleep(tokio::time::Duration::from_millis(retry_delay_ms)).await;
            final_evidence = Self::evaluate_signals(
                technique,
                target_agent_id,
                execution_time,
                window_seconds,
                &alerts_provider(),
                attempts as u32,
            );
            if final_evidence.verdict != DetectionVerdict::HardGap {
                break;
            }
        }

        final_evidence
    }

    /// Single evaluation pass across candidate alerts
    pub fn verify_execution(
        technique: &AttackTechnique,
        target_agent_id: &str,
        execution_time: DateTime<Utc>,
        window_seconds: i64,
        candidate_alerts: &[Alert],
    ) -> VerificationEvidence {
        Self::evaluate_signals(
            technique,
            target_agent_id,
            execution_time,
            window_seconds,
            candidate_alerts,
            0,
        )
    }

    fn evaluate_signals(
        technique: &AttackTechnique,
        target_agent_id: &str,
        execution_time: DateTime<Utc>,
        window_seconds: i64,
        candidate_alerts: &[Alert],
        retry_count: u32,
    ) -> VerificationEvidence {
        let start_time = execution_time - Duration::seconds(2);
        let end_time = execution_time + Duration::seconds(window_seconds);

        // Filter alerts within correlation time window for the targeted agent
        let window_alerts: Vec<&Alert> = candidate_alerts
            .iter()
            .filter(|a| {
                a.timestamp >= start_time
                    && a.timestamp <= end_time
                    && (a.agent.id == target_agent_id || target_agent_id.is_empty())
            })
            .collect();

        let latency_ms = (Utc::now() - execution_time).num_milliseconds().max(0) as u64;
        let mut evaluated_signals = Vec::new();

        // 1. Check for Strong Detection (MITRE Match)
        for alert in &window_alerts {
            if let Some(mitre) = &alert.rule.mitre {
                let matches_mitre = technique
                    .expected_mitre_ids
                    .iter()
                    .any(|id| mitre.id.starts_with(id) || id.starts_with(&mitre.id));

                if matches_mitre {
                    evaluated_signals.push(format!("mitre_id_match:{}", mitre.id));
                    info!(
                        "VERIFIED DEFENDED: Technique {} triggered Alert {} (Rule #{}: {})",
                        technique.id, alert.id, alert.rule.id, alert.rule.description
                    );
                    return VerificationEvidence {
                        verdict: DetectionVerdict::Defended,
                        matched_alert_id: Some(alert.id),
                        matched_rule_id: Some(alert.rule.id),
                        matched_rule_description: Some(alert.rule.description.clone()),
                        matched_alert: Some((*alert).clone()),
                        retry_count,
                        evaluated_signals,
                        reason: format!(
                            "Strong Detection: Matched MITRE technique {} on Rule #{}: '{}'.",
                            mitre.id, alert.rule.id, alert.rule.description
                        ),
                        latency_ms,
                    };
                }
            }
        }

        // 2. Multi-Signal IOC & Rule Group Matching
        for alert in &window_alerts {
            let log_text = format!("{} {}", alert.full_log, alert.rule.description).to_lowercase();
            
            // Check telemetry indicators
            let mut ioc_matches = Vec::new();
            for ioc in &technique.expected_telemetry {
                if log_text.contains(&ioc.to_lowercase()) {
                    ioc_matches.push(ioc.clone());
                }
            }
            for ind in &technique.detection_indicators {
                if log_text.contains(&ind.to_lowercase()) {
                    ioc_matches.push(ind.clone());
                }
            }

            // Check rule group classifications
            let mut group_matches = Vec::new();
            for expected_grp in &technique.expected_rule_groups {
                if alert.rule.groups.iter().any(|g| g.eq_ignore_ascii_case(expected_grp)) {
                    group_matches.push(expected_grp.clone());
                }
            }

            if !ioc_matches.is_empty() && !group_matches.is_empty() && alert.rule.level >= 7 {
                // High-confidence correlation even without explicit MITRE tag in rule definition
                evaluated_signals.push(format!("iocs:{:?}", ioc_matches));
                evaluated_signals.push(format!("rule_groups:{:?}", group_matches));
                return VerificationEvidence {
                    verdict: DetectionVerdict::Defended,
                    matched_alert_id: Some(alert.id),
                    matched_rule_id: Some(alert.rule.id),
                    matched_rule_description: Some(alert.rule.description.clone()),
                    matched_alert: Some((*alert).clone()),
                    retry_count,
                    evaluated_signals,
                    reason: format!(
                        "High-Confidence Defended: Rule #{} matched expected IOCs ({:?}) and groups ({:?}).",
                        alert.rule.id, ioc_matches, group_matches
                    ),
                    latency_ms,
                };
            }

            if !ioc_matches.is_empty() || !group_matches.is_empty() {
                evaluated_signals.push(format!("partial_iocs:{:?}", ioc_matches));
                evaluated_signals.push(format!("partial_groups:{:?}", group_matches));
                return VerificationEvidence {
                    verdict: DetectionVerdict::SoftGap,
                    matched_alert_id: Some(alert.id),
                    matched_rule_id: Some(alert.rule.id),
                    matched_rule_description: Some(alert.rule.description.clone()),
                    matched_alert: Some((*alert).clone()),
                    retry_count,
                    evaluated_signals,
                    reason: format!(
                        "Soft Detection Gap: Generic alert fired (Rule #{}: '{}'), but lacked precise MITRE ATT&CK {} mapping.",
                        alert.rule.id, alert.rule.description, technique.id
                    ),
                    latency_ms,
                };
            }
        }

        // 3. Hard Gap: Completely undetected. Store closest candidate alert if any fired on that agent.
        let closest_candidate = window_alerts.first().map(|a| (*a).clone());

        VerificationEvidence {
            verdict: DetectionVerdict::HardGap,
            matched_alert_id: closest_candidate.as_ref().map(|a| a.id),
            matched_rule_id: closest_candidate.as_ref().map(|a| a.rule.id),
            matched_rule_description: closest_candidate.as_ref().map(|a| a.rule.description.clone()),
            matched_alert: closest_candidate,
            retry_count,
            evaluated_signals,
            reason: format!(
                "Hard Detection Gap: Zero alerts fired for technique {} within {}s window (after {} retries). Telemetry completely evaded active rules.",
                technique.id, window_seconds, retry_count
            ),
            latency_ms,
        }
    }
}
