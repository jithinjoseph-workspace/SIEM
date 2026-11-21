use crate::models::DetectionVerdict;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metrics for Purple Team Coverage Heatmap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverage {
    pub tactic: String,
    pub total_techniques: usize,
    pub tested: usize,
    pub defended: usize,
    pub soft_gaps: usize,
    pub hard_gaps: usize,
    /// caught by the rules, but the computer does not send the log
    pub not_collected: usize,
    pub coverage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapTechniqueNode {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    /// windows / linux: some technique ids exist for both
    pub platform: String,
    pub status: String, // "defended", "soft_gap", "hard_gap", "not_collected", "untested"
    pub last_tested_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleHeatmapData {
    pub tactics: Vec<TacticCoverage>,
    pub techniques: Vec<HeatmapTechniqueNode>,
    pub overall_defense_rate: f64,
}

pub struct MetricsCalculator;

impl MetricsCalculator {
    pub fn compute_heatmap(
        all_techniques: &[crate::models::AttackTechnique],
        records: &[crate::models::ExecutionRecord],
    ) -> PurpleHeatmapData {
        let mut tactic_map: HashMap<String, (usize, usize, usize, usize, usize)> = HashMap::new();
        let mut tech_latest_status: HashMap<(String, String), (DetectionVerdict, chrono::DateTime<chrono::Utc>)> = HashMap::new();

        // the newest round of each attack on each system decides
        for record in records {
            let key = (record.technique_id.clone(), record.target_os.to_lowercase());
            let newer = tech_latest_status.get(&key).is_none_or(|(_, ts)| record.timestamp > *ts);
            if newer {
                tech_latest_status.insert(key, (record.verification.verdict.clone(), record.timestamp));
            }
        }

        let mut nodes = Vec::new();

        for tech in all_techniques {
            let platform = tech.platforms.first().map(|p| p.to_lowercase()).unwrap_or_default();
            let (status_str, verdict) = if let Some((v, ts)) = tech_latest_status.get(&(tech.id.clone(), platform.clone())) {
                let s = match v {
                    DetectionVerdict::Defended => "defended",
                    DetectionVerdict::SoftGap => "soft_gap",
                    DetectionVerdict::HardGap => "hard_gap",
                    DetectionVerdict::NotCollected => "not_collected",
                };
                (s, Some((v, ts)))
            } else {
                ("untested", None)
            };

            nodes.push(HeatmapTechniqueNode {
                technique_id: tech.id.clone(),
                technique_name: tech.name.clone(),
                tactic: tech.tactic.clone(),
                platform,
                status: status_str.to_string(),
                last_tested_at: verdict.map(|(_, ts)| ts.to_rfc3339()),
            });

            let entry = tactic_map
                .entry(tech.tactic.clone())
                .or_insert((0, 0, 0, 0, 0));
            entry.0 += 1; // total

            if let Some((v, _)) = verdict {
                match v {
                    DetectionVerdict::Defended => entry.1 += 1,
                    DetectionVerdict::SoftGap => entry.2 += 1,
                    DetectionVerdict::HardGap => entry.3 += 1,
                    DetectionVerdict::NotCollected => entry.4 += 1,
                }
            }
        }

        let mut tactics = Vec::new();
        let mut total_tested = 0;
        let mut total_defended = 0;

        for (tactic, (tot, def, soft, hard, blind)) in tactic_map {
            let tested = def + soft + hard + blind;
            total_tested += tested;
            total_defended += def;
            let coverage_percent = if tested > 0 {
                (def as f64 / tested as f64) * 100.0
            } else {
                0.0
            };

            tactics.push(TacticCoverage {
                tactic,
                total_techniques: tot,
                tested,
                defended: def,
                soft_gaps: soft,
                hard_gaps: hard,
                not_collected: blind,
                coverage_percent: (coverage_percent * 10.0).round() / 10.0,
            });
        }

        tactics.sort_by(|a, b| a.tactic.cmp(&b.tactic));

        let overall_defense_rate = if total_tested > 0 {
            ((total_defended as f64 / total_tested as f64) * 100.0 * 10.0).round() / 10.0
        } else {
            100.0
        };

        PurpleHeatmapData {
            tactics,
            techniques: nodes,
            overall_defense_rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::get_curated_catalog;
    use crate::models::*;

    fn round(id: &str, os: &str, verdict: DetectionVerdict, mins_ago: i64) -> ExecutionRecord {
        ExecutionRecord {
            id: uuid::Uuid::new_v4(),
            campaign_id: String::new(),
            tenant_id: String::new(),
            timestamp: chrono::Utc::now() - chrono::Duration::minutes(mins_ago),
            technique_id: id.into(),
            technique_name: String::new(),
            tactic: String::new(),
            mode: SwarmExecutionMode::SafeTelemetryOnly,
            target_agent_id: String::new(),
            target_agent_name: String::new(),
            target_agent_ip: String::new(),
            target_os: os.into(),
            execution_success: true,
            execution_output: String::new(),
            cleanup_status: CleanupStatus::NotApplicable,
            cleanup_output: None,
            verification: VerificationEvidence {
                verdict,
                matched_alert_id: None,
                matched_rule_id: None,
                matched_rule_description: None,
                matched_alert: None,
                retry_count: 0,
                evaluated_signals: vec![],
                reason: String::new(),
                latency_ms: 0,
            },
            draft_rule: None,
        }
    }

    #[test]
    fn the_newest_round_decides_and_systems_stay_apart() {
        let status = |records: &[ExecutionRecord], id: &str, os: &str| {
            let h = MetricsCalculator::compute_heatmap(&get_curated_catalog(), records);
            h.techniques.iter().find(|n| n.technique_id == id && n.platform == os).unwrap().status.clone()
        };
        // newest first, as the history gives them: the gap was fixed, the heatmap says so
        let fixed = [round("T1110", "windows", DetectionVerdict::Defended, 1), round("T1110", "windows", DetectionVerdict::HardGap, 30)];
        assert_eq!(status(&fixed, "T1110", "windows"), "defended");
        // same in the other order
        let fixed = [fixed[1].clone(), fixed[0].clone()];
        assert_eq!(status(&fixed, "T1110", "windows"), "defended");
        // the Windows and Linux "new account" attacks share an id, not a result
        let both = [round("T1136.001", "windows", DetectionVerdict::Defended, 1), round("T1136.001", "linux", DetectionVerdict::NotCollected, 2)];
        assert_eq!(status(&both, "T1136.001", "windows"), "defended");
        assert_eq!(status(&both, "T1136.001", "linux"), "not_collected");
    }
}
