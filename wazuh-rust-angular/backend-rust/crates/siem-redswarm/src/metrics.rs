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
    pub coverage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapTechniqueNode {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub status: String, // "defended", "soft_gap", "hard_gap", "untested"
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
        let mut tactic_map: HashMap<String, (usize, usize, usize, usize)> = HashMap::new();
        let mut tech_latest_status: HashMap<String, (DetectionVerdict, String)> = HashMap::new();

        for record in records {
            tech_latest_status.insert(
                record.technique_id.clone(),
                (
                    record.verification.verdict.clone(),
                    record.timestamp.to_rfc3339(),
                ),
            );
        }

        let mut nodes = Vec::new();

        for tech in all_techniques {
            let (status_str, verdict) = if let Some((v, ts)) = tech_latest_status.get(&tech.id) {
                let s = match v {
                    DetectionVerdict::Defended => "defended",
                    DetectionVerdict::SoftGap => "soft_gap",
                    DetectionVerdict::HardGap => "hard_gap",
                };
                (s, Some((v, ts)))
            } else {
                ("untested", None)
            };

            nodes.push(HeatmapTechniqueNode {
                technique_id: tech.id.clone(),
                technique_name: tech.name.clone(),
                tactic: tech.tactic.clone(),
                status: status_str.to_string(),
                last_tested_at: verdict.map(|(_, ts)| ts.clone()),
            });

            let entry = tactic_map
                .entry(tech.tactic.clone())
                .or_insert((0, 0, 0, 0));
            entry.0 += 1; // total

            if let Some((v, _)) = verdict {
                match v {
                    DetectionVerdict::Defended => entry.1 += 1,
                    DetectionVerdict::SoftGap => entry.2 += 1,
                    DetectionVerdict::HardGap => entry.3 += 1,
                }
            }
        }

        let mut tactics = Vec::new();
        let mut total_tested = 0;
        let mut total_defended = 0;

        for (tactic, (tot, def, soft, hard)) in tactic_map {
            let tested = def + soft + hard;
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
