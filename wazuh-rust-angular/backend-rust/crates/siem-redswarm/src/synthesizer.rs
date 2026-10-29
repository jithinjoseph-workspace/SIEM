use crate::models::{
    AttackTechnique, DraftRuleStatus, SynthesizedRuleDraft,
};
use chrono::Utc;
use tracing::info;
use uuid::Uuid;

pub struct RuleSynthesizer;

impl RuleSynthesizer {
    /// Generates a high-quality draft Wazuh XML rule for an evaded attack technique.
    /// Runs validation through logtest logic and stores as "Pending Approval".
    /// NEVER writes directly to production ruleset without explicit approval.
    pub fn synthesize_draft_rule(
        execution_id: Uuid,
        technique: &AttackTechnique,
        sample_log: &str,
    ) -> SynthesizedRuleDraft {
        let draft_rule_id = Uuid::new_v4();
        let rule_id_num = 100_000 + (draft_rule_id.as_u128() % 899_999) as u32;

        // Narrowest criteria: the longest indicator found in the sample log as <match>, and a
        // second one as <regex> (a rule needs both), so the rule does not fire on any benign log
        let mut present: Vec<&str> = technique
            .expected_telemetry
            .iter()
            .chain(&technique.detection_indicators)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && sample_log.contains(*s))
            .collect();
        present.sort();
        present.dedup();
        present.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let match_target = present
            .first()
            .copied()
            .or_else(|| technique.expected_telemetry.first().map(|s| s.as_str()))
            .unwrap_or(sample_log);
        // plain words only; `\.` is a literal dot in the engine's regex and any char in Wazuh's OS_Regex
        let regex_line = present
            .iter()
            .skip(1)
            .find(|s| !match_target.contains(**s) && s.chars().all(|c| c.is_ascii_alphanumeric() || " _-.".contains(c)))
            .map(|s| format!("\n    <regex>{}</regex>", s.replace('.', r"\.")))
            .unwrap_or_default();

        let sanitized_match = match_target
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");

        let rule_xml = format!(
            r#"<group name="redswarm_purple_team,mitre_{}">
  <!-- Auto-synthesized by ProVigil Red Swarm Perpetual Purple Engine -->
  <!-- Target Evasion: {} ({}) -->
  <rule id="{}" level="8">
    <match>{}</match>{}
    <description>ProVigil Detection Gap: {} [{}]</description>
    <mitre>
      <id>{}</id>
    </mitre>
    <group>attack,purple_team,evasion_closed</group>
  </rule>
</group>"#,
            technique.id.to_lowercase().replace('.', "_"),
            technique.name,
            technique.id,
            rule_id_num,
            sanitized_match,
            regex_line,
            technique.name,
            technique.id,
            technique.id,
        );

        // Logtest: run the drafted rule itself on the sample log
        let logtest_passed = siem_engine::parse_rules_xml(&rule_xml).first().is_some_and(|r| {
            r.matches(sample_log, "", None, &[], &[], &std::collections::HashMap::new(), None, "", None, None)
        });

        let logtest_output = if logtest_passed {
            format!(
                "Synthesized Rule #{} matched the sample log.\n    Level: 8\n    MITRE: {}\n    wazuh-analysisd checks the rule again when it is deployed.",
                rule_id_num, technique.id
            )
        } else {
            format!("Validation Warning: Rule #{} did not match the sample log; analyst review required.", rule_id_num)
        };

        let hardening_recommendation = format!(
            "Hardening Recommendation for {}: In addition to deploying Rule #{}, ensure endpoint logging is configured to forward {} telemetry (Sysmon / Auditd / PowerShell Script Block Logging EventID 4104).",
            technique.id, rule_id_num, technique.tactic
        );

        info!(
            "Draft Wazuh rule #{} synthesized for gap {}. Staged in PendingApproval state.",
            rule_id_num, technique.id
        );

        SynthesizedRuleDraft {
            id: draft_rule_id,
            execution_id,
            technique_id: technique.id.clone(),
            technique_name: technique.name.clone(),
            rule_xml,
            logtest_passed,
            logtest_output,
            hardening_recommendation,
            created_at: Utc::now(),
            status: DraftRuleStatus::PendingApproval,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::find_technique;

    fn fires(xml: &str, log: &str) -> bool {
        siem_engine::parse_rules_xml(xml)[0].matches(log, "", None, &[], &[], &Default::default(), None, "", None, None)
    }

    #[test]
    fn draft_needs_the_attack_not_one_common_word() {
        let t = find_technique("T1059.001").unwrap();
        let d = RuleSynthesizer::synthesize_draft_rule(Uuid::new_v4(), &t, &t.sample_raw_logs[0]);
        assert!(d.logtest_passed, "{}", d.rule_xml);
        assert!(d.rule_xml.contains("<match>-EncodedCommand</match>") && d.rule_xml.contains(r"<regex>powershell\.exe</regex>"), "{}", d.rule_xml);
        assert!(!fires(&d.rule_xml, "Process Create: powershell.exe -File backup.ps1"));

        let t = find_technique("T1036.005").unwrap();
        let d = RuleSynthesizer::synthesize_draft_rule(Uuid::new_v4(), &t, &t.sample_raw_logs[0]);
        assert!(d.logtest_passed);
        assert!(!fires(&d.rule_xml, r"Image: C:\Windows\System32\svchost.exe -k netsvcs"));
    }
}
