use crate::models::{
    AttackTechnique, DraftRuleStatus, SynthesizedRuleDraft,
};
use chrono::Utc;
use tracing::info;
use uuid::Uuid;

pub struct RuleSynthesizer;

impl RuleSynthesizer {
    /// Drafts a ProVigil XML rule for an attack the rules missed.
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
        // plain words only; `\.` is a literal dot in the engine's regex and any char in the analysis engine's regex
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
  <!-- Drafted by ProVigil Red Swarm -->
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
            r.matches_log(sample_log)
        });

        // a first check on the attack's raw sample; the analysis engine checks the rule when it is
        // applied, and the next round of the attack shows whether it now catches it
        let logtest_output = if logtest_passed {
            format!(
                "Draft rule #{} matches the attack's sample event (level 8, ATT&CK {}). The analysis engine checks the rule when it is applied; the next round of this attack shows whether it is caught.",
                rule_id_num, technique.id
            )
        } else {
            format!("Warning: draft rule #{} does not match the attack's sample event; an analyst must edit it before it is applied.", rule_id_num)
        };

        let logs = if technique.platforms.iter().any(|p| p.eq_ignore_ascii_case("windows")) {
            "the Windows Security log and Sysmon"
        } else {
            "the system and authentication logs (syslog, auth.log, kernel)"
        };
        let hardening_recommendation = format!(
            "{}: besides rule #{}, make sure the computers send {logs}, where this attack shows up.",
            technique.id, rule_id_num
        );

        info!("Red Swarm drafted rule #{} for the gap {}; it waits for an analyst's approval.", rule_id_num, technique.id);

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
        siem_engine::parse_rules_xml(xml)[0].matches_log(log)
    }

    #[test]
    fn draft_needs_the_attack_not_one_common_word() {
        let t = find_technique("T1059.001").unwrap();
        let d = RuleSynthesizer::synthesize_draft_rule(Uuid::new_v4(), &t, &t.sample_raw_logs[0]);
        assert!(d.logtest_passed, "{}", d.rule_xml);
        assert!(d.rule_xml.contains("<match>-EncodedCommand</match>") && d.rule_xml.contains(r"<regex>powershell\.exe</regex>"), "{}", d.rule_xml);
        assert!(!fires(&d.rule_xml, "Process Create: powershell.exe -File backup.ps1"));

        let t = find_technique("T1003.001").unwrap();
        let d = RuleSynthesizer::synthesize_draft_rule(Uuid::new_v4(), &t, &t.sample_raw_logs[0]);
        assert!(d.logtest_passed);
        assert!(!fires(&d.rule_xml, r"Image: C:\Windows\System32\svchost.exe -k netsvcs"));
    }
}
