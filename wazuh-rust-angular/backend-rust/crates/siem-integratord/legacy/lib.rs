//! Wazuh External Integrations Daemon (src/os_integrator)
//!
//! Complete port of Wazuh's external integration subsystem:
//! - `config`: `<integration>` XML parsing and validation (`config.c`, `integrator-config.h`).
//! - `executor`: Alert serialization and subprocess execution (`integrator.c`).
//! - `engine`: Alert filter engine and dispatcher (`integrator.c`).
//! - `intgcom`: IPC control interface (`intgcom.c`).

pub mod config;
pub mod engine;
pub mod executor;
pub mod intgcom;

pub use config::{AlertFormat, IntegratorConfig};
pub use engine::IntegratorEngine;
pub use executor::{ExecutorError, IntegrationExecutor, IntegrationInvocation};
pub use intgcom::intgcom_dispatch;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_integration_xml_parsing_and_validation() {
        let xml = r#"
        <ossec_config>
            <integration>
                <name>slack</name>
                <hook_url>https://hooks.slack.com/services/XXX/YYY/ZZZ</hook_url>
                <level>10</level>
                <alert_format>json</alert_format>
            </integration>

            <integration>
                <name>pagerduty</name>
                <api_key>pd-secret-api-key-12345</api_key>
                <level>12</level>
                <rule_id>5710, 5712, 5715</rule_id>
                <group>sshd, pam</group>
                <alert_format>text</alert_format>
            </integration>

            <integration>
                <name>custom-soar</name>
                <hook_url>https://soar.internal/webhook</hook_url>
                <level>7</level>
                <options>{"channel": "soc-alerts"}</options>
            </integration>
        </ossec_config>
        "#;

        let list = IntegratorConfig::parse_xml(xml).unwrap();
        assert_eq!(list.len(), 3);

        // Slack
        let slack = &list[0];
        assert_eq!(slack.name, "slack");
        assert_eq!(
            slack.hookurl,
            Some("https://hooks.slack.com/services/XXX/YYY/ZZZ".to_string())
        );
        assert_eq!(slack.level, 10);
        assert_eq!(slack.alert_format, AlertFormat::Json);
        assert!(slack.validate().is_ok());

        // PagerDuty
        let pd = &list[1];
        assert_eq!(pd.name, "pagerduty");
        assert_eq!(pd.apikey, Some("pd-secret-api-key-12345".to_string()));
        assert_eq!(pd.level, 12);
        assert_eq!(pd.rule_ids, vec![5710, 5712, 5715]);
        assert_eq!(pd.group, Some("sshd, pam".to_string()));
        assert_eq!(pd.alert_format, AlertFormat::Text);
        assert!(pd.validate().is_ok());

        // Custom
        let custom = &list[2];
        assert_eq!(custom.name, "custom-soar");
        assert_eq!(custom.options, Some(r#"{"channel": "soc-alerts"}"#.to_string()));
        assert!(custom.validate().is_ok());

        // Maltiverse (requires both hookurl and apikey)
        let mv_valid = IntegratorConfig {
            name: "maltiverse".to_string(),
            hookurl: Some("https://api.maltiverse.com".to_string()),
            apikey: Some("mv-key".to_string()),
            ..Default::default()
        };
        assert!(mv_valid.validate().is_ok());

        let mv_missing_key = IntegratorConfig {
            name: "maltiverse".to_string(),
            hookurl: Some("https://api.maltiverse.com".to_string()),
            apikey: None,
            ..Default::default()
        };
        assert!(mv_missing_key.validate().is_err());

        // Unsupported integration
        let unsupported = IntegratorConfig {
            name: "unsupported-tool".to_string(),
            ..Default::default()
        };
        assert!(unsupported.validate().is_err());

        // Test invalid validation (Slack without hook_url)
        let invalid_slack = IntegratorConfig {
            name: "slack".to_string(),
            hookurl: None,
            ..Default::default()
        };
        assert!(invalid_slack.validate().is_err());
    }

    #[test]
    fn test_alert_formatting_json_and_text() {
        let alert = json!({
            "timestamp": "2026-09-28T14:00:00Z",
            "location": "/var/log/auth.log",
            "rule": {
                "id": "5710",
                "level": 10,
                "description": "sshd: Multiple failed login attempts"
            },
            "data": {
                "srcip": "192.168.1.50"
            },
            "full_log": "Sep 28 14:00:00 host sshd[123]: Failed password for root; user=root"
        });

        // Test JSON formatting
        let json_str = IntegrationExecutor::format_alert(AlertFormat::Json, &alert, 1024);
        assert!(json_str.contains("\"id\":\"5710\""));
        assert!(json_str.contains("192.168.1.50"));

        // Test Text formatting with sanitization
        let text_str = IntegrationExecutor::format_alert(AlertFormat::Text, &alert, 1024);
        assert!(text_str.contains("alertdate='2026-09-28T14:00:00Z'"));
        assert!(text_str.contains("ruleid='5710'"));
        assert!(text_str.contains("alertlevel='10'"));
        assert!(text_str.contains("srcip='192.168.1.50'"));
        // Semicolons are sanitized to commas
        assert!(!text_str.contains("; user=root"));
        assert!(text_str.contains(", user=root"));
    }

    #[test]
    fn test_integrator_engine_filtering_and_dispatch() {
        let slack = IntegratorConfig {
            name: "slack".to_string(),
            hookurl: Some("https://hooks.slack.com/services/XXX".to_string()),
            apikey: None,
            level: 10,
            rule_ids: Vec::new(),
            group: Some("syslog, pam".to_string()),
            location: None,
            alert_format: AlertFormat::Json,
            options: None,
            timeout: 10,
            retries: 3,
            max_log: 1024,
            path: Some("/var/ossec/integrations/slack".to_string()),
            enabled: true,
        };

        let virustotal = IntegratorConfig {
            name: "virustotal".to_string(),
            hookurl: None,
            apikey: Some("vt-api-key".to_string()),
            level: 7,
            rule_ids: vec![87105],
            group: None,
            location: None,
            alert_format: AlertFormat::Json,
            options: None,
            timeout: 10,
            retries: 3,
            max_log: 1024,
            path: Some("/var/ossec/integrations/virustotal".to_string()),
            enabled: true,
        };

        let mut engine = IntegratorEngine::new(vec![slack, virustotal]);

        // Alert 1: Level 5, rule 1001 -> Matches neither
        let alert_low = json!({
            "rule": { "id": "1001", "level": 5, "description": "Low severity", "groups": ["syslog"] },
            "location": "syslog"
        });
        assert_eq!(engine.process_alert(&alert_low).unwrap(), 0);

        // Alert 2: Level 12, rule 5710, group pam -> Matches Slack only (via comma-separated group)
        let alert_high = json!({
            "rule": { "id": "5710", "level": 12, "description": "SSH Brute Force", "groups": ["pam"] },
            "location": "auth.log"
        });
        assert_eq!(engine.process_alert(&alert_high).unwrap(), 1);
        assert_eq!(engine.mock_invocations.len(), 1);
        assert_eq!(engine.mock_invocations[0].integration_name, "slack");

        // Alert 3: Level 7, rule 87105 -> Matches VirusTotal only
        let alert_vt = json!({
            "rule": { "id": "87105", "level": 7, "description": "Malware file created" },
            "location": "syscheck"
        });
        assert_eq!(engine.process_alert(&alert_vt).unwrap(), 1);
        assert_eq!(engine.mock_invocations.len(), 2);
        assert_eq!(engine.mock_invocations[1].integration_name, "virustotal");
    }

    #[test]
    fn test_intgcom_ipc_queries() {
        let integrations = vec![
            IntegratorConfig {
                name: "slack".to_string(),
                hookurl: Some("https://hooks.slack.com".to_string()),
                level: 10,
                ..Default::default()
            },
        ];

        // getconfig without arg
        let resp_no_arg = intgcom_dispatch("getconfig", &integrations);
        assert_eq!(resp_no_arg, "err INTGCOM getconfig needs arguments");

        // getconfig integration
        let resp = intgcom_dispatch("getconfig integration", &integrations);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"name\":\"slack\""));
        assert!(resp.contains("\"integration\":"));

        // getconfig invalid section
        let resp_inv_sec = intgcom_dispatch("getconfig invalid_sec", &integrations);
        assert_eq!(resp_inv_sec, "err Could not get requested section");

        // unrecognized command
        let invalid = intgcom_dispatch("unknown_cmd", &integrations);
        assert_eq!(invalid, "err Unrecognized command");
    }
}
