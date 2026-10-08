pub mod agent_conf_validator;
pub mod agent_control_ops;
pub mod regex_evaluator;
pub mod report_generator;
pub mod stats_manager;

pub use agent_conf_validator::{AgentConfValidator, ConfigValidationError};
pub use agent_control_ops::{AgentControlOps, AgentFilter, OutputFormat};
pub use regex_evaluator::{RegexEvaluator, RegexMatchResult};
pub use report_generator::{AlertItem, ReportFilter, ReportGenerator};
pub use stats_manager::StatsManager;

#[cfg(test)]
mod tests {
    use super::*;
    use siem_wdb::{ConnectionStatus, GlobalDb};

    #[test]
    fn test_report_generator_filtering_and_relations() {
        let alert1 = AlertItem {
            rule_id: "5710".to_string(),
            level: 10,
            description: "sshd failed login".to_string(),
            groups: vec!["authentication_failed".to_string(), "sshd".to_string()],
            location: "/var/log/auth.log".to_string(),
            srcip: Some("192.168.1.100".to_string()),
            dstip: None,
            user: Some("admin".to_string()),
            filename: None,
            timestamp: "2026-09-28T10:00:00Z".to_string(),
        };

        let alert2 = AlertItem {
            rule_id: "5715".to_string(),
            level: 3,
            description: "sshd login success".to_string(),
            groups: vec!["authentication_success".to_string(), "sshd".to_string()],
            location: "/var/log/auth.log".to_string(),
            srcip: Some("192.168.1.100".to_string()),
            dstip: None,
            user: Some("admin".to_string()),
            filename: None,
            timestamp: "2026-09-28T10:05:00Z".to_string(),
        };

        let alert3 = AlertItem {
            rule_id: "5710".to_string(),
            level: 10,
            description: "sshd failed login".to_string(),
            groups: vec!["authentication_failed".to_string(), "sshd".to_string()],
            location: "/var/log/auth.log".to_string(),
            srcip: Some("10.0.0.50".to_string()),
            dstip: None,
            user: Some("root".to_string()),
            filename: None,
            timestamp: "2026-09-28T10:10:00Z".to_string(),
        };

        // 1. Filter by level >= 10
        let mut gen1 = ReportGenerator::new(ReportFilter {
            min_level: Some(10),
            top_field: Some("rule".to_string()),
            ..Default::default()
        });
        gen1.process_alert(alert1.clone());
        gen1.process_alert(alert2.clone());
        gen1.process_alert(alert3.clone());

        let report1 = gen1.generate_report();
        assert!(report1.contains("Total alerts processed: 2")); // alert2 skipped
        assert!(report1.contains("5710"));

        // 2. Relation: user -> srcip
        let mut gen2 = ReportGenerator::new(ReportFilter {
            related: Some(("user".to_string(), "srcip".to_string())),
            ..Default::default()
        });
        gen2.process_alert(alert1);
        gen2.process_alert(alert2);
        gen2.process_alert(alert3);

        let report2 = gen2.generate_report();
        assert!(report2.contains("Related entries for 'user' -> 'srcip'"));
        assert!(report2.contains("[admin]"));
        assert!(report2.contains("[root]"));
        assert!(report2.contains("192.168.1.100"));
        assert!(report2.contains("10.0.0.50"));
    }

    #[test]
    fn test_agent_control_listing_and_filtering() {
        let global = GlobalDb::new();
        global.insert_agent(1, "linux-srv-1", Some("10.0.0.1"), None, None, None).unwrap();
        global.insert_agent(2, "win-workstation-1", Some("10.0.0.2"), None, None, None).unwrap();
        global.update_agent_keepalive(1, ConnectionStatus::Active);

        // List all
        let all_text = AgentControlOps::list_agents(&global, AgentFilter::All, OutputFormat::Text);
        assert!(all_text.contains("linux-srv-1"));
        assert!(all_text.contains("win-workstation-1"));

        // List active only
        let active_text = AgentControlOps::list_agents(&global, AgentFilter::ActiveOnly, OutputFormat::Text);
        assert!(active_text.contains("linux-srv-1"));
        assert!(!active_text.contains("win-workstation-1"));

        // List disconnected only
        let disc_text = AgentControlOps::list_agents(&global, AgentFilter::DisconnectedOnly, OutputFormat::Text);
        assert!(!disc_text.contains("linux-srv-1"));
        assert!(disc_text.contains("win-workstation-1"));

        // JSON format
        let json_out = AgentControlOps::list_agents(&global, AgentFilter::All, OutputFormat::Json);
        assert!(json_out.contains("\"id\":1"));
        assert!(json_out.contains("\"name\":\"linux-srv-1\""));

        // CSV format
        let csv_out = AgentControlOps::list_agents(&global, AgentFilter::All, OutputFormat::Csv);
        assert!(csv_out.starts_with("id,name,ip,status\n"));
    }

    #[test]
    fn test_agent_control_info_and_commands() {
        let global = GlobalDb::new();
        global.insert_agent(1, "srv-01", Some("192.168.1.10"), None, None, Some("prod")).unwrap();
        global.update_agent_keepalive(1, ConnectionStatus::Active);

        let info = AgentControlOps::get_agent_info(&global, 1, OutputFormat::Text).unwrap();
        assert!(info.contains("Agent ID:   001"));
        assert!(info.contains("Agent Name: srv-01"));
        assert!(info.contains("Configuration/Group: prod"));

        // Commands
        let restart_one = AgentControlOps::build_restart_command(Some(1));
        assert_eq!(restart_one, "001 restart-ossec");

        let restart_all = AgentControlOps::build_restart_command(None);
        assert_eq!(restart_all, "ALL restart-ossec");

        let syscheck_cmd = AgentControlOps::build_syscheck_command(Some(1));
        assert_eq!(syscheck_cmd, "001 syscheck check_now");

        let ar_cmd = AgentControlOps::build_active_response_command(Some(1), "firewall-drop", Some("1.2.3.4"));
        assert_eq!(ar_cmd, "001 active-response firewall-drop 1.2.3.4");
    }

    #[test]
    fn test_agent_conf_validation() {
        let valid_xml = r#"
        <agent_config os="Linux">
            <syscheck>
                <directories check_all="yes">/etc,/usr/bin</directories>
                <frequency>7200</frequency>
            </syscheck>
            <rootcheck>
                <frequency>14400</frequency>
            </rootcheck>
        </agent_config>
        "#;
        assert!(AgentConfValidator::validate_str(valid_xml).is_ok());

        let invalid_mismatched = r#"
        <agent_config os="Linux">
            <syscheck>
                <directories check_all="yes">/etc</directories>
            </rootcheck>
        </agent_config>
        "#;
        assert!(AgentConfValidator::validate_str(invalid_mismatched).is_err());
    }

    #[test]
    fn test_regex_evaluator() {
        let pattern = r"^sshd\[\d+\]: Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)";
        let log = "sshd[12345]: Failed password for root from 192.168.1.200 port 22";

        let res = RegexEvaluator::evaluate(pattern, log).unwrap();
        assert!(res.matched);
        assert_eq!(res.captures.len(), 2);
        assert_eq!(res.captures[0], "root");
        assert_eq!(res.captures[1], "192.168.1.200");

        let no_match = "systemd: Started Daily apt download activities.";
        let res2 = RegexEvaluator::evaluate(pattern, no_match).unwrap();
        assert!(!res2.matched);

        // Test OSRegex evaluation
        let os_res = RegexEvaluator::evaluate_os_regex(pattern, log).unwrap();
        assert!(os_res.matched);
        assert_eq!(os_res.captures, vec!["root", "192.168.1.200"]);

        // Test OSMatch evaluation
        assert!(RegexEvaluator::evaluate_os_match("^sshd|nginx", log).unwrap());
        assert!(!RegexEvaluator::evaluate_os_match("^apache", log).unwrap());
    }
}
