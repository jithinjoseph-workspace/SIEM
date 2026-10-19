//! Wazuh Email Notification Daemon (src/os_maild)
//!
//! Provides the complete port of Wazuh's alert email subsystem:
//! - `config`: `<email_alerts>` and `<global>` configuration parsing (`config.c`).
//! - `mail_list`: Alert buffering and aggregation queue (`mail_list.c`, `mail_list.h`).
//! - `mailer`: RFC 2822 formatting and RFC 5321 SMTP dialog (`sendmail.c`, `sendcustomemail.c`).
//! - `maild`: Daemon runtime, rate limiter, severity filter, granular router (`maild.c`).
//! - `mailcom`: IPC control socket and inspection dispatcher (`mailcom.c`).

pub mod config;
pub mod mail_list;
pub mod mailcom;
pub mod maild;
pub mod mailer;

pub use config::{EmailFormat, GranularEmailRule, MailConfig, MailSource};
pub use mail_list::{MailMsg, MailQueue, DEFAULT_MAIL_LIST_SIZE};
pub use mailcom::{mailcom_dispatch, mailcom_getconfig};
pub use maild::{HourlyRateTracker, MailDaemon};
pub use mailer::{AlertMailFormatter, MailerError, SmtpTransport};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mail_config_xml_parsing() {
        let xml = r#"
        <ossec_config>
            <global>
                <email_notification>yes</email_notification>
                <email_to>security@example.com</email_to>
                <email_from>wazuh-alerts@example.com</email_from>
                <smtp_server>smtp.example.com</smtp_server>
                <email_maxperhour>24</email_maxperhour>
                <email_idsname>SecOps-SIEM</email_idsname>
            </global>

            <alerts>
                <email_alert_level>10</email_alert_level>
            </alerts>

            <email_alerts>
                <email_to>critical-incidents@example.com</email_to>
                <rule_id>5710</rule_id>
                <rule_id>5712</rule_id>
                <level>12</level>
                <format>do_not_delay</format>
            </email_alerts>
        </ossec_config>
        "#;

        let cfg = MailConfig::parse_xml(xml).unwrap();
        assert_eq!(cfg.smtpserver, "smtp.example.com");
        assert_eq!(cfg.from, "wazuh-alerts@example.com");
        assert_eq!(cfg.to, vec!["security@example.com"]);
        assert_eq!(cfg.maxperhour, 24);
        assert_eq!(cfg.idsname, "SecOps-SIEM");
        assert_eq!(cfg.min_level, 10);

        assert_eq!(cfg.gran_to.len(), 1);
        let gran = &cfg.gran_to[0];
        assert_eq!(gran.to, "critical-incidents@example.com");
        assert_eq!(gran.level, Some(12));
        assert_eq!(gran.rule_ids, vec![5710, 5712]);
        assert_eq!(gran.format, EmailFormat::DoNotDelay);
    }

    #[test]
    fn test_mail_queue_buffering() {
        let mut q = MailQueue::new(3);
        assert!(q.is_empty());

        let msg1 = MailMsg::new("Subj 1", "Body 1", vec!["admin@test.com".to_string()]);
        let msg2 = MailMsg::new("Subj 2", "Body 2", vec!["admin@test.com".to_string()]);
        let msg3 = MailMsg::new("Subj 3", "Body 3", vec!["admin@test.com".to_string()]);
        let msg4 = MailMsg::new("Subj 4", "Body 4", vec!["admin@test.com".to_string()]);

        q.push(msg1);
        q.push(msg2);
        q.push(msg3);
        assert!(q.is_full());
        assert_eq!(q.len(), 3);

        // Pushing 4th drops oldest (msg1)
        q.push(msg4);
        assert_eq!(q.len(), 3);

        let popped = q.pop().unwrap();
        assert_eq!(popped.subject, "Subj 2");
    }

    #[test]
    fn test_hourly_rate_limiting() {
        let mut tracker = HourlyRateTracker::new(2);
        assert!(tracker.allow_email()); // 1
        assert!(tracker.allow_email()); // 2
        assert!(!tracker.allow_email()); // 3 - dropped
        assert!(!tracker.allow_email()); // 4 - dropped

        assert_eq!(tracker.current_hour_count(), 2);
        assert_eq!(tracker.dropped_count(), 2);
    }

    #[test]
    fn test_maild_alert_processing_and_routing() {
        let mut config = MailConfig::default();
        config.to = vec!["general-admin@example.com".to_string()];
        config.min_level = 8;
        config.gran_to.push(GranularEmailRule {
            to: "soc-tier2@example.com".to_string(),
            level: Some(12),
            rule_ids: vec![5710],
            groups: vec!["sshd".to_string()],
            locations: Vec::new(),
            format: EmailFormat::DoNotDelay,
        });

        let mut daemon = MailDaemon::new(config);

        // Alert 1: Level 5 -> Skipped (below min_level 8)
        let alert_low = json!({
            "rule": { "id": "1001", "level": 5, "description": "Low severity event" },
            "agent": { "name": "srv-1", "id": "001" },
            "location": "/var/log/syslog"
        });
        assert!(!daemon.process_alert_json(&alert_low).unwrap());

        // Alert 2: Level 10 -> Matches default recipients
        let alert_med = json!({
            "rule": { "id": "1002", "level": 10, "description": "High severity event" },
            "agent": { "name": "srv-1", "id": "001" },
            "location": "/var/log/syslog"
        });
        assert!(daemon.process_alert_json(&alert_med).unwrap());
        assert_eq!(daemon.queue.len(), 1);

        // Alert 3: Level 14, rule 5710, group sshd -> Matches granular rule (DoNotDelay = instant send)
        let alert_crit = json!({
            "rule": { "id": "5710", "level": 14, "description": "SSH Brute Force", "groups": ["sshd"] },
            "agent": { "name": "srv-prod", "id": "005" },
            "location": "/var/log/auth.log",
            "full_log": "Failed password for root from 192.168.1.100 port 22"
        });
        assert!(daemon.process_alert_json(&alert_crit).unwrap());
        assert_eq!(daemon.mock_sent_messages.len(), 1);
        assert!(daemon.mock_sent_messages[0].contains("To: soc-tier2@example.com"));
        assert!(daemon.mock_sent_messages[0].contains("SSH Brute Force"));

        // Flush remaining queued alerts
        let batches = daemon.flush_queue().unwrap();
        assert_eq!(batches, 1);
        assert_eq!(daemon.mock_sent_messages.len(), 2);
        assert!(daemon.mock_sent_messages[1].contains("To: general-admin@example.com"));
    }

    #[test]
    fn test_mailcom_ipc_queries() {
        let config = MailConfig {
            smtpserver: "mail.local".to_string(),
            from: "siem@local".to_string(),
            to: vec!["ops@local".to_string()],
            min_level: 9,
            ..Default::default()
        };

        // Query global
        let resp_global = mailcom_dispatch("getconfig global", &config);
        assert!(resp_global.starts_with("ok "));
        assert!(resp_global.contains("mail.local"));

        // Query alerts
        let resp_alerts = mailcom_dispatch("getconfig alerts", &config);
        assert!(resp_alerts.starts_with("ok "));
        assert!(resp_alerts.contains("\"email_alert_level\":9"));

        // Query invalid section
        let resp_err = mailcom_dispatch("getconfig non_existent", &config);
        assert!(resp_err.starts_with("err "));
    }
}
