//! Wazuh Mailcom IPC Control Socket and Client (src/os_maild/mailcom.c, os_maild_client.c)
//!
//! Provides the Unix domain IPC control interface for wazuh-maild:
//! - Commands: `getconfig global`, `getconfig alerts`, `getconfig internal`
//! - Dispatches responses formatted as `ok <json_data>` or `err <msg>`

use crate::config::MailConfig;
use serde_json::json;

/// Port of `mailcom.c: mailcom_dispatch`:
/// Handles incoming management command string and produces response.
pub fn mailcom_dispatch(command: &str, config: &MailConfig) -> String {
    let parts: Vec<&str> = command.trim().split_whitespace().collect();
    if parts.is_empty() {
        return "err No command provided".to_string();
    }

    match parts[0] {
        "getconfig" => {
            if parts.len() < 2 {
                return "err MAILCOM getconfig needs arguments".to_string();
            }
            mailcom_getconfig(parts[1], config)
        }
        _ => "err Unrecognized command".to_string(),
    }
}

/// Port of `mailcom.c: mailcom_getconfig`:
/// Returns JSON configuration for the requested section.
pub fn mailcom_getconfig(section: &str, config: &MailConfig) -> String {
    match section {
        "global" => {
            let data = json!({
                "email_to": config.to,
                "email_from": config.from,
                "email_reply_to": config.reply_to,
                "email_idsname": config.idsname,
                "smtp_server": config.smtpserver,
                "helo_server": config.heloserver,
                "email_maxperhour": config.maxperhour,
                "email_log_source": "alerts.json",
            });
            format!("ok {}", data)
        }
        "alerts" => {
            let data = json!({
                "email_notification": if config.enabled { "yes" } else { "no" },
                "email_alert_level": config.min_level,
                "granular_rules": config.gran_to,
            });
            format!("ok {}", data)
        }
        "internal" => {
            let data = json!({
                "mail_timeout": 5,
                "strict_checking": config.strict_checking,
                "grouping": config.grouping,
            });
            format!("ok {}", data)
        }
        _ => "err Could not get requested section".to_string(),
    }
}
