//! Active Response command invocation and JSON serialization
//! (parity with src/analysisd/active-response.c, ar_json.c, and alerts/exec.c)

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use siem_core::Alert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArLocation {
    Local,
    Server,
    DefinedAgent(String),
    AllAgents,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveResponseCommand {
    pub name: String,
    pub executable: String,
    pub timeout_allowed: bool,
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveResponseRule {
    pub command: String,
    pub location: ArLocation,
    pub level: Option<u8>,
    pub rules_id: Vec<u32>,
    pub rules_group: Vec<String>,
    pub timeout: Option<u32>, // in seconds
}

/// Builds active response JSON payload according to Wazuh AR protocol Version 1
/// (parity with getActiveResponseInJSON in ar_json.c)
pub fn build_ar_json(
    command_name: &str,
    module_name: &str,
    origin_name: &str,
    extra_args: &[String],
    alert: &Alert,
) -> Value {
    json!({
        "version": 1,
        "origin": {
            "name": origin_name,
            "module": module_name,
        },
        "command": command_name,
        "parameters": {
            "extra_args": extra_args,
            "alert": alert,
        }
    })
}

/// Evaluates if an active response rule should trigger for a given alert
pub fn should_trigger_ar(rule: &ActiveResponseRule, alert: &Alert) -> bool {
    // 1. Check rule ID match
    if !rule.rules_id.is_empty() && rule.rules_id.contains(&alert.rule.id) {
        return true;
    }

    // 2. Check rule level threshold
    if let Some(min_level) = rule.level {
        if alert.rule.level >= min_level {
            return true;
        }
    }

    // 3. Check rule group match
    if !rule.rules_group.is_empty() {
        for g in &rule.rules_group {
            if alert.rule.groups.iter().any(|grp| grp.eq_ignore_ascii_case(g)) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use siem_core::{AgentAlertInfo, DecodedFields, RuleAlertInfo};
    use uuid::Uuid;

    #[test]
    fn test_ar_trigger_and_json_format() {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: RuleAlertInfo {
                id: 5710,
                level: 10,
                description: "SSHD failed login attempts".to_string(),
                groups: vec!["syslog".to_string(), "sshd".to_string()],
                mitre: None,
            },
            agent: AgentAlertInfo {
                id: "001".to_string(),
                name: "ubuntu-server".to_string(),
                ip: "192.168.1.50".to_string(),
            },
            manager: None,
            decoder: None,
            full_log: "Failed password for root from 1.2.3.4".to_string(),
            decoded: DecodedFields {
                src_ip: Some("1.2.3.4".to_string()),
                user: Some("root".to_string()),
                ..Default::default()
            },
            location: "/var/log/auth.log".to_string(),
            data: Default::default(),
        };

        let ar_rule = ActiveResponseRule {
            command: "firewall-drop".to_string(),
            location: ArLocation::Local,
            level: Some(6),
            rules_id: vec![5710],
            rules_group: vec![],
            timeout: Some(600),
        };

        assert!(should_trigger_ar(&ar_rule, &alert));

        let payload = build_ar_json(
            "firewall-drop",
            "wazuh-analysisd",
            "manager01",
            &["-t".to_string(), "600".to_string()],
            &alert,
        );

        assert_eq!(payload["version"], 1);
        assert_eq!(payload["command"], "firewall-drop");
        assert_eq!(payload["origin"]["module"], "wazuh-analysisd");
        assert_eq!(payload["parameters"]["alert"]["rule"]["id"], 5710);
    }
}
