//! Agentlessd IPC Control Dispatcher (`src/agentlessd/lessdcom.c`)
//!
//! Handles `getconfig agentless` management queries returning active configuration JSON.

use crate::config::AgentlessConfig;

/// Dispatches an incoming plain text management command matching `lessdcom_dispatch`.
pub fn lessdcom_dispatch(command: &str, config: &AgentlessConfig) -> String {
    let trimmed = command.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let args = parts.next();

    match cmd {
        "getconfig" => match args {
            Some(section) => lessdcom_getconfig(section.trim(), config),
            None => "err LESSDCOM getconfig needs arguments".to_string(),
        },
        _ => "err Unrecognized command".to_string(),
    }
}

/// Retrieves configuration section matching `lessdcom_getconfig`.
pub fn lessdcom_getconfig(section: &str, config: &AgentlessConfig) -> String {
    if section == "agentless" {
        let json_val = config.get_agentless_config_json();
        format!("ok {}", serde_json::to_string(&json_val).unwrap_or_default())
    } else {
        "err Could not get requested section".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentlessEntry;

    #[test]
    fn test_lessdcom_dispatch() {
        let mut config = AgentlessConfig::default();
        config.entries.push(AgentlessEntry {
            script_type: "ssh_pixconfig_diff".to_string(),
            servers: vec!["cisco-router".to_string()],
            ..Default::default()
        });

        let res = lessdcom_dispatch("getconfig agentless", &config);
        assert!(res.starts_with("ok "));
        assert!(res.contains("ssh_pixconfig_diff"));

        let unk = lessdcom_dispatch("unknown_cmd", &config);
        assert_eq!(unk, "err Unrecognized command");
    }
}
