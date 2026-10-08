//! Monitord IPC Management Dispatcher (`src/monitord/moncom.c`)
//!
//! Handles `getconfig` queries over unix sockets / pipes returning JSON options.

use crate::config::MonitorConfig;

/// Dispatches an incoming plain text management command matching `moncom_dispatch`.
pub fn moncom_dispatch(command: &str, config: &MonitorConfig) -> String {
    let trimmed = command.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let args = parts.next();

    match cmd {
        "getconfig" => match args {
            Some(section) => moncom_getconfig(section.trim(), config),
            None => "err MONCOM getconfig needs arguments".to_string(),
        },
        _ => "err Unrecognized command".to_string(),
    }
}

/// Retrieves configuration section matching `moncom_getconfig`.
pub fn moncom_getconfig(section: &str, config: &MonitorConfig) -> String {
    match section {
        "internal" => {
            let json_val = config.get_monitor_internal_options();
            format!("ok {}", serde_json::to_string(&json_val).unwrap_or_default())
        }
        "global" => {
            let json_val = config.get_monitor_global_options();
            format!("ok {}", serde_json::to_string(&json_val).unwrap_or_default())
        }
        "reports" => {
            let json_val = config.get_reports_options();
            format!("ok {}", serde_json::to_string(&json_val).unwrap_or_default())
        }
        _ => "err Could not get requested section".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_moncom_commands() {
        let config = MonitorConfig::default();

        let int_res = moncom_dispatch("getconfig internal", &config);
        assert!(int_res.starts_with("ok "));
        assert!(int_res.contains("\"rotate_log\":1"));

        let glob_res = moncom_dispatch("getconfig global", &config);
        assert!(glob_res.starts_with("ok "));
        assert!(glob_res.contains("\"agents_disconnection_time\":900"));

        let rep_res = moncom_dispatch("getconfig reports", &config);
        assert!(rep_res.starts_with("ok "));

        let unk_res = moncom_dispatch("unknown_cmd", &config);
        assert_eq!(unk_res, "err Unrecognized command");
    }
}
