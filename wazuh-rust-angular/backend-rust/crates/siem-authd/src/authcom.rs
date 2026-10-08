//! Remote Request & IPC Control Listener (`src/os_auth/authcom.c`)
//!
//! Handles `getconfig auth` IPC commands returning the serialized JSON configuration.

use crate::config::AuthdConfig;

/// Dispatches an incoming plain text management command matching `authcom_dispatch`.
pub fn authcom_dispatch(command: &str, config: &AuthdConfig) -> String {
    let trimmed = command.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let args = parts.next();

    match cmd {
        "getconfig" => match args {
            Some(section) => authcom_getconfig(section.trim(), config),
            None => "err AUTHCOM getconfig needs arguments".to_string(),
        },
        _ => "err Unrecognized command".to_string(),
    }
}

/// Retrieves configuration section matching `authcom_getconfig`.
pub fn authcom_getconfig(section: &str, config: &AuthdConfig) -> String {
    if section == "auth" {
        let json_cfg = config.get_authd_config_json();
        let json_str = serde_json::to_string(&json_cfg).unwrap_or_default();
        format!("ok {}", json_str)
    } else {
        "err Could not get requested section".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authcom_getconfig() {
        let config = AuthdConfig::default();
        let res = authcom_dispatch("getconfig auth", &config);
        assert!(res.starts_with("ok "));
        assert!(res.contains("\"port\":1515"));
    }

    #[test]
    fn test_authcom_missing_args() {
        let config = AuthdConfig::default();
        let res = authcom_dispatch("getconfig", &config);
        assert_eq!(res, "err AUTHCOM getconfig needs arguments");
    }

    #[test]
    fn test_authcom_invalid_command() {
        let config = AuthdConfig::default();
        let res = authcom_dispatch("unknown_cmd foo", &config);
        assert_eq!(res, "err Unrecognized command");
    }
}
