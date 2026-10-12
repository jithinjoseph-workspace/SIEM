//! Wazuh Logcollector IPC Control Interface (src/logcollector/lccom.c)
//!
//! Handles control socket requests:
//! - `getconfig localfile`
//! - `getconfig socket`
//! - `getconfig internal`
//! - `getstate` / `getstate json`
//! - `reload`

use crate::config::LogCollectorConfig;
use crate::state::FileStateManager;

/// Port of `lccom.c: lccom_dispatch`:
/// Handles incoming management command string and returns response formatted as `ok <json_data>` or `err <msg>`
pub fn lccom_dispatch(
    command: &str,
    config: &LogCollectorConfig,
    state_mgr: &FileStateManager,
) -> String {
    let trimmed = command.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let args = parts.next().map(|s| s.trim());

    match cmd {
        "getconfig" => match args {
            None | Some("") => "err LCCOM getconfig needs arguments".to_string(),
            Some("localfile") => {
                let json = config.get_localfile_config_json();
                format!("ok {}", serde_json::to_string(&json).unwrap_or_default())
            }
            Some("socket") => {
                let json = config.get_socket_config_json();
                format!("ok {}", serde_json::to_string(&json).unwrap_or_default())
            }
            Some("internal") => {
                let json = config.get_internal_options_json();
                format!("ok {}", serde_json::to_string(&json).unwrap_or_default())
            }
            Some(section) => {
                tracing::debug!("At LCCOM getconfig: Could not get '{}' section", section);
                "err Could not get requested section".to_string()
            }
        },
        "getstate" => {
            let json = state_mgr.get_state_json();
            format!("ok {}", serde_json::to_string(&json).unwrap_or_default())
        }
        "reload" => {
            "ok Configuration reloaded successfully".to_string()
        }
        _ => {
            tracing::debug!("LCCOM Unrecognized command '{}'.", cmd);
            "err Unrecognized command".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_lccom_dispatch_commands() {
        let config = LogCollectorConfig::default();
        let tmp = NamedTempFile::new().unwrap();
        let state_mgr = FileStateManager::new(tmp.path());

        // getconfig localfile
        let resp = lccom_dispatch("getconfig localfile", &config, &state_mgr);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"localfile\":"));

        // getconfig socket
        let resp = lccom_dispatch("getconfig socket", &config, &state_mgr);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"socket\":"));

        // getconfig internal
        let resp = lccom_dispatch("getconfig internal", &config, &state_mgr);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"logcollector\":"));

        // getstate
        let resp = lccom_dispatch("getstate", &config, &state_mgr);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"files\":"));

        // reload
        let resp = lccom_dispatch("reload", &config, &state_mgr);
        assert_eq!(resp, "ok Configuration reloaded successfully");

        // errors
        assert_eq!(
            lccom_dispatch("getconfig", &config, &state_mgr),
            "err LCCOM getconfig needs arguments"
        );
        assert_eq!(
            lccom_dispatch("getconfig unknown", &config, &state_mgr),
            "err Could not get requested section"
        );
        assert_eq!(
            lccom_dispatch("unknown_cmd", &config, &state_mgr),
            "err Unrecognized command"
        );
    }
}
