//! Wazuh Integrator IPC Control Interface (src/os_integrator/intgcom.c)
//!
//! Provides the Unix domain IPC control dispatcher for wazuh-integratord:
//! - Commands: `getconfig`
//! - Dispatches responses formatted as `ok <json_data>` or `err <msg>`

use crate::config::{get_integrator_config_json, IntegratorConfig};

/// Port of `intgcom.c: intgcom_dispatch`:
/// Handles incoming management command string and produces response.
pub fn intgcom_dispatch(command: &str, integrations: &[IntegratorConfig]) -> String {
    let trimmed = command.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let args = parts.next().map(|s| s.trim());

    if cmd == "getconfig" {
        match args {
            None | Some("") => "err INTGCOM getconfig needs arguments".to_string(),
            Some("integration") => {
                let json = get_integrator_config_json(integrations);
                format!("ok {}", serde_json::to_string(&json).unwrap_or_default())
            }
            Some(section) => {
                tracing::debug!("At INTGCOM getconfig: Could not get '{}' section", section);
                "err Could not get requested section".to_string()
            }
        }
    } else {
        tracing::debug!("INTGCOM Unrecognized command '{}'.", cmd);
        "err Unrecognized command".to_string()
    }
}
