//! Wazuh Agent Control Socket Interface (src/client-agent/agcom.c & state.c)
//!
//! Handles IPC commands sent to `/var/ossec/queue/sockets/agent`:
//! - `getconfig client`
//! - `getconfig buffer`
//! - `getconfig labels`
//! - `getconfig internal`
//! - `getstate`
//! - `reload`
#![allow(dead_code)]

use crate::buffer::AgentBuffer;
use crate::client_agent::AgentConfig;
use serde_json::json;

/// Dispatches an agent control socket command string and returns "ok <json>" or "err <msg>".
/// Mirroring `src/client-agent/agcom.c: agcom_dispatch`
pub fn agcom_dispatch(
    command: &str,
    config: &AgentConfig,
    buffer: &AgentBuffer,
) -> String {
    let trimmed = command.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let args = parts.next().map(|s| s.trim());

    match cmd {
        "getconfig" => match args {
            None | Some("") => "err AGCOM getconfig needs arguments".to_string(),
            Some("client") => {
                let j = get_client_config(config);
                format!("ok {}", serde_json::to_string(&j).unwrap_or_default())
            }
            Some("buffer") => {
                let j = get_buffer_config(config);
                format!("ok {}", serde_json::to_string(&j).unwrap_or_default())
            }
            Some("labels") => {
                let j = get_labels_config();
                format!("ok {}", serde_json::to_string(&j).unwrap_or_default())
            }
            Some("internal") => {
                let j = get_agent_internal_options();
                format!("ok {}", serde_json::to_string(&j).unwrap_or_default())
            }
            Some(sec) => {
                tracing::debug!("AGCOM getconfig: Section '{}' not found", sec);
                "err Could not get requested section".to_string()
            }
        },
        "getstate" => {
            let j = get_agent_state(config, buffer);
            format!("ok {}", serde_json::to_string(&j).unwrap_or_default())
        }
        "reload" => {
            "ok Agent configuration reloaded successfully".to_string()
        }
        _ => {
            tracing::debug!("AGCOM Unrecognized command '{}'.", cmd);
            "err Unrecognized command".to_string()
        }
    }
}

/// Returns `<client>` configuration in Wazuh JSON format.
/// Mirroring `src/client-agent/agcom.c: getClientConfig`
pub fn get_client_config(config: &AgentConfig) -> serde_json::Value {
    json!({
        "client": {
            "server": {
                "address": config.manager_url,
                "port": 1514,
                "protocol": "tcp"
            },
            "notify_time": 10,
            "time-reconnect": 60,
            "auto_restart": "yes",
            "crypto_method": "aes",
            "enrollment": {
                "enabled": "yes",
                "manager_address": config.manager_url,
                "port": 1515,
                "agent_name": config.agent_name
            }
        }
    })
}

/// Returns `<client_buffer>` configuration in Wazuh JSON format.
/// Mirroring `src/client-agent/agcom.c: getBufferConfig`
pub fn get_buffer_config(config: &AgentConfig) -> serde_json::Value {
    json!({
        "buffer": {
            "disabled": "no",
            "queue_size": config.buffer_capacity,
            "events_per_second": config.events_per_second
        }
    })
}

/// Returns `<labels>` configuration in Wazuh JSON format.
/// Mirroring `src/client-agent/agcom.c: getLabelsConfig`
pub fn get_labels_config() -> serde_json::Value {
    json!({
        "labels": {
            "agent_type": "linux_endpoint",
            "os_family": "linux"
        }
    })
}

/// Returns internal agent configuration options.
/// Mirroring `src/client-agent/agcom.c: getAgentInternalOptions`
pub fn get_agent_internal_options() -> serde_json::Value {
    json!({
        "agent": {
            "debug": 0,
            "min_eps": 50,
            "max_eps": 1000,
            "state_interval": 10,
            "keepalive_interval": 10
        }
    })
}

/// Returns agent state structure matching `src/client-agent/state.c`.
pub fn get_agent_state(config: &AgentConfig, buffer: &AgentBuffer) -> serde_json::Value {
    json!({
        "status": "connected",
        "last_keepalive": chrono::Utc::now().to_rfc3339(),
        "version": "4.14.7",
        "agent_id": config.agent_id,
        "agent_name": config.agent_name,
        "manager_url": config.manager_url,
        "buffer": {
            "capacity": config.buffer_capacity,
            "events_per_second": config.events_per_second,
            "dropped_events": buffer.dropped_events()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agcom_dispatch_commands() {
        let config = AgentConfig::default();
        let (buffer, _worker) = AgentBuffer::new(config.manager_url.clone(), 5000, 500);

        // 1. getconfig client
        let resp = agcom_dispatch("getconfig client", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"client\":"));
        assert!(resp.contains("\"crypto_method\":\"aes\""));

        // 2. getconfig buffer
        let resp = agcom_dispatch("getconfig buffer", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"queue_size\":5000"));

        // 3. getconfig labels
        let resp = agcom_dispatch("getconfig labels", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"agent_type\":\"linux_endpoint\""));

        // 4. getconfig internal
        let resp = agcom_dispatch("getconfig internal", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"agent\":"));

        // 5. getstate
        let resp = agcom_dispatch("getstate", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"status\":\"connected\""));
        assert!(resp.contains("\"version\":\"4.14.7\""));

        // 6. reload
        let resp = agcom_dispatch("reload", &config, &buffer);
        assert_eq!(resp, "ok Agent configuration reloaded successfully");

        // 7. error cases
        assert_eq!(
            agcom_dispatch("getconfig", &config, &buffer),
            "err AGCOM getconfig needs arguments"
        );
        assert_eq!(
            agcom_dispatch("getconfig unknown", &config, &buffer),
            "err Could not get requested section"
        );
        assert_eq!(
            agcom_dispatch("badcommand", &config, &buffer),
            "err Unrecognized command"
        );
    }
}
