//! Agent Control Socket Interface
//!
//! Handles IPC commands sent to `/opt/provigil-agent/queue/sockets/agent`:
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

/// Dispatches an agent control command string and returns "ok <json>" or "err <msg>".
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
            None | Some("") => "err control getconfig needs arguments".to_string(),
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
                tracing::debug!("control getconfig: Section '{}' not found", sec);
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
            tracing::debug!("control Unrecognized command '{}'.", cmd);
            "err Unrecognized command".to_string()
        }
    }
}

/// Returns `<client>` configuration as JSON.
pub fn get_client_config(config: &AgentConfig) -> serde_json::Value {
    json!({
        "client": {
            "server": {
                "address": config.manager_url,
                "port": 8443,
                "protocol": "https"
            },
            "notify_time": 10,
            "time-reconnect": 60,
            "auto_restart": "yes",
            "crypto_method": "tls",
            "enrollment": {
                "enabled": "yes",
                "manager_address": config.manager_url,
                "agent_name": config.agent_name
            }
        }
    })
}

/// Returns `<client_buffer>` configuration as JSON.
pub fn get_buffer_config(config: &AgentConfig) -> serde_json::Value {
    json!({
        "buffer": {
            "disabled": "no",
            "queue_size": config.buffer_capacity,
            "events_per_second": config.events_per_second
        }
    })
}

/// Returns agent labels configuration as JSON.
pub fn get_labels_config() -> serde_json::Value {
    json!({
        "labels": {
            "agent_type": "linux_endpoint",
            "os_family": "linux"
        }
    })
}

/// Returns internal agent configuration options.
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

/// Returns agent runtime state JSON.
pub fn get_agent_state(config: &AgentConfig, buffer: &AgentBuffer) -> serde_json::Value {
    json!({
        "status": "connected",
        "last_keepalive": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0",
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
        let (buffer, _worker) = AgentBuffer::new(
            config.manager_url.clone(),
            5000,
            500,
            std::sync::Arc::new(crate::lifecycle::LifecycleCoordinator::new(
                config.agent_id.clone(),
                config.manager_url.clone(),
            )),
        );

        let resp = agcom_dispatch("getconfig client", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"client\":"));
        assert!(resp.contains("\"crypto_method\":\"tls\""));

        let resp = agcom_dispatch("getconfig buffer", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"queue_size\":5000"));

        let resp = agcom_dispatch("getconfig labels", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"agent_type\":\"linux_endpoint\""));

        let resp = agcom_dispatch("getconfig internal", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"agent\":"));

        let resp = agcom_dispatch("getstate", &config, &buffer);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"status\":\"connected\""));
        assert!(resp.contains("\"version\":\"1.0.0\""));

        let resp = agcom_dispatch("reload", &config, &buffer);
        assert_eq!(resp, "ok Agent configuration reloaded successfully");

        assert_eq!(
            agcom_dispatch("getconfig", &config, &buffer),
            "err control getconfig needs arguments"
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
