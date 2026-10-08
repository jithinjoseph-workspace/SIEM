//! Local Authd Server & IPC Dispatcher (`src/os_auth/local-server.c`)
//!
//! Handles local JSON commands sent via `AUTH_LOCAL_SOCK` (or Windows named pipe)
//! supporting `add`, `remove`, and `get` operations with Wazuh standard error codes.

use crate::authcom::authcom_dispatch;
use crate::config::{AuthdConfig, ForceOptions};
use crate::enrollment::{can_replace_agent, is_valid_name, AgentDbInfo};
use crate::groups::validate_groups;
use serde_json::{json, Value};
use siem_crypto::keys::{ClientKey, KeyStore};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Wazuh standard local error codes matching `ERRORS[]` in `local-server.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalErrorCode {
    Internal = 9001,
    JsonParse = 9002,
    NoSuchFunction = 9003,
    NoSuchArgument = 9004,
    NoSuchName = 9005,
    NoSuchIp = 9006,
    DuplicateIp = 9007,
    DuplicateName = 9008,
    KeyGeneration = 9009,
    NoSuchAgentId = 9010,
    AgentIdNotFound = 9011,
    DuplicateId = 9012,
    MaxAgentsReached = 9013,
    InvalidGroupName = 9014,
    WorkerNodeRejected = 9015,
}

impl LocalErrorCode {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Internal => "Internal error",
            Self::JsonParse => "Parsing JSON input",
            Self::NoSuchFunction => "No such function",
            Self::NoSuchArgument => "No such argument",
            Self::NoSuchName => "No such name",
            Self::NoSuchIp => "No such IP",
            Self::DuplicateIp => "Duplicate IP",
            Self::DuplicateName => "Duplicate name",
            Self::KeyGeneration => "Issue generating key",
            Self::NoSuchAgentId => "No such agent ID",
            Self::AgentIdNotFound => "Agent ID not found",
            Self::DuplicateId => "Duplicate ID",
            Self::MaxAgentsReached => "Maximum number of agents reached",
            Self::InvalidGroupName => "Invalid Group(s) Name(s)",
            Self::WorkerNodeRejected => "Cannot execute this request on a worker node",
        }
    }
}

pub fn error_response(code: LocalErrorCode) -> Value {
    json!({
        "error": code as i32,
        "message": code.message()
    })
}

pub fn success_agent_response(key: &ClientKey) -> Value {
    json!({
        "error": 0,
        "data": {
            "id": key.id,
            "name": key.name,
            "ip": key.ip,
            "key": key.raw_key
        }
    })
}

pub fn success_delete_response() -> Value {
    json!({
        "error": 0,
        "data": "Agent deleted successfully."
    })
}

/// Dispatches an incoming request buffer matching `local_dispatch`.
pub async fn local_dispatch(
    input: &str,
    keystore: &Arc<RwLock<KeyStore>>,
    config: &AuthdConfig,
    server_hostname: &str,
    db_info_lookup: Option<&(dyn Fn(&str) -> Option<AgentDbInfo> + Send + Sync)>,
) -> String {
    let trimmed = input.trim();

    if trimmed.starts_with('{') {
        if config.worker_node {
            return error_response(LocalErrorCode::WorkerNodeRejected).to_string();
        }

        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return error_response(LocalErrorCode::JsonParse).to_string(),
        };

        let function = match parsed.get("function").and_then(Value::as_str) {
            Some(f) => f,
            None => return error_response(LocalErrorCode::NoSuchFunction).to_string(),
        };

        let arguments = match parsed.get("arguments").and_then(Value::as_object) {
            Some(a) => a,
            None => return error_response(LocalErrorCode::NoSuchArgument).to_string(),
        };

        match function {
            "add" => {
                let name = match arguments.get("name").and_then(Value::as_str) {
                    Some(n) if is_valid_name(n) => n,
                    _ => return error_response(LocalErrorCode::NoSuchName).to_string(),
                };

                let ip = match arguments.get("ip").and_then(Value::as_str) {
                    Some(i) => i,
                    _ => return error_response(LocalErrorCode::NoSuchIp).to_string(),
                };

                let id = arguments.get("id").and_then(Value::as_str);
                let key = arguments.get("key").and_then(Value::as_str);
                let key_hash = arguments.get("key_hash").and_then(Value::as_str);

                let groups = if let Some(g_val) = arguments.get("groups").and_then(Value::as_str) {
                    match validate_groups(g_val) {
                        Ok(valid) => Some(valid),
                        Err(_) => return error_response(LocalErrorCode::InvalidGroupName).to_string(),
                    }
                } else {
                    None
                };

                let force_options = if let Some(force_val) = arguments.get("force") {
                    parse_custom_force(force_val).unwrap_or_else(|| config.force_options.clone())
                } else {
                    config.force_options.clone()
                };

                local_add(
                    keystore,
                    name,
                    ip,
                    id,
                    groups.as_deref(),
                    key,
                    key_hash,
                    &force_options,
                    server_hostname,
                    db_info_lookup,
                )
                .await
            }
            "remove" => {
                let id = match arguments.get("id").and_then(Value::as_str) {
                    Some(i) => i,
                    None => return error_response(LocalErrorCode::NoSuchAgentId).to_string(),
                };

                local_remove(keystore, id).await
            }
            "get" => {
                let id = match arguments.get("id").and_then(Value::as_str) {
                    Some(i) => i,
                    None => return error_response(LocalErrorCode::NoSuchAgentId).to_string(),
                };

                local_get(keystore, id).await
            }
            _ => error_response(LocalErrorCode::NoSuchFunction).to_string(),
        }
    } else {
        // Plaintext configuration commands
        authcom_dispatch(trimmed, config)
    }
}

fn parse_custom_force(val: &Value) -> Option<ForceOptions> {
    let mut opts = ForceOptions::default();
    if let Some(enabled) = val.get("enabled").and_then(Value::as_bool) {
        opts.enabled = enabled;
    }
    if let Some(key_mismatch) = val.get("key_mismatch").and_then(Value::as_bool) {
        opts.key_mismatch = key_mismatch;
    }
    if let Some(disc) = val.get("disconnected_time") {
        if let Some(enabled) = disc.get("enabled").and_then(Value::as_bool) {
            opts.disconnected_time_enabled = enabled;
        }
        if let Some(value) = disc.get("value").and_then(Value::as_u64) {
            opts.disconnected_time = value;
        }
    }
    if let Some(after_reg) = val.get("after_registration_time").and_then(Value::as_u64) {
        opts.after_registration_time = after_reg;
    }
    Some(opts)
}

/// Executes local agent addition matching `local_add`.
async fn local_add(
    keystore: &Arc<RwLock<KeyStore>>,
    name: &str,
    ip: &str,
    id: Option<&str>,
    _groups: Option<&str>,
    key: Option<&str>,
    key_hash: Option<&str>,
    force: &ForceOptions,
    server_hostname: &str,
    db_info_lookup: Option<&(dyn Fn(&str) -> Option<AgentDbInfo> + Send + Sync)>,
) -> String {
    if name == server_hostname {
        return error_response(LocalErrorCode::DuplicateName).to_string();
    }

    let mut ks = keystore.write().await;

    // Check duplicate ID
    if let Some(target_id) = id {
        if let Some(existing) = ks.find_by_id(target_id) {
            let db_info = db_info_lookup.and_then(|f| f(&existing.id));
            if can_replace_agent(existing, db_info.as_ref(), key_hash, force).is_err() {
                return error_response(LocalErrorCode::DuplicateId).to_string();
            }
            let to_remove = existing.id.clone();
            ks.delete_key(&to_remove);
        }
    }

    // Check duplicate IP (if not "any")
    if ip != "any" {
        if let Some(existing) = ks.find_by_ip(ip) {
            let db_info = db_info_lookup.and_then(|f| f(&existing.id));
            if can_replace_agent(existing, db_info.as_ref(), key_hash, force).is_err() {
                return error_response(LocalErrorCode::DuplicateIp).to_string();
            }
            let to_remove = existing.id.clone();
            ks.delete_key(&to_remove);
        }
    }

    // Check duplicate Name
    if let Some(existing) = ks.find_by_name(name) {
        let db_info = db_info_lookup.and_then(|f| f(&existing.id));
        if can_replace_agent(existing, db_info.as_ref(), key_hash, force).is_err() {
            return error_response(LocalErrorCode::DuplicateName).to_string();
        }
        let to_remove = existing.id.clone();
        ks.delete_key(&to_remove);
    }

    let agent_id = id.map(ToString::to_string).unwrap_or_else(|| ks.next_id());
    let raw_key = key.map(ToString::to_string).unwrap_or_else(KeyStore::generate_raw_key);

    let client_key = ClientKey::new(agent_id, name.to_string(), ip.to_string(), raw_key);
    ks.add_key(client_key.clone());

    success_agent_response(&client_key).to_string()
}

/// Executes local agent deletion matching `local_remove`.
async fn local_remove(keystore: &Arc<RwLock<KeyStore>>, id: &str) -> String {
    let mut ks = keystore.write().await;
    if ks.delete_key(id).is_some() {
        success_delete_response().to_string()
    } else {
        error_response(LocalErrorCode::AgentIdNotFound).to_string()
    }
}

/// Executes local agent lookup matching `local_get`.
async fn local_get(keystore: &Arc<RwLock<KeyStore>>, id: &str) -> String {
    let ks = keystore.read().await;
    if let Some(key) = ks.find_by_id(id) {
        success_agent_response(key).to_string()
    } else {
        error_response(LocalErrorCode::AgentIdNotFound).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_add_remove_get() {
        let ks = Arc::new(RwLock::new(KeyStore::new()));
        let config = AuthdConfig::default();

        // 1. Add agent
        let add_cmd = r#"{"function": "add", "arguments": {"name": "server-1", "ip": "10.0.0.10"}}"#;
        let res = local_dispatch(add_cmd, &ks, &config, "manager", None).await;
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert_eq!(parsed["error"], 0);
        assert_eq!(parsed["data"]["id"], "001");
        assert_eq!(parsed["data"]["name"], "server-1");

        // 2. Get agent
        let get_cmd = r#"{"function": "get", "arguments": {"id": "001"}}"#;
        let res2 = local_dispatch(get_cmd, &ks, &config, "manager", None).await;
        let parsed2: Value = serde_json::from_str(&res2).unwrap();
        assert_eq!(parsed2["error"], 0);
        assert_eq!(parsed2["data"]["id"], "001");

        // 3. Remove agent
        let rm_cmd = r#"{"function": "remove", "arguments": {"id": "001"}}"#;
        let res3 = local_dispatch(rm_cmd, &ks, &config, "manager", None).await;
        let parsed3: Value = serde_json::from_str(&res3).unwrap();
        assert_eq!(parsed3["error"], 0);

        // 4. Get removed agent should return 9011 (Agent ID not found)
        let res4 = local_dispatch(get_cmd, &ks, &config, "manager", None).await;
        let parsed4: Value = serde_json::from_str(&res4).unwrap();
        assert_eq!(parsed4["error"], 9011);
    }
}
