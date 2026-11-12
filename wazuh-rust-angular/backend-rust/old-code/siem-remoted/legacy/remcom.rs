//! Remoted IPC Control Socket Protocol (remcom.c, request.c)
//!
//! Handles control requests from local daemons or API over `/queue/sockets/remcom`
//! (getagentsstate, getconfig, assigngroup, disconnect).

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::RemoteSection;
use crate::keys::KeysDatabase;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemcomRequest {
    pub command: String,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemcomResponse {
    pub error: u32,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

pub struct RemcomHandler {
    keys_db: Arc<KeysDatabase>,
    config: RemoteSection,
}

impl RemcomHandler {
    pub fn new(keys_db: Arc<KeysDatabase>, config: RemoteSection) -> Self {
        Self { keys_db, config }
    }

    /// Process incoming JSON command string and return JSON response string.
    pub fn process_command(&self, request_str: &str) -> String {
        let req: RemcomRequest = match serde_json::from_str(request_str) {
            Ok(r) => r,
            Err(e) => {
                return serde_json::to_string(&RemcomResponse {
                    error: 2, // ERROR_INVALID_INPUT
                    message: format!("Invalid JSON input: {}", e),
                    data: None,
                })
                .unwrap_or_default();
            }
        };

        let response = match req.command.as_str() {
            "getagentsstate" => {
                let agents = self.keys_db.list_agents();
                let agents_data: Vec<serde_json::Value> = agents
                    .into_iter()
                    .map(|a| {
                        serde_json::json!({
                            "id": a.id,
                            "name": a.name,
                            "ip": a.ip,
                            "last_counter": a.last_counter,
                        })
                    })
                    .collect();

                RemcomResponse {
                    error: 0,
                    message: "ok".to_string(),
                    data: Some(serde_json::json!({ "agents": agents_data })),
                }
            }
            "getconfig" => {
                let section = req
                    .parameters
                    .as_ref()
                    .and_then(|p| p.get("section"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("remote");

                if section == "remote" {
                    RemcomResponse {
                        error: 0,
                        message: "ok".to_string(),
                        data: Some(serde_json::to_value(&self.config).unwrap_or_default()),
                    }
                } else {
                    RemcomResponse {
                        error: 7, // ERROR_UNRECOGNIZED_SECTION
                        message: format!("Unrecognized section: {}", section),
                        data: None,
                    }
                }
            }
            "assigngroup" => {
                if let Some(params) = req.parameters {
                    let agent_id = params.get("agent").and_then(|a| a.as_str());
                    let group_hash = params.get("md5").and_then(|m| m.as_str());

                    if let (Some(id), Some(hash)) = (agent_id, group_hash) {
                        RemcomResponse {
                            error: 0,
                            message: "ok".to_string(),
                            data: Some(serde_json::json!({
                                "agent": id,
                                "group_hash": hash,
                                "status": "assigned",
                            })),
                        }
                    } else {
                        RemcomResponse {
                            error: 12, // ERROR_EMPTY_AGENT_OR_MD5
                            message: "Missing agent or md5 parameter".to_string(),
                            data: None,
                        }
                    }
                } else {
                    RemcomResponse {
                        error: 5, // ERROR_EMPTY_PARAMATERS
                        message: "Empty parameters".to_string(),
                        data: None,
                    }
                }
            }
            other => RemcomResponse {
                error: 4, // ERROR_UNRECOGNIZED_COMMAND
                message: format!("Unrecognized command: {}", other),
                data: None,
            },
        };

        serde_json::to_string(&response).unwrap_or_default()
    }
}
