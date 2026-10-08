use super::tasks::{TaskData, UpgradeAgentStatusTask, UpgradeCommand, UpgradeCustomTask, UpgradeTask};
use super::validate::UpgradeErrorCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeResponseItem {
    pub error: u32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeResponse {
    pub error: u32,
    pub message: String,
    pub data: Vec<UpgradeResponseItem>,
}

/// Parses an API/CLI upgrade request message
pub fn parse_message(buffer: &str) -> Result<(UpgradeCommand, Vec<u32>, Option<TaskData>), (UpgradeErrorCode, String)> {
    let root: Value = serde_json::from_str(buffer).map_err(|e| {
        (
            UpgradeErrorCode::ParsingError,
            format!("Could not parse message JSON: {e}"),
        )
    })?;

    let command_str = root
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or((UpgradeErrorCode::ParsingRequiredParameter, "Missing 'command'".into()))?;

    let params = root
        .get("parameters")
        .and_then(|v| v.as_object())
        .ok_or((UpgradeErrorCode::ParsingRequiredParameter, "Missing 'parameters'".into()))?;

    let mut agent_ids = Vec::new();
    if let Some(agents_val) = params.get("agents").and_then(|v| v.as_array()) {
        for a in agents_val {
            if let Some(id) = a.as_u64() {
                agent_ids.push(id as u32);
            }
        }
    }

    match command_str {
        "upgrade" => {
            let task = UpgradeTask {
                wpk_repository: params.get("repository").and_then(|v| v.as_str()).map(String::from),
                custom_version: params.get("version").and_then(|v| v.as_str()).map(String::from),
                use_http: params.get("use_http").map(|v| v.as_bool().unwrap_or(false) || v.as_str() == Some("true") || v.as_i64() == Some(1)).unwrap_or(false),
                force_upgrade: params.get("force_upgrade").map(|v| v.as_bool().unwrap_or(false) || v.as_str() == Some("true") || v.as_i64() == Some(1)).unwrap_or(false),
                wpk_version: None,
                wpk_file: None,
                wpk_sha1: None,
                package_type: params.get("package_type").and_then(|v| v.as_str()).map(String::from),
            };
            Ok((UpgradeCommand::Upgrade, agent_ids, Some(TaskData::Standard(task))))
        }
        "upgrade_custom" => {
            let file_path = params
                .get("file_path")
                .and_then(|v| v.as_str())
                .ok_or((UpgradeErrorCode::ParsingRequiredParameter, "Missing 'file_path'".into()))?;
            let installer = params.get("installer").and_then(|v| v.as_str()).map(String::from);

            let custom_task = UpgradeCustomTask {
                custom_file_path: file_path.to_string(),
                custom_installer: installer,
            };
            Ok((UpgradeCommand::UpgradeCustom, agent_ids, Some(TaskData::Custom(custom_task))))
        }
        "upgrade_update_status" => {
            let status = params
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("Done")
                .to_string();
            let error_code = params.get("error_code").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let message = params.get("error_msg").and_then(|v| v.as_str()).map(String::from);

            let status_task = UpgradeAgentStatusTask {
                error_code,
                message,
                status,
            };
            Ok((UpgradeCommand::UpgradeUpdateStatus, agent_ids, Some(TaskData::StatusUpdate(status_task))))
        }
        "upgrade_result" => Ok((UpgradeCommand::UpgradeResult, agent_ids, None)),
        "upgrade_cancel_tasks" => Ok((UpgradeCommand::UpgradeCancelTasks, agent_ids, None)),
        _ => Err((UpgradeErrorCode::TaskConfigurations, format!("Unknown command '{command_str}'"))),
    }
}

/// Builds response JSON for API clients
pub fn build_response(error_code: UpgradeErrorCode, data: Vec<UpgradeResponseItem>) -> Value {
    let msg = if error_code == UpgradeErrorCode::Success {
        "Successful"
    } else {
        error_code.as_str()
    };

    json!({
        "error": error_code as u32,
        "message": msg,
        "data": data,
    })
}

/// Parses an agent upgrade command ACK response
pub fn parse_agent_ack_response(response: &str) -> Result<(), (u32, String)> {
    let root: Value = serde_json::from_str(response).map_err(|e| (1, format!("Invalid ACK JSON: {e}")))?;
    let err = root.get("error").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    if err == 0 {
        Ok(())
    } else {
        let msg = root.get("message").and_then(|v| v.as_str()).unwrap_or("Agent error").to_string();
        Err((err, msg))
    }
}
