use super::parsing::parse_agent_ack_response;
use super::tasks::AgentInfo;
use super::validate::{compare_wazuh_versions, UpgradeErrorCode, WM_UPGRADE_NEW_UPGRADE_MECHANISM};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use tracing::{debug, error, info};

#[async_trait]
pub trait UpgradeTransport: Send + Sync {
    /// Transmits command to agent and receives response string
    async fn send_command(&self, agent_id: u32, command_str: &str) -> Result<String, String>;
}

/// Dispatches an upgrade to an agent following the 6-step wire protocol
pub async fn send_wpk_to_agent<T: UpgradeTransport>(
    transport: &T,
    agent_info: &AgentInfo,
    wpk_file_name: &str,
    wpk_data: &[u8],
    expected_sha1: &str,
    installer: &str,
    chunk_size: usize,
) -> Result<(), UpgradeErrorCode> {
    let agent_id = agent_info.agent_id;
    let is_modern = compare_wazuh_versions(&agent_info.wazuh_version, WM_UPGRADE_NEW_UPGRADE_MECHANISM)
        != std::cmp::Ordering::Less;

    // Step 1: Send lock_restart
    info!("Agent {agent_id:03}: Sending lock_restart");
    let lock_cmd = format!("{agent_id:03} com lock_restart -1");
    match transport.send_command(agent_id, &lock_cmd).await {
        Ok(res) => {
            if let Err(e) = parse_agent_ack_response(&res) {
                error!("Agent {agent_id:03}: lock_restart failed: {e:?}");
                return Err(UpgradeErrorCode::SendLockRestartError);
            }
        }
        Err(e) => {
            error!("Agent {agent_id:03}: lock_restart transport error: {e}");
            return Err(UpgradeErrorCode::SendLockRestartError);
        }
    }

    // Step 2: Send open
    debug!("Agent {agent_id:03}: Sending open {wpk_file_name}");
    let open_cmd = if is_modern {
        let payload = json!({
            "command": "open",
            "parameters": {
                "mode": "wb",
                "file": wpk_file_name,
            }
        });
        format!("{agent_id:03} upgrade {}", payload)
    } else {
        format!("{agent_id:03} com open wb {wpk_file_name}")
    };

    match transport.send_command(agent_id, &open_cmd).await {
        Ok(res) => {
            if let Err(e) = parse_agent_ack_response(&res) {
                error!("Agent {agent_id:03}: open failed: {e:?}");
                return Err(UpgradeErrorCode::SendOpenError);
            }
        }
        Err(e) => {
            error!("Agent {agent_id:03}: open transport error: {e}");
            return Err(UpgradeErrorCode::SendOpenError);
        }
    }

    // Step 3: Stream chunks (write)
    let chunks = wpk_data.chunks(chunk_size.clamp(64, 60000));
    let total_chunks = chunks.len();
    debug!("Agent {agent_id:03}: Streaming {total_chunks} chunks (size {chunk_size} bytes)");

    for (idx, chunk) in chunks.enumerate() {
        let write_cmd = if is_modern {
            let encoded = BASE64.encode(chunk);
            let payload = json!({
                "command": "write",
                "parameters": {
                    "buffer": encoded,
                    "length": chunk.len(),
                    "file": wpk_file_name,
                }
            });
            format!("{agent_id:03} upgrade {}", payload)
        } else {
            let encoded = BASE64.encode(chunk);
            format!("{agent_id:03} com write {} {wpk_file_name} {encoded}", chunk.len())
        };

        match transport.send_command(agent_id, &write_cmd).await {
            Ok(res) => {
                if let Err(e) = parse_agent_ack_response(&res) {
                    error!("Agent {agent_id:03}: write chunk {idx}/{total_chunks} failed: {e:?}");
                    return Err(UpgradeErrorCode::SendWriteError);
                }
            }
            Err(e) => {
                error!("Agent {agent_id:03}: write transport error on chunk {idx}: {e}");
                return Err(UpgradeErrorCode::SendWriteError);
            }
        }
    }

    // Step 4: Send close
    debug!("Agent {agent_id:03}: Sending close {wpk_file_name}");
    let close_cmd = if is_modern {
        let payload = json!({
            "command": "close",
            "parameters": {
                "file": wpk_file_name,
            }
        });
        format!("{agent_id:03} upgrade {}", payload)
    } else {
        format!("{agent_id:03} com close {wpk_file_name}")
    };

    match transport.send_command(agent_id, &close_cmd).await {
        Ok(res) => {
            if let Err(e) = parse_agent_ack_response(&res) {
                error!("Agent {agent_id:03}: close failed: {e:?}");
                return Err(UpgradeErrorCode::SendCloseError);
            }
        }
        Err(e) => {
            error!("Agent {agent_id:03}: close transport error: {e}");
            return Err(UpgradeErrorCode::SendCloseError);
        }
    }

    // Step 5: Send sha1 verification
    debug!("Agent {agent_id:03}: Sending sha1 verification");
    let sha1_cmd = if is_modern {
        let payload = json!({
            "command": "sha1",
            "parameters": {
                "file": wpk_file_name,
                "sha1": expected_sha1,
            }
        });
        format!("{agent_id:03} upgrade {}", payload)
    } else {
        format!("{agent_id:03} com sha1 {wpk_file_name} {expected_sha1}")
    };

    match transport.send_command(agent_id, &sha1_cmd).await {
        Ok(res) => {
            if let Err(e) = parse_agent_ack_response(&res) {
                error!("Agent {agent_id:03}: sha1 verification failed: {e:?}");
                return Err(UpgradeErrorCode::SendSha1Error);
            }
        }
        Err(e) => {
            error!("Agent {agent_id:03}: sha1 transport error: {e}");
            return Err(UpgradeErrorCode::SendSha1Error);
        }
    }

    // Step 6: Send upgrade
    info!("Agent {agent_id:03}: Sending execute upgrade with installer {installer}");
    let upgrade_cmd = if is_modern {
        let payload = json!({
            "command": "upgrade",
            "parameters": {
                "file": wpk_file_name,
                "installer": installer,
            }
        });
        format!("{agent_id:03} upgrade {}", payload)
    } else {
        format!("{agent_id:03} com upgrade {wpk_file_name} {installer}")
    };

    match transport.send_command(agent_id, &upgrade_cmd).await {
        Ok(res) => {
            if let Err(e) = parse_agent_ack_response(&res) {
                error!("Agent {agent_id:03}: upgrade command failed: {e:?}");
                return Err(UpgradeErrorCode::SendUpgradeError);
            }
        }
        Err(e) => {
            error!("Agent {agent_id:03}: upgrade transport error: {e}");
            return Err(UpgradeErrorCode::SendUpgradeError);
        }
    }

    info!("Agent {agent_id:03}: Upgrade script executed successfully");
    Ok(())
}
