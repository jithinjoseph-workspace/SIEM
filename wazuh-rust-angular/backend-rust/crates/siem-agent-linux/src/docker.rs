//! Docker Container Activity & Security Monitor (mirroring Wazuh wm_docker.c)
//!
//! Connects to `/var/run/docker.sock` and monitors real-time container lifecycle events
//! (`create`, `start`, `stop`, `die`, `kill`, `pause`, `unpause`, `destroy`).

use crate::buffer::AgentBuffer;
#[allow(unused_imports)]
use siem_core::{EventSource, RawEvent};
#[allow(unused_imports)]
use std::path::Path;
use std::sync::Arc;
#[allow(unused_imports)]
use std::time::Duration;
use tracing::info;

/// Spawns the Docker container activity monitoring worker (mirroring Wazuh wm_docker.c)
pub fn spawn_docker_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        {
            let socket_path = "/var/run/docker.sock";
            if !Path::new(socket_path).exists() {
                info!("wazuh-docker: Docker socket '{}' not detected. Dynamic container monitoring dormant.", socket_path);
                return;
            }

            info!("wazuh-docker: Initializing real-time Docker container event listener on '{}'", socket_path);

            loop {
                match tokio::net::UnixStream::connect(socket_path).await {
                    Ok(stream) => {
                        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

                        let (reader, mut writer) = stream.into_split();
                        let request = "GET /events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n";

                        if writer.write_all(request.as_bytes()).await.is_ok() {
                            let mut lines = BufReader::new(reader).lines();

                            // Skip HTTP headers
                            while let Ok(Some(header_line)) = lines.next_line().await {
                                if header_line.trim().is_empty() {
                                    break;
                                }
                            }

                            // Stream incoming JSON chunks
                            while let Ok(Some(line)) = lines.next_line().await {
                                let trimmed = line.trim();
                                if trimmed.is_empty() || trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                                    // Skip chunk size headers
                                    continue;
                                }

                                if let Ok(event_json) = serde_json::from_str::<serde_json::Value>(trimmed) {
                                    let action = event_json.get("Action")
                                        .or_else(|| event_json.get("status"))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");

                                    let container_id = event_json.get("id")
                                        .or_else(|| event_json.get("Actor").and_then(|a| a.get("ID")))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");

                                    let short_id = if container_id.len() >= 12 { &container_id[..12] } else { container_id };

                                    let container_name = event_json.get("Actor")
                                        .and_then(|a| a.get("Attributes"))
                                        .and_then(|attr| attr.get("name"))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or(short_id);

                                    let image = event_json.get("from")
                                        .or_else(|| event_json.get("Actor").and_then(|a| a.get("Attributes")).and_then(|attr| attr.get("image")))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");

                                    let msg = format!(
                                        "wazuh-docker: Container '{}' ({}) action: '{}' (image: {})",
                                        container_name, short_id, action, image
                                    );
                                    info!("{}", msg);

                                    let mut event = RawEvent::new(&agent_id, EventSource::Custom("docker".into()), "docker/events", msg);
                                    event.metadata.insert("container_id".into(), container_id.to_string());
                                    event.metadata.insert("container_name".into(), container_name.to_string());
                                    event.metadata.insert("container_image".into(), image.to_string());
                                    event.metadata.insert("action".into(), action.to_string());
                                    event.metadata.insert("os_type".into(), "linux".into());

                                    buffer.push(event).await;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Sleep before reconnect attempt
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&agent_id, &buffer);
            info!("wazuh-docker: Docker container monitoring worker dormant on non-Linux host.");
        }
    })
}
