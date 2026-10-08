//! Wazuh Authd Server Daemon Engine (`src/os_auth/main-server.c`)
//!
//! Orchestrates the TCP enrollment server, client connection pool, local IPC command
//! dispatcher, and persistent `client.keys` disk synchronization.

use crate::config::{AuthdConfig, KEYS_FILE};
use crate::enrollment::{
    add_agent_to_keystore, format_success_response, parse_enrollment_data, validate_and_prepare,
    CURRENT_MANAGER_VERSION,
};
use crate::local_server::local_dispatch;
use siem_crypto::keys::KeyStore;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub struct AuthDaemon {
    pub config: AuthdConfig,
    pub keystore: Arc<RwLock<KeyStore>>,
    pub keys_file_path: PathBuf,
    pub hostname: String,
    pub running: Arc<AtomicBool>,
}

impl AuthDaemon {
    pub fn new(config: AuthdConfig, keys_path: Option<&Path>) -> Self {
        let keys_file = keys_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(KEYS_FILE));

        let keystore = if keys_file.exists() {
            KeyStore::load_file(&keys_file).unwrap_or_else(|e| {
                warn!("Failed to load {}: {}. Starting with empty keystore.", keys_file.display(), e);
                KeyStore::new()
            })
        } else {
            KeyStore::new()
        };

        let hostname = match std::env::var("HOSTNAME") {
            Ok(h) if !h.is_empty() => h,
            _ => "localhost".to_string(),
        };

        Self {
            config,
            keystore: Arc::new(RwLock::new(keystore)),
            keys_file_path: keys_file,
            hostname,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Handles an incoming enrollment connection on TCP port 1515.
    pub async fn handle_connection(&self, mut socket: TcpStream, peer_addr: std::net::SocketAddr) {
        let peer_ip = peer_addr.ip().to_string();
        info!("Authd: New connection from {}", peer_ip);

        let (reader, mut writer) = socket.split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        match buf_reader.read_line(&mut line).await {
            Ok(0) => {
                info!("Authd: Connection closed by peer {}", peer_ip);
                return;
            }
            Ok(_) => {
                let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                let response = self.process_request(trimmed, &peer_ip).await;
                if let Err(e) = writer.write_all(response.as_bytes()).await {
                    error!("Authd: Failed to write response to {}: {}", peer_ip, e);
                }
                let _ = writer.flush().await;
            }
            Err(e) => {
                error!("Authd: Error reading from {}: {}", peer_ip, e);
            }
        }
    }

    /// Processes a single enrollment request string.
    pub async fn process_request(&self, request_str: &str, peer_ip: &str) -> String {
        let parsed = match parse_enrollment_data(
            request_str,
            self.config.password.as_deref(),
            peer_ip,
            self.config.use_source_ip,
            self.config.allow_higher_versions,
            CURRENT_MANAGER_VERSION,
        ) {
            Ok(req) => req,
            Err(e) => {
                warn!("Authd: Enrollment parse failed from {}: {}", peer_ip, e);
                return format!("{}. Unable to add agent\n", e);
            }
        };

        let mut ks = self.keystore.write().await;

        if let Err(e) = validate_and_prepare(
            &mut ks,
            &parsed,
            &self.hostname,
            &self.config.force_options,
            None,
        ) {
            warn!("Authd: Validation failed for agent '{}' from {}: {}", parsed.name, peer_ip, e);
            return format!("{}. Unable to add agent\n", e);
        }

        let new_key = add_agent_to_keystore(&mut ks, &parsed.name, &parsed.ip, None, None);

        // Persist to keys file
        if let Err(e) = ks.save_file(&self.keys_file_path) {
            error!("Authd: Failed to write client.keys to {}: {}", self.keys_file_path.display(), e);
        }

        info!(
            "Authd: Agent key generated for '{}' (id: {}, ip: {}, requested by {})",
            new_key.name, new_key.id, new_key.ip, peer_ip
        );

        format!("{}\n", format_success_response(&new_key))
    }

    /// Processes local IPC commands.
    pub async fn process_local_ipc(&self, cmd: &str) -> String {
        local_dispatch(cmd, &self.keystore, &self.config, &self.hostname, None).await
    }

    /// Runs the TCP listener service until shutdown is triggered.
    pub async fn run_server(&self) -> std::io::Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Authd daemon listening on {}", addr);

        while self.running.load(Ordering::SeqCst) {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((socket, peer_addr)) => {
                            let daemon_ref = self.clone_handle();
                            tokio::spawn(async move {
                                daemon_ref.handle_connection(socket, peer_addr).await;
                            });
                        }
                        Err(e) => {
                            error!("Authd accept error: {}", e);
                        }
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(500)) => {
                    // Periodic poll to check running flag
                }
            }
        }

        info!("Authd daemon shut down gracefully.");
        Ok(())
    }

    pub fn clone_handle(&self) -> Arc<Self> {
        Arc::new(Self {
            config: self.config.clone(),
            keystore: Arc::clone(&self.keystore),
            keys_file_path: self.keys_file_path.clone(),
            hostname: self.hostname.clone(),
            running: Arc::clone(&self.running),
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_authd_process_request_lifecycle() {
        let temp_keys = NamedTempFile::new().unwrap();
        let mut config = AuthdConfig::default();
        config.password = Some("testpass123".to_string());

        let daemon = AuthDaemon::new(config, Some(temp_keys.path()));

        // Valid enrollment
        let req = "OSSEC PASS: testpass123 OSSEC A:'node-linux-1' G:'web' IP:'192.168.1.100'";
        let resp = daemon.process_request(req, "192.168.1.100").await;

        assert!(resp.starts_with("OSSEC K:'001 node-linux-1 192.168.1.100 "));

        // Re-read keystore to verify persistence
        let ks = daemon.keystore.read().await;
        assert_eq!(ks.len(), 1);
        assert_eq!(ks.find_by_id("001").unwrap().name, "node-linux-1");
    }

    #[tokio::test]
    async fn test_authd_local_ipc() {
        let temp_keys = NamedTempFile::new().unwrap();
        let config = AuthdConfig::default();
        let daemon = AuthDaemon::new(config, Some(temp_keys.path()));

        let cmd = r#"{"function": "add", "arguments": {"name": "local-agent", "ip": "10.10.10.1"}}"#;
        let res = daemon.process_local_ipc(cmd).await;
        assert!(res.contains("\"error\":0"));
        assert!(res.contains("\"name\":\"local-agent\""));
    }
}
