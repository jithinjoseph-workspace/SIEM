use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use siem_core::{Alert, EventSource, RawEvent};
use siem_engine::AnalysisEngine;

use crate::crypto::{decrypt_aes256_cbc, encrypt_aes256_cbc, CryptoError};
use crate::keys::{KeyError, KeysDatabase};
use crate::protocol::{ProtocolError, RemotedMessage, WazuhSubsystem};

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Agent unidentified: IP {0} not in client.keys")]
    UnknownAgent(String),
}

#[derive(Debug, Clone)]
pub struct RemotedConfig {
    pub bind_addr: SocketAddr,
    pub enable_udp: bool,
    pub enable_tcp: bool,
}

impl Default for RemotedConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:1514".parse().unwrap(),
            enable_udp: true,
            enable_tcp: true,
        }
    }
}

pub struct RemotedServer {
    keys_db: Arc<KeysDatabase>,
    engine: Arc<AnalysisEngine>,
    config: RemotedConfig,
}

impl RemotedServer {
    pub fn new(
        keys_db: Arc<KeysDatabase>,
        engine: Arc<AnalysisEngine>,
        config: RemotedConfig,
    ) -> Self {
        Self {
            keys_db,
            engine,
            config,
        }
    }

    /// Process an incoming binary message from an agent over Port 1514
    pub fn process_agent_packet(
        &self,
        peer_ip: &str,
        packet_bytes: &[u8],
    ) -> Result<(RemotedMessage, Option<Alert>), ServerError> {
        // Agent packets in Wazuh:
        // Format A: starts with "!agent_id:ciphertext" or ":agent_id:ciphertext"
        // Format B: pure ciphertext, key looked up by peer_ip
        let (agent_id, ciphertext) = if packet_bytes.starts_with(b"!") || packet_bytes.starts_with(b":") {
            let s = String::from_utf8_lossy(packet_bytes);
            if let Some(colon_idx) = s[1..].find(':') {
                let id = &s[1..=colon_idx];
                let offset = 1 + colon_idx + 1;
                (id.to_string(), &packet_bytes[offset..])
            } else {
                ("".to_string(), packet_bytes)
            }
        } else {
            ("".to_string(), packet_bytes)
        };

        // Lookup agent key
        let agent = if !agent_id.is_empty() {
            self.keys_db.get_by_id(&agent_id)
        } else {
            // Find agent matching peer_ip
            self.keys_db.get_by_name(peer_ip).or_else(|| {
                // If not found, try lookup by ID
                self.keys_db.get_by_id("001")
            })
        }
        .ok_or_else(|| ServerError::UnknownAgent(peer_ip.to_string()))?;

        // Decrypt AES-256-CBC
        let plaintext_bytes = decrypt_aes256_cbc(&agent.key_bytes, ciphertext)?;
        let plaintext_str = String::from_utf8_lossy(&plaintext_bytes);

        // Parse protocol message
        let remoted_msg = RemotedMessage::parse(&agent.id, &plaintext_str)?;

        // Verify and update counter for replay defense
        self.keys_db
            .verify_and_update_counter(&agent.id, remoted_msg.counter)?;

        // Map subsystem to SIEM EventSource
        let source = match remoted_msg.subsystem {
            WazuhSubsystem::Fim => EventSource::Fim,
            WazuhSubsystem::Syscollector => EventSource::Syscollector,
            WazuhSubsystem::Sca => EventSource::Sca,
            WazuhSubsystem::Keepalive => EventSource::Syscollector,
            WazuhSubsystem::Rootcheck => EventSource::Syscollector,
            WazuhSubsystem::ActiveResponse => EventSource::Auth,
            WazuhSubsystem::Log => EventSource::Syslog,
        };

        let location = match remoted_msg.subsystem {
            WazuhSubsystem::Fim => "syscheck",
            WazuhSubsystem::Rootcheck => "rootcheck",
            WazuhSubsystem::Syscollector => "syscollector",
            WazuhSubsystem::Sca => "sca",
            WazuhSubsystem::Keepalive => "wazuh-agent",
            WazuhSubsystem::ActiveResponse => "active-response",
            WazuhSubsystem::Log => "remoted",
        };

        // Create RawEvent and evaluate against rule engine
        let raw_event = RawEvent::new(&agent.id, source, location, &remoted_msg.payload);
        let alert = self.engine.process_event(&raw_event, &agent.name, &agent.ip);

        Ok((remoted_msg, alert))
    }

    /// Craft an encrypted response/command to send to an agent
    pub fn craft_agent_message(
        &self,
        agent_id: &str,
        counter: u64,
        subsystem_id: u8,
        payload: &str,
    ) -> Result<Vec<u8>, ServerError> {
        let agent = self
            .keys_db
            .get_by_id(agent_id)
            .ok_or_else(|| ServerError::Key(KeyError::AgentNotFound(agent_id.to_string())))?;

        let wire_text = RemotedMessage::format_wire(counter, subsystem_id, payload);
        let encrypted = encrypt_aes256_cbc(&agent.key_bytes, wire_text.as_bytes());

        // Prefix with agent identification
        let mut full_packet = format!("!{}:", agent.id).into_bytes();
        full_packet.extend(encrypted);
        Ok(full_packet)
    }

    /// Start listening on UDP port 1514 (mirroring Wazuh remoted UDP receiver)
    pub async fn start_udp_listener(self: Arc<Self>) -> Result<(), std::io::Error> {
        let socket = UdpSocket::bind(self.config.bind_addr).await?;
        info!("Wazuh Remoted listening on UDP {}", self.config.bind_addr);

        let mut buf = [0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    let packet = &buf[..len];
                    let peer_ip = src_addr.ip().to_string();

                    match self.process_agent_packet(&peer_ip, packet) {
                        Ok((msg, maybe_alert)) => {
                            debug!(
                                "Remoted UDP: Decrypted msg from agent {} (counter={})",
                                msg.agent_id, msg.counter
                            );
                            if let Some(alert) = maybe_alert {
                                info!(
                                    "Remoted Alert [Level {}]: {} - {}",
                                    alert.rule.level, alert.rule.description, alert.agent.name
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Remoted UDP: Failed to process packet from {}: {}", src_addr, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Remoted UDP socket error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AgentKey;

    #[test]
    fn test_process_agent_packet_end_to_end() {
        let keys_db = Arc::new(KeysDatabase::new());
        let engine = Arc::new(AnalysisEngine::new());

        let (raw_key, key_bytes) = KeysDatabase::generate_key();
        let agent = AgentKey {
            id: "001".to_string(),
            name: "ubuntu-server".to_string(),
            ip: "192.168.1.100".to_string(),
            raw_key,
            key_bytes,
            last_counter: 0,
        };
        keys_db.add_agent(agent).unwrap();

        let server = RemotedServer::new(keys_db.clone(), engine, RemotedConfig::default());

        // Agent crafts encrypted message
        let wire = RemotedMessage::format_wire(101, 1, "/etc/passwd modified");
        let encrypted = encrypt_aes256_cbc(&key_bytes, wire.as_bytes());

        let mut packet = b"!001:".to_vec();
        packet.extend(encrypted);

        // Server processes incoming packet
        let (msg, _alert) = server
            .process_agent_packet("192.168.1.100", &packet)
            .expect("Packet should be successfully processed");

        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.counter, 101);
        assert_eq!(msg.subsystem, WazuhSubsystem::Fim);
        assert_eq!(msg.payload, "/etc/passwd modified");

        // Counter updated: replay of counter 101 should fail
        let replay_res = server.process_agent_packet("192.168.1.100", &packet);
        assert!(replay_res.is_err(), "Replay attack must be blocked");
    }
}
