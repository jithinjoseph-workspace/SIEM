use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use siem_engine::AnalysisEngine;
use siem_remoted::{AuthdConfig, AuthdService, KeysDatabase, RemotedConfig, RemotedServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("============================================================");
    info!("Starting High-Capacity Wazuh-Compatible Agent Gateway (50,000+ Agents)");
    info!("============================================================");

    let keys_db = Arc::new(KeysDatabase::new());

    // Load existing keys from environment or volume if available
    let keys_path = std::env::var("CLIENT_KEYS_PATH").unwrap_or_else(|_| "client.keys".to_string());
    if let Ok(content) = std::fs::read_to_string(&keys_path) {
        let loaded = keys_db.load_from_str(&content);
        info!("Loaded {} active agent keys from {}", loaded, keys_path);
    } else {
        info!("No existing {} found, starting with empty keys DB", keys_path);
    }

    let engine = Arc::new(AnalysisEngine::new());

    let remoted_port: u16 = std::env::var("REMOTED_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1514);

    let authd_port: u16 = std::env::var("AUTHD_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1515);

    let remoted_addr: SocketAddr = format!("0.0.0.0:{}", remoted_port).parse()?;
    let authd_addr: SocketAddr = format!("0.0.0.0:{}", authd_port).parse()?;

    let remoted_config = RemotedConfig {
        bind_addr: remoted_addr,
        enable_udp: true,
        enable_tcp: true,
    };

    let server = Arc::new(RemotedServer::new(
        keys_db.clone(),
        engine.clone(),
        remoted_config,
    ));

    // 1. Spawn UDP Port 1514 Listener (High-throughput agent wire)
    let server_udp = server.clone();
    tokio::spawn(async move {
        if let Err(e) = server_udp.start_udp_listener().await {
            error!("Fatal error in Remoted UDP listener: {}", e);
        }
    });

    // 2. Spawn TCP Port 1514 Listener (Reliable WAN agents)
    let server_tcp = server.clone();
    tokio::spawn(async move {
        let listener = match TcpListener::bind(remoted_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind TCP 1514: {}", e);
                return;
            }
        };
        info!("Wazuh Remoted listening on TCP {}", remoted_addr);

        loop {
            match listener.accept().await {
                Ok((mut stream, peer)) => {
                    let s_clone = server_tcp.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        let peer_ip = peer.ip().to_string();
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => break, // Connection closed
                                Ok(n) => {
                                    let packet = &buf[..n];
                                    if let Err(e) = s_clone.process_agent_packet(&peer_ip, packet) {
                                        warn!("TCP packet error from {}: {}", peer, e);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(e) => error!("TCP accept error: {}", e),
            }
        }
    });

    // 3. Spawn TCP Port 1515 Listener (ossec-authd Agent Enrollment Daemon)
    let authd_service = Arc::new(AuthdService::new(
        keys_db.clone(),
        AuthdConfig::default(),
    ));

    let authd_listener = TcpListener::bind(authd_addr).await?;
    info!("Wazuh Authd Enrollment Daemon listening on TCP {}", authd_addr);

    let kpath_clone = keys_path.clone();
    let kdb_clone = keys_db.clone();

    loop {
        match authd_listener.accept().await {
            Ok((mut socket, peer)) => {
                let service = authd_service.clone();
                let kp = kpath_clone.clone();
                let kdb = kdb_clone.clone();

                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let peer_ip = peer.ip().to_string();

                    if let Ok(n) = socket.read(&mut buf).await {
                        if n > 0 {
                            let req = String::from_utf8_lossy(&buf[..n]);
                            match service.handle_enrollment_request(&peer_ip, &req) {
                                Ok(resp) => {
                                    let _ = socket.write_all(resp.as_bytes()).await;
                                    info!("Authd: Agent enrolled from {}, credentials sent", peer);

                                    // Persist updated client.keys to volume
                                    let exported = kdb.export_client_keys();
                                    let _ = std::fs::write(&kp, exported);
                                }
                                Err(e) => {
                                    warn!("Authd: Enrollment rejected for {}: {}", peer, e);
                                    let err_msg = format!("OSSEC ERROR: '{}'", e);
                                    let _ = socket.write_all(err_msg.as_bytes()).await;
                                }
                            }
                        }
                    }
                });
            }
            Err(e) => error!("Authd accept error: {}", e),
        }
    }
}
