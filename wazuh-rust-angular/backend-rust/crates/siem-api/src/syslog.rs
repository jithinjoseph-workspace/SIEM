use std::net::SocketAddr;
use chrono::Utc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info};
use siem_core::{Agent, AgentStatus, EventSource, RawEvent};
use crate::AppState;

/// Spawns background tasks for UDP and TCP syslog ingestion
pub fn start_syslog_listeners(state: AppState) {
    let udp_port = std::env::var("SYSLOG_UDP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(514);

    let tcp_port = std::env::var("SYSLOG_TCP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(601);

    let state_udp = state.clone();
    tokio::spawn(async move {
        start_udp(udp_port, state_udp).await;
    });

    let state_tcp = state.clone();
    tokio::spawn(async move {
        start_tcp(tcp_port, state_tcp).await;
    });
}

async fn start_udp(port: u16, state: AppState) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = match UdpSocket::bind(addr).await {
        Ok(s) => {
            info!("Syslog UDP receiver bound to {}", addr);
            s
        }
        Err(e) => {
            error!("Syslog UDP failed to bind {}: {} (port may require admin/root)", addr, e);
            return;
        }
    };

    let mut buf = vec![0u8; 65535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let raw = String::from_utf8_lossy(&buf[..len]).to_string();
                let peer_ip = peer.ip().to_string();
                let state_clone = state.clone();
                tokio::spawn(async move {
                    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                        process_syslog_line(line.trim(), &peer_ip, &state_clone).await;
                    }
                });
            }
            Err(e) => {
                error!("Syslog UDP recv error: {}", e);
            }
        }
    }
}

async fn start_tcp(port: u16, state: AppState) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!("Syslog TCP receiver listening on {}", addr);
            l
        }
        Err(e) => {
            error!("Syslog TCP failed to bind {}: {} (port may require admin/root)", addr, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                let peer_ip = peer.ip().to_string();
                let state_clone = state.clone();
                tokio::spawn(handle_tcp_connection(socket, peer_ip, state_clone));
            }
            Err(e) => {
                error!("Syslog TCP accept error: {}", e);
            }
        }
    }
}

async fn handle_tcp_connection(mut socket: tokio::net::TcpStream, peer_ip: String, state: AppState) {
    let mut buf = vec![0u8; 65535];
    let mut leftover = String::new();

    loop {
        match socket.read(&mut buf).await {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                leftover.push_str(&chunk);

                // Syslog TCP newline-framing (RFC 6587)
                while let Some(pos) = leftover.find('\n') {
                    let line = leftover[..pos].trim().to_string();
                    leftover = leftover[pos + 1..].to_string();
                    if !line.is_empty() {
                        let state_clone = state.clone();
                        let ip = peer_ip.clone();
                        tokio::spawn(async move {
                            process_syslog_line(&line, &ip, &state_clone).await;
                        });
                    }
                }
            }
            Err(e) => {
                debug!("Syslog TCP read finished from {}: {}", peer_ip, e);
                break;
            }
        }
    }
}

async fn process_syslog_line(line: &str, peer_ip: &str, state: &AppState) {
    let agent_id = format!("syslog-{}", peer_ip);
    let agent_name = format!("net-device-{}", peer_ip);

    // Register / keepalive the network device agent
    {
        let mut agents = state.agents.write().unwrap();
        let ag = agents.entry(agent_id.clone()).or_insert_with(|| Agent {
            id: agent_id.clone(),
            name: agent_name.clone(),
            ip: peer_ip.to_string(),
            os: "Network Appliance (Syslog)".into(),
            version: "syslog-rfc5424".into(),
            status: AgentStatus::Active,
            last_keepalive: Utc::now(),
            os_type: "network".into(),
        });
        ag.last_keepalive = Utc::now();
        ag.status = AgentStatus::Active;
    }

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("source_ip".to_string(), peer_ip.to_string());
    metadata.insert("collector".to_string(), "syslog".to_string());

    let raw_event = RawEvent {
        id: uuid::Uuid::new_v4(),
        agent_id: agent_id.clone(),
        source: EventSource::Syslog,
        message: line.to_string(),
        timestamp: Utc::now(),
        location: format!("{}:syslog", peer_ip),
        metadata,
    };

    // Method 2: Dynamic Parser Engine Hot-Path Execution (< 5 microseconds)
    let _maybe_dynamic = state.parser_registry.execute(line);

    // Evaluate against high-performance Wazuh XML rules & sliding-window accumulator
    let maybe_alert = state.engine.process_event(&raw_event, &agent_name, peer_ip);

    if let Some(alert) = maybe_alert {
        state.alerts.write().unwrap().push(alert.clone());
        state.db.insert_alert(&alert).await;
        let _ = state.broadcast_tx.send(alert);
    }

    state.db.insert_event(&raw_event).await;
    state.events.write().unwrap().push(raw_event);
}
