// Syslog receiver: TCP :601, TCP :6514, UDP :514
// Each received frame is forwarded to the pipeline for normalisation and ingest.

use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, error, debug};

use crate::ingest::pipeline::Pipeline;

const SOURCE_ID: &str = "syslog";
// Tenant resolution: syslog has no built-in tenant header.
// Use "default" here; production deployments should map by source IP → tenant
// in a routing table (future: siem_sources table lookup).
const DEFAULT_TENANT: &str = "default";

pub async fn start_tcp(addr: &'static str, pipeline: Arc<Pipeline>) {
    let listener = TcpListener::bind(addr).await
        .unwrap_or_else(|e| panic!("Syslog TCP bind {addr} failed: {e}"));
    info!("Syslog TCP listening on {addr}");

    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                let peer_ip = peer.ip().to_string();
                let pl = Arc::clone(&pipeline);
                tokio::spawn(handle_tcp(socket, peer_ip, pl));
            }
            Err(e) => error!("Syslog TCP accept error: {e}"),
        }
    }
}

pub async fn start_udp(addr: &'static str, pipeline: Arc<Pipeline>) {
    let socket = UdpSocket::bind(addr).await
        .unwrap_or_else(|e| panic!("Syslog UDP bind {addr} failed: {e}"));
    info!("Syslog UDP listening on {addr}");

    let mut buf = vec![0u8; 65535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let raw     = String::from_utf8_lossy(&buf[..len]).to_string();
                let peer_ip = peer.ip().to_string();
                let pl      = Arc::clone(&pipeline);
                tokio::spawn(async move {
                    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                        pl.process_syslog(line, &peer_ip, DEFAULT_TENANT, SOURCE_ID).await;
                    }
                });
            }
            Err(e) => error!("Syslog UDP recv error: {e}"),
        }
    }
}

async fn handle_tcp(mut socket: tokio::net::TcpStream, peer_ip: String, pipeline: Arc<Pipeline>) {
    let mut buf = vec![0u8; 65535];
    let mut leftover = String::new();

    loop {
        match socket.read(&mut buf).await {
            Ok(0) => break, // connection closed
            Ok(n) => {
                let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                leftover.push_str(&chunk);

                // Syslog TCP uses newline-framing (RFC 6587 non-octet-counted)
                while let Some(pos) = leftover.find('\n') {
                    let line = leftover[..pos].trim().to_string();
                    leftover = leftover[pos + 1..].to_string();
                    if !line.is_empty() {
                        debug!("Syslog TCP from {peer_ip}: {line}");
                        pipeline.process_syslog(&line, &peer_ip, DEFAULT_TENANT, SOURCE_ID).await;
                    }
                }
            }
            Err(e) => {
                error!("Syslog TCP read error from {peer_ip}: {e}");
                break;
            }
        }
    }
}
