use std::net::SocketAddr;
use chrono::Utc;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info};
use siem_core::{Agent, AgentStatus, EventSource, RawEvent};
use crate::syslog_tenancy::Device;
use crate::{tenancy, AppState};

/// Who sent a line: a plain-syslog address, or a TLS device (its certificate).
pub enum Origin {
    Ip,
    Device(Device),
}

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

    let state_tls = state.clone();
    tokio::spawn(async move {
        crate::syslog_tenancy::start_tls(state_tls).await;
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
                        process_syslog_line(line.trim(), &peer_ip, &Origin::Ip, &state_clone).await;
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
                tokio::spawn(read_lines(socket, peer_ip, state_clone, Origin::Ip));
            }
            Err(e) => {
                error!("Syslog TCP accept error: {}", e);
            }
        }
    }
}

/// Reads one syslog stream (plain TCP or TLS): RFC 6587 newline framing or
/// RFC 5425 octet counting (`<len> <msg>`). A TLS device that is revoked
/// stops at its next message.
pub async fn read_lines<R: AsyncRead + Unpin>(mut r: R, peer_ip: String, state: AppState, origin: Origin) {
    let mut buf = vec![0u8; 65535];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!("Syslog stream from {} finished: {}", peer_ip, e);
                break;
            }
        };
        pending.extend_from_slice(&buf[..n]);
        if pending.len() > 1 << 20 {
            // no frame end within 1 MiB: not syslog
            debug!("Syslog stream from {} dropped: oversized frame", peer_ip);
            break;
        }
        while let Some((msg, used)) = next_frame(&pending) {
            let line = String::from_utf8_lossy(&msg).trim().to_string();
            pending.drain(..used);
            if line.is_empty() {
                continue;
            }
            if let Origin::Device(d) = &origin {
                if !crate::syslog_tenancy::get().map(|st| st.device_active(&d.id)).unwrap_or(false) {
                    info!("Syslog TLS device '{}' was revoked; closing", d.name);
                    return;
                }
            }
            // in order, one message at a time
            process_syslog_line(&line, &peer_ip, &origin, &state).await;
        }
    }
}

/// The next complete message and the bytes it used.
fn next_frame(p: &[u8]) -> Option<(Vec<u8>, usize)> {
    let digits = p.iter().take_while(|c| c.is_ascii_digit()).count();
    // an octet count is always followed by the message's <PRI>
    if digits > 0 && digits < 10 && p.get(digits) == Some(&b' ') && p.get(digits + 1).map_or(true, |&c| c == b'<') {
        let len: usize = std::str::from_utf8(&p[..digits]).ok()?.parse().ok()?;
        let start = digits + 1;
        return (p.len() >= start + len).then(|| (p[start..start + len].to_vec(), start + len));
    }
    let nl = p.iter().position(|&c| c == b'\n')?;
    Some((p[..nl].to_vec(), nl + 1))
}

async fn process_syslog_line(line: &str, peer_ip: &str, origin: &Origin, state: &AppState) {
    // the tenant: the device's certificate, else the source-IP map, else the default tenant
    let (agent_id, agent_name, tenant) = match origin {
        Origin::Device(d) => (format!("syslog-{}", d.id), d.name.clone(), d.tenant_id.clone()),
        Origin::Ip => {
            let t = crate::syslog_tenancy::get().and_then(|st| st.tenant_for_ip(peer_ip)).unwrap_or_else(|| tenancy::DEFAULT_TENANT.to_string());
            (format!("syslog-{}", peer_ip), format!("net-device-{}", peer_ip), t)
        }
    };
    state.agent_tenants.write().unwrap().insert(agent_id.clone(), tenant.clone());

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
    metadata.insert("tenant_id".to_string(), tenant.clone());

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
        let alert = tenancy::tag_alert(alert, &tenant);
        state.alerts.write().unwrap().push(alert.clone());
        state.db.insert_alert(&alert).await;
        let _ = state.broadcast_tx.send(alert);
    }

    state.db.insert_event(&raw_event).await;
    state.events.write().unwrap().push(raw_event);
}

#[cfg(test)]
mod tests {
    use super::next_frame;

    #[test]
    fn framing() {
        assert_eq!(next_frame(b"<13>hello\nrest"), Some((b"<13>hello".to_vec(), 10)));
        assert_eq!(next_frame(b"9 <13>hello12 <1"), Some((b"<13>hello".to_vec(), 11)));
        // digits and a space without a <PRI> after them: newline framing
        assert_eq!(next_frame(b"2024 Jan 1 host x\n"), Some((b"2024 Jan 1 host x".to_vec(), 18)));
        assert_eq!(next_frame(b"20 <13>short"), None);
        assert_eq!(next_frame(b"<13>no end yet"), None);
        // a message starting with digits but no space after them is newline-framed
        assert_eq!(next_frame(b"2024-01-01 x\n"), Some((b"2024-01-01 x".to_vec(), 13)));
    }
}
