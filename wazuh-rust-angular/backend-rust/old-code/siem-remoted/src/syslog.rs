//! Port of `src/remoted/syslog.c` and `syslogtcp.c`: remote syslog
//! receivers for `<connection>syslog</connection>` blocks.

use crate::Remoted;
use siem_ipc::mq::queues::SYSLOG_MQ;
use siem_ipc::OS_MAXSTR;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};

/// `OS_IPNotAllowed`
pub fn ip_not_allowed(r: &Remoted, srcip: &str) -> bool {
    let cfg = &r.settings.remote;
    if !cfg.denyips.is_empty() && siem_regex::ip_found_list(srcip, &cfg.denyips) {
        return true;
    }
    if !cfg.allowips.is_empty() && siem_regex::ip_found_list(srcip, &cfg.allowips) {
        return false;
    }
    true
}

/// `w_get_pri_header_len`
pub fn pri_header_len(msg: &[u8]) -> usize {
    if msg.first() == Some(&b'<') {
        if let Some(p) = msg[1..].iter().position(|&c| c == b'>') {
            return p + 2;
        }
    }
    0
}

impl Remoted {
    /// `HandleSyslog`
    pub(crate) async fn syslog_udp(self: Arc<Self>, sock: UdpSocket, port: i32) {
        tracing::info!("Started. Listening on port {port}/UDP (syslog).");
        let mut buf = vec![0u8; OS_MAXSTR];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
            if n == 0 {
                continue;
            }
            let mut msg = &buf[..n];
            if let Some(p) = msg.iter().position(|&b| b == 0) {
                msg = &msg[..p];
            }
            if msg.last() == Some(&b'\n') {
                msg = &msg[..msg.len() - 1];
            }
            let srcip = peer.ip().to_string();
            let body = &msg[pri_header_len(msg)..];
            if ip_not_allowed(&self, &srcip) {
                tracing::warn!("(1213): Message from '{srcip}' not allowed. Cannot find the ID of the agent.");
                continue;
            }
            self.mq.send_msg(body, &srcip, SYSLOG_MQ).await;
        }
    }

    /// `HandleSyslogTCP` (one task per client instead of one process).
    pub(crate) async fn syslog_tcp(self: Arc<Self>, l: TcpListener, port: i32) {
        tracing::info!("Started. Listening on port {port}/TCP (syslog).");
        loop {
            let Ok((mut s, peer)) = l.accept().await else {
                tracing::warn!("Accepting TCP connection from client failed");
                continue;
            };
            let srcip = peer.ip().to_string();
            if ip_not_allowed(&self, &srcip) {
                tracing::warn!("(1213): Message from '{srcip}' not allowed. Cannot find the ID of the agent.");
                continue;
            }
            let me = self.clone();
            tokio::spawn(async move {
                let mut data: Vec<u8> = Vec::new();
                let mut buf = vec![0u8; OS_MAXSTR];
                loop {
                    let room = OS_MAXSTR.saturating_sub(data.len());
                    if room == 0 {
                        // The C buffer is full without a newline: nothing more can be read.
                        break;
                    }
                    let n = match s.read(&mut buf[..room]).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    data.extend_from_slice(&buf[..n]);
                    // send_buffer: every complete line goes to the queue
                    while let Some(p) = data.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = data.drain(..=p).collect();
                        let mut line = &line[..line.len() - 1];
                        if let Some(z) = line.iter().position(|&b| b == 0) {
                            line = &line[..z];
                        }
                        let body = &line[pri_header_len(line)..];
                        me.mq.send_msg(body, &srcip, SYSLOG_MQ).await;
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::pri_header_len;

    #[test]
    fn pri_header() {
        assert_eq!(pri_header_len(b"<13>Oct  5 x"), 4);
        assert_eq!(pri_header_len(b"<13 no close"), 0);
        assert_eq!(pri_header_len(b"plain"), 0);
    }
}
