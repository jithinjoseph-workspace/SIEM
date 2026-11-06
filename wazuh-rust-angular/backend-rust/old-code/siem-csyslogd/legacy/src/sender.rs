//! UDP Syslog Socket Sender (`src/os_csyslogd/alert.c`, `src/os_net/os_net.c`)
//!
//! Manages UDP socket communication, DNS resolution, and auto-reconnection
//! for remote Syslog collectors.

use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use tracing::{debug, info, warn};

/// Manages UDP socket connection to a Syslog server destination.
#[derive(Debug)]
pub struct UdpSyslogSender {
    pub server: String,
    pub port: u16,
    socket: Option<UdpSocket>,
}

impl UdpSyslogSender {
    pub fn new(server: String, port: u16) -> Self {
        Self {
            server,
            port,
            socket: None,
        }
    }

    /// Resolves target address and connects the UDP socket.
    pub fn connect(&mut self) -> io::Result<()> {
        let addr_str = format!("{}:{}", self.server, self.port);
        debug!("Resolving and connecting UDP to syslog server: {}", addr_str);

        // Resolve addresses
        let addrs: Vec<_> = addr_str.to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Could not resolve hostname '{}'", self.server),
            ));
        }

        // Bind local ephemeral port
        let local_addr = if addrs[0].is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let sock = UdpSocket::bind(local_addr)?;
        sock.connect(addrs[0])?;
        info!("Forwarding alerts via syslog to: '{}:{}'", self.server, self.port);

        self.socket = Some(sock);
        Ok(())
    }

    /// Sends a formatted syslog message to the destination server.
    /// If socket is disconnected or error occurs, reconnects and retries once.
    pub fn send(&mut self, msg: &str) -> io::Result<()> {
        if self.socket.is_none() {
            self.connect()?;
        }

        let res = if let Some(ref sock) = self.socket {
            sock.send(msg.as_bytes())
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "Socket not connected"))
        };

        match res {
            Ok(bytes) => {
                debug!("Sent {} bytes to {}:{}", bytes, self.server, self.port);
                Ok(())
            }
            Err(err) => {
                warn!("Syslog send failed to {}:{}: {}. Attempting reconnect...", self.server, self.port, err);
                self.socket = None;
                self.connect()?;
                if let Some(ref sock) = self.socket {
                    sock.send(msg.as_bytes())?;
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Failed to reconnect UDP socket",
                    ))
                }
            }
        }
    }

    /// Returns whether the socket is currently initialized
    pub fn is_connected(&self) -> bool {
        self.socket.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_sender_loopback() {
        // Start a mock UDP receiver on 127.0.0.1:0
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = receiver.local_addr().unwrap().port();

        let mut sender = UdpSyslogSender::new("127.0.0.1".to_string(), port);
        sender.connect().unwrap();
        assert!(sender.is_connected());

        let test_msg = "<132>Jul 10 12:00:00 localhost ossec: Alert Level: 3; Rule: 100 - Test; Location: sys;";
        sender.send(test_msg).unwrap();

        let mut buf = [0u8; 1024];
        let (bytes, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..bytes], test_msg.as_bytes());
    }
}
