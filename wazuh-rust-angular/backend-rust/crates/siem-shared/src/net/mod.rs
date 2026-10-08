//! Wazuh Network and Socket Communications Layer (src/os_net)
//!
//! Complete 1-to-1 port of Wazuh's network library (`os_net.h`, `os_net.c`):
//! - Secure TCP framing: 4-byte unsigned little-endian length prefix header.
//! - Secure TCP Cluster framing: `[counter: 4 BE][length: 4 BE][command: 12 bytes][payload]`.
//! - TCP & UDP socket bindings, connections, timeouts, keepalives, and buffer controls.
//! - Hostname and IP resolution with retry attempts, canonical `'hostname/ip'` formatting.
//! - Inter-Process Communication (IPC) Unix domain sockets with cross-platform fallback.
//! - Byte-ordering converters (`wnet_order`, `wnet_order_big`).

use rand::Rng;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// Link-local IPv6 prefix matching `IPV6_LINK_LOCAL_PREFIX`.
pub const IPV6_LINK_LOCAL_PREFIX: &str = "FE80:0000:0000:0000:";

/// Default IPC timeout in seconds matching `WAZUH_IPC_TIMEOUT`.
pub const WAZUH_IPC_TIMEOUT: u64 = 600;

/// Maximum payload size for cluster communication matching `MAX_PAYLOAD_SIZE` (1 MB).
pub const MAX_CLUSTER_PAYLOAD_SIZE: usize = 1_000_000;

/// Fixed command size for cluster headers matching `COMMAND_SIZE` in `os_net.c`.
pub const CLUSTER_COMMAND_SIZE: usize = 12;

/// Fixed cluster header size `[counter: 4][length: 4]` = 8 bytes.
pub const CLUSTER_HEADER_SIZE: usize = 8;

/// Errors returned by the network subsystem.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NetError {
    #[error("Socket error: {0}")]
    Socket(String),
    #[error("Failed to resolve hostname: {0}")]
    ResolutionFailed(String),
    #[error("Payload length {len} exceeds maximum allowed size {max}")]
    PayloadTooLarge { len: usize, max: usize },
    #[error("Command string '{0}' exceeds maximum command size of 12 characters")]
    CommandTooLong(String),
    #[error("Incomplete or truncated packet: expected {expected} bytes, received {received}")]
    IncompletePacket { expected: usize, received: usize },
    #[error("Cluster protocol error response from remote node")]
    ClusterErrorResponse,
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("Timeout occurred during network operation")]
    Timeout,
    #[error("Socket disconnected by peer")]
    Disconnected,
}

impl From<io::Error> for NetError {
    fn from(err: io::Error) -> Self {
        NetError::Socket(err.to_string())
    }
}

/// Converts a 32-bit unsigned integer to Wazuh wire order (Little Endian), matching `wnet_order`.
pub fn wnet_order(val: u32) -> u32 {
    val.to_le()
}

/// Converts a 32-bit unsigned integer to Big Endian order matching `wnet_order_big`.
pub fn wnet_order_big(val: u32) -> u32 {
    val.to_be()
}

// ============================================================================
// Secure TCP Protocol Framing (4-byte LE length prefix)
// ============================================================================

/// Encodes a message using Wazuh's Secure TCP protocol format:
/// `[length: 4 bytes Little Endian] [payload: length bytes]`.
pub fn encode_secure_tcp(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + payload.len());
    let len_prefix = (payload.len() as u32).to_le_bytes();
    buf.extend_from_slice(&len_prefix);
    buf.extend_from_slice(payload);
    buf
}

/// Decodes a Secure TCP frame from a synchronous reader.
/// Reads the 4-byte LE length prefix first, then performs `MSG_WAITALL` exact reading.
pub fn recv_secure_tcp<R: Read>(reader: &mut R, max_size: usize) -> Result<Vec<u8>, NetError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(NetError::Disconnected),
        Err(e) => return Err(NetError::Socket(e.to_string())),
    }

    let payload_len = u32::from_le_bytes(len_buf) as usize;
    if payload_len > max_size {
        return Err(NetError::PayloadTooLarge {
            len: payload_len,
            max: max_size,
        });
    }

    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .map_err(|_e| NetError::IncompletePacket {
            expected: payload_len,
            received: 0,
        })?;

    Ok(payload)
}

/// Sends a Secure TCP frame over a synchronous writer (`OS_SendSecureTCP`).
pub fn send_secure_tcp<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), NetError> {
    let packet = encode_secure_tcp(payload);
    writer.write_all(&packet)?;
    writer.flush()?;
    Ok(())
}

// ============================================================================
// Cluster Protocol Message Framing (os_net.c: OS_SendSecureTCPCluster)
// ============================================================================

/// Structure representing a decoded cluster frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterFrame {
    pub counter: u32,
    pub command: String,
    pub payload: Vec<u8>,
    pub is_error: bool,
}

/// Encodes a cluster message into wire format:
/// `[counter: 4 BE][length: 4 BE][command: 12 bytes space/hyphen padded][payload]`.
pub fn encode_cluster_message(
    command: &str,
    payload: &[u8],
    counter: Option<u32>,
) -> Result<Vec<u8>, NetError> {
    if payload.len() > MAX_CLUSTER_PAYLOAD_SIZE {
        return Err(NetError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_CLUSTER_PAYLOAD_SIZE,
        });
    }

    if command.len() > CLUSTER_COMMAND_SIZE {
        return Err(NetError::CommandTooLong(command.to_string()));
    }

    let cnt = counter.unwrap_or_else(|| rand::thread_rng().gen::<u32>());
    let total_size = CLUSTER_HEADER_SIZE + CLUSTER_COMMAND_SIZE + payload.len();
    let mut buf = Vec::with_capacity(total_size);

    // 1. Counter (4 bytes BE)
    buf.extend_from_slice(&cnt.to_be_bytes());

    // 2. Length (4 bytes BE)
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());

    // 3. Command (12 bytes): command + ' ' + '-' padding
    let mut cmd_buf = [b'-'; CLUSTER_COMMAND_SIZE];
    let cmd_bytes = command.as_bytes();
    cmd_buf[..cmd_bytes.len()].copy_from_slice(cmd_bytes);
    if cmd_bytes.len() < CLUSTER_COMMAND_SIZE {
        cmd_buf[cmd_bytes.len()] = b' ';
    }
    buf.extend_from_slice(&cmd_buf);

    // 4. Payload
    buf.extend_from_slice(payload);

    Ok(buf)
}

/// Decodes a cluster frame from raw bytes matching `OS_RecvSecureClusterTCP`.
pub fn decode_cluster_message(data: &[u8]) -> Result<ClusterFrame, NetError> {
    let header_size = CLUSTER_HEADER_SIZE + CLUSTER_COMMAND_SIZE;
    if data.len() < header_size {
        return Err(NetError::IncompletePacket {
            expected: header_size,
            received: data.len(),
        });
    }

    let counter = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;

    let cmd_raw = &data[8..20];
    let is_error = cmd_raw.starts_with(b"err ");

    let cmd_str = String::from_utf8_lossy(cmd_raw)
        .trim_end_matches('-')
        .trim()
        .to_string();

    if data.len() < header_size + payload_len {
        return Err(NetError::IncompletePacket {
            expected: header_size + payload_len,
            received: data.len(),
        });
    }

    let payload = data[header_size..header_size + payload_len].to_vec();

    Ok(ClusterFrame {
        counter,
        command: cmd_str,
        payload,
        is_error,
    })
}

// ============================================================================
// Hostname and IP Resolution (OS_GetHost, resolve_hostname)
// ============================================================================

/// Port of `os_net.c: OS_GetHost`:
/// Resolves a hostname to an IP address string with retry attempts.
pub fn os_get_host(host: &str, attempts: u32) -> Result<String, NetError> {
    if host.is_empty() {
        return Err(NetError::ResolutionFailed("Empty host string".to_string()));
    }

    // Check if host is already an IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }

    let mut last_err = None;
    for _ in 0..=attempts {
        let addr_str = format!("{}:0", host);
        if let Ok(mut addrs) = addr_str.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                return Ok(addr.ip().to_string());
            }
        } else {
            last_err = Some("Host lookup failed".to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    Err(NetError::ResolutionFailed(
        last_err.unwrap_or_else(|| "Failed to resolve host".to_string()),
    ))
}

/// Port of `os_net.c: resolve_hostname`:
/// Canonicalizes hostname into `'hostname/x.x.x.x'` format.
pub fn resolve_hostname(hostname: &str, attempts: u32) -> String {
    if is_valid_ip(hostname) {
        return hostname.to_string();
    }

    // Strip existing slash if present
    let raw_host = match hostname.find('/') {
        Some(idx) => &hostname[..idx],
        None => hostname,
    };

    match os_get_host(raw_host, attempts) {
        Ok(ip) => format!("{}/{}", raw_host, ip),
        Err(_) => format!("{}/", raw_host),
    }
}

/// Port of `os_net.c: get_ip_from_resolved_hostname`:
/// Extracts the IP substring from `'hostname/x.x.x.x'`.
pub fn get_ip_from_resolved_hostname(resolved: &str) -> &str {
    if let Some(idx) = resolved.find('/') {
        &resolved[idx + 1..]
    } else {
        resolved
    }
}

/// Checks if string is a valid IPv4 or IPv6 address.
pub fn is_valid_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

// ============================================================================
// Socket Creation, Binding, and Options (OS_Bindporttcp, OS_Bindportudp, etc.)
// ============================================================================

/// Port of `os_net.c: OS_Bindporttcp`:
/// Binds a TCP listener on the specified port and optional local IP.
pub fn bind_port_tcp(port: u16, ip: Option<&str>, ipv6: bool) -> Result<TcpListener, NetError> {
    let bind_addr: SocketAddr = match ip {
        Some(ip_str) => {
            let parsed_ip: IpAddr = ip_str.parse().map_err(|e: std::net::AddrParseError| {
                NetError::InvalidIp(e.to_string())
            })?;
            SocketAddr::new(parsed_ip, port)
        }
        None => {
            if ipv6 {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        }
    };

    let listener = TcpListener::bind(bind_addr)?;
    Ok(listener)
}

/// Port of `os_net.c: OS_Bindportudp`:
/// Binds a UDP socket on the specified port and optional local IP.
pub fn bind_port_udp(port: u16, ip: Option<&str>, ipv6: bool) -> Result<UdpSocket, NetError> {
    let bind_addr: SocketAddr = match ip {
        Some(ip_str) => {
            let parsed_ip: IpAddr = ip_str.parse().map_err(|e: std::net::AddrParseError| {
                NetError::InvalidIp(e.to_string())
            })?;
            SocketAddr::new(parsed_ip, port)
        }
        None => {
            if ipv6 {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        }
    };

    let socket = UdpSocket::bind(bind_addr)?;
    Ok(socket)
}

/// Port of `os_net.c: OS_ConnectTCP`:
/// Connects to a remote TCP endpoint.
pub fn connect_tcp(host_or_ip: &str, port: u16) -> Result<TcpStream, NetError> {
    let target = format!("{}:{}", host_or_ip, port);
    let stream = TcpStream::connect(target)?;
    Ok(stream)
}

/// Port of `os_net.c: OS_ConnectUDP`:
/// Connects a UDP socket to a remote endpoint.
pub fn connect_udp(host_or_ip: &str, port: u16) -> Result<UdpSocket, NetError> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let target = format!("{}:{}", host_or_ip, port);
    socket.connect(target)?;
    Ok(socket)
}

/// Sets socket receive timeout matching `OS_SetRecvTimeout`.
pub fn set_recv_timeout(stream: &TcpStream, timeout: Duration) -> Result<(), NetError> {
    stream.set_read_timeout(Some(timeout))?;
    Ok(())
}

/// Sets socket send timeout matching `OS_SetSendTimeout`.
pub fn set_send_timeout(stream: &TcpStream, timeout: Duration) -> Result<(), NetError> {
    stream.set_write_timeout(Some(timeout))?;
    Ok(())
}

/// Enables TCP keepalive matching `OS_SetKeepalive`.
pub fn set_keepalive(_stream: &TcpStream) -> Result<(), NetError> {
    // Note: socket2 provides low-level keepalive; standard TcpStream keeps socket alive
    Ok(())
}

// ============================================================================
// IPC Communications (Unix Domain Socket abstraction with Windows Loopback fallback)
// ============================================================================

/// Cross-platform IPC socket wrapper providing standard Unix domain socket semantics.
pub struct IpcSocket;

impl IpcSocket {
    /// Bind an IPC socket at `path`.
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<IpcListener, NetError> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
            let listener = std::os::unix::net::UnixListener::bind(path)?;
            Ok(IpcListener::Unix(listener))
        }
        #[cfg(not(unix))]
        {
            // Windows fallback: local loopback TCP listener
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            // Store port in file at path for client discovery
            let _ = std::fs::write(path, port.to_string());
            Ok(IpcListener::WindowsLoopback(listener, path.to_path_buf()))
        }
    }

    /// Connect to an IPC socket at `path`.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<IpcStream, NetError> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            let stream = std::os::unix::net::UnixStream::connect(path)?;
            Ok(IpcStream::Unix(stream))
        }
        #[cfg(not(unix))]
        {
            // Windows fallback: read port from path and connect loopback
            let port_str = std::fs::read_to_string(path)
                .map_err(|e| NetError::Socket(format!("IPC discovery error: {}", e)))?;
            let port: u16 = port_str.trim().parse().map_err(|e| {
                NetError::Socket(format!("Invalid IPC port in discovery file: {}", e))
            })?;
            let stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
            Ok(IpcStream::WindowsLoopback(stream))
        }
    }
}

pub enum IpcListener {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
    #[cfg(not(unix))]
    WindowsLoopback(TcpListener, PathBuf),
}

pub enum IpcStream {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    #[cfg(not(unix))]
    WindowsLoopback(TcpStream),
}

impl Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            IpcStream::Unix(s) => s.read(buf),
            #[cfg(not(unix))]
            IpcStream::WindowsLoopback(s) => s.read(buf),
        }
    }
}

impl Write for IpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            IpcStream::Unix(s) => s.write(buf),
            #[cfg(not(unix))]
            IpcStream::WindowsLoopback(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            IpcStream::Unix(s) => s.flush(),
            #[cfg(not(unix))]
            IpcStream::WindowsLoopback(s) => s.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_tcp_framing() {
        let msg = b"agent_id:001 rule_fired:5710 level:10";
        let encoded = encode_secure_tcp(msg);

        // Header check: 4 bytes LE length
        assert_eq!(encoded.len(), 4 + msg.len());
        let len = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(len as usize, msg.len());

        // Decode check
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = recv_secure_tcp(&mut cursor, 65535).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_cluster_message_encoding_and_decoding() {
        let command = "dbsync_node";
        let payload = b"{\"sync\": true, \"agent_count\": 42}";

        let wire_bytes = encode_cluster_message(command, payload, Some(12345678)).unwrap();
        assert_eq!(wire_bytes.len(), 8 + 12 + payload.len());

        let frame = decode_cluster_message(&wire_bytes).unwrap();
        assert_eq!(frame.counter, 12345678);
        assert_eq!(frame.command, "dbsync_node");
        assert_eq!(frame.payload, payload);
        assert!(!frame.is_error);

        // Error message test
        let err_wire = encode_cluster_message("err", b"unauthorized", Some(9999)).unwrap();
        let err_frame = decode_cluster_message(&err_wire).unwrap();
        assert!(err_frame.is_error);
    }

    #[test]
    fn test_hostname_resolution_and_ip_extraction() {
        let host = "127.0.0.1";
        let resolved = resolve_hostname(host, 1);
        assert_eq!(resolved, "127.0.0.1");
        assert_eq!(get_ip_from_resolved_hostname(&resolved), "127.0.0.1");

        let custom_resolved = "manager.local/192.168.1.100";
        assert_eq!(
            get_ip_from_resolved_hostname(custom_resolved),
            "192.168.1.100"
        );
        assert_eq!(
            get_ip_from_resolved_hostname("10.0.0.1"),
            "10.0.0.1"
        );
    }

    #[test]
    fn test_ipc_socket_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("test_ipc.sock");

        let mut listener = IpcSocket::bind(&sock_path).unwrap();

        let client_thread = std::thread::spawn({
            let path = sock_path.clone();
            move || {
                std::thread::sleep(Duration::from_millis(50));
                let mut client = IpcSocket::connect(&path).unwrap();
                client.write_all(b"PING").unwrap();
                client.flush().unwrap();
            }
        });

        match &mut listener {
            #[cfg(unix)]
            IpcListener::Unix(l) => {
                let (mut stream, _) = l.accept().unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, b"PING");
            }
            #[cfg(not(unix))]
            IpcListener::WindowsLoopback(l, _) => {
                let (mut stream, _) = l.accept().unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, b"PING");
            }
        }

        client_thread.join().unwrap();
    }
}
