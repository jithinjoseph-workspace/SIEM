//! What the agent's inventory and the live-response program both list.

use serde::{Deserialize, Serialize};

#[cfg(windows)]
pub mod win;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub command_line: Option<String>,
    pub owner: Option<String>,
    pub parent_pid: u32,
    pub memory_mb: u64,
    pub cpu_time_ms: u64,
    pub start_time: u64,
    /// base priority
    pub priority: i32,
    /// thread count
    pub threads: u32,
    /// the committed (private) virtual memory
    pub virtual_kb: Option<u64>,
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub startup_type: String,
    pub account: Option<String>,
    /// the executable / image path
    pub path: Option<String>,
    /// `None` when stopped
    pub pid: Option<u32>,
    pub description: Option<String>,
}

/// A TCP connection or listener, or a UDP endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortInfo {
    /// `tcp`, `tcp6`, `udp` or `udp6`
    pub protocol: String,
    pub local_ip: String,
    pub local_port: u16,
    /// `None` for UDP and listeners
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    /// lower case (`listening`, `established`, ...); `None` for UDP
    pub state: Option<String>,
    pub pid: u32,
    /// the name of the owning process
    pub process: Option<String>,
}

/// The trimmed text, or `None` when it is empty.
pub fn nonempty(s: &str) -> Option<String> {
    let t = s.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    (!t.is_empty()).then(|| t.to_string())
}

/// The lower-case name of a TCP state number (the IP Helper `MIB_TCP_STATE` values).
pub fn tcp_state(n: u32) -> &'static str {
    match n {
        1 => "closed",
        2 => "listening",
        3 => "syn_sent",
        4 => "syn_received",
        5 => "established",
        6 => "fin_wait1",
        7 => "fin_wait2",
        8 => "close_wait",
        9 => "closing",
        10 => "last_ack",
        11 => "time_wait",
        12 => "delete_tcb",
        _ => "unknown",
    }
}
