//! `siem-ipc`: the local IPC ProVigil daemons use to talk to each other.
//!
//! * [`local`]: datagram and stream "Unix" sockets at ProVigil paths
//!   (`queue/sockets/queue`, `queue/db/wdb`, ...). On Unix these are real
//!   `AF_UNIX` sockets, so the Rust daemons interoperate with upstream C daemons.
//!   On Windows (development only) each socket path maps to a loopback port,
//!   written to `<path>.port`.
//! * [`framing`]: `OS_SendSecureTCP` / `OS_RecvSecureTCP` (4-byte
//!   little-endian length prefix).
//! * [`mq`]: `SendMSG` formatting (`<queue>:<escaped location>:<message>`).
//! * [`wdbc`]: the provigil-db client (`wdbc_query_ex`, `wdbc_parse_result`).

pub mod framing;
pub mod local;
pub mod mq;
pub mod mq_op;
#[cfg(unix)]
pub mod os_net;
#[cfg(windows)]
#[path = "os_net_win.rs"]
pub mod os_net;
pub mod wdbc;

/// `OS_MAXSTR`
pub const OS_MAXSTR: usize = 65536;
pub mod platform_stream;
