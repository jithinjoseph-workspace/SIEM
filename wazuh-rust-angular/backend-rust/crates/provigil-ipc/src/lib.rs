//! Local IPC of the ProVigil manager services.
//!
//! * [`local`]: sockets at manager paths (`queue/db/wdb`, `queue/router/<topic>`, ...): a Unix
//!   socket on Unix; on Windows a loopback TCP port whose number is in `<path>.port`.
//! * [`framing`]: messages preceded by their length (u32, little endian).
//! * [`agentdb`]: the agent-database client (`queue/db/wdb`).
//! * [`platform_stream`]: the write-ahead stream of results to siem-api.

pub mod agentdb;
pub mod framing;
pub mod local;
pub mod platform_stream;

/// The largest message on the local sockets.
pub const MAX_MESSAGE: usize = 65536;
