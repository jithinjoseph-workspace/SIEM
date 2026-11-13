//! Local IPC of the ProVigil manager services.
//!
//! * [`local`]: blocking sockets at manager paths (`queue/db/wdb`, `queue/router/<topic>`, ...):
//!   a Unix socket on Unix; on Windows a loopback TCP port whose number is in `<path>.port`.
//! * [`aio`]: the same for async code, plus datagram queues and async framing.
//! * [`framing`]: messages preceded by their length (u32, little endian).
//! * [`agentdb`]: the agent-database clients (`queue/db/wdb`), blocking and async.
//! * [`queue`]: the message format of the detection engine's event queue.
//! * [`platform_stream`]: the write-ahead stream of results to siem-api.

pub mod agentdb;
pub mod aio;
pub mod framing;
pub mod local;
pub mod platform_stream;
pub mod queue;

/// The largest message on the local sockets.
pub const MAX_MESSAGE: usize = 65536;
