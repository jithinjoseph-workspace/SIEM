//! The analysis engine's input and its load, as a datagram sender sees them.

use std::path::Path;
use std::time::Duration;

use siem_ipc::mq;

/// Datagrams the engine may be behind, well inside its input channel and receive buffer.
pub const LAG_MAX: u64 = 2_000;
/// How full its fullest decoder queue may get.
pub const QUEUE_MAX: f64 = 0.25;
/// With other senders on the engine, whose datagrams cannot be told apart: queue usage only.
pub const QUEUE_MAX_SHARED: f64 = 0.15;
pub const LOAD_EVERY: Duration = Duration::from_millis(500);
/// The analysis thread answers between two messages: longer than this, it is stuck behind.
pub const LOAD_TIMEOUT: Duration = Duration::from_secs(1);
pub const LOAD_SOCKET: &str = "queue/sockets/analysis";
/// The engine's largest message.
pub const MAX_MESSAGE: usize = siem_ipc::OS_MAXSTR;

/// The hand-off label of an agent: `[<id>] (<name>) <ip>`.
pub fn source(agent_id: &str, name: &str, ip: &str) -> Option<String> {
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    Some(format!("[{id}] ({name}) {}", if ip.is_empty() { "any" } else { ip }))
}

/// One event as the engine reads it: `<q>:<location, ':' and '|' escaped>:<message>` in the
/// secure form, marked as coming from the platform. `None`: too long for the queue.
pub fn datagram(source: &str, q: u8, location: &str, message: &str) -> Option<Vec<u8>> {
    let mut agent_msg = vec![q, b':'];
    agent_msg.extend(mq::wstr_escape(location.as_bytes(), b'|', b':', 8193));
    agent_msg.push(b':');
    agent_msg.extend_from_slice(message.as_bytes());
    let mut m = mq::format_msg(&agent_msg, source, mq::queues::SECURE_MQ)?;
    m.insert(0, siem_ipc::platform_stream::FROM_API);
    Some(m)
}

/// The datagrams sent and not yet received, from readings of both counters.
#[derive(Default)]
pub struct Lag {
    last: Option<(u64, u64)>,
    lag: u64,
    /// Set by the reading that showed a restart: what may have been in the engine's buffer.
    pub lost_at_restart: Option<u64>,
}

impl Lag {
    pub fn observe(&mut self, sent: u64, received: u64) -> u64 {
        self.lost_at_restart = None;
        if let Some((s, r)) = self.last {
            let new = sent.saturating_sub(s);
            // a lower count: the engine restarted and what it held is gone
            let got = if received < r {
                self.lost_at_restart = Some(self.lag);
                self.lag = 0;
                received
            } else {
                received - r
            };
            // nothing moved: the rest was lost on the way, it is not waiting to be read
            self.lag = if new == 0 && got == 0 { 0 } else { (self.lag + new).saturating_sub(got) };
        }
        self.last = Some((sent, received));
        self.lag
    }
}

/// The engine's load: how full its fullest queue is (0 to 1) and the platform datagrams it read.
/// Err(true): it took too long to answer. Err(false): it is not there.
pub async fn load(path: &Path) -> Result<(f64, u64), bool> {
    use siem_ipc::{framing, local::LocalStream};
    let mut s = LocalStream::connect(path).await.map_err(|_| false)?;
    let asked = async {
        framing::send(&mut s, b"{\"command\":\"getload\"}").await.ok()?;
        framing::recv(&mut s, 4096).await.ok()
    };
    let r = tokio::time::timeout(LOAD_TIMEOUT, asked).await.map_err(|_| true)?.ok_or(false)?;
    let v: serde_json::Value = serde_json::from_slice(&r).map_err(|_| false)?;
    Ok((v["data"]["queue_usage"].as_f64().ok_or(false)?, v["data"]["received"].as_f64().ok_or(false)? as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lag_follows_sent_and_received() {
        let mut l = Lag::default();
        assert_eq!(l.observe(100, 100), 0);
        assert_eq!(l.observe(3_100, 200), 2_900);
        assert_eq!(l.observe(3_200, 3_000), 200);
        assert_eq!(l.observe(3_200, 3_000), 0, "no movement: lost, not waiting");
        assert_eq!(l.observe(3_300, 3_000), 100);
        assert_eq!(l.observe(3_400, 50), 50, "the engine restarted");
        assert_eq!(l.lost_at_restart, Some(100));
        assert_eq!(l.observe(3_400, 50), 0);
    }

    #[test]
    fn datagram_form() {
        let m = datagram("[007] (pc) any", b'f', "Event:Channel", "hello").unwrap();
        assert_eq!(m[0], siem_ipc::platform_stream::FROM_API);
        let t = String::from_utf8_lossy(&m[1..]);
        assert_eq!(t, "f:[007] (pc) any->Event|:Channel:hello");
        assert_eq!(source("x", "n", ""), None);
        assert_eq!(source("7", "n", "").as_deref(), Some("[007] (n) any"));
    }
}
