//! The analysis engine's input and its load, as a datagram sender sees them.

use std::path::Path;
use std::time::Duration;

use siem_ipc::mq;

/// Datagrams the engine may be behind, well inside its input channel and receive buffer.
pub const LAG_MAX: u64 = 2_000;
/// How full its fullest decoder queue may get.
pub const QUEUE_MAX: f64 = 0.25;
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
/// secure form, marked as coming from gateway `sender`. `None`: too long for the queue.
pub fn datagram(sender: u8, source: &str, q: u8, location: &str, message: &str) -> Option<Vec<u8>> {
    let mut agent_msg = vec![q, b':'];
    agent_msg.extend(mq::wstr_escape(location.as_bytes(), b'|', b':', 8193));
    agent_msg.push(b':');
    agent_msg.extend_from_slice(message.as_bytes());
    let mut m = mq::format_msg(&agent_msg, source, mq::queues::SECURE_MQ)?;
    m.splice(0..0, [siem_ipc::platform_stream::FROM_GATEWAY, sender]);
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

/// The engine's load: how full its fullest queue is (0 to 1) and the datagrams of gateway `sender`
/// it read. Err(true): it took too long to answer. Err(false): it is not there.
pub async fn load(path: &Path, sender: u8) -> Result<(f64, u64), bool> {
    use siem_ipc::{framing, local::LocalStream};
    let mut s = LocalStream::connect(path).await.map_err(|_| false)?;
    let asked = async {
        framing::send(&mut s, b"{\"command\":\"getload\"}").await.ok()?;
        framing::recv(&mut s, 4096).await.ok()
    };
    let r = tokio::time::timeout(LOAD_TIMEOUT, asked).await.map_err(|_| true)?.ok_or(false)?;
    let v: serde_json::Value = serde_json::from_slice(&r).map_err(|_| false)?;
    let usage = v["data"]["queue_usage"].as_f64().ok_or(false)?;
    // an engine without per-sender counts cannot tell this gateway's datagrams: not one to feed
    let senders = v["data"]["senders"].as_object().ok_or(false)?;
    Ok((usage, senders.get(&sender.to_string()).and_then(serde_json::Value::as_u64).unwrap_or(0)))
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
        let m = datagram(9, "[007] (pc) any", b'f', "Event:Channel", "hello").unwrap();
        assert_eq!(m[..2], [siem_ipc::platform_stream::FROM_GATEWAY, 9]);
        let t = String::from_utf8_lossy(&m[2..]);
        assert_eq!(t, "f:[007] (pc) any->Event|:Channel:hello");
        assert_eq!(source("x", "n", ""), None);
        assert_eq!(source("7", "n", "").as_deref(), Some("[007] (n) any"));
    }

    /// What the engine answers `getload`; the socket gone, or an analysis thread that does not
    /// answer, are told apart.
    #[tokio::test(flavor = "multi_thread")]
    async fn load_is_read_from_its_socket() {
        use siem_ipc::{framing, local::StreamListener};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("analysis");
        let l = StreamListener::bind(&path).await.unwrap();
        let server = tokio::spawn(async move {
            let mut s = l.accept().await.unwrap();
            assert_eq!(framing::recv(&mut s, 4096).await.unwrap(), b"{\"command\":\"getload\"}");
            framing::send(&mut s, br#"{"error":0,"message":"ok","data":{"queue_usage":0.5,"received":1,"senders":{"3":70000}}}"#).await.unwrap();
            // the next one stays unanswered
            let mut stuck = l.accept().await.unwrap();
            let _ = framing::recv(&mut stuck, 4096).await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        assert_eq!(load(&path, 3).await, Ok((0.5, 70_000)));
        assert_eq!(load(&path, 3).await, Err(true));
        server.abort();
        assert_eq!(load(&dir.path().join("gone"), 3).await, Err(false));
    }
}
