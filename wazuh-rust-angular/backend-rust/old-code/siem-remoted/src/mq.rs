//! Delivery of events to analysisd (`StartMQ` + `SendMSG` with reconnection).

use siem_ipc::local::DatagramSender;
use siem_ipc::mq::format_msg;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::Mutex;

/// Where remoted sends events.
#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    /// Deliver one fully formatted queue message.
    async fn deliver(&self, msg: Vec<u8>) -> bool;
}

/// `queue/sockets/queue` datagram socket, reconnecting like
/// `StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)`.
pub struct QueueSocket {
    path: PathBuf,
    sock: Mutex<Option<DatagramSender>>,
}

impl QueueSocket {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), sock: Mutex::new(None) }
    }

    async fn connect_forever(&self) -> DatagramSender {
        loop {
            match DatagramSender::connect(&self.path).await {
                Ok(s) => return s,
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    }
}

#[async_trait::async_trait]
impl EventSink for QueueSocket {
    async fn deliver(&self, mut msg: Vec<u8>) -> bool {
        // OS_SendUnix(queue, tmpstr, 0) sends strlen + 1 bytes
        msg.push(0);
        let mut g = self.sock.lock().await;
        if g.is_none() {
            *g = Some(self.connect_forever().await);
        }
        if g.as_ref().unwrap().send(&msg).await.is_ok() {
            return true;
        }
        tracing::error!("(1210): Queue '{}' not accessible.", self.path.display());
        *g = Some(self.connect_forever().await);
        tracing::info!("Successfully reconnected to '{}'", self.path.display());
        match g.as_ref().unwrap().send(&msg).await {
            Ok(()) => true,
            Err(e) => {
                tracing::error!("(1210): Queue '{}' not accessible: {e}", self.path.display());
                false
            }
        }
    }
}

/// In-process sink (used when remoted runs inside another binary or in tests).
pub struct ChannelSink(pub tokio::sync::mpsc::UnboundedSender<Vec<u8>>);

#[async_trait::async_trait]
impl EventSink for ChannelSink {
    async fn deliver(&self, msg: Vec<u8>) -> bool {
        self.0.send(msg).is_ok()
    }
}

/// `SendMSG` front-end.
pub struct Mq {
    pub sink: Box<dyn EventSink>,
}

impl Mq {
    /// Returns true when the message was delivered or deliberately dropped
    /// (keepalive locations), mirroring `SendMSG() >= 0`.
    pub async fn send_msg(&self, message: &[u8], locmsg: &str, loc: u8) -> bool {
        match format_msg(message, locmsg, loc) {
            Some(m) => self.sink.deliver(m).await,
            None => {
                if message.len() >= 2 && message[1] != b':' {
                    tracing::error!("(1106): String not correctly formatted.");
                }
                true
            }
        }
    }
}
