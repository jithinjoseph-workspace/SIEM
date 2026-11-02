//! The platform's stream (not in Wazuh): when siem-api starts a manager daemon with
//! `SIEM_STREAM_ADDR` (its loopback listener) and `SIEM_STREAM_TOKEN`, the daemon sends
//! what it would write to a file (analysisd: alerts and archived events; the
//! vulnerability scanner: its result documents) to siem-api, which stores it in
//! ClickHouse. A writer thread sends them, so the daemon never waits on the network;
//! while siem-api is away or busy they wait in a bounded queue, and lines are dropped
//! (and counted) only when it is full.
//!
//! Frames: `[u32 LE length of what follows][kind][JSON]`, kind `H` (the token, first),
//! `A` (alert), `E` (archived event) or `V` (vulnerability result).

use std::io::Write;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::time::Duration;

/// Lines waiting while siem-api is away or busy.
pub const CAPACITY: usize = 50_000;

pub const ALERT: u8 = b'A';
pub const EVENT: u8 = b'E';
pub const HELLO: u8 = b'H';
pub const VULNERABILITY: u8 = b'V';

pub struct Stream {
    tx: SyncSender<Vec<u8>>,
    pub dropped: u64,
}

/// One frame.
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
    let mut f = Vec::with_capacity(5 + payload.len());
    f.extend_from_slice(&((payload.len() + 1) as u32).to_le_bytes());
    f.push(kind);
    f.extend_from_slice(payload);
    f
}

impl Stream {
    /// The stream siem-api asked for, with its writer thread; None when not asked.
    pub fn from_env() -> Option<Stream> {
        let addr = std::env::var("SIEM_STREAM_ADDR").ok().filter(|a| !a.is_empty())?;
        let token = std::env::var("SIEM_STREAM_TOKEN").ok().filter(|t| !t.is_empty())?;
        let (tx, rx) = sync_channel::<Vec<u8>>(CAPACITY);
        std::thread::Builder::new().name("siem-stream".into()).spawn(move || writer(&addr, &token, rx)).ok()?;
        Some(Stream { tx, dropped: 0 })
    }

    /// Queues one alert or event line. Some(warning) every 1,000 lines dropped.
    pub fn send(&mut self, kind: u8, json: &[u8]) -> Option<String> {
        match self.tx.try_send(frame(kind, json)) {
            Ok(()) => None,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped += 1;
                (self.dropped % 1000 == 1).then(|| format!("siem-api stream: queue of {CAPACITY} full, {} line(s) dropped so far", self.dropped))
            }
        }
    }
}

/// Sends the queued frames, connecting (again) when needed; a frame leaves the
/// queue only once it was written whole.
fn writer(addr: &str, token: &str, rx: Receiver<Vec<u8>>) {
    let mut conn: Option<std::net::TcpStream> = None;
    let mut pending: Option<Vec<u8>> = None;
    loop {
        let f = match pending.take() {
            Some(f) => f,
            None => match rx.recv() {
                Ok(f) => f,
                Err(_) => return,
            },
        };
        if conn.is_none() {
            conn = std::net::TcpStream::connect(addr).ok().and_then(|mut s| {
                let _ = s.set_nodelay(true);
                s.write_all(&frame(HELLO, token.as_bytes())).ok().map(|_| s)
            });
            if conn.is_none() {
                pending = Some(f);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        }
        if conn.as_mut().is_some_and(|s| s.write_all(&f).is_err()) {
            // siem-api drops a frame cut short with its connection: this one goes again
            conn = None;
            pending = Some(f);
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn read_frame(r: &mut impl Read) -> Option<(u8, Vec<u8>)> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len).ok()?;
        let mut b = vec![0u8; u32::from_le_bytes(len) as usize];
        r.read_exact(&mut b).ok()?;
        Some((b[0], b[1..].to_vec()))
    }

    #[test]
    fn frames_reach_the_listener_after_it_appears() {
        assert_eq!(frame(ALERT, b"{\"a\":1}\n"), [&8u32.to_le_bytes()[..], b"A{\"a\":1}"].concat());
        // the listener starts after the first lines were queued: nothing is lost
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        drop(l);
        std::env::set_var("SIEM_STREAM_ADDR", &addr);
        std::env::set_var("SIEM_STREAM_TOKEN", "t0k");
        let mut s = Stream::from_env().unwrap();
        assert!(s.send(ALERT, b"{\"n\":1}\n").is_none());
        assert!(s.send(EVENT, b"{\"n\":2}").is_none());
        std::thread::sleep(Duration::from_millis(300));
        let l = std::net::TcpListener::bind(&addr).unwrap();
        let (mut c, _) = l.accept().unwrap();
        assert_eq!(read_frame(&mut c), Some((HELLO, b"t0k".to_vec())));
        assert_eq!(read_frame(&mut c), Some((ALERT, b"{\"n\":1}".to_vec())));
        assert_eq!(read_frame(&mut c), Some((EVENT, b"{\"n\":2}".to_vec())));
    }
}
