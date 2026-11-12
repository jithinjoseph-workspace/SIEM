//! Report delivery: alerts are queued in `queue/vd/reports` and sent one datagram each to the
//! analysis daemon's socket `queue/sockets/queue`, at most `wmMaxEps` per second.

use crate::log::Log;
use crate::queue::DurableQueue;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// Where report lines go. The scanner's own dispatcher, or a collector given by tests.
pub trait ReportSink: Send + Sync {
    fn push(&self, line: String);
}

/// A connection-on-demand datagram endpoint.
pub trait Datagram: Send {
    fn send(&mut self, data: &[u8]) -> std::io::Result<()>;
    /// Forgets the connection after a failure.
    fn reset(&mut self);
}

#[cfg(unix)]
pub struct UnixDatagramSender {
    path: std::path::PathBuf,
    sock: Option<std::os::unix::net::UnixDatagram>,
}

#[cfg(unix)]
impl UnixDatagramSender {
    pub fn new(home: &std::path::Path) -> Self {
        UnixDatagramSender { path: home.join("queue/sockets/queue"), sock: None }
    }
}

#[cfg(unix)]
impl Datagram for UnixDatagramSender {
    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        if self.sock.is_none() {
            let s = std::os::unix::net::UnixDatagram::unbound()?;
            s.connect(&self.path)?;
            self.sock = Some(s);
        }
        self.sock.as_ref().map_or(Ok(0), |s| s.send(data)).map(|_| ())
    }
    fn reset(&mut self) {
        self.sock = None;
    }
}

/// UDP datagrams to `127.0.0.1:<port from <socket>.port>`, sent from a socket bound to
/// `127.0.0.1:0`. The port file is read on every connection attempt.
pub struct UdpDatagramSender {
    socket: std::path::PathBuf,
    sock: Option<std::net::UdpSocket>,
}

impl UdpDatagramSender {
    pub fn new(socket: &std::path::Path) -> Self {
        UdpDatagramSender { socket: socket.to_path_buf(), sock: None }
    }
}

impl Datagram for UdpDatagramSender {
    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        if self.sock.is_none() {
            let port = crate::agentdb::read_port(&self.socket)?;
            let s = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            s.connect((std::net::Ipv4Addr::LOCALHOST, port))?;
            self.sock = Some(s);
        }
        self.sock.as_ref().map_or(Ok(0), |s| s.send(data)).map(|_| ())
    }
    fn reset(&mut self) {
        self.sock = None;
    }
}

/// The platform's report socket `<home>/queue/sockets/queue`.
#[cfg(unix)]
pub fn local_datagram(home: &std::path::Path) -> Box<dyn Datagram> {
    Box::new(UnixDatagramSender::new(home))
}

/// The platform's report socket `<home>/queue/sockets/queue`.
#[cfg(not(unix))]
pub fn local_datagram(home: &std::path::Path) -> Box<dyn Datagram> {
    Box::new(UdpDatagramSender::new(&home.join("queue/sockets/queue")))
}

/// The scanner's own report dispatcher.
pub struct ReportQueue {
    pub queue: Arc<DurableQueue>,
    max: usize,
}

impl ReportQueue {
    pub fn new(queue: Arc<DurableQueue>, max: usize) -> Self {
        ReportQueue { queue, max }
    }
}

impl ReportSink for ReportQueue {
    /// Beyond the size limit the report is dropped silently (kept behaviour).
    fn push(&self, line: String) {
        if self.max == 0 || self.queue.len() < self.max {
            self.queue.push("", line.as_bytes());
        }
    }
}

/// Sender thread: sends the oldest report, retries every second while the socket is down.
pub fn spawn_sender(queue: Arc<DurableQueue>, mut dg: Box<dyn Datagram>, eps: u32, stop: Arc<AtomicBool>, log: Log) -> JoinHandle<()> {
    let pause = Duration::from_micros(1_000_000 / u64::from(eps.max(1)));
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let Some((seq, _, item)) = queue.wait_front(Duration::from_secs(1)) else { continue };
            if dg.send(&item).is_err() {
                dg.reset();
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            queue.remove(seq);
            std::thread::sleep(pause);
            vs!(log, Debug2, "Report sent: {}", String::from_utf8_lossy(&item));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake(Arc<Mutex<(bool, Vec<Vec<u8>>)>>);
    impl Datagram for Fake {
        fn send(&mut self, d: &[u8]) -> std::io::Result<()> {
            let mut g = self.0.lock().unwrap();
            if !g.0 {
                return Err(std::io::ErrorKind::NotFound.into());
            }
            g.1.push(d.to_vec());
            Ok(())
        }
        fn reset(&mut self) {}
    }

    #[test]
    fn udp_report_with_port_file() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("queue");
        let mut dg = UdpDatagramSender::new(&sock);
        assert!(dg.send(b"x").is_err());
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        std::fs::write(home.path().join("queue.port"), rx.local_addr().unwrap().port().to_string()).unwrap();
        let line = b"1:[001] (a) 1->vulnerability-detector:{}";
        dg.send(line).unwrap();
        let mut buf = [0u8; 256];
        let (n, from) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], line);
        assert!(from.ip().is_loopback());
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(home.path().join("queue/sockets")).unwrap();
            std::fs::write(home.path().join("queue/sockets/queue.port"), rx.local_addr().unwrap().port().to_string()).unwrap();
            local_datagram(home.path()).send(b"y").unwrap();
            let (n, _) = rx.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"y");
        }
    }

    #[test]
    fn queue_limit_and_retry() {
        let d = tempfile::tempdir().unwrap();
        let q = Arc::new(DurableQueue::open(d.path()).unwrap());
        let one = ReportQueue::new(q.clone(), 1);
        one.push("a".into());
        one.push("b".into());
        assert_eq!(q.len(), 1);
        let state = Arc::new(Mutex::new((false, Vec::new())));
        let stop = Arc::new(AtomicBool::new(false));
        let t = spawn_sender(q.clone(), Box::new(Fake(state.clone())), 100, stop.clone(), Log::null());
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(q.len(), 1);
        state.lock().unwrap().0 = true;
        for _ in 0..50 {
            if q.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(state.lock().unwrap().1, vec![b"a".to_vec()]);
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
    }
}
