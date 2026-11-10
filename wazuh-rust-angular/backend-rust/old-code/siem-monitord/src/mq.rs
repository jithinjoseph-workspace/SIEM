//! `StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)` + `SendMSG`.
//!
//! On Unix this is the C-faithful `siem_ipc::mq_op`. A manager running on
//! Windows (development) reaches analysisd's queue through the loopback port
//! in `queue/sockets/queue.port` (see `siem_ipc::local`).

/// A connected queue (`mond.a_queue > 0`).
pub struct Queue {
    #[cfg(unix)]
    fd: i32,
    #[cfg(not(unix))]
    sock: std::net::UdpSocket,
}

impl Queue {
    /// Blocks until the queue is reachable.
    #[cfg(unix)]
    pub fn start() -> Option<Queue> {
        use siem_ipc::mq_op::{start_mq, INFINITE_OPENQ_ATTEMPTS, WRITE};
        let fd = start_mq(crate::DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
        (fd > 0).then_some(Queue { fd })
    }

    #[cfg(not(unix))]
    pub fn start() -> Option<Queue> {
        let port_file = format!("{}.port", crate::DEFAULTQUEUE);
        loop {
            let s = std::fs::read_to_string(&port_file).ok().and_then(|p| p.trim().parse::<u16>().ok()).and_then(|p| {
                let s = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
                s.connect(("127.0.0.1", p)).ok()?;
                Some(s)
            });
            if let Some(sock) = s {
                return Some(Queue { sock });
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    /// `SendMSG(queue, message, locmsg, loc)`: 0 or -1.
    #[cfg(unix)]
    pub fn send(&self, message: &[u8], locmsg: &str, loc: u8) -> i32 {
        siem_ipc::mq_op::send_msg(self.fd, message, locmsg, loc)
    }

    #[cfg(not(unix))]
    pub fn send(&self, message: &[u8], locmsg: &str, loc: u8) -> i32 {
        match siem_ipc::mq::format_msg(message, locmsg, loc) {
            Some(mut m) => {
                m.push(0);
                if self.sock.send(&m).is_ok() {
                    0
                } else {
                    -1
                }
            }
            None => 0,
        }
    }
}

/// `SendMSG` on a queue that may be closed (`a_queue < 0` gives -1).
pub fn send(q: &Option<Queue>, message: &[u8], locmsg: &str, loc: u8) -> i32 {
    match q {
        Some(q) => q.send(message, locmsg, loc),
        None => -1,
    }
}
