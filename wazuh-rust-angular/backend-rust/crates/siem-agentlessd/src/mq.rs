//! Message queue helper for agentlessd.

pub const DEFAULTQUEUE: &str = "queue/sockets/queue";

pub struct Queue {
    #[cfg(unix)]
    fd: i32,
    #[cfg(not(unix))]
    sock: std::net::UdpSocket,
}

impl Queue {
    #[cfg(unix)]
    pub fn start() -> Option<Queue> {
        use siem_ipc::mq_op::{start_mq, INFINITE_OPENQ_ATTEMPTS, WRITE};
        let fd = start_mq(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
        (fd > 0).then_some(Queue { fd })
    }

    #[cfg(not(unix))]
    pub fn start() -> Option<Queue> {
        let port_file = format!("{DEFAULTQUEUE}.port");
        let s = std::fs::read_to_string(&port_file)
            .ok()
            .and_then(|p| p.trim().parse::<u16>().ok())
            .and_then(|p| {
                let s = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
                s.connect(("127.0.0.1", p)).ok()?;
                Some(s)
            })
            .or_else(|| {
                let s = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
                let _ = s.connect(("127.0.0.1", 1514));
                Some(s)
            });
        s.map(|sock| Queue { sock })
    }

    #[cfg(unix)]
    pub fn send(&self, message: &[u8], locmsg: &str, loc: u8) -> i32 {
        siem_ipc::mq_op::send_msg(self.fd, message, locmsg, loc)
    }

    #[cfg(not(unix))]
    pub fn send(&self, message: &[u8], locmsg: &str, loc: u8) -> i32 {
        match siem_ipc::mq::format_msg(message, locmsg, loc) {
            Some(mut m) => {
                m.push(0);
                if self.sock.send(&m).is_ok() { 0 } else { -1 }
            }
            None => 0,
        }
    }
}

pub fn send(q: &Option<Queue>, message: &[u8], locmsg: &str, loc: u8) -> i32 {
    match q {
        Some(q) => q.send(message, locmsg, loc),
        None => -1,
    }
}

