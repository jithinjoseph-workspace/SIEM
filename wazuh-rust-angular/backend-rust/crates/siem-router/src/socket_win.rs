//! The router's socket layer on Windows: the API of `socket.rs` (Linux,
//! epoll + unix sockets) over loopback TCP. Each socket path maps to a port
//! that the listener writes to `<path>.port`, as siem-ipc does for the other
//! daemons. Same `AppendHeaderProtocol` framing (`[u32 packet size][u32 header
//! size][header][body]`, little endian), one thread per connection, and the
//! client's reconnection with a doubling delay (max 30 s).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

pub const BUFFER_MAX_SIZE: usize = 8192 * 8;

/// The `onRead` callback: (fd, body, header).
pub type OnRead = Arc<dyn Fn(i32, &[u8], &[u8]) + Send + Sync>;

/// The errors of the socket operations (`what()` texts).
pub type SockResult<T> = Result<T, String>;

fn port_file(path: &str) -> String {
    format!("{path}.port")
}

/// `[u32 size][u32 header size][header][body]`
fn frame(body: &[u8], header: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + header.len() + body.len());
    buf.extend_from_slice(&((body.len() + 4 + header.len()) as u32).to_le_bytes());
    buf.extend_from_slice(&(header.len() as u32).to_le_bytes());
    buf.extend_from_slice(header);
    buf.extend_from_slice(body);
    buf
}

/// Reads packets until the peer closes or errs: each goes to `cb(body, header)`.
fn read_loop(mut s: TcpStream, cb: &dyn Fn(&[u8], &[u8])) {
    loop {
        let mut size = [0u8; 4];
        if s.read_exact(&mut size).is_err() {
            return;
        }
        let total = u32::from_le_bytes(size) as usize;
        let mut buf = vec![0u8; total];
        if s.read_exact(&mut buf).is_err() {
            return;
        }
        if total < 4 {
            cb(&[], &[]);
            continue;
        }
        let hs = (u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize).min(total - 4);
        cb(&buf[4 + hs..], &buf[4..4 + hs]);
    }
}

static NEXT_FD: AtomicI32 = AtomicI32::new(1);

/// `SocketServer`
pub struct SocketServer {
    path: String,
    should_stop: Arc<AtomicBool>,
    port: Mutex<u16>,
    clients: Arc<Mutex<HashMap<i32, TcpStream>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl SocketServer {
    pub fn new(path: &str) -> SocketServer {
        SocketServer {
            path: path.to_string(),
            should_stop: Arc::new(AtomicBool::new(false)),
            port: Mutex::new(0),
            clients: Arc::new(Mutex::new(HashMap::new())),
            thread: Mutex::new(None),
        }
    }

    /// `listen(onRead)`
    pub fn listen(&self, on_read: OnRead) -> SockResult<()> {
        self.should_stop.store(false, Ordering::SeqCst);
        if let Some(dir) = std::path::Path::new(&self.path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("Failed to bind socket: {e}"))?;
        let port = l.local_addr().map_err(|e| e.to_string())?.port();
        std::fs::write(port_file(&self.path), port.to_string()).map_err(|e| format!("Failed to bind socket: {e}"))?;
        *self.port.lock() = port;
        let (stop, clients) = (self.should_stop.clone(), self.clients.clone());
        let t = std::thread::spawn(move || {
            for conn in l.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(s) = conn else { continue };
                let _ = s.set_nodelay(true);
                let fd = NEXT_FD.fetch_add(1, Ordering::SeqCst);
                let Ok(w) = s.try_clone() else { continue };
                clients.lock().insert(fd, w);
                let (cb, clients) = (on_read.clone(), clients.clone());
                std::thread::spawn(move || {
                    read_loop(s, &|body, header| cb(fd, body, header));
                    clients.lock().remove(&fd);
                });
            }
        });
        *self.thread.lock() = Some(t);
        Ok(())
    }

    /// `send(fd, body, header)`: Err("Client not found") for unknown peers.
    pub fn send(&self, fd: i32, body: &[u8], header: &[u8]) -> SockResult<()> {
        let mut c = self.clients.lock();
        let Some(s) = c.get_mut(&fd) else {
            return Err("Client not found".into());
        };
        if s.write_all(&frame(body, header)).is_err() {
            c.remove(&fd);
        }
        Ok(())
    }

    /// `stop`
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
        let port = *self.port.lock();
        if port != 0 {
            // wakes the accept loop
            let _ = TcpStream::connect(("127.0.0.1", port));
        }
        if let Some(t) = self.thread.lock().take() {
            let _ = t.join();
        }
        for (_, s) in self.clients.lock().drain() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_file(port_file(&self.path));
    }
}

/// `SocketClient`
pub struct SocketClient {
    path: String,
    stream: Arc<Mutex<Option<TcpStream>>>,
    /// packets sent before the connection is up (`m_unsentMessages`)
    unsent: Arc<Mutex<Vec<Vec<u8>>>>,
    should_stop: Arc<AtomicBool>,
    cv: Arc<(Mutex<()>, Condvar)>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl SocketClient {
    pub fn new(path: &str) -> SocketClient {
        SocketClient {
            path: path.to_string(),
            stream: Arc::new(Mutex::new(None)),
            unsent: Arc::new(Mutex::new(Vec::new())),
            should_stop: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(()), Condvar::new())),
            thread: Mutex::new(None),
        }
    }

    fn try_connect(path: &str) -> Option<TcpStream> {
        let port: u16 = std::fs::read_to_string(port_file(path)).ok()?.trim().parse().ok()?;
        let s = TcpStream::connect(("127.0.0.1", port)).ok()?;
        let _ = s.set_nodelay(true);
        Some(s)
    }

    /// `connect(onRead, onConnect)`: connects (retrying), then reads until the peer goes away, and reconnects.
    pub fn connect(&self, on_read: Arc<dyn Fn(&[u8], &[u8]) + Send + Sync>, on_connect: Arc<dyn Fn() + Send + Sync>) {
        let mut t = self.thread.lock();
        if t.is_some() {
            return;
        }
        let (path, stream, unsent, stop, cv) = (self.path.clone(), self.stream.clone(), self.unsent.clone(), self.should_stop.clone(), self.cv.clone());
        *t = Some(std::thread::spawn(move || {
            let mut delay = 1u64;
            while !stop.load(Ordering::SeqCst) {
                let Some(s) = Self::try_connect(&path) else {
                    delay = (delay * 2).min(30);
                    let mut g = cv.0.lock();
                    if !stop.load(Ordering::SeqCst) {
                        cv.1.wait_for(&mut g, Duration::from_secs(delay));
                    }
                    continue;
                };
                delay = 1;
                let Ok(mut w) = s.try_clone() else { continue };
                for p in unsent.lock().drain(..) {
                    let _ = w.write_all(&p);
                }
                *stream.lock() = Some(w);
                on_connect();
                read_loop(s, &|body, header| on_read(body, header));
                *stream.lock() = None;
            }
        }));
    }

    /// `send(body, header)`
    pub fn send(&self, body: &[u8], header: &[u8]) {
        let buf = frame(body, header);
        let mut g = self.stream.lock();
        match g.as_mut() {
            Some(s) => {
                if s.write_all(&buf).is_err() {
                    *g = None;
                    self.unsent.lock().push(buf);
                }
            }
            None => self.unsent.lock().push(buf),
        }
    }

    /// `stop`
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
        if let Some(s) = self.stream.lock().take() {
            let _ = s.shutdown(Shutdown::Both);
        }
        {
            let _g = self.cv.0.lock();
            self.cv.1.notify_all();
        }
        if let Some(t) = self.thread.lock().take() {
            let _ = t.join();
        }
    }
}

impl Drop for SocketClient {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_client_roundtrip() {
        let dir = std::env::temp_dir().join(format!("router-sock-{}", std::process::id()));
        let path = dir.join("topic").to_string_lossy().into_owned();
        let server = Arc::new(SocketServer::new(&path));
        let got = Arc::new(Mutex::new(Vec::new()));
        let (g, srv) = (got.clone(), Arc::downgrade(&server));
        server
            .listen(Arc::new(move |fd, body: &[u8], header: &[u8]| {
                g.lock().push((body.to_vec(), header.to_vec()));
                if let Some(s) = srv.upgrade() {
                    let _ = s.send(fd, b"pong", b"H");
                }
            }))
            .unwrap();
        let reply = Arc::new(Mutex::new(Vec::new()));
        let r = reply.clone();
        let client = SocketClient::new(&path);
        client.send(b"before-connect", b"P");
        client.connect(Arc::new(move |body: &[u8], _| r.lock().push(body.to_vec())), Arc::new(|| {}));
        client.send(b"ping", b"");
        for _ in 0..100 {
            if reply.lock().len() == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(got.lock().as_slice(), [(b"before-connect".to_vec(), b"P".to_vec()), (b"ping".to_vec(), Vec::new())]);
        assert_eq!(reply.lock().len(), 2);
        client.stop();
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
