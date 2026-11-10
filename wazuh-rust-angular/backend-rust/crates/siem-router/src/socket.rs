//! shared_modules/utils socketWrapper.hpp / socketServer.hpp /
//! socketClient.hpp / epollWrapper.hpp: non-blocking unix sockets with the
//! `AppendHeaderProtocol` framing (`[u32 packet size][u32 header size]
//! [header][body]`, little endian), an unsent packet queue and epoll loops.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

pub const BUFFER_MAX_SIZE: usize = 8192 * 8;
const PACKET_FIELD_SIZE: u32 = 4;

/// The `onRead` callback: (fd, body, header).
pub type OnRead = Arc<dyn Fn(i32, &[u8], &[u8]) + Send + Sync>;

fn errno() -> i32 {
    // SAFETY: reading errno.
    unsafe { *libc::__errno_location() }
}

fn strerror(e: i32) -> String {
    // SAFETY: strerror returns a static string.
    unsafe { std::ffi::CStr::from_ptr(libc::strerror(e)).to_string_lossy().into_owned() }
}

/// `EpollWrapper` (errors go to stderr like the C++).
pub struct Epoll {
    fd: i32,
}

impl Epoll {
    pub fn new() -> Epoll {
        // SAFETY: plain syscall.
        let fd = unsafe { libc::epoll_create1(0) };
        if fd == -1 {
            panic!("Error creating epoll instance");
        }
        Epoll { fd }
    }

    pub fn wait(&self, events: &mut [libc::epoll_event], timeout: i32) -> i32 {
        // SAFETY: the slice bounds the events.
        unsafe { libc::epoll_wait(self.fd, events.as_mut_ptr(), events.len() as i32, timeout) }
    }

    fn ctl(&self, op: i32, fd: i32, events: u32, what: &str) {
        let mut ev = libc::epoll_event { events, u64: fd as u32 as u64 };
        // SAFETY: valid epoll descriptor.
        if unsafe { libc::epoll_ctl(self.fd, op, fd, &mut ev) } == -1 {
            eprintln!("{what}");
        }
    }

    pub fn add(&self, fd: i32, events: u32) {
        self.ctl(libc::EPOLL_CTL_ADD, fd, events, "Error adding FD to interface.");
    }

    pub fn modify(&self, fd: i32, events: u32) {
        self.ctl(libc::EPOLL_CTL_MOD, fd, events, "Error modifying FD from interface.");
    }

    pub fn delete(&self, fd: i32) {
        // SAFETY: valid epoll descriptor.
        if unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) } == -1 {
            eprintln!("Error removing FD from interface.");
        }
    }
}

impl Default for Epoll {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        // SAFETY: closing our descriptor.
        unsafe { libc::close(self.fd) };
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Header,
    Body,
}

struct ReadState {
    status: Status,
    read_position: u32,
    read_size: u32,
    total_read_size: u32,
    buf: Vec<u8>,
}

/// `Socket<OSPrimitives, AppendHeaderProtocol>`
pub struct Socket {
    fd: AtomicI32,
    read: Mutex<ReadState>,
    /// The unsent packets (data, offset); the mutex is `m_mutex`.
    unsent: Mutex<VecDeque<(Vec<u8>, usize)>>,
}

/// The errors of the socket operations (`what()` texts).
pub type SockResult<T> = Result<T, String>;

fn set_buffers(sock: i32) {
    let opt: u32 = BUFFER_MAX_SIZE as u32;
    // SAFETY: valid option pointer.
    unsafe {
        if libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, (&opt as *const u32).cast(), 4) < 0 {
            eprintln!("Failed to set socket options");
        }
        if libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE, (&opt as *const u32).cast(), 4) < 0 {
            eprintln!("Failed to set socket options");
        }
    }
}

/// A `sockaddr_un` for `path` (`UnixAddress::address`).
fn unix_addr(path: &str) -> SockResult<libc::sockaddr_un> {
    // SAFETY: a zeroed sockaddr_un is valid.
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if path.len() >= a.sun_path.len() {
        return Err("Error setting socket path (too long)".into());
    }
    for (i, b) in path.bytes().enumerate() {
        a.sun_path[i] = b as libc::c_char;
    }
    Ok(a)
}

impl Socket {
    pub fn new(fd: i32) -> Socket {
        Socket {
            fd: AtomicI32::new(fd),
            read: Mutex::new(ReadState {
                status: Status::Header,
                read_position: 0,
                read_size: PACKET_FIELD_SIZE,
                total_read_size: 0,
                buf: vec![0; BUFFER_MAX_SIZE],
            }),
            unsent: Mutex::new(VecDeque::new()),
        }
    }

    pub fn fd(&self) -> i32 {
        self.fd.load(Ordering::SeqCst)
    }

    pub fn has_unsent_messages(&self) -> bool {
        !self.unsent.lock().is_empty()
    }

    /// `connect(connInfo, SOCK_STREAM | SOCK_NONBLOCK)`
    pub fn connect(&self, path: &str) -> SockResult<()> {
        let old = self.fd();
        if old != -1 {
            // SAFETY: closing our descriptor.
            unsafe { libc::close(old) };
        }
        // SAFETY: plain syscalls.
        let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
        self.fd.store(sock, Ordering::SeqCst);
        if sock == -1 {
            return Err("Error creating socket.".into());
        }
        let a = unix_addr(path)?;
        // SAFETY: valid address.
        if unsafe { libc::connect(sock, (&a as *const libc::sockaddr_un).cast(), std::mem::size_of::<libc::sockaddr_un>() as u32) } < 0 {
            let e = errno();
            if e != libc::EINPROGRESS && e != libc::EAGAIN {
                return Err(format!("Error connecting to socket: {}", strerror(e)));
            }
        }
        set_buffers(sock);
        Ok(())
    }

    /// `read(callback)`: every complete packet goes to the callback; EAGAIN
    /// ends the call, a closed peer or an error is an Err.
    pub fn read(&self, cb: &dyn Fn(i32, &[u8], &[u8])) -> SockResult<()> {
        let sock = self.fd();
        if sock == -1 {
            return Err("Invalid socket".into());
        }
        let mut st = self.read.lock();
        let mut data_to_read = true;
        while data_to_read {
            if st.status == Status::Header {
                let pos = st.read_position as usize;
                let n = st.read_size as usize;
                // SAFETY: the buffer has room for pos + n bytes.
                let ret = unsafe { libc::recv(sock, st.buf[pos..].as_mut_ptr().cast(), n, 0) };
                if ret == -1 {
                    let e = errno();
                    if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                        data_to_read = false;
                    } else {
                        return Err("Error reading from socket.".into());
                    }
                } else if ret == 0 {
                    return Err("Remote shutdown / disconnect.".into());
                } else if ret as u32 != st.read_size {
                    st.read_position += ret as u32;
                    st.read_size -= ret as u32;
                } else {
                    let total = u32::from_le_bytes([st.buf[0], st.buf[1], st.buf[2], st.buf[3]]);
                    st.total_read_size = total;
                    if total as usize > BUFFER_MAX_SIZE {
                        st.buf.resize(total as usize + 1, 0);
                    }
                    st.read_position = 0;
                    st.read_size = total;
                    st.status = Status::Body;
                }
            }
            if st.status == Status::Body {
                let pos = st.read_position as usize;
                let n = st.read_size as usize;
                // SAFETY: the buffer has room for pos + n bytes.
                let ret = unsafe { libc::recv(sock, st.buf[pos..].as_mut_ptr().cast(), n, 0) };
                if ret == -1 {
                    let e = errno();
                    if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                        data_to_read = false;
                    } else {
                        return Err("Error reading from socket.".into());
                    }
                } else if ret == 0 {
                    return Err("Remote shutdown / disconnect.".into());
                } else if st.read_size != ret as u32 {
                    st.read_size -= ret as u32;
                    st.read_position += ret as u32;
                } else {
                    st.read_position = 0;
                    st.read_size = PACKET_FIELD_SIZE;
                    st.status = Status::Header;
                    let total = st.total_read_size as usize;
                    // AppendHeaderProtocol: the header size is the first u32
                    let header_size = u32::from_le_bytes([st.buf[0], st.buf[1], st.buf[2], st.buf[3]]) as usize;
                    let data_offset = 4 + header_size;
                    let header = st.buf[4.min(st.buf.len())..(4 + header_size).min(st.buf.len())].to_vec();
                    let body = if data_offset <= total { st.buf[data_offset..total].to_vec() } else { Vec::new() };
                    let big = total > BUFFER_MAX_SIZE;
                    drop(st);
                    cb(sock, &body, &header);
                    st = self.read.lock();
                    if big {
                        st.buf.resize(BUFFER_MAX_SIZE, 0);
                    }
                }
            }
        }
        Ok(())
    }

    /// `accept`: a non-blocking peer.
    pub fn accept(&self) -> SockResult<i32> {
        // SAFETY: plain syscalls on our listening socket.
        unsafe {
            let sock = libc::accept(self.fd(), std::ptr::null_mut(), std::ptr::null_mut());
            if sock == -1 {
                return Err(format!("Failed to accept socket{}", strerror(errno())));
            }
            set_buffers(sock);
            let flags = libc::fcntl(sock, libc::F_GETFL, 0);
            if flags == -1 {
                return Err("Failed to get socket flags".into());
            }
            if libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err("Failed to set socket flags".into());
            }
            Ok(sock)
        }
    }

    /// `sendUnsentMessages`
    pub fn send_unsent_messages(&self) -> SockResult<()> {
        let mut q = self.unsent.lock();
        while let Some((data, offset)) = q.front_mut() {
            // SAFETY: the slice bounds the read.
            let ret = unsafe { libc::send(self.fd(), data[*offset..].as_ptr().cast(), data.len() - *offset, libc::MSG_NOSIGNAL) };
            if ret <= 0 {
                let e = errno();
                if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                    return Err("Waiting for socket to be ready".into());
                }
                return Err(format!("Error sending data to socket: {}", strerror(e)));
            }
            // (the C++ compares ret with the whole size, not the remainder)
            if ret as usize != data.len() {
                *offset += ret as usize;
            } else {
                q.pop_front();
            }
        }
        Ok(())
    }

    /// `send(body, header)`
    pub fn send(&self, body: &[u8], header: &[u8]) -> SockResult<()> {
        let mut buf = Vec::with_capacity(8 + header.len() + body.len());
        buf.extend_from_slice(&((body.len() + 4 + header.len()) as u32).to_le_bytes());
        buf.extend_from_slice(&(header.len() as u32).to_le_bytes());
        buf.extend_from_slice(header);
        buf.extend_from_slice(body);
        let mut q = self.unsent.lock();
        if !q.is_empty() {
            q.push_back((buf, 0));
            return Ok(());
        }
        let mut sent = 0usize;
        while sent != buf.len() {
            // SAFETY: the slice bounds the read.
            let ret = unsafe { libc::send(self.fd(), buf[sent..].as_ptr().cast(), buf.len() - sent, libc::MSG_NOSIGNAL) };
            if ret <= 0 {
                let e = errno();
                q.push_back((buf[sent..].to_vec(), 0));
                return Err(format!("Error sending data to socket: {}", strerror(e)));
            }
            sent += ret as usize;
        }
        Ok(())
    }

    /// `listen(unix address)`
    pub fn listen(&self, path: &str) -> SockResult<()> {
        if self.fd() != -1 {
            return Err("Socket already initialized".into());
        }
        let a = unix_addr(path)?;
        // SAFETY: plain syscalls with valid arguments.
        unsafe {
            let sock = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
            if sock == -1 {
                return Err("Failed to create socket".into());
            }
            self.fd.store(sock, Ordering::SeqCst);
            let reuse: libc::c_int = 1;
            if libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_REUSEADDR, (&reuse as *const libc::c_int).cast(), 4) < 0 {
                self.close_socket();
                return Err("Failed to set socket options".into());
            }
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            if libc::fchmod(sock, 0o666) != 0 {
                let e = strerror(errno());
                self.close_socket();
                return Err(format!("Failed to fchmod socket {e}"));
            }
            if libc::bind(sock, (&a as *const libc::sockaddr_un).cast(), std::mem::size_of::<libc::sockaddr_un>() as u32) != 0 {
                let e = strerror(errno());
                self.close_socket();
                return Err(format!("Failed to bind socket {e}"));
            }
            let c = std::ffi::CString::new(path).unwrap_or_default();
            if libc::chmod(c.as_ptr(), 0o666) != 0 {
                let e = strerror(errno());
                self.close_socket();
                return Err(format!("Failed to chmod socket {e}"));
            }
            if libc::listen(sock, libc::SOMAXCONN) != 0 {
                let e = strerror(errno());
                self.close_socket();
                return Err(format!("Failed to listen socket {e}"));
            }
            set_buffers(sock);
        }
        Ok(())
    }

    /// `closeSocket`
    pub fn close_socket(&self) {
        let fd = self.fd.swap(-1, Ordering::SeqCst);
        if fd != -1 {
            // SAFETY: shutting down and closing our descriptor.
            unsafe {
                if libc::shutdown(fd, libc::SHUT_WR) == -1 {
                    eprintln!("Shutdown error: {}", errno());
                }
                libc::close(fd);
            }
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.close_socket();
    }
}

fn stop_pipe() -> [i32; 2] {
    let mut p = [-1i32; 2];
    // SAFETY: valid array of two descriptors.
    unsafe {
        if libc::pipe(p.as_mut_ptr()) == -1 {
            panic!("Failed to create stop pipe");
        }
        if libc::fcntl(p[0], libc::F_SETFL, libc::O_NONBLOCK) == -1 {
            panic!("Failed to set stop pipe to non-blocking");
        }
    }
    p
}

const EVENTS: usize = 32;
const EVENTS_LIMIT: usize = 1024;

/// `SocketServer<Socket, EpollWrapper>`
pub struct SocketServer {
    path: String,
    should_stop: Arc<AtomicBool>,
    stop_fd: [i32; 2],
    epoll: Arc<Epoll>,
    listen_socket: Arc<Socket>,
    clients: Arc<Mutex<HashMap<i32, Arc<Socket>>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl SocketServer {
    pub fn new(path: &str) -> SocketServer {
        let stop_fd = stop_pipe();
        let epoll = Arc::new(Epoll::new());
        epoll.add(stop_fd[0], (libc::EPOLLIN | libc::EPOLLET) as u32);
        SocketServer {
            path: path.to_string(),
            should_stop: Arc::new(AtomicBool::new(false)),
            stop_fd,
            epoll,
            listen_socket: Arc::new(Socket::new(-1)),
            clients: Arc::new(Mutex::new(HashMap::new())),
            thread: Mutex::new(None),
        }
    }

    /// `listen(onRead)`
    pub fn listen(&self, on_read: OnRead) -> SockResult<()> {
        self.should_stop.store(false, Ordering::SeqCst);
        let _ = std::fs::remove_file(&self.path);
        self.listen_socket.listen(&self.path)?;
        self.epoll.add(self.listen_socket.fd(), libc::EPOLLIN as u32);
        let (stop, epoll, ls, clients, stop_rd) =
            (self.should_stop.clone(), self.epoll.clone(), self.listen_socket.clone(), self.clients.clone(), self.stop_fd[0]);
        let t = std::thread::spawn(move || {
            let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; EVENTS];
            while !stop.load(Ordering::SeqCst) {
                let n = epoll.wait(&mut events, -1);
                for i in 0..n.max(0) as usize {
                    let fd = events[i].u64 as i32;
                    let ev = events[i].events;
                    if fd == ls.fd() {
                        match ls.accept() {
                            Ok(c) => {
                                clients.lock().insert(c, Arc::new(Socket::new(c)));
                                epoll.add(c, libc::EPOLLIN as u32);
                            }
                            Err(e) => eprintln!("Failed to initialize client socket: {e}"),
                        }
                    } else if fd == stop_rd {
                        let mut d = [0u8; 1];
                        // SAFETY: reading one byte from our pipe.
                        unsafe { libc::read(stop_rd, d.as_mut_ptr().cast(), 1) };
                        break;
                    } else {
                        let client = clients.lock().get(&fd).cloned();
                        if let Some(client) = client {
                            if ev & libc::EPOLLOUT as u32 != 0 && client.send_unsent_messages().is_ok() {
                                epoll.modify(client.fd(), libc::EPOLLIN as u32);
                            }
                            if ev & libc::EPOLLIN as u32 != 0 {
                                let cb = on_read.clone();
                                let _ = client.read(&*cb);
                            }
                            if ev & (libc::EPOLLERR | libc::EPOLLHUP) as u32 != 0 {
                                clients.lock().remove(&fd);
                            }
                        }
                    }
                }
                if n as usize == events.len() && n as usize >= EVENTS_LIMIT {
                    let l = events.len() * 2;
                    events.resize(l, libc::epoll_event { events: 0, u64: 0 });
                }
            }
        });
        *self.thread.lock() = Some(t);
        Ok(())
    }

    /// `send(fd, body, header)`: Err("Client not found") for unknown peers.
    pub fn send(&self, fd: i32, body: &[u8], header: &[u8]) -> SockResult<()> {
        let client = self.clients.lock().get(&fd).cloned();
        let Some(client) = client else {
            return Err("Client not found".into());
        };
        if client.send(body, header).is_err() {
            self.epoll.modify(fd, (libc::EPOLLIN | libc::EPOLLOUT) as u32);
        }
        Ok(())
    }

    /// `stop`
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
        let d = b'x';
        // SAFETY: writing one byte to our pipe.
        unsafe { libc::write(self.stop_fd[1], (&d as *const u8).cast(), 1) };
        if let Some(t) = self.thread.lock().take() {
            let _ = t.join();
        }
        self.epoll.delete(self.listen_socket.fd());
        self.listen_socket.close_socket();
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        self.stop();
        // SAFETY: closing our pipe.
        unsafe {
            libc::close(self.stop_fd[0]);
            libc::close(self.stop_fd[1]);
        }
        let _ = std::fs::remove_file(&self.path).or_else(|_| std::fs::remove_dir_all(&self.path));
    }
}

const CLIENT_EPOLL_EVENTS: usize = 32;

/// `SocketClient<Socket, EpollWrapper>`
pub struct SocketClient {
    path: String,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    epoll: Arc<Epoll>,
    socket: Arc<Socket>,
    should_stop: Arc<AtomicBool>,
    cv: Arc<(Mutex<()>, Condvar)>,
    stop_fd: [i32; 2],
    /// `m_socketMutex`
    socket_mutex: Arc<parking_lot::RwLock<()>>,
}

impl SocketClient {
    pub fn new(path: &str) -> SocketClient {
        let stop_fd = stop_pipe();
        let epoll = Arc::new(Epoll::new());
        epoll.add(stop_fd[0], (libc::EPOLLIN | libc::EPOLLET) as u32);
        SocketClient {
            path: path.to_string(),
            thread: Mutex::new(None),
            epoll,
            socket: Arc::new(Socket::new(-1)),
            should_stop: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(()), Condvar::new())),
            stop_fd,
            socket_mutex: Arc::new(parking_lot::RwLock::new(())),
        }
    }

    /// `handleConnect`: retries with a doubling delay (max 30 s) until it
    /// connects or the client stops.
    fn handle_connect(path: &str, socket: &Socket, epoll: &Epoll, stop: &AtomicBool, cv: &(Mutex<()>, Condvar), lock: &parking_lot::RwLock<()>) {
        let mut delay = 1u64;
        let _w = lock.write();
        loop {
            match socket.connect(path) {
                Ok(()) => {
                    epoll.add(socket.fd(), (libc::EPOLLIN | libc::EPOLLOUT) as u32);
                    break;
                }
                Err(_) => delay = (delay * 2).min(30),
            }
            let mut g = cv.0.lock();
            if stop.load(Ordering::SeqCst) {
                break;
            }
            cv.1.wait_for(&mut g, Duration::from_secs(delay));
            if stop.load(Ordering::SeqCst) {
                break;
            }
        }
    }

    /// `connect(onRead, onConnect)`
    pub fn connect(&self, on_read: Arc<dyn Fn(&[u8], &[u8]) + Send + Sync>, on_connect: Arc<dyn Fn() + Send + Sync>) {
        let mut t = self.thread.lock();
        if t.is_some() {
            return;
        }
        let (path, epoll, socket, stop, cv, lock, stop_rd) = (
            self.path.clone(),
            self.epoll.clone(),
            self.socket.clone(),
            self.should_stop.clone(),
            self.cv.clone(),
            self.socket_mutex.clone(),
            self.stop_fd[0],
        );
        *t = Some(std::thread::spawn(move || {
            Self::handle_connect(&path, &socket, &epoll, &stop, &cv, &lock);
            let mut after_connect = true;
            let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; CLIENT_EPOLL_EVENTS];
            'main: while !stop.load(Ordering::SeqCst) {
                let n = epoll.wait(&mut events, -1);
                for i in 0..n.max(0) as usize {
                    let fd = events[i].u64 as i32;
                    let ev = events[i].events;
                    if fd == stop_rd {
                        let mut d = [0u8; 1];
                        // SAFETY: reading one byte from our pipe.
                        unsafe { libc::read(stop_rd, d.as_mut_ptr().cast(), 1) };
                        break;
                    }
                    let r: SockResult<()> = (|| {
                        if ev & (libc::EPOLLERR | libc::EPOLLHUP) as u32 != 0 {
                            Self::handle_connect(&path, &socket, &epoll, &stop, &cv, &lock);
                            after_connect = true;
                        }
                        if ev & libc::EPOLLOUT as u32 != 0 {
                            if after_connect {
                                after_connect = false;
                                on_connect();
                            }
                            let _w = lock.write();
                            if socket.send_unsent_messages().is_ok() {
                                epoll.modify(socket.fd(), libc::EPOLLIN as u32);
                            }
                        }
                        if ev & libc::EPOLLIN as u32 != 0 {
                            let _w = lock.write();
                            socket.read(&|_, body, header| on_read(body, header))?;
                        }
                        Ok(())
                    })();
                    if r.is_err() {
                        stop.store(true, Ordering::SeqCst);
                        break 'main;
                    }
                }
            }
        }));
    }

    /// `send(body, header)`
    pub fn send(&self, body: &[u8], header: &[u8]) {
        let _r = self.socket_mutex.read();
        if self.socket.send(body, header).is_err() {
            self.epoll.modify(self.socket.fd(), (libc::EPOLLIN | libc::EPOLLOUT) as u32);
        }
    }

    /// `stop`
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
        let d = b'x';
        // SAFETY: writing one byte to our pipe.
        unsafe { libc::write(self.stop_fd[1], (&d as *const u8).cast(), 1) };
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
        // SAFETY: closing our pipe.
        unsafe {
            libc::close(self.stop_fd[0]);
            libc::close(self.stop_fd[1]);
        }
    }
}
