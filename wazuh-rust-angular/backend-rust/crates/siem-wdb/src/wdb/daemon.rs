//! The wazuh-db daemon (wazuh_db/main.c): the local socket dealer, the
//! worker pool sharing an epoll notification queue, and the gc, upgrade
//! and backup threads. Linux only, like the C (`wnotify` is epoll there).

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use siem_log::WLog;

use super::state::Tv;
use super::*;

/// `WDB_AGENT_EVENTS_TOPIC` / `WDB_INVENTORY_EVENTS_TOPIC`
pub const WDB_AGENT_EVENTS_TOPIC: &str = "wdb-agent-events";
pub const WDB_INVENTORY_EVENTS_TOPIC: &str = "wdb-inventory-events";

/// The router providers the daemon publishes to (`router_provider_send`).
pub trait RouterSink: Send + Sync {
    /// `router_provider_create(topic, false)`: whether a handle was created.
    fn create(&self, topic: &str) -> bool;
    /// `router_provider_send(handle, msg, len)`
    fn send(&self, topic: &str, msg: &[u8]) -> i32;
}

/// The router module (siem-router): remote providers of the topics,
/// `router_provider_create(topic, false)` / `router_provider_send`.
#[derive(Default)]
pub struct WazuhRouter {
    handles: Mutex<std::collections::HashMap<String, siem_router::ProviderHandle>>,
}

impl RouterSink for WazuhRouter {
    fn create(&self, topic: &str) -> bool {
        let h = siem_router::router_provider_create(topic, false);
        if h == 0 {
            return false;
        }
        self.handles.lock().insert(topic.to_string(), h);
        true
    }
    fn send(&self, topic: &str, msg: &[u8]) -> i32 {
        let h = self.handles.lock().get(topic).copied().unwrap_or(0);
        siem_router::router_provider_send(h, msg)
    }
}

/// `router_initialize(taggedLogFunction)`: the module logs with the
/// ":router" tag.
pub fn router_initialize(log: Arc<WLog>) {
    siem_router::router_initialize(Arc::new(move |level: &str, msg: &[u8]| {
        let lv = match level {
            "ERROR" => "ERROR",
            "ERROR_EXIT" => "CRITICAL",
            "INFO" => "INFO",
            "WARNING" => "WARNING",
            "DEBUG" => "DEBUG",
            "DEBUG_VERBOSE" => "DEBUG2",
            _ => return,
        };
        log.tagged(":router", lv, msg);
        if level == "ERROR_EXIT" {
            std::process::exit(1);
        }
    }));
}

/// A router without a broker: providers are created and messages dropped.
pub struct NullRouter;

impl RouterSink for NullRouter {
    fn create(&self, _topic: &str) -> bool {
        true
    }
    fn send(&self, _topic: &str, _msg: &[u8]) -> i32 {
        0
    }
}

/// The process services of the daemon.
pub struct DaemonEnv {
    pub log: Arc<WLog>,
    pub router: Arc<dyn RouterSink>,
    /// The `ossec.conf` `w_is_single_node` reads.
    pub ossecconf: std::path::PathBuf,
}

/// `errno` and `strerror(errno)` of the last OS error.
fn last_errno() -> (i32, String) {
    errno_text(&std::io::Error::last_os_error())
}

impl WdbEnv for DaemonEnv {
    #[track_caller]
    fn log(&self, level: &str, msg: &[u8]) {
        match level {
            "ERROR" => self.log.error(msg),
            "WARNING" => self.log.warn(msg),
            "INFO" => self.log.info(msg),
            "DEBUG" => self.log.debug1(msg),
            "DEBUG2" => self.log.debug2(msg),
            "CRITICAL" => self.log.critical(msg),
            _ => self.log.error(msg),
        }
    }

    fn time(&self) -> i64 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(_) => 0,
        }
    }

    fn timeofday(&self) -> Tv {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        Tv { sec: d.as_secs() as i64, usec: d.subsec_micros() as i64 }
    }

    fn router_send(&self, handle: i32, msg: &[u8]) {
        let topic = if handle == 1 { WDB_AGENT_EVENTS_TOPIC } else { WDB_INVENTORY_EVENTS_TOPIC };
        self.router.send(topic, msg);
    }

    fn send_peer(&self, peer: i32, msg: &[u8]) -> i32 {
        os_send_secure_tcp(peer, msg)
    }

    fn set_send_timeout(&self, peer: i32, secs: i32) -> i32 {
        let tv = libc::timeval { tv_sec: secs as libc::time_t, tv_usec: 0 };
        // SAFETY: valid socket option pointer and size.
        unsafe {
            libc::setsockopt(
                peer,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        }
    }

    fn is_single_node(&self) -> (i32, i32) {
        let (single, worker) = siem_config::cluster::is_single_node(&self.ossecconf);
        let b = |v: Option<bool>| match v {
            Some(true) => 1,
            Some(false) => 0,
            None => OS_INVALID,
        };
        (b(single), b(worker))
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    fn close_peer(&self, peer: i32) {
        // SAFETY: closing a descriptor the worker owns.
        unsafe {
            libc::close(peer);
        }
    }
}

/// `OS_SendSecureTCP`: 0 or OS_SOCKTERR.
pub fn os_send_secure_tcp(sock: i32, msg: &[u8]) -> i32 {
    if sock < 0 {
        return OS_SOCKTERR;
    }
    let mut buf = Vec::with_capacity(msg.len() + 4);
    buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    buf.extend_from_slice(msg);
    // SAFETY: valid buffer; errno = 0 like the C.
    unsafe {
        *libc::__errno_location() = 0;
        if libc::send(sock, buf.as_ptr().cast(), buf.len(), 0) == buf.len() as isize {
            0
        } else {
            OS_SOCKTERR
        }
    }
}

/// `os_recv_waitall`
fn os_recv_waitall(sock: i32, buf: &mut [u8]) -> isize {
    let mut offset = 0;
    while offset < buf.len() {
        // SAFETY: the slice bounds the write.
        let r = unsafe { libc::recv(sock, buf[offset..].as_mut_ptr().cast(), buf.len() - offset, 0) };
        if r <= 0 {
            return r;
        }
        offset += r as usize;
    }
    offset as isize
}

/// `OS_RecvSecureTCP`: the payload length, 0 / -1 from the header read, or
/// OS_SOCKTERR when the announced size is bigger than `size`.
pub fn os_recv_secure_tcp(sock: i32, ret: &mut [u8], size: usize) -> isize {
    let mut hdr = [0u8; 4];
    let r = os_recv_waitall(sock, &mut hdr);
    if r == -1 || r == 0 {
        return r;
    }
    let msgsize = u32::from_le_bytes(hdr) as usize;
    if msgsize > size {
        return OS_SOCKTERR as isize;
    }
    let recvb = os_recv_waitall(sock, &mut ret[..msgsize]);
    if recvb == msgsize as isize && msgsize < size {
        ret[msgsize] = 0;
    }
    recvb
}

/// `OS_BindUnixDomain(path, SOCK_STREAM, max_msg_size)`
pub fn os_bind_unix_domain(path: &str, max_msg_size: i32) -> i32 {
    let Ok(cpath) = std::ffi::CString::new(path) else {
        return OS_SOCKTERR;
    };
    // SAFETY: plain socket calls with valid arguments.
    unsafe {
        libc::unlink(cpath.as_ptr());
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in path.bytes().take(addr.sun_path.len() - 1).enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        let sock = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if sock < 0 {
            return OS_SOCKTERR;
        }
        // SUN_LEN
        let len = (std::mem::size_of::<libc::sa_family_t>() + path.len().min(addr.sun_path.len() - 1)) as libc::socklen_t;
        if libc::bind(sock, (&addr as *const libc::sockaddr_un).cast(), len) < 0
            || libc::chmod(cpath.as_ptr(), 0o660) < 0
            || libc::chown(cpath.as_ptr(), libc::getuid(), libc::getgid()) < 0
            || libc::listen(sock, 128) < 0
        {
            libc::close(sock);
            return OS_SOCKTERR;
        }
        // OS_SetSocketSize(RECV_SOCK)
        let mut cur: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::getsockopt(sock, libc::SOL_SOCKET, libc::SO_RCVBUF, (&mut cur as *mut libc::c_int).cast(), &mut optlen) == -1 {
            cur = 0;
        }
        if cur < max_msg_size {
            let v: libc::c_int = max_msg_size;
            if libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_RCVBUF, (&v as *const libc::c_int).cast(), optlen) < 0 {
                libc::close(sock);
                return OS_SOCKTERR;
            }
        }
        sock
    }
}

/// `wnotify_t` (epoll, one event per wait).
pub struct Notify {
    fd: i32,
    event: Mutex<libc::epoll_event>,
}

impl Notify {
    /// `wnotify_init(1)`
    pub fn init() -> Option<Notify> {
        // SAFETY: epoll_create with a positive size.
        let fd = unsafe { libc::epoll_create(1) };
        (fd >= 0).then(|| Notify { fd, event: Mutex::new(libc::epoll_event { events: 0, u64: 0 }) })
    }

    fn ctl(&self, op: i32, fd: i32) -> i32 {
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: fd as u64 };
        // SAFETY: valid epoll descriptor and event.
        unsafe { libc::epoll_ctl(self.fd, op, fd, &mut ev) }
    }

    /// `wnotify_add(notify, fd, WO_READ)`
    pub fn add(&self, fd: i32) -> i32 {
        self.ctl(libc::EPOLL_CTL_ADD, fd)
    }

    /// `wnotify_delete(notify, fd, WO_READ)`
    pub fn delete(&self, fd: i32) -> i32 {
        self.ctl(libc::EPOLL_CTL_DEL, fd)
    }

    /// `wnotify_wait(notify, timeout)`
    pub fn wait(&self, timeout_ms: i32) -> i32 {
        let mut ev = self.event.lock();
        // SAFETY: room for exactly one event.
        unsafe { libc::epoll_wait(self.fd, &mut *ev, 1, timeout_ms) }
    }

    /// `wnotify_get(notify, 0, NULL)`
    pub fn get(&self) -> i32 {
        self.event.lock().u64 as i32
    }
}

impl Drop for Notify {
    /// `wnotify_close`
    fn drop(&mut self) {
        // SAFETY: closing our epoll descriptor.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// `running`, cleared by the signal handler.
pub static RUNNING: AtomicBool = AtomicBool::new(true);
static SIGNUM: AtomicI32 = AtomicI32::new(0);

extern "C" fn handler(sig: libc::c_int) {
    SIGNUM.store(sig, Ordering::SeqCst);
    RUNNING.store(false, Ordering::SeqCst);
}

/// The signal manipulation of main(): SIGTERM/SIGHUP/SIGINT stop the
/// daemon (SA_RESTART), SIGPIPE is ignored. The handler's log message is
/// written by a watcher thread.
pub fn install_signals(log: Arc<WLog>) {
    // SAFETY: installing handlers with valid function pointers.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        for s in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
            libc::sigaction(s, &action, std::ptr::null_mut());
        }
        let mut ign: libc::sigaction = std::mem::zeroed();
        ign.sa_sigaction = libc::SIG_IGN;
        ign.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGPIPE, &ign, std::ptr::null_mut());
    }
    std::thread::spawn(move || loop {
        let s = SIGNUM.swap(0, Ordering::SeqCst);
        if s != 0 {
            // SAFETY: strsignal returns a static string or NULL.
            let name = unsafe {
                let p = libc::strsignal(s);
                if p.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
                }
            };
            log.info(format!("(1225): SIGNAL [({s})-({name})] Received. Exit Cleaning..."));
        }
        std::thread::sleep(Duration::from_millis(50));
    });
}

fn running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// `run_dealer`
pub fn run_dealer(d: Arc<Wdbd>, notify: Arc<Notify>) {
    let sock = os_bind_unix_domain(WDB_LOCAL_SOCK, OS_MAXSTR as i32);
    if sock < 0 {
        let (_, t) = last_errno();
        d.env.log("CRITICAL", &msg!("Unable to bind to socket '", WDB_LOCAL_SOCK, "': '", t, "'. Closing local server."));
        std::process::exit(1);
    }
    // SAFETY: FD_CLOEXEC on our socket.
    if unsafe { libc::fcntl(sock, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        let (n, t) = last_errno();
        d.mwarn(&msg!("Cannot set close-on-exec flag to socket: ", t, " (", n, ")"));
    }
    while running() {
        // Wait for socket
        let mut pfd = libc::pollfd { fd: sock, events: libc::POLLIN, revents: 0 };
        // select() with a one second timeout
        // SAFETY: one valid pollfd.
        match unsafe { libc::poll(&mut pfd, 1, 1000) } {
            -1 => {
                let (n, t) = last_errno();
                if n == libc::EINTR {
                    d.minfo(&msg!("at run_dealer(): select(): ", t));
                } else {
                    d.env.log("CRITICAL", &msg!("at run_dealer(): select(): ", t));
                    std::process::exit(1);
                }
                continue;
            }
            0 => continue,
            _ => {}
        }
        // Accept new peer
        // SAFETY: accept on a listening socket.
        let peer = unsafe { libc::accept(sock, std::ptr::null_mut(), std::ptr::null_mut()) };
        if peer < 0 {
            let (n, t) = last_errno();
            if n == libc::EINTR {
                d.minfo(&msg!("at run_dealer(): accept(): ", t));
            } else {
                d.merror(&msg!("at run_dealer(): accept(): ", t));
            }
            continue;
        }
        if notify.add(peer) < 0 {
            let (n, t) = last_errno();
            d.merror(&msg!("at run_dealer(): wnotify_add(", peer, "): ", t, " (", n, ")"));
            break;
        }
        d.mdebug1(&msg!("New client connected (", peer, ")."));
    }
    // SAFETY: closing our socket and removing its path.
    unsafe {
        libc::close(sock);
        if let Ok(p) = std::ffi::CString::new(WDB_LOCAL_SOCK) {
            libc::unlink(p.as_ptr());
        }
    }
}

/// `run_worker`
pub fn run_worker(d: Arc<Wdbd>, notify: Arc<Notify>, queue_mutex: Arc<Mutex<()>>) {
    let mut buffer = vec![0u8; OS_MAXSTR + 1];
    while running() {
        // Dequeue peer
        let g = queue_mutex.lock();
        match notify.wait(100) {
            -1 => {
                let (n, t) = last_errno();
                if n == libc::EINTR {
                    d.mdebug1(&msg!("at run_worker(): wnotify_wait(): ", t));
                } else {
                    d.merror(&msg!("at run_worker(): wnotify_wait(): ", t));
                }
                drop(g);
                continue;
            }
            0 => {
                drop(g);
                continue;
            }
            _ => {}
        }
        let peer = notify.get();
        if notify.delete(peer) < 0 {
            let (n, t) = last_errno();
            d.merror(&msg!("at run_worker(): wnotify_delete(", peer, "): ", t, " (", n, ")"));
        }
        drop(g);

        let count = os_recv_secure_tcp(peer, &mut buffer, OS_MAXSTR);
        if count == OS_SOCKTERR as isize {
            d.mwarn(&msg!("at run_worker(): received string size is bigger than ", OS_MAXSTR, " bytes"));
            // the C `break`s out of the loop: this worker ends
            break;
        }
        let length = count;
        match length {
            -1 => {
                let (n, t) = last_errno();
                d.mdebug1(&msg!("at run_worker(): at recv(): ", t, " (", n, ")"));
                // SAFETY: closing the peer.
                unsafe { libc::close(peer) };
                continue;
            }
            0 => {
                d.mdebug1(&msg!("Client ", peer, " disconnected."));
                // SAFETY: closing the peer.
                unsafe { libc::close(peer) };
                continue;
            }
            _ => {
                let length = length as usize;
                let terminal = buffer[length - 1] == b'\n';
                let req = if terminal { &buffer[..length - 1] } else { &buffer[..length] };
                // the request ends at the first NUL
                let req = cstr(req);
                let mut response = if req.first() == Some(&b'{') { d.wdbcom_dispatch(req) } else { d.parse(req, peer).1 };
                response.truncate(cstr(&response).len());
                if !response.is_empty() {
                    if terminal && response.len() < OS_MAXSTR - 1 {
                        response.push(b'\n');
                    }
                    if os_send_secure_tcp(peer, &response) < 0 {
                        let (n, t) = last_errno();
                        d.merror(&msg!("at run_worker(): OS_SendSecureTCP(", peer, "): ", t, " (", n, ")"));
                    }
                }
            }
        }
        if notify.add(peer) < 0 {
            let (n, t) = last_errno();
            d.merror(&msg!("at run_worker(): wnotify_add(", peer, "): ", t, " (", n, ")"));
        }
    }
}

/// `run_gc`
pub fn run_gc(d: Arc<Wdbd>) {
    let mut fragmentation_interval = d.cfg.check_fragmentation_interval;
    while running() {
        d.commit_old();
        if fragmentation_interval <= 0 {
            d.check_fragmentation();
            fragmentation_interval = d.cfg.check_fragmentation_interval;
        } else {
            fragmentation_interval -= 1;
        }
        d.close_old();
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// `run_backup`
pub fn run_backup(d: Arc<Wdbd>) {
    let mut last_global_backup_time = d.global_get_most_recent_backup().0;
    let global_interval = d.cfg.backup[WDB_GLOBAL_BACKUP].interval;
    let global_enabled = d.cfg.backup[WDB_GLOBAL_BACKUP].enabled;
    d.mdebug2(b"Database backup thread started.");
    while running() {
        for i in 0..WDB_LAST_BACKUP {
            if i == WDB_GLOBAL_BACKUP && global_enabled {
                let current_time = d.time();
                if current_time - last_global_backup_time >= global_interval {
                    let mut output: B = Vec::new();
                    if let Some(mut wdb) = d.open_global() {
                        if wdb.enabled && d.global_create_backup(&mut wdb, &mut output, None) != OS_SUCCESS {
                            d.merror(&msg!("Creating Global DB snapshot by interval failed: ", cstr(&output)));
                        }
                        last_global_backup_time = current_time;
                        d.leave(wdb);
                    } else {
                        last_global_backup_time = current_time;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// `run_up`: open (and upgrade) every agent database, one per second.
pub fn run_up(d: Arc<Wdbd>) {
    let db_folder = WDB2_DIR;
    let rd = match std::fs::read_dir(d.path(db_folder)) {
        Ok(r) => r,
        Err(e) => {
            let (_, t) = errno_text(&e);
            d.mdebug1(&msg!("Opening directory: '", db_folder, "': ", t));
            return;
        }
    };
    for e in rd.flatten() {
        if !running() {
            break;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name == ".template.db" || name == "000.db" || name.contains('-') {
            continue;
        }
        let Some(dot) = name.find('.') else {
            continue;
        };
        if let Some(wdb) = d.open_agent2(super::atoi(name[..dot].as_bytes())) {
            d.leave(wdb);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
