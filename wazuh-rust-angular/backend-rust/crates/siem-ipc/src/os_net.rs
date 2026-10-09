//! Blocking port of `src/os_net/os_net.c` on raw file descriptors, for the
//! daemons that keep Wazuh's threaded, select-based design (wazuh-agentd
//! and the other agent daemons). Return values follow the C code: a
//! descriptor, `OS_SOCKTERR` / `OS_INVALID`, or a byte count.
//!
//! The few messages os_net.c logs go to the logger installed with
//! [`set_logger`].

use std::ffi::CString;
use std::sync::{Arc, OnceLock};

use siem_log::WLog;

// glibc functions the libc crate does not bind.
mod ffi {
    extern "C" {
        pub fn inet_pton(af: libc::c_int, src: *const libc::c_char, dst: *mut libc::c_void) -> libc::c_int;
        pub fn inet_ntop(af: libc::c_int, src: *const libc::c_void, dst: *mut libc::c_char, size: libc::socklen_t) -> *const libc::c_char;
    }
}

pub const OS_SUCCESS: i32 = 0;
pub const OS_INVALID: i32 = -1;
pub const OS_SOCKTERR: i32 = -6;
pub const OS_SOCKBUSY: i32 = -11;
pub const OS_MAXSTR: i32 = 65536;
pub const BACKLOG: i32 = 128;
pub const RECV_SOCK: i32 = 0;
pub const SEND_SOCK: i32 = 1;
/// `IPPROTO_TCP` / `IPPROTO_UDP`
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const IPV6_LINK_LOCAL_PREFIX: &str = "FE80:0000:0000:0000:";
/// `INET6_ADDRSTRLEN`
pub const IPSIZE: usize = 46;

static LOGGER: OnceLock<Arc<WLog>> = OnceLock::new();

/// Installs the daemon's logger for os_net / mq_op messages.
pub fn set_logger(log: Arc<WLog>) {
    let _ = LOGGER.set(log);
}

pub(crate) fn logger() -> Option<&'static Arc<WLog>> {
    LOGGER.get()
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn set_errno(e: i32) {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = e
    };
    #[cfg(not(target_os = "linux"))]
    let _ = e;
}

pub fn strerror(e: i32) -> String {
    unsafe { std::ffi::CStr::from_ptr(libc::strerror(e)).to_string_lossy().into_owned() }
}

fn cstr(s: &str) -> CString {
    CString::new(s.split('\0').next().unwrap_or("")).unwrap()
}

/// `get_ipv4_numeric`: inet_pton(AF_INET). On failure `addr` is untouched.
pub fn get_ipv4_numeric(address: &str, addr: &mut libc::in_addr) -> i32 {
    let c = cstr(address);
    if unsafe { ffi::inet_pton(libc::AF_INET, c.as_ptr(), (addr as *mut libc::in_addr).cast()) } == 1 {
        OS_SUCCESS
    } else {
        OS_INVALID
    }
}

/// `get_ipv6_numeric`
pub fn get_ipv6_numeric(address: &str, addr: &mut libc::in6_addr) -> i32 {
    let c = cstr(address);
    if unsafe { ffi::inet_pton(libc::AF_INET6, c.as_ptr(), (addr as *mut libc::in6_addr).cast()) } == 1 {
        OS_SUCCESS
    } else {
        OS_INVALID
    }
}

/// `get_ipv4_string` (inet_ntop into a buffer of `size` bytes).
pub fn get_ipv4_string(addr: libc::in_addr, size: usize) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; size.max(1)];
    let r = unsafe {
        ffi::inet_ntop(libc::AF_INET, (&addr as *const libc::in_addr).cast(), buf.as_mut_ptr(), size as libc::socklen_t)
    };
    if r.is_null() {
        return None;
    }
    Some(unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned())
}

/// `get_ipv6_string`: inet_ntop, then `OS_GetIPv4FromIPv6` or `OS_ExpandIPv6`.
pub fn get_ipv6_string(addr: libc::in6_addr, size: usize) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; size.max(1)];
    let r = unsafe {
        ffi::inet_ntop(libc::AF_INET6, (&addr as *const libc::in6_addr).cast(), buf.as_mut_ptr(), size as libc::socklen_t)
    };
    if r.is_null() {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned();
    if let Some(v4) = siem_regex::os_ip::get_ipv4_from_ipv6(&s) {
        return Some(v4);
    }
    Some(siem_regex::os_ip::expand_ipv6(&s).unwrap_or(s))
}

/// `OS_CloseSocket`
pub fn close_socket(sock: i32) -> i32 {
    unsafe {
        libc::shutdown(sock, libc::SHUT_RDWR);
        libc::close(sock)
    }
}

/// `OS_SetSocketSize`
pub fn set_socket_size(sock: i32, mode: i32, max_msg_size: i32) -> i32 {
    let opt = if mode == RECV_SOCK {
        libc::SO_RCVBUF
    } else if mode == SEND_SOCK {
        libc::SO_SNDBUF
    } else {
        return 0;
    };
    let mut len: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe { libc::getsockopt(sock, libc::SOL_SOCKET, opt, (&mut len as *mut libc::c_int).cast(), &mut optlen) } == -1 {
        len = 0;
    }
    if len < max_msg_size {
        len = max_msg_size;
        if unsafe { libc::setsockopt(sock, libc::SOL_SOCKET, opt, (&len as *const libc::c_int).cast(), optlen) } < 0 {
            return -1;
        }
    }
    0
}

/// `OS_getsocketsize`
pub fn get_socket_size(sock: i32) -> i32 {
    let mut len: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe { libc::getsockopt(sock, libc::SOL_SOCKET, libc::SO_SNDBUF, (&mut len as *mut libc::c_int).cast(), &mut optlen) } == -1 {
        return OS_SOCKTERR;
    }
    len
}

fn set_cloexec(sock: i32) {
    if unsafe { libc::fcntl(sock, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        let e = errno();
        if let Some(l) = logger() {
            l.warn(format!("Cannot set close-on-exec flag to socket: {} ({})", strerror(e), e));
        }
    }
}

fn unix_addr(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // strncpy(sun_path, path, sizeof(sun_path) - 1)
    let bytes = path.as_bytes();
    let mut n = 0;
    while n < a.sun_path.len() - 1 && n < bytes.len() && bytes[n] != 0 {
        a.sun_path[n] = bytes[n] as libc::c_char;
        n += 1;
    }
    // SUN_LEN
    let len = std::mem::size_of::<libc::sa_family_t>() + n;
    (a, len as libc::socklen_t)
}

/// `OS_BindUnixDomainWithPerms`
pub fn bind_unix_domain_with_perms(path: &str, ty: i32, max_msg_size: i32, uid: u32, gid: u32, mode: u32) -> i32 {
    let c = cstr(path);
    unsafe { libc::unlink(c.as_ptr()) };
    let (a, len) = unix_addr(path);
    let sock = unsafe { libc::socket(libc::AF_UNIX, ty, 0) };
    if sock < 0 {
        return OS_SOCKTERR;
    }
    unsafe {
        if libc::bind(sock, (&a as *const libc::sockaddr_un).cast(), len) < 0
            || libc::chmod(c.as_ptr(), mode as libc::mode_t) < 0
            || libc::chown(c.as_ptr(), uid, gid) < 0
            || (ty == libc::SOCK_STREAM && libc::listen(sock, 128) < 0)
        {
            close_socket(sock);
            return OS_SOCKTERR;
        }
    }
    if set_socket_size(sock, RECV_SOCK, max_msg_size) < 0 {
        close_socket(sock);
        return OS_SOCKTERR;
    }
    set_cloexec(sock);
    sock
}

/// `OS_BindUnixDomain`
pub fn bind_unix_domain(path: &str, ty: i32, max_msg_size: i32) -> i32 {
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    bind_unix_domain_with_perms(path, ty, max_msg_size, uid, gid, 0o660)
}

/// `OS_ConnectUnixDomain`
pub fn connect_unix_domain(path: &str, ty: i32, max_msg_size: i32) -> i32 {
    let (a, len) = unix_addr(path);
    let sock = unsafe { libc::socket(libc::AF_UNIX, ty, 0) };
    if sock < 0 {
        return OS_SOCKTERR;
    }
    if unsafe { libc::connect(sock, (&a as *const libc::sockaddr_un).cast(), len) } < 0 {
        let e = errno();
        close_socket(sock);
        set_errno(e);
        return OS_SOCKTERR;
    }
    if set_socket_size(sock, SEND_SOCK, max_msg_size) < 0 {
        close_socket(sock);
        return OS_SOCKTERR;
    }
    set_cloexec(sock);
    sock
}

/// `OS_Connect`
fn os_connect(port: u16, protocol: i32, ip: &str, ipv6: bool, network_interface: u32) -> i32 {
    let max_msg_size = OS_MAXSTR + 512;
    let fam = if ipv6 { libc::AF_INET6 } else { libc::AF_INET };
    let sock = if protocol == IPPROTO_TCP {
        unsafe { libc::socket(fam, libc::SOCK_STREAM, libc::IPPROTO_TCP) }
    } else if protocol == IPPROTO_UDP {
        unsafe { libc::socket(fam, libc::SOCK_DGRAM, libc::IPPROTO_UDP) }
    } else {
        return OS_INVALID;
    };
    if sock < 0 {
        return OS_SOCKTERR;
    }
    if ip.is_empty() {
        close_socket(sock);
        return OS_INVALID;
    }
    let fail = |sock: i32| {
        let e = errno();
        close_socket(sock);
        set_errno(e);
        OS_SOCKTERR
    };
    if ipv6 {
        let mut is_link_local = false;
        if ip.as_bytes().starts_with(IPV6_LINK_LOCAL_PREFIX.as_bytes()) {
            if network_interface == 0 {
                if let Some(l) = logger() {
                    l.info("No network interface provided to use with link-local IPv6 address.");
                }
            }
            is_link_local = true;
        }
        let mut local: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        local.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        if is_link_local && network_interface > 0 {
            local.sin6_scope_id = network_interface;
        }
        let sz = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        if unsafe { libc::bind(sock, (&local as *const libc::sockaddr_in6).cast(), sz) } < 0 {
            return fail(sock);
        }
        let mut server: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        server.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        server.sin6_port = port.to_be();
        if is_link_local && network_interface > 0 {
            server.sin6_scope_id = network_interface;
        }
        get_ipv6_numeric(ip, &mut server.sin6_addr);
        if unsafe { libc::connect(sock, (&server as *const libc::sockaddr_in6).cast(), sz) } < 0 {
            return fail(sock);
        }
    } else {
        let mut local: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        local.sin_family = libc::AF_INET as libc::sa_family_t;
        let sz = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if unsafe { libc::bind(sock, (&local as *const libc::sockaddr_in).cast(), sz) } < 0 {
            return fail(sock);
        }
        let mut server: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        server.sin_family = libc::AF_INET as libc::sa_family_t;
        server.sin_port = port.to_be();
        get_ipv4_numeric(ip, &mut server.sin_addr);
        if unsafe { libc::connect(sock, (&server as *const libc::sockaddr_in).cast(), sz) } < 0 {
            return fail(sock);
        }
    }
    if set_socket_size(sock, RECV_SOCK, max_msg_size) < 0 || set_socket_size(sock, SEND_SOCK, max_msg_size) < 0 {
        close_socket(sock);
        return OS_SOCKTERR;
    }
    sock
}

/// `OS_ConnectTCP`
pub fn connect_tcp(port: u16, ip: &str, ipv6: bool, network_interface: u32) -> i32 {
    os_connect(port, IPPROTO_TCP, ip, ipv6, network_interface)
}

/// `OS_ConnectUDP`
pub fn connect_udp(port: u16, ip: &str, ipv6: bool, network_interface: u32) -> i32 {
    os_connect(port, IPPROTO_UDP, ip, ipv6, network_interface)
}

/// `OS_Bindport`
fn bindport(port: u16, proto: i32, ip: Option<&str>, ipv6: bool) -> i32 {
    let fam = if ipv6 { libc::AF_INET6 } else { libc::AF_INET };
    let sock;
    if proto == IPPROTO_UDP {
        sock = unsafe { libc::socket(fam, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
        if sock < 0 {
            return OS_SOCKTERR;
        }
    } else if proto == IPPROTO_TCP {
        sock = unsafe { libc::socket(fam, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
        if sock < 0 {
            return OS_SOCKTERR;
        }
        let flag: libc::c_int = 1;
        if unsafe { libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_REUSEADDR, (&flag as *const libc::c_int).cast(), 4) } < 0 {
            close_socket(sock);
            return OS_SOCKTERR;
        }
    } else {
        return OS_INVALID;
    }
    let ip = ip.filter(|s| !s.is_empty());
    let r = if ipv6 {
        let mut a: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        a.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        a.sin6_port = port.to_be();
        if let Some(ip) = ip {
            get_ipv6_numeric(ip, &mut a.sin6_addr);
        }
        unsafe { libc::bind(sock, (&a as *const libc::sockaddr_in6).cast(), std::mem::size_of::<libc::sockaddr_in6>() as u32) }
    } else {
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        a.sin_family = libc::AF_INET as libc::sa_family_t;
        a.sin_port = port.to_be();
        if let Some(ip) = ip {
            get_ipv4_numeric(ip, &mut a.sin_addr);
        }
        unsafe { libc::bind(sock, (&a as *const libc::sockaddr_in).cast(), std::mem::size_of::<libc::sockaddr_in>() as u32) }
    };
    if r < 0 || (proto == IPPROTO_TCP && unsafe { libc::listen(sock, BACKLOG) } < 0) {
        close_socket(sock);
        return OS_SOCKTERR;
    }
    sock
}

/// `OS_Bindporttcp`
pub fn bindport_tcp(port: u16, ip: Option<&str>, ipv6: bool) -> i32 {
    bindport(port, IPPROTO_TCP, ip, ipv6)
}

/// `OS_Bindportudp`
pub fn bindport_udp(port: u16, ip: Option<&str>, ipv6: bool) -> i32 {
    bindport(port, IPPROTO_UDP, ip, ipv6)
}

/// `OS_AcceptTCP`: returns the client socket and its address string.
pub fn accept_tcp(sock: i32, addrsize: usize) -> (i32, String) {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let c = unsafe { libc::accept(sock, (&mut ss as *mut libc::sockaddr_storage).cast(), &mut len) };
    if c < 0 {
        return (-1, String::new());
    }
    match ss.ss_family as i32 {
        libc::AF_INET => {
            let a: libc::sockaddr_in = unsafe { std::ptr::read((&ss as *const libc::sockaddr_storage).cast()) };
            (c, get_ipv4_string(a.sin_addr, addrsize - 1).unwrap_or_default())
        }
        libc::AF_INET6 => {
            let a: libc::sockaddr_in6 = unsafe { std::ptr::read((&ss as *const libc::sockaddr_storage).cast()) };
            (c, get_ipv6_string(a.sin6_addr, addrsize - 1).unwrap_or_default())
        }
        _ => {
            unsafe { libc::close(c) };
            (-1, String::new())
        }
    }
}

fn send(sock: i32, buf: &[u8], flags: i32) -> isize {
    unsafe { libc::send(sock, buf.as_ptr().cast(), buf.len(), flags) }
}

fn recv(sock: i32, buf: &mut [u8]) -> isize {
    unsafe { libc::recv(sock, buf.as_mut_ptr().cast(), buf.len(), 0) }
}

/// `OS_SendTCP` (`msg` stops at its first NUL like `strlen`).
pub fn send_tcp(sock: i32, msg: &[u8]) -> i32 {
    let n = msg.iter().position(|&b| b == 0).unwrap_or(msg.len());
    if send(sock, &msg[..n], 0) <= 0 {
        OS_SOCKTERR
    } else {
        0
    }
}

/// `OS_SendTCPbySize`
pub fn send_tcp_by_size(sock: i32, msg: &[u8]) -> i32 {
    if send(sock, msg, 0) < msg.len() as isize {
        OS_SOCKTERR
    } else {
        0
    }
}

/// `OS_SendUDPbySize`: retries up to 5 times on ENOBUFS.
pub fn send_udp_by_size(sock: i32, msg: &[u8]) -> i32 {
    let mut i = 0u32;
    while send(sock, msg, 0) < 0 {
        if errno() != libc::ENOBUFS || i >= 5 {
            return OS_SOCKTERR;
        }
        i += 1;
        if let Some(l) = logger() {
            l.info(format!("Remote socket busy, waiting {i} s."));
        }
        std::thread::sleep(std::time::Duration::from_secs(i as u64));
    }
    0
}

/// `OS_RecvTCPBuffer`: up to `size - 1` bytes.
pub fn recv_tcp_buffer(sock: i32, buf: &mut [u8], size: usize) -> isize {
    let n = size.saturating_sub(1).min(buf.len());
    recv(sock, &mut buf[..n])
}

/// `OS_RecvConnUDP`: returns 0 on error.
pub fn recv_conn_udp(sock: i32, buf: &mut [u8], size: usize) -> i32 {
    let n = size.min(buf.len());
    let r = recv(sock, &mut buf[..n]);
    if r < 0 {
        0
    } else {
        r as i32
    }
}

/// `OS_RecvUnix`: up to `size - 1` bytes, 0 on error.
pub fn recv_unix(sock: i32, size: usize, buf: &mut Vec<u8>) -> i32 {
    buf.resize(size, 0);
    let r = unsafe {
        libc::recvfrom(sock, buf.as_mut_ptr().cast(), size - 1, 0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    if r < 0 {
        buf.clear();
        return 0;
    }
    buf.truncate(r as usize);
    r as i32
}

/// `OS_SendUnix`: `size` 0 means `strlen(msg) + 1` (the NUL is sent).
pub fn send_unix(sock: i32, msg: &[u8], size: usize) -> i32 {
    let owned;
    let data: &[u8] = if size == 0 {
        let n = msg.iter().position(|&b| b == 0).unwrap_or(msg.len());
        let mut v = msg[..n].to_vec();
        v.push(0);
        owned = v;
        &owned
    } else {
        &msg[..size.min(msg.len())]
    };
    if send(sock, data, 0) < data.len() as isize {
        if errno() == libc::ENOBUFS {
            return OS_SOCKBUSY;
        }
        return OS_SOCKTERR;
    }
    OS_SUCCESS
}

/// `OS_SendSecureTCP`
pub fn send_secure_tcp(sock: i32, msg: &[u8]) -> i32 {
    if sock < 0 {
        return OS_SOCKTERR;
    }
    let mut buf = Vec::with_capacity(msg.len() + 4);
    buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    buf.extend_from_slice(msg);
    set_errno(0);
    if send(sock, &buf, 0) == buf.len() as isize {
        0
    } else {
        OS_SOCKTERR
    }
}

/// `os_recv_waitall`
pub fn recv_waitall(sock: i32, buf: &mut [u8]) -> isize {
    let mut off = 0;
    while off < buf.len() {
        let r = recv(sock, &mut buf[off..]);
        if r <= 0 {
            return r;
        }
        off += r as usize;
    }
    off as isize
}

/// `OS_RecvSecureTCP`: reads one frame of at most `size` bytes into `ret`
/// (resized to the frame). Returns the payload length, 0 on disconnect,
/// -1 on error or `OS_SOCKTERR` when the frame is too long.
pub fn recv_secure_tcp(sock: i32, ret: &mut Vec<u8>, size: u32) -> isize {
    let mut hdr = [0u8; 4];
    let r = recv_waitall(sock, &mut hdr);
    if r == -1 || r == 0 {
        return r;
    }
    let msgsize = u32::from_le_bytes(hdr);
    if msgsize > size {
        return OS_SOCKTERR as isize;
    }
    ret.clear();
    ret.resize(msgsize as usize, 0);
    let rb = recv_waitall(sock, ret);
    if rb >= 0 && (rb as usize) < ret.len() {
        ret.truncate(rb as usize);
    }
    rb
}

/// `OS_SetRecvTimeout`
pub fn set_recv_timeout(sock: i32, seconds: i64, useconds: i64) -> i32 {
    let tv = libc::timeval { tv_sec: seconds as libc::time_t, tv_usec: useconds as libc::suseconds_t };
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as u32,
        )
    }
}

/// `OS_SetSendTimeout`
pub fn set_send_timeout(sock: i32, seconds: i32) -> i32 {
    let tv = libc::timeval { tv_sec: seconds as libc::time_t, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as u32,
        )
    }
}

/// `OS_SetKeepalive`
pub fn set_keepalive(sock: i32) -> i32 {
    let v: libc::c_int = 1;
    unsafe { libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_KEEPALIVE, (&v as *const libc::c_int).cast(), 4) }
}

/// `OS_SetKeepalive_Options`
pub fn set_keepalive_options(sock: i32, idle: i32, intvl: i32, cnt: i32) {
    let set = |opt: i32, v: i32, name: &str| {
        if unsafe { libc::setsockopt(sock, libc::IPPROTO_TCP, opt, (&v as *const i32).cast(), 4) } < 0 {
            if let Some(l) = logger() {
                l.error(format!("OS_SetKeepalive_Options({name}) failed with error '{}'", strerror(errno())));
            }
        }
    };
    if cnt > 0 {
        set(libc::TCP_KEEPCNT, cnt, "TCP_KEEPCNT");
    }
    if idle > 0 {
        set(libc::TCP_KEEPIDLE, idle, "SO_KEEPIDLE");
    }
    if intvl > 0 {
        set(libc::TCP_KEEPINTVL, intvl, "TCP_KEEPINTVL");
    }
}

/// `wnet_select`
pub fn wnet_select(sock: i32, timeout: i64) -> i32 {
    unsafe {
        let mut set: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut set);
        libc::FD_SET(sock, &mut set);
        let mut tv = libc::timeval { tv_sec: timeout as libc::time_t, tv_usec: 0 };
        libc::select(sock + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv)
    }
}

/// `OS_GetHost`: first IPv4/IPv6 address of `host`, retrying `attempts`
/// times with one second between failed lookups.
pub fn get_host(host: &str, attempts: u32) -> Option<String> {
    let c = cstr(host);
    let mut i = 0;
    while i <= attempts {
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        if unsafe { libc::getaddrinfo(c.as_ptr(), std::ptr::null(), std::ptr::null(), &mut res) } != 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            i += 1;
            continue;
        }
        let mut ip = None;
        let mut p = res;
        while !p.is_null() {
            let ai = unsafe { &*p };
            if ai.ai_family == libc::AF_INET {
                let a: libc::sockaddr_in = unsafe { std::ptr::read(ai.ai_addr.cast()) };
                ip = Some(get_ipv4_string(a.sin_addr, IPSIZE).unwrap_or_default());
                break;
            } else if ai.ai_family == libc::AF_INET6 {
                let a: libc::sockaddr_in6 = unsafe { std::ptr::read(ai.ai_addr.cast()) };
                ip = Some(get_ipv6_string(a.sin6_addr, IPSIZE).unwrap_or_default());
                break;
            }
            p = ai.ai_next;
        }
        unsafe { libc::freeaddrinfo(res) };
        return ip;
    }
    None
}

/// `resolve_hostname`: "host" becomes "host/ip" (or "host/" when it does
/// not resolve); an IP address is kept as it is.
pub fn resolve_hostname(hostname: &mut String, attempts: u32) {
    if siem_regex::is_valid_ip(hostname).0 == 1 {
        return;
    }
    if let Some(i) = hostname.find('/') {
        hostname.truncate(i);
    }
    let s = match get_host(hostname, attempts) {
        Some(ip) => format!("{hostname}/{ip}"),
        None => format!("{hostname}/"),
    };
    // snprintf(ip_str, 127, ...)
    let mut n = s.len().min(126);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    *hostname = s[..n].to_string();
}

/// `get_ip_from_resolved_hostname`
pub fn get_ip_from_resolved_hostname(resolved: &str) -> &str {
    match resolved.find('/') {
        Some(i) => &resolved[i + 1..],
        None => resolved,
    }
}

/// `external_socket_connect`
pub fn external_socket_connect(path: &str, response_timeout: i64) -> i32 {
    let sock = connect_unix_domain(path, libc::SOCK_STREAM, OS_MAXSTR);
    if sock < 0 {
        return sock;
    }
    if set_send_timeout(sock, 5) < 0 || set_recv_timeout(sock, response_timeout, 0) < 0 {
        unsafe { libc::close(sock) };
        return -1;
    }
    sock
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_tcp_roundtrip() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) }, 0);
        assert_eq!(send_secure_tcp(fds[0], b"hello"), 0);
        let mut v = Vec::new();
        assert_eq!(recv_secure_tcp(fds[1], &mut v, 100), 5);
        assert_eq!(v, b"hello");
        assert_eq!(send_secure_tcp(fds[0], b"toolong"), 0);
        assert_eq!(recv_secure_tcp(fds[1], &mut v, 3), OS_SOCKTERR as isize);
        close_socket(fds[0]);
        close_socket(fds[1]);
    }

    #[test]
    fn resolve() {
        let mut h = "localhost".to_string();
        resolve_hostname(&mut h, 0);
        assert!(h.starts_with("localhost/"), "{h}");
        let mut ip = "10.0.0.1".to_string();
        resolve_hostname(&mut ip, 0);
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(get_ip_from_resolved_hostname("a/1.2.3.4"), "1.2.3.4");
    }
}
