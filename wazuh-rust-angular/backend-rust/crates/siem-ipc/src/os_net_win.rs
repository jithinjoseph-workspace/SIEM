//! Windows build of `src/os_net/os_net.c` (the `WIN32` branches): Winsock
//! sockets kept as `int` like the C code, no Unix domain sockets.
//!
//! Error reporting follows the C agent: the Winsock calls set
//! `WSAGetLastError()`, while the CRT `errno` (msvcrt, the same runtime the
//! MinGW build links) is what `strerror(errno)` reports, so [`errno`] and
//! [`strerror`] go to msvcrt and [`wsa_errno`] / [`win_strerror`] to Winsock.

use std::ffi::CString;
use std::sync::{Arc, OnceLock};

use siem_log::WLog;
use windows_sys::Win32::Networking::WinSock as ws;

pub const OS_SUCCESS: i32 = 0;
pub const OS_INVALID: i32 = -1;
pub const OS_SOCKTERR: i32 = -6;
pub const OS_SOCKBUSY: i32 = -11;
pub const OS_MAXSTR: i32 = 65536;
pub const BACKLOG: i32 = 128;
pub const RECV_SOCK: i32 = 0;
pub const SEND_SOCK: i32 = 1;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const IPV6_LINK_LOCAL_PREFIX: &str = "FE80:0000:0000:0000:";
pub const IPSIZE: usize = 46;
/// `ENOBUFS` of the MinGW `errno.h`
pub const ENOBUFS: i32 = 119;
/// `SOCK_STREAM` / `SOCK_DGRAM`
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
/// MinGW `errno.h` values (what the CRT `errno` is compared against)
pub const EAGAIN: i32 = 11;
pub const EPIPE: i32 = 32;
pub const ECONNREFUSED: i32 = 107;
pub const ENOTCONN: i32 = 126;
pub const EWOULDBLOCK: i32 = 140;

/// `recv(sock, buf, len, MSG_DONTWAIT)`: `MSG_DONTWAIT` is 0 on Windows.
pub fn recv_flags(sock: i32, buf: &mut [u8], _dontwait: bool) -> isize {
    recv(sock, buf)
}

/// Winsock `gethostname(buf, len)`: the name (up to the first NUL), `None`
/// on error.
pub fn gethostname(len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len + 1];
    // SAFETY: gethostname into a buffer of len + 1 bytes.
    if unsafe { ws::gethostname(buf.as_mut_ptr(), len as i32) } != 0 {
        return None;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    buf.truncate(n);
    Some(buf)
}

/// `close(fd)` on a socket: `closesocket`
pub fn close_fd(fd: i32) -> i32 {
    // SAFETY: closing a socket we own.
    unsafe { ws::closesocket(sk(fd)) }
}

/// The local address of a socket (`getsockname`).
pub enum SockName {
    V4(String),
    V6(String),
    /// another family
    Other(i32),
}

/// `getsockname` + `get_ipv4_string` / `get_ipv6_string` into `size` bytes;
/// `Err` when `getsockname` fails (see `WSAGetLastError`).
pub fn sock_name(sock: i32, size: usize) -> Result<SockName, ()> {
    // SAFETY: getsockname into a SOCKADDR_STORAGE.
    unsafe {
        let mut ss: ws::SOCKADDR_STORAGE = std::mem::zeroed();
        let mut len = std::mem::size_of::<ws::SOCKADDR_STORAGE>() as i32;
        if ws::getsockname(sk(sock), (&mut ss as *mut ws::SOCKADDR_STORAGE).cast(), &mut len) != 0 {
            return Err(());
        }
        Ok(match ss.ss_family {
            ws::AF_INET => {
                let a: ws::SOCKADDR_IN = std::ptr::read((&ss as *const ws::SOCKADDR_STORAGE).cast());
                SockName::V4(get_ipv4_string(a.sin_addr, size).unwrap_or_default())
            }
            ws::AF_INET6 => {
                let a: ws::SOCKADDR_IN6 = std::ptr::read((&ss as *const ws::SOCKADDR_STORAGE).cast());
                SockName::V6(get_ipv6_string(a.sin6_addr, size).unwrap_or_default())
            }
            f => SockName::Other(f as i32),
        })
    }
}

/// `ioctlsocket(sock, FIONBIO, &1)`: non-blocking mode.
pub fn set_nonblocking(sock: i32) -> i32 {
    let mut mode: u32 = 1;
    // SAFETY: plain Winsock call.
    unsafe { ws::ioctlsocket(sk(sock), ws::FIONBIO, &mut mode) }
}

pub type InAddr = ws::IN_ADDR;
pub type In6Addr = ws::IN6_ADDR;

mod crt {
    extern "C" {
        pub fn _errno() -> *mut i32;
        pub fn strerror(e: i32) -> *const std::ffi::c_char;
    }
}

static LOGGER: OnceLock<Arc<WLog>> = OnceLock::new();

/// Installs the daemon's logger for os_net / mq_op messages.
pub fn set_logger(log: Arc<WLog>) {
    let _ = LOGGER.set(log);
}

pub(crate) fn logger() -> Option<&'static Arc<WLog>> {
    LOGGER.get()
}

/// The CRT `errno`.
pub fn errno() -> i32 {
    // SAFETY: msvcrt's per-thread errno.
    unsafe { *crt::_errno() }
}

pub fn set_errno(e: i32) {
    // SAFETY: as above.
    unsafe { *crt::_errno() = e }
}

/// msvcrt `strerror`
pub fn strerror(e: i32) -> String {
    // SAFETY: msvcrt returns a static string.
    unsafe { std::ffi::CStr::from_ptr(crt::strerror(e)).to_string_lossy().into_owned() }
}

/// `WSAGetLastError()`
pub fn wsa_errno() -> i32 {
    // SAFETY: plain Winsock call.
    unsafe { ws::WSAGetLastError() }
}

pub fn wsa_set_errno(e: i32) {
    // SAFETY: plain Winsock call.
    unsafe { ws::WSASetLastError(e) }
}

/// `win_strerror` (`debug_op.c`): `FormatMessage` up to the first `\r`.
pub fn win_strerror(error: u32) -> String {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FormatMessageA, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    };
    // The C buffer is static: what a failed call leaves is the last message.
    static LAST: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
    let mut buf = vec![0u8; 4096];
    // SAFETY: FormatMessageA into a 4096-byte buffer.
    let n = unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            error,
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
            std::ptr::null(),
        )
    };
    let mut last = LAST.lock().unwrap();
    if n > 0 {
        buf.truncate(n as usize);
        *last = buf;
    }
    let s = &last[..];
    let end = s.iter().position(|&c| c == b'\r' || c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

/// `WSAStartup(MAKEWORD(2, 0))`
pub fn wsa_startup() -> i32 {
    // SAFETY: WSADATA is plain data.
    unsafe {
        let mut d: ws::WSADATA = std::mem::zeroed();
        ws::WSAStartup(0x0002, &mut d)
    }
}

/// `WSACleanup()`
pub fn wsa_cleanup() {
    // SAFETY: plain Winsock call.
    unsafe {
        ws::WSACleanup();
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s.split('\0').next().unwrap_or("")).unwrap()
}

fn sk(sock: i32) -> ws::SOCKET {
    sock as u32 as ws::SOCKET
}

fn new_socket(fam: u16, ty: i32, proto: i32) -> i32 {
    // SAFETY: plain Winsock call.
    let s = unsafe { ws::socket(fam as i32, ty, proto) };
    if s == ws::INVALID_SOCKET {
        -1
    } else {
        s as i32
    }
}

/// `get_ipv4_numeric` (`checkVista()` holds: `inet_pton`).
pub fn get_ipv4_numeric(address: &str, addr: &mut InAddr) -> i32 {
    let c = cstr(address);
    // SAFETY: inet_pton into an IN_ADDR.
    if unsafe { ws::inet_pton(ws::AF_INET as i32, c.as_ptr().cast(), (addr as *mut InAddr).cast()) } == 1 {
        OS_SUCCESS
    } else {
        OS_INVALID
    }
}

/// `get_ipv6_numeric`
pub fn get_ipv6_numeric(address: &str, addr: &mut In6Addr) -> i32 {
    let c = cstr(address);
    // SAFETY: inet_pton into an IN6_ADDR.
    if unsafe { ws::inet_pton(ws::AF_INET6 as i32, c.as_ptr().cast(), (addr as *mut In6Addr).cast()) } == 1 {
        OS_SUCCESS
    } else {
        OS_INVALID
    }
}

fn ntop(fam: u16, addr: *const std::ffi::c_void, size: usize) -> Option<String> {
    let mut buf = vec![0u8; size.max(1)];
    // SAFETY: inet_ntop into a buffer of `size` bytes.
    let r = unsafe { ws::inet_ntop(fam as i32, addr, buf.as_mut_ptr(), size) };
    if r.is_null() {
        return None;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// `get_ipv4_string`
pub fn get_ipv4_string(addr: InAddr, size: usize) -> Option<String> {
    ntop(ws::AF_INET, (&addr as *const InAddr).cast(), size)
}

/// `get_ipv6_string`: inet_ntop, then `OS_GetIPv4FromIPv6` or `OS_ExpandIPv6`.
pub fn get_ipv6_string(addr: In6Addr, size: usize) -> Option<String> {
    let s = ntop(ws::AF_INET6, (&addr as *const In6Addr).cast(), size)?;
    if let Some(v4) = siem_regex::os_ip::get_ipv4_from_ipv6(&s) {
        return Some(v4);
    }
    Some(siem_regex::os_ip::expand_ipv6(&s).unwrap_or(s))
}

/// `OS_CloseSocket`: `shutdown(SD_BOTH)` + `closesocket`.
pub fn close_socket(sock: i32) -> i32 {
    // SAFETY: plain Winsock calls.
    unsafe {
        ws::shutdown(sk(sock), ws::SD_BOTH);
        ws::closesocket(sk(sock))
    }
}

fn getsockopt_int(sock: i32, level: i32, opt: i32) -> Option<i32> {
    let mut v: i32 = 0;
    let mut len = 4i32;
    // SAFETY: getsockopt into an int.
    let r = unsafe { ws::getsockopt(sk(sock), level, opt, (&mut v as *mut i32).cast(), &mut len) };
    (r != -1).then_some(v)
}

fn setsockopt_raw(sock: i32, level: i32, opt: i32, val: &[u8]) -> i32 {
    // SAFETY: setsockopt with a byte buffer.
    unsafe { ws::setsockopt(sk(sock), level, opt, val.as_ptr(), val.len() as i32) }
}

/// `OS_SetSocketSize`
pub fn set_socket_size(sock: i32, mode: i32, max_msg_size: i32) -> i32 {
    let opt = if mode == RECV_SOCK {
        ws::SO_RCVBUF
    } else if mode == SEND_SOCK {
        ws::SO_SNDBUF
    } else {
        return 0;
    };
    let mut len = getsockopt_int(sock, ws::SOL_SOCKET, opt).unwrap_or(0);
    if len < max_msg_size {
        len = max_msg_size;
        if setsockopt_raw(sock, ws::SOL_SOCKET, opt, &len.to_ne_bytes()) < 0 {
            return -1;
        }
    }
    0
}

/// `OS_Connect`
fn os_connect(port: u16, protocol: i32, ip: &str, ipv6: bool, network_interface: u32) -> i32 {
    let max_msg_size = OS_MAXSTR + 512;
    let fam = if ipv6 { ws::AF_INET6 } else { ws::AF_INET };
    let sock = if protocol == IPPROTO_TCP {
        new_socket(fam, SOCK_STREAM, IPPROTO_TCP)
    } else if protocol == IPPROTO_UDP {
        new_socket(fam, SOCK_DGRAM, IPPROTO_UDP)
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
    // connect() failures keep their WSA error across OS_CloseSocket
    let fail_connect = |sock: i32| {
        let e = wsa_errno();
        close_socket(sock);
        wsa_set_errno(e);
        OS_SOCKTERR
    };
    // SAFETY: zeroed sockaddr structs, bind/connect with their sizes.
    unsafe {
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
            let sz = std::mem::size_of::<ws::SOCKADDR_IN6>() as i32;
            let mut local: ws::SOCKADDR_IN6 = std::mem::zeroed();
            local.sin6_family = ws::AF_INET6;
            if is_link_local && network_interface > 0 {
                local.Anonymous.sin6_scope_id = network_interface;
            }
            if ws::bind(sk(sock), (&local as *const ws::SOCKADDR_IN6).cast(), sz) < 0 {
                close_socket(sock);
                return OS_SOCKTERR;
            }
            let mut server: ws::SOCKADDR_IN6 = std::mem::zeroed();
            server.sin6_family = ws::AF_INET6;
            server.sin6_port = port.to_be();
            if is_link_local && network_interface > 0 {
                server.Anonymous.sin6_scope_id = network_interface;
            }
            get_ipv6_numeric(ip, &mut server.sin6_addr);
            if ws::connect(sk(sock), (&server as *const ws::SOCKADDR_IN6).cast(), sz) < 0 {
                return fail_connect(sock);
            }
        } else {
            let sz = std::mem::size_of::<ws::SOCKADDR_IN>() as i32;
            let mut local: ws::SOCKADDR_IN = std::mem::zeroed();
            local.sin_family = ws::AF_INET;
            if ws::bind(sk(sock), (&local as *const ws::SOCKADDR_IN).cast(), sz) < 0 {
                close_socket(sock);
                return OS_SOCKTERR;
            }
            let mut server: ws::SOCKADDR_IN = std::mem::zeroed();
            server.sin_family = ws::AF_INET;
            server.sin_port = port.to_be();
            get_ipv4_numeric(ip, &mut server.sin_addr);
            if ws::connect(sk(sock), (&server as *const ws::SOCKADDR_IN).cast(), sz) < 0 {
                return fail_connect(sock);
            }
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
    let fam = if ipv6 { ws::AF_INET6 } else { ws::AF_INET };
    let sock;
    if proto == IPPROTO_UDP {
        sock = new_socket(fam, SOCK_DGRAM, IPPROTO_UDP);
        if sock < 0 {
            return OS_SOCKTERR;
        }
    } else if proto == IPPROTO_TCP {
        sock = new_socket(fam, SOCK_STREAM, IPPROTO_TCP);
        if sock < 0 {
            return OS_SOCKTERR;
        }
        if setsockopt_raw(sock, ws::SOL_SOCKET, ws::SO_REUSEADDR, &1i32.to_ne_bytes()) < 0 {
            close_socket(sock);
            return OS_SOCKTERR;
        }
    } else {
        return OS_INVALID;
    }
    let ip = ip.filter(|s| !s.is_empty());
    // SAFETY: zeroed sockaddr structs, bind/listen with their sizes.
    let r = unsafe {
        if ipv6 {
            let mut a: ws::SOCKADDR_IN6 = std::mem::zeroed();
            a.sin6_family = ws::AF_INET6;
            a.sin6_port = port.to_be();
            if let Some(ip) = ip {
                get_ipv6_numeric(ip, &mut a.sin6_addr);
            }
            ws::bind(sk(sock), (&a as *const ws::SOCKADDR_IN6).cast(), std::mem::size_of::<ws::SOCKADDR_IN6>() as i32)
        } else {
            let mut a: ws::SOCKADDR_IN = std::mem::zeroed();
            a.sin_family = ws::AF_INET;
            a.sin_port = port.to_be();
            if let Some(ip) = ip {
                get_ipv4_numeric(ip, &mut a.sin_addr);
            }
            ws::bind(sk(sock), (&a as *const ws::SOCKADDR_IN).cast(), std::mem::size_of::<ws::SOCKADDR_IN>() as i32)
        }
    };
    if r < 0 || (proto == IPPROTO_TCP && unsafe { ws::listen(sk(sock), BACKLOG) } < 0) {
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

/// `OS_AcceptTCP`
pub fn accept_tcp(sock: i32, addrsize: usize) -> (i32, String) {
    // SAFETY: accept into a SOCKADDR_STORAGE.
    unsafe {
        let mut ss: ws::SOCKADDR_STORAGE = std::mem::zeroed();
        let mut len = std::mem::size_of::<ws::SOCKADDR_STORAGE>() as i32;
        let c = ws::accept(sk(sock), (&mut ss as *mut ws::SOCKADDR_STORAGE).cast(), &mut len);
        if c == ws::INVALID_SOCKET {
            return (-1, String::new());
        }
        let c = c as i32;
        match ss.ss_family {
            ws::AF_INET => {
                let a: ws::SOCKADDR_IN = std::ptr::read((&ss as *const ws::SOCKADDR_STORAGE).cast());
                (c, get_ipv4_string(a.sin_addr, addrsize - 1).unwrap_or_default())
            }
            ws::AF_INET6 => {
                let a: ws::SOCKADDR_IN6 = std::ptr::read((&ss as *const ws::SOCKADDR_STORAGE).cast());
                (c, get_ipv6_string(a.sin6_addr, addrsize - 1).unwrap_or_default())
            }
            _ => {
                ws::closesocket(sk(c));
                (-1, String::new())
            }
        }
    }
}

fn send(sock: i32, buf: &[u8], flags: i32) -> isize {
    // SAFETY: send from a valid slice.
    unsafe { ws::send(sk(sock), buf.as_ptr(), buf.len() as i32, flags) as isize }
}

fn recv(sock: i32, buf: &mut [u8]) -> isize {
    // SAFETY: recv into a valid slice.
    unsafe { ws::recv(sk(sock), buf.as_mut_ptr(), buf.len() as i32, 0) as isize }
}

/// `OS_SendTCP`
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

/// `OS_SendUDPbySize`: the ENOBUFS retry looks at the CRT `errno`, which
/// Winsock does not set.
pub fn send_udp_by_size(sock: i32, msg: &[u8]) -> i32 {
    let mut i = 0u32;
    while send(sock, msg, 0) < 0 {
        if errno() != ENOBUFS || i >= 5 {
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

/// `OS_RecvTCPBuffer`
pub fn recv_tcp_buffer(sock: i32, buf: &mut [u8], size: usize) -> isize {
    let n = size.saturating_sub(1).min(buf.len());
    recv(sock, &mut buf[..n])
}

/// `OS_RecvConnUDP`
pub fn recv_conn_udp(sock: i32, buf: &mut [u8], size: usize) -> i32 {
    let n = size.min(buf.len());
    let r = recv(sock, &mut buf[..n]);
    if r < 0 {
        0
    } else {
        r as i32
    }
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

/// `OS_RecvSecureTCP`
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

/// `OS_SetRecvTimeout`: a DWORD of milliseconds.
pub fn set_recv_timeout(sock: i32, seconds: i64, useconds: i64) -> i32 {
    let ms = (seconds * 1000 + useconds / 1000) as u32;
    setsockopt_raw(sock, ws::SOL_SOCKET, ws::SO_RCVTIMEO, &ms.to_ne_bytes())
}

/// `OS_SetSendTimeout`
pub fn set_send_timeout(sock: i32, seconds: i32) -> i32 {
    let ms = (seconds as u32).wrapping_mul(1000);
    setsockopt_raw(sock, ws::SOL_SOCKET, ws::SO_SNDTIMEO, &ms.to_ne_bytes())
}

/// `OS_SetKeepalive`
pub fn set_keepalive(sock: i32) -> i32 {
    setsockopt_raw(sock, ws::SOL_SOCKET, ws::SO_KEEPALIVE, &1i32.to_ne_bytes())
}

/// `OS_SetKeepalive_Options`: no keepalive tuning on Windows.
pub fn set_keepalive_options(_sock: i32, idle: i32, intvl: i32, cnt: i32) {
    if let Some(l) = logger() {
        if cnt > 0 {
            l.warn("Cannot set up keepalive count parameter: unsupported platform.");
        }
        if idle > 0 {
            l.warn("Cannot set up keepalive idle parameter: unsupported platform.");
        }
        if intvl > 0 {
            l.warn("Cannot set up keepalive interval parameter: unsupported platform.");
        }
    }
}

/// `wnet_select`
pub fn wnet_select(sock: i32, timeout: i64) -> i32 {
    // SAFETY: an FD_SET holding one socket.
    unsafe {
        let mut set: ws::FD_SET = std::mem::zeroed();
        set.fd_count = 1;
        set.fd_array[0] = sk(sock);
        let tv = ws::TIMEVAL { tv_sec: timeout as i32, tv_usec: 0 };
        ws::select(sock + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &tv)
    }
}

/// `select()` on one socket with a seconds/microseconds timeout (the
/// `fd_set` loops of `receiver_messages`).
pub fn select_read(sock: i32, sec: i32, usec: i32) -> i32 {
    // SAFETY: as in wnet_select.
    unsafe {
        let mut set: ws::FD_SET = std::mem::zeroed();
        set.fd_count = 1;
        set.fd_array[0] = sk(sock);
        let tv = ws::TIMEVAL { tv_sec: sec, tv_usec: usec };
        ws::select(sock + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &tv)
    }
}

/// `OS_GetHost`
pub fn get_host(host: &str, attempts: u32) -> Option<String> {
    let c = cstr(host);
    let mut i = 0;
    while i <= attempts {
        let mut res: *mut ws::ADDRINFOA = std::ptr::null_mut();
        // SAFETY: getaddrinfo/freeaddrinfo pair.
        if unsafe { ws::getaddrinfo(c.as_ptr().cast(), std::ptr::null(), std::ptr::null(), &mut res) } != 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            i += 1;
            continue;
        }
        let mut ip = None;
        let mut p = res;
        while !p.is_null() {
            // SAFETY: a node of the getaddrinfo list.
            let ai = unsafe { &*p };
            if ai.ai_family == ws::AF_INET as i32 {
                let a: ws::SOCKADDR_IN = unsafe { std::ptr::read(ai.ai_addr.cast()) };
                ip = Some(get_ipv4_string(a.sin_addr, IPSIZE).unwrap_or_default());
                break;
            } else if ai.ai_family == ws::AF_INET6 as i32 {
                let a: ws::SOCKADDR_IN6 = unsafe { std::ptr::read(ai.ai_addr.cast()) };
                ip = Some(get_ipv6_string(a.sin6_addr, IPSIZE).unwrap_or_default());
                break;
            }
            p = ai.ai_next;
        }
        unsafe { ws::freeaddrinfo(res) };
        return ip;
    }
    None
}

/// `resolve_hostname`
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

/// `external_socket_connect`: not available on Windows.
pub fn external_socket_connect(_path: &str, _response_timeout: i64) -> i32 {
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_roundtrip() {
        assert_eq!(wsa_startup(), 0);
        let srv = bindport_tcp(0, Some("127.0.0.1"), false);
        assert!(srv >= 0);
        // port the system picked
        let port = unsafe {
            let mut a: ws::SOCKADDR_IN = std::mem::zeroed();
            let mut l = std::mem::size_of::<ws::SOCKADDR_IN>() as i32;
            ws::getsockname(sk(srv), (&mut a as *mut ws::SOCKADDR_IN).cast(), &mut l);
            u16::from_be(a.sin_port)
        };
        let cli = connect_tcp(port, "127.0.0.1", false, 0);
        assert!(cli >= 0);
        let (c, ip) = accept_tcp(srv, IPSIZE + 1);
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(send_secure_tcp(cli, b"hello"), 0);
        let mut v = Vec::new();
        assert_eq!(recv_secure_tcp(c, &mut v, 100), 5);
        assert_eq!(v, b"hello");
        assert_eq!(wnet_select(c, 0), 0);
        close_socket(cli);
        close_socket(c);
        close_socket(srv);
        assert_eq!(connect_tcp(port, "127.0.0.1", false, 0), OS_SOCKTERR);
        assert!(!win_strerror(wsa_errno() as u32).is_empty());
        assert_eq!(strerror(2), "No such file or directory");
    }
}
