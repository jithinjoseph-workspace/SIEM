//! The wazuh-db local server on hosts without `AF_UNIX` stream sockets and
//! epoll (Windows, macOS builds of the manager): `queue/db/wdb` maps to a
//! loopback TCP port written to `queue/db/wdb.port`, like every siem_ipc
//! local socket there. Each peer gets a thread running `run_worker`'s
//! request handling (`OS_RecvSecureTCP`, `wdb_parse` / `wdbcom_dispatch`,
//! `OS_SendSecureTCP`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use siem_log::WLog;

use super::state::Tv;
use super::threads::running;
use super::*;

/// The process services of the daemon; peers are numbered streams.
pub struct PortableEnv {
    pub log: Arc<WLog>,
    /// The `ossec.conf` `w_is_single_node` reads.
    pub ossecconf: std::path::PathBuf,
    peers: Mutex<HashMap<i32, TcpStream>>,
    next: AtomicI32,
}

impl PortableEnv {
    pub fn new(log: Arc<WLog>, ossecconf: std::path::PathBuf) -> Self {
        PortableEnv { log, ossecconf, peers: Mutex::new(HashMap::new()), next: AtomicI32::new(1) }
    }

    fn add_peer(&self, s: &TcpStream) -> Option<i32> {
        let c = s.try_clone().ok()?;
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.peers.lock().insert(id, c);
        Some(id)
    }

    fn remove_peer(&self, peer: i32) {
        self.peers.lock().remove(&peer);
    }
}

impl WdbEnv for PortableEnv {
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

    /// The router (Linux only, like the C) has no providers here.
    fn router_send(&self, _handle: i32, _msg: &[u8]) {}

    fn send_peer(&self, peer: i32, msg: &[u8]) -> i32 {
        let s = self.peers.lock().get(&peer).and_then(|s| s.try_clone().ok());
        match s {
            Some(mut s) => send_secure_tcp(&mut s, msg),
            None => OS_SOCKTERR,
        }
    }

    fn set_send_timeout(&self, peer: i32, secs: i32) -> i32 {
        let g = self.peers.lock();
        let Some(s) = g.get(&peer) else {
            return -1;
        };
        let t = (secs > 0).then(|| Duration::from_secs(secs as u64));
        if s.set_write_timeout(t).is_ok() {
            0
        } else {
            -1
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

    fn close_peer(&self, peer: i32) {
        if let Some(s) = self.peers.lock().remove(&peer) {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

/// `OS_SendSecureTCP`: 0 or OS_SOCKTERR.
fn send_secure_tcp(s: &mut TcpStream, msg: &[u8]) -> i32 {
    let mut buf = Vec::with_capacity(msg.len() + 4);
    buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    buf.extend_from_slice(msg);
    if s.write_all(&buf).is_ok() {
        0
    } else {
        OS_SOCKTERR
    }
}

/// `os_recv_waitall`: the bytes read, 0 on EOF before any byte, -1 on error.
fn recv_waitall(s: &mut TcpStream, buf: &mut [u8]) -> isize {
    let mut offset = 0;
    while offset < buf.len() {
        match s.read(&mut buf[offset..]) {
            Ok(0) => return 0,
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return -1,
        }
    }
    offset as isize
}

/// `OS_RecvSecureTCP`
fn recv_secure_tcp(s: &mut TcpStream, ret: &mut [u8], size: usize) -> isize {
    let mut hdr = [0u8; 4];
    let r = recv_waitall(s, &mut hdr);
    if r == -1 || r == 0 {
        return r;
    }
    let msgsize = u32::from_le_bytes(hdr) as usize;
    if msgsize > size {
        return OS_SOCKTERR as isize;
    }
    let recvb = recv_waitall(s, &mut ret[..msgsize]);
    if recvb == msgsize as isize && msgsize < size {
        ret[msgsize] = 0;
    }
    recvb
}

/// `<path>.port`
fn port_file(path: &str) -> String {
    format!("{path}.port")
}

/// `OS_BindUnixDomain(WDB_LOCAL_SOCK)` on the loopback mapping.
/// shortcut: any local user can reach this port (the Unix socket is 0660 to wazuh), so it
/// exposes global.db and the agent keys; run the manager on a single-user host, or move
/// this to a named pipe with an ACL before sharing the machine.
pub fn bind_local(path: &str) -> std::io::Result<TcpListener> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let l = TcpListener::bind("127.0.0.1:0")?;
    std::fs::write(port_file(path), l.local_addr()?.port().to_string())?;
    Ok(l)
}

/// `run_dealer` + `run_worker`: accept peers until the daemon stops.
pub fn run_dealer(d: Arc<Wdbd>, env: Arc<PortableEnv>) {
    let listener = match bind_local(WDB_LOCAL_SOCK) {
        Ok(l) => l,
        Err(e) => {
            let (_, t) = errno_text(&e);
            d.env.log("CRITICAL", &msg!("Unable to bind to socket '", WDB_LOCAL_SOCK, "': '", t, "'. Closing local server."));
            std::process::exit(1);
        }
    };
    let _ = listener.set_nonblocking(true);
    while running() {
        let s = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(e) => {
                let (_, t) = errno_text(&e);
                d.merror(&msg!("at run_dealer(): accept(): ", t));
                continue;
            }
        };
        let _ = s.set_nonblocking(false);
        let Some(peer) = env.add_peer(&s) else {
            continue;
        };
        d.mdebug1(&msg!("New client connected (", peer, ")."));
        let (dd, ee) = (d.clone(), env.clone());
        let _ = std::thread::Builder::new().name("run_worker".into()).spawn(move || run_peer(dd, ee, s, peer));
    }
    let _ = std::fs::remove_file(port_file(WDB_LOCAL_SOCK));
}

/// `run_worker`'s handling of one peer's requests.
fn run_peer(d: Arc<Wdbd>, env: Arc<PortableEnv>, mut s: TcpStream, peer: i32) {
    let mut buffer = vec![0u8; OS_MAXSTR + 1];
    while running() {
        let count = recv_secure_tcp(&mut s, &mut buffer, OS_MAXSTR);
        if count == OS_SOCKTERR as isize {
            d.mwarn(&msg!("at run_worker(): received string size is bigger than ", OS_MAXSTR, " bytes"));
            break;
        }
        match count {
            -1 => {
                let (n, t) = errno_text(&std::io::Error::last_os_error());
                d.mdebug1(&msg!("at run_worker(): at recv(): ", t, " (", n, ")"));
                break;
            }
            0 => {
                d.mdebug1(&msg!("Client ", peer, " disconnected."));
                break;
            }
            _ => {
                let length = count as usize;
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
                    if send_secure_tcp(&mut s, &response) < 0 {
                        let (n, t) = errno_text(&std::io::Error::last_os_error());
                        d.merror(&msg!("at run_worker(): OS_SendSecureTCP(", peer, "): ", t, " (", n, ")"));
                    }
                }
            }
        }
    }
    env.remove_peer(peer);
}
