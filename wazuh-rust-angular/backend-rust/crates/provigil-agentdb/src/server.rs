//! The local server (spec § 1.1): clients connect to `queue/db/wdb`, a Unix socket on Linux
//! (root and the provigil group), a loopback TCP port named in `queue/db/wdb.port` on Windows
//! (provigil_ipc::local); each message is a 4-byte little-endian length and the request. One
//! thread per client. Requests starting with `{` are JSON commands.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use provigil_ipc::local::{self, Listener, Stream};

use crate::text::until_nul;
use crate::Engine;

/// The largest request and answer.
pub const MAX_MESSAGE: usize = 65536;
/// The socket path clients know (relative to the home folder).
pub const SOCKET: &str = "queue/db/wdb";

/// The connected clients, by number (answers in pieces go straight to them).
#[derive(Default)]
pub struct Peers {
    map: Mutex<HashMap<i32, Stream>>,
    next: AtomicI32,
}

impl Peers {
    fn add(&self, s: &Stream) -> Option<i32> {
        let c = s.try_clone().ok()?;
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        self.map.lock().insert(id, c);
        Some(id)
    }

    fn remove(&self, id: i32) {
        self.map.lock().remove(&id);
    }

    /// Sends one framed message: 0, or -1 when the client is gone or the write fails.
    pub fn send(&self, id: i32, msg: &[u8]) -> i32 {
        let s = self.map.lock().get(&id).and_then(|s| s.try_clone().ok());
        match s {
            Some(mut s) => send_framed(&mut s, msg),
            None => -1,
        }
    }

    pub fn set_send_timeout(&self, id: i32, secs: i32) -> i32 {
        let g = self.map.lock();
        let Some(s) = g.get(&id) else { return -1 };
        let t = (secs > 0).then(|| Duration::from_secs(secs as u64));
        if s.set_write_timeout(t).is_ok() {
            0
        } else {
            -1
        }
    }

    pub fn close(&self, id: i32) {
        if let Some(s) = self.map.lock().remove(&id) {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

fn send_framed(s: &mut Stream, msg: &[u8]) -> i32 {
    let mut buf = Vec::with_capacity(msg.len() + 4);
    buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    buf.extend_from_slice(msg);
    if s.write_all(&buf).is_ok() {
        0
    } else {
        -1
    }
}

enum Received {
    Message(Vec<u8>),
    Closed,
    TooBig,
    Failed(std::io::Error),
}

fn receive(s: &mut Stream) -> Received {
    let mut hdr = [0u8; 4];
    match s.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Received::Closed,
        Err(e) => return Received::Failed(e),
    }
    let n = u32::from_le_bytes(hdr) as usize;
    if n > MAX_MESSAGE {
        return Received::TooBig;
    }
    let mut buf = vec![0u8; n];
    match s.read_exact(&mut buf) {
        Ok(()) => Received::Message(buf),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Received::Closed,
        Err(e) => Received::Failed(e),
    }
}

/// Listens at the socket path (Unix: owner and group only, as the other manager sockets).
/// shortcut: on Windows any local user can reach the port and read global.db and the agent keys
/// through it; keep the manager on a host of its own, or move to a named pipe with an ACL.
pub fn bind(home: &Path) -> std::io::Result<Listener> {
    let path = home.join(SOCKET);
    let l = local::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
    }
    Ok(l)
}

/// Accepts clients until `running` is cleared; removes the port file at the end.
pub fn serve(engine: Arc<Engine>, peers: Arc<Peers>, listener: Listener, home: PathBuf, running: Arc<AtomicBool>) {
    let _ = listener.set_nonblocking(true);
    while running.load(Ordering::SeqCst) {
        let s = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(e) => {
                engine.error(cat!("at run_dealer(): accept(): ", crate::agent::os_text(&e)));
                continue;
            }
        };
        let _ = s.set_nonblocking(false);
        let Some(peer) = peers.add(&s) else { continue };
        engine.debug(cat!("New client connected (", peer, ")."));
        let (e, p, r) = (engine.clone(), peers.clone(), running.clone());
        let _ = std::thread::Builder::new().name("client".into()).spawn(move || client(e, p, s, peer, r));
    }
    local::unbind(&home.join(SOCKET));
}

fn client(engine: Arc<Engine>, peers: Arc<Peers>, mut s: Stream, peer: i32, running: Arc<AtomicBool>) {
    while running.load(Ordering::SeqCst) {
        let msg = match receive(&mut s) {
            Received::Message(m) => m,
            Received::Closed => {
                engine.debug(cat!("Client ", peer, " disconnected."));
                break;
            }
            Received::TooBig => {
                engine.warn(cat!("at run_worker(): received string size is bigger than ", MAX_MESSAGE, " bytes"));
                break;
            }
            Received::Failed(e) => {
                engine.debug(cat!("at run_worker(): at recv(): ", crate::agent::os_text(&e), " (", e.raw_os_error().unwrap_or(0), ")"));
                break;
            }
        };
        // an empty message reads as the client leaving (as it always did)
        if msg.is_empty() {
            engine.debug(cat!("Client ", peer, " disconnected."));
            break;
        }
        // a request ending in a newline gets an answer ending in one
        let newline = msg.last() == Some(&b'\n');
        let req = until_nul(if newline { &msg[..msg.len() - 1] } else { &msg[..] });
        let mut answer = if req.first() == Some(&b'{') { engine.json_command(req) } else { engine.handle(req, peer).1 };
        answer.truncate(until_nul(&answer).len());
        if answer.is_empty() {
            continue;
        }
        if newline && answer.len() < MAX_MESSAGE - 1 {
            answer.push(b'\n');
        }
        if send_framed(&mut s, &answer) < 0 {
            let e = std::io::Error::last_os_error();
            engine.error(cat!("at run_worker(): OS_SendSecureTCP(", peer, "): ", crate::agent::os_text(&e), " (", e.raw_os_error().unwrap_or(0), ")"));
        }
    }
    peers.remove(peer);
}
