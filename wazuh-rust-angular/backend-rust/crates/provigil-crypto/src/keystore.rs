//! The manager daemons' key table: client.keys (or the platform key service), lookups and sockets.

use crate::keys::ClientKey;
use siem_regex::{IpNet, OsIp};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use std::{fs, thread};

pub const UDP_SOCK: i64 = -1;
pub const KEYS_REQ: u8 = b'K';
pub const VERSION_REQ: u8 = b'V';
pub const KEYSIZE: usize = 128;
/// Longest id / name / ip / key field kept from a client.keys line.
const FIELD_MAX: usize = KEYSIZE - 1;
const KEY_SERVICE: &str = "the platform's key service";

#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    #[error("(1103): Could not open file '{0}': {1}")]
    Open(String, String),
    #[error("(1237): Invalid ip address: '{0}'.")]
    InvalidIp(String),
    #[error("(1750): No client configured. Exiting.")]
    NoClientKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetProtocol {
    #[default]
    Unknown,
    Tcp,
    Udp,
}

/// mtime + inode (Unix) or file length (Windows); the key service uses its version + `u64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileStamp {
    pub mtime: i64,
    pub inode: u64,
}

#[derive(Debug, Clone)]
pub struct KeyState {
    pub rcvd: i64,
    pub sock: i64,
    pub net_protocol: NetProtocol,
    pub peer: Option<SocketAddr>,
    pub post_startup: bool,
    pub key: ClientKey,
}

#[derive(Debug)]
pub struct KeyEntry {
    pub keyid: usize,
    pub id: String,
    pub name: String,
    pub ip_str: String,
    pub ip: OsIp,
    pub raw_key: String,
    pub time_added: i64,
    pub state: Mutex<KeyState>,
}

#[derive(Debug, Clone)]
pub struct KeySnapshot {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub peer: Option<SocketAddr>,
}

impl KeyEntry {
    /// IPv4 entry with an all-ones mask.
    pub fn is_single_host(&self) -> bool {
        matches!(self.ip.net, IpNet::V4 { netmask: u32::MAX, .. })
    }

    pub fn snapshot(&self) -> KeySnapshot {
        KeySnapshot { id: self.id.clone(), name: self.name.clone(), ip: self.ip_str.clone(), peer: lock(&self.state).peer }
    }
}

#[derive(Debug, Default)]
pub struct KeyStore {
    pub entries: Vec<Arc<KeyEntry>>,
    pub file: String,
    pub stamp: Option<FileStamp>,
    pub id_counter: i64,
    pub removed_keys: Vec<String>,
    pub save_removed: bool,
    by_id: HashMap<String, usize>,
    by_ip: HashMap<String, usize>,
    sockets: Mutex<HashMap<i64, usize>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Cuts to at most 127 bytes on a character boundary.
fn cut(s: &str) -> &str {
    let mut n = s.len().min(FIELD_MAX);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

impl KeyStore {
    pub fn add_key(&mut self, id: &str, name: &str, ip: &str, key: &str, time_added: i64) -> Result<usize, KeysError> {
        let parsed = match siem_regex::is_valid_ip(ip) {
            (code, Some(p)) if code != 0 => p,
            _ => return Err(KeysError::InvalidIp(ip.into())),
        };
        let ip_str = parsed.ip.split('/').next().unwrap_or_default().to_string();
        let keyid = self.entries.len();
        self.by_id.entry(id.into()).or_insert(keyid);
        self.by_ip.entry(ip_str.clone()).or_insert(keyid);
        let state = KeyState {
            rcvd: 0,
            sock: UDP_SOCK,
            net_protocol: NetProtocol::Unknown,
            peer: None,
            post_startup: false,
            key: ClientKey::new(id.into(), name.into(), ip.into(), key.into()),
        };
        self.entries.push(Arc::new(KeyEntry {
            keyid,
            id: id.into(),
            name: name.into(),
            ip_str,
            ip: parsed,
            raw_key: key.into(),
            time_added,
            state: Mutex::new(state),
        }));
        Ok(keyid)
    }

    /// Parses client.keys text into this table (see the spec for the line rules).
    pub fn parse(&mut self, text: &str) -> Result<(), KeysError> {
        for line in text.split_inclusive('\n') {
            if line.starts_with('#') || line.starts_with(' ') {
                continue;
            }
            let Some((id, rest)) = line.split_once(' ') else {
                tracing::error!("(1401): Error reading authentication key: '{line}'.");
                continue;
            };
            let raw_id = id;
            let id = cut(id);
            if let Ok(n) = id.parse::<i64>() {
                self.id_counter = self.id_counter.max(n);
            }
            if rest.starts_with('#') || rest.starts_with('!') {
                if self.save_removed {
                    self.removed_keys.push(line.trim_end_matches('\n').to_string());
                }
                continue;
            }
            let rest = rest.strip_suffix('\n').unwrap_or(rest);
            let Some((name, ip, key)) = rest.split_once(' ').and_then(|(n, r)| r.split_once(' ').map(|(i, k)| (n, i, k))) else {
                tracing::error!("(1401): Error reading authentication key: '{raw_id}'.");
                continue;
            };
            self.add_key(id, cut(name), cut(ip), cut(key), 0)?;
        }
        Ok(())
    }

    /// Loads the table from the platform key service when configured, else from `file`.
    pub fn read(file: &str, pass_empty_keyfile: bool, save_removed: bool) -> Result<KeyStore, KeysError> {
        let mut ks = KeyStore { file: file.into(), save_removed, ..Default::default() };
        if platform_source().is_some() {
            let mut last = String::new();
            for _ in 0..30 {
                match platform_fetch(KEYS_REQ) {
                    Ok((version, text)) => {
                        ks.stamp = Some(platform_stamp(version));
                        ks.parse(&text)?;
                        return ks.non_empty(pass_empty_keyfile);
                    }
                    Err(e) => last = e,
                }
                thread::sleep(Duration::from_secs(1));
            }
            return Err(KeysError::Open(KEY_SERVICE.into(), last));
        }
        ks.stamp = file_stamp(file);
        match fs::read(file) {
            Ok(bytes) => ks.parse(&String::from_utf8_lossy(&bytes))?,
            Err(e) if !pass_empty_keyfile => return Err(KeysError::Open(file.into(), e.to_string())),
            Err(_) => tracing::debug!("(1751): File client.keys not found or empty."),
        }
        ks.non_empty(pass_empty_keyfile)
    }

    fn non_empty(self, pass_empty_keyfile: bool) -> Result<KeyStore, KeysError> {
        if self.entries.is_empty() && !pass_empty_keyfile {
            return Err(KeysError::NoClientKeys);
        }
        Ok(self)
    }

    pub fn needs_reload(&self) -> bool {
        if platform_source().is_some() {
            return matches!(platform_fetch(VERSION_REQ), Ok((v, _)) if Some(platform_stamp(v)) != self.stamp);
        }
        file_stamp(&self.file) != self.stamp
    }

    /// Reads the table again, keeping rcvd / sock / peer of entries whose id and ip did not change.
    pub fn reload(&self, pass_empty_keyfile: bool) -> Result<KeyStore, KeysError> {
        let new = KeyStore::read(&self.file, pass_empty_keyfile, self.save_removed)?;
        for old in &self.entries {
            let Some(&i) = new.by_id.get(&old.id) else { continue };
            if new.entries[i].ip_str != old.ip_str {
                continue;
            }
            let o = lock(&old.state).clone();
            {
                let mut s = lock(&new.entries[i].state);
                s.rcvd = o.rcvd;
                s.sock = o.sock;
                s.peer = o.peer;
            }
            if o.sock >= 0 {
                new.add_socket(i, o.sock);
            }
        }
        Ok(new)
    }

    pub fn allowed_ip(&self, srcip: &str) -> Option<Arc<KeyEntry>> {
        self.by_ip.get(srcip).map(|&i| self.entries[i].clone())
    }

    pub fn allowed_id(&self, id: &str) -> Option<Arc<KeyEntry>> {
        self.by_id.get(id).map(|&i| self.entries[i].clone())
    }

    /// First entry with that name, in table order.
    pub fn allowed_name(&self, name: &str) -> Option<Arc<KeyEntry>> {
        self.entries.iter().find(|e| e.name == name).cloned()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn allowed_dynamic_id(&self, id: &str, srcip: &str) -> Option<Arc<KeyEntry>> {
        self.allowed_id(id).filter(|e| siem_regex::ip_found(srcip, &e.ip))
    }

    /// Maps a socket to an entry; false when it replaced an existing mapping.
    pub fn add_socket(&self, keyid: usize, sock: i64) -> bool {
        lock(&self.sockets).insert(sock, keyid).is_none()
    }

    /// Drops a socket mapping; the entry's sock goes back to -1 only if it still is this socket.
    pub fn delete_socket(&self, sock: i64) -> bool {
        let Some(keyid) = lock(&self.sockets).remove(&sock) else { return false };
        if let Some(e) = self.entries.get(keyid) {
            let mut s = lock(&e.state);
            if s.sock == sock {
                s.sock = UDP_SOCK;
            }
        }
        true
    }

    pub fn net_protocol(&self, id: &str) -> Option<NetProtocol> {
        self.allowed_id(id).map(|e| lock(&e.state).net_protocol)
    }
}

pub fn file_stamp(path: &str) -> Option<FileStamp> {
    let m = fs::metadata(path).ok()?;
    let mtime = m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64);
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&m);
    #[cfg(not(unix))]
    let inode = m.len();
    Some(FileStamp { mtime, inode })
}

pub fn platform_stamp(version: u64) -> FileStamp {
    FileStamp { mtime: version as i64, inode: u64::MAX }
}

/// `(SIEM_KEYS_ADDR, SIEM_KEYS_TOKEN)` when both are set and non-empty.
pub fn platform_source() -> Option<(String, String)> {
    let get = |k| std::env::var(k).ok().filter(|v: &String| !v.is_empty());
    Some((get("SIEM_KEYS_ADDR")?, get("SIEM_KEYS_TOKEN")?))
}

/// Asks the key service for `kind` (KEYS_REQ / VERSION_REQ); returns (version, client.keys text).
pub fn platform_fetch(kind: u8) -> Result<(u64, String), String> {
    let (addr, token) = platform_source().ok_or("no key service")?;
    let mut s = TcpStream::connect(&addr).map_err(|e| format!("{addr}: {e}"))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let mut req = ((1 + token.len()) as u32).to_le_bytes().to_vec();
    req.push(kind);
    req.extend_from_slice(token.as_bytes());
    s.write_all(&req).map_err(|e| e.to_string())?;
    let mut n = [0u8; 4];
    s.read_exact(&mut n).map_err(|e| e.to_string())?;
    let n = u32::from_le_bytes(n);
    if n == 0 || n > 64 << 20 {
        return Err(format!("answer of {n} bytes"));
    }
    let mut body = vec![0u8; n as usize];
    s.read_exact(&mut body).map_err(|e| e.to_string())?;
    if body[0] != kind {
        return Err("refused".into());
    }
    let text = String::from_utf8_lossy(&body[1..]);
    let (version, keys) = text.split_once('\n').unwrap_or((&text, ""));
    let version = version.trim().parse::<u64>().map_err(|_| "bad version")?;
    Ok((version, keys.to_string()))
}
