//! The manager keystore as remoted uses it: port of `OS_ReadKeys`,
//! `OS_AddKey`, `OS_IsAllowed*`, `OS_CheckUpdateKeys` / `OS_UpdateKeys`
//! (`move_netdata`), `OS_AddSocket` / `OS_DeleteSocket` from
//! `src/os_crypto/shared/keys.c`.

use crate::keys::{ClientKey, CryptoMethod};
use siem_regex::{ip_found, is_valid_ip, OsIp};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// `KEYSIZE`
pub const KEYSIZE: usize = 128;
/// `USING_UDP_NO_CLIENT_SOCKET`
pub const UDP_SOCK: i64 = -1;

/// Network protocol an agent is currently using.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetProtocol {
    #[default]
    Unknown,
    Tcp,
    Udp,
}

/// Mutable, per-agent runtime state (fields of `keyentry` guarded by its mutex).
#[derive(Debug, Clone)]
pub struct KeyState {
    /// Last valid message timestamp (`rcvd`).
    pub rcvd: i64,
    /// TCP connection id, or -1.
    pub sock: i64,
    pub net_protocol: NetProtocol,
    pub peer: Option<SocketAddr>,
    pub post_startup: bool,
    /// Encryption material + received counters + detected cipher.
    pub key: ClientKey,
}

#[derive(Debug)]
pub struct KeyEntry {
    pub keyid: usize,
    pub id: String,
    pub name: String,
    /// `ip->ip` (CIDR suffix stripped).
    pub ip_str: String,
    pub ip: OsIp,
    pub raw_key: String,
    pub time_added: i64,
    pub state: Mutex<KeyState>,
}

impl KeyEntry {
    /// `isSingleHost(ip)`
    pub fn is_single_host(&self) -> bool {
        match &self.ip.net {
            siem_regex::IpNet::V4 { netmask, .. } => *netmask == 0xFFFF_FFFF,
            siem_regex::IpNet::V6 { .. } => false,
        }
    }

    /// `OS_DupKeyEntry` snapshot used by control-message processing.
    pub fn snapshot(&self) -> KeySnapshot {
        let st = self.state.lock().unwrap();
        KeySnapshot {
            id: self.id.clone(),
            name: self.name.clone(),
            ip: self.ip_str.clone(),
            peer: st.peer,
        }
    }
}

/// Copy of the identity fields of a key (`OS_DupKeyEntry`).
#[derive(Debug, Clone)]
pub struct KeySnapshot {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub peer: Option<SocketAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    #[error("(1103): Could not open file '{0}': {1}")]
    Open(String, String),
    #[error("(1237): Invalid ip address: '{0}'.")]
    InvalidIp(String),
    #[error("(1750): No client configured. Exiting.")]
    NoClientKeys,
}

/// File identity used by `OS_CheckUpdateKeys` (mtime + inode; inode is not
/// available on Windows, so the size stands in for it there).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileStamp {
    pub mtime: i64,
    pub inode: u64,
}

pub fn file_stamp(path: &str) -> Option<FileStamp> {
    let m = std::fs::metadata(path).ok()?;
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&m);
    #[cfg(not(unix))]
    let inode = m.len();
    Some(FileStamp { mtime, inode })
}

#[derive(Debug, Default)]
pub struct KeyStore {
    pub entries: Vec<Arc<KeyEntry>>,
    by_id: HashMap<String, usize>,
    by_ip: HashMap<String, usize>,
    by_sock: Mutex<HashMap<i64, usize>>,
    pub file: String,
    pub stamp: Option<FileStamp>,
    pub id_counter: i64,
    pub removed_keys: Vec<String>,
    pub save_removed: bool,
}

/// Copy at most KEYSIZE - 1 bytes (`strncpy(dst, src, KEYSIZE - 1)`).
fn trunc(s: &str) -> String {
    let mut end = s.len().min(KEYSIZE - 1);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

impl KeyStore {
    /// `OS_AddKey`
    pub fn add_key(&mut self, id: &str, name: &str, ip: &str, key: &str, time_added: i64) -> Result<usize, KeysError> {
        let (ok, parsed) = is_valid_ip(ip);
        let parsed = match (ok, parsed) {
            (0, _) | (_, None) => return Err(KeysError::InvalidIp(ip.to_string())),
            (_, Some(p)) => p,
        };
        let ip_str = parsed.ip.split('/').next().unwrap_or("").to_string();
        let keyid = self.entries.len();
        let client = ClientKey::new(id.to_string(), name.to_string(), ip.to_string(), key.to_string());
        let entry = Arc::new(KeyEntry {
            keyid,
            id: id.to_string(),
            name: name.to_string(),
            ip_str: ip_str.clone(),
            ip: parsed,
            raw_key: key.to_string(),
            time_added,
            state: Mutex::new(KeyState {
                rcvd: 0,
                sock: -1,
                net_protocol: NetProtocol::Unknown,
                peer: None,
                post_startup: false,
                key: ClientKey { crypto_method: CryptoMethod::Blowfish, ..client },
            }),
        });
        // rbtree_insert keeps the first entry on duplicate keys.
        self.by_id.entry(id.to_string()).or_insert(keyid);
        self.by_ip.entry(ip_str).or_insert(keyid);
        self.entries.push(entry);
        Ok(keyid)
    }

    /// Parse the text of a `client.keys` file (`OS_ReadKeys` loop).
    pub fn parse(&mut self, text: &str) -> Result<(), KeysError> {
        // fgets(buffer, OS_BUFFER_SIZE): lines are read one at a time.
        for raw in text.split_inclusive('\n') {
            if raw.starts_with('#') || raw.starts_with(' ') {
                continue;
            }
            let Some(sp) = raw.find(' ') else {
                tracing::error!("(1110): Invalid key: '{}'.", raw.trim_end_matches('\n'));
                continue;
            };
            let id = trunc(&raw[..sp]);
            let rest = &raw[sp + 1..];
            if let Ok(n) = id.parse::<i64>() {
                if n > self.id_counter {
                    self.id_counter = n;
                }
            }
            if rest.starts_with('#') || rest.starts_with('!') {
                if self.save_removed {
                    self.removed_keys.push(raw.trim_end_matches('\n').to_string());
                }
                continue;
            }
            let Some(sp) = rest.find(' ') else {
                tracing::error!("(1110): Invalid key: '{}'.", raw.trim_end_matches('\n'));
                continue;
            };
            let name = trunc(&rest[..sp]);
            let rest = &rest[sp + 1..];
            let Some(sp) = rest.find(' ') else {
                tracing::error!("(1110): Invalid key: '{}'.", raw.trim_end_matches('\n'));
                continue;
            };
            let ip = trunc(&rest[..sp]);
            let key = trunc(rest[sp + 1..].split('\n').next().unwrap_or(""));
            self.add_key(&id, &name, &ip, &key, 0)?;
        }
        Ok(())
    }

    /// `OS_ReadKeys(keys, W_ENCRYPTION_KEY, save_removed)`.
    pub fn read(file: &str, pass_empty_keyfile: bool, save_removed: bool) -> Result<Self, KeysError> {
        let mut ks = KeyStore { file: file.to_string(), save_removed, ..Default::default() };
        ks.stamp = file_stamp(file);
        match std::fs::read(file) {
            Ok(data) => ks.parse(&String::from_utf8_lossy(&data))?,
            Err(e) => {
                if !pass_empty_keyfile {
                    return Err(KeysError::Open(file.to_string(), e.to_string()));
                }
                tracing::debug!("(1751): File client.keys not found or empty.");
            }
        }
        if ks.entries.is_empty() && !pass_empty_keyfile {
            return Err(KeysError::NoClientKeys);
        }
        Ok(ks)
    }

    /// `OS_CheckUpdateKeys`
    pub fn needs_reload(&self) -> bool {
        file_stamp(&self.file) != self.stamp
    }

    /// `OS_UpdateKeys`: re-read the file and carry over network data
    /// (`move_netdata`) for agents whose id and IP did not change.
    pub fn reload(&self, pass_empty_keyfile: bool) -> Result<Self, KeysError> {
        let new = Self::read(&self.file, pass_empty_keyfile, self.save_removed)?;
        for old in &self.entries {
            if let Some(&idx) = new.by_id.get(&old.id) {
                let ne = &new.entries[idx];
                if ne.ip_str == old.ip_str {
                    let os = old.state.lock().unwrap();
                    let mut ns = ne.state.lock().unwrap();
                    ns.rcvd = os.rcvd;
                    ns.sock = os.sock;
                    ns.peer = os.peer;
                    if os.sock >= 0 {
                        new.by_sock.lock().unwrap().insert(os.sock, idx);
                    }
                }
            }
        }
        Ok(new)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `OS_IsAllowedIP`: exact match of the configured address string.
    pub fn allowed_ip(&self, srcip: &str) -> Option<Arc<KeyEntry>> {
        self.by_ip.get(srcip).map(|&i| self.entries[i].clone())
    }

    /// `OS_IsAllowedID`
    pub fn allowed_id(&self, id: &str) -> Option<Arc<KeyEntry>> {
        self.by_id.get(id).map(|&i| self.entries[i].clone())
    }

    /// `OS_IsAllowedName`
    pub fn allowed_name(&self, name: &str) -> Option<Arc<KeyEntry>> {
        self.entries.iter().find(|e| e.name == name).cloned()
    }

    /// `OS_IsAllowedDynamicID`: the id exists and `srcip` is inside its network.
    pub fn allowed_dynamic_id(&self, id: &str, srcip: &str) -> Option<Arc<KeyEntry>> {
        let e = self.allowed_id(id)?;
        if ip_found(srcip, &e.ip) {
            Some(e)
        } else {
            None
        }
    }

    /// `OS_AddSocket`: returns true when a new mapping was added, false when
    /// an existing one was updated.
    pub fn add_socket(&self, keyid: usize, sock: i64) -> bool {
        self.by_sock.lock().unwrap().insert(sock, keyid).is_none()
    }

    /// `OS_DeleteSocket`
    pub fn delete_socket(&self, sock: i64) -> bool {
        let mut m = self.by_sock.lock().unwrap();
        match m.remove(&sock) {
            Some(idx) => {
                let mut st = self.entries[idx].state.lock().unwrap();
                if st.sock == sock {
                    st.sock = -1;
                }
                true
            }
            None => false,
        }
    }

    /// `w_get_agent_net_protocol_from_keystore`
    pub fn net_protocol(&self, id: &str) -> Option<NetProtocol> {
        self.allowed_id(id).map(|e| e.state.lock().unwrap().net_protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &str = "001 web01 any 5c6f0e1ef1c3b1b5c3a1d0e8c4f6a3b2e9d7c1f0a5b4c3d2e1f0a9b8c7d6e5f4\n\
                        002 db01 10.0.0.5 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
                        003 !removed any deadbeef\n\
                        # comment\n\
                        004 net 192.168.0.0/24 cafebabe\n";

    #[test]
    fn parse_and_lookup() {
        let mut ks = KeyStore { save_removed: true, ..Default::default() };
        ks.parse(KEYS).unwrap();
        assert_eq!(ks.len(), 3);
        assert_eq!(ks.id_counter, 4);
        assert_eq!(ks.removed_keys, vec!["003 !removed any deadbeef"]);
        assert_eq!(ks.allowed_ip("10.0.0.5").unwrap().id, "002");
        assert_eq!(ks.allowed_ip("any").unwrap().id, "001");
        assert_eq!(ks.allowed_ip("192.168.0.0").unwrap().id, "004");
        assert!(ks.allowed_dynamic_id("001", "8.8.8.8").is_some());
        assert!(ks.allowed_dynamic_id("004", "192.168.0.77").is_some());
        assert!(ks.allowed_dynamic_id("004", "192.168.1.77").is_none());
        assert!(ks.allowed_id("001").unwrap().ip.net != ks.allowed_id("002").unwrap().ip.net);
        assert!(!ks.allowed_id("001").unwrap().is_single_host());
        assert!(ks.allowed_id("002").unwrap().is_single_host());
        assert!(ks.add_socket(0, 7));
        ks.entries[0].state.lock().unwrap().sock = 7;
        assert!(ks.delete_socket(7));
        assert_eq!(ks.entries[0].state.lock().unwrap().sock, -1);
    }

    #[test]
    fn invalid_ip_is_fatal() {
        let mut ks = KeyStore::default();
        assert!(matches!(ks.parse("001 a 999.1.1.1 k\n"), Err(KeysError::InvalidIp(_))));
    }
}
