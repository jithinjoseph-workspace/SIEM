//! The agent side of `os_crypto/shared/keys.c` and `msgs.c`:
//! `OS_ReadKeys` (one key: the agent's own), `OS_CheckKeys`,
//! `OS_StartCounter`, `ReloadCounter`, `StoreCounter`,
//! `StoreSenderCounter`, `OS_UpdateKeys`, and the agent's use of
//! `CreateSecMSG` / `ReadSecMSG` with their counter bookkeeping.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use siem_crypto::keys::{ClientKey, CryptoMethod};
use siem_crypto::keystore::KeyStore;
use siem_crypto::msgs::{self, CreateOptions, KeyState, MsgError, ReadOptions, SenderCounter};
use siem_config::client::W_METH_BLOWFISH;

use crate::*;

/// `OS_BUFFER_SIZE`
const OS_BUFFER_SIZE: usize = 2048;
/// `KEYSIZE`
const KEYSIZE: usize = 128;

/// `keyentries[0]`: the agent's own key.
#[derive(Debug, Clone)]
pub struct AgentKey {
    pub id: String,
    pub name: String,
    /// `ip->ip` (CIDR suffix removed).
    pub ip: String,
    /// `isSingleHost(ip)`
    pub single_host: bool,
    /// Encryption key, method and received counters.
    pub key: ClientKey,
}

/// What C keeps in `keys`, the sender entry and the msgs.c statics.
#[derive(Default)]
pub struct AgentKeys {
    pub entry: Option<AgentKey>,
    /// `pass_empty_keyfile`
    pub pass_empty_keyfile: bool,
    /// `global_count` / `local_count`
    pub sender: SenderCounter,
    pub(crate) sender_fp: Option<File>,
    pub(crate) sender_inode: u64,
    pub(crate) recv_fp: Option<File>,
    pub(crate) recv_inode: u64,
    pub(crate) rids_node: bool,
    pub(crate) rcv_count: u32,
    pub(crate) evt_count: u32,
    pub(crate) c_orig_size: u64,
    pub(crate) c_comp_size: u64,
    pub(crate) saved_time: i64,
    /// `_s_recv_flush`, `_s_comp_print`, `_s_verify_counter`
    pub recv_flush: u32,
    pub comp_print: u32,
    pub verify_counter: bool,
}

impl AgentKeys {
    /// `keys.keysize`
    pub fn keysize(&self) -> usize {
        usize::from(self.entry.is_some())
    }
}

/// `File_Inode`: 0 when the file cannot be stat'ed.
fn file_inode(path: &str) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map(|m| m.ino()).unwrap_or(0)
}

/// `File_DateofChange` >= 0
pub fn file_exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

/// `fopen(path, "r+")`
fn open_rw(path: &str) -> Option<File> {
    OpenOptions::new().read(true).write(true).open(path).ok()
}

/// `fopen(path, "w")`
fn open_w(path: &str) -> std::io::Result<File> {
    OpenOptions::new().write(true).create(true).truncate(true).open(path)
}

/// `fscanf(fp, "%u:%u", &g, &l) == 2`
fn scan_counter(f: &mut File) -> Option<(u32, u32)> {
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    msgs::parse_counter(&s)
}

/// `fseek(fp, 0, SEEK_SET); fprintf(fp, "%u:%u:", g, l); fflush(fp)`
fn write_counter(f: &mut File, g: u32, l: u32) {
    let _ = f.seek(SeekFrom::Start(0));
    let _ = write!(f, "{g}:{l}:");
    let _ = f.flush();
}

/// `fgets(buffer, size, fp)` chunking (each chunk keeps its '\n').
fn fgets_lines(data: &[u8], size: usize) -> Vec<&[u8]> {
    let max = size - 1;
    let mut out = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let mut end = start;
        while end < data.len() && end - start < max {
            end += 1;
            if data[end - 1] == b'\n' {
                break;
            }
        }
        out.push(&data[start..end]);
        start = end;
    }
    out
}

/// `strncpy(dst, src, KEYSIZE - 1)` into a zeroed `KEYSIZE + 1` buffer.
fn keysize_copy(s: &[u8]) -> String {
    let s = &s[..s.len().min(KEYSIZE - 1)];
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    String::from_utf8_lossy(s).into_owned()
}

fn invalid_key(s: &[u8]) -> String {
    format!("(1401): Error reading authentication key: '{}'.", String::from_utf8_lossy(s))
}

/// `OS_CheckKeys`
pub fn check_keys(ag: &Agentd) -> bool {
    if !file_exists(KEYS_FILE) {
        ag.log.error(no_authfile(KEYS_FILE));
        ag.log.error(NO_CLIENT_KEYS);
        return false;
    }
    if let Err(e) = File::open(KEYS_FILE) {
        ag.log.error(fopen_error(KEYS_FILE, e.raw_os_error().unwrap_or(0)));
        ag.log.error(no_authfile(KEYS_FILE));
        ag.log.error(NO_CLIENT_KEYS);
        return false;
    }
    true
}

/// `OS_ReadKeys(&keys, W_DUAL_KEY, 0)`: the agent keeps the first entry.
pub fn read_keys(ag: &Agentd) {
    let pass_empty = ag.keys.lock().unwrap().pass_empty_keyfile;
    if !file_exists(KEYS_FILE) {
        if pass_empty {
            ag.log.debug1(no_authfile(KEYS_FILE));
        } else {
            ag.log.error(no_authfile(KEYS_FILE));
            ag.exit_critical(NO_CLIENT_KEYS);
        }
    }
    let data = match std::fs::read(KEYS_FILE) {
        Ok(d) => Some(d),
        Err(e) => {
            if !pass_empty {
                ag.log.error(fopen_error(KEYS_FILE, e.raw_os_error().unwrap_or(0)));
                ag.exit_critical(NO_CLIENT_KEYS);
            }
            None
        }
    };

    let mut store = KeyStore::default();
    let mut first: Option<AgentKey> = None;
    for line in data.as_deref().map(|d| fgets_lines(d, OS_BUFFER_SIZE)).unwrap_or_default() {
        // fgets stops at a NUL byte for string purposes
        let line = &line[..line.iter().position(|&c| c == 0).unwrap_or(line.len())];
        if line.first() == Some(&b'#') || line.first() == Some(&b' ') {
            continue;
        }
        let Some(sp) = line.iter().position(|&c| c == b' ') else {
            ag.log.error(invalid_key(line));
            continue;
        };
        let id_raw = &line[..sp];
        // snprintf(id, KEYSIZE + 1, "%s", ...)
        let id = keysize_trunc(id_raw);
        if id_raw.len() >= KEYSIZE + 1 {
            ag.log.error(invalid_key(id.as_bytes()));
        }
        let rest = &line[sp + 1..];
        if rest.first() == Some(&b'#') || rest.first() == Some(&b'!') {
            continue;
        }
        let Some(sp) = rest.iter().position(|&c| c == b' ') else {
            ag.log.error(invalid_key(id_raw));
            continue;
        };
        let name = keysize_copy(&rest[..sp]);
        let rest = &rest[sp + 1..];
        let Some(sp) = rest.iter().position(|&c| c == b' ') else {
            ag.log.error(invalid_key(id_raw));
            continue;
        };
        let ip = keysize_copy(&rest[..sp]);
        let rest = &rest[sp + 1..];
        let key = keysize_copy(&rest[..rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len())]);

        // OS_AddKey
        let keyid = match store.add_key(&id, &name, &ip, &key, 0) {
            Ok(k) => k,
            Err(_) => ag.exit_critical(format!("(1237): Invalid ip address: '{ip}'.")),
        };
        if first.is_none() {
            let e = &store.entries[keyid];
            first = Some(AgentKey {
                id: id.clone(),
                name: name.clone(),
                ip: e.ip_str.clone(),
                single_host: e.is_single_host(),
                key: ClientKey::new(id.clone(), name.clone(), ip.clone(), key.clone()),
            });
        }
    }

    if first.is_none() {
        if pass_empty {
            ag.log.debug1(NO_CLIENT_KEYS);
        } else {
            ag.exit_critical(NO_CLIENT_KEYS);
        }
    }
    let mut k = ag.keys.lock().unwrap();
    k.entry = first;
    k.sender_fp = None;
    k.sender_inode = 0;
    k.recv_fp = None;
    k.recv_inode = 0;
    k.rids_node = false;
}

/// `snprintf(id, KEYSIZE + 1, "%s", s)`
fn keysize_trunc(s: &[u8]) -> String {
    String::from_utf8_lossy(&s[..s.len().min(KEYSIZE)]).into_owned()
}

/// `OS_StartCounter`
pub fn start_counter(ag: &Agentd) {
    let mut k = ag.keys.lock().unwrap();
    let keysize = k.keysize();
    ag.log.debug1(format!("OS_StartCounter: keysize: {keysize}"));
    for i in 0..=keysize {
        let sender = i == keysize;
        let rids_file = if sender {
            format!("{RIDS_DIR}/{SENDER_COUNTER}")
        } else {
            format!("{RIDS_DIR}/{}", k.entry.as_ref().unwrap().id)
        };
        let fp = match open_rw(&rids_file) {
            Some(mut f) => {
                let (g, l) = match scan_counter(&mut f) {
                    Some(c) => c,
                    None => {
                        if sender {
                            ag.log.debug1("No previous sender counter.");
                        } else {
                            ag.log.debug1(format!(
                                "No previous counter available for '{}'.",
                                k.entry.as_ref().unwrap().name
                            ));
                        }
                        (0, 0)
                    }
                };
                if sender {
                    ag.log.debug1(format!("Assigning sender counter: {g}:{l}"));
                    k.sender = SenderCounter { global: g, local: l };
                } else {
                    let e = k.entry.as_mut().unwrap();
                    ag.log.debug1(format!("Assigning counter for agent {}: '{g}:{l}'.", e.name));
                    e.key.global_counter = g;
                    e.key.local_counter = l;
                }
                f
            }
            None => match open_w(&rids_file) {
                Ok(f) => f,
                Err(e) => {
                    let n = e.raw_os_error().unwrap_or(0);
                    ag.log.error(format!("Unable to open agent file. errno: {n}"));
                    ag.exit_critical(fopen_error(&rids_file, n));
                }
            },
        };
        let inode = file_inode(&rids_file);
        if sender {
            k.sender_fp = Some(fp);
            k.sender_inode = inode;
        } else {
            drop(fp);
            k.recv_fp = None;
            k.recv_inode = inode;
        }
    }
    ag.log.debug2("Stored counter.");

    if k.recv_flush == 0 {
        k.recv_flush = ag.define_int("remoted", "recv_counter_flush", 10, 999999) as u32;
    }
    if k.comp_print == 0 {
        k.comp_print = ag.define_int("remoted", "comp_average_printout", 10, 999999) as u32;
    }
    k.verify_counter = ag.define_int("remoted", "verify_msg_id", 0, 1) != 0;
}

/// `os_set_agent_crypto_method(&keys, method)`
pub fn set_crypto_method(ag: &Agentd, method: i32) {
    if let Some(e) = ag.keys.lock().unwrap().entry.as_mut() {
        e.key.crypto_method = if method == W_METH_BLOWFISH { CryptoMethod::Blowfish } else { CryptoMethod::Aes };
    }
}

/// `OS_UpdateKeys`
pub fn update_keys(ag: &Agentd) {
    ag.log.debug1("Reloading keys");
    ag.log.debug2("OS_DupKeys");
    ag.log.debug2("Freekeys");
    ag.log.debug2("OS_ReadKeys");
    ag.log.info(ENC_READ);
    read_keys(ag);
    ag.log.debug2("OS_StartCounter");
    start_counter(ag);
    ag.log.debug2("move_netdata");
    ag.log.debug1("Key reloading completed");
}

/// `ReloadCounter(keys, keys->keysize, SENDER_COUNTER)`
fn reload_sender_counter(ag: &Agentd, k: &mut AgentKeys) {
    let rids_file = format!("{RIDS_DIR}/{SENDER_COUNTER}");
    let new_inode = file_inode(&rids_file);
    if k.sender_inode == new_inode {
        return;
    }
    match open_rw(&rids_file) {
        Some(mut f) => {
            match scan_counter(&mut f) {
                Some((g, l)) => {
                    ag.log.debug1(format!("Reloading sender counter: {g}:{l}"));
                    k.sender = SenderCounter { global: g, local: l };
                }
                None => {
                    ag.log.debug1("No previous sender counter.");
                    ag.log.debug1("Reloading sender counter: 0:0");
                    k.sender = SenderCounter::default();
                }
            }
            k.sender_fp = Some(f);
        }
        None => match open_w(&rids_file) {
            Ok(f) => k.sender_fp = Some(f),
            Err(e) => {
                let n = e.raw_os_error().unwrap_or(0);
                ag.log.error(format!("Unable to open agent file. errno: {n}"));
                ag.exit_critical(fopen_error(&rids_file, n));
            }
        },
    }
    k.sender_inode = new_inode;
}

/// `ReloadCounter(keys, 0, id)` for the received counter.
fn reload_recv_counter(ag: &Agentd, k: &mut AgentKeys) {
    let Some(id) = k.entry.as_ref().map(|e| e.id.clone()) else { return };
    let rids_file = format!("{RIDS_DIR}/{id}");
    let new_inode = file_inode(&rids_file);
    if k.recv_inode == new_inode {
        return;
    }
    match open_rw(&rids_file) {
        Some(mut f) => {
            let (g, l) = match scan_counter(&mut f) {
                Some(c) => c,
                None => {
                    ag.log.debug1(format!("No previous counter available for '{id}'."));
                    (0, 0)
                }
            };
            ag.log.debug1(format!("Reloading counter for agent {id}: '{g}:{l}'."));
            let e = k.entry.as_mut().unwrap();
            e.key.global_counter = g;
            e.key.local_counter = l;
            k.recv_fp = Some(f);
        }
        None => match open_w(&rids_file) {
            Ok(f) => k.recv_fp = Some(f),
            Err(e) => {
                let n = e.raw_os_error().unwrap_or(0);
                ag.log.error(format!("Unable to open agent file. errno: {n}"));
                ag.exit_critical(fopen_error(&rids_file, n));
            }
        },
    }
    k.recv_inode = new_inode;
}

/// `StoreCounter(keys, 0, global, local)`
fn store_recv_counter(ag: &Agentd, k: &mut AgentKeys, g: u32, l: u32) {
    let Some(id) = k.entry.as_ref().map(|e| e.id.clone()) else { return };
    if k.recv_fp.is_none() {
        let rids_file = format!("{RIDS_DIR}/{id}");
        let f = match open_rw(&rids_file) {
            Some(f) => f,
            None => match open_w(&rids_file) {
                Ok(f) => f,
                Err(e) => {
                    let n = e.raw_os_error().unwrap_or(0);
                    ag.log.error(format!("Unable to open agent file. errno: {n}"));
                    ag.exit_critical(fopen_error(&rids_file, n));
                }
            },
        };
        k.recv_fp = Some(f);
        ag.log.debug2(format!("Opening rids for agent {id}."));
    }
    write_counter(k.recv_fp.as_mut().unwrap(), g, l);
    if !k.rids_node {
        ag.log.debug2(format!("Pushing rids_node for agent {id}."));
        k.rids_node = true;
    } else {
        ag.log.debug2(format!("Updating rids_node for agent {id}."));
    }
}

/// `CreateSecMSG(&keys, msg, len, crypt_msg, 0)`. `None` is the C 0/-1
/// return (an error the caller reports as `SEC_ERROR`).
pub fn create_msg(ag: &Agentd, msg: &[u8]) -> Option<Vec<u8>> {
    let mut k = ag.keys.lock().unwrap();
    if msg.len() > OS_MAXSTR - OS_HEADER_SIZE || msg.is_empty() {
        let t = now();
        if t - k.saved_time > 3600 {
            ag.log.error(format!("Incorrect message size: {}", msg.len()));
            k.saved_time = t;
        }
        // ENCSIZE_ERROR "%64s"
        ag.log.debug2(format!("(1405): Message size not valid: '{:>64}'.", String::from_utf8_lossy(cstr(msg))));
        return None;
    }
    let key = k.entry.as_ref()?.key.clone();
    let dynamic_prefix = !k.entry.as_ref()?.single_host;

    reload_sender_counter(ag, &mut k);
    let mut counter = k.sender;
    let r = msgs::create_sec_msg_sized(&key, &mut counter, msg, CreateOptions { dynamic_prefix, random: None });
    k.sender = counter;
    match r {
        Ok((out, cmp_size)) => {
            // Average sizes: length = md5 (32) + "%05hu%010u:%04u:" + msg
            let length = 32 + format!("{:05}{:010}:{:04}:", 0, counter.global, counter.local).len() + msg.len();
            k.c_orig_size += length as u64;
            k.c_comp_size += cmp_size as u64;
            if k.evt_count > k.comp_print {
                ag.log.debug1(format!(
                    "Event count after '{}': {}->{} ({}%)",
                    k.evt_count,
                    k.c_orig_size,
                    k.c_comp_size,
                    (k.c_comp_size * 100) / k.c_orig_size.max(1)
                ));
                k.evt_count = 0;
                k.c_orig_size = 0;
                k.c_comp_size = 0;
            }
            k.evt_count += 1;
            let c = k.sender;
            if let Some(f) = k.sender_fp.as_mut() {
                write_counter(f, c.global, c.local);
            }
            Some(out)
        }
        Err(MsgError::CompressionFailed) => {
            ag.log.error(format!("(2201): Error compressing string: '{}'.", String::from_utf8_lossy(msg)));
            None
        }
        Err(_) => None,
    }
}

/// `ReadSecMSG(&keys, buffer, cleartext, 0, recv_b - 1, ...)`: the payload
/// when the message is `KS_VALID`.
pub fn read_msg(ag: &Agentd, buffer: &[u8]) -> Option<Vec<u8>> {
    let mut k = ag.keys.lock().unwrap();
    let verify = k.verify_counter;
    if verify && k.rcv_count >= k.recv_flush {
        reload_recv_counter(ag, &mut k);
    }
    let (saved_g, saved_l) = {
        let e = k.entry.as_ref()?;
        (e.key.global_counter, e.key.local_counter)
    };
    let r = {
        let e = k.entry.as_mut()?;
        msgs::read_sec_msg(&mut e.key, buffer, ReadOptions { verify_counter: verify })
    };
    match r {
        Ok(res) => {
            if k.rcv_count >= k.recv_flush {
                store_recv_counter(ag, &mut k, res.global, res.local);
                k.rcv_count = 0;
            }
            k.rcv_count += 1;
            Some(res.payload)
        }
        Err(MsgError::Rejected(KeyState::Rids)) if verify => {
            // Only reached by the compressed format when the global counters match.
            let name = k.entry.as_ref().map(|e| e.name.clone()).unwrap_or_default();
            let (g, l) = peek_counters(&k.entry.as_ref()?.key, buffer).unwrap_or((saved_g, 0));
            ag.log.warn(format!(
                "Duplicate error:  global: {g}, local: {l}, saved global: {saved_g}, saved local:{saved_l}"
            ));
            ag.log.error(format!("(1407): Duplicated counter for '{name}'."));
            None
        }
        Err(_) => None,
    }
}

/// The counters of a message (decrypted without verification).
fn peek_counters(key: &ClientKey, buffer: &[u8]) -> Option<(u32, u32)> {
    let mut k = key.clone();
    msgs::read_sec_msg(&mut k, buffer, ReadOptions { verify_counter: false }).ok().map(|r| (r.global, r.local))
}

/// The C string view of a buffer (up to the first NUL).
pub fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `os_write_agent_info(name, NULL, id, profile)`
pub fn write_agent_info(ag: &Agentd, name: &str, id: &str, profile: Option<&str>) -> bool {
    match open_w(AGENT_INFO_FILE) {
        Ok(mut f) => {
            let _ = write!(f, "{name}\n-\n{id}\n{}\n", profile.unwrap_or("-"));
            true
        }
        Err(e) => {
            ag.log.error(fopen_error(AGENT_INFO_FILE, e.raw_os_error().unwrap_or(0)));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fgets_chunks_lines() {
        let v = fgets_lines(b"a b\ncc\n", 2048);
        assert_eq!(v, vec![&b"a b\n"[..], &b"cc\n"[..]]);
        let long = vec![b'x'; 5000];
        let v = fgets_lines(&long, 2048);
        assert_eq!(v.iter().map(|c| c.len()).collect::<Vec<_>>(), vec![2047, 2047, 906]);
    }
}
