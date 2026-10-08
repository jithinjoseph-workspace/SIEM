//! Wazuh secure agent message framing — port of `src/os_crypto/shared/msgs.c`
//! (`CreateSecMSG`, `ReadSecMSG`, counter handling).
//!
//! Wire layout produced by `CreateSecMSG` (after the optional `!<id>!` prefix
//! that agents with a dynamic IP add):
//!
//! ```text
//! ":"      + Blowfish-CBC( "!"{1..8} + zlib( md5hex(T) + T ) )      (Blowfish)
//! "#AES:"  + AES-256-CBC ( "!"{1..8} + zlib( md5hex(T) + T ) )      (AES, PKCS7)
//! T = "%05hu%010u:%04u:" (random, global counter, local counter) + payload
//! ```
//!
//! The number of leading `!` is `1 + bfsize`, where `bfsize` pads the
//! compressed data plus one `!` to a multiple of 8. There is always at
//! least one `!`: the receiver uses it to tell the compressed format from
//! the legacy `:` format.
//!
//! Every function here is checked against the original C code, compiled
//! with gcc (see `tests/msgs_oracle.rs`).

use crate::ciphers::{os_aes_str, os_bf_str};
use crate::hashes::md5_bytes;
use crate::keys::{ClientKey, CryptoMethod};
use siem_shared::zlib::{os_zlib_compress, os_zlib_uncompress};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// `OS_MAXSTR`
pub const OS_MAXSTR: usize = 65536;
/// `OS_HEADER_SIZE`
pub const OS_HEADER_SIZE: usize = 128;

const MD5_CHECKSUM_SIZE: usize = 32;
const RANDOM_DATA_SIZE: usize = 5;
const GLOBAL_COUNTER_SIZE: usize = 10;
const LOCAL_COUNTER_SIZE: usize = 4;
const COUNTER_FORMAT_SIZE: usize = 1;
/// `MSG_OVERHEAD`
pub const MSG_OVERHEAD: usize =
    MD5_CHECKSUM_SIZE + RANDOM_DATA_SIZE + GLOBAL_COUNTER_SIZE + LOCAL_COUNTER_SIZE + 2 * COUNTER_FORMAT_SIZE;

/// `key_states` returned by `ReadSecMSG`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// `KS_VALID`
    Valid = 0,
    /// `KS_RIDS` — duplicated / replayed counter.
    Rids = 1,
    /// `KS_CORRUPT` — bad format, checksum or compression.
    Corrupt = 2,
    /// `KS_ENCKEY` — cannot decrypt with this agent's key (remoted then
    /// pushes a key request to authd).
    EncKey = 3,
}

#[derive(Error, Debug)]
pub enum MsgError {
    #[error("Message too large or empty: {0}")]
    InvalidSize(usize),
    #[error("Compression failed")]
    CompressionFailed,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("ReadSecMSG rejected the message: {0:?}")]
    Rejected(KeyState),
}

impl MsgError {
    pub fn key_state(&self) -> Option<KeyState> {
        match self {
            MsgError::Rejected(s) => Some(*s),
            _ => None,
        }
    }
}

/// C `atoi` over a byte slice (leading blanks, optional sign, digits).
fn atoi(b: &[u8]) -> i64 {
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || (b'\t'..=b'\r').contains(&b[i])) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((b[i] - b'0') as i64);
        i += 1;
    }
    if neg {
        -v
    } else {
        v
    }
}

/// `(unsigned int) atoi(...)`: atoi saturates to int, then the cast wraps.
fn atoi_u32(b: &[u8]) -> u32 {
    atoi(b).clamp(i32::MIN as i64, i32::MAX as i64) as i32 as u32
}

fn md5_hex(data: &[u8]) -> [u8; 32] {
    let d = md5_bytes(data);
    let mut out = [0u8; 32];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in d.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0xf) as usize];
    }
    out
}

/// `strncmp(a, b, 32) == 0` (stops at the first NUL).
fn strncmp32_eq(a: &[u8], b: &[u8]) -> bool {
    for i in 0..32 {
        let ca = a.get(i).copied().unwrap_or(0);
        let cb = b.get(i).copied().unwrap_or(0);
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
    }
    true
}

/// Sender-side counters (`global_count` / `local_count` statics in msgs.c,
/// persisted in `queue/rids/sender_counter`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SenderCounter {
    pub global: u32,
    pub local: u32,
}

impl SenderCounter {
    /// The increment done by `CreateSecMSG` before each message.
    pub fn next(&mut self) {
        if self.local >= 9997 {
            self.local = 0;
            self.global = self.global.wrapping_add(1);
        }
        self.local += 1;
    }
}

/// Options for [`create_sec_msg`].
#[derive(Debug, Clone, Copy)]
pub struct CreateOptions {
    /// `isAgent && !isSingleHost(key->ip)`: an agent registered with a
    /// non-single-host IP ("any", a CIDR) prefixes `!<id>!` so the manager
    /// can find its key.
    pub dynamic_prefix: bool,
    /// The 16-bit random value (`(u_int16_t) os_random()`); `None` draws one.
    pub random: Option<u16>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self { dynamic_prefix: false, random: None }
    }
}

/// `CreateSecMSG`: frame, compress, pad and encrypt `msg` for `key`.
///
/// `counter` is the sender counter. It is advanced here exactly like the C
/// code; persist it with [`CounterStore::store_sender`] afterwards.
pub fn create_sec_msg(
    key: &ClientKey,
    counter: &mut SenderCounter,
    msg: &[u8],
    opts: CreateOptions,
) -> Result<Vec<u8>, MsgError> {
    if msg.len() > OS_MAXSTR - OS_HEADER_SIZE || msg.is_empty() {
        return Err(MsgError::InvalidSize(msg.len()));
    }

    let token: &str = match key.crypto_method {
        CryptoMethod::Blowfish => ":",
        CryptoMethod::Aes => "#AES:",
    };

    let rand1: u16 = opts.random.unwrap_or_else(rand::random::<u16>);

    counter.next();

    // _tmpmsg = "%05hu%010u:%04u:" + msg  (snprintf bounded by OS_MAXSTR)
    let mut tmpmsg = format!("{:05}{:010}:{:04}:", rand1, counter.global, counter.local).into_bytes();
    tmpmsg.extend_from_slice(msg);

    let md5sum = md5_hex(&tmpmsg);
    let mut finmsg = Vec::with_capacity(32 + tmpmsg.len());
    finmsg.extend_from_slice(&md5sum);
    finmsg.extend_from_slice(&tmpmsg);

    // os_zlib_compress(_finmsg, _tmpmsg + 8, length, OS_MAXSTR - 12)
    let compressed = os_zlib_compress(&finmsg).map_err(|_| MsgError::CompressionFailed)?;
    if compressed.is_empty() || compressed.len() > OS_MAXSTR - 12 {
        return Err(MsgError::CompressionFailed);
    }

    let mut cmp_size = compressed.len() + 1;
    let mut bfsize = 8 - (cmp_size % 8);
    if bfsize == 8 {
        bfsize = 0;
    }
    cmp_size += bfsize;

    // Plaintext handed to the cipher: (bfsize + 1) '!' then the zlib data.
    let mut plain = vec![b'!'; bfsize + 1];
    plain.extend_from_slice(&compressed);
    debug_assert_eq!(plain.len(), cmp_size);

    // snprintf(msg_encrypted, 16, "!%s!%s", id, token) or snprintf(.., 6, "%s", token)
    let (full_prefix, limit) = if opts.dynamic_prefix {
        (format!("!{}!{}", key.id, token).into_bytes(), 15)
    } else {
        (token.as_bytes().to_vec(), 5)
    };
    let length = full_prefix.len();
    let mut out = vec![0u8; length];
    let shown = length.min(limit);
    out[..shown].copy_from_slice(&full_prefix[..shown]);

    let encrypted = match key.crypto_method {
        CryptoMethod::Blowfish => os_bf_str(&plain, &key.encryption_key, true),
        CryptoMethod::Aes => os_aes_str(&plain, &key.encryption_key, true),
    }
    .map_err(|e| MsgError::EncryptionFailed(e.to_string()))?;

    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// What `ReadSecMSG` needs to know about counter verification.
#[derive(Debug, Clone, Copy)]
pub struct ReadOptions {
    /// `remoted.verify_msg_id` (internal option, default 0 on the manager).
    pub verify_counter: bool,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self { verify_counter: false }
    }
}

/// Result of a successful [`read_sec_msg`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub payload: Vec<u8>,
    pub global: u32,
    pub local: u32,
}

/// `ReadSecMSG`.
///
/// `buffer` is the message as remoted hands it over: starting at `#AES:` or
/// `:` (the `!<id>!` prefix already removed). On success, the agent's
/// received counters in `key` are updated as the C code does. Persist them
/// through a [`CounterStore`].
pub fn read_sec_msg(key: &mut ClientKey, buffer: &[u8], opts: ReadOptions) -> Result<ReadResult, MsgError> {
    let reject = |s: KeyState| Err(MsgError::Rejected(s));

    let mut buf = buffer;
    // In C, buffer_size = recv_b - 1: the full length minus the ':' byte.
    let mut buffer_size = buffer.len().saturating_sub(1);

    let method = if buf.starts_with(b"#AES") {
        buf = &buf[4..];
        key.crypto_method = CryptoMethod::Aes;
        CryptoMethod::Aes
    } else {
        key.crypto_method = CryptoMethod::Blowfish;
        CryptoMethod::Blowfish
    };

    if buf.first() == Some(&b':') {
        buf = &buf[1..];
    } else {
        return reject(KeyState::Corrupt);
    }

    let cleartext: Vec<u8> = match method {
        CryptoMethod::Blowfish => {
            let n = buffer_size.min(buf.len());
            let whole = n - n % 8;
            match os_bf_str(&buf[..whole], &key.encryption_key, false) {
                Ok(v) => v,
                Err(_) => return reject(KeyState::EncKey),
            }
        }
        CryptoMethod::Aes => {
            buffer_size = buffer_size.saturating_sub(4);
            let n = buffer_size.min(buf.len());
            match os_aes_str(&buf[..n], &key.encryption_key, false) {
                Ok(v) if !v.is_empty() => v,
                _ => return reject(KeyState::EncKey),
            }
        }
    };

    // The C cleartext buffer is zero-filled; reads past the plaintext see 0.
    let clear_at = |i: usize| cleartext.get(i).copied().unwrap_or(0);

    if clear_at(0) == b'!' {
        // Compressed (current) format
        let mut start = 1usize;
        let mut size = buffer_size.saturating_sub(1);
        while clear_at(start) == b'!' {
            start += 1;
            size = size.saturating_sub(1);
        }
        let end = (start + size).min(cleartext.len().max(start));
        let src = if start <= cleartext.len() { &cleartext[start..end.min(cleartext.len())] } else { &[][..] };

        let decompressed = match os_zlib_uncompress(src) {
            Ok(v) if !v.is_empty() && v.len() <= OS_MAXSTR => v,
            _ => return reject(KeyState::Corrupt),
        };
        if decompressed.len() < MSG_OVERHEAD {
            return reject(KeyState::Corrupt);
        }

        // CheckSum
        let checksum = md5_hex(&decompressed[32..]);
        if !strncmp32_eq(&checksum, &decompressed[..32]) {
            return reject(KeyState::Corrupt);
        }

        let f = &decompressed[32..];
        // Remove random, then "%010u:%04u:"
        let msg_global = atoi_u32(&f[5..]);
        if f.get(15) != Some(&b':') {
            return reject(KeyState::Corrupt);
        }
        let msg_local = atoi_u32(&f[16..]);
        if f.get(20) != Some(&b':') {
            return reject(KeyState::Corrupt);
        }
        let payload = f[21..].to_vec();

        if !opts.verify_counter {
            key.global_counter = msg_global;
            key.local_counter = msg_local;
            return Ok(ReadResult { payload, global: msg_global, local: msg_local });
        }

        if msg_global > key.global_counter || (msg_global == key.global_counter && msg_local > key.local_counter) {
            key.global_counter = msg_global;
            key.local_counter = msg_local;
            return Ok(ReadResult { payload, global: msg_global, local: msg_local });
        }

        if msg_global == key.global_counter {
            return reject(KeyState::Rids);
        }
        // An older global counter falls through to the final KS_ENCKEY.
        return reject(KeyState::EncKey);
    } else if clear_at(0) == b':' {
        // Legacy format: ':' + md5(32) + "<time>:<count>:..." (pre-compression agents)
        let size = buffer_size;
        // Zero-filled C buffer with `cleartext[buffer_size] = '\0'`.
        let mut ct: Vec<u8> = (0..size + 64).map(clear_at).collect();
        ct[size] = 0;
        // cleartext++ ; CheckSum(cleartext, buffer_size): md5 over [33, 1 + size)
        let body = &ct[33..(1 + size).max(33)];
        if !strncmp32_eq(&md5_hex(body), &ct[1..33]) {
            return reject(KeyState::Corrupt);
        }
        // f_msg = cleartext + 32 => index 33; the C string ends at index `size`.
        let tail = &ct[33..size.max(33)];
        let msg_time = atoi_u32(&tail);
        let msg_count = atoi_u32(tail.get(11..).unwrap_or(&[]));
        let after = tail.get(16..).unwrap_or(&[]);
        // strchr stops at the first NUL
        let after = match after.iter().position(|&b| b == 0) {
            Some(n) => &after[..n],
            None => after,
        };
        let colon = after.iter().position(|&b| b == b':');

        if !opts.verify_counter {
            key.global_counter = msg_time;
            // The C code stores `msg_local`, which is still 0 on this path.
            key.local_counter = 0;
            return match colon {
                Some(p) => Ok(ReadResult { payload: after[p + 1..].to_vec(), global: msg_time, local: msg_count }),
                None => reject(KeyState::Corrupt),
            };
        }

        if msg_time > key.global_counter || (msg_time == key.global_counter && msg_count > key.local_counter) {
            key.global_counter = msg_time;
            key.local_counter = msg_count;
            return match colon {
                Some(p) => Ok(ReadResult { payload: after[p + 1..].to_vec(), global: msg_time, local: msg_count }),
                None => reject(KeyState::Corrupt),
            };
        }
        return reject(KeyState::Rids);
    }

    reject(KeyState::EncKey)
}

/// Persistence of message counters in `queue/rids/` (`OS_StartCounter`,
/// `StoreCounter`, `StoreSenderCounter`, `ReloadCounter`, `OS_RemoveCounter`).
/// Files hold `"%u:%u:"`.
#[derive(Debug, Clone)]
pub struct CounterStore {
    dir: PathBuf,
    /// `remoted.recv_counter_flush` (default 128): received counters are
    /// written every N messages.
    pub recv_flush: u32,
    rcv_count: u32,
}

pub const SENDER_COUNTER: &str = "sender_counter";

impl CounterStore {
    pub fn new(dir: impl Into<PathBuf>, recv_flush: u32) -> Self {
        Self { dir: dir.into(), recv_flush, rcv_count: 0 }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Read `"%u:%u"`; `(0, 0)` when missing or malformed.
    pub fn load(&self, name: &str) -> (u32, u32) {
        let Ok(s) = fs::read_to_string(self.path(name)) else { return (0, 0) };
        let mut it = s.split(':');
        let g = it.next().and_then(|v| v.trim().parse::<u32>().ok());
        let l = it.next().and_then(|v| v.trim().parse::<u32>().ok());
        match (g, l) {
            (Some(g), Some(l)) => (g, l),
            _ => (0, 0),
        }
    }

    pub fn store(&self, name: &str, global: u32, local: u32) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        fs::write(self.path(name), format!("{global}:{local}:"))
    }

    /// `OS_StartCounter` for one agent.
    pub fn start_agent(&self, key: &mut ClientKey) {
        let (g, l) = self.load(&key.id);
        key.global_counter = g;
        key.local_counter = l;
    }

    pub fn load_sender(&self) -> SenderCounter {
        let (global, local) = self.load(SENDER_COUNTER);
        SenderCounter { global, local }
    }

    pub fn store_sender(&self, c: &SenderCounter) -> io::Result<()> {
        self.store(SENDER_COUNTER, c.global, c.local)
    }

    /// Called after every accepted message; writes the agent counter every
    /// `recv_flush` messages, as `ReadSecMSG` does.
    pub fn on_received(&mut self, key: &ClientKey) -> io::Result<()> {
        if self.rcv_count >= self.recv_flush {
            self.store(&key.id, key.global_counter, key.local_counter)?;
            self.rcv_count = 0;
        }
        self.rcv_count += 1;
        Ok(())
    }

    /// `OS_RemoveCounter`
    pub fn remove(&self, id: &str) -> io::Result<()> {
        match fs::remove_file(self.path(id)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(method: CryptoMethod) -> ClientKey {
        let mut k = ClientKey::new("001".into(), "agent1".into(), "192.168.1.5".into(), "supersecretkey123456789".into());
        k.crypto_method = method;
        k
    }

    #[test]
    fn roundtrip_both_ciphers_and_replay() {
        for method in [CryptoMethod::Blowfish, CryptoMethod::Aes] {
            let sender = key(method);
            let mut receiver = sender.clone();
            let mut ctr = SenderCounter::default();
            let msg = b"1:/var/log/auth.log:Oct  5 10:00:00 host sshd[1]: Accepted password";
            let enc = create_sec_msg(&sender, &mut ctr, msg, CreateOptions::default()).unwrap();
            assert_eq!(ctr, SenderCounter { global: 0, local: 1 });
            let opts = ReadOptions { verify_counter: true };
            let r = read_sec_msg(&mut receiver, &enc, opts).unwrap();
            assert_eq!(r.payload, msg);
            assert_eq!(read_sec_msg(&mut receiver, &enc, opts).unwrap_err().key_state(), Some(KeyState::Rids));
            // Default manager behaviour (verify_msg_id=0) accepts replays.
            assert!(read_sec_msg(&mut receiver, &enc, ReadOptions::default()).is_ok());
        }
    }

    #[test]
    fn always_at_least_one_bang() {
        // Whatever the compressed size, the first decrypted byte must be '!'.
        let k = key(CryptoMethod::Blowfish);
        let mut ctr = SenderCounter::default();
        for n in 1..200 {
            let msg = vec![b'a' + (n % 26) as u8; n];
            let enc = create_sec_msg(&k, &mut ctr, &msg, CreateOptions::default()).unwrap();
            let plain = os_bf_str(&enc[1..], &k.encryption_key, false).unwrap();
            assert_eq!(plain[0], b'!');
            assert_eq!(plain.len() % 8, 0);
        }
    }

    #[test]
    fn dynamic_prefix() {
        let k = key(CryptoMethod::Aes);
        let mut ctr = SenderCounter::default();
        let enc = create_sec_msg(&k, &mut ctr, b"x", CreateOptions { dynamic_prefix: true, random: Some(1) }).unwrap();
        assert!(enc.starts_with(b"!001!#AES:"));
    }

    #[test]
    fn counter_rollover() {
        let mut c = SenderCounter { global: 3, local: 9997 };
        c.next();
        assert_eq!(c, SenderCounter { global: 4, local: 1 });
    }

    #[test]
    fn counter_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = CounterStore::new(dir.path(), 128);
        store.store("001", 7, 42).unwrap();
        assert_eq!(fs::read_to_string(dir.path().join("001")).unwrap(), "7:42:");
        assert_eq!(store.load("001"), (7, 42));
        assert_eq!(store.load("missing"), (0, 0));
    }
}
