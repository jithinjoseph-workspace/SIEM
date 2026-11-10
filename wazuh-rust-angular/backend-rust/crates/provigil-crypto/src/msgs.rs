//! The agent message envelope: counters + MD5 + zlib + Blowfish/AES, and the counter files.

use crate::ciphers::{os_aes_str, os_bf_str};
use crate::hashes::md5_bytes;
use crate::keys::{ClientKey, CryptoMethod};
use flate2::{write::ZlibEncoder, Compression, Decompress, FlushDecompress, Status};
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const OS_MAXSTR: usize = 65536;
pub const OS_HEADER_SIZE: usize = 128;
/// 32-byte checksum + 5 random + 10 global + ':' + 4 local + ':'.
pub const MSG_OVERHEAD: usize = 53;
pub const SENDER_COUNTER: &str = "sender_counter";
/// Largest compressed body that still fits a message.
const MAX_COMPRESSED: usize = OS_MAXSTR - 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Valid = 0,
    Rids = 1,
    Corrupt = 2,
    EncKey = 3,
}

#[derive(Debug, thiserror::Error)]
pub enum MsgError {
    #[error("Message too large or empty: {0}")]
    InvalidSize(usize),
    #[error("Compression failed")]
    CompressionFailed,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("message refused by the envelope check: {0:?}")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Format,
    EncKey,
    EncKeySrc,
    Uncompress,
    TooShort,
    Sum,
    Rids,
}

thread_local! {
    static LAST_REJECT: Cell<RejectReason> = const { Cell::new(RejectReason::EncKeySrc) };
}

/// Why this thread's last `read_sec_msg` rejected a message.
pub fn last_reject_reason() -> RejectReason {
    LAST_REJECT.with(Cell::get)
}

fn reject(state: KeyState, reason: RejectReason) -> MsgError {
    LAST_REJECT.with(|c| c.set(reason));
    MsgError::Rejected(state)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub payload: Vec<u8>,
    pub global: u32,
    pub local: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CreateOptions {
    pub dynamic_prefix: bool,
    pub random: Option<u16>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOptions {
    pub verify_counter: bool,
    pub client: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SenderCounter {
    pub global: u32,
    pub local: u32,
}

impl SenderCounter {
    /// Local counts 1..=9997, then global goes up.
    pub fn next(&mut self) {
        if self.local >= 9997 {
            self.local = 0;
            self.global = self.global.wrapping_add(1);
        }
        self.local += 1;
    }
}

pub fn create_sec_msg(key: &ClientKey, counter: &mut SenderCounter, msg: &[u8], opts: CreateOptions) -> Result<Vec<u8>, MsgError> {
    create_sec_msg_sized(key, counter, msg, opts).map(|(m, _)| m)
}

/// Builds the wire message; also returns the size of the padded compressed body.
pub fn create_sec_msg_sized(
    key: &ClientKey,
    counter: &mut SenderCounter,
    msg: &[u8],
    opts: CreateOptions,
) -> Result<(Vec<u8>, usize), MsgError> {
    if msg.is_empty() || msg.len() > OS_MAXSTR - OS_HEADER_SIZE {
        return Err(MsgError::InvalidSize(msg.len()));
    }
    counter.next();
    let random = opts.random.unwrap_or_else(rand::random);
    let mut text = format!("{random:05}{:010}:{:04}:", counter.global, counter.local).into_bytes();
    text.extend_from_slice(msg);
    let mut inner = hex::encode(md5_bytes(&text)).into_bytes();
    inner.extend(text);

    let mut z = ZlibEncoder::new(Vec::new(), Compression::best());
    let compressed = z.write_all(&inner).and_then(|_| z.finish()).map_err(|_| MsgError::CompressionFailed)?;
    if compressed.is_empty() || compressed.len() > MAX_COMPRESSED {
        return Err(MsgError::CompressionFailed);
    }
    let pad = (8 - (compressed.len() + 1) % 8) % 8;
    let mut plain = vec![b'!'; 1 + pad];
    plain.extend(compressed);
    let cmp_size = plain.len();

    let token: &[u8] = match key.crypto_method {
        CryptoMethod::Blowfish => b":",
        CryptoMethod::Aes => b"#AES:",
    };
    let (mut out, keep) = if opts.dynamic_prefix {
        ([b"!", key.id.as_bytes(), b"!", token].concat(), 15)
    } else {
        (token.to_vec(), 5)
    };
    // The prefix keeps its length, but only its first bytes are copied (long ids give NUL bytes).
    out.iter_mut().skip(keep).for_each(|b| *b = 0);
    let enc = match key.crypto_method {
        CryptoMethod::Blowfish => os_bf_str(&plain, &key.encryption_key, true),
        CryptoMethod::Aes => os_aes_str(&plain, &key.encryption_key, true),
    };
    out.extend(enc.map_err(|e| MsgError::EncryptionFailed(e.to_string()))?);
    Ok((out, cmp_size))
}

/// C `atoi` over a zero-extended buffer: white space, sign, digits, saturating to i32.
fn atoi(at: &dyn Fn(usize) -> u8, mut i: usize) -> i32 {
    while matches!(at(i), b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let neg = at(i) == b'-';
    if matches!(at(i), b'+' | b'-') {
        i += 1;
    }
    let mut v: i64 = 0;
    while at(i).is_ascii_digit() {
        v = (v * 10 + i64::from(at(i) - b'0')).min(1 << 32);
        i += 1;
    }
    (if neg { -v } else { v }).clamp(i32::MIN.into(), i32::MAX.into()) as i32
}

fn md5_hex(data: &[u8]) -> Vec<u8> {
    hex::encode(md5_bytes(data)).into_bytes()
}

/// zlib-decompresses one stream (trailing bytes ignored); None if broken, empty or over OS_MAXSTR.
fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(OS_MAXSTR + 1);
    match Decompress::new(true).decompress_vec(data, &mut out, FlushDecompress::Finish) {
        Ok(Status::StreamEnd) if !out.is_empty() && out.len() <= OS_MAXSTR => Some(out),
        _ => None,
    }
}

/// Reads a message starting at `#AES:` or `:`; stores the message counters in `key` when accepted.
pub fn read_sec_msg(key: &mut ClientKey, buffer: &[u8], opts: ReadOptions) -> Result<ReadResult, MsgError> {
    use KeyState::*;
    use RejectReason as R;
    let mut size = buffer.len().saturating_sub(1);
    let aes_prefix = buffer.starts_with(b"#AES");
    let mut pos = if aes_prefix { 4 } else { 0 };
    if !opts.client {
        key.crypto_method = if aes_prefix { CryptoMethod::Aes } else { CryptoMethod::Blowfish };
    }
    if buffer.get(pos) != Some(&b':') {
        return Err(reject(Corrupt, R::Format));
    }
    pos += 1;
    let body = &buffer[pos..];
    let plain = match key.crypto_method {
        CryptoMethod::Blowfish => {
            let n = size.min(body.len()) / 8 * 8;
            os_bf_str(&body[..n], &key.encryption_key, false).map_err(|_| reject(EncKey, R::EncKey))?
        }
        CryptoMethod::Aes => {
            size = size.saturating_sub(4);
            let p = os_aes_str(&body[..size.min(body.len())], &key.encryption_key, false)
                .map_err(|_| reject(EncKey, R::EncKey))?;
            if p.is_empty() {
                return Err(reject(EncKey, R::EncKey));
            }
            p
        }
    };
    let at = |i: usize| plain.get(i).copied().unwrap_or(0);
    let newer = |g: u32, l: u32, k: &ClientKey| g > k.global_counter || (g == k.global_counter && l > k.local_counter);

    match at(0) {
        b'!' => {
            let bangs = plain.iter().take_while(|&&b| b == b'!').count();
            let end = (bangs + size.saturating_sub(bangs)).min(plain.len());
            let f = inflate(&plain[bangs..end]).ok_or_else(|| reject(Corrupt, R::Uncompress))?;
            if f.len() < MSG_OVERHEAD {
                return Err(reject(Corrupt, R::TooShort));
            }
            let (sum, rest) = f.split_at(32);
            if sum != md5_hex(rest) {
                return Err(reject(Corrupt, R::Sum));
            }
            let fat = |i: usize| rest.get(i).copied().unwrap_or(0);
            let global = atoi(&fat, 5) as u32;
            if rest[15] != b':' {
                return Err(reject(Corrupt, R::Format));
            }
            let local = atoi(&fat, 16) as u32;
            if rest[20] != b':' {
                return Err(reject(Corrupt, R::Format));
            }
            if opts.verify_counter && !newer(global, local, key) {
                return Err(if global == key.global_counter { reject(Rids, R::Rids) } else { reject(EncKey, R::EncKeySrc) });
            }
            key.global_counter = global;
            key.local_counter = local;
            Ok(ReadResult { payload: rest[21..].to_vec(), global, local })
        }
        b':' => {
            // Legacy uncompressed format: ":<md5 of the rest><time>:<count>:<payload>".
            let region: Vec<u8> = (33..1 + size).map(at).collect();
            let sum: Vec<u8> = (1..33).map(at).collect();
            if sum != md5_hex(&region) {
                return Err(reject(Corrupt, R::Sum));
            }
            let time = atoi(&at, 33) as u32;
            let count = atoi(&at, 44) as u32;
            // NUL bytes before offset 49 do not end the text.
            let text_end = (49..size).find(|&i| at(i) == 0).unwrap_or(size);
            let payload = (49..text_end)
                .find(|&i| at(i) == b':')
                .map(|c| (c + 1..text_end).map(at).collect::<Vec<u8>>());
            if !opts.verify_counter {
                key.global_counter = time;
                key.local_counter = 0;
            } else if newer(time, count, key) {
                key.global_counter = time;
                key.local_counter = count;
            } else {
                return Err(reject(Rids, R::Rids));
            }
            let payload = payload.ok_or_else(|| reject(Corrupt, R::Format))?;
            Ok(ReadResult { payload, global: time, local: count })
        }
        _ => Err(reject(EncKey, R::EncKeySrc)),
    }
}

/// Counter files `"<global>:<local>:"`, one per agent id plus the sender's own.
#[derive(Debug, Clone)]
pub struct CounterStore {
    pub recv_flush: u32,
    dir: PathBuf,
    count: u32,
}

impl CounterStore {
    pub fn new(dir: impl Into<PathBuf>, recv_flush: u32) -> CounterStore {
        CounterStore { recv_flush, dir: dir.into(), count: 0 }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load(&self, name: &str) -> (u32, u32) {
        let parse = |s: String| {
            let mut p = s.split(':');
            Some((p.next()?.trim().parse().ok()?, p.next()?.trim().parse().ok()?))
        };
        fs::read_to_string(self.dir.join(name)).ok().and_then(parse).unwrap_or((0, 0))
    }

    /// Deletes an agent's counter file; a missing file is fine.
    pub fn remove(&self, id: &str) -> io::Result<()> {
        match fs::remove_file(self.dir.join(id)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    pub fn store(&self, name: &str, global: u32, local: u32) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        fs::write(self.dir.join(name), format!("{global}:{local}:"))
    }

    pub fn start_agent(&self, key: &mut ClientKey) {
        (key.global_counter, key.local_counter) = self.load(&key.id);
    }

    pub fn load_sender(&self) -> SenderCounter {
        let (global, local) = self.load(SENDER_COUNTER);
        SenderCounter { global, local }
    }

    pub fn store_sender(&self, c: &SenderCounter) -> io::Result<()> {
        self.store(SENDER_COUNTER, c.global, c.local)
    }

    /// Call after each accepted message: writes the key's counters every `recv_flush` calls.
    pub fn on_received(&mut self, key: &ClientKey) -> io::Result<()> {
        if self.count >= self.recv_flush {
            // On failure the count stays, so the next accepted message writes again.
            self.store(&key.id, key.global_counter, key.local_counter)?;
            self.count = 0;
        }
        self.count += 1;
        Ok(())
    }
}

/// The sender counter file, kept open; stores overwrite from the start without truncating.
#[derive(Debug)]
pub struct SenderCounterFile {
    file: File,
}

impl SenderCounterFile {
    pub fn open(path: impl AsRef<Path>) -> io::Result<(SenderCounterFile, SenderCounter)> {
        let path = path.as_ref();
        let mut file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(f) => f,
            Err(_) => return Ok((SenderCounterFile { file: File::create(path)? }, SenderCounter::default())),
        };
        let mut text = Vec::new();
        // Unreadable or non-UTF-8 content counts as 0:0.
        let read = file.read_to_end(&mut text).ok().and_then(|_| String::from_utf8(text).ok());
        let (global, local) = read.and_then(|t| parse_counter(&t)).unwrap_or((0, 0));
        Ok((SenderCounterFile { file }, SenderCounter { global, local }))
    }

    pub fn store(&mut self, c: &SenderCounter) {
        let _ = self.file.seek(SeekFrom::Start(0));
        let _ = self.file.write_all(format!("{}:{}:", c.global, c.local).as_bytes());
        let _ = self.file.flush();
    }
}

/// Like C `fscanf("%u:%u")`, with any Unicode white space allowed before each number.
pub fn parse_counter(s: &str) -> Option<(u32, u32)> {
    let (global, rest) = scan_unsigned(s)?;
    let (local, _) = scan_unsigned(rest.strip_prefix(':')?)?;
    Some((global, local))
}

/// `%u`: optional white space and sign, at least one digit; overflow gives the maximum, cut to 32 bits.
fn scan_unsigned(s: &str) -> Option<(u32, &str)> {
    let s = s.trim_start_matches(char::is_whitespace);
    let b = s.as_bytes();
    let mut i = 0;
    let neg = b.get(i) == Some(&b'-');
    if matches!(b.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let start = i;
    let mut v: u64 = 0;
    while let Some(d) = b.get(i).filter(|c| c.is_ascii_digit()) {
        v = v.checked_mul(10).and_then(|v| v.checked_add(u64::from(d - b'0'))).unwrap_or(u64::MAX);
        i += 1;
    }
    if i == start {
        return None;
    }
    let v = v as u32;
    Some((if neg { v.wrapping_neg() } else { v }, &s[i..]))
}
