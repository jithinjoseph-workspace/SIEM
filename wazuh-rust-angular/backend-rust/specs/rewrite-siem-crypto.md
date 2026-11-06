# Rewrite spec: `siem-crypto`

Clean-room description of the crypto / agent-key / message-envelope crate. It says **what** the crate
does. The writer must not open the old crate (`crates/siem-crypto/`) or `old-code/`.

Vectors in `specs/vectors/siem-crypto/` come from running the old crate; they define correct behaviour.
Where text and vector disagree, the vector wins.

Libraries (all MIT/Apache-2.0, already in the workspace lock file): `aes 0.8` + `cbc 0.1` (AES-256-CBC,
PKCS#7), `blowfish 0.9` (Blowfish, standard big-endian variant, via `cbc` without padding), `md-5 0.10`,
`sha1 0.10`, `sha2 0.10`, `hmac 0.12`, `hex`, `rand 0.8`, `flate2 1.x` with its default backend for zlib
(through `siem-shared`'s `zlib` module as today, or directly), `serde`, `thiserror`, `tracing`. No
hand-written cryptography. Depends on `siem-regex` for IP parsing (`is_valid_ip`, `ip_found`, `OsIp`,
`IpNet`).

**Byte-identical wire output** in `msgs.json` needs the same zlib encoder (flate2 default backend,
level 9 = best). If another compressor is used, compare `create_sec_msg` vectors by decrypting and
decompressing instead of by bytes; everything else must still match exactly.

---

## 1. Public interface

### 1.1 Used by other crates

| # | Item | Signature / shape | Used by (files) |
|---|---|---|---|
| C1 | `hashes::md5_bytes` | `fn (data: &[u8]) -> [u8; 16]` | siem-agentd `examples/fake_manager.rs` |
| C2 | `hashes::sha1_str` | `fn (s: &str) -> String` (40 lower-case hex) | siem-agentd `enrollment.rs` |
| C3 | `hashes::sha1_file` | `fn <P: AsRef<Path>>(path: P) -> io::Result<String>` | siem-modulesd `agent_upgrade.rs` |
| C4 | `keys::CryptoMethod` | `#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] enum { Blowfish = 0, Aes = 1 }`, `Default = Blowfish`; also root re-export | siem-agentd, siem-remoted tests, tools/loadgen |
| C5 | `keys::ClientKey` | `#[derive(Debug, Clone, Serialize, Deserialize)] struct { pub id, pub name, pub ip, pub raw_key, pub encryption_key: String, pub crypto_method: CryptoMethod, pub global_counter: u32, pub local_counter: u32 }` | siem-agentd, siem-api, siem-authd, siem-remoted, tools/loadgen |
| C6 | `ClientKey::new` | `fn new(id: String, name: String, ip: String, raw_key: String) -> ClientKey` | same |
| C7 | `ClientKey::to_key_line` | `fn (&self) -> String` | siem-api `provigil_manager.rs` |
| C8 | `keys::KeyStore` | `#[derive(Debug, Clone, Default)] struct { pub keys: Vec<ClientKey>, /* private indexes */ }` | siem-api, siem-authd, siem-util |
| C9 | `keys::KeyStore::new` | `fn () -> KeyStore` | siem-api, siem-authd |
| C10 | `keys::KeyStore::load_file` | `fn <P: AsRef<Path>>(p: P) -> io::Result<KeyStore>` | siem-authd `server.rs`; siem-api `provigil_manager.rs` |
| C11 | `keys::KeyStore::save_file` | `fn <P: AsRef<Path>>(&self, p: P) -> io::Result<()>` | siem-authd `server.rs` |
| C12 | `keys::KeyStore::parse_line` | `fn (line: &str) -> Option<ClientKey>` | siem-api `agent_keys_store.rs` |
| C13 | `keys::KeyStore::generate_raw_key` | `fn () -> String` | siem-authd, siem-util `manage_agents.rs` |
| C14 | `keys::KeyStore::next_id` | `fn (&self) -> String` | siem-authd |
| C15 | `keys::KeyStore::add_key` | `fn (&mut self, key: ClientKey)` | siem-authd, siem-api |
| C16 | `keys::KeyStore::delete_key` | `fn (&mut self, id: &str) -> Option<ClientKey>` | siem-authd |
| C17 | `keys::KeyStore::find_by_id` / `find_by_name` / `find_by_ip` | `fn (&self, &str) -> Option<&ClientKey>` | siem-authd, siem-api |
| C18 | `keys::KeyStore::len` | `fn (&self) -> usize` | siem-authd tests |
| C19 | `keystore::KeyStore` | `#[derive(Debug, Default)] struct { pub entries: Vec<Arc<KeyEntry>>, pub file: String, pub stamp: Option<FileStamp>, pub id_counter: i64, pub removed_keys: Vec<String>, pub save_removed: bool, /* private: id index, ip index, socket map behind a Mutex */ }` | siem-remoted (re-exports the whole module), siem-agentd `keys.rs`, siem-modulesd `database.rs` |
| C20 | `keystore::KeyStore::add_key` | `fn (&mut self, id: &str, name: &str, ip: &str, key: &str, time_added: i64) -> Result<usize, KeysError>` | siem-agentd |
| C21 | `keystore::KeyStore::read` | `fn (file: &str, pass_empty_keyfile: bool, save_removed: bool) -> Result<KeyStore, KeysError>` | siem-remoted `lib.rs`; siem-modulesd |
| C22 | `keystore::KeyStore::needs_reload` / `reload` | `fn (&self) -> bool` / `fn (&self, pass_empty_keyfile: bool) -> Result<KeyStore, KeysError>` | siem-remoted `forwarders.rs` |
| C23 | `keystore::KeyStore::allowed_ip` / `allowed_id` / `allowed_dynamic_id` | `-> Option<Arc<KeyEntry>>` (`(&self, &str)`, `(&self, &str)`, `(&self, id: &str, srcip: &str)`) | siem-remoted `server.rs`, `manager.rs` |
| C24 | `keystore::KeyStore::add_socket` / `delete_socket` | `fn (&self, keyid: usize, sock: i64) -> bool` / `fn (&self, sock: i64) -> bool` | siem-remoted `server.rs` |
| C25 | `keystore::KeyStore::net_protocol` | `fn (&self, id: &str) -> Option<NetProtocol>` | siem-remoted `manager.rs`, `request.rs` |
| C26 | `keystore::KeyEntry` | `#[derive(Debug)] struct { pub keyid: usize, pub id, pub name, pub ip_str: String, pub ip: OsIp, pub raw_key: String, pub time_added: i64, pub state: Mutex<KeyState> }` | siem-remoted, siem-agentd, siem-modulesd |
| C27 | `KeyEntry::is_single_host` / `snapshot` | `fn (&self) -> bool` / `fn (&self) -> KeySnapshot` | siem-agentd / siem-remoted |
| C28 | `keystore::KeySnapshot` | `#[derive(Debug, Clone)] struct { pub id, pub name, pub ip: String, pub peer: Option<SocketAddr> }` | siem-remoted `manager.rs`, `server.rs` |
| C29 | `keystore::KeyState` | `#[derive(Debug, Clone)] struct { pub rcvd: i64, pub sock: i64, pub net_protocol: NetProtocol, pub peer: Option<SocketAddr>, pub post_startup: bool, pub key: ClientKey }` | siem-remoted |
| C30 | `keystore::NetProtocol` | `#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] enum { #[default] Unknown, Tcp, Udp }` | siem-remoted |
| C31 | `keystore::UDP_SOCK` | `pub const i64 = -1` | siem-remoted |
| C32 | `keystore::KeysError` | `#[derive(Debug, thiserror::Error)] enum { Open(String, String), InvalidIp(String), NoClientKeys }` | siem-remoted `lib.rs` |
| C33 | `keystore::FileStamp`, `keystore::file_stamp` | `#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] struct { pub mtime: i64, pub inode: u64 }`; `fn (path: &str) -> Option<FileStamp>` | siem-remoted `shared_download.rs` |
| C34 | `keystore::KEYS_REQ`, `keystore::VERSION_REQ` | `pub const u8 = b'K'`, `b'V'` | siem-api `provigil_manager.rs`; siem-modulesd |
| C35 | `keystore::platform_source`, `keystore::platform_fetch` | `fn () -> Option<(String, String)>`; `fn (kind: u8) -> Result<(u64, String), String>` | siem-modulesd `database.rs` |
| C36 | `msgs::create_sec_msg` | `fn (key: &ClientKey, counter: &mut SenderCounter, msg: &[u8], opts: CreateOptions) -> Result<Vec<u8>, MsgError>`; also root | siem-remoted `server.rs`, tests; siem-agentd example; tools/loadgen |
| C37 | `msgs::create_sec_msg_sized` | same, `-> Result<(Vec<u8>, usize), MsgError>` | siem-agentd `keys.rs` |
| C38 | `msgs::read_sec_msg` | `fn (key: &mut ClientKey, buffer: &[u8], opts: ReadOptions) -> Result<ReadResult, MsgError>`; also root | siem-remoted, siem-agentd |
| C39 | `msgs::ReadResult` | `#[derive(Debug, Clone, PartialEq, Eq)] struct { pub payload: Vec<u8>, pub global: u32, pub local: u32 }` | fields read by siem-agentd |
| C40 | `msgs::CreateOptions` | `#[derive(Debug, Clone, Copy)] struct { pub dynamic_prefix: bool, pub random: Option<u16> }`, `Default` = (false, None) | siem-remoted, siem-agentd, tools/loadgen |
| C41 | `msgs::ReadOptions` | `#[derive(Debug, Clone, Copy)] struct { pub verify_counter: bool, pub client: bool }`, `Default` = (false, false) | siem-remoted, siem-agentd |
| C42 | `msgs::SenderCounter` + `next` | `#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)] struct { pub global: u32, pub local: u32 }`; `fn next(&mut self)` | siem-remoted, siem-agentd, tools/loadgen |
| C43 | `msgs::KeyState` | `#[derive(Debug, Clone, Copy, PartialEq, Eq)] enum { Valid = 0, Rids = 1, Corrupt = 2, EncKey = 3 }` (root re-export is this one) | siem-remoted `server.rs`, siem-agentd |
| C44 | `msgs::MsgError` + `key_state` | `#[derive(Debug, thiserror::Error)] enum { InvalidSize(usize), CompressionFailed, EncryptionFailed(String), Rejected(KeyState) }`; `fn key_state(&self) -> Option<KeyState>` | siem-remoted, siem-agentd |
| C45 | `msgs::RejectReason`, `msgs::last_reject_reason` | `#[derive(Debug, Clone, Copy, PartialEq, Eq)] enum { Format, EncKey, EncKeySrc, Uncompress, TooShort, Sum, Rids }`; `fn () -> RejectReason` | siem-agentd `keys.rs` |
| C46 | `msgs::CounterStore` | `#[derive(Debug, Clone)] struct { pub recv_flush: u32, /* dir, count */ }`; `new(dir: impl Into<PathBuf>, recv_flush: u32)`, `dir(&self) -> &Path`, `load(&self, name: &str) -> (u32, u32)`, `store(&self, name, g, l) -> io::Result<()>`, `start_agent(&self, key: &mut ClientKey)`, `load_sender(&self) -> SenderCounter`, `store_sender(&self, &SenderCounter) -> io::Result<()>`, `on_received(&mut self, key: &ClientKey) -> io::Result<()>` | siem-remoted `lib.rs`, `server.rs`, `forwarders.rs` |
| C47 | `msgs::SENDER_COUNTER` | `pub const &str = "sender_counter"` | siem-remoted |
| C48 | `msgs::SenderCounterFile` | `struct` (holds an open file); `open(path: impl AsRef<Path>) -> io::Result<(SenderCounterFile, SenderCounter)>`, `store(&mut self, &SenderCounter)` | siem-remoted |
| C49 | `msgs::parse_counter` | `fn (s: &str) -> Option<(u32, u32)>` | siem-agentd `keys.rs` |

Module names that must exist: `ciphers`, `hashes`, `keys`, `keystore`, `msgs`, `signature` (the last
only if kept). Root re-exports used: `ClientKey`, `CryptoMethod`, `KeyStore` (the `keys` one), `KeyState`
(the `msgs` one), `create_sec_msg`, `read_sec_msg`, `CreateOptions`, `ReadOptions`, `SenderCounter`.

### 1.2 Public today, used by nobody outside the crate (may be dropped; listed on purpose)

| # | Item | Why it can go |
|---|---|---|
| CU1 | `hashes::{md5_str, md5_file, sha1_bytes, sha256_str, sha256_bytes, sha256_file, sha512_str, sha512_bytes, sha512_file, hmac_sha1_str, hmac_sha1_file, multi_hash_file}` | no caller (`md5_str` is needed inside for key derivation). Vectors kept in `hashes.json`. |
| CU2 | `ciphers::{encrypt_aes, decrypt_aes, os_aes_str, encrypt_blowfish, decrypt_blowfish, os_bf_str, PROVIGIL_AES_IV, PROVIGIL_BLOWFISH_IV, CipherError}` | no caller; the message code needs the behaviour, so it may become private. |
| CU3 | `CipherError::InvalidKeyLength` | never produced. |
| CU4 | `keys::derive_encryption_key` | no caller; `ClientKey::new` needs it inside. |
| CU5 | `keys::KeyStore::{find_by_id_mut, is_empty}` | no caller. |
| CU6 | `keystore::KeyStore::{allowed_name, len, is_empty}` | no caller. |
| CU7 | `keystore::KeyStore` fields `id_counter`, `removed_keys` (and `save_removed` as a field) | no caller reads them (they are filled by `parse`, see 2.4; keep if cheap). |
| CU8 | `keystore::KEYSIZE` (128) | siem-agentd has its own copy. The 127-byte field limit itself is behaviour. |
| CU9 | `keystore::platform_stamp` | no caller; behaviour used inside. |
| CU10 | `KeyEntry::time_added` field | no caller reads it. |
| CU11 | `msgs::{OS_MAXSTR, OS_HEADER_SIZE, MSG_OVERHEAD}` | callers have their own constants; the values (65536, 128, 53) are behaviour. |
| CU12 | `msgs::CounterStore::remove` | no caller. |
| CU13 | `signature` module (`read_wpk_header`, `WpkHeader`, `WPK_MAGIC`, `WPK_SIGNATURE_LEN`, `SignatureError`) | no caller; it only reads a header and never verifies anything. Vectors in `signature.json` if kept. |
| CU14 | `Serialize`/`Deserialize` on `ClientKey`, `CryptoMethod` | no caller serialises them (checked siem-authd, siem-api). Keep the derives if cheap. |

Count: 49 used entries (C1-C49, about 75 single items counting methods and types), 14 unused groups
(about 45 single items).

---

## 2. Behaviour

### 2.1 Hashes

- MD5, SHA-1, SHA-256, SHA-512 as standardised (RFC 1321, FIPS 180-4). `*_str` hash the UTF-8 bytes and
  return lower-case hex; `*_bytes` return the raw digest; `*_file` stream the file and return lower-case
  hex, or the `io::Error` of opening/reading (kind `NotFound` for a missing file).
- HMAC-SHA1 (RFC 2104) with the key's UTF-8 bytes (any length, empty allowed), lower-case hex.
- `multi_hash_file(path, max)`: MD5, SHA-1, SHA-256 of the file in one pass as `(md5, sha1, sha256)`
  hex. `max == 0` means no limit; otherwise a file **larger** than `max` bytes gives
  `io::ErrorKind::InvalidData` with text `File size exceeded max allowed size of <max> bytes` (equal size
  is fine).

### 2.2 Ciphers

- AES: AES-256-CBC with PKCS#7. The key is zero-padded or cut to 32 bytes, the IV to 16 bytes (so any
  key/IV length is accepted). Encrypting always adds 1-16 padding bytes. Decrypting input whose length is
  not a positive multiple of 16, or with bad padding, -> `CipherError::Decryption`.
- Blowfish: Blowfish-CBC, standard (big-endian) Blowfish, no padding scheme. Key must be 4-56 bytes,
  else `Encryption` (encrypt) / `Decryption` (decrypt). IV zero-padded or cut to 8 bytes. Encrypt
  zero-pads the data to a multiple of 8 (empty stays empty). Decrypt requires a multiple of 8 (else
  `Decryption`) and returns the blocks as decrypted (padding left in place).
- `os_aes_str(input, key_text, encrypt)` / `os_bf_str(...)`: the above with the key text's bytes and the
  fixed IVs: AES IV = the 16 ASCII bytes `FEDCBA0987654321`; Blowfish IV = `fe dc ba 98 76 54 32 10`.

Vectors: `ciphers.json` (824 cases, incl. mutated ciphertexts).

### 2.3 `keys` module (client.keys text kept by the API/enrolment side)

- `derive_encryption_key(name, id, raw)` = `md5hex(raw)` followed by the first 15 characters of
  `md5hex(md5hex(name) + md5hex(id))` (all lower-case hex): always 47 characters. Consequence: the AES
  message key (first 32 bytes) is just `md5hex(raw_key)`; Blowfish uses all 47 bytes.
- `ClientKey::new` fills `encryption_key` with that, `crypto_method = Blowfish`, counters 0.
  `to_key_line()` = `"<id> <name> <ip> <raw_key>"`.
- `KeyStore::parse_line(line)`: split on any run of white space; fewer than 4 fields -> `None`; extra
  fields ignored; builds a `ClientKey`. No special meaning for `#` or `!` here.
- `load_file(path)`: read lines; each line is trimmed; empty lines and lines starting with `#` are
  skipped; the rest go through `parse_line` (lines that give `None` are skipped silently); keys are added
  with `add_key` in file order. Missing file -> the `io::Error`.
- `add_key(key)`: appended; the id and name lookups and the ip lookup (except for ip `any`) now point to
  this key; a later key with the same id/name/ip **replaces** the earlier one in the lookup (both stay in
  `keys`).
- `delete_key(id)`: removes the key the id lookup points to (the last one added with that id), returns
  it, rebuilds the lookups from the remaining list (again last wins); unknown id -> `None`.
- `find_by_id/name/ip`: through the lookups; `find_by_ip("any")` is always `None`.
- `next_id()`: largest id that parses as an unsigned 64-bit number (others ignored) plus one, written
  with at least 3 digits (`"001"`, `"1000"`); empty store -> `"001"`. (At the u64 maximum the old code
  overflows: panic in debug builds; nobody reaches it.)
- `save_file(path)`: create/truncate and write `to_key_line() + "\n"` for each key in list order.
- `generate_raw_key()`: 32 random bytes as 64 lower-case hex characters.

Vectors: `keys.json`.

### 2.4 `keystore` module (key table of the manager daemons)

- `add_key(id, name, ip, key, time_added)`: `ip` parsed with `siem_regex::is_valid_ip`; code 0 ->
  `Err(InvalidIp(ip))`. Entry: `keyid` = position, `ip_str` = the parsed stored text up to its first
  `/` (so IPv6 addresses appear expanded, `::ffff:` addresses as plain IPv4), `ip` = the parsed entry,
  state: `rcvd 0`, `sock -1`, `Unknown`, no peer, `post_startup false`, `key = ClientKey::new(id, name,
  ip as given, key)` with Blowfish. Lookups: by id and by `ip_str`, the **first** entry wins on
  duplicates.
- `parse(text)`: line by line (any length, `\n` kept for the checks below):
  - a line starting with `#` or a space is skipped;
  - no space in the line -> log ERROR `(1401): Error reading authentication key: '<whole line incl. its
    newline>'.` and skip;
  - id = text before the first space, cut to 127 bytes (on a character boundary); if it parses as a
    signed 64-bit number larger than `id_counter`, `id_counter` takes it (also for removed lines);
  - the text after the first space starting with `#` or `!` -> a removed agent: when `save_removed`, the
    line without its `\n` is appended to `removed_keys`; skip;
  - name = up to the next space, ip = up to the next space (missing -> log ERROR `(1401)...'<id>'.` and
    skip), key = the rest up to the `\n` (keeps `\r`, inner spaces), each cut to 127 bytes;
  - `add_key(..., 0)`; an invalid IP stops parsing with `Err(InvalidIp(ip))` (entries before it stay).
- `read(file, pass_empty, save_removed)`:
  - Platform key service (when `platform_source()` is `Some`): up to 30 attempts one second apart of
    `platform_fetch(KEYS_REQ)`; on success `stamp = {mtime: version, inode: u64::MAX}`, `parse` the
    text, then an empty table without `pass_empty` -> `NoClientKeys`. All 30 fail ->
    `Open("the platform's key service", <last error>)`.
  - File: `stamp = file_stamp(file)` (taken before reading); read the file (invalid UTF-8 replaced);
    missing/unreadable: without `pass_empty` -> `Open(file, <io error text>)`; with it -> log DEBUG
    `(1751): File client.keys not found or empty.` and continue empty. Then an empty table without
    `pass_empty` -> `NoClientKeys`. `file` field = the path given.
  - Error texts: `(1103): Could not open file '<a>': <b>`, `(1237): Invalid ip address: '<ip>'.`,
    `(1750): No client configured. Exiting.`
- `needs_reload()`: with the key service: `platform_fetch(VERSION_REQ)` succeeds and its stamp differs
  from `stamp` (a failed fetch -> `false`); else `file_stamp(file) != stamp`.
- `reload(pass_empty)`: `read(file, pass_empty, save_removed)`; then for every old entry whose id exists
  in the new table with the **same `ip_str`**, copy `rcvd`, `sock` and `peer` into the new entry (not
  the protocol, `post_startup` or counters) and, when the old `sock >= 0`, map that socket to the new
  entry.
- `allowed_ip(srcip)`: entry whose `ip_str` equals the text exactly (`"any"` finds the first `any`
  entry). `allowed_id(id)`: by id. `allowed_name(name)`: first entry with that name.
  `allowed_dynamic_id(id, srcip)`: the id's entry if `siem_regex::ip_found(srcip, entry.ip)`.
- `add_socket(keyid, sock)`: map socket -> entry; `true` if the socket was new, `false` if it replaced a
  mapping. `delete_socket(sock)`: remove the mapping; if there was one, set that entry's `sock` to -1
  only when it still equals `sock`; returns whether a mapping existed. Thread-safe through `&self`.
- `net_protocol(id)`: the entry's current protocol.
- `is_single_host()`: IPv4 entry with an all-ones mask; IPv6 and `any` -> false.
- `snapshot()`: `id`, `name`, `ip = ip_str`, current `peer`.
- `file_stamp(path)`: `None` if the path cannot be stat'ed; `mtime` = modification time in whole
  seconds since 1970 (0 if unavailable); `inode` = inode number on Unix, **file length** on Windows.
- `platform_source()`: `(SIEM_KEYS_ADDR, SIEM_KEYS_TOKEN)` when both environment variables are set and
  non-empty.
- `platform_fetch(kind)`: no source -> `Err("no key service")`. TCP connect to the address (`Err("<addr>:
  <error>")`), 10 s read timeout. Request: `u32 little-endian (1 + token length)`, the kind byte, the
  token bytes. Answer: `u32 LE n`; `n == 0` or `n > 64 MiB` -> `Err("answer of <n> bytes")`; then `n`
  bytes (short read -> the I/O error text); first byte not the requested kind -> `Err("refused")`; the
  rest as text (lossy UTF-8): before the first `\n` is the version (trimmed, unsigned 64-bit, else
  `Err("bad version")`), after it the client.keys text (`""` when there is no newline).
  `KEYS_REQ = b'K'`, `VERSION_REQ = b'V'`. The server side lives in siem-api (`provigil_manager.rs`).

Vectors: `keystore.json` (parse x save_removed, lookups, sockets, read, reload, platform fetch with a
local fake server: request bytes and every answer kind).

### 2.5 `msgs` - the agent message envelope

**Create** (`create_sec_msg_sized(key, counter, msg, opts)`; `create_sec_msg` drops the size):
1. `msg` empty or longer than 65,408 bytes (65536 - 128) -> `InvalidSize(len)`, counter unchanged.
2. Advance the counter: if `local >= 9997` then `local = 0` and `global += 1` (wrapping); then
   `local += 1`.
3. `random` = the given value or a random `u16`.
4. Text `T` = `random` as 5 decimal digits (zero-padded) + `global` as 10 digits + `:` + `local` as 4
   digits (more if larger) + `:` + `msg` bytes.
5. Inner = lower-case hex MD5 of `T` (32 bytes) + `T`.
6. zlib-compress the inner (RFC 1950, best compression). Failure, empty output, or output longer than
   65,524 bytes -> `CompressionFailed` (the counter has already advanced).
7. Plain = `1 + p` bytes `!` followed by the compressed data, where `p` (0-7) makes the length a
   multiple of 8. `cmp_size` = plain length.
8. Prefix = `"!<id>!" + token` when `dynamic_prefix`, else `token`; token = `:` for Blowfish, `#AES:`
   for AES. Only the first 15 bytes (dynamic) or 5 bytes (plain) of the prefix are copied; the
   remaining prefix length is filled with zero bytes (long ids give NUL bytes; total length unchanged).
9. Output = prefix + `os_bf_str(plain, encryption_key)` or `os_aes_str(plain, encryption_key)` (AES adds
   PKCS#7 padding). Encryption failure -> `EncryptionFailed(text)` (Blowfish key outside 4-56 bytes).

**Read** (`read_sec_msg(key, buffer, opts)`; `buffer` starts at `#AES:` or `:`, any `!<id>!` already
removed). Each rejection sets the thread's `last_reject_reason()` (initially `EncKeySrc`) and returns
`Rejected(state)`:
1. `size = len - 1` (0 for empty).
2. Starts with `#AES` -> skip 4 bytes; manager mode (`client = false`) sets `key.crypto_method = Aes`.
   Otherwise manager mode sets it to `Blowfish`. In client mode the key's configured method is used
   whatever the prefix says (the 4 bytes are still skipped).
3. Next byte must be `:` -> else `Corrupt`/`Format` (also for an empty buffer). Skip it.
4. Blowfish: decrypt the largest multiple of 8 bytes not longer than `min(size, remaining)`; failure ->
   `EncKey`/`EncKey`. AES: `size -= 4`; decrypt `min(size, remaining)` bytes; failure or empty result ->
   `EncKey`/`EncKey`. Reads past the decrypted text see zero bytes.
5. First plain byte `!` (current format): skip all leading `!`; take at most `size - 1 - (extra !)`
   bytes after them (clipped to the text) and zlib-decompress (bytes after the end of the zlib stream
   are ignored). Error, empty, or more than 65,536 bytes -> `Corrupt`/`Uncompress`. Shorter than 53
   bytes -> `Corrupt`/`TooShort`. The first 32 bytes must equal the lower-case hex MD5 of the rest,
   compared like C `strncmp` over 32 (stops early at a NUL in either) -> else `Corrupt`/`Sum`. In the
   rest `F`: global = C-atoi of `F[5..]` (white space, sign, digits; saturates to i32, then cast to u32 so
   `-7` becomes 4294967289); `F[15]` must be `:`; local = C-atoi of `F[16..]`; `F[20]` must be `:` (else
   `Corrupt`/`Format`); payload = `F[21..]`.
   - `verify_counter = false`: store the message counters in `key` and accept.
   - `true`: accept and store when `global > saved` or (`global == saved` and `local > saved local`);
     equal global otherwise -> `Rids`/`Rids`; older global -> `EncKey`/`EncKeySrc`. Rejections leave the
     saved counters unchanged.
6. First plain byte `:` (legacy, uncompressed): the 32 bytes after the `:` must equal the MD5 hex of the
   plain bytes from offset 33 up to offset `1 + size` (zero bytes past the decrypted text count; with AES
   the padding makes this fail) -> else `Corrupt`/`Sum`. time = C-atoi from offset 33, count = C-atoi from
   offset 44; payload = text after the first `:` at or after offset 49, within the text up to `size` or
   the first NUL. `verify_counter = false`: `key.global = time`, `key.local = 0` (always 0), then accept
   if that `:` exists else `Corrupt`/`Format` (counters already stored). `true`: newer (same rule as
   above) -> store time/count, accept or `Format`; otherwise `Rids`/`Rids`.
7. Any other first byte -> `EncKey`/`EncKeySrc`.
- Success returns `ReadResult { payload, global, local }` (the message's counters).
- Error texts: `Message too large or empty: <n>`, `Compression failed`, `Encryption failed: <text>`,
  `ReadSecMSG rejected the message: <State>` (only shown in logs; may be renamed if callers are checked).

**Counters on disk** (`CounterStore`, directory given at creation; files contain `"<global>:<local>:"`):
- `load(name)`: read the file; split on `:`; the first two parts trimmed and parsed as `u32`; anything
  else (missing file, bad text) -> `(0, 0)`.
- `store(name, g, l)`: create the directory if needed, write `"g:l:"` (truncating).
- `start_agent(key)`: `load(key.id)` into the key's counters. `load_sender` / `store_sender`: the file
  `sender_counter`.
- `on_received(key)`: called after each accepted message; writes the key's counters when the internal
  count has reached `recv_flush`, then resets the count; the count then increases by one. So with
  `recv_flush = 3` the file is written on calls 4, 7, 10, ... (every 3rd call after the first 3);
  with 0 on every call; with 1 on every call from the second on.
- `remove(id)` (unused): delete the file; a missing file is fine.
- `SenderCounterFile::open(path)`: an existing file is opened read/write and its counter read with
  `parse_counter` (`(0,0)` when it does not parse); a missing file is created empty -> `(0,0)`.
  `store(c)`: write `"g:l:"` at the start of the file **without truncating** (old longer text stays
  after it: `123456:789:` then store(1,2) -> `1:2:56:789:`), then flush; errors are ignored.
- `parse_counter(s)`: like C `fscanf("%u:%u")`: optional leading white space, optional sign, at least one
  digit (value as unsigned 64-bit, overflow -> u64 max, then cut to the low 32 bits; a `-` negates
  modulo 2^32), then `:` immediately, then the same for the second number; otherwise `None`.

Vectors: `msgs.json` (1,132 cases: creates for 3 keys x 2 ciphers x many lengths x counters x prefix,
each with reads under 6 saved counters x options, wrong key, and hostile buffers: truncated, flipped,
appended, crafted plaintexts for every reject reason, legacy format), `counters.json`.

### 2.6 Signature (unused, CU13)

`read_wpk_header(path)`: file must start with `WPK256` (else `InvalidMagic`; shorter file -> I/O error);
one optional NUL after it; then 256 signature bytes (short -> I/O error); `content_offset` = position
after them (263 with NUL, 262 without); `certificate_der` always empty. Nothing is verified.

---

## 3. Feature table

| # | Feature | Vectors |
|---|---|---|
| G1 | MD5/SHA-1/SHA-256/SHA-512 over text, bytes, files | hashes |
| G2 | HMAC-SHA1 text/file | hashes |
| G3 | multi-hash with size limit (0 = none, larger -> InvalidData) | hashes |
| G4 | Missing-file errors | hashes |
| G5 | AES-256-CBC PKCS#7, key/IV pad-or-cut | ciphers |
| G6 | Blowfish-CBC, key 4-56 bytes, zero-pad on encrypt, multiple-of-8 on decrypt | ciphers |
| G7 | Fixed IVs for the text-key helpers | ciphers |
| G8 | 47-char encryption key derivation | keys |
| G9 | ClientKey defaults and key line | keys |
| G10 | client.keys line parsing (white space, >= 4 fields) | keys |
| G11 | load_file skipping blank/# lines | keys |
| G12 | Lookups last-wins, `any` not indexed, delete + rebuild | keys |
| G13 | next_id (max numeric + 1, 3 digits) | keys |
| G14 | save_file format | keys |
| G15 | generate_raw_key shape | keys |
| G16 | keystore add_key (IP check, ip_str, first-wins lookups, default state) | keystore |
| G17 | keystore parse rules, 127-byte cuts, id_counter, removed keys, error logs | keystore |
| G18 | read from file / platform with pass_empty rules and error texts | keystore |
| G19 | needs_reload and stamps (inode or length) | keystore |
| G20 | reload keeps rcvd/sock/peer for same id + ip | keystore |
| G21 | allowed_ip / id / name / dynamic_id | keystore |
| G22 | socket map add/delete semantics | keystore |
| G23 | is_single_host, snapshot, net_protocol | keystore |
| G24 | platform key service protocol and errors | keystore |
| G25 | create: size limits, counter advance and rollover at 9997 | msgs |
| G26 | create: text layout, MD5, zlib level 9, `!` padding, cmp_size | msgs |
| G27 | create: prefix (dynamic, 15/5-byte copy, zero fill) | msgs |
| G28 | create: cipher per key method | msgs |
| G29 | read: cipher from prefix (manager) or key (client) | msgs |
| G30 | read: compressed format checks and reject reasons | msgs |
| G31 | read: counter verification (Rids / EncKeySrc) | msgs |
| G32 | read: legacy format incl. local counter 0 quirk | msgs |
| G33 | last_reject_reason per thread | msgs |
| G34 | CounterStore load/store/start/sender/on_received flush rule | counters |
| G35 | SenderCounterFile open/store without truncation | counters |
| G36 | parse_counter fscanf semantics | counters |
| G37 | WPK header reader (unused) | signature |
| G38 | Constants: KEYS_REQ, VERSION_REQ, UDP_SOCK, SENDER_COUNTER, 65536/128/53, 127-byte field cut | keystore (`constants`) |

## 4. Vector files

`specs/vectors/siem-crypto/*.json`, same envelope as siem-regex. Byte inputs are `{"hex": ...}` or
`{"repeat_hex": "41", "times": n}`. Generated on Windows; a Linux run gave the same results except OS
error texts (`No such file or directory` vs `The system cannot find the file specified`), the random key
example and the local port number.

| File | Cases |
|---|---|
| hashes.json | 90 |
| ciphers.json | 824 |
| keys.json | 25 |
| keystore.json | 53 |
| msgs.json | 1,132 (creates hold up to 20 reads each; 9,540 read results in all) |
| counters.json | 41 |
| signature.json | 9 |
| **total** | **2,174** top-level cases |
