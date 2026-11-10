# Review: `provigil-crypto` / `provigil-fileop` against `siem-crypto` / `siem-fileop`

Reviewer's record for the clean-room rewrite. Old: `crates/siem-crypto`, `crates/siem-fileop`. New:
`crates/provigil-crypto`, `crates/provigil-fileop`. Specs: `rewrite-siem-crypto.md`, `rewrite-siem-fileop.md`.
Rule: nothing from the old code may be missing; names may differ; extras are fine; behaviour must be the same.

Status words: **same** (same behaviour, same way), **same-m** (same behaviour, different method or
signature), **missing** (not in the new crate), **different** (behaviour differs; see note),
**different (accepted)** (a difference the owner or reviewer accepted). Rows cite files and functions,
not lines. "Fix n" points to section 8 (round 1); "R2-n" points to section 9 (round 2).

How the review was done, both rounds: every old source file read in full and compared with the new one;
the workspace callers compiled against the new crates (section 5); a throwaway differential program ran
old and new on the same random inputs on Windows and on Linux (section 6).

**Summary, round 3 (final, 2026-11-06):** 232 rows (122 crypto, 110 fileop): 183 same, 41 same-m,
8 different (accepted), **0 different, 0 missing**. All 11 round-2 fixes are in and match old (section 1
and 2 rows marked "Round 3"). Differential check on Windows and Linux: only the accepted differences
(F-14, F-15, F-33) remain (section 6.1). Every caller compiles (section 5). Licence check: pass (section
7). Round 3: no fixes left (section 10).

**Summary, round 2 (kept for the record):** 232 rows (122 crypto, 110 fileop): 176 same, 37 same-m, 8 different
(accepted), **11 different, 0 missing** (round 1: 48 different, 29 missing). All 40 round-1 fixes are in;
what is left is edges: one Blowfish error text (C-10), a parameter type (C-27), two unused WPK error kinds
(C-120), four Unix detection edges (F-58, F-75, F-79, F-87), command paths (F-83), and the Windows
detection logger details and two pre-Vista names (F-92, F-94, F-104). 11 round-2 fixes (section 9). No
caller of the old crates loses anything (section 5). Licence check: pass (section 7).

---

## 1. `siem-crypto` -> `provigil-crypto`

### 1.1 `lib.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| C-1 | module list `ciphers, hashes, keys, keystore, msgs, signature` | `lib.rs` | same | Round 2: `signature` back. |
| C-2 | root re-exports of `ClientKey, CryptoMethod, KeyStore, KeyState, create_sec_msg, read_sec_msg, CreateOptions, ReadOptions, SenderCounter` | `lib.rs` | same | |
| C-3 | root re-exports of all cipher and hash functions, `derive_encryption_key`, `CounterStore`, `MsgError`, `ReadResult`, the WPK items | `lib.rs` (globs for ciphers and hashes) | same | Round 2: restored; extra names are fine. |

### 1.2 `ciphers.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| C-4 | `PROVIGIL_AES_IV`, `PROVIGIL_BLOWFISH_IV` | `ciphers.rs` | same | |
| C-5 | `CipherError { InvalidKeyLength{expected,got}, Encryption(String), Decryption(String) }` | same three variants and texts | same | Round 2 (Fix 8). |
| C-6 | `encrypt_aes(key, iv, plaintext) -> Result` | `encrypt_aes(data, key, iv) -> Vec` | same-m | Argument order changed, cannot fail. No outside caller. |
| C-7 | `decrypt_aes(key, iv, ct)` | `decrypt_aes(data, key, iv)` | same-m | Error text `Decryption error: UnpadError` as old. |
| C-8 | `os_aes_str` | same | same | |
| C-9 | `encrypt_blowfish(key, iv, data)` | `encrypt_blowfish(data, key, iv)` | same-m | |
| C-10 | `decrypt_blowfish`: data length checked **before** the key | length first, then key | same | Round 3 (R2-1): `Decryption error: Data length must be multiple of 8` for any bad length, key checked after; error texts identical in section 6. |
| C-11 | `os_bf_str` | same | same | |
| C-12 | `normalize_key_32 / normalize_iv_16 / normalize_iv_8` | `fit::<N>` | same-m | |

### 1.3 `hashes.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| C-13 | `md5_str` | same | same | |
| C-14 | `md5_bytes` | same | same | |
| C-15 | `md5_file` | same | same | Round 2: added. |
| C-16 | `sha1_str` | same | same | |
| C-17 | `sha1_bytes` | same | same | Round 2: added. |
| C-18 | `sha1_file` (4 KiB loop) | `io::copy` | same-m | |
| C-19 | `sha256_str` | same | same | Round 2: added. |
| C-20 | `sha256_bytes` | same | same | Round 2: added. |
| C-21 | `sha256_file` | same | same | Round 2: added. |
| C-22 | `sha512_str` | same | same | Round 2: added. |
| C-23 | `sha512_bytes` | same | same | Round 2: added. |
| C-24 | `sha512_file` | same | same | Round 2: added. |
| C-25 | `hmac_sha1_str(key, text)` | same order | same | Round 2: added. |
| C-26 | `hmac_sha1_file(key, path)` | same order | same | Round 2: added. |
| C-27 | `multi_hash_file(path, max: platform size type)` | same type | same | Round 3 (R2-2). |

### 1.4 `keys.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| C-28 | `CryptoMethod` + `Default = Blowfish` + serde | same | same | |
| C-29 | `ClientKey` + serde | same | same | |
| C-30 | `ClientKey::new` | same | same | |
| C-31 | `ClientKey::to_key_line` | same | same | |
| C-32 | `derive_encryption_key` | same | same | |
| C-33 | `KeyStore { keys, lookups }` | `KeyStore { keys, idx }` | same-m | |
| C-34 | `KeyStore::new` | same | same | |
| C-35 | `load_file` (line reader; non-UTF-8 -> `InvalidData`) | whole file as text | same | Round 2 (Fix 3). |
| C-36 | `save_file` | one write | same-m | |
| C-37 | `parse_line` | same | same | |
| C-38 | `generate_raw_key` | same | same | |
| C-39 | `next_id` | same | same | Only at an id of `u64::MAX` old overflows; not reachable. |
| C-40 | `add_key` | same | same | |
| C-41 | `rebuild_indices` | inline | same-m | |
| C-42 | `delete_key` | same | same | |
| C-43 | `find_by_id` | same | same | |
| C-44 | `find_by_id_mut` | same | same | Round 2: added. |
| C-45 | `find_by_name` | same | same | |
| C-46 | `find_by_ip` | lookup never holds `any` | same-m | |
| C-47 | `len` | same | same | |
| C-48 | `is_empty` | same | same | Round 2: added. |

### 1.5 `keystore.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| C-49 | `KEYSIZE = 128` | same | same | Round 2: added; field cut 127. |
| C-50 | `UDP_SOCK` | same | same | |
| C-51 | `NetProtocol` | same | same | |
| C-52 | `KeyState` | same | same | |
| C-53 | `KeyEntry` | same | same | |
| C-54 | `KeyEntry::is_single_host` | same | same | |
| C-55 | `KeyEntry::snapshot` | same | same | |
| C-56 | `KeySnapshot` | same | same | |
| C-57 | `KeysError` and its texts | same | same | |
| C-58 | `FileStamp` | same | same | |
| C-59 | `KEYS_REQ`, `VERSION_REQ` | same | same | |
| C-60 | `platform_source` | same | same | |
| C-61 | `platform_stamp` | same | same | |
| C-62 | `platform_fetch` | same | same | |
| C-63 | `file_stamp` | same | same | |
| C-64 | `KeyStore` fields | same | same | |
| C-65 | `trunc` | `cut` | same-m | |
| C-66 | `add_key` | same | same | |
| C-67 | `parse` line rules | same | same | |
| C-68 | `parse`: id in the "(1401)" log for a line without name/ip | id as written | same | Round 2 (Fix 6). |
| C-69 | `read`: key service, sleep after every failed attempt | same | same | Round 2 (Fix 7). |
| C-70 | `read`: file path | same | same | |
| C-71 | `needs_reload` | same | same | |
| C-72 | `reload` | same | same | |
| C-73 | `len` | same | same | Round 2: added. |
| C-74 | `is_empty` | same | same | Round 2: added. |
| C-75 | `allowed_ip` | same | same | |
| C-76 | `allowed_id` | same | same | |
| C-77 | `allowed_name` | same | same | Round 2: added. |
| C-78 | `allowed_dynamic_id` | same | same | |
| C-79 | `add_socket` | same | same | |
| C-80 | `delete_socket` | same | same | A bad keyid: old panics, new ignores (accepted). |
| C-81 | `net_protocol` | same | same | |
| C-82 | locks unwrap (panic when poisoned) | poison-tolerant | different (accepted) | Safer. |

### 1.6 `msgs.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| C-83 | `OS_MAXSTR`, `OS_HEADER_SIZE`, `MSG_OVERHEAD` | same | same | |
| C-84 | `KeyState` | same | same | |
| C-85 | `MsgError` variants | same | same | |
| C-86 | `Rejected` text `ReadSecMSG rejected the message: <State>` | `message refused by the envelope check: <State>` | different (accepted) | Allowed by the spec; no caller matches the text. |
| C-87 | `MsgError::key_state` | same | same | |
| C-88 | `atoi`, `atoi_u32` | zero-extended reader | same-m | |
| C-89 | `md5_hex` | same | same | |
| C-90 | `strncmp32_eq` | exact compare | same-m | |
| C-91 | `SenderCounter` + `next` | same | same | |
| C-92 | `CreateOptions` + `Default` | same | same | |
| C-93 | `create_sec_msg(_sized)` | flate2 directly | same | Wire bytes and `cmp_size` identical (section 6). |
| C-94 | `EncryptionFailed(<cipher error text>)` | same | same | Round 2: `Encryption failed: Encryption error: InvalidLength` for a hand-set key outside 4-56 bytes, as old. |
| C-95 | `ReadOptions` | same | same | |
| C-96 | `RejectReason` | same | same | |
| C-97 | `last_reject_reason` | same | same | |
| C-98 | `ReadResult` | same | same | |
| C-99 | read: prefix, cipher choice, `:` check | same | same | |
| C-100 | read: lengths | same | same | |
| C-101 | read: leading `!`, size, clip | same | same | |
| C-102 | read: zlib | `Decompress` | same-m | |
| C-103 | read: checks, counter rules | same | same | |
| C-104 | legacy checksum region | same | same | |
| C-105 | legacy: text end = first NUL from offset 49 | same | same | Round 2 (Fix 9). |
| C-106 | legacy counters | same | same | |
| C-107 | other first byte | same | same | |
| C-108 | `CounterStore`, `new`, `dir` | same | same | |
| C-109 | `load` | same | same | |
| C-110 | `store` | same | same | |
| C-111 | `start_agent`, `load_sender`, `store_sender` | same | same | |
| C-112 | `on_received` (count kept when the write fails) | same | same | Round 2 (Fix 10). |
| C-113 | `CounterStore::remove` | same | same | Round 2: added. |
| C-114 | `SENDER_COUNTER` | same | same | |
| C-115 | `SenderCounterFile::open` | same | same | Round 2 (Fix 11). |
| C-116 | `SenderCounterFile::store` | same | same | |
| C-117 | `parse_counter` (Unicode white space) | same | same | Round 2 (Fix 12). |
| C-118 | unit tests | `tests/vectors.rs` | same-m | |

### 1.7 `signature.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| C-119 | `WPK_MAGIC`, `WPK_SIGNATURE_LEN` | same | same | Round 2: added. |
| C-120 | `SignatureError { Io, InvalidMagic, IncompleteHeader, VerificationFailed }` | same four, same texts | same | Round 3 (R2-3); texts compared in section 6. Still never produced, as in old. |
| C-121 | `WpkHeader` | same fields | same | |
| C-122 | `read_wpk_header` | same | same | Round 2: added; all header shapes identical in section 6. |

Test-only parts of the old crate (`tests/msgs_oracle.rs`, `tools/`) are tooling against the upstream C
code, not product behaviour; not counted.

---

## 2. `siem-fileop` -> `provigil-fileop`

### 2.1 `lib.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| F-1 | `set_logger` | same | same | |
| F-2 | `log_error` / `log_warn` / `log_debug` (debug at level 2) | `log(Lvl, ...)` | same-m | The log line shows the call site's line number (accepted). |
| F-3 | 64 KiB pieces | `piece` | same-m | |
| F-4 | `dirname` | same | same | |
| F-5 | `default_path_offset` | same | same | |
| F-6 | `merge_append_file` | same | same | |
| F-7 | name from an offset inside a character -> empty | same | same | Round 2 (Fix 14). |
| F-8 | `fgets_chunks` | `piece` | same-m | |
| F-9 | `check_binary_file` | same | same | |
| F-10 | header size too big -> 0 | same | same | Round 2 (Fix 15). |
| F-11 | `test_unmerge_files` | same | same | |
| F-12 | `unmerge_files` | same | same | |
| F-13 | `unmerge_files_mode`: read, header loop | same | same | |
| F-14 | `..` refused only with an optdir | always refused | different (accepted) | No caller passes no optdir. |
| F-15 | parents created even for a refused `..` name (can be outside optdir), then stop | refused first, nothing created | different (accepted) | Owner-approved Fix 16. Result, names, files and logs unchanged; only fewer directories (section 4.2 h). |
| F-16 | parent computed with `/` only | same | same | Round 2 (Fix 16). |
| F-17 | temp file, write, rename, names | same | same | |
| F-18 | `wfopen_errno` | same | same | |
| F-19 | `strerror` | same | same | |
| F-20 | `mktemp` | same | same | |
| F-21 | `mkstemp_ex` (Unix) | random source differs | same-m | |
| F-22 | (1128) log names the failed file | same | same | Round 2 (Fix 17). |
| F-23 | `mkstemp_ex` (Windows) template check | same | same | |
| F-24 | 26 names taken -> "returned 22" log | same | same | Round 2 (Fix 17). |
| F-25 | Windows DACL | protected, file-all-access | same-m | |
| F-26 | `rename_ex` (Unix) | same | same | |
| F-27 | `rename_ex` (Windows) | `create_new` | same-m | |
| F-28 | `ref_parent_folder` | same | same | |
| F-29 | `wreaddir` | same | same | |
| F-30 | `copy_file` | same | same | |
| F-31 | `rmdir_ex` | plus Windows directory links | different (accepted) | |
| F-32 | `should_preserve` | inline | same-m | |
| F-33 | protected link to a directory followed | not followed | different (accepted) | Owner decision (Fix 18), new kept. |
| F-34 | unreadable entries skipped; emptied-directory removal failure ignored | same | same | Round 2 (Fix 19). |
| F-35 | path from the lossy name | real path | different (accepted) | |
| F-36 | `cldir_ex_ignore` | same | same | |
| F-37 | `md5_file` | same | same | |
| F-38 | `md5_hex` | same | same | |
| F-39 | `mtime` | same | same | |
| F-40 | tests | `tests/` | same-m | |

### 2.2 `crt.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| F-41 | `TEXT_TRANSLATION` | same | same | |
| F-42 | `text_in` | same | same | |
| F-43 | `text_out` | same | same | |
| F-44 | `read_text` | same | same | |
| F-45 | `write_text` | same | same | |
| F-46 | `TextFile` | same | same | |
| F-47 | `is_network_path`: UNC / redirector targets | same | same | |
| F-48 | non-`\Device\` target -> registry test | same | same | Round 2 (Fix 20). |
| F-49 | first byte before `:` | ASCII letters only | same-m | |
| F-50 | `network_path_executed` | same | same | |

### 2.3 `version_op.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| F-51 | `OSSEC_NAME`, `OSSEC_VERSION` | `PRODUCT_NAME`, `PRODUCT_VERSION` (+ `AGENT_PRODUCT`) | same-m | Round 2: same values. |
| F-52 | `OsInfo` | same | same | |
| F-53 | `UtsName` | same | same | |
| F-54 | `Probe::popen` output whatever the exit status | `System::run`, same rule | same-m | Round 2 (Fix 22). |
| F-55 | live commands through `/bin/sh -c` | direct exec | same-m | |
| F-56 | live `is_file` | `is_executable` = any regular file | same-m | Round 2 (Fix 23). |
| F-57 | 254-byte pieces | `pieces` | same | Round 2 (Fix 24). |
| F-58 | `Strtok` rules | `key_value`, `first_line`, `ID` word | same-m | Round 3 (R2-9): `ID` takes the first word after `=` (spaces skipped), then drops its quotes; `ID= "rhel"` gives `rhel`. |
| F-59 | `unquote` | `release_value` | same-m | |
| F-60 | `w_regexec` | `&str` subject | same-m | |
| F-61 | unset group -> "" | same | same | Round 2 (Fix 26). |
| F-62 | `get_binary_path` rules | same | same | Round 2 (Fix 27). |
| F-63 | `osx_release_name` | same | same | |
| F-64 | `first_match` | same | same-m | |
| F-65 | `atoi` (Darwin codename) | digit prefix parse | same-m | |
| F-66 | os-release first-wins rules | same | same | |
| F-67 | empty value -> panic | empty value | different (accepted) | Spec allowed it. |
| F-68 | centos override, tumbleweed/arch "" | same | same | |
| F-69 | step-2 reset | `OsInfo::default()` | same-m | |
| F-70 | centos-release | same | same | |
| F-71 | fedora-release | same | same | |
| F-72 | redhat-release | same | same | |
| F-73 | arch-release | same | same | |
| F-74 | gentoo pattern (space before the number) | same | same | Round 2 (Fix 28). |
| F-75 | SuSE pattern: anything, then `VERSION = <digits>` (last occurrence on the line) | `last_capture` of `VERSION = <digits>` | same-m | Round 3 (R2-10). |
| F-76 | lsb-release value as written | same | same | Round 2 (Fix 29); empty value gives "" instead of a panic (accepted). |
| F-77 | debian_version, alpine-release | same | same | |
| F-78 | slackware pattern (space before) | same | same | Round 2 (Fix 28). |
| F-79 | Darwin name from `system_profiler` (255-byte pieces, leading `:` skipped, no word -> next line) | same rules | same-m | Round 3 (R2-11); newline kept as old. |
| F-80 | Darwin `sw_vers` empty line -> unset | same | same | Round 2 (Fix 31). |
| F-81 | Darwin codename: number anywhere in `<resolved uname> -r` | same | same | Round 2 (Fix 32). |
| F-82 | SunOS version up to the next space | same | same | Round 2 (Fix 33). |
| F-83 | HP-UX / BSD / ZscalerOS: `<resolved uname> -r`; `system_profiler`, `sw_vers`, `oslevel` resolved through `PATH` | same | same | Round 3 (R2-4). |
| F-84 | ZscalerOS stops at any white space | same | same | Round 2 (Fix 28). |
| F-85 | AIX first line minus last character | same | same | Round 2 (Fix 34); command path see F-83. |
| F-86 | `uname()` fill | same | same | |
| F-87 | minor pattern requires a digit after the first dot | same | same | Round 3 (R2-8). |
| F-88 | patch group optional | same | same | Round 2 (Fix 26). |
| F-89 | darwin version + codename | same | same | |
| F-90 | `getuname_with` | same | same | |
| F-91 | `getuname` once | same | same | |

### 2.4 `win_version.rs`

| # | Old | New | Status | Note |
|---|---|---|---|---|
| F-92 | `Level { Debug1, Debug2, Warn, Error }` | same | same | Round 3 (R2-5). |
| F-93 | `set_logger(Box<dyn Fn(Level, &str) + Send + Sync>)`, first call wins | same | same | Round 2: added. |
| F-94 | 13 messages (section 9, R2-6) | same texts, levels, order and counts | same | Round 3 (R2-6), checked line by line against old; live machine: identical (none emitted) in section 6. |
| F-95 | registry helpers | `Registry` trait + `LiveRegistry` | same-m | |
| F-96 | `get_release_from_build` | same table | same-m | Its "not recognized" message is part of F-94. |
| F-97 | ProductName, cut 1023 | no cut | same-m | Not reachable. |
| F-98 | minor unreadable -> major/minor/build unset | same | same | Round 2 (Fix 36). |
| F-99 | build + `.UBR`, cut 63 | same | same | |
| F-100 | release looked up with the build incl. `.UBR` | same | same | Round 2 (Fix 37). |
| F-101 | 6.2/6.3: build only with `CurrentVersion` | same | same | Round 2 (Fix 36). |
| F-102 | `os_version` | same | same | |
| F-103 | Windows 11 rename | same | same | |
| F-104 | non-6 majors: fixed names, fields, 16-bit build | `legacy_name` | same-m | Round 3 (R2-7): `... XP Professional x64 Edition`; unmatched major 4 has no name. |
| F-105 | `server_2003_name` | inside `legacy_name` | same-m | |
| F-106 | service pack exact values | same | same | Round 2 (Fix 39). |
| F-107 | machine `unknown` stored | same | same | Round 2 (Fix 40). |
| F-108 | node name `unknown` stored | same | same | Round 2 (Fix 40). |
| F-109 | `GetVersionExA` with fallback | `GetVersionExW` | same-m | |
| F-110 | Windows `getuname` | same | same | |

---

## 3. Feature tables from the specs (round 3)

### 3.1 Crypto

| # | Feature | Result |
|---|---|---|
| G1 | Hashes over text, bytes, files | same |
| G2 | HMAC-SHA1 | same |
| G3 | multi-hash with limit | same |
| G4 | Missing-file errors | same |
| G5-G7 | Ciphers, fixed IVs | same (results and error texts) |
| G8-G15 | `keys` store | same |
| G16-G24 | `keystore` table and key service | same |
| G25-G33 | Envelope create/read, reasons, legacy | same |
| G34-G36 | Counters | same |
| G37 | WPK header reader | same |
| G38 | Constants | same |

### 3.2 Fileop

| # | Feature | Result |
|---|---|---|
| H1 | Logger hook | same |
| H2-H7 | Paths, bundle format, merge, binary check, structure test | same |
| H8 | `unmerge_files_mode` | same except the accepted F-14 / F-15 |
| H9-H22 | Directories, files, temp files, errno, text mode, network path | same except accepted F-31 / F-33 / F-35 |
| H23 | Unix detection | same |
| H24 | Version split | same |
| H25 | Unix `getuname` | same |
| H26 | Windows detection | same (logic, messages, `Level`, legacy names) |
| H27-H28 | Windows `getuname`, OSX names | same |

---

## 4. The writer's skips, guesses and round-2 details

### 4.1 Round-1 skips

Every round-1 skip (`md5_file`, `sha1_bytes`, `sha256_*`, `sha512_*`, `hmac_sha1_*`, `multi_hash_file`,
`find_by_id_mut`, `is_empty`, `allowed_name`, `len`, `KEYSIZE`, `CounterStore::remove`, `signature`,
the product constants, the Windows logger hook, the pre-Vista names) is now present. Left over: C-27
(parameter type), C-120 (two error variants), F-92 / F-94 (logger details), F-104 (two names).

### 4.2 Round-2 questions, right or wrong

| Item | Verdict |
|---|---|
| a. Fix 35, messages and levels | **Wrong.** Old has 13 message forms (full list in R2-6); the writer emits 2. Most read failures were error level in old, not debug 1; several texts name something other than the registry value (`Current Version`, `Architecture`, `hostname`); the `ReleaseId` failure has its own sentence; old was silent when `CurrentMajorVersionNumber` or `UBR` were missing (new logs both); the "release not recognized" and "not a recognizable service pack" messages are missing; and the `(1758)` message for the `CurrentVersion` key is logged a different number of times. |
| a. Hook signature | **Right.** `Box<dyn Fn(Level, &str) + Send + Sync>` is exactly old's. The three daemon callers (agentd, execd, winagent) call the crate-root `set_logger(Arc<WLog>)`, not this hook, in old and new alike, so nothing changes for them; a daemon that wants these messages can pass a closure that owns an `Arc<WLog>` (the logger is `Send + Sync`). |
| b. Fix 13, error kinds | **Wrong.** Old has four: `Io` (`I/O error: <e>`), `InvalidMagic` (`Invalid WPK magic number: expected WPK256`), `IncompleteHeader` (`Incomplete WPK signature or header`), `VerificationFailed` (`Signature verification failed`). The last two were never produced. R2-3. |
| c. Fix 38, pre-Vista names | **Mostly right.** `Microsoft Windows 2000`, `Microsoft Windows XP`, `Microsoft Windows Server 2003 R2`, `Microsoft Windows Server 2003`, `Microsoft Windows NT`, `Microsoft Windows 95`, `Microsoft Windows 98`, `Microsoft Windows ME`, `Microsoft Windows` (majors other than 4, 5, 6) are exact, and the 5.2 order (XP x64 test, then R2, then 2003) is right. Wrong: the XP x64 name is `Microsoft Windows XP Professional x64 Edition`, and a major-4 system matching none of the four cases had **no** name in old. R2-7. |
| d. Fix 2, HMAC argument order | **Right**: `(key, text)` and `(key, path)` as old. |
| e. Fix 26, optional groups | **Right for patch, wrong for minor.** Old's patch group is optional (unset -> ""), but old's minor group **requires** a digit after the first dot. R2-8. |
| f. Fixes 30 / 33, trailing newline | **Right** (same as old). No caller sees a change compared with old. Where it happens (a Darwin host whose `System Version:` line ends right after the name, or a SunOS `/etc/release` first line ending right after the version) the description carries a newline into the agent keep-alive (siem-agentd `notify.rs` puts the description on the first line of the message), into the "Version detected" log line and into siem-modulesd's stored OS data, exactly as old did. Real `system_profiler` and `/etc/release` output have more text after the value, so it is rare. |
| g. Fix 32, resolved `uname` only for Darwin | **Wrong.** Old ran `<resolved uname> -r` for HP-UX, BSD and ZscalerOS too, and resolved `system_profiler`, `sw_vers` and `oslevel` through `PATH` before running them. Same program in practice; differs only with a non-executable file of that name earlier in `PATH`. R2-4. |
| h. Fix 16, the files_unix deviation | **Confirmed.** In the differential run (1,198 Linux / 1,319 Windows cases) the only unmerge differences are directories old created for a refused `..` name (for example `x/out` for `..`, `x/evil` for `../evil/x`, `x` for `q/../../out`); results, written files, names and logs are identical. The old second log line ("couldn't create directory") after a `..` refusal could only appear when that directory creation also failed; it no longer appears. Nothing is created or written outside `optdir`. |

### 4.3 Round-1 guesses

Unchanged from round 1: `WLog` debug level right; wrong AES key right; `bin.dat` right; socket and
reload steps right; HP-UX and Fedora patterns right; SuSE, ZscalerOS, Gentoo, Slackware were wrong
(fixed in round 2 except the SuSE last-occurrence edge, F-75); `get_binary_path` fixed;
`DISTRIB_RELEASE=` empty accepted.

---

## 5. Callers across the workspace

Method: a copy of the workspace (under `target/pv-review`, deleted) where `siem-crypto` and `siem-fileop`
were replaced by the new sources under the old package names, then `cargo check --all-targets`.

| Caller | Round 2 and round 3 result |
|---|---|
| siem-api, siem-authd, siem-util, siem-remoted, siem-modulesd, siem-config, siem-execd, siem-logcollector, siem-sca, siem-syscheckd, siem-agentlessd (Windows); tools/loadgen | compile, 0 errors (round 3 re-run on a fresh copy) |
| siem-agentd (incl. example), siem-remoted, siem-crypto, siem-fileop (Linux) | compile (round 3 re-run) |
| siem-winagent | not compiled (needs OpenSSL on Windows; on Linux siem-syscheckd does not build, unrelated to this rewrite). Its uses checked by hand: all present with the same signatures. |

Public items callers lose: **none**. Round 3: the round-2 gaps for hypothetical callers (C-27, C-120,
F-92) are closed.

---

## 6. Differential check beyond the vectors

A throwaway program (outside the repository, deleted after) linked old and new and fed both the same
pseudo-random inputs. Round 2: seed 12345; Windows 11 (not elevated) 1,724,400 comparisons; Linux (WSL
Ubuntu 20.04) 1,724,380 comparisons. New in round 2: all hash functions, `multi_hash_file` limits, HMAC,
the WPK reader (400 headers), cipher **error texts**, hand-set encryption keys, `allowed_name`, `len`,
`is_empty`, `find_by_id_mut`, `KEYSIZE`, counter removal, product constants, more release-file and
command-output shapes, and log texts for temp files and renames.

| Area | Round 1 | Round 2 |
|---|---|---|
| Envelope create (wire bytes, `cmp_size`, counters, errors incl. hand-set keys) | 0 (wire) | **0** |
| Cross reads, hostile reads, 30,000 crafted plaintexts | 384 (legacy, C-105) | **0** |
| Ciphers | results 0 | results 0; error texts: 2,598 Blowfish decrypts of a length not a multiple of 8 (C-10, R2-1) |
| Hashes, HMAC, multi-hash, WPK header | not compared (missing) | **0** |
| `keys` store | 558 (C-35) | **0** |
| `keystore` (parse, lookups incl. by name, sockets, read, reload, logs, key service) | 299 log texts (C-68) | **0** |
| Counters (files, flush rule, removal, `parse_counter`) | 764 | **0** |
| Paths, text mode, merge, binary check, structure test | 160 | **0** |
| Unmerge | F-10 / F-16 / F-15 | only F-15 (accepted: fewer directories for refused `..` names) and F-14 on Linux (accepted) |
| Directories, temp files, rename, errno | 3 | only F-33 on Linux (owner decision) |
| OS detection, 60,000 fake systems (Linux) | many | 296 F-58 (`ID= "rhel"`), 802 F-75 (SuSE last occurrence), 211 F-79 (Darwin empty value / leading `:`), 517 F-87 (minor group); nothing else. On Windows (where patterns never match) only F-58 and F-79. |
| Live system: Linux `getuname`; Windows `get_release_from_build`, `get_win_version`, `getuname`, `is_network_path` (15 paths) | 0 | **0** |

Not exercised by the program (found by reading): C-27 (type only), C-120, F-83 (needs a non-executable
file in `PATH`), F-92, F-94, F-104 (failing registry reads and pre-Vista systems are not on this machine).

---

### 6.1 Round 3

Same program and inputs as round 2 (seed 12345), extended with the round-2 edge cases (`ID= "rhel"`,
`ID="two words"`, several `VERSION =` on one SuSE line, empty / space-only / `:`-prefixed
`System Version` lines, a key without a colon, `oslevel` and `system_profiler` found in `PATH`), the WPK
error texts, and on Windows a capture of the detection messages through both crates' logger hooks.

| Platform | Comparisons | Mismatches | Outside the accepted list |
|---|---|---|---|
| Windows 11 (not elevated) | 1,724,402 | 1,319 unmerge directory trees (F-15, accepted) | **0** |
| Linux (WSL Ubuntu 20.04) | 1,724,381 | 1,198 unmerge directory trees (F-15), 2 no-optdir cases (F-14), 1 protected link (F-33), all accepted | **0** |

Everything else 0 on both: envelope, crafted and hostile reads, ciphers including error texts, all
hashes, HMAC, multi-hash, WPK headers and error texts, keys, keystore and its logs, key service, counters,
paths, bundles, directories, temp files, 60,000 fake OS-detection systems (old panicked on none), live
Linux `getuname`, and on Windows `get_win_version`, `getuname`, `is_network_path` and the detection
messages (none are emitted on this machine by either crate). The failing-registry and pre-Vista paths of
F-94 / F-104 cannot be produced here and were checked against old by reading (section 1-2 rows).

---

## 7. Licence evidence

- **Comments:** none of the old comments is in the new code, in either round. New comments describe
  behaviour in the spec's or the review's words; no upstream function or file names.
- **Identical lines:** only spec-prescribed signatures and texts, product output texts (log messages,
  OS names, error texts) and obvious one-liners. Round 1 noted two one-liners and the private map names;
  nothing new of concern in round 2. The Windows code is now structured differently from old (a
  `Registry` trait and a pure `win_version_with`).
- **Result: pass.**

### 7.1 Dependencies

| Crate | Dependencies |
|---|---|
| provigil-crypto | aes 0.8, cbc 0.1 (alloc), blowfish 0.9, md-5 0.10, sha1 0.10, sha2 0.10, hmac 0.12 (std), hex 0.4, rand 0.8, flate2 1, serde 1, thiserror 2, tracing 0.1, **siem-regex** (path); dev: serde_json |
| provigil-fileop | md-5 0.10, libc 0.2, tracing 0.1, **siem-log** (path); Windows: windows-sys 0.59 (Foundation, Security, Security_Authorization, Storage_FileSystem, System_Registry, System_SystemInformation, UI_WindowsAndMessaging); dev: serde_json, hex |

- **siem-regex**: used for `is_valid_ip`, `ip_found`, `OsIp`, `IpNet` only; `provigil-regex` exports the
  same four, so provigil-crypto can switch once that rewrite is accepted.
- **siem-log**: used for `WLog` (in `set_logger`), `WLog::is_debug`, `WLog::log_at`, `siem_log::Level`.
  siem-log calls itself a port of the upstream logging code, so it needs the same clean-room treatment;
  the `set_logger` signature in its three callers changes together with it.

---

## 8. Fixes for the writer (round 1)

All 40 applied in round 2; kept for the record (numbers are referenced above).

1 root re-exports; 2 hash functions, HMAC, multi-hash; 3 non-UTF-8 client.keys -> `InvalidData`;
4 small lookups and counter removal; 5 `KEYSIZE`; 6 id as written in the "(1401)" log; 7 sleep after the
30th failed key-service attempt; 8 cipher error texts; 9 legacy text end from offset 49; 10 count kept
after a failed counter write; 11 sender counter file open rules; 12 Unicode white space in
`parse_counter`; 13 WPK header reader; 14 empty bundle name inside a character; 15 oversized bundle size
counts as 0; 16 refuse `..` before creating anything, `/`-only parent; 17 temp-file log texts;
18 protected link (owner decision: keep new); 19 directory cleaning errors; 20 network drive registry
fallback; 21 product constants; 22 command output whatever the exit status; 23 any regular file in
`PATH`; 24 254-byte pieces; 25 key/value splitting; 26 unset groups give ""; 27 `get_binary_path` rules;
28 version patterns; 29 lsb value as written; 30 Darwin name; 31 Darwin empty `sw_vers`; 32 Darwin
codename; 33 SunOS version; 34 AIX first line; 35 Windows detection log; 36 registry gaps; 37 release from
build with UBR; 38 pre-Vista names; 39 exact service-pack values; 40 `unknown` machine / node name.

---

## 9. Fixes for the writer, round 2

Behaviour descriptions only. Message texts and names below are product output.

**R2-1. Blowfish decryption error order and text.** Check the data length before the key. Data whose
length is not a multiple of 8 fails with `Decryption error: Data length must be multiple of 8`, whatever
the key; only data of a valid length with a bad key gives `Decryption error: InvalidLength`.

**R2-2. Multi-hash limit type.** The size limit of `multi_hash_file` takes the platform's size type again
(as before), not a 64-bit number. Behaviour unchanged.

**R2-3. WPK error kinds.** Add the two never-produced kinds: "incomplete header" with the text
`Incomplete WPK signature or header`, and "verification failed" with the text
`Signature verification failed`.

**R2-4. Commands run through their `PATH` location.** Like the `uname` command itself, resolve
`system_profiler`, `sw_vers` and `oslevel` through the same `PATH` lookup before running them (full path
when found, plain name otherwise), and run `<resolved uname> -r` for HP-UX, BSD and ZscalerOS as well,
not only for Darwin.

**R2-5. Logger level name.** The warning level of the Windows detection logger is named `Warn`.

**R2-6. Windows detection messages.** Exactly these, in the order detection runs (E = error, D1 =
debug 1, D2 = debug 2; `<n>` is the registry error code; the four key paths as written in the spec):
1. E `(1758): Unable to open registry key: '<key>'.` when one of the four keys cannot be opened. For
   `SOFTWARE\Microsoft\Windows NT\CurrentVersion` it appears exactly twice per detection when the key
   cannot be opened (once for the product name, once for the version values), and no "Error reading"
   message follows for that key. For the other three keys, once.
2. E `Error reading 'ProductName' from Windows registry. (Error <n>)`
3. No message when `CurrentMajorVersionNumber` is missing (it only selects the 6.2/6.3 path).
4. E `Error reading 'CurrentMinorVersionNumber' from Windows registry. (Error <n>)`
5. E `Error reading 'CurrentBuildNumber' from Windows registry. (Error <n>)` (both paths).
6. No message when `UBR` is missing.
7. D1 `Could not read the 'ReleaseId' key from Windows registry. (Error <n>)`
8. D1 `The release associated with the <build> build is not recognized.` whenever the release table
   is consulted with a known build that is not in it (`<build>` as looked up, including `.<UBR>`); no
   message when there is no build.
9. E `Error reading 'Current Version' from Windows registry. (Error <n>)` (6.2/6.3 path; with the space).
10. E `Error reading 'CSDVersion' from Windows registry. (Error <n>)`
11. D2 `The value of CSDVersion is not a recognizable service pack.: <n>.` (`<n>` = the value read).
12. E `Error reading 'Architecture' from Windows registry. (Error <n>)`
13. E `Error reading 'hostname' from Windows registry. (Error <n>)`
No other messages.

**R2-7. Pre-Vista names.** The 5.2 workstation-on-x64 name is `Microsoft Windows XP Professional x64
Edition`. A major-4 system that is neither NT nor 95 / 98 / ME (by platform and minor) has no name (the
description then falls back to `Microsoft Windows`, as before).

**R2-8. Minor version group.** The minor number is taken only when at least one digit follows the first
dot; otherwise it stays unset (only the patch group is optional).

**R2-9. os-release `ID`.** Take the first word after the `=` (leading spaces skipped, ending at a space
or newline), then drop quotes from that word (a leading quote removed, text up to the next quote kept).
`ID= "rhel"` gives `rhel`.

**R2-10. SuSE version.** When a line holds several `VERSION = <n>`, the last one counts.

**R2-11. Darwin name edges.** Read `system_profiler` output in pieces of 255 bytes. Before taking the key,
skip leading `:` characters (`:System Version: z` gives `z`). When the text after the colon has no word
(only spaces, or nothing, and no newline), the line gives no name and the search goes on to later lines.

---

## 10. Fixes for the writer, round 3

Round 3: no fixes left.

All 11 round-2 fixes were checked against old code (rows C-10, C-27, C-120, F-58, F-75, F-79, F-83,
F-87, F-92, F-94, F-104) and match. The only remaining differences are the accepted ones (C-82, C-86,
F-14, F-15, F-31, F-33, F-35, F-67). Licence re-check (round 3): no old comments or upstream names in the
new sources; identical lines are still only spec-given names and texts and obvious one-liners; pass.
