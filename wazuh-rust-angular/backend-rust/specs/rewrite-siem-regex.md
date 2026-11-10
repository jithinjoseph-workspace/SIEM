# Rewrite spec: `siem-regex`

Clean-room description of the pattern-matching crate. It says **what** the crate does, never how the
old one does it. The writer must not open the old crate (`crates/siem-regex/`) or `old-code/`.

The test vectors in `specs/vectors/siem-regex/` were produced by running the old crate. They are the
definition of correct behaviour: the new crate passes when it gives the same answer for every case.
Where this text and a vector disagree, the vector wins (and tell the reader, so the text gets fixed).

Library: the only external engine needed is PCRE2 for the `Pcre2` expression type. Use the `pcre2`
crate (MIT/Unlicense, PCRE2 itself is BSD). The two in-house matchers (`OsRegex`, `OsMatch`) and the IP
helpers are small and must be written by hand from this description; do not use the `regex` crate for
them (its semantics differ).

---

## 1. Public interface

Paths below are the paths callers write today; keep them all (root re-exports **and** module paths).

### 1.1 Used by other crates (must exist, same names and signatures)

| # | Item | Signature / shape | Used by (files) |
|---|---|---|---|
| R1 | `OS_RETURN_SUBSTRING` | `pub const u32 = 128` (root) | siem-analysisd `decoders.rs`, `plugins.rs`; siem-sca `check.rs` |
| R2 | `OS_CASE_SENSITIVE` | `pub const u32 = 256` (root) | siem-syscheckd `port/rootcheck.rs` |
| R3 | `OS_PATTERN_MAXSIZE` | `pub const usize = 20480` (root) | siem-config `lib.rs` |
| R4 | `OsRegex` | `#[derive(Debug, Clone)] pub struct`, `Send + Sync` | siem-analysisd `rules.rs`, `ruleset.rs`, `plugins.rs`, `decoders.rs` |
| R5 | `OsRegex::compile` | `fn compile(pattern: &str, flags: u32) -> Result<OsRegex, RegexError>` | same |
| R6 | `OsRegex::execute_bytes` | `fn execute_bytes(&self, s: &[u8]) -> Option<RegexMatch>` | siem-analysisd `engine.rs`, `plugins.rs` |
| R7 | `OsRegex::is_match` | `fn is_match(&self, s: &str) -> bool` | siem-analysisd `ruleset.rs`, `rules.rs` |
| R8 | `OsRegex::has_sub_strings` | `fn has_sub_strings(&self) -> bool` | siem-analysisd `decoders.rs` |
| R9 | `OsRegex::raw` | `fn raw(&self) -> &str` | siem-analysisd `config_json.rs` |
| R10 | `RegexMatch` | `pub struct { pub end: isize, pub sub_strings: Vec<String>, pub sub_bytes: Vec<Vec<u8>> }`, derives `Debug, Clone, PartialEq, Eq` | siem-analysisd `plugins.rs` (`end`, `sub_bytes`), `engine.rs` (`sub_bytes`) |
| R11 | `RegexError` | `#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)] pub enum` with `MaxSize = 3`, `BadRegex = 6`, `BadParenthesis = 7` (values castable with `as i32`) | returned by R5, R14, `Expression::compile`; callers only test `is_err()` |
| R12 | `os_regex` | `fn os_regex(pattern: &str, s: &str) -> bool` | siem-analysisd `rules.rs`; siem-config `active_response.rs`; siem-logcollector `collector.rs`; siem-sca `check.rs`; siem-syscheckd `port/rootcheck.rs` |
| R13 | `OsMatch` | `#[derive(Debug, Clone)] pub struct`, `Send + Sync` | siem-analysisd `ar.rs`, `lists.rs`, `rules.rs`, `output.rs`; siem-config `global.rs`; siem-syscheckd `port/config.rs`, `port/create_db.rs`, `port/rootcheck.rs` |
| R14 | `OsMatch::compile` | `fn compile(pattern: &str, flags: u32) -> Result<OsMatch, RegexError>` | same |
| R15 | `OsMatch::is_match_bytes` | `fn is_match_bytes(&self, s: &[u8]) -> bool` | siem-analysisd `ar.rs`, `lists.rs`, `output.rs`; siem-syscheckd `port/create_db.rs`, `port/rootcheck.rs` |
| R16 | `OsMatch::is_match` | `fn is_match(&self, s: &str) -> bool` | siem-analysisd `rules.rs` |
| R17 | `OsMatch::raw` | `fn raw(&self) -> &str` | siem-analysisd `config_json.rs`, `rules.rs`; siem-syscheckd `port/config.rs`, `port/create_db.rs`, `port/rootcheck.rs` |
| R18 | `OsMatch::patterns` | `fn patterns(&self) -> Vec<&[u8]>` | siem-analysisd `config_json.rs` |
| R19 | `os_match2` | `fn os_match2(pattern: &str, s: &str) -> bool` | siem-config `lib.rs`; siem-sca `check.rs`; siem-syscheckd `port/rootcheck.rs` |
| R20 | `os_word_match` | `fn os_word_match(pattern: &str, s: &str) -> bool` | siem-analysisd `rules.rs` |
| R21 | `ExpType` | `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum { OsRegex, OsMatch, String, OsIpArray, Pcre2 }`; root and `expression::ExpType` | siem-analysisd, siem-config `localfile.rs`, siem-sca `check.rs`, `registry.rs`, `wm.rs` |
| R22 | `Expression` | `#[derive(Debug, Clone)] pub struct { pub kind: ExpressionKind, pub negate: bool }`; root and `expression::Expression` | siem-analysisd `rules.rs`, `decoders.rs`, `engine.rs`, `config_json.rs`; siem-config `localfile.rs`; siem-logcollector `collector.rs`; siem-sca `check.rs` |
| R23 | `Expression::compile` | `fn compile(t: ExpType, pattern: &str, flags: u32) -> Result<Expression, ExpressionError>` | same |
| R24 | `Expression::add_osip` | `fn add_osip(this: &mut Option<Expression>, ip: &str) -> Result<(), ExpressionError>` | siem-analysisd `rules.rs` |
| R25 | `Expression::match_bytes` | `fn match_bytes(&self, s: &[u8], captures: Option<&mut Vec<Vec<u8>>>) -> (bool, Option<isize>)` | siem-analysisd `decoders.rs`, `engine.rs`; siem-logcollector `collector.rs`; siem-sca `check.rs` |
| R26 | `Expression::pattern` | `fn pattern(&self) -> Option<&str>` | siem-analysisd `config_json.rs`; siem-logcollector `collector.rs` |
| R27 | `Expression::type_str` | `fn type_str(&self) -> Option<&'static str>` | siem-analysisd `config_json.rs` |
| R28 | `ExpressionKind` | `#[derive(Debug, Clone)] pub enum { OsRegex(OsRegex), OsMatch(OsMatch), String(String), OsIpArray(Vec<OsIp>), Pcre2(Pcre2Code) }` | siem-analysisd `decoders.rs` (matches `OsRegex`), `config_json.rs` (matches `OsIpArray`) |
| R29 | `ExpressionError` | `#[derive(Debug, thiserror::Error)] pub enum { Regex(RegexError) /* From */, Pcre2(String), InvalidIp(String) }` | error type of R23/R24; callers only test `is_err()` |
| R30 | `Pcre2Code` | `#[derive(Debug, Clone)] pub struct` (payload of the `Pcre2` variant) | named only through R28 |
| R31 | `expression::OSREGEX_STR`, `expression::PCRE2_STR` | `pub const &str = "osregex"`, `"pcre2"` | siem-sca `wm.rs` |
| R32 | `OsIp` | `#[derive(Debug, Clone, PartialEq, Eq)] pub struct { pub ip: String, pub net: IpNet, pub is_ipv6: bool }` | siem-analysisd `ar.rs`, `config_json.rs`; siem-config `global.rs`, `remote.rs`; siem-modulesd `database.rs`; siem-crypto keystore |
| R33 | `IpNet` | `#[derive(Debug, Clone, PartialEq, Eq)] pub enum { V4 { ip_address: u32, netmask: u32 }, V6 { ip_address: [u8; 16], netmask: [u8; 16] } }` | siem-crypto keystore (single-host test, comparisons) |
| R34 | `is_valid_ip` | `fn is_valid_ip(text: &str) -> (u32, Option<OsIp>)` (root) | siem-agentd `enrollment.rs`; siem-config `client.rs`, `global.rs`, `remote.rs`; siem-ipc `os_net.rs`, `os_net_win.rs`; siem-crypto keystore |
| R35 | `ip_found` | `fn ip_found(target: &str, entry: &OsIp) -> bool` (root) | siem-crypto keystore |
| R36 | `ip_found_list` | `fn ip_found_list(target: &str, list: &[OsIp]) -> bool` (root) | siem-analysisd `ar.rs`; siem-remoted `syslog.rs`; `Expression` |
| R37 | `os_ip::get_ipv4_from_ipv6` | `fn (text: &str) -> Option<String>` | siem-ipc `os_net.rs`, `os_net_win.rs` |
| R38 | `os_ip::expand_ipv6` | `fn (text: &str) -> Option<String>` | siem-config `client.rs`, `remote.rs`; siem-ipc; siem-logcollector `win.rs` |
| R39 | `os_ip::atoi` | `fn (text: &str) -> i32` | siem-modulesd `database.rs`, `wdb.rs` |
| R40 | `os_ip::cidr_to_str` | `fn (entry: &OsIp) -> Option<String>` | siem-modulesd `database.rs` |
| R41 | `str_is_num` | `fn str_is_num(s: &str) -> bool` (root) | siem-agentlessd, siem-analysisd, siem-config, siem-syscheckd (many) |
| R42 | `str_break` | `fn str_break(sep: char, s: &str, size: usize) -> Option<Vec<String>>` (root and `strings::`) | siem-agentd, siem-analysisd, siem-config, siem-execd, siem-remoted `manager.rs`, siem-syscheckd |
| R43 | `strings::str_break_bytes` | `fn (sep: u8, s: &[u8], size: usize) -> Option<Vec<Vec<u8>>>` | siem-sca `check.rs`, `sched.rs` |
| R44 | `is_valid_hostname_char` | `fn (c: u8) -> bool` (root) | siem-analysisd `plugins.rs` |
| R45 | `maps::HOSTNAME_MAP` | `pub const [u8; 256]` | siem-analysisd `event.rs` (tests `== 1`) |

Module names that must exist: `expression`, `maps`, `os_ip`, `os_match`, `os_regex`, `strings`.

### 1.2 Public today but used by nobody outside the crate (may be dropped; listed, not dropped silently)

| # | Item | Why it can go |
|---|---|---|
| U1 | `maps::CHARMAP` | internal case-folding table; no caller. Needed behaviour is "ASCII A-Z fold to a-z". |
| U2 | `maps::REGEXMAP` | internal class table; behaviour described in 2.3 and `tables.json`. |
| U3 | `expression::OSMATCH_STR`, `expression::STRING_STR` | no caller names them (their text values are still returned by `type_str`). |
| U4 | `ExpType::from_attr` | no caller (callers parse the attribute themselves). |
| U5 | `Expression::exp_type`, `Expression::matches`, `Expression::is_match` | no caller; callers use `match_bytes` and apply `negate` themselves. `matches` vectors are still in `expression.json` if you keep it. |
| U6 | `ExpressionMatch` struct | only returned by U5. |
| U7 | `Pcre2Code` fields `code`, `raw_pattern` | no caller reads them. |
| U8 | `RegexError::{PatternNull = 2, OutOfMemory = 4, StrNull = 5}` | never produced. |
| U9 | `OsMatch::is_negated` | no caller. |
| U10 | `OsRegex::execute(&str)` | no caller (same result as `execute_bytes` on the UTF-8 bytes). |
| U11 | `RegexMatch::sub_strings` field | no caller reads it (it is always the lossy UTF-8 text of `sub_bytes`). Keep it if cheap; it is part of `PartialEq`. |
| U12 | `OsIp::negated()` | no caller. |
| U13 | `OsIp::is_ipv6` field | no caller reads it. |
| U14 | `str_starts_with`, `str_how_closed_match` | no caller (siem-analysisd has its own). Vectors kept in `strings.json`. |

Count: 45 used items (R1-R45, counting each method), 14 unused groups (about 22 single items).

---

## 2. Behaviour

General rules for both hand-written matchers:
- Subjects are byte strings. A subject behaves as if it ends at its first NUL byte (bytes after a NUL are
  never looked at) unless a function says otherwise.
- "Case-insensitive" always means ASCII only: `A`-`Z` equal `a`-`z`; every other byte compares as itself.
- Bytes 0x80-0xFF in a pattern are **never** matched by a literal comparison against a subject byte in the
  places marked "signed-byte rule" below (an inherited quirk the stock rules are tuned to).

### 2.1 `OsRegex` - the decoder/rule regular-expression dialect

**Compile** (`OsRegex::compile(pattern, flags)`):
- Pattern longer than 20480 **bytes** -> `MaxSize`. Exactly 20480 is accepted.
- Escapes (backslash + one character). Valid ones and what they match (one subject byte each):
  `\d` digits; `\w` letters, digits, `-`, `_`, `@`; `\s` the space byte only (not tab, not newline);
  `\p` punctuation: ``! " # $ % & ' ( ) * + , - .`` and ``: ; < = > ?`` and `[`, `]`, `{`, `|`, `}`
  (not `/`, `@`, `\`, `^`, `_`, `` ` ``, `~`); `\W` everything except letters, digits, `-`, `_`, `@`;
  `\D` everything except digits; `\S` everything except the space byte; `\.` any byte; `\t` the tab byte;
  `\$` a literal `$`; `\(` a literal `(`; `\)` a literal `)`; `\\` a literal backslash; `\|` a literal
  `|`; `\<` a literal `<`. The exact byte sets are in `tables.json` (`member_bytes` per escape; byte 0 is
  listed for some classes but a NUL never reaches the matcher).
  Any other character after a backslash, or a backslash at the very end, -> `BadRegex`.
- `+` or `*` directly after an escape make it repeat (one-or-more / zero-or-more). After a literal
  character, `+` and `*` are ordinary literal characters.
- `(` opens a capture group and `)` closes it. Only one level: a second `(` inside a group, a `)` with no
  open group, a group left open at the end, or a `|` inside a group -> `BadParenthesis`. (Escaped
  parentheses do not count.)
- `|` (unescaped) separates alternatives. Empty alternatives are allowed.
- In each alternative a leading `^` anchors it to the start of the subject and a trailing unescaped `$`
  anchors it to the end; anywhere else `^` and `$` are literal characters. An alternative that is just
  `^` or `^$` or `$` is an empty pattern with those anchors.
- Without `OS_CASE_SENSITIVE`, literal pattern characters are folded to lower case. With it they are kept
  as written. The subject is **always** folded to lower case before a literal comparison, so with
  `OS_CASE_SENSITIVE` an upper-case literal can never match (vector: pattern `ABC`, flags 256, subject
  `ABC` -> no match). Class escapes are not affected by the flag.
- Literal bytes 0x80-0xFF in the pattern never match (signed-byte rule): `é` never matches `é`.
- `has_sub_strings()` is true only when `OS_RETURN_SUBSTRING` was given **and** the pattern has at least
  one `)`. Captures are only produced in that case.
- `raw()` returns the pattern exactly as given.

**Execute** (`execute_bytes(subject)` -> `None` for no match, else `RegexMatch`):
- Alternatives are tried left to right; the first that matches gives the result.
- `end` is the offset of the **last subject byte the matcher consumed**, not one past it. It can be `-1`
  when the alternative starts with a `\x*` element that matched nothing at offset 0 (1,467 vectors).
- `sub_bytes` lists the text of each `( )` group in pattern order (empty groups give empty entries);
  `sub_strings` is the same converted with lossy UTF-8. Both are empty without `has_sub_strings()`.
- A group whose recorded end lies before its start makes the whole execute return `None`.
- Matching is a single left-to-right scan, not a backtracking regex: an unanchored alternative may start
  at any offset; repeated escapes stop consuming as soon as the next pattern element can match the
  current byte (shortest, not longest), with a small fixed number of retry points (four) to continue a
  repetition when what follows fails; when an attempt fails the scan restarts just after the byte where
  that attempt started. An alternative anchored with `^` fails as soon as the first attempt fails. A
  trailing `$` requires the attempt to end exactly at the end of the subject. A pattern whose remaining
  elements are only zero-or-more escapes (and group marks) succeeds at the end of the subject.
  Consequences visible in the vectors: `\w+` on `abc` gives `end 0`; `\S(\s*)$` matches `abc` without
  `OS_RETURN_SUBSTRING` but not with it; `(\w*)x` on `x  123` gives `end 0` and one empty capture.
- The exact order of these steps decides `end` and the captures in corner cases and cannot be stated
  shorter than the vectors: `osregex.json` (74,482 cases: special patterns x flags x subjects, 35k
  cases from the stock ruleset patterns and test logs, 48k fuzzed) is the definition. The new engine must
  reproduce every case, including the odd ones.
- `is_match(s)` is `execute_bytes(s.as_bytes()).is_some()`.

`os_regex(pattern, s)`: compile with flags 0, then `is_match`; a compile error gives `false`.

### 2.2 `OsMatch` - the plain match dialect

**Compile** (`OsMatch::compile(pattern, flags)`):
- Longer than 20480 bytes -> `MaxSize` (the length includes a leading `!`). No other compile error.
- One leading `!` negates the whole result (only the first `!`; a second `!` is a literal).
- Without `OS_CASE_SENSITIVE` the pattern is folded to lower case (ASCII).
- The rest is split on every `|` (no escaping). Each piece:
  - starts with `^` and ends with `$` (and is longer than just `^`) -> whole subject must equal the text
    between them;
  - is empty -> always matches;
  - ends with `$` -> subject must end with the text before `$`;
  - starts with `^` -> subject must start with the text after `^` (`^` alone always matches);
  - otherwise -> subject must contain the text.
- `patterns()` returns the pieces with the anchors removed (after folding), in order; `raw()` returns
  the pattern as given (including any `!`).

**Match** (`is_match_bytes(subject)`; `is_match(&str)` is the same on the UTF-8 bytes): subject cut at
its first NUL. Result is true if any piece matches, inverted when negated (so `!` alone never matches,
`!a` matches everything that has no `a`).
- "contains": compares the folded pattern piece with the subject folded to lower case; signed-byte rule
  applies (a piece with bytes >= 0x80 never matches); with `OS_CASE_SENSITIVE` an upper-case piece
  never matches. A subject shorter than the piece never matches.
- "starts with", "ends with", "equals": ASCII case-insensitive comparison on both sides, bytes >= 0x80
  compared as they are (so `^é` matches `é`), and `OS_CASE_SENSITIVE` has no effect.

`os_match2(pattern, s)`: compile with flags 0 then match; a compile error gives `false`.

Vectors: `osmatch.json` (36,439 cases).

### 2.3 `os_word_match(pattern, s)`

Case-insensitive (ASCII) search with `|` alternatives and a `^` prefix anchor; no `$`, no `!`, no flags.
- Empty pattern -> false.
- Each `|`-separated piece is tried in order; true at the first piece that matches.
- A piece starting with `^` matches when the subject starts with the rest of the piece (compare the piece
  length minus one bytes, case-insensitive; `^` alone matches anything).
- Otherwise the piece must occur somewhere in the subject (case-insensitive). An empty subject never
  matches a non-empty, non-`^` piece.
- The subject ends at its first NUL (the `&str` may contain one).
- Edge cases with empty pieces (`a||b`, trailing `|`) follow the vectors.

Vectors: `word_match_and_oneshot.json` (`fn = os_word_match`; also `os_regex` and `os_match2`).

### 2.4 `Expression`

A tagged matcher chosen by a rule/decoder `type` attribute.

`compile(t, pattern, flags)`:
- `OsMatch` / `OsRegex`: compile as above with `flags`; errors become `ExpressionError::Regex(code)`.
- `Pcre2`: compile with PCRE2 default options (no UTF mode, byte semantics, no JIT needed); `flags`
  ignored; a compile error becomes `ExpressionError::Pcre2(message)` (message text free).
- `String`: stores the pattern; never fails.
- `OsIpArray`: parse the pattern with `is_valid_ip`; code 0 -> `ExpressionError::InvalidIp(pattern)`;
  otherwise a one-entry IP list.
- `negate` starts `false`.

`match_bytes(subject, captures)` (does **not** apply `negate`; callers do). The subject is cut at its
first NUL first.
- `OsMatch`: `(is_match_bytes, None)`; `captures` untouched.
- `OsRegex`: if `captures` is given it is first cleared, then filled with the match's `sub_bytes` when
  it matched. Returns `(true, Some(end))` or `(false, None)`.
- `Pcre2`: on a match `end` = (offset just past the whole match) - 1 (so an empty match at 0 gives
  `-1`). Captures = groups 1..k where k is the highest-numbered group that took part; groups that did
  not take part give empty entries. `captures` is replaced only when k >= 1; with no group it keeps its
  old content (vector: prior `PRIOR` stays). No match: `(false, None)`, `captures` untouched.
- `String`: `(pattern bytes == subject bytes, None)`.
- `OsIpArray`: `(ip_found_list(lossy text of subject, list), None)`.

`add_osip(this, ip)`:
- `ip` invalid (code 0) -> sets `*this = None` (any list built so far is dropped) and returns
  `Err(InvalidIp(ip))`.
- `this` holds an IP list -> append. `this` is `None` or holds any other kind -> replaced by a new
  one-entry IP list (with `negate = false`).

`pattern()`: `OsRegex`/`OsMatch` -> their raw pattern; `Pcre2` -> the pattern; `String` -> the string;
`OsIpArray` -> `None`. `type_str()`: `"osmatch"`, `"osregex"`, `"pcre2"`, `"string"`, `None` for IP
lists.

Vectors: `expression.json` (1,830 cases: compile result, `pattern_fn`, `type_str`, per subject
`match_bytes` with captures pre-filled with `["PRIOR"]`, and the U5 `matches` result; `add_osip` step
sequences).

### 2.5 IP addresses (`os_ip`)

`is_valid_ip(text)` returns `(code, entry)`: 0 invalid (`None`), 1 single address, 2 network (CIDR or
netmask) or `any`.
- One leading `!` is ignored for parsing and is **not** kept in the stored text.
- Stored text (`OsIp.ip`): the first 46 characters of the text after `!`; if that text is
  `::ffff:<IPv4>[/mask]` (the four `f` in any case) the stored text becomes the IPv4 part with its
  mask. IPv6 results are then rewritten to the expanded form (see `expand_ipv6`).
- `any` (exactly, lower case) -> code 2, `IpNet::V6` with all-zero address and mask, `is_ipv6 = false`,
  stored text `any`.
- IPv4: optional `::ffff:` prefix, dotted quad with each part 0-255 and no leading zeros (`0` itself is
  fine), optional `/prefix` (0-32, written as `0`-`9`, `10`-`29`, `30`-`32`; `01` is invalid) or
  `/a.b.c.d` netmask (any four valid octets, contiguous or not). Code 2 when a mask is present.
  `IpNet::V4`: `netmask` = prefix ones (all ones without a mask), `ip_address` = address AND netmask.
  Both `u32` hold the four bytes in network order in memory (`to_ne_bytes()` gives `[a, b, c, d]`);
  vectors show them as hex in that order.
- IPv6: eight groups, or a `::`-compressed form, with an optional `/prefix` 0-128 (`0`-`99` with at most
  two digits, `100`-`119`, `120`-`128`; `064` invalid). No zone (`%eth0`), no embedded IPv4 except the
  `::ffff:` case above (`::1.2.3.4` is invalid), `::` alone is valid but `::/0` is invalid. The address
  must also be a valid IPv6 address. `IpNet::V6`: netmask = prefix ones over 16 bytes (all ones without
  a prefix), address = address AND netmask, `is_ipv6 = true`, code 2 with a prefix.
- Everything else -> `(0, None)`.

`ip_found(target, entry)`: target parsed as strict dotted IPv4, else as IPv6 (standard textual forms,
`::ffff:a.b.c.d` included); unparsable -> false. "Inside" means: v4 target and v4 net: target AND mask
== address; v6 and v6: same per byte; v4 target and a v6 net: inside only if the first 4 bytes of the
net's mask and address are all zero (true for `any` and `/0` nets); v6 target and v4 net: never.
Result: inside -> true, outside -> false; reversed when the entry's stored text starts with `!`
(only hand-built entries can have that).

`ip_found_list(target, list)`: unparsable target -> false. Walk the list; once an entry whose text
starts with `!` is seen, the "found" answer becomes false for the rest of the walk (sticky). The first
entry that contains the target returns the current answer. No entry contains it -> `true` if a `!` entry
was seen, else `false`.

`get_ipv4_from_ipv6(text)`: `text` must be exactly `::ffff:` (any case) + valid IPv4 + optional
`/prefix` or `/netmask` as in `is_valid_ip`; returns the part after `::ffff:`. Otherwise `None`.

`expand_ipv6(text)`: split on `/` ignoring empty pieces; the first piece must parse as IPv6 (standard
forms, embedded IPv4 allowed) else `None`; a second piece is read with `atoi` and must be 0-128 else
`None`; later pieces ignored. Output: 8 groups of 4 upper-case hex digits joined by `:`, plus
`/<prefix>` when the prefix is not 0.

`atoi(text)`: C `atoi`: skip leading white space, optional sign, then digits until the first non-digit;
nothing -> 0; clamps to `i32` range (`99999999999` -> 2147483647).

`cidr_to_str(entry)`:
- stored text contains `:` and net is v6 -> count the one bits of the mask; fewer than 128 ->
  `"<text>/<count>"`, else the text. Note the stored text may already end in `/n`, giving
  `.../32/32` (kept on purpose, vector `2001:db8::/32`).
- no `:`, net v4, mask not all ones, text not `any` -> the prefix length whose mask equals this mask
  (0-31) -> `"<text>/<n>"` (again after any `/n` already in the text: `10.0.0.0/8/8`); a non-contiguous
  mask -> `None`.
- anything else -> the stored text.

Vectors: `ip.json` (28,211 cases).

### 2.6 String helpers

- `str_is_num(s)`: every byte is an ASCII digit; the empty string is numeric.
- `str_break(sep, s, size)`: `size == 0` -> `None`. `sep` is used as **one byte** = the low 8 bits of the
  character's code (so `'\u{12c}'` splits on `,`, `'é'` (0xE9) never matches UTF-8 text). The input ends
  at its first NUL. Splits into at most `size` pieces; the last piece takes the rest unsplit. A separator
  directly after a backslash does not split: the backslash is removed and the separator kept (only while
  more pieces may still be produced; inside the last piece both stay). An empty input gives `[""]`.
  Pieces are converted with lossy UTF-8.
- `strings::str_break_bytes(sep, s, size)`: the same on bytes, no conversion.
- `is_valid_hostname_char(c)`: `HOSTNAME_MAP[c] != 0`, i.e. true for every byte except 0 and 1.
- `maps::HOSTNAME_MAP[c] == 1` exactly for `(`, `)`, `-`, `.`, `/`, `0`-`9`, `@`, `A`-`Z`, `_`,
  `a`-`z`. The full 256 values (other non-zero values) are in `tables.json` (`hostname_value`); keep the
  table byte-for-byte since callers compare with `== 1`.
- Unused U14: `str_starts_with` = byte prefix test; `str_how_closed_match` = length of the common prefix,
  except that two empty strings give 1.

Vectors: `strings.json`, `tables.json`.

---

## 3. Feature table

| # | Feature | Vectors |
|---|---|---|
| F1 | OsRegex compile: 20480-byte limit (`MaxSize`) | osregex |
| F2 | OsRegex escapes and their byte classes (15 escapes) | osregex, tables |
| F3 | Unknown escape / trailing backslash -> `BadRegex` | osregex |
| F4 | `+` / `*` repeat only after an escape; literal elsewhere | osregex |
| F5 | One level of groups; nesting, stray `)`, open group, `|` in group -> `BadParenthesis` | osregex |
| F6 | `|` alternatives, tried in order; empty alternatives | osregex |
| F7 | `^` / `$` anchors per alternative; literal elsewhere; `\$` literal | osregex |
| F8 | Case folding of pattern unless `OS_CASE_SENSITIVE`; subject always folded | osregex |
| F9 | Non-ASCII literal bytes never match (signed-byte rule) | osregex, osmatch |
| F10 | `has_sub_strings` only with flag 128 and a `)` | osregex |
| F11 | `end` = offset of last consumed byte, may be -1 | osregex |
| F12 | Captures in order, empty captures, inverted capture -> no match | osregex |
| F13 | Shortest-repetition scan with 4 retry points and restart rule | osregex |
| F14 | `raw()` returns the pattern | osregex (asserted) |
| F15 | `os_regex` one-shot, false on compile error | word_match_and_oneshot |
| F16 | OsMatch 20480 limit incl. `!` | osmatch |
| F17 | OsMatch leading `!` negation | osmatch |
| F18 | OsMatch pieces: equals / starts / ends / contains / empty=always | osmatch |
| F19 | OsMatch folding rules differ for contains vs anchored | osmatch |
| F20 | OsMatch `patterns()` (anchors stripped, folded) | osmatch |
| F21 | Subjects end at first NUL | osregex, osmatch, expression |
| F22 | `os_match2` one-shot | word_match_and_oneshot |
| F23 | `os_word_match` with `|` and `^` | word_match_and_oneshot |
| F24 | Expression compile for 5 types and error kinds | expression |
| F25 | Expression `match_bytes` per type, end offsets, capture rules (PCRE2 keeps old captures when no group) | expression |
| F26 | `add_osip` append / replace / drop-on-error | expression |
| F27 | `pattern()` / `type_str()` | expression |
| F28 | `negate` field, applied by callers | expression |
| F29 | `is_valid_ip` IPv4 forms, prefix and netmask, AND-ed address | ip |
| F30 | `is_valid_ip` IPv6 forms, prefixes, expanded stored text | ip |
| F31 | `::ffff:` IPv4 handling | ip |
| F32 | `any` and leading `!` | ip |
| F33 | `ip_found` incl. v4-in-`any` rule | ip |
| F34 | `ip_found_list` sticky negation | ip |
| F35 | `get_ipv4_from_ipv6`, `expand_ipv6` | ip |
| F36 | `atoi` C semantics with clamping | ip |
| F37 | `cidr_to_str` incl. double suffix and `None` for non-contiguous mask | ip |
| F38 | `str_is_num` | strings |
| F39 | `str_break` / `str_break_bytes`: size limit, escape rule, NUL end, low-byte separator | strings |
| F40 | `is_valid_hostname_char`, `HOSTNAME_MAP` values | strings, tables |
| F41 | Constants `OS_RETURN_SUBSTRING`, `OS_CASE_SENSITIVE`, `OS_PATTERN_MAXSIZE`, `OSREGEX_STR`, `PCRE2_STR` | - |
| F42 | Compiled matchers are `Clone + Send + Sync` and immutable | - |

## 4. Vector files

`specs/vectors/siem-regex/*.json`: `{"meta": {about, platform, part, parts, count}, "cases": [...]}`.
Byte strings are hex (`*_hex`). Regex and IP results were identical on Windows and Linux runs.

| File | Cases |
|---|---|
| osregex.json | 74,482 |
| osmatch.json | 36,439 |
| word_match_and_oneshot.json | 19,127 |
| expression.json | 1,830 |
| ip.json | 28,211 |
| strings.json | 33,702 |
| tables.json | 18 |
| **total** | **193,809** |

Generator: `tools/rewrite-vectors/` (standalone Cargo project, not in the workspace; run
`cargo run --release -- <out-dir> <scratch-dir> all`).
