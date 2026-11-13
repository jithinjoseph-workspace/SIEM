//! File integrity events (spec sections 2.24 and 2.25): the checksum messages of agents
//! before 3.11 are compared with the agent's integrity database; JSON events carry the old
//! and new attributes. Both become `syscheck_*` events with the integrity fields and a
//! readable log.

use std::collections::HashMap;

use provigil_json::Json;

use crate::alert_json::fim;
use crate::decoders::{Decoder, DecoderSet};
use crate::event::*;
use crate::host::Host;

type B = Vec<u8>;

pub const CHANGED: &str = "syscheck_integrity_changed";
pub const NEW: &str = "syscheck_new_entry";
pub const DELETED: &str = "syscheck_deleted";
const KEY_CHANGED: &str = "syscheck_registry_key_modified";
const KEY_NEW: &str = "syscheck_registry_key_added";
const KEY_DELETED: &str = "syscheck_registry_key_deleted";
const VALUE_CHANGED: &str = "syscheck_registry_value_modified";
const VALUE_NEW: &str = "syscheck_registry_value_added";
const VALUE_DELETED: &str = "syscheck_registry_value_deleted";
const ADDED_NAMES: [&str; 3] = [NEW, KEY_NEW, VALUE_NEW];
const CHANGED_NAMES: [&str; 3] = [CHANGED, KEY_CHANGED, VALUE_CHANGED];
const DELETED_NAMES: [&str; 3] = [DELETED, KEY_DELETED, VALUE_DELETED];

/// The integrity field names, in their order.
pub const FIELD_NAMES: [&str; fim::COUNT] = [
    "file",
    "hard_links",
    "mode",
    "size",
    "size_before",
    "perm",
    "perm_before",
    "uid",
    "uid_before",
    "gid",
    "gid_before",
    "md5",
    "md5_before",
    "sha1",
    "sha1_before",
    "uname",
    "uname_before",
    "gname",
    "gname_before",
    "mtime",
    "mtime_before",
    "inode",
    "inode_before",
    "sha256",
    "sha256_before",
    "changed_content",
    "win_attributes",
    "win_attributes_before",
    "changed_fields",
    "user_id",
    "user_name",
    "group_id",
    "group_name",
    "process_name",
    "parent_name",
    "cwd",
    "parent_cwd",
    "audit_uid",
    "audit_name",
    "effective_uid",
    "effective_name",
    "ppid",
    "process_id",
    "tag",
    "symbolic_path",
    "arch",
    "value_name",
    "value_type",
    "hash_full_path",
    "entry_type",
    "event_type",
];

/// The ids of the integrity decoder names (file, registry key, registry value).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ids {
    pub added: [u16; 3],
    pub changed: [u16; 3],
    pub deleted: [u16; 3],
}

impl Ids {
    pub fn of(d: &DecoderSet) -> Ids {
        let mut x = Ids::default();
        for i in 0..3 {
            x.added[i] = d.id_of(ADDED_NAMES[i]);
            x.changed[i] = d.id_of(CHANGED_NAMES[i]);
            x.deleted[i] = d.id_of(DELETED_NAMES[i]);
        }
        x
    }
}

/// The `<syscheck>` options the decoder uses.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub alert_new: bool,
    pub auto_ignore: bool,
    pub ignore_time: i64,
    pub ignore_frequency: i32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Change {
    Added,
    Changed,
    Deleted,
}

fn cut(b: &[u8]) -> &[u8] {
    text_at(b, 0)
}

fn first(mut v: B, room: usize) -> B {
    v.truncate(room.saturating_sub(1));
    v
}

fn or_null(v: &Option<B>) -> &[u8] {
    v.as_deref().unwrap_or(b"(null)")
}

fn join(to: &mut Option<B>, v: &[u8], sep: u8) {
    match to {
        Some(t) => {
            if sep != 0 {
                t.push(sep);
            }
            t.extend_from_slice(v);
        }
        None => *to = Some(v.to_vec()),
    }
}

// ---------------------------------------------------------------- checksum helpers

pub fn replace(s: &[u8], from: &[u8], to: &[u8]) -> B {
    crate::text_logs::replace_all(s, from, to)
}

/// `!`, `:` and space escaped with a backslash.
pub fn escape(s: &[u8]) -> B {
    replace(&replace(&replace(s, b"!", b"\\!"), b":", b"\\:"), b" ", b"\\ ")
}

/// The escapes removed; None for nothing or an empty text.
pub fn unescape(s: Option<&[u8]>) -> Option<B> {
    let s = s.filter(|s| !s.is_empty())?;
    Some(replace(&replace(&replace(s, b"\\ ", b" "), b"\\!", b"!"), b"\\:", b":"))
}

/// A Windows path (`C:/...`) gets backslashes.
pub fn windows_path(p: &mut [u8]) {
    if p.len() >= 2 && p[1] == b':' && p[0].is_ascii_alphabetic() {
        for c in p.iter_mut().filter(|c| **c == b'/') {
            *c = b'\\';
        }
    }
}

pub fn long(s: &[u8]) -> i64 {
    super::small::long(s)
}

/// A double as a C `long` (out of range: the lowest long).
pub fn as_long(d: f64) -> i64 {
    if d.is_finite() && (-9.223_372_036_854_776e18..9.223_372_036_854_776e18).contains(&d) {
        d as i64
    } else {
        i64::MIN
    }
}

/// `strtoul` as an unsigned 32-bit value.
fn unsigned(s: &[u8]) -> u32 {
    let mut i = s.iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).count();
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let mut v: u64 = 0;
    let mut over = false;
    while let Some(c) = s.get(i).filter(|c| c.is_ascii_digit()) {
        match v.checked_mul(10).and_then(|x| x.checked_add(u64::from(c - b'0'))) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    (if over {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    }) as u32
}

/// Who changed a file (who-data).
#[derive(Debug, Clone, Default)]
pub struct Who {
    pub user_id: Option<B>,
    pub user_name: Option<B>,
    pub group_id: Option<B>,
    pub group_name: Option<B>,
    pub process_name: Option<B>,
    pub cwd: Option<B>,
    pub audit_uid: Option<B>,
    pub audit_name: Option<B>,
    pub effective_uid: Option<B>,
    pub effective_name: Option<B>,
    pub parent_name: Option<B>,
    pub parent_cwd: Option<B>,
    pub ppid: Option<B>,
    pub process_id: Option<B>,
}

/// A decoded checksum.
#[derive(Debug, Clone, Default)]
pub struct Sum {
    pub size: Option<B>,
    pub perm: i32,
    pub win_perm: Option<B>,
    pub uid: Option<B>,
    pub gid: Option<B>,
    pub md5: Option<B>,
    pub sha1: Option<B>,
    pub sha256: Option<B>,
    pub attributes: Option<B>,
    pub uname: Option<B>,
    pub gname: Option<B>,
    pub mtime: i64,
    pub inode: i64,
    pub tag: Option<B>,
    pub symbolic_path: Option<B>,
    pub changes: i32,
    pub date_alert: i64,
    pub silent: bool,
    pub who: Who,
}

/// The text before and after the first `:` (`escaped`: not after a backslash).
fn split(s: &[u8], escaped: bool) -> Option<(B, B)> {
    let p = if escaped { super::small::unescaped(s, b':') } else { s.iter().position(|&c| c == b':') }?;
    Some((s[..p].to_vec(), s[p + 1..].to_vec()))
}

/// Decodes `size:perm:uid:gid:md5:sha1[:uname:gname:mtime:inode[:sha256[:attrs]]]` and the
/// who-data part: 0 decoded, 1 deleted (`-1`), -1 malformed. When a separator is missing,
/// the field being read keeps the rest of the text and the next stays unset; what was read
/// before an error stays.
pub fn decode_sum(sum: &mut Sum, c_sum: &[u8], who: Option<&[u8]>) -> i32 {
    let mut result = 0;
    if c_sum.starts_with(b"-1") {
        result = 1;
    } else {
        sum.size = Some(c_sum.to_vec());
        let Some((size, rest)) = split(c_sum, false) else { return -1 };
        sum.size = Some(size);
        let Some((perm, rest)) = split(&rest, true) else {
            sum.uid = None;
            return -1;
        };
        sum.uid = Some(rest.clone());
        match perm.first() {
            Some(b'|') => sum.win_perm = windows_permissions(&unescape(Some(&perm)).unwrap_or_default()),
            Some(b':') => {}
            Some(c) if c.is_ascii_digit() => sum.perm = long(&perm) as i32,
            _ => sum.win_perm = Some(perm.clone()),
        }
        let field = |slot: &mut Option<B>, next: &mut Option<B>, text: &[u8]| -> Option<B> {
            let (a, b) = split(text, false)?;
            *slot = Some(a);
            *next = Some(b.clone());
            Some(b)
        };
        let Some(rest) = field(&mut sum.uid, &mut sum.gid, &rest) else { return -1 };
        let Some(rest) = field(&mut sum.gid, &mut sum.md5, &rest) else { return -1 };
        let Some(rest) = field(&mut sum.md5, &mut sum.sha1, &rest) else { return -1 };
        if let Some((sha1, rest)) = split(&rest, false) {
            sum.sha1 = Some(sha1);
            let Some((uname, rest)) = split(&rest, false) else {
                sum.gname = None;
                return -1;
            };
            sum.gname = Some(rest.clone());
            sum.uname = Some(uname.into_iter().filter(|&c| c != b'\\').collect());
            let Some((gname, rest)) = split(&rest, false) else { return -1 };
            sum.gname = Some(gname);
            let Some((mtime, rest)) = split(&rest, false) else { return -1 };
            sum.sha256 = None;
            if let Some((inode, rest)) = split(&rest, false) {
                sum.sha256 = Some(rest.clone());
                if let Some((sha256, attrs)) = split(&rest, false) {
                    sum.sha256 = Some(sha256);
                    sum.attributes = Some(if attrs.first().is_some_and(u8::is_ascii_digit) { windows_attributes(unsigned(&attrs)) } else { attrs });
                }
                sum.mtime = long(&mtime);
                sum.inode = long(&inode);
            }
        }
    }
    let Some(w) = who else { return result };
    // user_id:user_name:group_id:group_name:process_name:audit_uid:audit_name:effective_uid:
    // effective_name:ppid:process_id[:tag[:symbolic_path[:+silent]]], backslash escapes
    let x = &mut sum.who;
    x.user_id = Some(w.to_vec());
    let Some((user_id, rest)) = split(w, true) else { return -1 };
    x.user_id = Some(user_id);
    let Some((user_name, rest)) = split(&rest, true) else {
        x.group_id = None;
        return -1;
    };
    x.group_id = Some(rest.clone());
    let Some((group_id, rest)) = split(&rest, true) else { return -1 };
    x.group_id = Some(group_id);
    x.group_name = Some(rest.clone());
    let Some((group_name, rest)) = split(&rest, true) else { return -1 };
    x.group_name = Some(group_name);
    let Some((process_name, rest)) = split(&rest, true) else {
        x.audit_uid = None;
        return -1;
    };
    x.audit_uid = Some(rest.clone());
    let field = |slot: &mut Option<B>, next: &mut Option<B>, text: &[u8]| -> Option<B> {
        let (a, b) = split(text, true)?;
        *slot = Some(a);
        *next = Some(b.clone());
        Some(b)
    };
    let Some(rest) = field(&mut x.audit_uid, &mut x.audit_name, &rest) else { return -1 };
    let Some(rest) = field(&mut x.audit_name, &mut x.effective_uid, &rest) else { return -1 };
    let Some(rest) = field(&mut x.effective_uid, &mut x.effective_name, &rest) else { return -1 };
    let Some(rest) = field(&mut x.effective_name, &mut x.ppid, &rest) else { return -1 };
    let Some(rest) = field(&mut x.ppid, &mut x.process_id, &rest) else { return -1 };
    sum.tag = None;
    let mut symbolic = None;
    if let Some((process_id, tag)) = split(&rest, true) {
        x.process_id = Some(process_id);
        sum.tag = Some(tag.clone());
        if let Some((tag, sym)) = split(&tag, true) {
            sum.tag = Some(tag);
            symbolic = Some(sym.clone());
            if let Some((sym, silent)) = split(&sym, true) {
                symbolic = Some(sym);
                sum.silent |= silent.first() == Some(&b'+');
            }
        }
    }
    sum.symbolic_path = unescape(symbolic.as_deref());
    x.user_name = unescape(Some(&user_name));
    x.process_name = unescape(Some(&process_name));
    if x.ppid.as_deref().and_then(|p| p.first()) == Some(&b'-') {
        x.ppid = None;
    }
    result
}

/// `!changes:date[:symbolic path]` after a stored checksum: the checksum before `!`, and
/// whether the extra part was read.
pub fn decode_extra(sum: &mut Sum, c_sum: &[u8]) -> (B, bool) {
    let Some(p) = c_sum.iter().position(|&c| c == b'!') else { return (c_sum.to_vec(), false) };
    let head = c_sum[..p].to_vec();
    let rest = &c_sum[p + 1..];
    let Some(d) = rest.iter().position(|&c| c == b':') else { return (head, false) };
    let (changes, date) = (&rest[..d], &rest[d + 1..]);
    let date = match date.iter().position(|&c| c == b':') {
        Some(s) => {
            sum.symbolic_path = unescape(Some(&date[s + 1..]));
            &date[..s]
        }
        None => date,
    };
    sum.changes = long(changes) as i32;
    sum.date_alert = long(date);
    (head, true)
}

/// The integrity fields from a decoded checksum.
pub fn fill_fields(vals: &mut [Option<B>], file: &[u8], sum: &Sum) {
    vals[fim::FILE] = Some(file.to_vec());
    if let Some(s) = &sum.size {
        vals[fim::SIZE] = Some(s.clone());
    }
    if sum.perm != 0 {
        vals[fim::PERM] = Some(first(format!("{:06o}", sum.perm as u32).into_bytes(), 7));
    } else if let Some(w) = sum.win_perm.as_ref().filter(|w| !w.is_empty()) {
        vals[fim::PERM] = Some(w.clone());
    }
    let w = &sum.who;
    for (i, v) in [(fim::UID, &sum.uid), (fim::GID, &sum.gid), (fim::MD5, &sum.md5), (fim::SHA1, &sum.sha1), (fim::UNAME, &sum.uname), (fim::GNAME, &sum.gname)] {
        if let Some(v) = v {
            vals[i] = Some(v.clone());
        }
    }
    if sum.mtime != 0 {
        vals[fim::MTIME] = Some(sum.mtime.to_string().into_bytes());
    }
    if sum.inode != 0 {
        vals[fim::INODE] = Some(sum.inode.to_string().into_bytes());
    }
    for (i, v) in [
        (fim::SHA256, &sum.sha256),
        (fim::ATTRS, &sum.attributes),
        (fim::USER_ID, &w.user_id),
        (fim::USER_NAME, &w.user_name),
        (fim::GROUP_ID, &w.group_id),
        (fim::GROUP_NAME, &w.group_name),
        (fim::PROC_NAME, &w.process_name),
        (fim::PROC_PNAME, &w.parent_name),
        (fim::AUDIT_CWD, &w.cwd),
        (fim::AUDIT_PCWD, &w.parent_cwd),
        (fim::AUDIT_ID, &w.audit_uid),
        (fim::AUDIT_NAME, &w.audit_name),
        (fim::EFFECTIVE_UID, &w.effective_uid),
        (fim::EFFECTIVE_NAME, &w.effective_name),
        (fim::PPID, &w.ppid),
        (fim::PROC_ID, &w.process_id),
        (fim::TAG, &sum.tag),
        (fim::SYM_PATH, &sum.symbolic_path),
    ] {
        if let Some(v) = v {
            vals[i] = Some(v.clone());
        }
    }
}

/// Windows file attribute bits as names joined with ", " (at most 255 bytes).
pub fn windows_attributes(bits: u32) -> B {
    const NAMES: [(u32, &str); 19] = [
        (0x20, "ARCHIVE"),
        (0x800, "COMPRESSED"),
        (0x40, "DEVICE"),
        (0x10, "DIRECTORY"),
        (0x4000, "ENCRYPTED"),
        (0x2, "HIDDEN"),
        (0x8000, "INTEGRITY_STREAM"),
        (0x80, "NORMAL"),
        (0x2000, "NOT_CONTENT_INDEXED"),
        (0x20000, "NO_SCRUB_DATA"),
        (0x1000, "OFFLINE"),
        (0x1, "READONLY"),
        (0x400000, "RECALL_ON_DATA_ACCESS"),
        (0x40000, "RECALL_ON_OPEN"),
        (0x400, "REPARSE_POINT"),
        (0x200, "SPARSE_FILE"),
        (0x4, "SYSTEM"),
        (0x100, "TEMPORARY"),
        (0x10000, "VIRTUAL"),
    ];
    let mut s: B = NAMES.iter().filter(|(b, _)| bits & b != 0).flat_map(|(_, n)| n.bytes().chain(*b", ")).collect();
    let full = s.len();
    s.truncate(255);
    if full > 2 {
        s.truncate(full - 2);
    }
    s
}

const PERMISSIONS: [(i64, &str); 17] = [
    (0x8000_0000, "generic_read"),
    (0x4000_0000, "generic_write"),
    (0x2000_0000, "generic_execute"),
    (0x1000_0000, "generic_all"),
    (0x0001_0000, "delete"),
    (0x0002_0000, "read_control"),
    (0x0004_0000, "write_dac"),
    (0x0008_0000, "write_owner"),
    (0x0010_0000, "synchronize"),
    (0x0000_0001, "read_data"),
    (0x0000_0002, "write_data"),
    (0x0000_0004, "append_data"),
    (0x0000_0008, "read_ea"),
    (0x0000_0010, "write_ea"),
    (0x0000_0020, "execute"),
    (0x0000_0080, "read_attributes"),
    (0x0000_0100, "write_attributes"),
];

const PERMISSIONS_ROOM: usize = 20480;

/// `|account,type,mask...` as `account (allowed): read_data|write_data, ...` in a
/// 20,480-byte buffer; None when an entry is cut off. Each entry's last `|` becomes `, `
/// while there is room; the final `, ` is removed.
pub fn windows_permissions(raw: &[u8]) -> Option<B> {
    if raw.first() != Some(&b'|') {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; PERMISSIONS_ROOM + 64];
    let (mut at, mut room, mut size): (usize, i64, i64) = (0, PERMISSIONS_ROOM as i64, 0);
    let mut p = 0;
    while let Some(bar) = raw[p..].iter().position(|&c| c == b'|').map(|x| x + p) {
        if raw.len() - bar < 3 {
            return None;
        }
        let start = bar + 1;
        let c1 = raw[start..].iter().position(|&c| c == b',')? + start;
        let account = &raw[start..c1];
        let c2 = raw[c1 + 1..].iter().position(|&c| c == b',')? + c1 + 1;
        let allowed = raw.get(c1 + 1) == Some(&b'0');
        let next = raw[c2 + 1..].iter().position(|&c| c == b'|').map(|x| x + c2 + 1);
        let mask = long(&raw[c2 + 1..next.unwrap_or(raw.len())]);
        let mut text = [account, if allowed { b" (allowed): " } else { b" (denied): " }].concat();
        for (bit, name) in PERMISSIONS {
            if mask & bit != 0 {
                text.extend_from_slice(name.as_bytes());
                text.push(b'|');
            }
        }
        size = text.len() as i64;
        if size > room {
            // an entry that does not fit is left out
            match next {
                Some(n) => {
                    p = n;
                    continue;
                }
                None => break,
            }
        }
        let n = (size as usize).min(room as usize - 1);
        buf[at..at + n].copy_from_slice(&text[..n]);
        buf[at + n] = 0;
        if size + 1 < room {
            let end = at + size as usize - 1;
            buf[end..end + 3].copy_from_slice(b", \0");
            size += 1;
        }
        at += size as usize;
        room -= size;
        match next {
            Some(n) => p = n,
            None => break,
        }
    }
    if at >= 2 && size > 1 {
        buf[at - 2] = 0;
    }
    Some(text_at(&buf, 0).to_vec())
}

/// A Unix mode as `rwxr-xr-x` (with s and t).
pub fn mode_text(mode: i32) -> B {
    let m = mode as u32;
    let b = |bit: u32, c: u8| if m & bit != 0 { c } else { b'-' };
    vec![
        b(0o400, b'r'),
        b(0o200, b'w'),
        if m & 0o4000 != 0 { b's' } else { b(0o100, b'x') },
        b(0o040, b'r'),
        b(0o020, b'w'),
        if m & 0o2000 != 0 { b's' } else { b(0o010, b'x') },
        b(0o004, b'r'),
        b(0o002, b'w'),
        if m & 0o1000 != 0 { b't' } else { b(0o001, b'x') },
    ]
}

// ---------------------------------------------------------------- the decoder

/// What the decoder remembers: when each agent's first scan ended.
#[derive(Debug, Default)]
pub struct Integrity {
    first_scan_end: HashMap<B, i64>,
}

struct Cx<'a> {
    host: &'a mut dyn Host,
    agent: B,
}

impl Cx<'_> {
    fn error(&mut self, m: &[u8]) {
        self.host.log("ERROR", m);
    }

    /// A query (cut to 6,143 bytes); on a send failure `bad` with the query is logged.
    fn query(&mut self, mut q: B, bad: &str) -> Result<B, i32> {
        q.truncate(6143);
        self.host.db_query(&q, 6144).map_err(|code| {
            if code == -2 {
                self.error(&[bad.as_bytes(), b" '", &q, b"'."].concat());
            }
            code
        })
    }

    /// A save or delete; errors are logged ("Agent not found" is not one).
    fn send(&mut self, q: &[u8]) {
        let r = match self.host.db_query(q, 65536) {
            Ok(r) => r,
            Err(-2) => return self.error(b"FIM decoder: Cannot communicate with database."),
            Err(_) => return self.error(b"FIM decoder: Cannot get response from database."),
        };
        let (head, arg) = match r.iter().position(|&c| c == b' ') {
            Some(p) => (&r[..p], &r[p + 1..]),
            None => (&r[..], &r[..]),
        };
        if head == b"err" && arg != b"Agent not found" {
            self.error(&[&b"FIM decoder: Bad response from database: "[..], arg].concat());
        }
    }

    fn scan_time(&mut self, which: &str) -> Option<i64> {
        let q = [&b"agent "[..], &self.agent, b" syscheck scan_info_get ", which.as_bytes()].concat();
        let r = self.query(q, "FIM decoder: Bad result getting scan date").ok()?;
        match r.iter().position(|&c| c == b' ') {
            Some(p) => Some(long(&r[p + 1..])),
            None => {
                self.error(&[&b"FIM decoder: Bad formatted response '"[..], &r, b"'"].concat());
                None
            }
        }
    }
}

fn set_fields(ev: &mut Event, vals: Vec<Option<B>>) {
    ev.fields = FIELD_NAMES.iter().zip(vals).map(|(k, v)| DynamicField { key: k.as_bytes().to_vec(), value: v }).collect();
}

impl Integrity {
    /// One event: JSON (3.11 and later) or a checksum message. True when it goes on to the
    /// rules. `decoder` is the integrity decoder entry; its name and id follow the event.
    pub fn decode(&mut self, host: &mut dyn Host, decoder: &mut Decoder, decoder_index: DecoderId, ids: &Ids, opts: &Options, ev: &mut Event) -> bool {
        ev.decoder = decoder_index;
        let agent = cut(ev.agent_id.as_deref().unwrap_or(b"")).to_vec();
        let mut c = Cx { host, agent };
        if ev.log().first() == Some(&b'{') {
            json_event(&mut c, decoder, ids, ev)
        } else {
            self.checksum_event(&mut c, decoder, ids, opts, ev) == 1
        }
    }

    fn checksum_event(&mut self, c: &mut Cx, decoder: &mut Decoder, ids: &Ids, opts: &Options, ev: &mut Event) -> i32 {
        let log = ev.log().to_vec();
        let Some(sp) = super::small::unescaped(&log, b' ') else {
            return match self.control(c, &log, ev.time.sec) {
                -2 | -1 => -1,
                0 => {
                    c.error(b"(1277): Invalid syscheck message received.");
                    -1
                }
                _ => 0,
            };
        };
        let mut rest = log[sp + 1..].to_vec();
        windows_path(&mut rest);
        let mut vals: Vec<Option<B>> = vec![None; fim::COUNT];
        let file = match rest.iter().position(|&x| x == b'\n') {
            Some(p) => {
                vals[fim::DIFF] = Some(rest[p + 1..].to_vec());
                rest[..p].to_vec()
            }
            None => rest,
        };
        let sums = &log[..sp];
        let (c_sum, who) = match super::small::unescaped(sums, b'!') {
            Some(p) => (&sums[..p], Some(&sums[p + 1..])),
            None => (sums, None),
        };
        self.compare(c, decoder, ids, opts, ev, &file, c_sum, who, vals)
    }

    #[allow(clippy::too_many_arguments)]
    fn compare(&mut self, c: &mut Cx, decoder: &mut Decoder, ids: &Ids, opts: &Options, ev: &mut Event, file: &[u8], c_sum: &[u8], who: Option<&[u8]>, mut vals: Vec<Option<B>>) -> i32 {
        let agent = c.agent.clone();
        let (mut old, mut new) = (Sum::default(), Sum::default());
        let q = [&b"agent "[..], &agent, b" syscheck load ", file].concat();
        let shown = first(q.clone(), 6144);
        let Ok(answer) = c.query(q, "FIM decoder: Bad load query:") else { return -1 };
        let Some(p) = super::small::unescaped(&answer, b' ') else {
            c.error(&[&b"FIM decoder: Bad response: '"[..], &shown, b"' '", &answer, b"'."].concat());
            return -1;
        };
        if &answer[..p] != b"ok" {
            return -1;
        }
        let (old_sum, _) = decode_extra(&mut old, &answer[p + 1..]);
        let decoded = decode_sum(&mut new, c_sum, who);
        let new_sum = adjusted(&new, c_sum);
        if same_sum(&old_sum, &new_sum) {
            let _ = c.query([&b"agent "[..], &agent, b" syscheck updatedate ", file].concat(), "FIM decoder: Bad result updating date field:");
            return 0;
        }
        let change;
        let mut changes = 0;
        match decoded {
            1 => {
                vals[fim::EVENT_TYPE] = Some(b"deleted".to_vec());
                change = Change::Deleted;
                if old_sum.is_empty() {
                    return 0;
                }
                if c.query([&b"agent "[..], &agent, b" syscheck delete ", file].concat(), "FIM decoder: Bad delete query:").is_err() {
                    return -1;
                }
            }
            0 => {
                if old_sum.is_empty() {
                    vals[fim::EVENT_TYPE] = Some(b"added".to_vec());
                    change = Change::Added;
                } else {
                    vals[fim::EVENT_TYPE] = Some(b"modified".to_vec());
                    change = Change::Changed;
                    changes = repeated_changes(opts, old.changes, old.date_alert, ev.time.sec);
                    decode_sum(&mut old, &old_sum, None);
                    if changes == -1 {
                        return 0;
                    }
                }
                let loc = ev.f[F_LOCATION].clone().unwrap_or_default();
                let kind: &[u8] = if find(cut(&loc), b"syscheck-registry").is_some() { b"registry" } else { b"file" };
                let symbolic = new.symbolic_path.as_deref().map(escape);
                let q = [
                    &b"agent "[..],
                    &agent,
                    b" syscheck save ",
                    kind,
                    b" ",
                    &replace(&new_sum, b" ", b"\\ "),
                    format!("!{changes}:{}:", ev.time.sec).as_bytes(),
                    symbolic.as_deref().unwrap_or(b""),
                    b" ",
                    file,
                ]
                .concat();
                if c.query(q, "FIM decoder: Bad save/update query:").is_err() {
                    return -1;
                }
                let end = match self.first_scan_end.get(&agent) {
                    Some(v) => *v,
                    None => {
                        let v = c.scan_time("end_scan").unwrap_or(0);
                        self.first_scan_end.insert(agent.clone(), v);
                        v
                    }
                };
                if change == Change::Added && (end == 0 || ev.time.sec < end || !opts.alert_new) {
                    return 0;
                }
            }
            _ => {
                c.host.log("WARNING", &[&b"at fim_db_search: Agent '"[..], &agent, b"' Couldn't decode fim sum '", &new_sum, b"' from file '", file, b"'."].concat());
                return -1;
            }
        }
        if new.silent {
            return 0;
        }
        fill_fields(&mut vals, file, &new);
        if checksum_alert(decoder, ids, ev, file, &mut old, &new, change, &mut vals) == -1 {
            return 0;
        }
        set_fields(ev, vals);
        1
    }

    /// Scan start / end messages: 1 handled, 0 not one, below 0 an error.
    fn control(&mut self, c: &mut Cx, key: &[u8], time: i64) -> i32 {
        let what: &[u8] = match key {
            b"fim-db-start-first-scan" => b"first_start",
            b"fim-db-end-first-scan" | b"fim-db-end-scan" => {
                if c.scan_time("start_scan") == Some(0) {
                    return -1;
                }
                if key == b"fim-db-end-first-scan" {
                    b"first_end"
                } else {
                    b"end_scan"
                }
            }
            b"fim-db-start-scan" => b"start_scan",
            b"syscheck-db-completed" => b"end_scan",
            _ => return 0,
        };
        let agent = c.agent.clone();
        if let Err(code) = c.query([&b"agent "[..], &agent, b" syscheck scan_info_update ", what, format!(" {time}").as_bytes()].concat(), "FIM decoder: Bad result from scan_info query:") {
            return code;
        }
        if matches!(key, b"fim-db-end-first-scan" | b"fim-db-end-scan" | b"syscheck-db-completed") {
            match self.first_scan_end.get_mut(&agent) {
                None => {
                    self.first_scan_end.insert(agent.clone(), time + 2);
                }
                Some(v) => *v = time,
            }
        }
        if key == b"fim-db-start-first-scan" {
            if let Err(code) = c.query([&b"agent "[..], &agent, format!(" syscheck control {time}").as_bytes()].concat(), "FIM decoder: Bad result from checks control query:") {
                return code;
            }
        }
        if key == b"fim-db-end-first-scan" {
            let _ = c.query([&b"agent "[..], &agent, b" syscheck cleandb "].concat(), "FIM decoder: Bad result from cleandb query:");
        }
        1
    }
}

/// With auto-ignore: the change count, or -1 when a file changed too often lately.
fn repeated_changes(o: &Options, count: i32, last: i64, now: i64) -> i32 {
    if !o.auto_ignore || now - last >= o.ignore_time {
        1
    } else if count >= o.ignore_frequency {
        -1
    } else {
        count + 1
    }
}

/// Same length and same text up to the last `:` (the last field is not compared).
fn same_sum(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let colon = |s: &[u8], from: usize| s[from..].iter().position(|&c| c == b':').map(|p| p + from);
    let (mut x, mut y) = (colon(a, 0), colon(b, 0));
    while let (Some(i), Some(j)) = (x, y) {
        x = colon(a, i + 1);
        y = colon(b, j + 1);
    }
    let (n, m) = (x.unwrap_or(a.len()), y.unwrap_or(b.len()));
    n == m && a[..n] == b[..n]
}

/// The new checksum with its decoded attributes and Windows permissions put in.
fn adjusted(new: &Sum, c_sum: &[u8]) -> B {
    let mut s = c_sum.to_vec();
    if let (Some(a), Some(p)) = (&new.attributes, c_sum.iter().rposition(|&c| c == b':')) {
        s.truncate(p + 1);
        s.extend_from_slice(a);
    }
    if let Some(wp) = new.win_perm.as_ref().filter(|w| !w.is_empty()) {
        let Some(first) = s.iter().position(|&c| c == b':') else { return s };
        let cut = first + 1;
        if cut >= s.len() {
            return s;
        }
        // the permissions field is replaced (its first character was already dropped)
        let tail = s[cut + 1..].to_vec();
        s.truncate(cut);
        let Some(sp) = tail.iter().position(|&c| c == b':') else { return s };
        s.extend_from_slice(&replace(wp, b":", b"\\:"));
        s.extend_from_slice(&tail[sp..]);
    }
    s
}

/// The checksum alert: the decoder's name and id, the changed fields and the log text.
/// -1 when nothing changed.
#[allow(clippy::too_many_arguments)]
fn checksum_alert(decoder: &mut Decoder, ids: &Ids, ev: &mut Event, file: &[u8], old: &mut Sum, new: &Sum, change: Change, vals: &mut [Option<B>]) -> i32 {
    let line = |v: B| first(v, 256);
    let mut changed = false;
    let mut parts: [B; 10] = Default::default(); // size, perm, owner, group, md5, sha1, sha256, mtime, inode, attributes
    let what: &[u8] = match change {
        Change::Deleted => {
            decoder.id = ids.deleted[0];
            decoder.name = Some(DELETED.into());
            changed = true;
            b"was deleted."
        }
        Change::Added => {
            decoder.id = ids.added[0];
            decoder.name = Some(NEW.into());
            changed = true;
            b"was added."
        }
        Change::Changed => {
            decoder.id = ids.changed[0];
            decoder.name = Some(CHANGED.into());
            let mut list = vals[fim::CHFIELDS].clone();
            let mut note = |list: &mut Option<B>, name: &[u8]| {
                changed = true;
                join(list, name, b',');
            };
            if let (Some(o), Some(n)) = (&old.size, &new.size) {
                if o != n {
                    note(&mut list, b"size");
                    parts[0] = line([&b"Size changed from '"[..], o, b"' to '", n, b"'\n"].concat());
                    vals[fim::SIZE_BEFORE] = Some(o.clone());
                }
            }
            if old.perm != 0 && new.perm != 0 {
                if old.perm != new.perm && old.perm > 0 && new.perm > 0 {
                    note(&mut list, b"perm");
                    let (o, n) = (mode_text(old.perm), mode_text(new.perm));
                    vals[fim::PERM_BEFORE] = Some(o.clone());
                    parts[1] = line([&b"Permissions changed from '"[..], &o, b"' to '", &n, b"'\n"].concat());
                }
            } else if let (Some(ow), Some(nw)) = (old.win_perm.clone(), new.win_perm.as_ref()) {
                let ow = replace(&ow, b"\\:", b":");
                old.win_perm = Some(ow.clone());
                if ow != *nw && !ow.is_empty() && !nw.is_empty() {
                    note(&mut list, b"perm");
                    parts[1] = b"Permissions changed.\n".to_vec();
                    vals[fim::PERM_BEFORE] = Some(ow);
                }
            }
            for (k, name, slot_before, names_before, nv, ov, nn, on, label) in [
                (2usize, &b"uid"[..], fim::UID_BEFORE, fim::UNAME_BEFORE, &new.uid, &old.uid, &new.uname, &old.uname, "Ownership was '"),
                (3, b"gid", fim::GID_BEFORE, fim::GNAME_BEFORE, &new.gid, &old.gid, &new.gname, &old.gname, "Group ownership was '"),
            ] {
                if let (Some(n), Some(o)) = (nv, ov) {
                    if n != o {
                        note(&mut list, name);
                        parts[k] = match (on, nn) {
                            (Some(on), Some(nn)) => {
                                vals[names_before] = Some(on.clone());
                                line([label.as_bytes(), on, b" (", o, b")', now it is '", nn, b" (", n, b")'\n"].concat())
                            }
                            _ => line([label.as_bytes(), o, b"', now it is '", n, b"'\n"].concat()),
                        };
                        vals[slot_before] = Some(o.clone());
                    }
                }
            }
            let set = |v: &Option<B>| v.clone().filter(|x| !x.is_empty());
            for (k, name, slot, nv, ov, label) in [(4usize, &b"md5"[..], fim::MD5_BEFORE, &new.md5, &old.md5, "md5sum"), (5, b"sha1", fim::SHA1_BEFORE, &new.sha1, &old.sha1, "sha1sum")] {
                if let (Some(n), Some(o)) = (set(nv), set(ov)) {
                    if n != o {
                        note(&mut list, name);
                        parts[k] = line(format!("Old {label} was: '").bytes().chain(o.iter().copied()).chain(format!("'\nNew {label} is : '").bytes()).chain(n.iter().copied()).chain(*b"'\n").collect());
                        vals[slot] = Some(o);
                    }
                }
            }
            if let Some(n) = set(&new.sha256) {
                match &old.sha256 {
                    Some(o) if *o != n => {
                        note(&mut list, b"sha256");
                        parts[6] = line([&b"Old sha256sum was: '"[..], o, b"'\nNew sha256sum is : '", &n, b"'\n"].concat());
                        vals[fim::SHA256_BEFORE] = Some(o.clone());
                    }
                    Some(_) => {}
                    None => {
                        note(&mut list, b"sha256");
                        parts[6] = line([&b"New sha256sum is : '"[..], &n, b"'\n"].concat());
                    }
                }
            }
            if old.mtime != 0 && new.mtime != 0 && old.mtime != new.mtime {
                note(&mut list, b"mtime");
                vals[fim::MTIME_BEFORE] = Some(old.mtime.to_string().into_bytes());
                let day = |t: i64| crate::time::ctime(t).map(|s| s.trim_end_matches('\n').to_string());
                let (o, n) = match (day(old.mtime), day(new.mtime)) {
                    (Some(o), Some(n)) => (o, n),
                    _ => ("Unknown".to_string(), "Unknown".to_string()),
                };
                parts[7] = line(format!("Old modification time was: '{o}', now it is '{n}'\n").into_bytes());
            }
            if old.inode != 0 && new.inode != 0 && old.inode != new.inode {
                note(&mut list, b"inode");
                parts[8] = line(format!("Old inode was: '{}', now it is '{}'\n", old.inode, new.inode).into_bytes());
                vals[fim::INODE_BEFORE] = Some(old.inode.to_string().into_bytes());
            }
            if let (Some(o), Some(n)) = (&old.attributes, &new.attributes) {
                if o != n {
                    note(&mut list, b"attributes");
                    parts[9] = first([&b"Old attributes were: '"[..], o, b"'\nNow they are '", n, b"'\n"].concat(), 1024);
                    vals[fim::ATTRS_BEFORE] = Some(o.clone());
                }
            }
            vals[fim::CHFIELDS] = list;
            b"checksum changed."
        }
    };
    ev.decoder_syscheck_id = decoder.id;
    let symbolic = match new.symbolic_path.as_ref().filter(|p| !p.is_empty()) {
        Some(p) => line([&b"Symbolic path: '"[..], p, b"'.\n"].concat()),
        None => B::new(),
    };
    // the order of the lines: size, perm, owner, group, md5, sha1, sha256, attributes, mtime, inode
    let order = [0, 1, 2, 3, 4, 5, 6, 9, 7, 8];
    let mut text = [&b"File '"[..], &file[..file.len().min(756)], b"' ", what, b"\n", &symbolic].concat();
    for i in order {
        text.extend_from_slice(&parts[i]);
    }
    let text = first(text, 65536);
    if !changed {
        return -1;
    }
    if let Some(l) = &mut vals[fim::CHFIELDS] {
        l.push(b',');
    }
    ev.buf = [text.as_slice(), &[0]].concat();
    ev.log_start = 0;
    ev.program_name = None;
    ev.dec_timestamp = None;
    0
}

/// A JSON event: `type` event, scan_start or scan_end.
fn json_event(c: &mut Cx, decoder: &mut Decoder, ids: &Ids, ev: &mut Event) -> bool {
    let log = ev.log().to_vec();
    let Ok((mut root, _)) = provigil_json::parse_with_opts(&log, false) else {
        c.error(b"Malformed FIM JSON event");
        return false;
    };
    let kind = match root.get("type") {
        Some(Json::String(t)) => Some(cut(t).to_vec()),
        _ => None,
    };
    let (Some(kind), true) = (kind, root.get("data").is_some()) else {
        c.error(b"Invalid FIM event");
        return false;
    };
    let data = root.get_mut("data").expect("checked above");
    match kind.as_slice() {
        b"event" => {
            if json_alert(c, decoder, ids, ev, data) == -1 {
                c.error(&[&b"Can't generate fim alert for event: '"[..], &log, b"'"].concat());
                return false;
            }
            true
        }
        b"scan_start" | b"scan_end" => {
            if let Some(Json::Number { double, .. }) = data.get("timestamp") {
                let which: &[u8] = if kind == b"scan_start" { b"start_scan" } else { b"end_scan" };
                let q = [&b"agent "[..], &c.agent.clone(), b" syscheck scan_info_update ", which, format!(" {}", as_long(*double)).as_bytes()].concat();
                if q.len() >= 6144 {
                    c.error(b"FIM decoder: Cannot build save query: input is too long.");
                } else {
                    c.send(&q);
                }
            }
            false
        }
        _ => false,
    }
}

fn json_alert(c: &mut Cx, decoder: &mut Decoder, ids: &Ids, ev: &mut Event, event: &mut Json) -> i32 {
    let mut vals: Vec<Option<B>> = vec![None; fim::COUNT];
    let (mut attributes, mut old_attributes, mut audit) = (None, None, None);
    let mut version = 0;
    let members: Vec<(Option<B>, Json)> = match &*event {
        Json::Object(m) => m.iter().map(|(k, v)| (Some(cut(k).to_vec()), v.clone())).collect(),
        Json::Array(a) => a.iter().map(|v| (None, v.clone())).collect(),
        _ => Vec::new(),
    };
    for (key, value) in &members {
        let Some(key) = key else { return -1 };
        match value {
            Json::String(v) => {
                let slot = match key.as_slice() {
                    b"path" => fim::FILE,
                    b"mode" => fim::MODE,
                    b"type" => fim::EVENT_TYPE,
                    b"tags" => fim::TAG,
                    b"content_changes" => fim::DIFF,
                    b"arch" => fim::REGISTRY_ARCH,
                    b"value_name" => fim::REGISTRY_VALUE_NAME,
                    b"index" => fim::REGISTRY_HASH,
                    _ => continue,
                };
                vals[slot] = Some(cut(v).to_vec());
            }
            Json::Array(items) if key == b"changed_attributes" => {
                for it in items {
                    if let Json::String(s) = it {
                        join(&mut vals[fim::CHFIELDS], cut(s), b',');
                    }
                }
            }
            Json::Array(_) if key == b"hard_links" => vals[fim::HARD_LINKS] = Some(value.print_unformatted()),
            Json::Object(_) => match key.as_slice() {
                b"attributes" => attributes = Some(value.clone()),
                b"old_attributes" => old_attributes = Some(value.clone()),
                b"audit" => audit = Some(value.clone()),
                _ => {}
            },
            Json::Number { int, .. } if key == b"version" => version = *int,
            _ => {}
        }
    }
    let entry = match attributes.as_ref().and_then(|a| a.get("type")) {
        Some(Json::String(t)) => cut(t).to_vec(),
        _ => return -1,
    };
    if matches!(entry.as_slice(), b"registry_key" | b"registry_value") && version >= 3 && vals[fim::REGISTRY_HASH].is_none() {
        return -1;
    }
    if vals[fim::EVENT_TYPE].is_none() || vals[fim::FILE].is_none() {
        return -1;
    }
    let k = match entry.as_slice() {
        b"file" | b"registry" => 0,
        b"registry_key" => 1,
        b"registry_value" => 2,
        _ => return -1,
    };
    vals[fim::ENTRY_TYPE] = Some(entry.clone());
    let (change, name, id) = match vals[fim::EVENT_TYPE].as_deref() {
        Some(b"added") => (Change::Added, ADDED_NAMES[k], ids.added[k]),
        Some(b"modified") => (Change::Changed, CHANGED_NAMES[k], ids.changed[k]),
        Some(b"deleted") => (Change::Deleted, DELETED_NAMES[k], ids.deleted[k]),
        _ => return -1,
    };
    decoder.name = Some(name.into());
    decoder.id = id;
    ev.decoder_syscheck_id = id;
    if let Some(text) = json_text(&mut vals, change, attributes.as_ref(), old_attributes.as_ref(), audit.as_ref()) {
        // written over the start of the buffer; the log position does not move
        let t = [first(text, 65536).as_slice(), &[0]].concat();
        if ev.buf.len() < t.len() {
            ev.buf.resize(t.len(), 0);
        }
        ev.buf[..t.len()].copy_from_slice(&t);
    }
    set_fields(ev, vals.clone());
    let agent = c.agent.clone();
    match change {
        Change::Added | Change::Changed => {
            for key in ["mode", "type", "tags", "content_changes", "changed_attributes", "hard_links", "old_attributes", "audit"] {
                event.remove(key);
            }
            let q = [&b"agent "[..], &agent, b" syscheck save2 ", &event.print_unformatted()].concat();
            if q.len() >= 65536 {
                c.error(b"FIM decoder: Cannot build save2 query: input is too long.");
            } else {
                c.send(&q);
            }
        }
        Change::Deleted => {
            let path = if entry == b"file" { &vals[fim::FILE] } else { &vals[fim::REGISTRY_HASH] };
            let q = [&b"agent "[..], &agent, b" syscheck delete ", or_null(path)].concat();
            if q.len() >= 6144 {
                c.error(b"FIM decoder: Cannot build delete query: input is too long.");
            } else {
                c.send(&q);
            }
        }
    }
    0
}

/// The attribute values of one state into the fields; -1 for an unnamed item.
fn read_attributes(vals: &mut [Option<B>], attrs: Option<&Json>, new: bool) -> i32 {
    let items: Vec<(Option<&[u8]>, &Json)> = match attrs {
        Some(Json::Object(m)) => m.iter().map(|(k, v)| (Some(cut(k)), v)).collect(),
        Some(Json::Array(a)) => a.iter().map(|v| (None, v)).collect(),
        _ => Vec::new(),
    };
    let pick = |n: usize, o: usize| if new { n } else { o };
    for (key, v) in items {
        let Some(key) = key else { return -1 };
        match v {
            Json::Number { double, .. } => {
                let slot = match key {
                    b"size" => pick(fim::SIZE, fim::SIZE_BEFORE),
                    b"inode" => pick(fim::INODE, fim::INODE_BEFORE),
                    b"mtime" => pick(fim::MTIME, fim::MTIME_BEFORE),
                    _ => continue,
                };
                vals[slot] = Some(as_long(*double).to_string().into_bytes());
            }
            Json::String(s) => {
                let slot = match key {
                    b"perm" => pick(fim::PERM, fim::PERM_BEFORE),
                    b"user_name" => pick(fim::UNAME, fim::UNAME_BEFORE),
                    b"group_name" => pick(fim::GNAME, fim::GNAME_BEFORE),
                    b"uid" => pick(fim::UID, fim::UID_BEFORE),
                    b"gid" => pick(fim::GID, fim::GID_BEFORE),
                    b"hash_md5" => pick(fim::MD5, fim::MD5_BEFORE),
                    b"hash_sha1" => pick(fim::SHA1, fim::SHA1_BEFORE),
                    b"hash_sha256" => pick(fim::SHA256, fim::SHA256_BEFORE),
                    b"attributes" => pick(fim::ATTRS, fim::ATTRS_BEFORE),
                    b"symlink_path" if new => fim::SYM_PATH,
                    b"value_type" => fim::REGISTRY_VALUE_TYPE,
                    b"inode" => pick(fim::INODE, fim::INODE_BEFORE),
                    _ => continue,
                };
                vals[slot] = Some(cut(s).to_vec());
            }
            Json::Object(_) if key == b"perm" => vals[pick(fim::PERM, fim::PERM_BEFORE)] = permissions_text(v),
            _ => {}
        }
    }
    0
}

/// One access entry: `account (allowed|denied): A|B, `.
fn access_entry(list: Option<&Json>, account: &[u8], kind: &[u8]) -> Option<B> {
    let list = list?;
    let mut out = [account, b" (", kind, b"): "].concat();
    let mut names = None;
    for x in list.children() {
        if let Json::String(s) = x {
            join(&mut names, cut(s), b'|');
        }
    }
    if let Some(n) = names {
        out.extend(n.iter().map(u8::to_ascii_uppercase));
    }
    out.extend_from_slice(b", ");
    Some(out)
}

/// A JSON permission object in the older text form.
fn permissions_text(perm: &Json) -> Option<B> {
    let items: Vec<(Option<&[u8]>, &Json)> = match perm {
        Json::Object(m) => m.iter().map(|(k, v)| (Some(cut(k)), v)).collect(),
        Json::Array(a) => a.iter().map(|v| (None, v)).collect(),
        _ => Vec::new(),
    };
    let mut out: Option<B> = None;
    for (key, x) in items {
        let name = match x.get("name") {
            Some(Json::String(n)) => cut(n).to_vec(),
            _ => key.map_or_else(|| b"(null)".to_vec(), <[u8]>::to_vec),
        };
        for kind in ["allowed", "denied"] {
            if let Some(e) = access_entry(x.get(kind), &name, kind.as_bytes()) {
                join(&mut out, &e, 0);
            }
        }
    }
    let mut out = out?;
    if out.len() > 2 && out[out.len() - 2] == b',' {
        out.truncate(out.len() - 2);
    }
    Some(out)
}

/// `<a><before><b><after><c>` when the values differ (cut to `room`), and its full length.
fn change_line(room: usize, a: &str, b: &str, c: &str, before: &Option<B>, after: &Option<B>) -> (B, usize) {
    let (x, y) = (before.as_deref().unwrap_or(b""), after.as_deref().unwrap_or(b""));
    if x == y {
        return (B::new(), 0);
    }
    let full = [a.as_bytes(), x, b.as_bytes(), y, c.as_bytes()].concat();
    let n = full.len();
    (first(full, room), n)
}

/// The log text of a JSON event; None when its attributes cannot be read.
fn json_text(vals: &mut [Option<B>], change: Change, attrs: Option<&Json>, old: Option<&Json>, audit: Option<&Json>) -> Option<B> {
    if read_attributes(vals, attrs, true) != 0 || read_attributes(vals, old, false) != 0 {
        return None;
    }
    if let Some(Json::Object(m)) = audit {
        for (k, v) in m {
            match v {
                Json::Number { double, .. } => {
                    let slot = match cut(k) {
                        b"ppid" => fim::PPID,
                        b"process_id" => fim::PROC_ID,
                        _ => continue,
                    };
                    vals[slot] = Some(first(as_long(*double).to_string().into_bytes(), 32));
                }
                Json::String(s) => {
                    let slot = match cut(k) {
                        b"user_id" => fim::USER_ID,
                        b"user_name" => fim::USER_NAME,
                        b"group_id" => fim::GROUP_ID,
                        b"group_name" => fim::GROUP_NAME,
                        b"process_name" => fim::PROC_NAME,
                        b"parent_name" => fim::PROC_PNAME,
                        b"cwd" => fim::AUDIT_CWD,
                        b"parent_cwd" => fim::AUDIT_PCWD,
                        b"audit_uid" => fim::AUDIT_ID,
                        b"audit_name" => fim::AUDIT_NAME,
                        b"effective_uid" => fim::EFFECTIVE_UID,
                        b"effective_name" => fim::EFFECTIVE_NAME,
                        _ => continue,
                    };
                    vals[slot] = Some(cut(s).to_vec());
                }
                _ => {}
            }
        }
    }
    let room = 257;
    let mut lines: Vec<B> = Vec::new();
    if change == Change::Changed {
        let v = |i: usize| vals[i].clone();
        let pairs: [(&str, &str, &str, usize, usize); 12] = [
            ("Size changed from '", "' to '", "'\n", fim::SIZE_BEFORE, fim::SIZE),
            ("Permissions changed from '", "' to '", "'\n", fim::PERM_BEFORE, fim::PERM),
            ("Ownership was '", "', now it is '", "'\n", fim::UID_BEFORE, fim::UID),
            ("User name was '", "', now it is '", "'\n", fim::UNAME_BEFORE, fim::UNAME),
            ("Group ownership was '", "', now it is '", "'\n", fim::GID_BEFORE, fim::GID),
            ("Group name was '", "', now it is '", "'\n", fim::GNAME_BEFORE, fim::GNAME),
            ("Old modification time was: '", "', now it is '", "'\n", fim::MTIME_BEFORE, fim::MTIME),
            ("Old inode was: '", "', now it is '", "'\n", fim::INODE_BEFORE, fim::INODE),
            ("Old md5sum was: '", "'\nNew md5sum is : '", "'\n", fim::MD5_BEFORE, fim::MD5),
            ("Old sha1sum was: '", "'\nNew sha1sum is : '", "'\n", fim::SHA1_BEFORE, fim::SHA1),
            ("Old sha256sum was: '", "'\nNew sha256sum is : '", "'\n", fim::SHA256_BEFORE, fim::SHA256),
            ("Old attributes were: '", "'\nNow they are '", "'\n", fim::ATTRS_BEFORE, fim::ATTRS),
        ];
        for (i, (a, b, c, before, after)) in pairs.iter().enumerate() {
            let (t, n) = change_line(room, a, b, c, &v(*before), &v(*after));
            // a permission list too long for the line is just "Permissions changed."
            lines.push(if i == 1 && n >= room { b"Permissions changed.\n".to_vec() } else { t });
        }
    }
    let changed = first([&b"Changed attributes: "[..], or_null(&vals[fim::CHFIELDS]), b"\n"].concat(), 256);
    let hard = vals[fim::HARD_LINKS].as_ref().map(|h| {
        let mut t = None;
        if let Some(Json::Array(a)) = provigil_json::parse(h) {
            for x in &a {
                if let Json::String(s) = x {
                    join(&mut t, cut(s), b',');
                }
            }
        }
        first([&b"Hard links: "[..], or_null(&t), b"\n"].concat(), 256)
    });
    let entry = vals[fim::ENTRY_TYPE].clone().unwrap_or_default();
    let file = vals[fim::FILE].clone().unwrap_or_default();
    let arch = vals[fim::REGISTRY_ARCH].clone();
    let (label, path): (&[u8], B) = match entry.as_slice() {
        b"file" | b"registry" => {
            let path = if file.len() > 756 { first([&file[..719], b" [...] ", &file[file.len() - 30..]].concat(), 757) } else { file.clone() };
            (b"File", path)
        }
        b"registry_key" => {
            let full = 6 + file.len();
            let path = if full > 756 {
                first([or_null(&arch), b" ", &file[..file.len().min(713)], b" [...] ", &file[full - 30..]].concat(), 757)
            } else {
                first([or_null(&arch), b" ", &file].concat(), 757)
            };
            (b"Registry Key", path)
        }
        _ => {
            let name = vals[fim::REGISTRY_VALUE_NAME].get_or_insert_with(|| b"Unknown key:Unknown Value".to_vec()).clone();
            let full = 6 + file.len() + name.len();
            let path = if full > 756 {
                let keep = 751usize.saturating_sub(name.len());
                first([or_null(&arch), b" ", &file[..file.len().min(keep)], b" [...] \\", &name].concat(), 757)
            } else {
                first([or_null(&arch), b" ", &file, b"\\", &name].concat(), 757)
            };
            (b"Registry Value", path)
        }
    };
    let mut out = [
        label,
        b" '",
        &path,
        b"' ",
        or_null(&vals[fim::EVENT_TYPE]),
        b"\n",
        hard.as_deref().unwrap_or(b""),
        b"Mode: ",
        or_null(&vals[fim::MODE]),
        b"\n",
        if vals[fim::CHFIELDS].is_some() { &changed } else { b"" },
    ]
    .concat();
    for l in lines {
        out.extend_from_slice(&l);
    }
    Some(out)
}
