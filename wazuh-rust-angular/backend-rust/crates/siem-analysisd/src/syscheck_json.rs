//! The `syscheck` section of an alert (to_json.c) and the helpers it uses
//! from shared/syscheck_op.c (`attrs_to_json`, `win_perm_to_json`).

use siem_cjson::Json;

use crate::event::Event;
use crate::logmsg::LogList;

/// `fim_fields` (syscheck_op.h): positions of the syscheck dynamic fields.
pub mod fim {
    pub const FILE: usize = 0;
    pub const HARD_LINKS: usize = 1;
    pub const MODE: usize = 2;
    pub const SIZE: usize = 3;
    pub const SIZE_BEFORE: usize = 4;
    pub const PERM: usize = 5;
    pub const PERM_BEFORE: usize = 6;
    pub const UID: usize = 7;
    pub const UID_BEFORE: usize = 8;
    pub const GID: usize = 9;
    pub const GID_BEFORE: usize = 10;
    pub const MD5: usize = 11;
    pub const MD5_BEFORE: usize = 12;
    pub const SHA1: usize = 13;
    pub const SHA1_BEFORE: usize = 14;
    pub const UNAME: usize = 15;
    pub const UNAME_BEFORE: usize = 16;
    pub const GNAME: usize = 17;
    pub const GNAME_BEFORE: usize = 18;
    pub const MTIME: usize = 19;
    pub const MTIME_BEFORE: usize = 20;
    pub const INODE: usize = 21;
    pub const INODE_BEFORE: usize = 22;
    pub const SHA256: usize = 23;
    pub const SHA256_BEFORE: usize = 24;
    pub const DIFF: usize = 25;
    pub const ATTRS: usize = 26;
    pub const ATTRS_BEFORE: usize = 27;
    pub const CHFIELDS: usize = 28;
    pub const USER_ID: usize = 29;
    pub const USER_NAME: usize = 30;
    pub const GROUP_ID: usize = 31;
    pub const GROUP_NAME: usize = 32;
    pub const PROC_NAME: usize = 33;
    pub const PROC_PNAME: usize = 34;
    pub const AUDIT_CWD: usize = 35;
    pub const AUDIT_PCWD: usize = 36;
    pub const AUDIT_ID: usize = 37;
    pub const AUDIT_NAME: usize = 38;
    pub const EFFECTIVE_UID: usize = 39;
    pub const EFFECTIVE_NAME: usize = 40;
    pub const PPID: usize = 41;
    pub const PROC_ID: usize = 42;
    pub const TAG: usize = 43;
    pub const SYM_PATH: usize = 44;
    pub const REGISTRY_ARCH: usize = 45;
    pub const REGISTRY_VALUE_NAME: usize = 46;
    pub const REGISTRY_VALUE_TYPE: usize = 47;
    pub const REGISTRY_HASH: usize = 48;
    pub const ENTRY_TYPE: usize = 49;
    pub const EVENT_TYPE: usize = 50;
    pub const NFIELDS: usize = 51;
}

fn field(ev: &Event, i: usize) -> Option<&[u8]> {
    ev.fields.get(i).and_then(|f| f.value.as_deref())
}

fn nonempty(v: Option<&[u8]>) -> Option<&[u8]> {
    v.filter(|x| !x.is_empty())
}

/// `print_before_field`
fn print_before(before: Option<&[u8]>, after: Option<&[u8]>) -> Option<Vec<u8>> {
    match before {
        Some(b) if !b.is_empty() && after.map_or(true, |a| a != b) => Some(b.to_vec()),
        _ => None,
    }
}

/// `attrs_to_json`
pub fn attrs_to_json(attributes: &[u8]) -> Json {
    let mut arr = Vec::new();
    for part in attributes.split(|&c| c == b',') {
        let p = part.iter().position(|&c| c != b' ').map(|i| &part[i..]).unwrap_or(&[]);
        arr.push(Json::String(p.to_vec()));
    }
    Json::Array(arr)
}

/// `win_perm_to_json`
pub fn win_perm_to_json(perms: &[u8]) -> Option<Json> {
    let mut out: Vec<Json> = Vec::new();
    let mut rest: Option<&[u8]> = Some(perms);
    while let Some(r) = rest {
        if r.is_empty() {
            break;
        }
        let (node, next) = match r.iter().position(|&c| c == b',') {
            Some(p) => (&r[..p], Some(&r[p + 1..])),
            None => (r, None),
        };
        rest = next;
        let node = &node[node.iter().position(|&c| c != b' ').unwrap_or(node.len())..];
        let Some(op) = node.iter().position(|&c| c == b'(') else {
            continue;
        };
        let mut username = node[..op].to_vec();
        if username.last() == Some(&b' ') {
            username.pop();
        }
        let after = &node[op + 1..];
        let Some(cp) = after.iter().position(|&c| c == b')') else {
            continue;
        };
        let perm_type = after[..cp].to_vec();
        let mut pn = &after[cp + 1..];
        if pn.first() == Some(&b':') {
            pn = &pn[1..];
        }
        let pn = &pn[pn.iter().position(|&c| c != b' ').unwrap_or(pn.len())..];
        let permissions = match pn.iter().position(|&c| c == b',') {
            Some(p) => &pn[..p],
            None => pn,
        };


        let mut user_idx: Option<usize> = None;
        let mut next_it = false;
        for (i, j) in out.iter().enumerate() {
            let Some(name) = j.get("name").and_then(|n| n.as_bytes()) else {
                continue;
            };
            if name == username.as_slice() {
                user_idx = Some(i);
                if j.get_bytes(&perm_type).is_some() {
                    next_it = true;
                }
                break;
            }
        }
        if next_it {
            continue;
        }
        let idx = match user_idx {
            Some(i) => i,
            None => {
                let mut o = Json::object();
                o.add("name", Json::String(username.clone()));
                out.push(o);
                out.len() - 1
            }
        };
        if permissions.is_empty() {
            out[idx].add(&perm_type, Json::array());
            continue;
        }
        let parts: Vec<Json> = permissions
            .split(|&c| c == b'|')
            .filter(|t| !t.is_empty())
            .map(|t| Json::String(t.to_ascii_uppercase()))
            .collect();
        if parts.is_empty() {
            return None;
        }
        out[idx].add(&perm_type, Json::Array(parts));
    }
    if out.is_empty() {
        None
    } else {
        Some(Json::Array(out))
    }
}

/// C `atol` (64-bit long, saturating like `strtol`).
fn atol(v: &[u8]) -> i64 {
    crate::internal::rootcheck::strtol(v)
}

/// `strftime(buf, 20, "%FT%T%z")`: the 24-character result does not fit,
/// so only the date and time (19 characters) end up in the buffer.
/// `buf` is the function's `char mtime[25]`, shared by both fields.
fn mtime_text(buf: &mut [u8; 25], v: &[u8]) -> Vec<u8> {
    let t = crate::internal::rootcheck::strtol(v);
    match crate::localtime::tm(t) {
        Some(tm) => crate::localtime::strftime_fttz(&mut buf[..], 20, &tm),
        None => {
            // snprintf(mtime, 24, "Invalid: '%s'", value)
            let mut m = [&b"Invalid: '"[..], v, b"'"].concat();
            m.truncate(23);
            buf[..m.len()].copy_from_slice(&m);
            buf[m.len()] = 0;
        }
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    buf[..n].to_vec()
}

fn split_tokens(v: &[u8]) -> Json {
    Json::Array(v.split(|&c| c == b',').filter(|t| !t.is_empty()).map(|t| Json::String(t.to_vec())).collect())
}

/// The `syscheck` object of the alert.
pub fn syscheck_section(ev: &Event, order_size: usize, log: &mut LogList) -> Option<Json> {
    use fim::*;
    let mut d = Json::object();
    let f = |i| field(ev, i);
    if let Some(v) = f(FILE) {
        d.add("path", Json::String(v.to_vec()));
    }
    if let Some(v) = nonempty(f(HARD_LINKS)) {
        if let Some(j) = siem_cjson::parse(v) {
            d.add("hard_links", j);
        }
    }
    if let Some(v) = f(MODE) {
        d.add("mode", Json::String(v.to_vec()));
    }
    if let Some(v) = nonempty(f(SYM_PATH)) {
        d.add("symbolic_path", Json::String(v.to_vec()));
    }
    for (k, i) in [("arch", REGISTRY_ARCH), ("value_name", REGISTRY_VALUE_NAME), ("value_type", REGISTRY_VALUE_TYPE)] {
        if let Some(v) = f(i) {
            d.add(k, Json::String(v.to_vec()));
        }
    }
    if let Some(b) = print_before(f(SIZE_BEFORE), f(SIZE)) {
        d.add("size_before", Json::String(b));
    }
    if let Some(v) = nonempty(f(SIZE)) {
        d.add("size_after", Json::String(v.to_vec()));
    }
    if let Some(b) = print_before(f(PERM_BEFORE), f(PERM)) {
        if b.contains(&b'|') {
            match win_perm_to_json(&b) {
                Some(j) => {
                    d.add("win_perm_before", j);
                }
                None => log.warn("The old permissions of the Windows event could not be added to the JSON alert."),
            }
        } else {
            d.add("perm_before", Json::String(b));
        }
    }
    if let Some(v) = nonempty(f(PERM)) {
        if v.contains(&b'|') {
            match win_perm_to_json(v) {
                Some(j) => {
                    d.add("win_perm_after", j);
                }
                None => log.error("The new permissions could not be added to the JSON alert."),
            }
        } else {
            d.add("perm_after", Json::String(v.to_vec()));
        }
    }
    for (kb, ka, ib, ia) in [
        ("uid_before", "uid_after", UID_BEFORE, UID),
        ("gid_before", "gid_after", GID_BEFORE, GID),
        ("md5_before", "md5_after", MD5_BEFORE, MD5),
        ("sha1_before", "sha1_after", SHA1_BEFORE, SHA1),
        ("sha256_before", "sha256_after", SHA256_BEFORE, SHA256),
    ] {
        if let Some(b) = print_before(f(ib), f(ia)) {
            d.add(kb, Json::String(b));
        }
        if let Some(v) = nonempty(f(ia)) {
            d.add(ka, Json::String(v.to_vec()));
        }
    }
    if let Some(b) = print_before(f(ATTRS_BEFORE), f(ATTRS)) {
        d.add("attrs_before", attrs_to_json(&b));
    }
    if let Some(v) = nonempty(f(ATTRS)) {
        d.add("attrs_after", attrs_to_json(v));
    }
    for (kb, ka, ib, ia) in [("uname_before", "uname_after", UNAME_BEFORE, UNAME), ("gname_before", "gname_after", GNAME_BEFORE, GNAME)] {
        if let Some(b) = print_before(f(ib), f(ia)) {
            d.add(kb, Json::String(b));
        }
        if let Some(v) = nonempty(f(ia)) {
            d.add(ka, Json::String(v.to_vec()));
        }
    }
    let mut mtime_buf = [0u8; 25];
    if let Some(b) = print_before(f(MTIME_BEFORE), f(MTIME)) {
        d.add("mtime_before", Json::String(mtime_text(&mut mtime_buf, &b)));
    }
    if let Some(v) = nonempty(f(MTIME)) {
        d.add("mtime_after", Json::String(mtime_text(&mut mtime_buf, v)));
    }
    if let Some(b) = print_before(f(INODE_BEFORE), f(INODE)) {
        d.add("inode_before", Json::number(atol(&b) as i32 as f64));
    }
    if let Some(v) = f(INODE) {
        let n = atol(v) as i32;
        if n != 0 {
            d.add("inode_after", Json::number(n as f64));
        }
    }
    if order_size > DIFF {
        if let Some(v) = f(DIFF) {
            if v != b"0" {
                d.add("diff", Json::String(v.to_vec()));
            }
        }
    }
    if let Some(v) = nonempty(f(TAG)) {
        d.add("tags", split_tokens(v));
    }
    if let Some(v) = nonempty(f(CHFIELDS)) {
        d.add("changed_attributes", split_tokens(v));
    }
    if let Some(v) = f(EVENT_TYPE) {
        d.add("event", Json::String(v.to_vec()));
    }
    Some(d)
}

/// The whodata `audit` object (`None` when no field is set).
pub fn audit_section(ev: &Event) -> Option<Json> {
    use fim::*;
    let mk = |pairs: &[(&str, usize)]| -> Option<Json> {
        let mut o: Option<Json> = None;
        for (k, i) in pairs {
            if let Some(v) = nonempty(field(ev, *i)) {
                o.get_or_insert_with(Json::object).add(*k, Json::String(v.to_vec()));
            }
        }
        o
    };
    let user = mk(&[("id", USER_ID), ("name", USER_NAME)]);
    let group = mk(&[("id", GROUP_ID), ("name", GROUP_NAME)]);
    let process = mk(&[
        ("id", PROC_ID),
        ("name", PROC_NAME),
        ("cwd", AUDIT_CWD),
        ("parent_name", PROC_PNAME),
        ("parent_cwd", AUDIT_PCWD),
        ("ppid", PPID),
    ]);
    let auser = mk(&[("id", AUDIT_ID), ("name", AUDIT_NAME)]);
    let euser = mk(&[("id", EFFECTIVE_UID), ("name", EFFECTIVE_NAME)]);
    if user.is_none() && process.is_none() && group.is_none() && auser.is_none() && euser.is_none() {
        return None;
    }
    let mut a = Json::object();
    for (k, v) in [("user", user), ("process", process), ("group", group), ("login_user", auser), ("effective_user", euser)] {
        if let Some(v) = v {
            a.add(k, v);
        }
    }
    Some(a)
}
