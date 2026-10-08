//! The legacy checksum helpers of shared/syscheck_op.c used by wazuh-db
//! (`sk_decode_sum`, `sk_decode_extradata`, `sk_build_sum`). The decoding
//! is the same code as siem-analysisd's port of the file.

pub type B = Vec<u8>;

fn find(h: &[u8], c: u8) -> Option<usize> {
    h.iter().position(|&x| x == c)
}

/// `wstr_replace`
pub fn replace(s: &[u8], from: &[u8], to: &[u8]) -> B {
    if from.is_empty() {
        return s.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = s[i..].windows(from.len()).position(|w| w == from) {
        out.extend_from_slice(&s[i..i + p]);
        out.extend_from_slice(to);
        i += p + from.len();
    }
    out.extend_from_slice(&s[i..]);
    out
}

/// `escape_syscheck_field`
pub fn escape_field(s: &[u8]) -> B {
    let s = replace(s, b"!", b"\\!");
    let s = replace(&s, b":", b"\\:");
    replace(&s, b" ", b"\\ ")
}

/// `unescape_syscheck_field` (NULL for NULL or "")
pub fn unescape_field(s: Option<&[u8]>) -> Option<B> {
    let s = s?;
    if s.is_empty() {
        return None;
    }
    let s = replace(s, b"\\ ", b" ");
    let s = replace(&s, b"\\!", b"!");
    Some(replace(&s, b"\\:", b":"))
}

/// `normalize_path`
pub fn normalize_path(p: &mut [u8]) {
    if p.len() >= 2 && p[1] == b':' && p[0].is_ascii_alphabetic() {
        for c in p.iter_mut() {
            if *c == b'/' {
                *c = b'\\';
            }
        }
    }
}

/// `wstr_chr` (backslash escapes)
pub fn wstr_chr(s: &[u8], c: u8) -> Option<usize> {
    super::wstr_chr(s, c)
}

/// `atoi` / `atol` (`strtol` truncated like the C conversions)
pub fn atol(s: &[u8]) -> i64 {
    super::strtol(s)
}

pub fn atoi(s: &[u8]) -> i32 {
    atol(s) as i32
}

/// `(long)d` on x86-64 (out of range gives LONG_MIN)
pub fn c_long(d: f64) -> i64 {
    if d.is_finite() && d >= -9.223372036854776e18 && d < 9.223372036854776e18 {
        d as i64
    } else {
        i64::MIN
    }
}

/// `strtoul(s, NULL, 10)` as an `unsigned int`
fn strtoul_u32(s: &[u8]) -> u32 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: u64 = 0;
    let mut over = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((s[i] - b'0') as u64)) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    let v = if over {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    };
    v as u32
}

/// `sk_sum_wdata`
#[derive(Debug, Clone, Default)]
pub struct Wdata {
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

/// `sk_sum_t`
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
    pub wdata: Wdata,
}

/// `strchr`/`wstr_chr` split: Some((before, after)).
fn split(s: &[u8], esc: bool) -> Option<(B, B)> {
    let p = if esc { wstr_chr(s, b':') } else { find(s, b':') }?;
    Some((s[..p].to_vec(), s[p + 1..].to_vec()))
}

/// `sk_decode_sum`: 0 ok, 1 deleted ("-1"), -1 malformed. The C function
/// cuts its input in place; when a separator is missing the piece being
/// split keeps the rest of the string and the next field stays NULL. The
/// fields decoded before an error stay set (callers use them).
pub fn sk_decode_sum(sum: &mut Sum, c_sum: &[u8], w_sum: Option<&[u8]>) -> i32 {
    let mut retval = 0;
    if c_sum.len() >= 2 && c_sum[0] == b'-' && c_sum[1] == b'1' {
        retval = 1;
    } else {
        sum.size = Some(c_sum.to_vec());
        let Some((size, rest)) = split(c_sum, false) else { return -1 };
        sum.size = Some(size);
        // the uid separator is found with wstr_chr (escaped ':' in Windows perms)
        let Some((c_perm, uid_rest)) = split(&rest, true) else {
            sum.uid = None;
            return -1;
        };
        sum.uid = Some(uid_rest.clone());
        if c_perm.first() == Some(&b'|') {
            let unsc = unescape_field(Some(&c_perm)).unwrap_or_default();
            sum.win_perm = decode_win_permissions(&unsc);
        } else if c_perm.first() == Some(&b':') {
        } else if c_perm.first().is_some_and(|c| c.is_ascii_digit()) {
            sum.perm = atoi(&c_perm);
        } else {
            sum.win_perm = Some(c_perm.clone());
        }
        let Some((uid, gid_rest)) = split(&uid_rest, false) else { return -1 };
        sum.uid = Some(uid);
        sum.gid = Some(gid_rest.clone());
        let Some((gid, md5_rest)) = split(&gid_rest, false) else { return -1 };
        sum.gid = Some(gid);
        sum.md5 = Some(md5_rest.clone());
        let Some((md5, sha1_rest)) = split(&md5_rest, false) else { return -1 };
        sum.md5 = Some(md5);
        sum.sha1 = Some(sha1_rest.clone());
        if let Some((sha1, uname_rest)) = split(&sha1_rest, false) {
            sum.sha1 = Some(sha1);
            let Some((uname, gname_rest)) = split(&uname_rest, false) else {
                sum.gname = None;
                return -1;
            };
            sum.gname = Some(gname_rest.clone());
            sum.uname = Some(uname.iter().copied().filter(|&c| c != b'\\').collect());
            let Some((gname, mtime_rest)) = split(&gname_rest, false) else { return -1 };
            sum.gname = Some(gname);
            let Some((c_mtime, inode_rest)) = split(&mtime_rest, false) else { return -1 };
            sum.sha256 = None;
            if let Some((c_inode, sha_rest)) = split(&inode_rest, false) {
                sum.sha256 = Some(sha_rest.clone());
                if let Some((sha256, attrs)) = split(&sha_rest, false) {
                    sum.sha256 = Some(sha256);
                    if attrs.first().is_some_and(|c| c.is_ascii_digit()) {
                        sum.attributes = Some(decode_win_attributes(strtoul_u32(&attrs)));
                    } else {
                        sum.attributes = Some(attrs);
                    }
                }
                sum.mtime = atol(&c_mtime);
                sum.inode = atol(&c_inode);
            }
        }
    }

    if let Some(w) = w_sum {
        let w = w.to_vec();
        sum.wdata.user_id = Some(w.clone());
        let Some((user_id, user_name)) = split(&w, true) else { return -1 };
        sum.wdata.user_id = Some(user_id);
        let Some((user_name, r)) = split(&user_name, true) else {
            sum.wdata.group_id = None;
            return -1;
        };
        sum.wdata.group_id = Some(r.clone());
        let Some((group_id, r)) = split(&r, true) else { return -1 };
        sum.wdata.group_id = Some(group_id);
        sum.wdata.group_name = Some(r.clone());
        let Some((group_name, process_rest)) = split(&r, true) else { return -1 };
        sum.wdata.group_name = Some(group_name);
        let Some((process_name, r)) = split(&process_rest, true) else {
            sum.wdata.audit_uid = None;
            return -1;
        };
        sum.wdata.audit_uid = Some(r.clone());
        let Some((audit_uid, r)) = split(&r, true) else { return -1 };
        sum.wdata.audit_uid = Some(audit_uid);
        sum.wdata.audit_name = Some(r.clone());
        let Some((audit_name, r)) = split(&r, true) else { return -1 };
        sum.wdata.audit_name = Some(audit_name);
        sum.wdata.effective_uid = Some(r.clone());
        let Some((effective_uid, r)) = split(&r, true) else { return -1 };
        sum.wdata.effective_uid = Some(effective_uid);
        sum.wdata.effective_name = Some(r.clone());
        let Some((effective_name, r)) = split(&r, true) else { return -1 };
        sum.wdata.effective_name = Some(effective_name);
        sum.wdata.ppid = Some(r.clone());
        let Some((ppid, r)) = split(&r, true) else { return -1 };
        sum.wdata.ppid = Some(ppid);
        sum.wdata.process_id = Some(r.clone());
        // process_id[:tag[:symbolic_path[:silent]]]
        sum.tag = None;
        let mut symbolic_path: Option<B> = None;
        if let Some((process_id, tag)) = split(&r, true) {
            sum.wdata.process_id = Some(process_id);
            sum.tag = Some(tag.clone());
            if let Some((tag, sp)) = split(&tag, true) {
                sum.tag = Some(tag);
                symbolic_path = Some(sp.clone());
                if let Some((sp, silent)) = split(&sp, true) {
                    symbolic_path = Some(sp);
                    if silent.first() == Some(&b'+') {
                        sum.silent = true;
                    }
                }
            }
        }
        sum.symbolic_path = unescape_field(symbolic_path.as_deref());
        sum.wdata.user_name = unescape_field(Some(&user_name));
        sum.wdata.process_name = unescape_field(Some(&process_name));
        if sum.wdata.ppid.as_deref().and_then(|p| p.first()) == Some(&b'-') {
            sum.wdata.ppid = None;
        }
    }
    retval
}

/// `sk_decode_extradata`: the part of `c_sum` before '!' (the C function
/// cuts the string there), and whether the extra data was found.
pub fn sk_decode_extradata(sum: &mut Sum, c_sum: &[u8]) -> (B, bool) {
    let Some(p) = find(c_sum, b'!') else {
        return (c_sum.to_vec(), false);
    };
    let head = c_sum[..p].to_vec();
    let changes = &c_sum[p + 1..];
    let Some(d) = find(changes, b':') else {
        return (head, false);
    };
    let (changes, date_alert) = (&changes[..d], &changes[d + 1..]);
    let date_alert = match find(date_alert, b':') {
        Some(s) => {
            sum.symbolic_path = unescape_field(Some(&date_alert[s + 1..]));
            &date_alert[..s]
        }
        None => date_alert,
    };
    sum.changes = atoi(changes);
    sum.date_alert = atol(date_alert);
    (head, true)
}

/// `printf("%s", s)` of a possibly NULL string.
fn pz(s: &Option<B>) -> &[u8] {
    match s {
        Some(v) => v,
        None => b"(null)",
    }
}

/// `sk_build_sum`: the legacy checksum string, or None when it does not
/// fit `size` bytes (-1).
pub fn sk_build_sum(sum: &Sum, size: usize) -> Option<B> {
    let s_perm: B = if sum.perm != 0 { sum.perm.to_string().into_bytes() } else { Vec::new() };
    let s_mtime = trunc16(sum.mtime.to_string().into_bytes());
    let s_inode = trunc16(sum.inode.to_string().into_bytes());
    let username = sum.uname.as_ref().map(|u| replace(u, b" ", b"\\ "));
    let win_perm = sum.win_perm.as_ref().map(|w| replace(w, b":", b"\\:"));
    let mut r: B = Vec::new();
    r.extend_from_slice(pz(&sum.size));
    r.push(b':');
    match &win_perm {
        Some(w) => r.extend_from_slice(w),
        None => r.extend_from_slice(&s_perm),
    }
    for f in [&sum.uid, &sum.gid, &sum.md5, &sum.sha1] {
        r.push(b':');
        r.extend_from_slice(pz(f));
    }
    r.push(b':');
    if sum.uname.is_some() {
        r.extend_from_slice(username.as_deref().unwrap_or(b""));
    }
    r.push(b':');
    r.extend_from_slice(sum.gname.as_deref().unwrap_or(b""));
    r.push(b':');
    if sum.mtime != 0 {
        r.extend_from_slice(&s_mtime);
    }
    r.push(b':');
    if sum.inode != 0 {
        r.extend_from_slice(&s_inode);
    }
    r.push(b':');
    r.extend_from_slice(sum.sha256.as_deref().unwrap_or(b""));
    r.push(b':');
    r.extend_from_slice(sum.attributes.as_deref().unwrap_or(b""));
    r.extend_from_slice(format!("!{}:{}", sum.changes, sum.date_alert).as_bytes());
    if r.len() < size {
        Some(r)
    } else {
        None
    }
}

/// `snprintf(buf, 16, "%ld", v)`
fn trunc16(mut v: B) -> B {
    v.truncate(15);
    v
}

pub use super::upgrade::decode_win_attributes;

const PERMS: &[(i64, &str)] = &[
    (0x80000000, "generic_read|"),
    (0x40000000, "generic_write|"),
    (0x20000000, "generic_execute|"),
    (0x10000000, "generic_all|"),
    (0x00010000, "delete|"),
    (0x00020000, "read_control|"),
    (0x00040000, "write_dac|"),
    (0x00080000, "write_owner|"),
    (0x00100000, "synchronize|"),
    (0x00000001, "read_data|"),
    (0x00000002, "write_data|"),
    (0x00000004, "append_data|"),
    (0x00000008, "read_ea|"),
    (0x00000010, "write_ea|"),
    (0x00000020, "execute|"),
    (0x00000080, "read_attributes|"),
    (0x00000100, "write_attributes|"),
];

/// `MAX_WIN_PERM_SIZE`
const MAX_WIN_PERM_SIZE: usize = 20480;

/// `decode_win_permissions` (NULL on a malformed list), over a buffer of
/// `MAX_WIN_PERM_SIZE` bytes like the C code.
pub fn decode_win_permissions(raw: &[u8]) -> Option<B> {
    if raw.first() != Some(&b'|') {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; MAX_WIN_PERM_SIZE + 64];
    let mut it: usize = 0; // decoded_it
    let mut perm_size: i64 = MAX_WIN_PERM_SIZE as i64;
    let mut written: i64 = 0;
    let mut size: i64 = 0;
    let end = raw.len();
    let mut p = 0usize; // perm_it
    loop {
        let Some(q) = raw[p..].iter().position(|&c| c == b'|').map(|x| x + p) else { break };
        p = q;
        if end - p < 3 {
            return None;
        }
        p += 1;
        let base = p;
        let Some(c) = raw[p..].iter().position(|&c| c == b',').map(|x| x + p) else { return None };
        let account = &raw[base..c];
        p = c + 1;
        let base = p;
        let Some(c2) = raw[p..].iter().position(|&c| c == b',').map(|x| x + p) else { return None };
        let a_type = raw.get(base).copied().unwrap_or(0);
        p = c2 + 1;
        let base = p;
        let next_bar = raw[p..].iter().position(|&c| c == b'|').map(|x| x + p);
        let mask = match next_bar {
            Some(nb) => super::strtol(&raw[base..nb]),
            None => super::strtol(&raw[base..]),
        };
        let mut text = account.to_vec();
        text.extend_from_slice(if a_type == b'0' { b" (allowed): " } else { b" (denied): " });
        for (bit, name) in PERMS {
            if mask & bit != 0 {
                text.extend_from_slice(name.as_bytes());
            }
        }
        size = text.len() as i64;
        if size > perm_size {
            match next_bar {
                Some(nb) => {
                    p = nb;
                    continue;
                }
                None => break,
            }
        }
        // snprintf(decoded_it, perm_size, ...)
        if perm_size > 0 {
            let n = (size as usize).min(perm_size as usize - 1);
            buf[it..it + n].copy_from_slice(&text[..n]);
            buf[it + n] = 0;
        }
        if size + 1 < perm_size {
            // strncpy(decoded_it + (size++) - 1, ", ", 3)
            let at = it + size as usize - 1;
            buf[at] = b',';
            buf[at + 1] = b' ';
            buf[at + 2] = 0;
            size += 1;
        }
        written += size;
        it += size as usize;
        perm_size -= size;
        match next_bar {
            Some(nb) => p = nb,
            None => break,
        }
    }
    let _ = written;
    if it >= 2 && size > 1 {
        buf[it - 2] = 0;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    buf.truncate(n);
    Some(buf)
}
