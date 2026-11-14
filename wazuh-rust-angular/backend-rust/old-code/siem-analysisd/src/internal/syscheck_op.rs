//! The manager side of shared/syscheck_op.c: legacy checksum decoding
//! (`sk_decode_sum`, `sk_decode_extradata`), `sk_fill_event`, Windows
//! attributes / permissions decoding and the field escaping helpers.

use crate::syscheck_json::fim;

pub type B = Vec<u8>;

fn find(h: &[u8], c: u8) -> Option<usize> {
    h.iter().position(|&x| x == c)
}

/// `wstr_replace`
pub fn replace(s: &[u8], from: &[u8], to: &[u8]) -> B {
    crate::output::search_and_replace(s, from, to)
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
    crate::internal::rootcheck::wstr_chr(s, c)
}

/// `atoi` / `atol` (`strtol` truncated like the C conversions)
pub fn atol(s: &[u8]) -> i64 {
    crate::internal::rootcheck::strtol(s)
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

/// `w_long_str`
pub fn long_str(v: i64) -> B {
    v.to_string().into_bytes()
}

/// `sk_fill_event`: the values set on the FIM fields.
pub fn sk_fill_event(vals: &mut [Option<B>], f_name: &[u8], sum: &Sum) {
    vals[fim::FILE] = Some(f_name.to_vec());
    if let Some(s) = &sum.size {
        vals[fim::SIZE] = Some(s.clone());
    }
    if sum.perm != 0 {
        // snprintf(.., 7, "%06o", perm)
        let mut p = format!("{:06o}", sum.perm as u32).into_bytes();
        p.truncate(6);
        vals[fim::PERM] = Some(p);
    } else if let Some(w) = sum.win_perm.as_ref().filter(|w| !w.is_empty()) {
        vals[fim::PERM] = Some(w.clone());
    }
    let set = |vals: &mut [Option<B>], i: usize, v: &Option<B>| {
        if let Some(v) = v {
            vals[i] = Some(v.clone());
        }
    };
    set(vals, fim::UID, &sum.uid);
    set(vals, fim::GID, &sum.gid);
    set(vals, fim::MD5, &sum.md5);
    set(vals, fim::SHA1, &sum.sha1);
    set(vals, fim::UNAME, &sum.uname);
    set(vals, fim::GNAME, &sum.gname);
    if sum.mtime != 0 {
        vals[fim::MTIME] = Some(long_str(sum.mtime));
    }
    if sum.inode != 0 {
        vals[fim::INODE] = Some(long_str(sum.inode));
    }
    set(vals, fim::SHA256, &sum.sha256);
    set(vals, fim::ATTRS, &sum.attributes);
    let w = &sum.wdata;
    set(vals, fim::USER_ID, &w.user_id);
    set(vals, fim::USER_NAME, &w.user_name);
    set(vals, fim::GROUP_ID, &w.group_id);
    set(vals, fim::GROUP_NAME, &w.group_name);
    set(vals, fim::PROC_NAME, &w.process_name);
    set(vals, fim::PROC_PNAME, &w.parent_name);
    set(vals, fim::AUDIT_CWD, &w.cwd);
    set(vals, fim::AUDIT_PCWD, &w.parent_cwd);
    set(vals, fim::AUDIT_ID, &w.audit_uid);
    set(vals, fim::AUDIT_NAME, &w.audit_name);
    set(vals, fim::EFFECTIVE_UID, &w.effective_uid);
    set(vals, fim::EFFECTIVE_NAME, &w.effective_name);
    set(vals, fim::PPID, &w.ppid);
    set(vals, fim::PROC_ID, &w.process_id);
    set(vals, fim::TAG, &sum.tag);
    set(vals, fim::SYM_PATH, &sum.symbolic_path);
}

/// `decode_win_attributes`
pub fn decode_win_attributes(attrs: u32) -> B {
    const A: &[(u32, &str)] = &[
        (0x20, "ARCHIVE, "),
        (0x800, "COMPRESSED, "),
        (0x40, "DEVICE, "),
        (0x10, "DIRECTORY, "),
        (0x4000, "ENCRYPTED, "),
        (0x2, "HIDDEN, "),
        (0x8000, "INTEGRITY_STREAM, "),
        (0x80, "NORMAL, "),
        (0x2000, "NOT_CONTENT_INDEXED, "),
        (0x20000, "NO_SCRUB_DATA, "),
        (0x1000, "OFFLINE, "),
        (0x1, "READONLY, "),
        (0x400000, "RECALL_ON_DATA_ACCESS, "),
        (0x40000, "RECALL_ON_OPEN, "),
        (0x400, "REPARSE_POINT, "),
        (0x200, "SPARSE_FILE, "),
        (0x4, "SYSTEM, "),
        (0x100, "TEMPORARY, "),
        (0x10000, "VIRTUAL, "),
    ];
    let mut s: B = A.iter().filter(|(b, _)| attrs & b != 0).flat_map(|(_, n)| n.bytes()).collect();
    // snprintf(str, OS_SIZE_256, ...)
    let size = s.len();
    s.truncate(255);
    if size > 2 {
        s.truncate(size - 2);
    }
    s
}

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
            Some(nb) => crate::internal::rootcheck::strtol(&raw[base..nb]),
            None => crate::internal::rootcheck::strtol(&raw[base..]),
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

/// `agent_file_perm`
pub fn agent_file_perm(mode: i32) -> B {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win_perms() {
        assert_eq!(
            decode_win_permissions(b"|account,0,4|other,1,2147483648").unwrap(),
            b"account (allowed): append_data, other (denied): generic_read".to_vec()
        );
        assert_eq!(decode_win_permissions(b"|a,0,0").unwrap(), b"a (allowed):".to_vec());
        assert_eq!(decode_win_permissions(b"x").unwrap(), b"".to_vec());
        assert!(decode_win_permissions(b"|a").is_none());
    }

    #[test]
    fn attrs_and_perms() {
        assert_eq!(decode_win_attributes(0x21), b"ARCHIVE, READONLY".to_vec());
        assert_eq!(decode_win_attributes(0), b"".to_vec());
        assert_eq!(agent_file_perm(0o104755), b"rwsr-xr-x".to_vec());
    }

    #[test]
    fn sums() {
        let mut s = Sum::default();
        let r = sk_decode_sum(&mut s, b"107:33188:0:0:abc:def:root:root:1600000000:123:sha:32", Some(b"0:root:0:root:/bin/x:0:root:0:root:1:2:tag:/sym\\:x:+"));
        assert_eq!(r, 0);
        assert_eq!(s.perm, 33188);
        assert_eq!(s.sha256.as_deref(), Some(&b"sha"[..]));
        assert_eq!(s.attributes.as_deref(), Some(&b"ARCHIVE"[..]));
        assert_eq!(s.inode, 123);
        assert_eq!(s.symbolic_path.as_deref(), Some(&b"/sym:x"[..]));
        assert!(s.silent);
        let mut s = Sum::default();
        assert_eq!(sk_decode_sum(&mut s, b"1:2:3:4:5:6", None), 0);
        assert_eq!(s.mtime, 0);
    }
}
