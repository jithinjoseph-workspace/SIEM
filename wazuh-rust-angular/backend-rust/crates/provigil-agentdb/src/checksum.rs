//! The FIM checksum text of the old protocol (spec § 2.1): `size:perm:uid:gid:md5:sha1[:uname:
//! gname:mtime:inode[:sha256[:attributes]]]` with `!changes:date[:symbolic_path]` after it.

use crate::text::{find_unescaped, read_long, read_ulong};

/// The fields of one checksum.
#[derive(Debug, Clone, Default)]
pub struct Sum {
    pub size: Option<Vec<u8>>,
    pub perm: i32,
    pub win_perm: Option<Vec<u8>>,
    pub uid: Option<Vec<u8>>,
    pub gid: Option<Vec<u8>>,
    pub md5: Option<Vec<u8>>,
    pub sha1: Option<Vec<u8>>,
    pub sha256: Option<Vec<u8>>,
    pub attributes: Option<Vec<u8>>,
    pub uname: Option<Vec<u8>>,
    pub gname: Option<Vec<u8>>,
    pub mtime: i64,
    pub inode: i64,
    pub symbolic_path: Option<Vec<u8>>,
    pub changes: i32,
    pub date_alert: i64,
}

/// Every `from` replaced by `to`.
pub fn replace(s: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    crate::sca::replace(s, from, to)
}

/// `\ `, `\!` and `\:` back to plain characters (None for none or empty).
pub fn unescape(s: Option<&[u8]>) -> Option<Vec<u8>> {
    let s = s.filter(|s| !s.is_empty())?;
    Some(replace(&replace(&replace(s, b"\\ ", b" "), b"\\!", b"!"), b"\\:", b":"))
}

/// Splits at the first `:` (escaped ones skipped when `esc`).
fn split(s: &[u8], esc: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    let p = if esc { find_unescaped(s, b':') } else { s.iter().position(|&c| c == b':') }?;
    Some((s[..p].to_vec(), s[p + 1..].to_vec()))
}

/// Decodes the checksum part: 0 ok, 1 deleted (`-1`), -1 malformed. Fields read before an
/// error stay set; when a separator is missing the field being split keeps the rest.
pub fn decode(sum: &mut Sum, c: &[u8]) -> i32 {
    if c.len() >= 2 && c[0] == b'-' && c[1] == b'1' {
        return 1;
    }
    sum.size = Some(c.to_vec());
    let Some((size, rest)) = split(c, false) else { return -1 };
    sum.size = Some(size);
    // Windows permissions may hold escaped ':'
    let Some((perm, rest)) = split(&rest, true) else {
        sum.uid = None;
        return -1;
    };
    sum.uid = Some(rest.clone());
    match perm.first() {
        Some(b'|') => sum.win_perm = windows_permissions(&unescape(Some(&perm)).unwrap_or_default()),
        Some(b':') => {}
        Some(c) if c.is_ascii_digit() => sum.perm = read_long(&perm).0 as i32,
        _ => sum.win_perm = Some(perm),
    }
    let Some((uid, rest)) = split(&rest, false) else { return -1 };
    sum.uid = Some(uid);
    sum.gid = Some(rest.clone());
    let Some((gid, rest)) = split(&rest, false) else { return -1 };
    sum.gid = Some(gid);
    sum.md5 = Some(rest.clone());
    let Some((md5, rest)) = split(&rest, false) else { return -1 };
    sum.md5 = Some(md5);
    sum.sha1 = Some(rest.clone());
    let Some((sha1, rest)) = split(&rest, false) else { return 0 };
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
            sum.attributes = Some(if attrs.first().is_some_and(|c| c.is_ascii_digit()) { windows_attributes(read_ulong(&attrs) as u32) } else { attrs });
        }
        sum.mtime = read_long(&mtime).0;
        sum.inode = read_long(&inode).0;
    }
    0
}

/// The part before `!` and, after it, `changes:date[:symbolic_path]`.
pub fn split_extra(sum: &mut Sum, c: &[u8]) -> Vec<u8> {
    let Some(p) = c.iter().position(|&x| x == b'!') else { return c.to_vec() };
    let head = c[..p].to_vec();
    let extra = &c[p + 1..];
    let Some(d) = extra.iter().position(|&x| x == b':') else { return head };
    let (changes, date) = (&extra[..d], &extra[d + 1..]);
    let date = match date.iter().position(|&x| x == b':') {
        Some(s) => {
            sum.symbolic_path = unescape(Some(&date[s + 1..]));
            &date[..s]
        }
        None => date,
    };
    sum.changes = read_long(changes).0 as i32;
    sum.date_alert = read_long(date).0;
    head
}

/// The checksum text of a stored entry, or None when it would not fit `size` bytes.
pub fn build(sum: &Sum, size: usize) -> Option<Vec<u8>> {
    let null = |s: &Option<Vec<u8>>| s.clone().unwrap_or_else(|| b"(null)".to_vec());
    let short = |v: i64| {
        let mut s = v.to_string().into_bytes();
        s.truncate(15);
        s
    };
    let mut r = null(&sum.size);
    r.push(b':');
    match &sum.win_perm {
        Some(w) => r.extend(replace(w, b":", b"\\:")),
        None if sum.perm != 0 => r.extend(sum.perm.to_string().into_bytes()),
        None => {}
    }
    for f in [&sum.uid, &sum.gid, &sum.md5, &sum.sha1] {
        r.push(b':');
        r.extend(null(f));
    }
    r.push(b':');
    if let Some(u) = &sum.uname {
        r.extend(replace(u, b" ", b"\\ "));
    }
    r.push(b':');
    r.extend(sum.gname.clone().unwrap_or_default());
    r.push(b':');
    if sum.mtime != 0 {
        r.extend(short(sum.mtime));
    }
    r.push(b':');
    if sum.inode != 0 {
        r.extend(short(sum.inode));
    }
    r.push(b':');
    r.extend(sum.sha256.clone().unwrap_or_default());
    r.push(b':');
    r.extend(sum.attributes.clone().unwrap_or_default());
    r.extend(format!("!{}:{}", sum.changes, sum.date_alert).into_bytes());
    (r.len() < size).then_some(r)
}

/// Windows file attribute flags as names (`ARCHIVE, HIDDEN`).
pub fn windows_attributes(a: u32) -> Vec<u8> {
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
    let mut s: Vec<u8> = NAMES.iter().filter(|(b, _)| a & b != 0).flat_map(|(_, n)| format!("{n}, ").into_bytes()).collect();
    let full = s.len();
    s.truncate(255);
    if full > 2 {
        s.truncate(full - 2);
    }
    s
}

/// Room for the decoded permission list.
const PERM_ROOM: i64 = 20480;

/// A Windows permission list `|account,type,mask|…` as text
/// (`account (allowed): read_data|write_data, other (denied): …`); None when malformed.
pub fn windows_permissions(raw: &[u8]) -> Option<Vec<u8>> {
    const BITS: [(i64, &str); 17] = [
        (0x80000000, "generic_read"),
        (0x40000000, "generic_write"),
        (0x20000000, "generic_execute"),
        (0x10000000, "generic_all"),
        (0x00010000, "delete"),
        (0x00020000, "read_control"),
        (0x00040000, "write_dac"),
        (0x00080000, "write_owner"),
        (0x00100000, "synchronize"),
        (0x00000001, "read_data"),
        (0x00000002, "write_data"),
        (0x00000004, "append_data"),
        (0x00000008, "read_ea"),
        (0x00000010, "write_ea"),
        (0x00000020, "execute"),
        (0x00000080, "read_attributes"),
        (0x00000100, "write_attributes"),
    ];
    if raw.first() != Some(&b'|') {
        return Some(Vec::new());
    }
    // a fixed-size zeroed text buffer, written the way the list was always built: each entry is
    // cut to the room left, its last character turned into ", " when there is room, and an
    // entry larger than the room is skipped
    let mut buf = vec![0u8; PERM_ROOM as usize + 64];
    let (mut at, mut room, mut size) = (0usize, PERM_ROOM, 0i64);
    let mut p = 0usize;
    while let Some(q) = raw[p..].iter().position(|&c| c == b'|') {
        p += q;
        if raw.len() - p < 3 {
            return None;
        }
        p += 1;
        let c1 = p + raw[p..].iter().position(|&c| c == b',')?;
        let account = &raw[p..c1];
        p = c1 + 1;
        let c2 = p + raw[p..].iter().position(|&c| c == b',')?;
        let allowed = raw.get(p) == Some(&b'0');
        p = c2 + 1;
        let next = raw[p..].iter().position(|&c| c == b'|').map(|x| x + p);
        let mask = read_long(&raw[p..next.unwrap_or(raw.len())]).0;
        let mut text = account.to_vec();
        text.extend_from_slice(if allowed { b" (allowed): " } else { b" (denied): " });
        for (bit, n) in BITS {
            if mask & bit != 0 {
                text.extend_from_slice(n.as_bytes());
                text.push(b'|');
            }
        }
        size = text.len() as i64;
        if size > room {
            match next {
                Some(n) => {
                    p = n;
                    continue;
                }
                None => break,
            }
        }
        if room > 0 {
            let n = (size as usize).min(room as usize - 1);
            buf[at..at + n].copy_from_slice(&text[..n]);
            buf[at + n] = 0;
        }
        if size + 1 < room {
            let c = at + size as usize - 1;
            buf[c] = b',';
            buf[c + 1] = b' ';
            buf[c + 2] = 0;
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
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    buf.truncate(end);
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_and_attributes() {
        assert_eq!(windows_attributes(0x22), b"ARCHIVE, HIDDEN".to_vec());
        assert_eq!(windows_attributes(0), Vec::<u8>::new());
        assert_eq!(windows_permissions(b"|S-1,0,3|S-2,1,32").unwrap(), b"S-1 (allowed): read_data|write_data, S-2 (denied): execute".to_vec());
        assert_eq!(windows_permissions(b"x").unwrap(), Vec::<u8>::new());
        assert!(windows_permissions(b"|ab").is_none());
    }
}
