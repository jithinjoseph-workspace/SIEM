//! Small text rules of the request protocol (spec § 1): answer size, the "near" error form,
//! numbers read the way the clients expect, and splitting on unescaped spaces.

/// Longest answer text (bytes); longer answers are cut.
pub const MAX_ANSWER: usize = 65536;

/// The answer cut to its maximum length.
pub fn answer(mut v: Vec<u8>) -> Vec<u8> {
    v.truncate(MAX_ANSWER);
    v
}

/// Joins answer or log parts.
#[macro_export]
macro_rules! cat {
    ($($p:expr),* $(,)?) => {{
        let mut v: Vec<u8> = Vec::new();
        $( $crate::text::Part::put(&$p, &mut v); )*
        v
    }};
}

/// Something that can be written into an answer or log line.
pub trait Part {
    fn put(&self, out: &mut Vec<u8>);
}
impl Part for &str {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}
impl Part for String {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}
impl Part for &[u8] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Part for Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Part for &Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Part for i32 {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_string().as_bytes());
    }
}
impl Part for i64 {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_string().as_bytes());
    }
}
impl Part for usize {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_string().as_bytes());
    }
}

/// The text up to the first NUL byte.
pub fn until_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// At most the first 32 bytes, as error answers quote the request.
pub fn first32(b: &[u8]) -> &[u8] {
    let b = until_nul(b);
    &b[..b.len().min(32)]
}

/// `<prefix>, near '<first 32 bytes>'`
pub fn near(prefix: &str, s: &[u8]) -> Vec<u8> {
    answer(cat!(prefix, ", near '", first32(s), "'"))
}

/// A decimal number the way clients' numbers are read: leading white space, an optional sign,
/// digits; anything else ends it. Saturates at the 64-bit limits. Also returns where it ended
/// (0 when no digit was read).
pub fn read_long(s: &[u8]) -> (i64, usize) {
    let s = until_nul(s);
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: i64 = 0;
    let mut over = false;
    while i < s.len() && s[i].is_ascii_digit() {
        let d = (s[i] - b'0') as i64;
        match v.checked_mul(10).and_then(|x| if neg { x.checked_sub(d) } else { x.checked_add(d) }) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    if over {
        v = if neg { i64::MIN } else { i64::MAX };
    }
    (v, i)
}

/// A number as `read_long`, cut to 32 bits like the clients' integer fields.
pub fn read_int(s: &[u8]) -> i32 {
    read_long(s).0 as i32
}

/// An unsigned number: like `read_long`, a leading `-` wraps around 2^64, overflow is the maximum.
pub fn read_ulong(s: &[u8]) -> u64 {
    let s = until_nul(s);
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
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
    if over {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    }
}

/// Position of the first `c` that is not escaped with a backslash.
pub fn find_unescaped(s: &[u8], c: u8) -> Option<usize> {
    let mut escaped = false;
    for (i, &ch) in s.iter().enumerate() {
        if ch == 0 {
            return None;
        }
        if escaped {
            escaped = false;
        } else if ch == c {
            return Some(i);
        } else if ch == b'\\' {
            escaped = true;
        }
    }
    None
}

/// Splits at the first unescaped space: (word, rest after the space).
pub fn split_word(s: &[u8]) -> (&[u8], Option<&[u8]>) {
    match find_unescaped(s, b' ') {
        Some(p) => (&s[..p], Some(&s[p + 1..])),
        None => (s, None),
    }
}

/// Space-separated tokens, empty ones skipped (as tokenizing on spaces does).
pub fn tokens(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    s.split(|&c| c == b' ').filter(|t| !t.is_empty())
}

/// An agent id with at least three digits.
pub fn id3(id: i32) -> String {
    format!("{id:03}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_and_splitting() {
        assert_eq!(read_long(b"  -12x"), (-12, 5));
        assert_eq!(read_long(b"x"), (0, 0));
        assert_eq!(read_long(b"99999999999999999999").0, i64::MAX);
        assert_eq!(read_ulong(b"-1"), u64::MAX);
        assert_eq!(read_ulong(b"99999999999999999999"), u64::MAX);
        assert_eq!(split_word(b"a\\ b c"), (&b"a\\ b"[..], Some(&b"c"[..])));
        assert_eq!(near("err X", b"0123456789012345678901234567890123456789"), b"err X, near '01234567890123456789012345678901'".to_vec());
        assert_eq!(tokens(b"  a  b ").collect::<Vec<_>>(), vec![&b"a"[..], &b"b"[..]]);
    }
}
