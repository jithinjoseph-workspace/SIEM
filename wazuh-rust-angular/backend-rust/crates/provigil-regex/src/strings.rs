pub fn str_is_num(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
}

/// The separator is the low byte of the character's code, on purpose.
pub fn str_break(sep: char, s: &str, size: usize) -> Option<Vec<String>> {
    let pieces = str_break_bytes(sep as u32 as u8, s.as_bytes(), size)?;
    Some(pieces.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect())
}

pub fn str_break_bytes(sep: u8, s: &[u8], size: usize) -> Option<Vec<Vec<u8>>> {
    if size == 0 {
        return None;
    }
    let s = crate::until_nul(s);
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if out.len() + 1 == size {
            cur.extend_from_slice(&s[i..]);
            break;
        }
        if s[i] != sep {
            cur.push(s[i]);
        } else if i > 0 && s[i - 1] == b'\\' {
            if cur.last() == Some(&b'\\') {
                cur.pop();
            }
            cur.push(sep);
        } else {
            out.push(std::mem::take(&mut cur));
        }
        i += 1;
    }
    out.push(cur);
    Some(out)
}

/// Byte prefix test (no NUL handling).
pub fn str_starts_with(s: &str, prefix: &str) -> bool {
    s.as_bytes().starts_with(prefix.as_bytes())
}

/// Length of the common start of two texts, each read up to a NUL. Two empty texts give 1.
pub fn str_how_closed_match(a: &str, b: &str) -> usize {
    let (a, b) = (crate::until_nul(a.as_bytes()), crate::until_nul(b.as_bytes()));
    if a.is_empty() && b.is_empty() {
        return 1;
    }
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}
