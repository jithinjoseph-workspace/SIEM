//! Port of the small string helpers in `src/os_regex/` (`os_regex_str.c`,
//! `os_regex_startswith.c`, `os_regex_strbreak.c`).

/// `OS_StrIsNum`: every byte is an ASCII digit (an empty string is numeric).
pub fn str_is_num(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
}

/// `OS_StrStartsWith`: case-sensitive prefix test.
pub fn str_starts_with(s: &str, pattern: &str) -> bool {
    s.as_bytes().starts_with(pattern.as_bytes())
}

/// `OS_StrHowClosedMatch`: length of the common prefix.
pub fn str_how_closed_match(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut count = 0usize;
    loop {
        let ca = a.get(count).copied().unwrap_or(0);
        let cb = b.get(count).copied().unwrap_or(0);
        if ca != cb {
            break;
        }
        count += 1;
        if a.get(count).copied().unwrap_or(0) == 0 || b.get(count).copied().unwrap_or(0) == 0 {
            break;
        }
    }
    count
}

/// `OS_StrBreak`: split `s` on `sep` into at most `size` pieces. A separator
/// preceded by `\` is kept literally (the backslash is removed) except inside
/// the last piece. Returns `None` when `size == 0`.
pub fn str_break(sep: char, s: &str, size: usize) -> Option<Vec<String>> {
    let v = str_break_bytes(sep as u32 as u8, s.as_bytes(), size)?;
    Some(v.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect())
}

/// [`str_break`] on bytes (C strings: the input ends at the first NUL).
pub fn str_break_bytes(sep: u8, s: &[u8], size: usize) -> Option<Vec<Vec<u8>>> {
    if size == 0 {
        return None;
    }
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut prev: Option<u8> = None;
    for &c in s {
        if out.len() < size - 1 && c == sep {
            if prev == Some(b'\\') {
                cur.pop();
                cur.push(c);
                prev = Some(c);
                continue;
            }
            out.push(std::mem::take(&mut cur));
            prev = Some(c);
            continue;
        }
        cur.push(c);
        prev = Some(c);
    }
    out.push(cur);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strbreak_basic() {
        assert_eq!(str_break(',', "a,b,c", 5).unwrap(), vec!["a", "b", "c"]);
        assert_eq!(str_break(',', "a,b,c", 2).unwrap(), vec!["a", "b,c"]);
        assert_eq!(str_break(':', r"a\:b:c", 3).unwrap(), vec!["a:b", "c"]);
        assert_eq!(str_break(',', "", 3).unwrap(), vec![""]);
        assert!(str_break(',', "a", 0).is_none());
    }

    #[test]
    fn closed_match() {
        assert_eq!(str_how_closed_match("abcd", "abxy"), 2);
        assert_eq!(str_how_closed_match("abc", "abc"), 3);
        assert_eq!(str_how_closed_match("", "abc"), 0);
    }
}
