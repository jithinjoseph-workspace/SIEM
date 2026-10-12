//! `stringHelper.h`, `globHelper.h` and the time helpers the providers use.

/// `Utils::rightTrim(str, args)`
pub fn right_trim<'a>(s: &'a str, args: &str) -> &'a str {
    match s.rfind(|c: char| !args.contains(c)) {
        Some(p) => &s[..p + s[p..].chars().next().map(|c| c.len_utf8()).unwrap_or(1)],
        None => "",
    }
}

/// `Utils::leftTrim(str, args)`
pub fn left_trim<'a>(s: &'a str, args: &str) -> &'a str {
    match s.find(|c: char| !args.contains(c)) {
        Some(p) => &s[p..],
        None => "",
    }
}

/// `Utils::trim(str, args = " ")`
pub fn trim<'a>(s: &'a str, args: &str) -> &'a str {
    left_trim(right_trim(s, args), args)
}

/// `Utils::trim` on bytes (the C++ works on bytes; args are ASCII).
pub fn trim_bytes<'a>(s: &'a [u8], args: &[u8]) -> &'a [u8] {
    let end = s.iter().rposition(|c| !args.contains(c)).map(|p| p + 1).unwrap_or(0);
    let s = &s[..end];
    let start = s.iter().position(|c| !args.contains(c)).unwrap_or(s.len());
    &s[start..]
}

/// `Utils::split(str, delimiter)` (std::getline: no trailing empty token).
pub fn split(s: &str, d: char) -> Vec<String> {
    let mut v: Vec<String> = s.split(d).map(String::from).collect();
    if v.last().is_some_and(|l| l.is_empty()) {
        v.pop();
    }
    v
}

/// `Utils::startsWith`
pub fn starts_with(s: &str, start: &str) -> bool {
    !s.is_empty() && s.len() >= start.len() && s.as_bytes().starts_with(start.as_bytes())
}

/// `Utils::endsWith`
pub fn ends_with(s: &str, ending: &str) -> bool {
    !s.is_empty() && s.len() >= ending.len() && s.as_bytes().ends_with(ending.as_bytes())
}

/// `Utils::isNumber`
pub fn is_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// `Utils::toUpperCase` (`std::toupper` in the "C" locale)
pub fn to_upper(s: &str) -> String {
    s.to_ascii_uppercase()
}

/// `Utils::toLowerCase`
pub fn to_lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// `Utils::replaceAll`
pub fn replace_all(data: &mut String, search: &str, replace: &str) -> bool {
    if search.is_empty() {
        return false;
    }
    let mut pos = data.find(search);
    let ret = pos.is_some();
    while let Some(p) = pos {
        data.replace_range(p..p + search.len(), replace);
        let from = p + replace.len();
        pos = data.get(from..).and_then(|t| t.find(search)).map(|q| q + from);
    }
    ret
}

/// `Utils::replaceFirst`
pub fn replace_first(data: &mut String, search: &str, replace: &str) -> bool {
    match data.find(search) {
        Some(p) => {
            data.replace_range(p..p + search.len(), replace);
            true
        }
        None => false,
    }
}

/// `Utils::splitNullTerminatedStrings`
pub fn split_null_terminated(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut ret = Vec::new();
    let mut i = 0;
    while i < buf.len() && buf[i] != 0 {
        let end = buf[i..].iter().position(|&c| c == 0).map(|p| i + p).unwrap_or(buf.len());
        ret.push(buf[i..end].to_vec());
        i = end + 1;
    }
    ret
}

/// `Utils::patternMatch` (globHelper.h): '*' and '?' without regex.
pub fn pattern_match(entry: &str, pattern: &str) -> bool {
    let e = entry.as_bytes();
    let p = pattern.as_bytes();
    let mut matched = true;
    let mut pp: usize = 0;
    let mut i: isize = 0;
    while (i as usize) < e.len() {
        let iu = i as usize;
        if pp < p.len() {
            if e[iu] == p[pp] {
                pp += 1;
            } else if p[pp] == b'*' {
                if pp + 1 < p.len() && p[pp + 1] == e[iu] {
                    pp += 1;
                    i -= 1;
                } else if pp + 1 == p.len() {
                    break;
                }
            } else if p[pp] == b'?' {
                pp += 1;
            } else {
                matched = false;
                break;
            }
        } else {
            matched = false;
            break;
        }
        i += 1;
    }
    if matched && pp < p.len() {
        // remaining pattern must be '*' only
        matched = p[pp..].iter().all(|&c| c == b'*');
    }
    matched
}

/// `std::stoi`: leading whitespace, sign, digits; Err when no digits or
/// out of `int` range. Returns (value, characters consumed).
pub fn stoi(s: &str) -> Result<(i32, usize), ()> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || (b'\t'..=b'\r').contains(&b[i])) {
        i += 1;
    }
    let start = i;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let ds = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == ds {
        return Err(());
    }
    let v: i64 = s[start..i].parse().map_err(|_| ())?;
    if v < i32::MIN as i64 || v > i32::MAX as i64 {
        return Err(());
    }
    Ok((v as i32, i))
}
