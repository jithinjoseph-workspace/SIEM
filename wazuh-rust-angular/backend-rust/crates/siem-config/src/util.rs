//! Small C library behaviours the config readers depend on.

/// C `atoi` (leading blanks, sign, digits; saturates like glibc's strtol cast).
pub fn atoi(s: &str) -> i32 {
    strtol(s).0.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// C `strtol(s, &end, 10)`: returns (value, index of first unparsed byte).
/// When no digits are found, `end` is 0 (strtol sets end = s).
pub fn strtol(s: &str) -> (i64, usize) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: i128 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = (v * 10 + (b[i] - b'0') as i128).min(i64::MAX as i128 + 1);
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    let v = if neg { -v } else { v };
    (v.clamp(i64::MIN as i128, i64::MAX as i128) as i64, i)
}

/// `OS_StrIsNum`
pub fn str_is_num(s: &str) -> bool {
    siem_regex::str_is_num(s)
}

/// `w_parse_time`: "<n>[wdhms]" to seconds, -1 on error.
pub fn parse_time(s: &str) -> i64 {
    let (seconds, end) = strtol(s);
    if seconds < 0 || seconds == i64::MAX {
        return -1;
    }
    let rest = &s.as_bytes()[end.min(s.len())..];
    let mult: i64 = match rest.first() {
        None => 1,
        Some(b'w') => 604800,
        Some(b'd') => 86400,
        Some(b'h') => 3600,
        Some(b'm') => 60,
        Some(b's') => 1,
        Some(_) => return -1,
    };
    match seconds.checked_mul(mult) {
        Some(v) if v >= 0 => v,
        _ => -1,
    }
}

/// `sscanf(s, "%d%c", &n, &c)`: returns (matched count, n, c).
pub fn sscanf_int_char(s: &str) -> (i32, i64, Option<char>) {
    let (n, end) = strtol(s);
    if end == 0 {
        return (0, 0, None);
    }
    match s[end..].chars().next() {
        Some(c) => (2, n, Some(c)),
        None => (1, n, None),
    }
}

/// `w_strtrim`: strip leading/trailing C-locale whitespace.
pub fn strtrim(s: &str) -> &str {
    s.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_time_units() {
        assert_eq!(parse_time("10"), 10);
        assert_eq!(parse_time("10m"), 600);
        assert_eq!(parse_time("2h"), 7200);
        assert_eq!(parse_time("1d"), 86400);
        assert_eq!(parse_time("1w"), 604800);
        assert_eq!(parse_time("5x"), -1);
        assert_eq!(parse_time("-1"), -1);
        // strtol reads nothing and leaves *end = 'a', which is not a unit.
        assert_eq!(parse_time("abc"), -1);
        assert_eq!(parse_time(""), 0);
    }
}
