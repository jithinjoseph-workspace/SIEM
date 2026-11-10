//! Rule time/weekday filters (shared/validate_op.c): `OS_IsValidTime`,
//! `OS_IsonTime`, `OS_IsValidDay`, `OS_IsonDay`.

/// C `atoi` on a byte slice.
fn atoi(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((s[i] - b'0') as i64);
        i += 1;
    }
    (if neg { -v } else { v }) as i32
}

fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// `__gethour`: returns the position after the hour and the "hh:mm" text.
fn gethour(s: &[u8], mut p: usize) -> Option<(usize, String)> {
    let mut chour = atoi(&s[p.min(s.len())..]);
    if !(0..24).contains(&chour) {
        return None;
    }
    let mut size = 0;
    while at(s, p).is_ascii_digit() {
        size += 1;
        p += 1;
    }
    if size > 2 {
        return None;
    }
    let mut cmin = 0;
    if at(s, p) == b':' {
        p += 1;
        if (!at(s, p).is_ascii_digit() || !at(s, p + 1).is_ascii_digit()) && at(s, p + 2).is_ascii_digit() {
            return None;
        }
        cmin = atoi(&s[p.min(s.len())..]);
        p += 2;
    }
    while at(s, p) == b' ' {
        p += 1;
    }
    let fmt = |h: i32, m: i32| -> Option<String> {
        let t = format!("{h:02}:{m:02}");
        // snprintf into a 7 byte buffer
        if t.len() >= 7 {
            None
        } else {
            Some(t)
        }
    };
    let c = at(s, p);
    if c == b'a' || c == b'A' {
        p += 1;
        if at(s, p) == b'm' || at(s, p) == b'M' {
            if chour == 12 {
                chour = 0;
            }
            let t = fmt(chour, cmin)?;
            return Some((p + 1, t));
        }
    } else if c == b'p' || c == b'P' {
        p += 1;
        if at(s, p) == b'm' || at(s, p) == b'M' {
            if chour == 12 {
                chour = 0;
            }
            chour += 12;
            if !(0..24).contains(&chour) {
                return None;
            }
            let t = fmt(chour, cmin)?;
            return Some((p + 1, t));
        }
    } else {
        let t = fmt(chour, cmin)?;
        return Some((p, t));
    }
    None
}

/// `OS_IsValidTime`: ".hh:mmhh:mm" or "!hh:mmhh:mm".
pub fn os_is_valid_time(time_str: &str) -> Option<String> {
    let s = time_str.as_bytes();
    let mut p = 0;
    while at(s, p) == b' ' {
        p += 1;
    }
    let mut ng = false;
    if at(s, p) == b'!' {
        ng = true;
        p += 1;
        while at(s, p) == b' ' {
            p += 1;
        }
    }
    let (np, first) = gethour(s, p)?;
    p = np;
    while at(s, p) == b' ' {
        p += 1;
    }
    if at(s, p) != b'-' {
        return None;
    }
    p += 1;
    while at(s, p) == b' ' {
        p += 1;
    }
    let (np, second) = gethour(s, p)?;
    p = np;
    while at(s, p) == b' ' {
        p += 1;
    }
    if at(s, p) != 0 {
        return None;
    }
    if first > second {
        return Some(format!("!{second}{first}"));
    }
    Some(format!("{}{}{}", if ng { '!' } else { '.' }, first, second))
}

fn strncmp5(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    for i in 0..5 {
        let x = at(a, i);
        let y = at(b, i);
        if x != y {
            return x.cmp(&y);
        }
        if x == 0 {
            break;
        }
    }
    std::cmp::Ordering::Equal
}

/// `OS_IsonTime`
pub fn os_is_on_time(time_str: &str, ossec_time: &str) -> bool {
    let t = time_str.as_bytes();
    let o = ossec_time.as_bytes();
    let tru = at(o, 0) != b'!';
    let o = &o[1.min(o.len())..];
    if strncmp5(t, o) != std::cmp::Ordering::Less && strncmp5(t, &o[5.min(o.len())..]) != std::cmp::Ordering::Greater {
        return tru;
    }
    !tru
}

/// `OS_IsValidDay`: 9 bytes, `[0..7)` one flag per weekday, `[7] == '!'` for negation.
pub fn os_is_valid_day(day_str: &str) -> Option<Vec<u8>> {
    const DAYS: [&str; 16] = [
        "sunday", "sun", "monday", "mon", "tuesday", "tue", "wednesday", "wed", "thursday", "thu", "friday", "fri", "saturday",
        "sat", "weekdays", "weekends",
    ];
    const DAYS_INT: [i32; 16] = [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 8];
    let s = day_str.as_bytes();
    let mut p = 0;
    let mut day_ret = [0u8; 9];
    while at(s, p) == b' ' {
        p += 1;
    }
    let mut ng = false;
    if at(s, p) == b'!' {
        // The '!' is not skipped (RM_WHITE only): the day match below fails.
        ng = true;
        while at(s, p) == b' ' {
            p += 1;
        }
    }
    while at(s, p) != 0 {
        let rest = &s[p..];
        let mut found = None;
        for (i, d) in DAYS.iter().enumerate() {
            let n = d.len();
            let cmp_len = n;
            let ok = (0..cmp_len).all(|k| at(rest, k).to_ascii_lowercase() == d.as_bytes()[k]);
            if ok {
                found = Some(i);
                break;
            }
        }
        let i = found?;
        match DAYS_INT[i] {
            7 => {
                for d in 1..=5 {
                    day_ret[d] = 1;
                }
            }
            8 => {
                day_ret[0] = 1;
                day_ret[6] = 1;
            }
            d => day_ret[d as usize] = 1,
        }
        p += DAYS[i].len();
        if at(s, p) == b' ' || at(s, p) == b',' {
            while at(s, p) == b' ' || at(s, p) == b',' {
                p += 1;
            }
            continue;
        } else if at(s, p) == 0 {
            break;
        } else {
            return None;
        }
    }
    let mut ret = vec![0u8; 9];
    if ng {
        ret[7] = b'!';
    }
    let mut any = false;
    for i in 0..=6 {
        if day_ret[i] == 1 {
            any = true;
        }
        ret[i] = day_ret[i];
    }
    if !any {
        return None;
    }
    Some(ret)
}

/// `OS_IsonDay`
pub fn os_is_on_day(week_day: i32, ossec_day: &[u8]) -> bool {
    let tru = ossec_day.get(7) != Some(&b'!');
    if !(0..=7).contains(&week_day) {
        return false;
    }
    if ossec_day.get(week_day as usize) == Some(&1) {
        return tru;
    }
    !tru
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(os_is_valid_time("6 pm - 8:30 am").as_deref(), Some("!08:3018:00"));
        assert_eq!(os_is_valid_time("9:00 - 17:00").as_deref(), Some(".09:0017:00"));
        assert_eq!(os_is_valid_time("!9:00 - 17:00").as_deref(), Some("!09:0017:00"));
        assert!(os_is_on_time("10:00:00", ".09:0017:00"));
        assert!(!os_is_on_time("18:00:00", ".09:0017:00"));
        assert!(os_is_on_time("19:00:00", "!08:3018:00"));
    }

    #[test]
    fn days() {
        assert_eq!(os_is_valid_day("weekends").unwrap()[..7], [1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(os_is_valid_day("monday,tue wed").unwrap()[..7], [0, 1, 1, 1, 0, 0, 0]);
        assert!(os_is_valid_day("!monday").is_none());
        assert!(os_is_valid_day("funday").is_none());
    }
}
