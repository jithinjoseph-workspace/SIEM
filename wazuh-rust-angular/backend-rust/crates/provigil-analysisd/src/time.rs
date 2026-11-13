//! Local time for the alert texts: the system time zone, or a fixed UTC offset (tests).

use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{Local, Offset, TimeZone};

const SYSTEM: i64 = i64::MIN;
static OFFSET: AtomicI64 = AtomicI64::new(SYSTEM);

/// Use a fixed offset (seconds east of UTC) instead of the system zone; None goes back.
pub fn set_fixed_offset(secs: Option<i32>) {
    OFFSET.store(secs.map_or(SYSTEM, i64::from), Ordering::SeqCst);
}

/// Seconds east of UTC at `t`.
pub fn offset_at(t: i64) -> i64 {
    match OFFSET.load(Ordering::SeqCst) {
        SYSTEM => Local.timestamp_opt(t, 0).single().map_or(0, |d| d.offset().fix().local_minus_utc() as i64),
        f => f,
    }
}

/// A broken-down local time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tm {
    pub year: i64,
    /// 0 = January
    pub mon: u32,
    pub mday: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
    /// 0 = Sunday
    pub wday: u32,
    /// seconds east of UTC
    pub gmtoff: i64,
}

/// The local time of `t`; None when the year does not fit a 32-bit year count from 1900.
pub fn local(t: i64) -> Option<Tm> {
    let off = offset_at(t);
    let s = t.checked_add(off)?;
    let (days, rem) = (s.div_euclid(86_400) as i128, s.rem_euclid(86_400));
    // days since 1970-01-01 to a civil date (proleptic Gregorian)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let mday = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 2 } else { mp - 10 };
    let year = yoe + era * 400 + i128::from(mon < 2);
    if !(i32::MIN as i128..=i32::MAX as i128).contains(&(year - 1900)) {
        return None;
    }
    Some(Tm {
        year: year as i64,
        mon: mon as u32,
        mday: mday as u32,
        hour: (rem / 3600) as u32,
        min: (rem % 3600 / 60) as u32,
        sec: (rem % 60) as u32,
        wday: (days + 4).rem_euclid(7) as u32,
        gmtoff: off,
    })
}

pub const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
pub const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// `Www Mmm dd hh:mm:ss yyyy\n`; None when it would not fit 25 characters.
pub fn ctime(t: i64) -> Option<String> {
    let tm = local(t)?;
    let r = format!("{} {}{:>3} {:02}:{:02}:{:02} {}\n", DAYS[tm.wday as usize], MONTHS[tm.mon as usize], tm.mday, tm.hour, tm.min, tm.sec, tm.year);
    (r.len() < 26).then_some(r)
}

/// `YYYY-MM-DDThh:mm:ss±hhmm` written into `buf` (room for `max` bytes with the final zero):
/// each part is written only when it fits whole; the first that does not ends the writing
/// without the final zero.
pub fn write_iso(buf: &mut [u8], max: usize, tm: &Tm) {
    let year = if tm.year < 0 { format!("-{:04}", -tm.year) } else { format!("{:04}", tm.year) };
    let z = tm.gmtoff;
    let parts = [
        format!("{year}-{:02}-{:02}", tm.mon + 1, tm.mday),
        "T".into(),
        format!("{:02}:{:02}:{:02}", tm.hour, tm.min, tm.sec),
        format!("{}{:02}{:02}", if z < 0 { '-' } else { '+' }, z.abs() / 3600, z.abs() % 3600 / 60),
    ];
    let mut at = 0;
    for p in &parts {
        if p.len() >= max - at {
            return;
        }
        buf[at..at + p.len()].copy_from_slice(p.as_bytes());
        at += p.len();
    }
    buf[at] = 0;
}

// ---------------------------------------------------------------- `<time>` and `<weekday>` of rules

fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// The leading number of `s` from `i` (spaces and a sign allowed, wrapping like C).
fn leading_int(s: &[u8], mut i: usize) -> i32 {
    while matches!(at(s, i), b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let neg = at(s, i) == b'-';
    if matches!(at(s, i), b'+' | b'-') {
        i += 1;
    }
    let mut v: i64 = 0;
    while at(s, i).is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add(i64::from(at(s, i) - b'0'));
        i += 1;
    }
    (if neg { -v } else { v }) as i32
}

/// `h[:mm][ ][am|pm]` at `p`: (position after it, "HH:MM").
fn hour(s: &[u8], mut p: usize) -> Option<(usize, String)> {
    let mut h = leading_int(s, p);
    if !(0..24).contains(&h) {
        return None;
    }
    let start = p;
    while at(s, p).is_ascii_digit() {
        p += 1;
    }
    if p - start > 2 {
        return None;
    }
    let mut min = 0;
    if at(s, p) == b':' {
        p += 1;
        // two digits, unless only the third is a digit
        if (!at(s, p).is_ascii_digit() || !at(s, p + 1).is_ascii_digit()) && at(s, p + 2).is_ascii_digit() {
            return None;
        }
        min = leading_int(s, p);
        p += 2;
    }
    while at(s, p) == b' ' {
        p += 1;
    }
    let text = |h: i32, m: i32| {
        let t = format!("{h:02}:{m:02}");
        (t.len() < 7).then_some(t)
    };
    match at(s, p).to_ascii_lowercase() {
        c @ (b'a' | b'p') => {
            if at(s, p + 1).to_ascii_lowercase() != b'm' {
                return None;
            }
            if h == 12 {
                h = 0;
            }
            if c == b'p' {
                h += 12;
                if !(0..24).contains(&h) {
                    return None;
                }
            }
            Some((p + 2, text(h, min)?))
        }
        _ => Some((p, text(h, min)?)),
    }
}

/// A rule's `<time>` range `[!]from - to` as `.HHMMHHMM`-like text: `.` or `!` (negated),
/// then the two "HH:MM" texts; a range given backwards becomes the negated range the other
/// way round. None when invalid.
pub fn rule_time(t: &str) -> Option<String> {
    let s = t.as_bytes();
    let mut p = 0;
    while at(s, p) == b' ' {
        p += 1;
    }
    let negated = at(s, p) == b'!';
    if negated {
        p += 1;
        while at(s, p) == b' ' {
            p += 1;
        }
    }
    let (q, first) = hour(s, p)?;
    p = q;
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
    let (q, second) = hour(s, p)?;
    p = q;
    while at(s, p) == b' ' {
        p += 1;
    }
    if at(s, p) != 0 {
        return None;
    }
    if first > second {
        return Some(format!("!{second}{first}"));
    }
    Some(format!("{}{first}{second}", if negated { '!' } else { '.' }))
}

/// Whether `now` ("HH:MM:SS") is in a [`rule_time`] range (the first 5 characters compared).
pub fn on_time(now: &str, range: &str) -> bool {
    let cmp5 = |a: &[u8], b: &[u8]| {
        for i in 0..5 {
            let (x, y) = (at(a, i), at(b, i));
            if x != y || x == 0 {
                return x.cmp(&y);
            }
        }
        std::cmp::Ordering::Equal
    };
    let r = range.as_bytes();
    let inside = at(r, 0) != b'!';
    let r = r.get(1..).unwrap_or(&[]);
    let n = now.as_bytes();
    let within = cmp5(n, r).is_ge() && cmp5(n, r.get(5..).unwrap_or(&[])).is_le();
    within == inside
}

/// A rule's `<weekday>` list (names, three-letter names, weekdays, weekends; separated by
/// spaces or commas) as 9 bytes: 1 for each day Sunday..Saturday, then `!` at 7 when negated.
/// A leading `!` is not skipped, so it never reads (as in the original).
pub fn rule_days(d: &str) -> Option<Vec<u8>> {
    const NAMES: [(&str, i32); 16] = [
        ("sunday", 0),
        ("sun", 0),
        ("monday", 1),
        ("mon", 1),
        ("tuesday", 2),
        ("tue", 2),
        ("wednesday", 3),
        ("wed", 3),
        ("thursday", 4),
        ("thu", 4),
        ("friday", 5),
        ("fri", 5),
        ("saturday", 6),
        ("sat", 6),
        ("weekdays", 7),
        ("weekends", 8),
    ];
    let s = d.as_bytes();
    let mut p = 0;
    while at(s, p) == b' ' {
        p += 1;
    }
    let negated = at(s, p) == b'!';
    let mut days = [0u8; 7];
    while at(s, p) != 0 {
        let (name, n) = NAMES.iter().find(|(name, _)| name.bytes().enumerate().all(|(k, c)| at(s, p + k).to_ascii_lowercase() == c))?;
        match n {
            7 => days[1..6].fill(1),
            8 => {
                days[0] = 1;
                days[6] = 1;
            }
            d => days[*d as usize] = 1,
        }
        p += name.len();
        match at(s, p) {
            b' ' | b',' => {
                while matches!(at(s, p), b' ' | b',') {
                    p += 1;
                }
            }
            0 => break,
            _ => return None,
        }
    }
    if !days.contains(&1) {
        return None;
    }
    let mut out = days.to_vec();
    out.extend_from_slice(&[if negated { b'!' } else { 0 }, 0]);
    Some(out)
}

/// Whether week day `wday` (0 = Sunday) is in a [`rule_days`] list.
pub fn on_day(wday: i32, days: &[u8]) -> bool {
    let inside = days.get(7) != Some(&b'!');
    if !(0..=7).contains(&wday) {
        return false;
    }
    (days.get(wday as usize) == Some(&1)) == inside
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        set_fixed_offset(Some(0));
        let t = local(951_782_400).unwrap(); // 2000-02-29
        assert_eq!((t.year, t.mon, t.mday, t.wday), (2000, 1, 29, 2));
        assert_eq!(ctime(0).unwrap(), "Thu Jan  1 00:00:00 1970\n");
        set_fixed_offset(None);
    }
}
