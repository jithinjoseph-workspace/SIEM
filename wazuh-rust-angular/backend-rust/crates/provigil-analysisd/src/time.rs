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
