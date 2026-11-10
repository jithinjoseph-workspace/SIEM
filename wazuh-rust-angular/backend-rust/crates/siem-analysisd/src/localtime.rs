//! `localtime_r` for the formatting code. By default the system local time
//! zone; tests (and the oracle comparison) can pin a fixed UTC offset.

use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, FixedOffset, Local, Offset, TimeZone};

const UNSET: i64 = i64::MIN;
static FIXED: AtomicI64 = AtomicI64::new(UNSET);

/// Use a fixed UTC offset (seconds east) instead of the system time zone.
pub fn set_fixed_offset(secs: Option<i32>) {
    FIXED.store(secs.map(|s| s as i64).unwrap_or(UNSET), Ordering::SeqCst);
}

/// The local broken-down time of `sec` (`localtime_r`).
pub fn at(sec: i64) -> DateTime<FixedOffset> {
    let f = FIXED.load(Ordering::SeqCst);
    if f != UNSET {
        let off = FixedOffset::east_opt(f as i32).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
        return off.timestamp_opt(sec, 0).single().unwrap_or_else(|| off.timestamp_opt(0, 0).unwrap());
    }
    match Local.timestamp_opt(sec, 0).single() {
        Some(d) => {
            let off = d.offset().fix();
            d.with_timezone(&off)
        }
        None => {
            let off = FixedOffset::east_opt(0).unwrap();
            off.timestamp_opt(0, 0).unwrap()
        }
    }
}

/// `localtime_r` that can fail (out of range times).
pub fn try_at(sec: i64) -> Option<DateTime<FixedOffset>> {
    let f = FIXED.load(Ordering::SeqCst);
    if f != UNSET {
        let off = FixedOffset::east_opt(f as i32)?;
        return off.timestamp_opt(sec, 0).single();
    }
    let d = Local.timestamp_opt(sec, 0).single()?;
    let off = d.offset().fix();
    Some(d.with_timezone(&off))
}

/// `struct tm` fields of a broken-down time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tm {
    pub year: i64,
    /// 0-11
    pub mon: u32,
    pub mday: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
    /// 0 = Sunday
    pub wday: u32,
    /// UTC offset in seconds
    pub gmtoff: i64,
}

/// `localtime_r` over the whole `time_t` range: None when the year does
/// not fit `tm_year` (an `int`), like glibc.
pub fn tm(t: i64) -> Option<Tm> {
    let f = FIXED.load(Ordering::SeqCst);
    let off: i64 = if f != UNSET {
        f
    } else {
        match Local.timestamp_opt(t, 0).single() {
            Some(d) => d.offset().fix().local_minus_utc() as i64,
            None => 0,
        }
    };
    let secs = t.checked_add(off)?;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil_from_days (H. Hinnant)
    let z = days as i128 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    let ty = y - 1900;
    if ty > i32::MAX as i128 || ty < i32::MIN as i128 {
        return None;
    }
    Some(Tm {
        year: y as i64,
        mon: (m - 1) as u32,
        mday: d as u32,
        hour: (rem / 3600) as u32,
        min: (rem % 3600 / 60) as u32,
        sec: (rem % 60) as u32,
        wday: (days as i128 + 4).rem_euclid(7) as u32,
        gmtoff: off,
    })
}

const WDAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// `ctime_r` (with its newline); None when `localtime_r` fails or the
/// text does not fit glibc's 26-byte buffer.
pub fn ctime(t: i64) -> Option<String> {
    let tm = tm(t)?;
    let r = format!(
        "{} {}{:>3} {:02}:{:02}:{:02} {}\n",
        WDAY[tm.wday as usize], MON[tm.mon as usize], tm.mday, tm.hour, tm.min, tm.sec, tm.year
    );
    if r.len() >= 26 {
        return None;
    }
    Some(r)
}

/// glibc `%Y` (padded to 4 digits)
fn year_text(y: i64) -> String {
    if y < 0 {
        format!("-{:04}", -y)
    } else {
        format!("{y:04}")
    }
}

/// `strftime(buf, maxsize, "%FT%T%z", tm)` writing into `buf` the way
/// glibc does: each conversion is written only if it fits entirely, the
/// first one that does not makes it stop without a terminating NUL (the
/// buffer keeps its previous bytes after that point).
pub fn strftime_fttz(buf: &mut [u8], maxsize: usize, tm: &Tm) {
    let z = tm.gmtoff;
    let zone = format!("{}{:02}{:02}", if z < 0 { '-' } else { '+' }, z.abs() / 3600, z.abs() % 3600 / 60);
    let pieces = [
        format!("{}-{:02}-{:02}", year_text(tm.year), tm.mon + 1, tm.mday),
        "T".to_string(),
        format!("{:02}:{:02}:{:02}", tm.hour, tm.min, tm.sec),
        zone,
    ];
    let mut i = 0usize;
    for p in &pieces {
        if p.len() >= maxsize - i {
            return;
        }
        buf[i..i + p.len()].copy_from_slice(p.as_bytes());
        i += p.len();
    }
    buf[i] = 0;
}
