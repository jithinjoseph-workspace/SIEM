//! `client-agent/rotate_log.c` (`w_rotate_log_thread`) with the parts of
//! `monitord/rotate_log.c` (`w_rotate_log`, `remove_old_logs*`) and
//! `monitord/compress_log.c` (`OS_CompressLog`) it calls.

use std::io::{Read, Write};
use std::sync::atomic::Ordering;

use chrono::{Datelike, Local, TimeZone};

use crate::*;

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const LOGFILE: &str = "logs/ossec.log";
const LOGJSONFILE: &str = "logs/ossec.json";

/// `IsFile(path) == 0`
fn is_file(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// `IsDir(path) == 0`
fn is_dir(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

fn mkdir_0770(ag: &Agentd, p: &str) {
    use std::os::unix::fs::DirBuilderExt;
    if !is_dir(p) {
        if let Err(e) = std::fs::DirBuilder::new().mode(0o770).create(p) {
            let n = e.raw_os_error().unwrap_or(0);
            ag.exit_critical(format!("(1107): Could not create directory '{p}' due to [({n})-({})].", strerror(n)));
        }
    }
}

/// `w_rotate_log_thread`
pub fn rotate_log_thread(ag: &Agentd) {
    let i = &ag.ints;
    let compress = ag.define_int("monitord", "compress", 0, 1);
    i.log_compress.store(compress, Ordering::SeqCst);
    let keep_log_days = ag.define_int("monitord", "keep_log_days", 0, 500);
    i.keep_log_days.store(keep_log_days, Ordering::SeqCst);
    let day_wait = ag.define_int("monitord", "day_wait", 0, 600);
    i.day_wait.store(day_wait, Ordering::SeqCst);
    let size_rotate_read = ag.define_int("monitord", "size_rotate", 0, 4096);
    i.size_rotate_read.store(size_rotate_read, Ordering::SeqCst);
    let size_rotate = size_rotate_read as u64 * 1024 * 1024;
    let daily_rotations = ag.define_int("monitord", "daily_rotations", 1, 256);
    i.daily_rotations.store(daily_rotations, Ordering::SeqCst);

    ag.log.debug1("Log rotating thread started.");
    let mut today = Local::now().day();
    loop {
        let tm = Local::now();
        if today != tm.day() {
            sleep_secs(day_wait as i64);
            w_rotate_log(ag, compress != 0, keep_log_days, true, false, daily_rotations);
            today = tm.day();
        }
        if size_rotate > 0 {
            if let Ok(m) = std::fs::metadata(LOGFILE) {
                if m.len() >= size_rotate {
                    w_rotate_log(ag, compress != 0, keep_log_days, false, false, daily_rotations);
                }
            }
            if let Ok(m) = std::fs::metadata(LOGJSONFILE) {
                if m.len() >= size_rotate {
                    w_rotate_log(ag, compress != 0, keep_log_days, false, true, daily_rotations);
                }
            }
        } else {
            ag.log.debug1("Disabled rotation of internal logs by size.");
        }
        sleep_secs(1);
    }
}

/// One of the two (`.log` / `.json`) halves of `w_rotate_log`.
fn rotate_one(
    ag: &Agentd,
    old_path: &str,
    month_dir: &str,
    mday: u32,
    ext: &str,
    counter: &mut i32,
    daily_rotations: i32,
    compress: bool,
) -> bool {
    let mut new_path = format!("{month_dir}/ossec-{mday:02}.{ext}");
    let mut compressed = format!("{new_path}.gz");
    while is_file(&compressed) {
        *counter += 1;
        new_path = format!("{month_dir}/ossec-{mday:02}-{:03}.{ext}", *counter);
        compressed = format!("{new_path}.gz");
    }
    if *counter == daily_rotations {
        if daily_rotations == 1 && *counter == 1 {
            new_path = format!("{month_dir}/ossec-{mday:02}.{ext}");
        } else {
            let mut rename_path = format!("{month_dir}/ossec-{mday:02}.{ext}.gz");
            let mut old_rename_path = format!("{month_dir}/ossec-{mday:02}-001.{ext}.gz");
            *counter = 1;
            while *counter < daily_rotations {
                if let Err(e) = std::fs::rename(&old_rename_path, &rename_path) {
                    ag.log.error(format!(
                        "Couldn't rename compressed log '{old_rename_path}' to '{rename_path}': '{}'",
                        strerror(e.raw_os_error().unwrap_or(0))
                    ));
                    return false;
                }
                *counter += 1;
                rename_path = old_rename_path.clone();
                old_rename_path = format!("{month_dir}/ossec-{mday:02}-{:03}.{ext}.gz", *counter);
            }
            new_path = format!("{month_dir}/ossec-{mday:02}-{:03}.{ext}", *counter - 1);
        }
    }
    if is_file(old_path) {
        match std::fs::rename(old_path, &new_path) {
            Ok(()) => {
                if compress {
                    compress_log(ag, &new_path);
                }
            }
            Err(e) => ag.log.error(format!(
                "Couldn't rename '{old_path}' to '{new_path}': {}",
                strerror(e.raw_os_error().unwrap_or(0))
            )),
        }
    }
    true
}

/// `w_rotate_log`
pub fn w_rotate_log(ag: &Agentd, compress: bool, keep_log_days: i32, new_day: bool, rotate_json: bool, daily_rotations: i32) {
    if new_day {
        ag.log.info("Running daily rotation of log files.");
    } else if rotate_json {
        ag.log.info(format!("Rotating '{LOGJSONFILE}' file: Maximum size reached."));
    } else {
        ag.log.info(format!("Rotating '{LOGFILE}' file: Maximum size reached."));
    }
    let t = if new_day { now() - 86400 } else { now() };
    let tm = Local.timestamp_opt(t, 0).single().unwrap_or_else(Local::now);
    let base_dir = "logs/wazuh";
    let year_dir = format!("{base_dir}/{}", tm.year());
    let month_dir = format!("{year_dir}/{}", MONTHS[tm.month0() as usize]);
    mkdir_0770(ag, &year_dir);
    mkdir_0770(ag, &month_dir);

    let mut counter = 0;
    if new_day || !rotate_json {
        if !rotate_one(ag, LOGFILE, &month_dir, tm.day(), "log", &mut counter, daily_rotations, compress) {
            return;
        }
    }
    if new_day || rotate_json {
        if !rotate_one(ag, LOGJSONFILE, &month_dir, tm.day(), "json", &mut counter, daily_rotations, compress) {
            return;
        }
    }
    ag.log.info("Starting new log after rotation.");
    remove_old_logs(ag, base_dir, keep_log_days);
}

/// `OS_CompressLog`
pub fn compress_log(ag: &Agentd, logfile: &str) {
    // SAFETY: umask has no preconditions.
    unsafe { libc::umask(0o027) };
    let gz_path = format!("{logfile}.gz");
    let Ok(mut log) = std::fs::File::open(logfile) else { return };
    let out = match std::fs::File::create(&gz_path) {
        Ok(f) => f,
        Err(e) => {
            ag.log.error(fopen_error(&gz_path, e.raw_os_error().unwrap_or(0)));
            return;
        }
    };
    let mut gz = flate2::GzBuilder::new().operating_system(3).write(out, flate2::Compression::default());
    let mut buf = vec![0u8; OS_MAXSTR];
    loop {
        match log.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if let Err(e) = gz.write_all(&buf[..n]) {
                    ag.log.error(format!("Compression error: {e}"));
                }
            }
        }
    }
    let _ = gz.finish();
    if let Err(e) = std::fs::remove_file(logfile) {
        ag.log.error(format!("Unable to delete '{logfile}' due to '{}'", strerror(e.raw_os_error().unwrap_or(0))));
    }
}

/// `sscanf(s, "%d", &v) > 0`
fn scan_int(s: &str) -> Option<i32> {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n: String = digits.chars().take_while(|c| c.is_ascii_digit()).collect();
    let v: i64 = n.parse().ok()?;
    Some(if neg { -v } else { v } as i32)
}

/// `sscanf(name, "ossec-%02d...", &day) > 0`
fn scan_day(name: &str) -> Option<i32> {
    let rest = name.strip_prefix("ossec-")?;
    let t = rest.trim_start();
    // %02d: a field of at most two characters, the sign included
    let field: String = t.chars().take(2).collect();
    let (neg, digits) = match field.as_bytes().first() {
        Some(b'-') => (true, &field[1..]),
        Some(b'+') => (false, &field[1..]),
        _ => (false, &field[..]),
    };
    let n: String = digits.chars().take_while(|c| c.is_ascii_digit()).collect();
    let v: i32 = n.parse().ok()?;
    Some(if neg { -v } else { v })
}

/// `mktime` of a (year, month, day) at 00:00:00 local time, normalising
/// out-of-range days like C does.
fn mktime_day(year: i32, month0: u32, day: i32) -> i64 {
    let Some(first) = chrono::NaiveDate::from_ymd_opt(year, month0 + 1, 1) else { return i64::MAX };
    let d = first + chrono::Duration::days(day as i64 - 1);
    let naive = d.and_hms_opt(0, 0, 0).unwrap();
    match Local.from_local_datetime(&naive) {
        chrono::LocalResult::Single(t) | chrono::LocalResult::Ambiguous(t, _) => t.timestamp(),
        chrono::LocalResult::None => naive.and_utc().timestamp(),
    }
}

/// `remove_old_logs`
pub fn remove_old_logs(ag: &Agentd, base_dir: &str, keep_log_days: i32) {
    let threshold = now() - (keep_log_days as i64 + 1) * 86400;
    let rd = match std::fs::read_dir(base_dir) {
        Ok(r) => r,
        Err(e) => {
            ag.log.error(format!(
                "Couldn't open directory '{base_dir}' to delete old logs: {}",
                strerror(e.raw_os_error().unwrap_or(0))
            ));
            return;
        }
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(year) = scan_int(&name) {
            remove_old_logs_y(ag, &format!("{base_dir}/{name}"), year, threshold);
        }
    }
}

fn remove_old_logs_y(ag: &Agentd, base_dir: &str, year: i32, threshold: i64) {
    let rd = match std::fs::read_dir(base_dir) {
        Ok(r) => r,
        Err(e) => {
            ag.log.error(format!(
                "Couldn't open directory '{base_dir}' to delete old logs: {}",
                strerror(e.raw_os_error().unwrap_or(0))
            ));
            return;
        }
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = format!("{base_dir}/{name}");
        match MONTHS.iter().position(|m| *m == name) {
            Some(month) => remove_old_logs_m(ag, &path, year, month as u32, threshold),
            None => ag.log.warn(format!("Unexpected folder '{path}'")),
        }
    }
}

fn remove_old_logs_m(ag: &Agentd, base_dir: &str, year: i32, month0: u32, threshold: i64) {
    let rd = match std::fs::read_dir(base_dir) {
        Ok(r) => r,
        Err(e) => {
            ag.log.error(format!(
                "Couldn't open directory '{base_dir}' to delete old logs: {}",
                strerror(e.raw_os_error().unwrap_or(0))
            ));
            return;
        }
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // The four sscanf patterns all start with "ossec-%02d"
        if let Some(day) = scan_day(&name) {
            if mktime_day(year, month0, day) <= threshold {
                let path = format!("{base_dir}/{name}");
                ag.log.debug2(format!("Removing old log '{path}'"));
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanf_like_c() {
        assert_eq!(scan_day("ossec-05.log"), Some(5));
        assert_eq!(scan_day("ossec-05-001.json.gz"), Some(5));
        assert_eq!(scan_day("ossec-x.log"), None);
        assert_eq!(scan_day("other"), None);
        assert_eq!(scan_int("2026"), Some(2026));
        assert_eq!(scan_int("Jan"), None);
    }
}
