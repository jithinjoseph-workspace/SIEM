//! `monitord/rotate_log.c`: rotation of `logs/ossec.log` / `logs/ossec.json`
//! into `logs/wazuh/<year>/<Mon>/ossec-<dd>[-<nnn>].{log,json}[.gz]`.

use chrono::{Datelike, Duration, Local, NaiveDate, TimeZone};

use crate::compress_log::os_compress_log;
use crate::{fatal, is_file, strerror, LOGFILE, LOGJSONFILE, MONTHS};
use siem_log::WLog;

const BASE_DIR: &str = "logs/wazuh";

fn mkdir_if_missing(log: &WLog, dir: &str) {
    if !std::path::Path::new(dir).is_dir() {
        if let Err(e) = std::fs::create_dir(dir) {
            fatal(log, &format!("(1107): Could not create directory '{dir}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), strerror(&e)));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o770));
        }
    }
}

fn rename(from: &str, to: &str) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

/// `w_rotate_log`
pub fn w_rotate_log(log: &WLog, compress: bool, keep_log_days: i32, new_day: bool, rotate_json: bool, daily_rotations: i32) {
    if new_day {
        log.info("Running daily rotation of log files.");
    } else if rotate_json {
        log.info(format!("Rotating '{LOGJSONFILE}' file: Maximum size reached."));
    } else {
        log.info(format!("Rotating '{LOGFILE}' file: Maximum size reached."));
    }
    let now = if new_day { Local::now() - Duration::seconds(86400) } else { Local::now() };
    let (year, mon, mday) = (now.year(), now.month0() as usize, now.day());

    let year_dir = format!("{BASE_DIR}/{year}");
    let month_dir = format!("{year_dir}/{}", MONTHS[mon]);
    let mut new_path = format!("{month_dir}/ossec-{mday:02}.log");
    let mut new_path_json = format!("{month_dir}/ossec-{mday:02}.json");
    let mut compressed_path = format!("{new_path}.gz");

    mkdir_if_missing(log, &year_dir);
    mkdir_if_missing(log, &month_dir);

    // The counter is shared by both files, as in C.
    let mut counter = 0;
    if new_day || !rotate_json {
        // Count rotated log files of the current day
        while is_file(&compressed_path) {
            counter += 1;
            new_path = format!("{month_dir}/ossec-{mday:02}-{counter:03}.log");
            compressed_path = format!("{new_path}.gz");
        }
        // Rotate compressed logs if needed
        if counter == daily_rotations {
            if daily_rotations == 1 && counter == 1 {
                new_path = format!("{month_dir}/ossec-{mday:02}.log");
            } else {
                let mut rename_path = format!("{month_dir}/ossec-{mday:02}.log.gz");
                let mut old_rename_path = format!("{month_dir}/ossec-{mday:02}-001.log.gz");
                counter = 1;
                while counter < daily_rotations {
                    if let Err(e) = rename(&old_rename_path, &rename_path) {
                        log.error(format!("Couldn't rename compressed log '{old_rename_path}' to '{rename_path}': '{}'", strerror(&e)));
                        return;
                    }
                    counter += 1;
                    rename_path = old_rename_path;
                    old_rename_path = format!("{month_dir}/ossec-{mday:02}-{counter:03}.log.gz");
                }
                new_path = format!("{month_dir}/ossec-{mday:02}-{:03}.log", counter - 1);
            }
        }
        if is_file(LOGFILE) {
            match rename(LOGFILE, &new_path) {
                Ok(()) => {
                    if compress {
                        os_compress_log(log, &new_path);
                    }
                }
                Err(e) => log.error(format!("Couldn't rename '{LOGFILE}' to '{new_path}': {}", strerror(&e))),
            }
        }
    }

    if new_day || rotate_json {
        compressed_path = format!("{new_path_json}.gz");
        while is_file(&compressed_path) {
            counter += 1;
            new_path_json = format!("{month_dir}/ossec-{mday:02}-{counter:03}.json");
            compressed_path = format!("{new_path_json}.gz");
        }
        if counter == daily_rotations {
            if daily_rotations == 1 && counter == 1 {
                new_path_json = format!("{month_dir}/ossec-{mday:02}.json");
            } else {
                let mut rename_path = format!("{month_dir}/ossec-{mday:02}.json.gz");
                let mut old_rename_path = format!("{month_dir}/ossec-{mday:02}-001.json.gz");
                counter = 1;
                while counter < daily_rotations {
                    if let Err(e) = rename(&old_rename_path, &rename_path) {
                        log.error(format!("Couldn't rename compressed log '{old_rename_path}' to '{rename_path}': '{}'", strerror(&e)));
                        return;
                    }
                    counter += 1;
                    rename_path = old_rename_path;
                    old_rename_path = format!("{month_dir}/ossec-{mday:02}-{counter:03}.json.gz");
                }
                new_path_json = format!("{month_dir}/ossec-{mday:02}-{:03}.json", counter - 1);
            }
        }
        if is_file(LOGJSONFILE) {
            match rename(LOGJSONFILE, &new_path_json) {
                Ok(()) => {
                    if compress {
                        os_compress_log(log, &new_path_json);
                    }
                }
                Err(e) => log.error(format!("Couldn't rename '{LOGJSONFILE}' to '{new_path_json}': {}", strerror(&e))),
            }
        }
    }

    log.info("Starting new log after rotation.");
    remove_old_logs(log, BASE_DIR, keep_log_days);
}

/// `sscanf(s, "%d")` > 0: the leading integer (after whitespace and a sign).
fn scan_int(s: &str, width: usize) -> Option<i32> {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let b = t.as_bytes();
    let mut i = 0;
    let mut neg = false;
    if i < b.len().min(width) && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: i64 = 0;
    while i < b.len() && i < width && b[i].is_ascii_digit() {
        v = (v * 10 + (b[i] - b'0') as i64).min(i32::MAX as i64 + 1);
        i += 1;
    }
    (i > start).then(|| (if neg { -v } else { v }) as i32)
}

fn read_dir(log: &WLog, dir: &str) -> Option<Vec<String>> {
    match std::fs::read_dir(dir) {
        Ok(rd) => Some(rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()),
        Err(e) => {
            log.error(format!("Couldn't open directory '{dir}' to delete old logs: {}", strerror(&e)));
            None
        }
    }
}

/// `remove_old_logs`
pub fn remove_old_logs(log: &WLog, base_dir: &str, keep_log_days: i32) {
    let threshold = Local::now().timestamp() - (keep_log_days as i64 + 1) * 86400;
    let Some(names) = read_dir(log, base_dir) else { return };
    for name in names {
        if let Some(year) = scan_int(&name, usize::MAX) {
            remove_old_logs_y(log, &format!("{base_dir}/{name}"), year, threshold);
        }
    }
}

fn remove_old_logs_y(log: &WLog, base_dir: &str, year: i32, threshold: i64) {
    let Some(names) = read_dir(log, base_dir) else { return };
    for name in names {
        let path = format!("{base_dir}/{name}");
        match MONTHS.iter().position(|m| *m == name) {
            Some(month) => remove_old_logs_m(log, &path, year, month as u32, threshold),
            None => log.warn(format!("Unexpected folder '{path}'")),
        }
    }
}

/// `mktime` of local midnight; `day` out of range rolls over like mktime.
fn midnight(year: i32, month0: u32, day: i32) -> Option<i64> {
    let first = NaiveDate::from_ymd_opt(year, month0 + 1, 1)?;
    let d = first.checked_add_signed(Duration::days(day as i64 - 1))?;
    Local.from_local_datetime(&d.and_hms_opt(0, 0, 0)?).earliest().map(|t| t.timestamp())
}

fn remove_old_logs_m(log: &WLog, base_dir: &str, year: i32, month0: u32, threshold: i64) {
    let Some(names) = read_dir(log, base_dir) else { return };
    for name in names {
        // The C code tries four sscanf patterns that all start with "ossec-%02d",
        // so a matching name is logged and unlinked four times.
        let Some(day) = name.strip_prefix("ossec-").and_then(|r| scan_int(r, 2)) else { continue };
        if midnight(year, month0, day).is_some_and(|t| t <= threshold) {
            let path = format!("{base_dir}/{name}");
            for _ in 0..4 {
                log.debug2(format!("Removing old log '{path}'"));
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sscanf_like() {
        assert_eq!(scan_int("2026", usize::MAX), Some(2026));
        assert_eq!(scan_int("05-001.log", 2), Some(5));
        assert_eq!(scan_int("5.json", 2), Some(5));
        assert_eq!(scan_int("x", 2), None);
        assert_eq!(scan_int("123", 2), Some(12));
    }

    #[test]
    fn mktime_rollover() {
        assert_eq!(midnight(2026, 1, 31), midnight(2026, 2, 3)); // 31 Feb -> 3 Mar
    }
}
