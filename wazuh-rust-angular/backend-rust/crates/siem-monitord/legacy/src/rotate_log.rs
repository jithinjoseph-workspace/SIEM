//! Log File Rotation & Retention Engine (`src/monitord/rotate_log.c`)
//!
//! Executes daily and size-triggered rotations for `ossec.log` and `ossec.json`,
//! manages rotation shift slots (up to `daily_rotations`), and purges logs exceeding `keep_log_days`.

use crate::compress_log::compress_log;
use chrono::{Datelike, Duration, Local};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Rotates log file into `base_dir/YYYY/Mon/ossec-DD.log` (or `.json`).
pub fn rotate_log_file(
    base_dir: &Path,
    source_log_path: &Path,
    is_json: bool,
    compress: bool,
    keep_log_days: u32,
    new_day: bool,
    daily_rotations: u32,
) -> io::Result<Option<PathBuf>> {
    if !source_log_path.exists() {
        return Ok(None);
    }

    let target_time = if new_day {
        Local::now() - Duration::days(1)
    } else {
        Local::now()
    };

    let year = target_time.year();
    let month_idx = (target_time.month() - 1) as usize;
    let month_str = MONTHS[month_idx];
    let day = target_time.day();

    let target_dir = base_dir.join(format!("{}/{}", year, month_str));
    fs::create_dir_all(&target_dir)?;

    let ext = if is_json { "json" } else { "log" };
    let mut final_path = target_dir.join(format!("ossec-{:02}.{}", day, ext));
    let mut gz_path = target_dir.join(format!("ossec-{:02}.{}.gz", day, ext));

    // Find rotation slot
    let mut counter = 0;
    while gz_path.exists() || final_path.exists() {
        counter += 1;
        if counter >= daily_rotations {
            break;
        }
        final_path = target_dir.join(format!("ossec-{:02}-{:03}.{}", day, counter, ext));
        gz_path = target_dir.join(format!("ossec-{:02}-{:03}.{}.gz", day, counter, ext));
    }

    // Rename current log to destination slot
    fs::rename(source_log_path, &final_path)?;

    info!(
        "Rotated {} -> {}",
        source_log_path.display(),
        final_path.display()
    );

    let resulting_path = if compress {
        match compress_log(&final_path) {
            Ok(gz) => Some(gz),
            Err(e) => {
                warn!("Failed to compress {}: {}", final_path.display(), e);
                Some(final_path)
            }
        }
    } else {
        Some(final_path)
    };

    // Purge old files beyond retention days
    remove_old_logs(base_dir, keep_log_days)?;

    Ok(resulting_path)
}

/// Recursively removes logs older than `keep_log_days` from `base_dir`.
pub fn remove_old_logs(base_dir: &Path, keep_log_days: u32) -> io::Result<()> {
    if !base_dir.exists() {
        return Ok(());
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let threshold_secs = now_secs.saturating_sub((keep_log_days as u64 + 1) * 86400);

    for entry in fs::read_dir(base_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Year directory
            for m_entry in fs::read_dir(&path)? {
                let m_entry = m_entry?;
                let m_path = m_entry.path();
                if m_path.is_dir() {
                    // Month directory
                    for f_entry in fs::read_dir(&m_path)? {
                        let f_entry = f_entry?;
                        let f_path = f_entry.path();
                        if f_path.is_file() {
                            if let Ok(meta) = f_path.metadata() {
                                if let Ok(modified) = meta.modified() {
                                    let mod_secs = modified
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    if mod_secs < threshold_secs {
                                        let _ = fs::remove_file(&f_path);
                                    }
                                }
                            }
                        }
                    }
                    // Remove month dir if empty
                    let _ = fs::remove_dir(&m_path);
                }
            }
            // Remove year dir if empty
            let _ = fs::remove_dir(&path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_rotate_log_file_basic() {
        let dir = tempdir().unwrap();
        let logs_base = dir.path().join("logs");
        let active_log = dir.path().join("ossec.log");

        fs::write(&active_log, "2026-09-28 log line 1\n").unwrap();

        let rotated = rotate_log_file(
            &logs_base,
            &active_log,
            false,
            true,
            30,
            false,
            12,
        )
        .unwrap();

        assert!(rotated.is_some());
        let gz_path = rotated.unwrap();
        assert!(gz_path.exists());
        assert!(!active_log.exists());
    }
}
