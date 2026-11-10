//! Log rotation, compression, checksum signing, and retention management.
//!
//! Replaces legacy `siem-monitord` log housekeeping with pure, clean-room Rust.
//! Monitord features preserved:
//! - Daily midnight log rotation.
//! - Size-based log rotation when file exceeds `max_size_bytes`.
//! - Standard archive directory structure: `<base>/<year>/<Mon>/<name>-<day>[-<seq>].<ext>`.
//! - Gzip compression (`.gz`) using `flate2` and removal of original uncompressed log.
//! - Checksum integrity signing (`.sum` file with SHA-256).
//! - Retention cleanup removing archived logs older than `keep_log_days`.

use chrono::{DateTime, Datelike, Local, NaiveDate, TimeZone};
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Configuration for log rotation and retention.
#[derive(Debug, Clone)]
pub struct LogRotatorConfig {
    /// List of active log files to monitor (e.g. provigil.log, provigil.json).
    pub log_files: Vec<PathBuf>,
    /// Base directory for archived logs.
    pub archive_dir: PathBuf,
    /// Maximum file size in bytes before size-based rotation triggers (default: 500 MB).
    pub max_size_bytes: u64,
    /// Days of archived logs to retain before deletion (default: 31 days).
    pub keep_log_days: u32,
    /// Whether to gzip compress rotated logs (default: true).
    pub compress: bool,
    /// Maximum daily rotations allowed for sequence numbering (default: 12).
    pub daily_rotations: u32,
    /// Polling interval for size check loop (default: 10 minutes).
    pub check_interval: Duration,
}

impl Default for LogRotatorConfig {
    fn default() -> Self {
        Self {
            log_files: vec![
                PathBuf::from("data/manager/logs/provigil.log"),
                PathBuf::from("data/manager/logs/provigil.json"),
            ],
            archive_dir: PathBuf::from("data/manager/logs/archive"),
            max_size_bytes: 500 * 1024 * 1024,
            keep_log_days: 31,
            compress: true,
            daily_rotations: 12,
            check_interval: Duration::from_secs(600),
        }
    }
}

/// Rotates a single log file if it exists and meets rotation conditions.
pub fn rotate_log_file(
    file_path: &Path,
    config: &LogRotatorConfig,
    force_new_day: bool,
    now: DateTime<Local>,
) -> io::Result<Option<PathBuf>> {
    if !file_path.is_file() {
        return Ok(None);
    }

    let meta = fs::metadata(file_path)?;
    let size = meta.len();

    // Only rotate if forced (new day) or size exceeds limit
    if !force_new_day && size < config.max_size_bytes {
        return Ok(None);
    }

    let file_stem = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("ossec");
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("log");

    let year = now.year();
    let mon = now.month0() as usize;
    let day = now.day();

    let year_dir = config.archive_dir.join(year.to_string());
    let month_dir = year_dir.join(MONTHS[mon]);
    fs::create_dir_all(&month_dir)?;

    // Determine target file name with sequence counter if needed
    let mut target_path = month_dir.join(format!("{file_stem}-{day:02}.{ext}"));
    let mut gz_target = month_dir.join(format!("{file_stem}-{day:02}.{ext}.gz"));

    let mut counter = 0;
    while gz_target.is_file() || target_path.is_file() {
        counter += 1;
        target_path = month_dir.join(format!("{file_stem}-{day:02}-{counter:03}.{ext}"));
        gz_target = month_dir.join(format!("{file_stem}-{day:02}-{counter:03}.{ext}.gz"));
        if counter >= config.daily_rotations {
            break;
        }
    }

    // Rename the active log file to the target archive path
    info!(
        source = %file_path.display(),
        target = %target_path.display(),
        force_new_day = force_new_day,
        size_bytes = size,
        "Rotating active log file"
    );
    fs::rename(file_path, &target_path)?;

    // Generate SHA-256 integrity checksum (.sum)
    if let Err(e) = sign_log_file(&target_path) {
        warn!(error = %e, path = %target_path.display(), "Failed to generate log checksum");
    }

    // Compress to .gz if configured
    let final_path = if config.compress {
        match compress_file(&target_path) {
            Ok(gz_path) => gz_path,
            Err(e) => {
                error!(error = %e, "Log compression failed; keeping raw archive");
                target_path
            }
        }
    } else {
        target_path
    };

    Ok(Some(final_path))
}

/// Compresses a file into gzip format and unlinks the original.
pub fn compress_file(src: &Path) -> io::Result<PathBuf> {
    let gz_path = PathBuf::from(format!("{}.gz", src.display()));
    let input = File::open(src)?;
    let output = File::create(&gz_path)?;

    let mut reader = io::BufReader::new(input);
    let mut encoder = GzEncoder::new(output, Compression::default());

    io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;

    // Remove uncompressed file
    let _ = fs::remove_file(src);
    Ok(gz_path)
}

/// Computes SHA-256 digest of a file and writes it to a `.sum` file.
pub fn sign_log_file(path: &Path) -> io::Result<PathBuf> {
    let sum_path = PathBuf::from(format!("{}.sum", path.display()));
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let digest = hasher.finalize();
    let hex_sum = format!("{:x}", digest);
    let content = format!(
        "Current checksum:\nSHA256 ({}) = {}\n",
        path.file_name().and_then(|n| n.to_str()).unwrap_or(""),
        hex_sum
    );

    fs::write(&sum_path, content)?;
    Ok(sum_path)
}

/// Purges archived log files older than `keep_log_days`.
pub fn cleanup_old_logs(
    archive_dir: &Path,
    keep_log_days: u32,
    now: DateTime<Local>,
) -> io::Result<usize> {
    if !archive_dir.is_dir() {
        return Ok(0);
    }

    let cutoff_timestamp = now.timestamp() - (keep_log_days as i64 * 86400);
    let mut removed_count = 0;

    let year_entries = match fs::read_dir(archive_dir) {
        Ok(e) => e,
        Err(_) => return Ok(0),
    };

    for year_entry in year_entries.flatten() {
        let year_path = year_entry.path();
        if !year_path.is_dir() {
            continue;
        }
        let year: i32 = match year_entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(y) => y,
            None => continue,
        };

        let month_entries = match fs::read_dir(&year_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for month_entry in month_entries.flatten() {
            let month_path = month_entry.path();
            if !month_path.is_dir() {
                continue;
            }
            let month_name = month_entry.file_name();
            let month_str = month_name.to_str().unwrap_or("");
            let month_idx = match MONTHS.iter().position(|m| *m == month_str) {
                Some(idx) => idx as u32 + 1,
                None => continue,
            };

            let file_entries = match fs::read_dir(&month_path) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for file_entry in file_entries.flatten() {
                let file_path = file_entry.path();
                let file_name = file_entry.file_name();
                let file_str = file_name.to_str().unwrap_or("");

                // Parse day from e.g. "ossec-15-001.log.gz" or "provigil-05.log"
                if let Some(day) = extract_day_from_filename(file_str) {
                    if let Some(file_date) = NaiveDate::from_ymd_opt(year, month_idx, day) {
                        if let Some(file_midnight) = Local
                            .from_local_datetime(&file_date.and_hms_opt(0, 0, 0).unwrap())
                            .earliest()
                        {
                            if file_midnight.timestamp() <= cutoff_timestamp {
                                debug!(path = %file_path.display(), "Purging expired log archive");
                                if fs::remove_file(&file_path).is_ok() {
                                    removed_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(removed_count)
}

fn extract_day_from_filename(name: &str) -> Option<u32> {
    for part in name.split('-') {
        if part.len() >= 2 {
            let prefix = &part[..2];
            if prefix.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(day) = prefix.parse::<u32>() {
                    if (1..=31).contains(&day) {
                        return Some(day);
                    }
                }
            }
        }
    }
    None
}

/// Background loop for log rotation and retention management.
pub fn start_log_rotator(config: LogRotatorConfig) {
    tokio::spawn(async move {
        info!("Started background ProVigil Log Rotator & Retention Manager");
        let mut last_day = Local::now().day();

        loop {
            tokio::time::sleep(config.check_interval).await;
            let now = Local::now();
            let current_day = now.day();
            let new_day = current_day != last_day;
            if new_day {
                last_day = current_day;
                info!("Midnight rollover detected: executing daily log rotation and cleanup");
            }

            for file in &config.log_files {
                if let Err(e) = rotate_log_file(file, &config, new_day, now) {
                    error!(file = %file.display(), error = %e, "Failed to rotate log file");
                }
            }

            if new_day {
                if let Ok(purged) = cleanup_old_logs(&config.archive_dir, config.keep_log_days, now)
                {
                    if purged > 0 {
                        info!(count = purged, "Purged expired archived logs");
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_day_extraction() {
        assert_eq!(extract_day_from_filename("provigil-05.log"), Some(5));
        assert_eq!(extract_day_from_filename("ossec-22-001.log.gz"), Some(22));
        assert_eq!(extract_day_from_filename("invalid.log"), None);
    }

    #[test]
    fn test_log_rotation_and_compression() {
        let dir = tempfile::tempdir().unwrap();
        let log_file = dir.path().join("provigil.log");
        let archive_dir = dir.path().join("archive");

        fs::write(&log_file, b"test log content line 1\ntest log line 2\n").unwrap();

        let config = LogRotatorConfig {
            log_files: vec![log_file.clone()],
            archive_dir: archive_dir.clone(),
            max_size_bytes: 10, // Small limit to trigger rotation
            keep_log_days: 30,
            compress: true,
            daily_rotations: 5,
            check_interval: Duration::from_secs(60),
        };

        let now = Local::now();
        let rotated = rotate_log_file(&log_file, &config, false, now).unwrap();
        assert!(rotated.is_some());
        let gz_path = rotated.unwrap();
        assert!(gz_path.to_str().unwrap().ends_with(".gz"));
        assert!(gz_path.is_file());

        // Checksum .sum file should exist
        let sum_path = PathBuf::from(gz_path.to_str().unwrap().trim_end_matches(".gz"))
            .with_extension("log.sum");
        assert!(
            sum_path.is_file(),
            "Checksum file {:?} should exist",
            sum_path
        );
        let sum_content = fs::read_to_string(&sum_path).unwrap();
        assert!(sum_content.contains("SHA256"));
    }
}
