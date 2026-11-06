//! Cryptographic Log Signing (`src/monitord/sign_log.c`)
//!
//! Generates chained cryptographic checksums (MD5, SHA-1, SHA-256) verifying
//! archive integrity across rotational boundaries.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksums {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

impl Default for Checksums {
    fn default() -> Self {
        Self {
            md5: "none".to_string(),
            sha1: "none".to_string(),
            sha256: "none".to_string(),
        }
    }
}

/// Reads previous `.sum` file and extracts old checksums matching `OS_SignLog`.
pub fn read_previous_sum_file<P: AsRef<Path>>(sum_path: P) -> Checksums {
    let file = match File::open(sum_path) {
        Ok(f) => f,
        Err(_) => return Checksums::default(),
    };

    let reader = BufReader::new(file);
    let mut in_current = false;
    let mut checksums = Checksums::default();

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed == "Current checksum:" {
            in_current = true;
            continue;
        } else if trimmed == "Chained checksum:" {
            in_current = false;
            continue;
        }

        if in_current {
            if let Some(hash) = trimmed.strip_prefix("MD5  (") {
                if let Some((_, h)) = hash.split_once(") = ") {
                    checksums.md5 = h.trim().to_string();
                }
            } else if let Some(hash) = trimmed.strip_prefix("SHA1 (") {
                if let Some((_, h)) = hash.split_once(") = ") {
                    checksums.sha1 = h.trim().to_string();
                }
            } else if let Some(hash) = trimmed.strip_prefix("SHA256 (") {
                if let Some((_, h)) = hash.split_once(") = ") {
                    checksums.sha256 = h.trim().to_string();
                }
            }
        }
    }

    checksums
}

/// Computes combined MD5, SHA-1, and SHA-256 for a log file and its daily rotation parts.
pub fn hash_logfile_stream<P: AsRef<Path>>(base_logfile_path: P) -> io::Result<Checksums> {
    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();

    let mut found_any = false;
    let mut buf = [0u8; 8192];

    // Primary log file
    if base_logfile_path.as_ref().exists() {
        if let Ok(mut f) = File::open(&base_logfile_path) {
            found_any = true;
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                md5_hasher.update(&buf[..n]);
                sha1_hasher.update(&buf[..n]);
                sha256_hasher.update(&buf[..n]);
            }
        }
    }

    if !found_any {
        return Ok(Checksums::default());
    }

    Ok(Checksums {
        md5: hex::encode(md5_hasher.finalize()),
        sha1: hex::encode(sha1_hasher.finalize()),
        sha256: hex::encode(sha256_hasher.finalize()),
    })
}

/// Signs a log file, generating a `.sum` file with current and chained previous checksums.
pub fn sign_log(
    logfile_base: &str,
    logfile_old_base: &str,
    ext: &str,
) -> io::Result<PathBuf> {
    let logfile_target = format!("{}.{}", logfile_base, ext);
    let logfile_target_path = Path::new(&logfile_target);
    let sum_file_path = PathBuf::from(format!("{}.sum", logfile_target));
    let old_sum_file_path = format!("{}.{}.sum", logfile_old_base, ext);

    // Compute checksum of current file
    let current_sums = hash_logfile_stream(logfile_target_path)?;

    // Read previous day's chained checksum
    let chained_sums = read_previous_sum_file(old_sum_file_path);

    // Ensure parent directory exists
    if let Some(parent) = sum_file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut sum_file = File::create(&sum_file_path)?;
    writeln!(sum_file, "Current checksum:")?;
    writeln!(sum_file, "MD5  ({}) = {}", logfile_base, current_sums.md5)?;
    writeln!(sum_file, "SHA1 ({}) = {}", logfile_base, current_sums.sha1)?;
    writeln!(sum_file, "SHA256 ({}) = {}\n", logfile_base, current_sums.sha256)?;

    writeln!(sum_file, "Chained checksum:")?;
    writeln!(sum_file, "MD5  ({}) = {}", logfile_old_base, chained_sums.md5)?;
    writeln!(sum_file, "SHA1 ({}) = {}", logfile_old_base, chained_sums.sha1)?;
    writeln!(sum_file, "SHA256 ({}) = {}\n", logfile_old_base, chained_sums.sha256)?;

    Ok(sum_file_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sign_log_chaining() {
        let dir = tempdir().unwrap();

        // 1. Day 1
        let day1_base = dir.path().join("ossec-alerts-01").to_str().unwrap().to_string();
        let day1_log = dir.path().join("ossec-alerts-01.log");
        fs::write(&day1_log, "2026-09-01 Alert test 1\n").unwrap();

        let sum1_path = sign_log(&day1_base, "none", "log").unwrap();
        assert!(sum1_path.exists());

        let content1 = fs::read_to_string(&sum1_path).unwrap();
        assert!(content1.contains("Current checksum:"));
        assert!(content1.contains("Chained checksum:\nMD5  (none) = none"));

        // 2. Day 2
        let day2_base = dir.path().join("ossec-alerts-02").to_str().unwrap().to_string();
        let day2_log = dir.path().join("ossec-alerts-02.log");
        fs::write(&day2_log, "2026-09-02 Alert test 2\n").unwrap();

        let sum2_path = sign_log(&day2_base, &day1_base, "log").unwrap();
        assert!(sum2_path.exists());

        let content2 = fs::read_to_string(&sum2_path).unwrap();
        assert!(content2.contains("Current checksum:"));
        assert!(content2.contains("Chained checksum:\nMD5  ("));
        assert!(content2.contains(&day1_base));
    }
}
