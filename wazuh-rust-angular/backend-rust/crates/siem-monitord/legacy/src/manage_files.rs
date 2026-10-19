//! Daily Archive & Alert File Manager (`src/monitord/manage_files.c`)
//!
//! Signs and compresses historical logs across categories (`archive`, `alerts`, `firewall`)
//! in both standard `.log` and structured `.json` formats.

use crate::compress_log::compress_log;
use crate::rotate_log::MONTHS;
use crate::sign_log::sign_log;
use chrono::{Datelike, Duration, Local};
use std::io;
use std::path::{Path, PathBuf};
use tracing::info;

pub const DIR_ALERTS: &str = "logs/alerts";
pub const DIR_ARCHIVES: &str = "logs/archives";
pub const DIR_FIREWALL: &str = "logs/firewall";

pub struct DailyFileManager {
    pub base_dir: PathBuf,
    pub compress: bool,
}

impl DailyFileManager {
    pub fn new<P: AsRef<Path>>(base_dir: P, compress: bool) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
            compress,
        }
    }

    /// Executes daily signing and compression for all archive types matching `manage_files`.
    pub fn manage_daily_files(&self) -> io::Result<()> {
        let now = Local::now();
        let prev_day = now - Duration::days(1);

        let cday = prev_day.day();
        let cmon = (prev_day.month() - 1) as usize;
        let cyear = prev_day.year();

        let day_before = prev_day - Duration::days(1);
        let old_day = day_before.day();
        let old_mon = (day_before.month() - 1) as usize;
        let old_year = day_before.year();

        info!(
            "Running daily log management for {:04}-{:02}-{:02}...",
            cyear,
            cmon + 1,
            cday
        );

        // Archives
        self.manage_log_type(DIR_ARCHIVES, "archive", "log", cday, cmon, cyear, old_day, old_mon, old_year)?;
        self.manage_log_type(DIR_ARCHIVES, "archive", "json", cday, cmon, cyear, old_day, old_mon, old_year)?;

        // Alerts
        self.manage_log_type(DIR_ALERTS, "alerts", "log", cday, cmon, cyear, old_day, old_mon, old_year)?;
        self.manage_log_type(DIR_ALERTS, "alerts", "json", cday, cmon, cyear, old_day, old_mon, old_year)?;

        // Firewall
        self.manage_log_type(DIR_FIREWALL, "firewall", "log", cday, cmon, cyear, old_day, old_mon, old_year)?;

        Ok(())
    }

    fn manage_log_type(
        &self,
        subdir: &str,
        tag: &str,
        ext: &str,
        cday: u32,
        cmon: usize,
        cyear: i32,
        old_day: u32,
        old_mon: usize,
        old_year: i32,
    ) -> io::Result<()> {
        let month_str = MONTHS[cmon];
        let old_month_str = MONTHS[old_mon];

        let target_dir = self.base_dir.join(subdir).join(format!("{}/{}", cyear, month_str));
        let old_dir = self.base_dir.join(subdir).join(format!("{}/{}", old_year, old_month_str));

        let logfile_base = target_dir.join(format!("ossec-{}-{:02}", tag, cday));
        let old_logfile_base = old_dir.join(format!("ossec-{}-{:02}", tag, old_day));

        let logfile_target = format!("{}.{}", logfile_base.display(), ext);
        if !Path::new(&logfile_target).exists() {
            return Ok(());
        }

        // 1. Sign log
        let _ = sign_log(
            &logfile_base.display().to_string(),
            &old_logfile_base.display().to_string(),
            ext,
        );

        // 2. Compress log
        if self.compress {
            let _ = compress_log(&logfile_target);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_manage_files_lifecycle() {
        let dir = tempdir().unwrap();
        let manager = DailyFileManager::new(dir.path(), true);

        let now = Local::now();
        let prev = now - Duration::days(1);
        let month_str = MONTHS[(prev.month() - 1) as usize];

        let alerts_dir = dir
            .path()
            .join(DIR_ALERTS)
            .join(format!("{}/{}", prev.year(), month_str));
        fs::create_dir_all(&alerts_dir).unwrap();

        let alert_file = alerts_dir.join(format!("ossec-alerts-{:02}.log", prev.day()));
        fs::write(&alert_file, "2026-09-27 Alert entry\n").unwrap();

        manager.manage_daily_files().unwrap();

        // Should produce .log.gz and .log.sum
        let sum_file = alerts_dir.join(format!("ossec-alerts-{:02}.log.sum", prev.day()));
        let gz_file = alerts_dir.join(format!("ossec-alerts-{:02}.log.gz", prev.day()));

        assert!(sum_file.exists());
        assert!(gz_file.exists());
        assert!(!alert_file.exists());
    }
}
