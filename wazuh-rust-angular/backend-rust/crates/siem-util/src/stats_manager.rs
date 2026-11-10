use std::path::PathBuf;

pub struct StatsManager {
    pub base_stats_dir: PathBuf,
}

impl StatsManager {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_stats_dir: base_dir.into(),
        }
    }

    /// Clear daily stats files
    pub fn clear_daily(&self) -> std::io::Result<usize> {
        let mut count = 0;
        let daily_dir = self.base_stats_dir.join("daily");
        if daily_dir.exists() {
            for entry in std::fs::read_dir(daily_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    std::fs::remove_file(entry.path())?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Clear weekly stats files across subdirectories 0-6
    pub fn clear_weekly(&self) -> std::io::Result<usize> {
        let mut count = 0;
        let weekly_dir = self.base_stats_dir.join("weekly");
        if weekly_dir.exists() {
            for day in 0..=6 {
                let day_dir = weekly_dir.join(day.to_string());
                if day_dir.exists() {
                    for entry in std::fs::read_dir(day_dir)? {
                        let entry = entry?;
                        if entry.file_type()?.is_file() {
                            std::fs::remove_file(entry.path())?;
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    /// Clear all stats (daily + weekly)
    pub fn clear_all(&self) -> std::io::Result<usize> {
        let daily = self.clear_daily()?;
        let weekly = self.clear_weekly()?;
        Ok(daily + weekly)
    }
}
