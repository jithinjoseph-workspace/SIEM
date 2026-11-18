use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{info, warn};

/// High-availability multi-manager failover manager.
/// Rotates between configured managers upon consecutive connection failures.
#[derive(Debug)]
pub struct Failover {
    urls: Vec<String>,
    current: AtomicUsize,
    failures: AtomicU32,
    max_retries: u32,
    retry_interval: Duration,
}

impl Failover {
    pub fn new(urls: Vec<String>, max_retries: u32, retry_interval: Duration) -> Self {
        let clean_urls: Vec<String> = urls
            .into_iter()
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .collect();

        let urls = if clean_urls.is_empty() {
            vec!["https://127.0.0.1:8443".to_string()]
        } else {
            clean_urls
        };

        Self {
            urls,
            current: AtomicUsize::new(0),
            failures: AtomicU32::new(0),
            max_retries: max_retries.max(1),
            retry_interval,
        }
    }

    /// Return the currently active manager URL.
    pub fn current_url(&self) -> String {
        let idx = self.current.load(Ordering::Relaxed) % self.urls.len();
        self.urls[idx].clone()
    }

    /// Return all configured manager URLs.
    pub fn all_urls(&self) -> Vec<String> {
        self.urls.clone()
    }

    /// Dynamically update the manager list (e.g. from central group config).
    pub fn update_urls(&mut self, new_urls: Vec<String>) {
        let clean: Vec<String> = new_urls
            .into_iter()
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .collect();

        if !clean.is_empty() && clean != self.urls {
            info!("Failover: Updating manager URLs list: {:?}", clean);
            self.urls = clean;
            self.current.store(0, Ordering::Relaxed);
            self.failures.store(0, Ordering::Relaxed);
        }
    }

    /// Report a successful connection / request to the current manager.
    pub fn report_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }

    /// Report a failed request or network error. Returns `true` if failover occurred.
    pub async fn report_failure(&self) -> bool {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.max_retries {
            if self.urls.len() > 1 {
                tokio::time::sleep(self.retry_interval).await;
                let next = (self.current.load(Ordering::Relaxed) + 1) % self.urls.len();
                self.current.store(next, Ordering::Relaxed);
                self.failures.store(0, Ordering::Relaxed);
                warn!(
                    "Failover: Max retries ({}) reached. Failing over to manager [{}]: {}",
                    self.max_retries, next, self.urls[next]
                );
                return true;
            } else {
                warn!(
                    "Failover: Manager unreachable, retried {} times (only 1 manager configured).",
                    failures
                );
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_failover_rotation() {
        let urls = vec![
            "https://mgr1.local:8443".to_string(),
            "https://mgr2.local:8443".to_string(),
            "https://mgr3.local:8443".to_string(),
        ];
        let failover = Failover::new(urls, 2, Duration::from_millis(10));

        assert_eq!(failover.current_url(), "https://mgr1.local:8443");

        // First failure: below max_retries
        let rotated = failover.report_failure().await;
        assert!(!rotated);
        assert_eq!(failover.current_url(), "https://mgr1.local:8443");

        // Second failure: reaches max_retries (2), rotates to mgr2
        let rotated = failover.report_failure().await;
        assert!(rotated);
        assert_eq!(failover.current_url(), "https://mgr2.local:8443");

        // Success resets failure count
        failover.report_success();

        // 2 more failures rotate to mgr3
        failover.report_failure().await;
        failover.report_failure().await;
        assert_eq!(failover.current_url(), "https://mgr3.local:8443");

        // 2 more failures wrap back to mgr1
        failover.report_failure().await;
        failover.report_failure().await;
        assert_eq!(failover.current_url(), "https://mgr1.local:8443");
    }
}
