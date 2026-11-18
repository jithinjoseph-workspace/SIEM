//! The managers this agent sends to, in failover order: `manager_url` first, then the
//! `manager_urls` of agent-config.json or `SIEM_MANAGER_URLS` (comma separated). After
//! `SWITCH_AFTER` requests in a row that do not reach the manager in use, the next one is
//! used; the list wraps, so the first is tried again after the last. Every request looks
//! the name up again, so a DNS name follows the manager when its address changes.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::OnceLock;
use tracing::warn;

/// Requests in a row that do not reach a manager before the next one is tried.
const SWITCH_AFTER: u32 = 3;

pub struct Failover {
    urls: Vec<String>,
    current: AtomicUsize,
    fails: AtomicU32,
}

impl Failover {
    /// `primary` first, then `extra`; trimmed, without a trailing '/', no repeats.
    pub fn new(primary: &str, extra: &[String]) -> Self {
        let mut urls: Vec<String> = Vec::new();
        for u in std::iter::once(primary).chain(extra.iter().map(String::as_str)) {
            let u = u.trim().trim_end_matches('/');
            if !u.is_empty() && !urls.iter().any(|x| x == u) {
                urls.push(u.to_string());
            }
        }
        Self { urls, current: AtomicUsize::new(0), fails: AtomicU32::new(0) }
    }

    pub fn current(&self) -> Option<&str> {
        (!self.urls.is_empty()).then(|| self.urls[self.current.load(Ordering::SeqCst) % self.urls.len()].as_str())
    }

    /// A request's outcome: `reached` is any answer from the manager below HTTP 500.
    pub fn report(&self, reached: bool) {
        if reached {
            self.fails.store(0, Ordering::SeqCst);
            return;
        }
        if self.urls.len() < 2 || self.fails.fetch_add(1, Ordering::SeqCst) + 1 < SWITCH_AFTER {
            return;
        }
        self.fails.store(0, Ordering::SeqCst);
        let next = (self.current.load(Ordering::SeqCst) + 1) % self.urls.len();
        self.current.store(next, Ordering::SeqCst);
        warn!("Manager not reachable; trying the next one in the list: {}", self.urls[next]);
    }
}

static MANAGERS: OnceLock<Failover> = OnceLock::new();

/// Set once at start, from the configuration.
pub fn init(primary: &str, extra: &[String]) {
    let _ = MANAGERS.set(Failover::new(primary, extra));
}

/// The manager to use now; `configured` before `init` (and in tests).
pub fn url(configured: &str) -> String {
    MANAGERS.get().and_then(Failover::current).unwrap_or(configured.trim_end_matches('/')).to_string()
}

/// Every manager of the list (`configured` alone before `init`).
pub fn all(configured: &str) -> Vec<String> {
    match MANAGERS.get() {
        Some(f) if !f.urls.is_empty() => f.urls.clone(),
        _ => vec![configured.trim_end_matches('/').to_string()],
    }
}

/// Counts a request to the manager in use: reached or not.
pub fn report(reached: bool) {
    if let Some(f) = MANAGERS.get() {
        f.report(reached);
    }
}

/// Whether an HTTP answer means the manager was reached (a server error counts as not).
pub fn reached<T>(r: &Result<reqwest::Response, T>) -> bool {
    matches!(r, Ok(res) if !res.status().is_server_error())
}

/// The manager list from agent-config.json's `manager_urls` and `SIEM_MANAGER_URLS`.
pub fn extra_from(config_json: Option<&serde_json::Value>) -> Vec<String> {
    let mut v: Vec<String> = config_json
        .and_then(|c| c.get("manager_urls"))
        .and_then(|u| u.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(String::from).collect())
        .unwrap_or_default();
    if let Ok(env) = std::env::var("SIEM_MANAGER_URLS") {
        v.extend(env.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switches_after_failures_and_wraps() {
        let f = Failover::new("https://a:8443/", &["https://b:8443".into(), "https://a:8443".into(), " ".into()]);
        assert_eq!(f.urls, vec!["https://a:8443", "https://b:8443"], "trimmed, no repeats");
        f.report(false);
        f.report(false);
        f.report(true);
        f.report(false);
        f.report(false);
        assert_eq!(f.current(), Some("https://a:8443"), "a success in between resets the count");
        f.report(false);
        assert_eq!(f.current(), Some("https://b:8443"));
        (0..3).for_each(|_| f.report(false));
        assert_eq!(f.current(), Some("https://a:8443"), "wraps to the first");
        let one = Failover::new("https://only", &[]);
        (0..10).for_each(|_| one.report(false));
        assert_eq!(one.current(), Some("https://only"));
    }

    #[test]
    fn list_from_config() {
        let c = serde_json::json!({ "manager_urls": ["https://siem.corp:8443", 5, "https://10.0.0.5:8443"] });
        let v = extra_from(Some(&c));
        assert!(v.starts_with(&["https://siem.corp:8443".to_string(), "https://10.0.0.5:8443".to_string()]));
        assert_eq!(url("https://x/"), "https://x", "before init: the configured one");
    }
}
