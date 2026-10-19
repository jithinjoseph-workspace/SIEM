//! Port of `wazuh-integratord` (`src/os_integrator`, Wazuh 4.14.7) and of the
//! integration scripts it runs (`integrations/{slack,pagerduty,virustotal,
//! shuffle,maltiverse}.py`), so the manager needs no Python.

pub mod config;
pub mod integrator;
pub mod pyjson;
pub mod scripts;

/// `strerror(errno)` text of an I/O error.
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.split(" (os error").next().unwrap_or(&s).to_string()
}
