//! Port of `wazuh-maild` (`src/os_maild`, Wazuh 4.14.7): e-mail alerts from
//! `alerts.json` / `alerts.log`, granular `<email_alerts>`, grouping, SMS
//! format, `email_maxperhour`, and the daily reports (`shared/report_op.c`)
//! monitord sends.
//!
//! Extension (not in Wazuh): SMTP over TLS with login, see [`smtp_ext`].

pub mod alert;
pub mod cfile;
pub mod client;
pub mod config;
pub mod maild;
pub mod report;
pub mod smtp;
pub mod smtp_ext;

use std::sync::{Arc, OnceLock};

use siem_log::WLog;

static LOG: OnceLock<Arc<WLog>> = OnceLock::new();

/// The daemon's logger (monitord installs its own when it sends reports).
pub fn set_logger(l: Arc<WLog>) {
    let _ = LOG.set(l);
}

pub fn log() -> &'static WLog {
    LOG.get_or_init(|| Arc::new(WLog::new_server("wazuh-maild", std::path::Path::new(""))))
}

/// `strerror(errno)` text of an I/O error.
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.split(" (os error").next().unwrap_or(&s).to_string()
}

/// `CreateThread`'s debug line (`wazuh.thread_stack_size`, KiB).
pub fn log_thread_start(log: &WLog) {
    let o = siem_config::internal_options::InternalOptions::from_home("");
    match o.get_int("wazuh", "thread_stack_size", 2048, 65536) {
        Ok(kib) => log.debug2(format!("Thread stack size set to: {kib} KiB")),
        // getDefine_Int: merror_exit
        Err(e) => {
            log.critical(&e.0);
            std::process::exit(1);
        }
    }
}
