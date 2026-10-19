//! Port of `wazuh-monitord` (`src/monitord`, Wazuh 4.14.7).
//!
//! * marks agents without keepalive as disconnected in wazuh-db and raises
//!   the "Agent disconnected" alert (rule 504) through analysisd's queue;
//! * optionally removes agents disconnected for too long (`delete_old_agents`);
//! * rotates `logs/ossec.log` / `logs/ossec.json` by day and by size;
//! * signs and compresses the previous day's alerts/archives/firewall logs;
//! * answers `getconfig` on `queue/sockets/monitor`;
//! * sends the daily `<reports>` e-mails (report and SMTP code in siem-maild).

pub mod actions;
pub mod compress_log;
pub mod config;
pub mod manage_files;
pub mod moncom;
pub mod monitord;
pub mod mq;
pub mod rotate_log;
pub mod sign_log;
pub mod wdb;

use siem_log::WLog;

pub const ARGV0: &str = "wazuh-monitord";
/// `LOGFILE` / `LOGJSONFILE` (manager layout)
pub const LOGFILE: &str = "logs/ossec.log";
pub const LOGJSONFILE: &str = "logs/ossec.json";
/// `DEFAULTQUEUE`
pub const DEFAULTQUEUE: &str = "queue/sockets/queue";
/// `MON_LOCAL_SOCK`
pub const MON_LOCAL_SOCK: &str = "queue/sockets/monitor";
/// `AUTH_LOCAL_SOCK`
pub const AUTH_LOCAL_SOCK: &str = "queue/sockets/auth";
/// `KEYS_FILE`
pub const KEYS_FILE: &str = "etc/client.keys";
/// `QUEUE_SEND`
pub const QUEUE_SEND: &str = "(1224): Error sending message to queue.";

pub const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// `strerror(errno)` text of an I/O error.
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.split(" (os error").next().unwrap_or(&s).to_string()
}

/// `IsFile(path) == 0`: a regular file exists.
pub fn is_file(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

/// `FileSize`: -1 when it cannot be stat'ed.
pub fn file_size(path: &str) -> i64 {
    std::fs::metadata(path).map(|m| m.len() as i64).unwrap_or(-1)
}

/// `merror_exit`
pub fn fatal(log: &WLog, msg: &str) -> ! {
    log.critical(msg);
    siem_daemon::handle_exit();
    std::process::exit(1);
}
