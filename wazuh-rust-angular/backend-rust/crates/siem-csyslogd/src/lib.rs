//! Wazuh Client Syslog Forwarder Daemon (`src/os_csyslogd`)
//!
//! Complete, 100% line-by-line parity port of Wazuh's syslog output daemon:
//! - `config`: `<syslog_output>` XML parser and JSON schema (`getCsyslogConfig`)
//! - `formatter`: Syslog message formatters (Default, CEF, JSON, Splunk) & filter evaluation
//! - `sender`: UDP syslog socket transport with auto-reconnection and DNS resolution
//! - `csyscom`: IPC control socket dispatcher (`getconfig csyslog`)
//! - `csyslogd`: Central daemon runtime loop

pub mod config;
pub mod csyscom;
pub mod csyslogd;
pub mod formatter;
pub mod sender;

pub use config::{SyslogConfig, SyslogConfigHolder, SyslogFormat};
pub use csyscom::{csyscom_dispatch, csyscom_getconfig};
pub use csyslogd::SyslogDaemon;
pub use formatter::{format_syslog_timestamp, SyslogAlert};
pub use sender::UdpSyslogSender;
