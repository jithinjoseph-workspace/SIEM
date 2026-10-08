//! Wazuh Monitoring, Disconnection Detector, Log Rotator & Report Subsystem (`src/monitord`)
//!
//! Provides agent keepalive tracking, disconnection detection and alerting,
//! automatic deletion of abandoned agents, daily and size-based log rotation,
//! cryptographic checksum chaining (`.sum`), gzip compression, and daily email summaries.

pub mod compress_log;
pub mod config;
pub mod daemon;
pub mod generate_reports;
pub mod manage_files;
pub mod moncom;
pub mod monitor_actions;
pub mod rotate_log;
pub mod sign_log;
pub mod time_control;

pub use compress_log::compress_log;
pub use config::{MonitorConfig, ReportConfig, ReportFilter};
pub use daemon::MonitorDaemon;
pub use generate_reports::{generate_report_from_file, ReportSummary};
pub use manage_files::DailyFileManager;
pub use moncom::{moncom_dispatch, moncom_getconfig};
pub use monitor_actions::{AgentMonitorEngine, AgentStatus, MonitoredAgent};
pub use rotate_log::{remove_old_logs, rotate_log_file, MONTHS};
pub use sign_log::{hash_logfile_stream, read_previous_sum_file, sign_log, Checksums};
pub use time_control::MonitorTimeControl;
