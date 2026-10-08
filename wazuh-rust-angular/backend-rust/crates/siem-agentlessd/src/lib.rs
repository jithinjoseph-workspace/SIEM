//! Wazuh Agentless Monitoring Subsystem (`src/agentlessd`)
//!
//! Executes periodic SSH/Expect integrity checks, diff tracking for network devices,
//! and forwards changes as security alerts.

pub mod config;
pub mod daemon;
pub mod diff;
pub mod executor;
pub mod lessdcom;

pub use config::{AgentlessConfig, AgentlessEntry, LESSD_STATE_CONNECTED, LESSD_STATE_DIFF, LESSD_STATE_PERIODIC};
pub use daemon::AgentlessDaemon;
pub use diff::{check_diff_file, open_diff_file};
pub use executor::{AgentlessExecutor, ScriptOutputMessage};
pub use lessdcom::{lessdcom_dispatch, lessdcom_getconfig};
