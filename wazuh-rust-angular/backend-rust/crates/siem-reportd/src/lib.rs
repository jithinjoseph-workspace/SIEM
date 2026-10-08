//! Wazuh Report Generator Subsystem (`src/reportd`)
//!
//! Generates summary reports, frequency distributions, and related correlations
//! across alert log files and event streams.

pub mod engine;
pub mod filter;

pub use engine::ReportEngine;
pub use filter::{AlertRecord, ReportFilter};
