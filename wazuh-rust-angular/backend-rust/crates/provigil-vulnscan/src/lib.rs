//! ProVigil vulnerability scanner.
//!
//! Keeps, per agent, the CVEs that affect its installed software and operating system: downloads
//! the vulnerability feed, matches inventory events against it, publishes state documents and
//! sends alerts for real-time changes. Specification: `specs/vulnerability-scanner.md`.

#[macro_use]
pub mod log;

pub mod agentdb;
pub mod config;
pub mod cpe;
pub mod event;
pub mod feed;
pub mod host;
pub mod inventory;
pub mod json;
pub mod kvstore;
pub mod legacy_names;
pub mod lru;
pub mod output;
pub mod patch;
pub mod queue;
pub mod report;
pub mod scan;
pub mod scanner;
pub mod schema;
pub mod sink;
pub mod updater;
pub mod version;

#[cfg(test)]
mod tests;

pub use scanner::{Router, Scanner, StartOptions};
