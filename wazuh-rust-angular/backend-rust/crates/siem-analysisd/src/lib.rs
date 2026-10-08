//! `siem-analysisd`: port of wazuh-analysisd (src/analysisd).
//!
//! The modules mirror the C sources: event pre-decoding (`cleanevent.c`),
//! XML decoders and `DecodeEvent`, plugin decoders, rules loading and
//! matching, CDB lists, FTS/ignore, the accumulator, `doDiff`, the alert
//! JSON format and the wazuh-logtest pipeline.

pub mod analysis;
pub mod ar;
pub mod asyscom;
pub mod config_json;
pub mod daemon;
pub mod daemon_config;
pub mod decoders;
pub mod engine;
pub mod input;
pub mod internal;
pub mod event;
pub mod labels;
pub mod limits;
pub mod lists;
pub mod localtime;
pub mod logmsg;
pub mod logtest;
pub mod mitre;
pub mod output;
pub mod plugins;
pub mod rules;
pub mod ruleset;
pub mod state;
pub mod syscheck_json;
pub mod timeday;
pub mod to_json;

/// Built with `USE_GEOIP=yes` (`LIBGEOIP_ENABLED`); off in default builds.
pub const GEOIP_ENABLED: bool = false;

pub use engine::{Engine, EngineConfig};
pub use event::Event;
