//! ProVigil manager analysis (see specs/provigil-analysisd.md).

pub mod alert_json;
pub mod builtin;
pub mod config;
pub mod daemon;
pub mod decoders;
pub mod engine;
pub mod host;
pub mod event;
pub mod getconfig;
pub mod limits;
pub mod lists;
pub mod logtest;
pub mod messages;
pub mod mitre;
pub mod plugins;
pub mod process;
pub mod queues;
pub mod responses;
pub mod rules;
pub mod socket;
pub mod stats;
pub mod text_logs;
pub mod time;
