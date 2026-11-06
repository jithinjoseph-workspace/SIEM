//! What provigil-gateway and siem-api share on the agent side. Phase 2 of the gateway moves
//! siem-api onto these modules and deletes its own copies (`http_agent_state.rs`,
//! `agent_config.rs`, parts of `agent_grpc.rs`, `provigil_manager.rs`, `agent_keys_store.rs`).

pub mod agent_config;
pub mod agent_state;
pub mod commands;
pub mod engine;
pub mod keys;
pub mod published;
pub mod tls;

/// The shared database: keys, registry, tenants, command queue.
pub const DEFAULT_DB: &str = "ndr";
