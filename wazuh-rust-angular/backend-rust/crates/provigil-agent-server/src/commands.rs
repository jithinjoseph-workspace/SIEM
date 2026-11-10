//! The shared command queue and the "talks the ProVigil protocol" mark in ClickHouse
//! (`specs/provigil-gateway.md` 3.3, `AGENT-REVIEW-FIXES.md` R.3). siem-api writes queued
//! commands and cancellations; a gateway writes handed out, done / failed, expired, no result.
//!
//! One row per command, last `version` wins: each writer sends the whole row.

use serde::{Deserialize, Serialize};

pub const TABLE: &str = "agent_command_queue";
pub const PROTOCOL_TABLE: &str = "agent_protocol";

pub const QUEUED: &str = "queued";
pub const HANDED: &str = "handed";
pub const DONE: &str = "done";
pub const FAILED: &str = "failed";
pub const EXPIRED: &str = "expired";
pub const CANCELLED: &str = "cancelled";
pub const NO_RESULT: &str = "no_result";

/// Waiting commands per agent; the oldest is expired beyond that.
pub const MAX_PER_AGENT: usize = 200;
pub const DEFAULT_TTL_MS: u64 = 24 * 3600 * 1000;
pub const LIVE_TTL_MS: u64 = 30_000;
/// A command handed out with no result after this long may be offered once more.
pub const RESULT_WAIT_MS: u64 = 120_000;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS agent_command_queue (
    agent_id String, command_id String, tenant_id LowCardinality(String),
    command String, origin LowCardinality(String),
    created_at UInt64, expires_at UInt64,
    state LowCardinality(String), state_at UInt64,
    gateway String, attempts UInt8, result String, version UInt64
) ENGINE = ReplacingMergeTree(version) ORDER BY (agent_id, command_id)
TTL toDateTime(intDiv(created_at, 1000)) + INTERVAL 30 DAY";

/// One row per agent that spoke the ProVigil protocol; a table of its own because siem-api writes
/// whole `agent_registry` rows, which would reset a column it does not know.
pub const PROTOCOL_DDL: &str = "CREATE TABLE IF NOT EXISTS agent_protocol (
    agent_id String, protocol LowCardinality(String), updated_at UInt64
) ENGINE = ReplacingMergeTree(updated_at) ORDER BY agent_id";

#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct CommandRow {
    pub agent_id: String,
    pub command_id: String,
    pub tenant_id: String,
    /// The command exactly as the agent receives it (JSON text).
    pub command: String,
    /// `console:<user>`, `engine` or `gateway`.
    pub origin: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub state: String,
    pub state_at: u64,
    pub gateway: String,
    pub attempts: u8,
    pub result: String,
    pub version: u64,
}

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ProtocolRow {
    pub agent_id: String,
    pub protocol: String,
    pub updated_at: u64,
}

/// Types the agent can safely run twice; an `ar` waits until it drops repeated command ids.
pub fn repeatable(kind: &str) -> bool {
    matches!(kind, "scan" | "getconfig" | "getstate" | "inventory_full" | "sca_full" | "fim_state_allowed" | "upgrade")
}

/// Whether a state is final: the row leaves a gateway's cache.
pub fn terminal(state: &str) -> bool {
    !matches!(state, QUEUED | HANDED)
}
