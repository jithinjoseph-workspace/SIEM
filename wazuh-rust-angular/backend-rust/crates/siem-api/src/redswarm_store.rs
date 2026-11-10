//! Red Swarm audit trail (execution records + synthesized rule drafts) kept in
//! ClickHouse so history, detection gaps and draft rules survive restarts.
//! ClickHouse is the master copy: it is loaded into the in-memory `AuditStore`
//! at start, then the store is written back as it changes. Each row stores the
//! full record as a JSON blob (every model derives serde), so the schema does
//! not have to track the model.
//!
//! Records are append-only (unique UUID each), so each instance flushes only its
//! own new rows by sequence number. Drafts change status (approve/reject/rollback),
//! so ClickHouse is the single source of truth: status changes are written through
//! immediately (`upsert_draft`) and every instance re-reads drafts each tick. This
//! stops a stale instance from overwriting another's approval.

use std::collections::HashSet;
use std::time::Duration;

use clickhouse::Row;
use serde::{Deserialize, Serialize};
use siem_redswarm::{ExecutionRecord, SynthesizedRuleDraft};
use tracing::{info, warn};

use crate::tenancy::DEFAULT_DB;
use crate::AppState;

/// Execution rows older than this are dropped by ClickHouse (drafts are kept).
const RETENTION_DAYS: u32 = 90;

#[derive(Row, Serialize, Deserialize)]
struct BlobRow {
    id: String,
    json: String,
    updated_at: u64,
}

async fn ensure_tables(state: &AppState) -> bool {
    let exec = format!(
        "CREATE TABLE IF NOT EXISTS `{DEFAULT_DB}`.redswarm_executions (
            id String, json String, updated_at UInt64
        ) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id
        TTL toDateTime(updated_at / 1000) + INTERVAL {RETENTION_DAYS} DAY"
    );
    let drafts = format!(
        "CREATE TABLE IF NOT EXISTS `{DEFAULT_DB}`.redswarm_drafts (
            id String, json String, updated_at UInt64
        ) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id"
    );
    for q in [&exec, &drafts] {
        if state.db.root().query(q).execute().await.map_err(|e| warn!("redswarm_store: {e}")).is_err() {
            return false;
        }
    }
    // Apply the TTL to a table created before this version, too.
    let alter = format!(
        "ALTER TABLE `{DEFAULT_DB}`.redswarm_executions MODIFY TTL toDateTime(updated_at / 1000) + INTERVAL {RETENTION_DAYS} DAY"
    );
    let _ = state.db.root().query(&alter).execute().await;
    true
}

/// None when ClickHouse could not be read (not the same as an empty table).
async fn fetch<T: for<'de> Deserialize<'de>>(state: &AppState, table: &str) -> Option<Vec<T>> {
    let rows = match state
        .db
        .root()
        .query(&format!("SELECT ?fields FROM `{DEFAULT_DB}`.{table} FINAL"))
        .fetch_all::<BlobRow>()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("redswarm_store: {e}");
            return None;
        }
    };
    Some(rows.iter()
        .filter_map(|r| serde_json::from_str::<T>(&r.json).map_err(|e| warn!("redswarm_store: bad row {}: {e}", r.id)).ok())
        .collect())
}

/// Load the persisted audit trail into the in-memory store. No-op when ClickHouse is down.
pub async fn load(state: &AppState) {
    if !state.db.is_connected() || !ensure_tables(state).await {
        return;
    }
    let records: Vec<ExecutionRecord> = fetch(state, "redswarm_executions").await.unwrap_or_default();
    let drafts: Vec<SynthesizedRuleDraft> = fetch(state, "redswarm_drafts").await.unwrap_or_default();
    info!("Loaded {} Red Swarm execution records and {} rule drafts from ClickHouse", records.len(), drafts.len());
    state.redswarm.audit().restore(records, drafts);
}

async fn write_rows(state: &AppState, table: &str, rows: &[BlobRow]) -> bool {
    if rows.is_empty() {
        return true;
    }
    let mut ins = match state.db.root().clone().with_database(DEFAULT_DB).insert(table) {
        Ok(i) => i,
        Err(e) => {
            warn!("redswarm_store: {e}");
            return false;
        }
    };
    for r in rows {
        if let Err(e) = ins.write(r).await {
            warn!("redswarm_store: {e}");
            return false;
        }
    }
    if let Err(e) = ins.end().await {
        warn!("redswarm_store: {e}");
        return false;
    }
    true
}

fn blob<T: Serialize>(id: String, v: &T, at: u64) -> Option<BlobRow> {
    serde_json::to_string(v).map(|json| BlobRow { id, json, updated_at: at }).ok()
}

/// Write a single draft to ClickHouse now (called from the approve/reject/rollback
/// handlers so a status change lands immediately and wins by its newer timestamp).
pub async fn upsert_draft(state: &AppState, draft: &SynthesizedRuleDraft) {
    if !state.db.is_connected() {
        return;
    }
    let at = chrono::Utc::now().timestamp_millis() as u64;
    if let Some(row) = blob(draft.id.to_string(), draft, at) {
        write_rows(state, "redswarm_drafts", &[row]).await;
    }
}

/// Flushes new execution records and newly-created drafts to ClickHouse, and
/// re-reads drafts back (ClickHouse is the source of truth for draft status) every 10 s.
pub fn spawn_sync(state: AppState) {
    if !state.db.is_connected() {
        return;
    }
    tokio::spawn(async move {
        let audit = state.redswarm.audit();
        // Records already loaded from ClickHouse are persisted; start after them.
        let mut last_seq = audit.recorded_seq();
        let mut persisted_drafts: HashSet<String> = audit.all_drafts().iter().map(|d| d.id.to_string()).collect();
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;

            // New execution records, by sequence (survives in-memory trimming).
            let (new_records, seq_end) = audit.records_after_seq(last_seq);
            let at = chrono::Utc::now().timestamp_millis() as u64;
            let rows: Vec<BlobRow> = new_records.iter().filter_map(|r| blob(r.id.to_string(), r, at)).collect();
            if write_rows(&state, "redswarm_executions", &rows).await {
                last_seq = seq_end;
            }

            // Newly-created drafts (status changes are written through by the handlers).
            // Use created_at so this initial write never outranks a later status change.
            let drafts = audit.all_drafts();
            let new_drafts: Vec<BlobRow> = drafts
                .iter()
                .filter(|d| !persisted_drafts.contains(&d.id.to_string()))
                .filter_map(|d| blob(d.id.to_string(), d, d.created_at.timestamp_millis() as u64))
                .collect();
            if write_rows(&state, "redswarm_drafts", &new_drafts).await {
                persisted_drafts.extend(new_drafts.iter().map(|r| r.id.clone()));
            }

            // Re-read drafts: picks up status changes from this and any other instance.
            // Skipped when the read fails, so a ClickHouse hiccup never empties the drafts.
            if let Some(fresh) = fetch::<SynthesizedRuleDraft>(&state, "redswarm_drafts").await {
                persisted_drafts.extend(fresh.iter().map(|d| d.id.to_string()));
                audit.merge_drafts(fresh);
            }
        }
    });
}
