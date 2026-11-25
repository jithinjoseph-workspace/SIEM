//! Registry rows of new agents written in batches, each enrollment told when its row is stored
//! (a PC gets its identity only after that). One ClickHouse insert per batch (what arrived within
//! [`GATHER`], at most [`BATCH`]) instead of one per agent: ClickHouse takes few large inserts
//! well and many single-row ones badly, which held mass enrollment to about 20 agents a second.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::db::{AgentRegistryRow, ClickHouseDb};

const BATCH: usize = 500;
const GATHER: Duration = Duration::from_millis(50);

type Job = (AgentRegistryRow, oneshot::Sender<bool>);

static QUEUE: OnceLock<mpsc::UnboundedSender<Job>> = OnceLock::new();

/// Starts the writer.
pub fn spawn(db: ClickHouseDb) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
    if QUEUE.set(tx).is_err() {
        return;
    }
    tokio::spawn(async move {
        while let Some(first) = rx.recv().await {
            let mut batch = vec![first];
            let until = tokio::time::Instant::now() + GATHER;
            while batch.len() < BATCH {
                match tokio::time::timeout_at(until, rx.recv()).await {
                    Ok(Some(j)) => batch.push(j),
                    _ => break,
                }
            }
            let rows: Vec<AgentRegistryRow> = batch.iter().map(|(r, _)| r.clone()).collect();
            let ok = match db.upsert_agent_registry_rows(&rows).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!("agent_registry: {} new agent row(s) not stored: {e}", rows.len());
                    false
                }
            };
            for (_, done) in batch {
                let _ = done.send(ok);
            }
        }
    });
}

/// Stores a new agent's registry row (with the others arriving now); false when ClickHouse did
/// not take it. Without the writer (tests), written alone.
pub async fn store(db: &ClickHouseDb, row: AgentRegistryRow) -> bool {
    let Some(q) = QUEUE.get() else {
        return db.upsert_agent_registry_rows(std::slice::from_ref(&row)).await.is_ok();
    };
    let (tx, rx) = oneshot::channel();
    if q.send((row, tx)).is_err() {
        return false;
    }
    rx.await.unwrap_or(false)
}
