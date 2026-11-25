//! Agent removals written to ClickHouse in batches. Removing agents (the console's bulk removal,
//! one agent, or the stale-agent cleanup) updates memory at once; what is stored goes through one
//! writer: per batch (half a second, at most [`BATCH`] agents) one registry insert, one delete per
//! table and tenant, the key store saved once, and retries while ClickHouse is busy. Before, every
//! agent made five queries at once: removing 12,000 load-test agents met ClickHouse's limit of
//! 1,000 simultaneous queries, nothing was retried, and most stayed in the registry.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::db::AgentRegistryRow;
use crate::AppState;

/// Agents per batch.
const BATCH: usize = 1000;
/// How long a batch gathers removals.
const GATHER: Duration = Duration::from_millis(500);
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);
/// Attempts per statement before it is given up (logged).
const ATTEMPTS: u32 = 20;

static QUEUE: OnceLock<mpsc::UnboundedSender<AgentRegistryRow>> = OnceLock::new();

/// Queues a removed agent's registry row (marked deleted) and its stored state for removal; false
/// when the writer is not running (tests): the caller writes it itself.
pub fn queue(row: AgentRegistryRow) -> bool {
    QUEUE.get().is_some_and(|q| q.send(row).is_ok())
}

/// Starts the writer.
pub fn spawn(state: AppState) {
    let (tx, mut rx) = mpsc::unbounded_channel::<AgentRegistryRow>();
    if QUEUE.set(tx).is_err() {
        return;
    }
    tokio::spawn(async move {
        while let Some(first) = rx.recv().await {
            let mut batch = vec![first];
            let until = tokio::time::Instant::now() + GATHER;
            while batch.len() < BATCH {
                match tokio::time::timeout_at(until, rx.recv()).await {
                    Ok(Some(r)) => batch.push(r),
                    _ => break,
                }
            }
            write(&state, batch).await;
        }
    });
}

/// The agents of one batch, by tenant (the per-tenant deletes).
pub fn by_tenant(rows: &[AgentRegistryRow]) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in rows {
        m.entry(r.tenant_id.clone()).or_default().push(r.agent_id.clone());
    }
    m
}

async fn write(state: &AppState, rows: Vec<AgentRegistryRow>) {
    let n = rows.len();
    // the registry first: the ids are never issued again and the agents stay gone after a restart
    retry("agent registry", || state.db.upsert_agent_registry_rows(&rows)).await;
    for (tenant, ids) in by_tenant(&rows) {
        for (what, sql, keys) in [
            ("fleet rows", "ALTER TABLE siem_agents DELETE WHERE has(?, id)", ids.clone()),
            ("vulnerability state", "DELETE FROM siem_vulnerability_state WHERE has(?, agent_id)", ids.clone()),
            ("tamper state", "DELETE FROM siem_tamper WHERE has(?, id)", ids.iter().map(|i| format!("agent:{i}")).collect()),
            ("configuration check rows", "DELETE FROM siem_sca_checks WHERE has(?, agent_id)", ids.clone()),
        ] {
            retry(what, || state.db.execute_with_list(&tenant, sql, &keys)).await;
        }
        crate::posture_store::forget_cached(&ids);
    }
    let ids: Vec<String> = rows.iter().map(|r| r.agent_id.clone()).collect();
    tokio::spawn(crate::provigil_manager::purge_removed(ids));
    crate::provigil_manager::save_keys(state);
    info!("{n} removed agent(s) stored");
}

async fn retry<F, Fut>(what: &str, f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    retry_from(what, RETRY_MIN, f).await
}

async fn retry_from<F, Fut>(what: &str, first_wait: Duration, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut wait = first_wait;
    for attempt in 1..=ATTEMPTS {
        match f().await {
            Ok(()) => return,
            Err(e) if attempt == ATTEMPTS => return warn!("removed agents: {what} not stored after {ATTEMPTS} attempts: {e}"),
            Err(e) => {
                if attempt == 1 {
                    warn!("removed agents: {what} not stored yet ({e}): trying again");
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(RETRY_MAX);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, tenant: &str) -> AgentRegistryRow {
        AgentRegistryRow { agent_id: id.into(), name: format!("pc-{id}"), tenant_id: tenant.into(), groups: String::new(), os_type: String::new(), deleted: 1, enrolled_at: 0, updated_at: 0, disabled: 1 }
    }

    #[test]
    fn a_batch_is_one_delete_per_tenant() {
        let g = by_tenant(&[row("1", "acme"), row("2", "default"), row("3", "acme")]);
        assert_eq!(g.len(), 2);
        assert_eq!(g["acme"], ["1", "3"]);
        assert_eq!(g["default"], ["2"]);
    }

    #[tokio::test]
    async fn busy_clickhouse_is_retried_until_it_takes_the_batch() {
        let tries = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let t = tries.clone();
        retry_from("test", Duration::from_millis(1), move || {
            let t = t.clone();
            async move {
                if t.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 3 {
                    Err("Too many simultaneous queries".to_string())
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(tries.load(std::sync::atomic::Ordering::SeqCst), 4, "three refusals, then stored");
    }
}
