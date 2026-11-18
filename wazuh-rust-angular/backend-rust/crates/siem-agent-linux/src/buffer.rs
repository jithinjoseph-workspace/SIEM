use siem_core::RawEvent;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Thread-safe client buffer with flow control and manager dispatch
pub struct AgentBuffer {
    tx: mpsc::Sender<RawEvent>,
    dropped_count: Arc<AtomicUsize>,
    capacity: usize,
}

impl AgentBuffer {
    pub fn new(
        manager_url: String,
        capacity: usize,
        events_per_second: usize,
        lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<RawEvent>(capacity);
        let dropped_count = Arc::new(AtomicUsize::new(0));

        let worker = tokio::spawn(async move {
            let client = crate::enroll::http_builder()
                .timeout(Duration::from_secs(5))
                .default_headers(tenant_headers())
                .build()
                .unwrap_or_default();
            info!("AgentBuffer: Initialized with capacity {} and manager '{}'", capacity, crate::managers::url(&manager_url));

            let delay_between_flushes = Duration::from_millis(
                if events_per_second > 0 { (1000 / events_per_second).max(5) as u64 } else { 10 }
            );

            // what the manager did not take waits on disk, and is sent first (oldest first)
            let mut spool = crate::spool::Spool::from_env();
            let mut draining: Option<(std::path::PathBuf, std::collections::VecDeque<RawEvent>)> = None;
            let mut offline_until: Option<tokio::time::Instant> = None;
            let mut backoff = Duration::from_secs(1);
            let mut batch: Vec<RawEvent> = Vec::with_capacity(50);

            loop {
                if lifecycle.is_terminated() {
                    // the events still queued are kept for the next start
                    while let Ok(event) = rx.try_recv() {
                        batch.push(event);
                    }
                    if !batch.is_empty() {
                        spool.put(&batch);
                    }
                    break;
                }

                // If agent is deactivated/dormant, pause sending
                if !lifecycle.is_active() {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }

                // Collect batch of events
                while let Ok(event) = rx.try_recv() {
                    batch.push(event);
                    if batch.len() >= 50 {
                        break;
                    }
                }

                if batch.is_empty() {
                    match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                        Ok(Some(event)) => batch.push(event),
                        _ => {}
                    }
                }

                let online = offline_until.map_or(true, |t| tokio::time::Instant::now() >= t);
                let mut failed = false;

                // the kept events go before new ones, so the manager gets them in order
                if online {
                    if draining.is_none() {
                        draining = spool.take_oldest().map(|(p, e)| (p, e.into()));
                    }
                    let mut sent = 0;
                    while let Some((path, queue)) = draining.as_mut() {
                        if queue.is_empty() {
                            spool.done(path);
                            draining = spool.take_oldest().map(|(p, e)| (p, e.into()));
                            continue;
                        }
                        let n = queue.len().min(50);
                        let chunk: Vec<RawEvent> = queue.iter().take(n).cloned().collect();
                        if send(&client, &manager_url, &chunk, &lifecycle).await == Sent::Failed {
                            failed = true;
                            break;
                        }
                        queue.drain(..n);
                        sent += n;
                        // new events are not held up for long: the rest on the next rounds
                        if sent >= 1000 {
                            break;
                        }
                    }
                }

                if !batch.is_empty() {
                    let to_send = std::mem::take(&mut batch);
                    if !online || failed || draining.is_some() || !spool.is_empty() {
                        spool.put(&to_send);
                    } else if send(&client, &manager_url, &to_send, &lifecycle).await == Sent::Failed {
                        spool.put(&to_send);
                        failed = true;
                    }
                }

                if failed {
                    if offline_until.is_none() {
                        warn!("AgentBuffer: Manager not reachable; events are kept on disk until it answers");
                    }
                    offline_until = Some(tokio::time::Instant::now() + backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                } else if online && offline_until.is_some() {
                    info!("AgentBuffer: Manager reachable again; sending the kept events");
                    offline_until = None;
                    backoff = Duration::from_secs(1);
                }

                tokio::time::sleep(delay_between_flushes).await;
            }
        });

        (
            Self {
                tx,
                dropped_count,
                capacity,
            },
            worker,
        )
    }

    /// Push an event into the local buffer
    pub async fn push(&self, event: RawEvent) -> bool {
        match self.tx.try_send(event) {
            Ok(_) => true,
            Err(_) => {
                let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed);
                if dropped % 100 == 0 {
                    warn!("AgentBuffer: Queue full ({}/{})! Dropped {} events.", self.capacity, self.capacity, dropped + 1);
                }
                false
            }
        }
    }

    #[allow(dead_code)]
    pub fn dropped_events(&self) -> usize {
        self.dropped_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn mock(capacity: usize) -> (Self, tokio::sync::mpsc::Receiver<siem_core::RawEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel::<siem_core::RawEvent>(capacity);
        (
            Self {
                tx,
                dropped_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                capacity,
            },
            rx,
        )
    }
}

#[derive(Debug, PartialEq)]
enum Sent {
    /// taken, or refused for good (dropped as before)
    Done,
    /// not reached, or a server error: kept and sent again
    Failed,
}

/// One batch to the manager in use (the next one after repeated failures).
async fn send(client: &reqwest::Client, manager_url: &str, events: &[RawEvent], lifecycle: &crate::lifecycle::LifecycleCoordinator) -> Sent {
    let endpoint = format!("{}/api/v1/events/ingest", crate::managers::url(manager_url));
    let key = std::env::var("SIEM_AGENT_KEY").unwrap_or_default();
    let key_trim = key.trim();
    let agent_id = std::env::var("SIEM_AGENT_ID").unwrap_or_default();
    let mut req = client.post(&endpoint).json(events);
    if !key_trim.is_empty() {
        req = req.header("x-agent-key", key_trim).header("authorization", format!("Bearer {}", key_trim));
    }
    if !agent_id.trim().is_empty() {
        req = req.header("x-agent-id", agent_id.trim());
    }
    let r = req.send().await;
    crate::managers::report(crate::managers::reached(&r));
    match r {
        Ok(res) if res.status().is_success() => {
            debug!("AgentBuffer: Dispatched {} events to Manager", events.len());
            Sent::Done
        }
        Ok(res) if res.status() == reqwest::StatusCode::GONE => {
            warn!("AgentBuffer: Manager returned 410 GONE (agent deactivated or dormant). Updating state...");
            if let Some(state) = lifecycle.fetch_state().await {
                lifecycle.set_state(state);
            } else {
                lifecycle.set_state(crate::lifecycle::AgentLifecycleState::Dormant);
            }
            Sent::Done
        }
        Ok(res) if res.status() == reqwest::StatusCode::NOT_FOUND => {
            warn!("AgentBuffer: Manager returned 404 NOT FOUND. Checking agent lifecycle state...");
            if let Some(state) = lifecycle.fetch_state().await {
                if state == crate::lifecycle::AgentLifecycleState::Decommissioned {
                    warn!("AgentBuffer: Agent is confirmed deleted in registry. Executing decommission...");
                    lifecycle.set_state(crate::lifecycle::AgentLifecycleState::Decommissioned);
                }
            }
            Sent::Done
        }
        // busy or failing: the events wait
        Ok(res) if res.status().is_server_error() || res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
            warn!("AgentBuffer: Manager answered HTTP {}; events kept", res.status());
            Sent::Failed
        }
        Ok(res) => {
            warn!("AgentBuffer: Manager rejected ingest batch with HTTP {}", res.status());
            Sent::Done
        }
        Err(err) => {
            debug!("AgentBuffer: Manager connection unreachable ({}).", err);
            Sent::Failed
        }
    }
}

/// Default headers for manager requests: the tenant agent key from
/// `SIEM_TENANT_KEY` (sent as `X-Tenant-Key`) puts this agent in that tenant.
fn tenant_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Ok(k) = std::env::var("SIEM_TENANT_KEY") {
        let cleaned = k.trim().trim_matches(|c| c == '\'' || c == '"').trim();
        if !cleaned.is_empty() {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(cleaned) {
                h.insert("x-tenant-key", v);
            }
        }
    }
    h
}
