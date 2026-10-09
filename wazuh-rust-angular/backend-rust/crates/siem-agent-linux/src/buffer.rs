use reqwest::Client;
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
    pub fn new(manager_url: String, capacity: usize, events_per_second: usize) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<RawEvent>(capacity);
        let dropped_count = Arc::new(AtomicUsize::new(0));

        let worker = tokio::spawn(async move {
            let client = Client::builder()
                .timeout(Duration::from_secs(5))
                .default_headers(tenant_headers())
                .build()
                .unwrap_or_default();

            let endpoint = format!("{}/api/events/ingest", manager_url.trim_end_matches('/'));
            info!("AgentBuffer: Initialized with capacity {} and target endpoint '{}'", capacity, endpoint);

            let delay_between_flushes = Duration::from_millis(
                if events_per_second > 0 { (1000 / events_per_second).max(5) as u64 } else { 10 }
            );

            let mut batch: Vec<RawEvent> = Vec::with_capacity(50);

            loop {
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

                if !batch.is_empty() {
                    let to_send = std::mem::take(&mut batch);
                    let count = to_send.len();

                    match client.post(&endpoint).json(&to_send).send().await {
                        Ok(res) if res.status().is_success() => {
                            debug!("AgentBuffer: Dispatched {} events to Manager", count);
                        }
                        Ok(res) if res.status() == reqwest::StatusCode::GONE => {
                            let id = to_send.first().map(|e| e.agent_id.clone()).unwrap_or_default();
                            crate::enroll::stop_deactivated(&id);
                        }
                        Ok(res) => {
                            warn!("AgentBuffer: Manager rejected ingest batch with HTTP {}", res.status());
                        }
                        Err(err) => {
                            debug!("AgentBuffer: Manager connection unreachable ({}). Buffered events queued.", err);
                        }
                    }
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
}

/// Default headers for manager requests: the tenant agent key from
/// `SIEM_TENANT_KEY` (sent as `X-Tenant-Key`) puts this agent in that tenant.
fn tenant_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Ok(k) = std::env::var("SIEM_TENANT_KEY") {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(k.trim()) {
            if !k.trim().is_empty() {
                h.insert("x-tenant-key", v);
            }
        }
    }
    h
}
