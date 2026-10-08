use siem_core::RawEvent;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Resilient Client Buffer matching Wazuh's client_buffer specifications
/// Queue capacity: 5,000 events
/// Events per second limit: 500 EPS
pub struct AgentBuffer {
    tx: mpsc::Sender<RawEvent>,
}

impl AgentBuffer {
    pub fn new(manager_url: String, queue_size: usize, eps_limit: u32) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<RawEvent>(queue_size);
        let client = Arc::new(reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default());

        let ingest_url = format!("{}/api/v1/ingest", manager_url);
        let interval_micros = if eps_limit > 0 { 1_000_000 / eps_limit as u64 } else { 2000 };

        let handle = tokio::spawn(async move {
            info!("Agent buffer worker started (capacity: {}, max EPS: {})", queue_size, eps_limit);
            let mut ticker = tokio::time::interval(Duration::from_micros(interval_micros));

            while let Some(event) = rx.recv().await {
                ticker.tick().await;

                // Send with retry
                let mut attempts = 0;
                let max_attempts = 3;
                let mut sent = false;

                while attempts < max_attempts && !sent {
                    attempts += 1;
                    match client.post(&ingest_url).json(&event).send().await {
                        Ok(resp) => {
                            if resp.status().is_success() {
                                sent = true;
                            } else {
                                warn!("Manager returned non-success code {} for event {}", resp.status(), event.id);
                                tokio::time::sleep(Duration::from_millis(500)).await;
                            }
                        }
                        Err(err) => {
                            warn!("Failed to dispatch event to manager (attempt {}/{}): {}", attempts, max_attempts, err);
                            tokio::time::sleep(Duration::from_millis(1000)).await;
                        }
                    }
                }

                if !sent {
                    error!("Dropped event {} after {} failed attempts", event.id, max_attempts);
                }
            }
        });

        (Self { tx }, handle)
    }

    pub async fn push(&self, event: RawEvent) {
        if let Err(e) = self.tx.send(event).await {
            warn!("Buffer overflow or channel closed: {}", e);
        }
    }
}
