//! OpenSearch / Elasticsearch Indexer Connector
//!
//! Provides high-throughput NDJSON bulk ingestion, multi-node failover,
//! buffer queueing with backpressure, and automatic retries for Wazuh events.

use crate::common::{ReturnType, Result, SharedModuleError};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerConfig {
    pub hosts: Vec<String>,
    pub default_index: String,
    pub max_batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_retries: u32,
    pub queue_capacity: usize,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            hosts: vec!["https://127.0.0.1:9200".to_string()],
            default_index: "wazuh-alerts-4.x".to_string(),
            max_batch_size: 500,
            flush_interval_ms: 1000,
            max_retries: 3,
            queue_capacity: 10000,
        }
    }
}

/// A document to be indexed in OpenSearch/Elasticsearch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDocument {
    pub index: Option<String>,
    pub doc_id: Option<String>,
    pub document: serde_json::Value,
}

/// The Indexer Connector managing connections, queueing, and bulk flushes.
pub struct IndexerConnector {
    config: IndexerConfig,
    queue_tx: mpsc::Sender<IndexDocument>,
    current_host_idx: AtomicUsize,
    client: reqwest::Client,
}

impl IndexerConnector {
    pub fn new(config: IndexerConfig) -> (Arc<Self>, mpsc::Receiver<IndexDocument>) {
        let (tx, rx) = mpsc::channel(config.queue_capacity);
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let connector = Arc::new(Self {
            config,
            queue_tx: tx,
            current_host_idx: AtomicUsize::new(0),
            client,
        });

        (connector, rx)
    }

    /// Select current active host in a round-robin / failover manner.
    pub fn get_active_host(&self) -> String {
        if self.config.hosts.is_empty() {
            return "https://127.0.0.1:9200".to_string();
        }
        let idx = self.current_host_idx.load(Ordering::Relaxed) % self.config.hosts.len();
        self.config.hosts[idx].clone()
    }

    /// Rotate to next host on connection failure.
    pub fn rotate_host(&self) {
        self.current_host_idx.fetch_add(1, Ordering::Relaxed);
    }

    /// Enqueue a document for indexing with backpressure.
    pub async fn push_document(&self, doc: IndexDocument) -> Result<()> {
        self.queue_tx.send(doc).await.map_err(|_| {
            SharedModuleError::Failure(ReturnType::BufferFull, "Indexer queue is closed".into())
        })
    }

    /// Try enqueueing a document synchronously without blocking.
    pub fn try_push_document(&self, doc: IndexDocument) -> Result<()> {
        self.queue_tx.try_send(doc).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                SharedModuleError::Failure(ReturnType::BufferFull, "Indexer queue is full".into())
            }
            mpsc::error::TrySendError::Closed(_) => {
                SharedModuleError::Failure(ReturnType::NetworkError, "Indexer queue closed".into())
            }
        })
    }

    /// Generate OpenSearch/Elasticsearch bulk NDJSON formatted payload.
    pub fn serialize_bulk_ndjson(&self, docs: &[IndexDocument]) -> Result<String> {
        let mut bulk_body = String::new();
        for doc in docs {
            let index_name = doc.index.as_deref().unwrap_or(&self.config.default_index);
            let action_header = if let Some(id) = &doc.doc_id {
                serde_json::json!({ "index": { "_index": index_name, "_id": id } })
            } else {
                serde_json::json!({ "index": { "_index": index_name } })
            };

            bulk_body.push_str(&serde_json::to_string(&action_header)?);
            bulk_body.push('\n');
            bulk_body.push_str(&serde_json::to_string(&doc.document)?);
            bulk_body.push('\n');
        }
        Ok(bulk_body)
    }

    /// Spawns a background flusher task that drains the receiver and executes bulk indexing.
    pub fn spawn_flusher(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<IndexDocument>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut batch = Vec::new();
            let mut interval = tokio::time::interval(Duration::from_millis(self.config.flush_interval_ms));

            loop {
                tokio::select! {
                    Some(doc) = rx.recv() => {
                        batch.push(doc);
                        if batch.len() >= self.config.max_batch_size {
                            let docs_to_flush = std::mem::take(&mut batch);
                            let _ = self.flush_batch(&docs_to_flush).await;
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            let docs_to_flush = std::mem::take(&mut batch);
                            let _ = self.flush_batch(&docs_to_flush).await;
                        }
                    }
                    else => break,
                }
            }
        })
    }

    /// Sends a batch via HTTP bulk API.
    async fn flush_batch(&self, docs: &[IndexDocument]) -> Result<()> {
        if docs.is_empty() {
            return Ok(());
        }

        let ndjson = self.serialize_bulk_ndjson(docs)?;
        let host = self.get_active_host();
        let bulk_url = format!("{}/_bulk", host.trim_end_matches('/'));

        let mut attempts = 0;
        while attempts < self.config.max_retries {
            attempts += 1;
            match self
                .client
                .post(&bulk_url)
                .header("Content-Type", "application/x-ndjson")
                .body(ndjson.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    return Ok(());
                }
                Ok(resp) => {
                    tracing::warn!(
                        "Bulk flush to {} returned status {}, retrying ({}/{})",
                        bulk_url,
                        resp.status(),
                        attempts,
                        self.config.max_retries
                    );
                    self.rotate_host();
                }
                Err(err) => {
                    tracing::warn!(
                        "Bulk flush error to {}: {}, retrying ({}/{})",
                        bulk_url,
                        err,
                        attempts,
                        self.config.max_retries
                    );
                    self.rotate_host();
                }
            }
            sleep(Duration::from_millis(200 * (1 << attempts))).await;
        }

        Err(SharedModuleError::Failure(
            ReturnType::NetworkError,
            format!("Failed to flush bulk payload of {} docs after {} retries", docs.len(), attempts),
        ))
    }
}
