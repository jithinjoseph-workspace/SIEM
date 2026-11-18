use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use siem_core::RawEvent;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Thread-safe client buffer with flow control, disk-persisted spooling, and manager dispatch
pub struct AgentBuffer {
    tx: mpsc::Sender<RawEvent>,
    dropped_count: Arc<AtomicUsize>,
    capacity: usize,
    spool_dir: PathBuf,
}

impl AgentBuffer {
    /// Initialize standard agent buffer with default spool directory
    pub fn new(
        manager_url: String,
        capacity: usize,
        events_per_second: usize,
        lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let failover = Arc::new(crate::failover::Failover::new(vec![manager_url], 3, Duration::from_secs(2)));
        Self::new_with_failover(
            failover,
            capacity,
            events_per_second,
            lifecycle,
            default_spool_dir(),
            None,
        )
    }

    /// Initialize agent buffer with an explicit spool directory (used in production or unit tests)
    #[allow(dead_code)]
    pub fn new_with_spool(
        manager_url: String,
        capacity: usize,
        events_per_second: usize,
        lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
        spool_dir: PathBuf,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let failover = Arc::new(crate::failover::Failover::new(vec![manager_url], 3, Duration::from_secs(2)));
        Self::new_with_failover(
            failover,
            capacity,
            events_per_second,
            lifecycle,
            spool_dir,
            None,
        )
    }

    /// Initialize agent buffer with multi-manager failover and central group config hot-reload
    pub fn new_with_failover(
        failover: Arc<crate::failover::Failover>,
        capacity: usize,
        events_per_second: usize,
        lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
        spool_dir: PathBuf,
        mut group_rx: Option<tokio::sync::watch::Receiver<crate::group_config::DynamicGroupConfig>>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<RawEvent>(capacity);
        let dropped_count = Arc::new(AtomicUsize::new(0));

        let spool_worker_dir = spool_dir.clone();
        let _dropped_worker = Arc::clone(&dropped_count);

        let worker = tokio::spawn(async move {
            let client = crate::enroll::http_builder()
                .timeout(Duration::from_secs(5))
                .default_headers(tenant_headers())
                .build()
                .unwrap_or_default();

            let grpc = crate::grpc_transport::GrpcTransport::new(&failover.current_url()).ok();

            info!(
                "AgentBuffer: Initialized with capacity {}, spool directory '{}', active manager '{}'",
                capacity,
                spool_worker_dir.display(),
                failover.current_url()
            );

            let mut delay_between_flushes = Duration::from_millis(
                if events_per_second > 0 {
                    (1000 / events_per_second).max(5) as u64
                } else {
                    10
                },
            );

            let mut batch: Vec<RawEvent> = Vec::with_capacity(50);

            loop {
                // Dynamic hot-reload: adapt EPS limit when central group configuration changes
                if let Some(ref mut rx) = group_rx {
                    if rx.has_changed().unwrap_or(false) {
                        let new_eps = rx.borrow_and_update().events_per_second;
                        if new_eps > 0 {
                            delay_between_flushes = Duration::from_millis((1000 / new_eps).max(5) as u64);
                            info!("AgentBuffer: Hot-reloaded events_per_second to {}", new_eps);
                        }
                    }
                }

                if lifecycle.is_terminated() {
                    // Flush any remaining in-memory events to disk spool before terminating
                    let mut remaining = Vec::new();
                    while let Ok(ev) = rx.try_recv() {
                        remaining.push(ev);
                    }
                    if !remaining.is_empty() {
                        spool_write(&spool_worker_dir, &remaining);
                        info!("AgentBuffer: Spooled {} pending events to disk on shutdown.", remaining.len());
                    }
                    break;
                }

                // If agent is deactivated/dormant, pause sending
                if !lifecycle.is_active() {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }

                let current_url = failover.current_url();
                let endpoint = format!("{}/api/v1/events/ingest", current_url.trim_end_matches('/'));

                // 1. Prioritize draining disk-persisted spool if manager is reachable
                if let Some((spool_path, spooled_events)) = spool_drain_oldest(&spool_worker_dir) {
                    if !spooled_events.is_empty() {
                        match dispatch_batch(&client, &endpoint, &spooled_events, grpc.as_ref()).await {
                            Ok(()) => {
                                failover.report_success();
                                debug!("AgentBuffer: Transmitted {} spooled events from '{}'", spooled_events.len(), spool_path.display());
                                let _ = std::fs::remove_file(&spool_path);
                                tokio::time::sleep(delay_between_flushes).await;
                                continue;
                            }
                            Err(e) => {
                                failover.report_failure().await;
                                debug!("AgentBuffer: Spool delivery paused (manager unreachable: {}).", e);
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                continue;
                            }
                        }
                    } else {
                        let _ = std::fs::remove_file(&spool_path);
                    }
                }

                // 2. Collect batch of real-time events from in-memory channel
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

                    let key = std::env::var("SIEM_AGENT_KEY").unwrap_or_default();
                    let key_trim = key.trim();
                    let agent_id = std::env::var("SIEM_AGENT_ID").unwrap_or_default();

                    // Prioritize high-performance gRPC streaming when available
                    if let Some(ref g) = grpc {
                        if g.is_available().await {
                            let json_events: Vec<String> = to_send.iter().filter_map(|e| serde_json::to_string(e).ok()).collect();
                            if let Ok(accepted) = g.send_events(&agent_id, key_trim, json_events).await {
                                failover.report_success();
                                debug!("AgentBuffer: Streamed {} events via gRPC (accepted: {})", count, accepted);
                                tokio::time::sleep(delay_between_flushes).await;
                                continue;
                            }
                        }
                    }

                    let mut req = client.post(&endpoint).json(&to_send);
                    if !key_trim.is_empty() {
                        req = req
                            .header("x-agent-key", key_trim)
                            .header("authorization", format!("Bearer {}", key_trim));
                    }
                    if !agent_id.trim().is_empty() {
                        req = req.header("x-agent-id", agent_id.trim());
                    }

                    match req.send().await {
                        Ok(res) if res.status().is_success() => {
                            failover.report_success();
                            debug!("AgentBuffer: Dispatched {} events to Manager", count);
                        }
                        Ok(res) if res.status() == reqwest::StatusCode::GONE => {
                            failover.report_success();
                            warn!("AgentBuffer: Manager returned 410 GONE (agent deactivated or dormant). Updating state...");
                            if let Some(state) = lifecycle.fetch_state().await {
                                lifecycle.set_state(state);
                            } else {
                                lifecycle.set_state(crate::lifecycle::AgentLifecycleState::Dormant);
                            }
                            // Save events to spool so they are not lost if reactivated
                            spool_write(&spool_worker_dir, &to_send);
                        }
                        Ok(res) if res.status() == reqwest::StatusCode::NOT_FOUND => {
                            failover.report_success();
                            warn!("AgentBuffer: Manager returned 404 NOT FOUND. Checking agent lifecycle state...");
                            if let Some(state) = lifecycle.fetch_state().await {
                                if state == crate::lifecycle::AgentLifecycleState::Decommissioned {
                                    warn!("AgentBuffer: Agent is confirmed deleted in registry. Executing decommission...");
                                    lifecycle.set_state(crate::lifecycle::AgentLifecycleState::Decommissioned);
                                }
                            }
                            spool_write(&spool_worker_dir, &to_send);
                        }
                        Ok(res) => {
                            if res.status().is_server_error() {
                                failover.report_failure().await;
                            }
                            warn!("AgentBuffer: Manager rejected ingest batch with HTTP {}. Persisting to disk spool.", res.status());
                            spool_write(&spool_worker_dir, &to_send);
                        }
                        Err(err) => {
                            failover.report_failure().await;
                            debug!("AgentBuffer: Manager connection unreachable ({}). Persisting batch to disk spool.", err);
                            spool_write(&spool_worker_dir, &to_send);
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
                spool_dir,
            },
            worker,
        )
    }

    /// Push an event into the local buffer. If memory queue is full, spools to disk instead of dropping.
    pub async fn push(&self, event: RawEvent) -> bool {
        match self.tx.try_send(event) {
            Ok(_) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(ev)) => {
                // In-memory channel full: Spool directly to disk to prevent data loss
                if spool_write(&self.spool_dir, &[ev]) {
                    true
                } else {
                    let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    if dropped % 100 == 0 {
                        warn!("AgentBuffer: Spool full/failed! Dropped {} events.", dropped + 1);
                    }
                    false
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    #[allow(dead_code)]
    pub fn capacity(&self) -> usize {
        self.capacity
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
                spool_dir: std::env::temp_dir().join(format!("test_spool_{}", uuid::Uuid::new_v4())),
            },
            rx,
        )
    }
}

/// Transmit a batch of events directly to the ingest endpoint, attempting gRPC first
async fn dispatch_batch(
    client: &reqwest::Client,
    endpoint: &str,
    events: &[RawEvent],
    grpc: Option<&crate::grpc_transport::GrpcTransport>,
) -> Result<(), String> {
    let key = std::env::var("SIEM_AGENT_KEY").unwrap_or_default();
    let key_trim = key.trim();
    let agent_id = std::env::var("SIEM_AGENT_ID").unwrap_or_default();

    if let Some(g) = grpc {
        if g.is_available().await {
            let json_events: Vec<String> = events.iter().filter_map(|e| serde_json::to_string(e).ok()).collect();
            if g.send_events(&agent_id, key_trim, json_events).await.is_ok() {
                return Ok(());
            }
        }
    }

    let mut req = client.post(endpoint).json(events);
    if !key_trim.is_empty() {
        req = req
            .header("x-agent-key", key_trim)
            .header("authorization", format!("Bearer {}", key_trim));
    }
    if !agent_id.trim().is_empty() {
        req = req.header("x-agent-id", agent_id.trim());
    }

    let res = req.send().await.map_err(|e| e.to_string())?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", res.status()))
    }
}

/// Compress and write events to a new chunk file in the spool directory
pub fn spool_write(dir: &Path, events: &[RawEvent]) -> bool {
    if events.is_empty() {
        return true;
    }
    if let Err(_) = std::fs::create_dir_all(dir) {
        return false;
    }
    let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let path = dir.join(format!("spool_{}.gz", now));

    let Ok(bytes) = serde_json::to_vec(events) else {
        return false;
    };
    let Ok(file) = std::fs::File::create(&path) else {
        return false;
    };

    let mut encoder = GzEncoder::new(file, Compression::default());
    if encoder.write_all(&bytes).is_err() {
        return false;
    }
    encoder.finish().is_ok()
}

/// Read and decompress the oldest chunk file from the spool directory
pub fn spool_drain_oldest(dir: &Path) -> Option<(PathBuf, Vec<RawEvent>)> {
    if !dir.is_dir() {
        return None;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return None;
    };
    let mut gz_files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "gz"))
        .collect();

    if gz_files.is_empty() {
        return None;
    }
    gz_files.sort();

    let oldest = gz_files.into_iter().next()?;
    let file = std::fs::File::open(&oldest).ok()?;
    let decoder = GzDecoder::new(file);
    let events: Vec<RawEvent> = serde_json::from_reader(decoder).ok()?;
    Some((oldest, events))
}

/// Default spool directory path for Linux
pub fn default_spool_dir() -> PathBuf {
    let opt_dir = Path::new("/opt/provigil-agent/queue");
    if opt_dir.is_dir() || Path::new("/opt/provigil-agent").is_dir() {
        opt_dir.to_path_buf()
    } else {
        PathBuf::from("data/queue")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_spool_write_and_drain() {
        let temp_dir = std::env::temp_dir().join(format!("test_spool_unit_{}", uuid::Uuid::new_v4()));
        let mut ev1 = RawEvent::new("agent-1", siem_core::EventSource::Fim, "test/fim", "file changed");
        ev1.metadata.insert("key1".into(), "val1".into());

        let mut ev2 = RawEvent::new("agent-1", siem_core::EventSource::Syslog, "test/syslog", "login ok");
        ev2.metadata.insert("user".into(), "root".into());

        let events = vec![ev1.clone(), ev2.clone()];

        // 1. Write to compressed disk spool
        assert!(spool_write(&temp_dir, &events));

        // 2. Drain oldest from disk spool
        let (file_path, drained) = spool_drain_oldest(&temp_dir).expect("Should find spooled file");
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].message, "file changed");
        assert_eq!(drained[1].message, "login ok");

        // 3. Remove file and verify queue is empty
        let _ = std::fs::remove_file(&file_path);
        assert!(spool_drain_oldest(&temp_dir).is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
