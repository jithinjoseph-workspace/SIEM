//! High-Performance gRPC Streaming Transport (provigil.agent.v1.AgentService)
//!
//! Provides bidirectional HTTP/2 event streaming on port 8089 with automatic
//! fallback to HTTPS REST (port 8443) on network failure or corporate proxy blockage.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use provigil_proto::{
    AgentServiceClient, ConfigRequest, EventsRequest, KeepaliveRequest, YaraRequest,
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, info, warn};

pub const DEFAULT_GRPC_PORT: u16 = 8089;
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MB
pub const GRPC_MAX_CONSECUTIVE_FAILS: u32 = 3;
pub const HTTPS_FALLBACK_DURATION: Duration = Duration::from_secs(600); // 10 minutes

/// Converts an HTTP/HTTPS manager URL to a gRPC endpoint URL.
/// E.g. "https://192.168.1.100:8443" -> "http://192.168.1.100:8089"
/// E.g. "grpc://192.168.1.100:8089"  -> "http://192.168.1.100:8089"
pub fn manager_url_to_grpc_endpoint(manager_url: &str) -> Result<String, String> {
    let trimmed = manager_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("manager URL is empty".to_string());
    }

    if let Some(rest) = trimmed.strip_prefix("grpc://") {
        return Ok(format!("http://{rest}"));
    }
    if let Some(rest) = trimmed.strip_prefix("grpcs://") {
        return Ok(format!("https://{rest}"));
    }

    // Parse host from http:// or https://
    let host_part = if let Some(rest) = trimmed.strip_prefix("https://") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        rest
    } else {
        trimmed
    };

    // Strip existing port or path
    let host = match host_part.split_once(':') {
        Some((h, _)) => h,
        None => match host_part.split_once('/') {
            Some((h, _)) => h,
            None => host_part,
        },
    };

    Ok(format!("http://{}:{}", host, DEFAULT_GRPC_PORT))
}

/// Compute a deterministic UUID batch ID from an array of JSON event strings
pub fn compute_batch_id<S: AsRef<str>>(events: &[S]) -> String {
    let mut h = Sha256::new();
    for e in events {
        h.update(e.as_ref().as_bytes());
        h.update([0]);
    }
    let digest = h.finalize();
    let bytes: [u8; 16] = digest[..16].try_into().unwrap_or_default();
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Manages gRPC connection and failover backoff state
#[derive(Clone)]
pub struct GrpcTransport {
    endpoint_url: String,
    client: Arc<Mutex<Option<AgentServiceClient>>>,
    consecutive_fails: Arc<AtomicU32>,
    fallback_until: Arc<Mutex<Option<Instant>>>,
}

impl GrpcTransport {
    /// Create a new transport bound to manager URL
    pub fn new(manager_url: &str) -> Result<Self, String> {
        let endpoint_url = manager_url_to_grpc_endpoint(manager_url)?;
        Ok(Self {
            endpoint_url,
            client: Arc::new(Mutex::new(None)),
            consecutive_fails: Arc::new(AtomicU32::new(0)),
            fallback_until: Arc::new(Mutex::new(None)),
        })
    }

    /// Check if gRPC transport is eligible to be used, or if it is currently in HTTPS fallback
    pub async fn is_available(&self) -> bool {
        let mut fallback = self.fallback_until.lock().await;
        if let Some(until) = *fallback {
            if Instant::now() < until {
                return false;
            } else {
                *fallback = None;
                self.consecutive_fails.store(0, Ordering::Relaxed);
                info!("GrpcTransport: Fallback timer elapsed. Attempting gRPC transport recovery.");
            }
        }
        true
    }

    /// Mark a failed gRPC attempt. After 3 consecutive fails, activates 10 min HTTPS fallback.
    pub async fn report_failure(&self, reason: &str) {
        let fails = self.consecutive_fails.fetch_add(1, Ordering::SeqCst) + 1;
        warn!("GrpcTransport: Connection failure #{}: {}", fails, reason);

        // Reset client channel to reconnect on next cycle
        let mut client_lock = self.client.lock().await;
        *client_lock = None;

        if fails >= GRPC_MAX_CONSECUTIVE_FAILS {
            let mut fallback = self.fallback_until.lock().await;
            let until = Instant::now() + HTTPS_FALLBACK_DURATION;
            *fallback = Some(until);
            warn!(
                "GrpcTransport: Reached {} consecutive gRPC failures. Falling back to HTTPS for {:?}",
                fails, HTTPS_FALLBACK_DURATION
            );
        }
    }

    /// Mark a successful gRPC transaction, clearing failure counters
    pub async fn report_success(&self) {
        self.consecutive_fails.store(0, Ordering::Relaxed);
        let mut fallback = self.fallback_until.lock().await;
        *fallback = None;
    }

    /// Internal helper to obtain or establish an active gRPC client channel
    async fn get_client(&self) -> Result<AgentServiceClient, String> {
        let mut client_lock = self.client.lock().await;
        if let Some(ref c) = *client_lock {
            return Ok(c.clone());
        }

        debug!("GrpcTransport: Establishing channel to {}", self.endpoint_url);
        let endpoint = Endpoint::from_shared(self.endpoint_url.clone())
            .map_err(|e| format!("Invalid gRPC endpoint URI {}: {}", self.endpoint_url, e))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true);

        let channel: Channel = endpoint.connect_lazy();
        let client = AgentServiceClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);

        *client_lock = Some(client.clone());
        Ok(client)
    }

    /// Attach authentication and agent identity headers to gRPC request
    fn attach_metadata<T>(req: T, agent_id: &str, agent_key: &str) -> tonic::Request<T> {
        let mut r = tonic::Request::new(req);
        let md = r.metadata_mut();
        if !agent_id.trim().is_empty() {
            if let Ok(val) = agent_id.trim().parse() {
                md.insert("x-agent-id", val);
            }
        }
        if !agent_key.trim().is_empty() {
            let key = agent_key.trim();
            if let Ok(val) = key.parse() {
                md.insert("x-agent-key", val);
            }
            if let Ok(bearer) = format!("Bearer {}", key).parse() {
                md.insert("authorization", bearer);
            }
        }
        r
    }

    /// Send a batch of JSON event strings over gRPC
    pub async fn send_events(
        &self,
        agent_id: &str,
        agent_key: &str,
        events_json: Vec<String>,
    ) -> Result<u32, String> {
        if !self.is_available().await {
            return Err("gRPC in fallback backoff mode".to_string());
        }

        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                self.report_failure(&e).await;
                return Err(e);
            }
        };

        let batch_id = compute_batch_id(&events_json);
        let req = Self::attach_metadata(
            EventsRequest {
                events_json,
                batch_id,
            },
            agent_id,
            agent_key,
        );

        match tokio::time::timeout(Duration::from_secs(10), client.events(req)).await {
            Ok(Ok(response)) => {
                self.report_success().await;
                Ok(response.into_inner().accepted)
            }
            Ok(Err(status)) => {
                let err_msg = format!("gRPC status: {}", status);
                self.report_failure(&err_msg).await;
                Err(err_msg)
            }
            Err(_) => {
                let err_msg = "gRPC events request timed out".to_string();
                self.report_failure(&err_msg).await;
                Err(err_msg)
            }
        }
    }

    /// Send a keepalive heartbeat over gRPC and retrieve pending active response commands
    pub async fn send_keepalive(
        &self,
        agent_id: &str,
        agent_name: &str,
        agent_ip: &str,
        agent_key: &str,
    ) -> Result<Vec<serde_json::Value>, String> {
        if !self.is_available().await {
            return Err("gRPC in fallback backoff mode".to_string());
        }

        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                self.report_failure(&e).await;
                return Err(e);
            }
        };

        let body = serde_json::json!({
            "agent_id": agent_id,
            "agent_name": agent_name,
            "status": "active",
            "agent_ip": agent_ip,
            "version": "1.0.0",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let req = Self::attach_metadata(
            KeepaliveRequest {
                body_json: body.to_string(),
            },
            agent_id,
            agent_key,
        );

        match tokio::time::timeout(Duration::from_secs(10), client.keepalive(req)).await {
            Ok(Ok(response)) => {
                self.report_success().await;
                let reply = response.into_inner();
                let commands: Vec<serde_json::Value> = reply
                    .commands_json
                    .into_iter()
                    .filter_map(|s| serde_json::from_str(&s).ok())
                    .collect();
                Ok(commands)
            }
            Ok(Err(status)) => {
                let err_msg = format!("gRPC status: {}", status);
                self.report_failure(&err_msg).await;
                Err(err_msg)
            }
            Err(_) => {
                let err_msg = "gRPC keepalive request timed out".to_string();
                self.report_failure(&err_msg).await;
                Err(err_msg)
            }
        }
    }

    /// Fetch central group configuration over gRPC
    pub async fn fetch_config(
        &self,
        agent_id: &str,
        agent_key: &str,
    ) -> Result<serde_json::Value, String> {
        if !self.is_available().await {
            return Err("gRPC in fallback backoff mode".to_string());
        }

        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                self.report_failure(&e).await;
                return Err(e);
            }
        };

        let req = Self::attach_metadata(ConfigRequest {}, agent_id, agent_key);

        match tokio::time::timeout(Duration::from_secs(10), client.config(req)).await {
            Ok(Ok(response)) => {
                self.report_success().await;
                let reply = response.into_inner();
                serde_json::from_str(&reply.config_json).map_err(|e| e.to_string())
            }
            Ok(Err(status)) => {
                let err_msg = format!("gRPC status: {}", status);
                self.report_failure(&err_msg).await;
                Err(err_msg)
            }
            Err(_) => {
                let err_msg = "gRPC config request timed out".to_string();
                self.report_failure(&err_msg).await;
                Err(err_msg)
            }
        }
    }

    /// Fetch compiled YARA rules over gRPC
    pub async fn fetch_yara_rules(
        &self,
        agent_id: &str,
        agent_key: &str,
    ) -> Result<Vec<u8>, String> {
        if !self.is_available().await {
            return Err("gRPC in fallback backoff mode".to_string());
        }

        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                self.report_failure(&e).await;
                return Err(e);
            }
        };

        let req = Self::attach_metadata(YaraRequest {}, agent_id, agent_key);

        match tokio::time::timeout(Duration::from_secs(15), client.yara(req)).await {
            Ok(Ok(response)) => {
                self.report_success().await;
                Ok(response.into_inner().data)
            }
            Ok(Err(status)) => {
                let err_msg = format!("gRPC status: {}", status);
                self.report_failure(&err_msg).await;
                Err(err_msg)
            }
            Err(_) => {
                let err_msg = "gRPC yara request timed out".to_string();
                self.report_failure(&err_msg).await;
                Err(err_msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_url_conversion() {
        assert_eq!(
            manager_url_to_grpc_endpoint("https://192.168.1.100:8443").unwrap(),
            "http://192.168.1.100:8089"
        );
        assert_eq!(
            manager_url_to_grpc_endpoint("http://siem.corp.internal:8088/").unwrap(),
            "http://siem.corp.internal:8089"
        );
        assert_eq!(
            manager_url_to_grpc_endpoint("grpc://10.0.0.5:9000").unwrap(),
            "http://10.0.0.5:9000"
        );
        assert_eq!(
            manager_url_to_grpc_endpoint("grpcs://secure.siem.io:8089").unwrap(),
            "https://secure.siem.io:8089"
        );
        assert_eq!(
            manager_url_to_grpc_endpoint("192.168.220.35").unwrap(),
            "http://192.168.220.35:8089"
        );
    }

    #[test]
    fn test_batch_id_determinism() {
        let events = vec!["{\"event\":1}", "{\"event\":2}"];
        let id1 = compute_batch_id(&events);
        let id2 = compute_batch_id(&events);
        assert_eq!(id1, id2);
        assert_ne!(id1, compute_batch_id(&["{\"event\":3}"]));
    }

    #[tokio::test]
    async fn test_grpc_fallback_state_machine() {
        let transport = GrpcTransport::new("https://127.0.0.1:8443").unwrap();
        assert!(transport.is_available().await);

        // First 2 failures do not trigger HTTPS fallback
        transport.report_failure("network reset").await;
        assert_eq!(transport.consecutive_fails.load(Ordering::SeqCst), 1);
        assert!(transport.is_available().await);

        transport.report_failure("timeout").await;
        assert_eq!(transport.consecutive_fails.load(Ordering::SeqCst), 2);
        assert!(transport.is_available().await);

        // 3rd failure activates 10-minute fallback
        transport.report_failure("refused").await;
        assert_eq!(transport.consecutive_fails.load(Ordering::SeqCst), 3);
        assert!(!transport.is_available().await);

        // Success immediately restores availability
        transport.report_success().await;
        assert_eq!(transport.consecutive_fails.load(Ordering::SeqCst), 0);
        assert!(transport.is_available().await);
    }
}
