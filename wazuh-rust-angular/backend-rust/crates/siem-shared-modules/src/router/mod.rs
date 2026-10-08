//! In-process pub-sub routing module (router)
//!
//! Provides decoupled event publishing and subscription using topic-based routing,
//! patterned after Wazuh's `RouterProvider` and `RouterSubscriber`.

use crate::common::{ReturnType, Result, SharedModuleError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterMessage {
    pub topic: String,
    pub sender: String,
    pub payload: serde_json::Value,
    pub timestamp: i64,
}

/// The core routing broker managing channels per topic.
#[derive(Debug, Clone)]
pub struct RouterProvider {
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<RouterMessage>>>>,
    buffer_capacity: usize,
}

impl Default for RouterProvider {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl RouterProvider {
    pub fn new(buffer_capacity: usize) -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            buffer_capacity,
        }
    }

    /// Publish a message to a specific topic.
    pub async fn publish(&self, topic: &str, sender: &str, payload: serde_json::Value) -> Result<usize> {
        let msg = RouterMessage {
            topic: topic.to_string(),
            sender: sender.to_string(),
            payload,
            timestamp: chrono::Utc::now().timestamp(),
        };

        let channels = self.channels.read().await;
        if let Some(sender_channel) = channels.get(topic) {
            // send returns the number of active receivers
            match sender_channel.send(msg) {
                Ok(receivers) => Ok(receivers),
                Err(_) => Ok(0), // No active receivers
            }
        } else {
            Ok(0)
        }
    }

    /// Create or retrieve a subscriber handle for a given topic.
    pub async fn subscribe(&self, topic: &str) -> RouterSubscriber {
        let mut channels = self.channels.write().await;
        let sender = channels
            .entry(topic.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(self.buffer_capacity);
                tx
            });

        RouterSubscriber {
            topic: topic.to_string(),
            receiver: sender.subscribe(),
        }
    }

    /// List all currently registered topics.
    pub async fn list_topics(&self) -> Vec<String> {
        let channels = self.channels.read().await;
        channels.keys().cloned().collect()
    }
}

/// Subscriber handle receiving messages for a subscribed topic.
pub struct RouterSubscriber {
    pub topic: String,
    receiver: broadcast::Receiver<RouterMessage>,
}

impl RouterSubscriber {
    /// Receive next message from topic.
    pub async fn recv(&mut self) -> Result<RouterMessage> {
        match self.receiver.recv().await {
            Ok(msg) => Ok(msg),
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                Err(SharedModuleError::Failure(
                    ReturnType::BufferFull,
                    format!("Subscriber lagged behind by {} messages", missed),
                ))
            }
            Err(broadcast::error::RecvError::Closed) => {
                Err(SharedModuleError::Failure(
                    ReturnType::NetworkError,
                    "Channel closed".into(),
                ))
            }
        }
    }

    /// Try to receive without blocking.
    pub fn try_recv(&mut self) -> Result<Option<RouterMessage>> {
        match self.receiver.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(broadcast::error::TryRecvError::Lagged(missed)) => {
                Err(SharedModuleError::Failure(
                    ReturnType::BufferFull,
                    format!("Subscriber lagged behind by {} messages", missed),
                ))
            }
            Err(broadcast::error::TryRecvError::Closed) => {
                Err(SharedModuleError::Failure(
                    ReturnType::NetworkError,
                    "Channel closed".into(),
                ))
            }
        }
    }
}
