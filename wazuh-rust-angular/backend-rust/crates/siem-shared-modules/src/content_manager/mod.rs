//! Security Content Manager (content_manager)
//!
//! Orchestrates on-demand and scheduled updates of security feeds (CVE vulnerability databases,
//! threat intelligence feeds, rule catalogs) and coordinates background updater workers.

use crate::common::{ReturnType, Result, SharedModuleError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateStatus {
    Idle,
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedRegistration {
    pub name: String,
    pub source_url: String,
    pub local_path: String,
    pub last_updated: Option<i64>,
    pub status: UpdateStatus,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentCommand {
    pub command: String,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentResponse {
    pub error: u32,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// Dynamic Content Manager managing feeds and trigger requests.
#[derive(Debug, Clone, Default)]
pub struct ContentManager {
    feeds: Arc<RwLock<HashMap<String, FeedRegistration>>>,
}

impl ContentManager {
    pub fn new() -> Self {
        Self {
            feeds: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new feed source.
    pub async fn register_feed(
        &self,
        name: &str,
        source_url: &str,
        local_path: &str,
    ) -> Result<()> {
        let mut feeds = self.feeds.write().await;
        feeds.insert(
            name.to_string(),
            FeedRegistration {
                name: name.to_string(),
                source_url: source_url.to_string(),
                local_path: local_path.to_string(),
                last_updated: None,
                status: UpdateStatus::Idle,
                last_error: None,
            },
        );
        Ok(())
    }

    /// Trigger update for a specific feed or all feeds.
    pub async fn trigger_update(&self, target: Option<&str>) -> Result<Vec<String>> {
        let mut feeds = self.feeds.write().await;
        let mut triggered = Vec::new();

        for (name, feed) in feeds.iter_mut() {
            if let Some(t) = target {
                if name != t {
                    continue;
                }
            }

            feed.status = UpdateStatus::InProgress;
            feed.last_updated = Some(chrono::Utc::now().timestamp());
            triggered.push(name.clone());
        }

        if triggered.is_empty() {
            if let Some(t) = target {
                return Err(SharedModuleError::Failure(
                    ReturnType::NotFound,
                    format!("Target feed '{}' not found", t),
                ));
            }
        }

        Ok(triggered)
    }

    /// Mark an update as finished.
    pub async fn mark_completed(&self, name: &str, success: bool, error_msg: Option<&str>) -> Result<()> {
        let mut feeds = self.feeds.write().await;
        if let Some(feed) = feeds.get_mut(name) {
            feed.status = if success {
                UpdateStatus::Completed
            } else {
                UpdateStatus::Failed
            };
            feed.last_error = error_msg.map(|s| s.to_string());
            Ok(())
        } else {
            Err(SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Feed '{}' not found", name),
            ))
        }
    }

    /// Process an on-demand socket control command.
    pub async fn process_command(&self, cmd: ContentCommand) -> ContentResponse {
        match cmd.command.as_str() {
            "update" => match self.trigger_update(cmd.target.as_deref()).await {
                Ok(triggered) => ContentResponse {
                    error: 0,
                    message: format!("Triggered update for feeds: {:?}", triggered),
                    data: Some(serde_json::json!({ "updated_feeds": triggered })),
                },
                Err(e) => ContentResponse {
                    error: 1,
                    message: e.to_string(),
                    data: None,
                },
            },
            "status" => {
                let feeds = self.feeds.read().await;
                let feed_list: Vec<FeedRegistration> = feeds.values().cloned().collect();
                ContentResponse {
                    error: 0,
                    message: "Current feed status retrieved".into(),
                    data: Some(serde_json::to_value(feed_list).unwrap_or_default()),
                }
            }
            other => ContentResponse {
                error: 2,
                message: format!("Unknown command: '{}'", other),
                data: None,
            },
        }
    }
}
