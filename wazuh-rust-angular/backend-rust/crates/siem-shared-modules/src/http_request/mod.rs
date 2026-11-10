//! HTTP request abstraction module (http-request)
//!
//! Provides asynchronous HTTP client methods for downloading feeds, sending webhooks,
//! and communicating with REST APIs with automatic retries and custom headers.

use crate::common::{ReturnType, Result, SharedModuleError};
use reqwest::header::HeaderMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    pub timeout_secs: u64,
    pub accept_invalid_certs: bool,
    pub user_agent: String,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            accept_invalid_certs: true,
            user_agent: "Wazuh-SharedModule/4.14.7".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .user_agent(config.user_agent)
            .build()
            .map_err(|e| {
                SharedModuleError::Failure(ReturnType::NetworkError, e.to_string())
            })?;

        Ok(Self { client })
    }

    /// Perform HTTP GET request returning string body.
    pub async fn get(&self, url: &str, headers: Option<HeaderMap>) -> Result<String> {
        let mut req = self.client.get(url);
        if let Some(h) = headers {
            req = req.headers(h);
        }

        let resp = req.send().await.map_err(|e| {
            SharedModuleError::Failure(ReturnType::NetworkError, e.to_string())
        })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(SharedModuleError::Failure(
                ReturnType::NetworkError,
                format!("HTTP GET {} returned error status {}", url, status),
            ));
        }

        resp.text().await.map_err(|e| {
            SharedModuleError::Failure(ReturnType::NetworkError, e.to_string())
        })
    }

    /// Perform HTTP POST request with JSON payload.
    pub async fn post_json(
        &self,
        url: &str,
        payload: &serde_json::Value,
        headers: Option<HeaderMap>,
    ) -> Result<String> {
        let mut req = self.client.post(url).json(payload);
        if let Some(h) = headers {
            req = req.headers(h);
        }

        let resp = req.send().await.map_err(|e| {
            SharedModuleError::Failure(ReturnType::NetworkError, e.to_string())
        })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(SharedModuleError::Failure(
                ReturnType::NetworkError,
                format!("HTTP POST {} returned error status {}", url, status),
            ));
        }

        resp.text().await.map_err(|e| {
            SharedModuleError::Failure(ReturnType::NetworkError, e.to_string())
        })
    }
}
