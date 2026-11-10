# SOAR HTTP Integrations Specification

A clean-room, pure Rust implementation of SOAR alert dispatch for external platforms:
Slack, PagerDuty, Shuffle, VirusTotal, and Maltiverse.
Replaces the dependency on `siem-integratord` and its legacy python-ported script binaries.

## Responsibilities

1. **Direct In-Process Async HTTP**:
   - Uses `reqwest::Client` with 15-second request timeouts.
   - Eliminates all temp file creation and subprocess execution (`.exe` scripts).
   - Validates destination URLs against SSRF policies (`provigil_common::soar::check_url`).

2. **Supported Platforms**:
   - **Slack**:
     - Webhook POST with attachments payload.
     - Color mapping: `level <= 4 -> "good"`, `level 5..=7 -> "warning"`, `level >= 8 -> "danger"`.
     - Fields: Agent (`({id}) - {name}`), Location, Rule ID (`{id} _(Level {level})_`).
     - Pretext: `"ProVigil Alert"`.
   - **PagerDuty**:
     - Events API v2 POST (`https://events.pagerduty.com/v2/enqueue`).
     - Severity mapping: `level >= 7 -> "warning"`, `level < 7 -> "info"`.
     - Payload includes `routing_key`, `event_action: "trigger"`, `summary`, `source`, `custom_details`.
     - Client name: `"ProVigil Monitoring Service"`.
   - **Shuffle**:
     - Webhook POST with alert payload.
     - Rule filter: Skips IDs `["87924", "87900", "87901", "87902", "87903", "87904", "86001", "86002", "86003", "87932", "80710", "87929", "87928", "5710"]`.
     - Severity mapping: `level <= 4 -> 1`, `level 5..=7 -> 2`, `level >= 8 -> 3`.
   - **VirusTotal**:
     - Queries VirusTotal v2 API for FIM alerts containing `syscheck.md5_after`.
     - Validates MD5 32-character hexadecimal format.
     - Reports `positives`, `total`, `permalink`, and flags `malicious = 1` if `positives > 0`.
   - **Maltiverse**:
     - Queries Maltiverse API for indicators (IP, domain, hash, URL) with Bearer token authentication.
     - Filters private, loopback, and reserved IP addresses.
     - Evaluates confidence rating based on blacklist sightings.

## Public Interface

```rust
pub async fn send_slack(webhook_url: &str, alert: &serde_json::Value) -> Result<String, String>;
pub async fn send_pagerduty(routing_key: &str, alert: &serde_json::Value) -> Result<String, String>;
pub async fn send_shuffle(webhook_url: &str, alert: &serde_json::Value) -> Result<String, String>;
pub async fn query_virustotal(api_key: &str, alert: &serde_json::Value) -> Result<serde_json::Value, String>;
pub async fn query_maltiverse(api_key: &str, endpoint: &str, alert: &serde_json::Value) -> Result<serde_json::Value, String>;

pub fn build_slack_payload(alert: &serde_json::Value) -> serde_json::Value;
pub fn build_pagerduty_payload(routing_key: &str, alert: &serde_json::Value) -> serde_json::Value;
pub fn build_shuffle_payload(alert: &serde_json::Value) -> Option<serde_json::Value>;
```

## Required Tests

1. `test_slack_payload`: verifies color tiers, fields, pretext, and attachment structure.
2. `test_pagerduty_payload`: verifies v2 schema, severity tiers, and custom_details embedding.
3. `test_shuffle_payload`: verifies rule skipping and severity integer mapping.
4. `test_virustotal_md5_validation`: verifies MD5 regex extraction and invalid checksum rejection.
5. `test_private_ip_detection`: verifies private/loopback/reserved IP exclusion for threat intel.

