# Syslog Sender Specification

A clean-room, pure Rust syslog alert formatting and forwarding module for ProVigil SIEM (`siem-api`).
Replaces the dependency on the ported `siem-csyslogd` crate in `soar.rs`.

## Responsibilities

1. **Format Alerts** into standard Syslog message formats:
   - **Default (RFC 3164 format)**:
     `<{priority}>{timestamp} {host} provigil: Alert Level: {level}; Rule: {rule_id} - {comment}; Location: {location}; [classification: {group};] [srcip: {srcip};] [dstip: {dstip};] [user: {user};] {log}`
   - **CEF (Common Event Format)**:
     `<{priority}>{timestamp} CEF:0|ProVigil|ProVigil|v1.0|{rule_id}|{comment}|{level_0_to_10}|dvc={host} cs1={location} cs1Label=Location [cat={group}] [src={srcip}] [spt={srcport}] [dst={dstip}] [dpt={dstport}] [fname={file}] [suser={user}] [msg={log}]`
   - **JSON (Structured Syslog)**:
     `<{priority}>{timestamp} {host} provigil: {compact_json_payload}`
   - **Splunk (Key-Value format)**:
     `<{priority}>{timestamp} {host} provigil: crit={level} id={rule_id} description="{comment}" component="{location}", [classification="{group}",] [src_ip="{srcip}",] [src_port={srcport},] [dst_ip="{dstip}",] [dst_port={dstport},] [file="{file}",] [acct="{user}",] [message="{log}"]`

2. **Syslog Priority & Headers**:
   - Default priority is `132` (`facility local0 (16) * 8 + severity warning (4)`).
   - Timestamp format: BSD / RFC 3164 format `Mmm dd hh:mm:ss` (e.g. `Nov  3 07:15:20`, single-digit day space-padded).
   - Host header: machine hostname (short hostname or full FQDN depending on config).

3. **Filtering**:
   - Minimum severity level: alert level must be >= configured level.
   - Rule ID filter: if configured, alert rule ID must match one of the specified IDs.
   - Group filter: regex or substring match against rule groups / classification.
   - Location filter: regex or substring match against alert location (checking suffix after `->` if present).

4. **Network Transport**:
   - Async UDP transmission via `tokio::net::UdpSocket`.
   - Hostname resolution with DNS lookup.
   - Re-attempt on transient socket busy errors.

5. **Direct JSON Ingestion**:
   - Accepts alerts directly as `&serde_json::Value` (no dependency on legacy `siem_cjson` or `AlertData`).

## Public Interface

```rust
pub enum SyslogFormat {
    Default,
    Cef,
    Json,
    Splunk,
}

pub struct SyslogTarget {
    pub host: String,
    pub port: u16,
    pub format: SyslogFormat,
    pub priority: u32,
    pub use_fqdn: bool,
    pub min_level: u32,
    pub rule_ids: Option<Vec<u32>>,
    pub group_filter: Option<String>,
    pub location_filter: Option<String>,
}

pub fn format_alert(alert: &serde_json::Value, format: SyslogFormat, priority: u32, host: &str) -> String;
pub fn matches_filter(alert: &serde_json::Value, target: &SyslogTarget) -> bool;
pub async fn send_syslog(target: &SyslogTarget, alert: &serde_json::Value) -> Result<(), String>;
```

## Required Tests

1. `test_format_default`: verifies RFC 3164 output with severity, rule, and optional fields.
2. `test_format_cef`: verifies CEF header with ProVigil vendor and product name, clamped severity (0-10), and extension keys.
3. `test_format_json`: verifies JSON alert enclosed in syslog header.
4. `test_format_splunk`: verifies key-value escaped formatting for Splunk.
5. `test_filters`: verifies level filtering, rule ID whitelisting, group matching, and location matching.
6. `test_udp_transmission`: verifies sending formatted syslog message to a local UDP listener.

