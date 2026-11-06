//! ProVigil SOAR HTTP Integrations
//!
//! Clean-room, pure Rust implementations of outbound SOAR notifications and lookups
//! for Slack, PagerDuty, Shuffle, VirusTotal, and Maltiverse.
//! Replaces external python-derived scripts with direct async in-process HTTP requests.

use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
pub const PAGERDUTY_V2_URL: &str = "https://events.pagerduty.com/v2/enqueue";
pub const VIRUSTOTAL_V2_URL: &str = "https://www.virustotal.com/vtapi/v2/file/report";
pub const DEFAULT_MALTIVERSE_URL: &str = "https://api.maltiverse.com";

const SHUFFLE_SKIP_RULE_IDS: [&str; 14] = [
    "87924", "87900", "87901", "87902", "87903", "87904", "86001", "86002", "86003", "87932",
    "80710", "87929", "87928", "5710",
];

// ───────────────────────────────────────── Slack ─────────────────────────────────────────

/// Formats an alert for Slack webhook delivery.
pub fn build_slack_payload(alert: &Value) -> Value {
    let rule = &alert["rule"];
    let level = rule["level"].as_u64().unwrap_or(0);
    let color = if level <= 4 {
        "good"
    } else if level <= 7 {
        "warning"
    } else {
        "danger"
    };

    let mut fields = Vec::new();

    if let (Some(id), Some(name)) = (
        alert["agent"]["id"].as_str(),
        alert["agent"]["name"].as_str(),
    ) {
        fields.push(json!({
            "title": "Agent",
            "value": format!("({id}) - {name}")
        }));
    }

    if let Some(host) = alert["agentless"]["host"].as_str() {
        fields.push(json!({
            "title": "Agentless Host",
            "value": host
        }));
    }

    if let Some(loc) = alert["location"].as_str() {
        fields.push(json!({
            "title": "Location",
            "value": loc
        }));
    }

    let rule_id = rule["id"]
        .as_str()
        .or_else(|| rule["id"].as_u64().map(|_| ""))
        .unwrap_or("0");
    fields.push(json!({
        "title": "Rule ID",
        "value": format!("{rule_id} _(Level {level})_")
    }));

    let title = rule["description"].as_str().unwrap_or("N/A");
    let text = alert["full_log"]
        .as_str()
        .or_else(|| alert["log"].as_str())
        .unwrap_or("");
    let ts = alert["id"].as_str().unwrap_or("");

    json!({
        "attachments": [
            {
                "color": color,
                "pretext": "ProVigil Alert",
                "title": title,
                "text": text,
                "fields": fields,
                "ts": ts
            }
        ]
    })
}

/// Dispatches an alert to Slack.
pub async fn send_slack(webhook_url: &str, alert: &Value) -> Result<String, String> {
    let payload = build_slack_payload(alert);
    let client = reqwest::Client::new();
    let res = client
        .post(webhook_url)
        .header("content-type", "application/json")
        .header("Accept-Charset", "UTF-8")
        .json(&payload)
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("Slack request failed: {e}"))?;

    if res.status().is_success() {
        Ok("Slack integration sent".to_string())
    } else {
        Err(format!("Slack server returned status {}", res.status()))
    }
}

// ─────────────────────────────────────── PagerDuty ───────────────────────────────────────

/// Formats an alert for PagerDuty Events API v2.
pub fn build_pagerduty_payload(routing_key: &str, alert: &Value) -> Value {
    let rule = &alert["rule"];
    let level = rule["level"].as_u64().unwrap_or(0);
    let severity = if level >= 7 { "warning" } else { "info" };

    let summary = rule["description"].as_str().unwrap_or("N/A");
    let timestamp = alert["timestamp"].as_str().unwrap_or("");
    let source = alert["agent"]["name"]
        .as_str()
        .or_else(|| alert["agent"]["id"].as_str())
        .or_else(|| alert["manager"]["name"].as_str())
        .unwrap_or("ProVigil");

    let groups = if let Some(arr) = rule["groups"].as_array() {
        arr.iter()
            .filter_map(|g| g.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        rule["groups"].as_str().unwrap_or("").to_string()
    };

    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "timestamp": timestamp,
            "source": source,
            "severity": severity,
            "group": groups,
            "custom_details": alert
        },
        "client": "ProVigil Monitoring Service",
        "client_url": "https://provigil.local"
    })
}

/// Dispatches an alert to PagerDuty.
pub async fn send_pagerduty(routing_key: &str, alert: &Value) -> Result<String, String> {
    let payload = build_pagerduty_payload(routing_key, alert);
    let client = reqwest::Client::new();
    let res = client
        .post(PAGERDUTY_V2_URL)
        .header("content-type", "application/json")
        .header("Accept-Charset", "UTF-8")
        .json(&payload)
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("PagerDuty request failed: {e}"))?;

    if res.status().is_success() {
        Ok("PagerDuty integration sent".to_string())
    } else {
        Err(format!("PagerDuty server returned status {}", res.status()))
    }
}

// ──────────────────────────────────────── Shuffle ────────────────────────────────────────

/// Formats an alert for Shuffle webhook delivery (returns None if rule is in skip list).
pub fn build_shuffle_payload(alert: &Value) -> Option<Value> {
    let rule = &alert["rule"];
    let rule_id = rule["id"]
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| rule["id"].as_u64().map(|n| n.to_string()))
        .unwrap_or_else(|| "0".to_string());

    if SHUFFLE_SKIP_RULE_IDS.contains(&rule_id.as_str()) {
        return None;
    }

    let level = rule["level"].as_u64().unwrap_or(0);
    let severity = if level <= 4 {
        1
    } else if level <= 7 {
        2
    } else {
        3
    };

    let title = rule["description"].as_str().unwrap_or("N/A");
    let text = alert["full_log"]
        .as_str()
        .or_else(|| alert["log"].as_str())
        .unwrap_or("");
    let timestamp = alert["timestamp"].as_str().unwrap_or("");
    let id = alert["id"].as_str().unwrap_or("");

    Some(json!({
        "severity": severity,
        "pretext": "ProVigil Alert",
        "title": title,
        "text": text,
        "rule_id": rule_id,
        "timestamp": timestamp,
        "id": id,
        "all_fields": alert
    }))
}

/// Dispatches an alert to Shuffle.
pub async fn send_shuffle(webhook_url: &str, alert: &Value) -> Result<String, String> {
    let Some(payload) = build_shuffle_payload(alert) else {
        let rule_id = alert["rule"]["id"].as_str().unwrap_or("");
        return Ok(format!("Skipped rule {rule_id} for Shuffle"));
    };

    let client = reqwest::Client::new();
    let res = client
        .post(webhook_url)
        .header("content-type", "application/json")
        .header("Accept-Charset", "UTF-8")
        .json(&payload)
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("Shuffle request failed: {e}"))?;

    if res.status().is_success() {
        Ok("Shuffle integration sent".to_string())
    } else {
        Err(format!("Shuffle server returned status {}", res.status()))
    }
}

// ────────────────────────────────────── VirusTotal ───────────────────────────────────────

fn is_valid_md5(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Queries VirusTotal API for a file's MD5 checksum from an alert.
pub async fn query_virustotal(api_key: &str, alert: &Value) -> Result<Value, String> {
    let syscheck = &alert["syscheck"];
    let md5 = syscheck["md5_after"]
        .as_str()
        .or_else(|| syscheck["md5"].as_str())
        .unwrap_or("");

    if !is_valid_md5(md5) {
        return Err("No valid 32-character MD5 checksum found in syscheck alert".to_string());
    }

    let client = reqwest::Client::new();
    let res = client
        .get(VIRUSTOTAL_V2_URL)
        .query(&[("apikey", api_key), ("resource", md5)])
        .header("User-Agent", "ProVigil-VirusTotal-Client")
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("VirusTotal API request failed: {e}"))?;

    match res.status().as_u16() {
        200 => {
            let data: Value = res
                .json()
                .await
                .map_err(|e| format!("Failed to parse VirusTotal response JSON: {e}"))?;
            let response_code = data["response_code"].as_i64().unwrap_or(0);
            let found = if response_code == 1 { 1 } else { 0 };
            let positives = data["positives"].as_u64().unwrap_or(0);
            let total = data["total"].as_u64().unwrap_or(0);
            let permalink = data["permalink"].as_str().unwrap_or("");

            Ok(json!({
                "integration": "virustotal",
                "virustotal": {
                    "found": found,
                    "malicious": if positives > 0 { 1 } else { 0 },
                    "positives": positives,
                    "total": total,
                    "permalink": permalink,
                    "source": {
                        "alert_id": alert["id"].as_str().unwrap_or(""),
                        "file": syscheck["path"].as_str().unwrap_or(""),
                        "md5": md5
                    }
                }
            }))
        }
        204 => Err("VirusTotal Public API request rate limit reached (status 204)".to_string()),
        403 => Err("VirusTotal credentials error: check API key (status 403)".to_string()),
        code => Err(format!(
            "VirusTotal API query failed with HTTP status {code}"
        )),
    }
}

// ────────────────────────────────────── Maltiverse ───────────────────────────────────────

/// Determines whether an IP address is private, loopback, or reserved.
pub fn is_private_or_reserved_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_multicast(),
    }
}

/// Queries Maltiverse threat intelligence API.
pub async fn query_maltiverse(
    api_key: &str,
    endpoint: &str,
    alert: &Value,
) -> Result<Value, String> {
    let base_url = if endpoint.trim().is_empty() {
        DEFAULT_MALTIVERSE_URL
    } else {
        endpoint.trim().trim_end_matches('/')
    };

    // Extract IOC: srcip or md5
    let srcip = alert["data"]["srcip"]
        .as_str()
        .or_else(|| alert["srcip"].as_str());
    let md5 = alert["syscheck"]["md5_after"]
        .as_str()
        .or_else(|| alert["syscheck"]["md5"].as_str());

    let (path, ioc_type) = if let Some(ip_str) = srcip {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if is_private_or_reserved_ip(&ip) {
                return Ok(json!({
                    "integration": "maltiverse",
                    "status": "skipped_private_ip",
                    "ip": ip_str
                }));
            }
        }
        (format!("{base_url}/ip/{ip_str}"), "ip")
    } else if let Some(hash) = md5 {
        (format!("{base_url}/sample/{hash}"), "sample")
    } else {
        return Err("No IOC (srcip or syscheck md5) found in alert for Maltiverse".to_string());
    };

    let client = reqwest::Client::new();
    let res = client
        .get(&path)
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {api_key}"))
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("Maltiverse API request failed: {e}"))?;

    if res.status().is_success() {
        let data: Value = res
            .json()
            .await
            .map_err(|e| format!("Failed to parse Maltiverse response JSON: {e}"))?;
        let classification = data["classification"].as_str().unwrap_or("neutral");
        let is_malicious = classification == "malicious";

        Ok(json!({
            "integration": "maltiverse",
            "maltiverse": {
                "type": ioc_type,
                "classification": classification,
                "malicious": if is_malicious { 1 } else { 0 },
                "details": data
            }
        }))
    } else {
        Err(format!("Maltiverse returned HTTP status {}", res.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_alert() -> Value {
        json!({
            "timestamp": "2026-11-03T07:15:20+00:00",
            "id": "1729664111.1234",
            "location": "/var/log/secure",
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "sshd: brute force",
                "groups": ["syslog", "sshd", "authentication_failures"]
            },
            "agent": {
                "id": "001",
                "name": "web-01"
            },
            "data": {
                "srcip": "203.0.113.9"
            },
            "full_log": "Failed password for root from 203.0.113.9 port 51022 ssh2"
        })
    }

    #[test]
    fn test_slack_payload() {
        let alert = sample_alert();
        let payload = build_slack_payload(&alert);

        let att = &payload["attachments"][0];
        assert_eq!(att["color"], "danger"); // level 10 -> danger
        assert_eq!(att["pretext"], "ProVigil Alert");
        assert_eq!(att["title"], "sshd: brute force");
        assert_eq!(
            att["text"],
            "Failed password for root from 203.0.113.9 port 51022 ssh2"
        );
        assert_eq!(att["ts"], "1729664111.1234");

        let fields = att["fields"].as_array().unwrap();
        assert!(fields
            .iter()
            .any(|f| f["title"] == "Agent" && f["value"] == "(001) - web-01"));
        assert!(fields
            .iter()
            .any(|f| f["title"] == "Location" && f["value"] == "/var/log/secure"));
        assert!(fields
            .iter()
            .any(|f| f["title"] == "Rule ID" && f["value"] == "5712 _(Level 10)_"));
    }

    #[test]
    fn test_pagerduty_payload() {
        let alert = sample_alert();
        let payload = build_pagerduty_payload("pd-token-xyz", &alert);

        assert_eq!(payload["routing_key"], "pd-token-xyz");
        assert_eq!(payload["event_action"], "trigger");
        assert_eq!(payload["client"], "ProVigil Monitoring Service");

        let p = &payload["payload"];
        assert_eq!(p["summary"], "sshd: brute force");
        assert_eq!(p["severity"], "warning"); // level 10 >= 7 -> warning
        assert_eq!(p["source"], "web-01");
        assert_eq!(p["group"], "syslog, sshd, authentication_failures");
        assert_eq!(p["custom_details"]["id"], "1729664111.1234");
    }

    #[test]
    fn test_shuffle_payload_and_skipping() {
        let alert = sample_alert();
        let payload = build_shuffle_payload(&alert).expect("should not be skipped");

        assert_eq!(payload["severity"], 3); // level 10 >= 8 -> 3
        assert_eq!(payload["pretext"], "ProVigil Alert");
        assert_eq!(payload["rule_id"], "5712");
        assert_eq!(payload["id"], "1729664111.1234");

        // Test rule skipping
        let mut skipped_alert = alert.clone();
        skipped_alert["rule"]["id"] = json!("5710"); // 5710 in skip list
        assert!(build_shuffle_payload(&skipped_alert).is_none());
    }

    #[test]
    fn test_virustotal_md5_validation() {
        assert!(is_valid_md5("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!is_valid_md5("too-short"));
        assert!(!is_valid_md5("d41d8cd98f00b204e9800998ecf8427z")); // 'z' not hex
    }

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_or_reserved_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_or_reserved_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_or_reserved_ip(&"10.0.5.1".parse().unwrap()));
        assert!(!is_private_or_reserved_ip(&"8.8.8.8".parse().unwrap()));
    }
}
