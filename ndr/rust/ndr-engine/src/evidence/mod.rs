use anyhow::Context;
use sha2::{Sha256, Digest};
use zip::{ZipWriter, write::FileOptions};
use serde_json::{json, Value};
use std::io::Write;

use crate::storage::clickhouse::tenant_db_pub as tenant_db;

fn sha256_of(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn unix_to_iso(ts: f64) -> String {
    if ts == 0.0 { return String::new(); }
    let secs = ts as i64;
    let nanos = (ts.fract() * 1_000_000_000.0) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

/// Query ClickHouse HTTP API; returns the `data` array of row objects.
async fn query_ch(
    http: &reqwest::Client,
    ch_url: &str,
    ch_user: &str,
    ch_pass: &str,
    sql: &str,
) -> Value {
    let url = format!("{}/?user={}&password={}", ch_url, ch_user, ch_pass);
    let full_sql = format!("{} FORMAT JSON", sql.trim_end_matches(';'));
    match http.post(&url)
        .header("Content-Type", "text/plain")
        .body(full_sql)
        .send().await
    {
        Ok(resp) => resp.json::<Value>().await
            .ok()
            .and_then(|v| v.get("data").cloned())
            .unwrap_or(json!([])),
        Err(_) => json!([]),
    }
}

/// For ndr_hits rows whose sigma_hits is empty, rule_name comes from
/// arrayElement(sigma_hits,1) which returns "". This function patches those
/// rows by looking up the actual Suricata signature from ndr_events.raw.
///
/// If no signature can be recovered, the fallback label is picked from the
/// row's own `correlation_status` (agent_s_only / agent_z_only / etc.) rather
/// than assuming Suricata — a hit can just as well have come from Zeek+Sigma,
/// and mislabeling it "Suricata IDS Alert" misattributes the detection.
async fn fill_rule_names(
    mut rows: Value,
    http: &reqwest::Client,
    ch_url: &str,
    ch_user: &str,
    ch_pass: &str,
    db: &str,
    community_id: &str,
) -> Value {
    let has_empty = rows.as_array()
        .map(|a| a.iter().any(|r| {
            r["rule_name"].as_str().map(|s| s.is_empty()).unwrap_or(true)
        }))
        .unwrap_or(false);

    if !has_empty { return rows; }

    let sig_rows = query_ch(http, ch_url, ch_user, ch_pass, &format!(
        "SELECT JSONExtractString(raw, 'alert', 'signature') as sig \
         FROM {}.ndr_events \
         WHERE community_id = '{}' AND source = 'agent-s' AND event_type = 'alert' \
         LIMIT 1",
        db, community_id
    )).await;

    let recovered_sig = sig_rows.get(0)
        .and_then(|r| r["sig"].as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    if let Value::Array(ref mut arr) = rows {
        for row in arr.iter_mut() {
            if row["rule_name"].as_str().map(|s| s.is_empty()).unwrap_or(true) {
                let fallback = recovered_sig.clone().unwrap_or_else(|| {
                    match row["correlation_status"].as_str().unwrap_or("") {
                        "agent_s_only" => "Agent-S Alert (signature unavailable)".to_string(),
                        "agent_z_only" | "zeek_only" => "Agent-Z Sigma Match (rule name unavailable)".to_string(),
                        other if !other.is_empty() => format!("NDR Correlation Alert ({})", other),
                        _ => "NDR Correlation Alert".to_string(),
                    }
                });
                row["rule_name"] = json!(fallback);
            }
        }
    }
    rows
}

/// Query Suricata events from ndr_events by community_id and event_type.
/// All Suricata log types carry community_id directly — no uid join needed.
async fn query_suricata_events(
    http: &reqwest::Client,
    ch_url: &str,
    ch_user: &str,
    ch_pass: &str,
    db: &str,
    community_id: &str,
    event_type: &str,
    limit: usize,
) -> Vec<Value> {
    let sql = format!(
        "SELECT raw FROM {}.ndr_events \
         WHERE community_id = '{}' AND source = 'agent-s' \
         AND JSONExtractString(raw, 'event_type') = '{}' \
         ORDER BY timestamp ASC LIMIT {}",
        db, community_id, event_type, limit
    );
    let rows = query_ch(http, ch_url, ch_user, ch_pass, &sql).await;
    rows.as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|row| {
            let raw_str = row["raw"].as_str()?;
            serde_json::from_str(raw_str).ok()
        })
        .collect()
}

/// Query ndr_events WHERE community_id = uid AND JSONExtractString(raw,'log_type') = log_type.
/// Parses each row's `raw` JSON string and returns the parsed events.
async fn query_raw_events(
    http: &reqwest::Client,
    ch_url: &str,
    ch_user: &str,
    ch_pass: &str,
    db: &str,
    uid: &str,
    log_type: &str,
    limit: usize,
) -> Vec<Value> {
    let sql = format!(
        "SELECT raw FROM {}.ndr_events \
         WHERE community_id = '{}' \
         AND JSONExtractString(raw, 'log_type') = '{}' \
         ORDER BY timestamp ASC LIMIT {}",
        db, uid, log_type, limit
    );
    let rows = query_ch(http, ch_url, ch_user, ch_pass, &sql).await;
    rows.as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|row| {
            let raw_str = row["raw"].as_str()?;
            serde_json::from_str(raw_str).ok()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn build_attack_summary(
    community_id: &str,
    alert: &Value,
    suricata_alerts: &Value,
    threat_intel: &Value,
    related_alerts: &Value,
    pcap_captured: bool,
    generated_at: &str,
    dns_preceded: bool,
    ssl_self_signed: bool,
    files_transferred: usize,
    http_user_agent: &str,
    zeek_anomalies: usize,
) -> Value {
    let src_ip   = alert["src_ip"].as_str().unwrap_or("unknown");
    let dst_ip   = alert["dst_ip"].as_str().unwrap_or("unknown");
    let severity = alert["severity"].as_str().unwrap_or("UNKNOWN");

    let rules_fired: Vec<Value> = suricata_alerts
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|r| json!({ "name": r["rule_name"], "severity": r["severity"] }))
        .collect();

    let empty_vec: Vec<Value> = vec![];
    let intel_count = threat_intel
        .as_array()
        .unwrap_or(&empty_vec)
        .len();

    let related_count = related_alerts
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    let rules_desc: Vec<String> = rules_fired.iter()
        .map(|r| format!("'{}' ({})",
            r["name"].as_str().unwrap_or("?"),
            r["severity"].as_str().unwrap_or("?")))
        .collect();
    let rules_str = if rules_desc.is_empty() {
        "no rules matched".to_string()
    } else {
        rules_desc.join(", ")
    };

    let mut narrative = format!(
        "Host {} made suspicious connection to {}. NDR engine fired {} rule(s) including {}.",
        src_ip, dst_ip, rules_fired.len(), rules_str
    );

    if intel_count > 0 {
        narrative.push_str(&format!(
            " Threat intel confirms {} IP(s) are known malicious.", intel_count
        ));
    } else {
        narrative.push_str(" No threat intel matches found for observed IPs.");
    }

    if related_count > 0 {
        narrative.push_str(&format!(
            " {} related alert(s) from the same source in a 30-minute window suggest active compromise.",
            related_count
        ));
    }

    if dns_preceded {
        narrative.push_str(
            " DNS resolution for the destination was observed immediately before the connection \
             — consistent with C2 domain lookup."
        );
    }

    if ssl_self_signed {
        narrative.push_str(
            " WARNING: TLS certificate is self-signed — typical of attacker-controlled infrastructure."
        );
    }

    if files_transferred > 0 {
        narrative.push_str(&format!(
            " {} file(s) transferred during session — hashes available in agent_z_files.json for VirusTotal lookup.",
            files_transferred
        ));
    }

    if !http_user_agent.is_empty() {
        narrative.push_str(&format!(" HTTP user agent: '{}'.", http_user_agent));
    }

    if zeek_anomalies > 0 {
        narrative.push_str(&format!(
            " Agent-Z detected {} protocol anomaly/anomalies — see agent_z_weird.json.", zeek_anomalies
        ));
    }

    let recommended_action = format!(
        "Isolate host {}. Block {} at firewall. Review all connections from {} in the last 24 hours.",
        src_ip, dst_ip, src_ip
    );

    json!({
        "title": "Security Incident Report",
        "community_id": community_id,
        "generated_at": generated_at,
        "severity": severity,
        "summary": narrative,
        "attacker_ip": dst_ip,
        "victim_ip": src_ip,
        "rules_fired": rules_fired,
        "threat_intel_hits": intel_count,
        "related_alerts": related_count,
        "pcap_captured": pcap_captured,
        "dns_lookup_before_connection": dns_preceded,
        "ssl_self_signed_cert": ssl_self_signed,
        "files_transferred": files_transferred,
        "http_user_agent": http_user_agent,
        "zeek_anomalies": zeek_anomalies,
        "recommended_action": recommended_action
    })
}

/// Query ClickHouse live and return a full investigation data object.
/// Used by get_bundle_contents to always show current data (avoids stale ZIP data).
pub async fn fetch_live_investigation(
    community_id: &str,
    tenant_id: &str,
    alert_from_zip: &Value,
    session_from_zip: &Value,
) -> Value {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let ch_url  = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
    let ch_user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "ndr".to_string());
    let ch_pass = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| {
        tracing::error!("CLICKHOUSE_PASSWORD not set");
        String::new()
    });
    let db = tenant_db(tenant_id);

    // ── Connection record — best available from either sensor ────────────────
    // Zeek misses short UDP flows (DNS); Suricata always records them.
    // Query both and pick: Zeek conn > Suricata flow > Suricata alert > any event.
    let conn_record = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT src_ip, dst_ip, src_port, dst_port, \
         lower(proto) as proto, event_type, \
         toString(timestamp) as timestamp, community_id, source, raw \
         FROM {}.ndr_events \
         WHERE community_id = '{}' AND src_ip != '' \
         ORDER BY \
           multiIf(source='agent-z', 0, \
                   JSONExtractString(raw,'event_type')='flow', 1, \
                   JSONExtractString(raw,'event_type')='alert', 2, 3) ASC, \
           timestamp ASC \
         LIMIT 1",
        db, community_id
    )).await
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // Get ALL distinct Zeek uids for this community_id (one conn may have multiple sessions)
    let all_uids: Vec<String> = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT DISTINCT JSONExtractString(raw,'uid') as uid \
         FROM {}.ndr_events \
         WHERE community_id = '{}' AND source = 'agent-z' \
         AND JSONExtractString(raw,'uid') != ''",
        db, community_id
    )).await
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|r| r["uid"].as_str().map(String::from))
        .collect();

    // Primary uid for display (first one); all uids used for log joins
    let uid: String = all_uids.first()
        .cloned()
        .unwrap_or_else(|| community_id.to_string());

    // Resolve src_ip/dst_ip from conn record, then ZIP alert, then ZIP session
    let src_ip = {
        let from_conn  = conn_record["src_ip"].as_str().unwrap_or("").to_string();
        let from_alert = alert_from_zip["src_ip"].as_str().unwrap_or("").to_string();
        let from_sess  = session_from_zip["source"]["source"]["ip"].as_str().unwrap_or("").to_string();
        if !from_conn.is_empty() { from_conn }
        else if !from_alert.is_empty() { from_alert }
        else { from_sess }
    };
    let dst_ip = {
        let from_conn  = conn_record["dst_ip"].as_str().unwrap_or("").to_string();
        let from_alert = alert_from_zip["dst_ip"].as_str().unwrap_or("").to_string();
        let from_sess  = session_from_zip["source"]["destination"]["ip"].as_str().unwrap_or("").to_string();
        if !from_conn.is_empty() { from_conn }
        else if !from_alert.is_empty() { from_alert }
        else { from_sess }
    };
    let alert_time = alert_from_zip["timestamp"].as_str()
        .or_else(|| alert_from_zip["auto_captured_at"].as_str())
        .unwrap_or("1970-01-01T00:00:00Z")
        .to_string();

    // Build enriched alert object
    let mut alert_obj = alert_from_zip.clone();
    if let Some(obj) = alert_obj.as_object_mut() {
        obj.insert("src_ip".into(), json!(src_ip));
        obj.insert("dst_ip".into(), json!(dst_ip));
    }

    let zeek_conn_json = json!({
        "source": "agent-z-conn",
        "community_id": community_id,
        "uid": uid,
        "record": conn_record
    });

    // ── Zeek per-type events — collect across ALL uids for this community_id ─
    let mut raw_dns:   Vec<Value> = vec![];
    let mut raw_http:  Vec<Value> = vec![];
    let mut raw_ssl:   Vec<Value> = vec![];
    let mut raw_files: Vec<Value> = vec![];
    let mut raw_weird: Vec<Value> = vec![];

    for u in &all_uids {
        raw_dns  .extend(query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, u, "dns",   20).await);
        raw_http .extend(query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, u, "http",  20).await);
        raw_ssl  .extend(query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, u, "ssl",   10).await);
        raw_files.extend(query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, u, "files", 20).await);
        raw_weird.extend(query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, u, "weird", 20).await);
    }

    let zeek_dns_events: Vec<Value> = raw_dns.iter().map(|raw| {
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        json!({
            "uid": raw["uid"], "timestamp": unix_to_iso(ts),
            "src_ip": raw["id.orig_h"], "dns_server": raw["id.resp_h"],
            "query": raw["query"], "answers": raw["answers"],
            "rcode": raw["rcode_name"], "proto": raw["proto"], "rejected": raw["rejected"]
        })
    }).collect();

    let resolves_to_target = zeek_dns_events.iter().any(|e| {
        e["answers"].as_array()
            .map(|a| a.iter().any(|ans| ans.as_str() == Some(dst_ip.as_str())))
            .unwrap_or(false)
    });

    let zeek_dns_json = json!({
        "queries": zeek_dns_events,
        "total": raw_dns.len(),
        "resolves_to_target_ip": resolves_to_target,
        "uid": uid
    });

    let zeek_http_requests: Vec<Value> = raw_http.iter().map(|raw| {
        let ts   = raw["ts"].as_f64().unwrap_or(0.0);
        let host = raw["host"].as_str().unwrap_or("");
        let uri  = raw["uri"].as_str().unwrap_or("/");
        // Fall back to dst IP:port when Zeek didn't capture the Host header
        let dst  = raw["id.resp_h"].as_str().unwrap_or(&dst_ip);
        let port = raw["id.resp_p"].as_u64().unwrap_or(80);
        let display_host = if host.is_empty() {
            if port == 80 { dst.to_string() } else { format!("{}:{}", dst, port) }
        } else {
            host.to_string()
        };
        let display_uri = if uri == "/" && raw["uri"].is_null() { String::new() } else { uri.to_string() };
        json!({
            "timestamp": unix_to_iso(ts),
            "method":    raw["method"],
            "host":      display_host,
            "uri":       display_uri,
            "full_url":  format!("http://{}{}", display_host, display_uri),
            "user_agent":        raw["user_agent"],
            "status_code":       raw["status_code"],
            "bytes_uploaded":    raw["request_body_len"],
            "bytes_downloaded":  raw["response_body_len"]
        })
    }).collect();

    let zeek_http_json = json!({
        "requests": zeek_http_requests,
        "total": raw_http.len(),
        "uid": uid
    });

    let zeek_ssl_connections: Vec<Value> = raw_ssl.iter().map(|raw| {
        let issuer  = raw["issuer"].as_str().unwrap_or("");
        let subject = raw["subject"].as_str().unwrap_or("");
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        json!({
            "timestamp": unix_to_iso(ts),
            "server_name": raw["server_name"], "subject": subject, "issuer": issuer,
            "validation_status": raw["validation_status"],
            "is_valid": raw["validation_status"].as_str() == Some("ok"),
            "self_signed": !issuer.is_empty() && issuer == subject,
            "cipher": raw["cipher"], "tls_version": raw["version"],
            "ja3": raw["ja3"], "ja3s": raw["ja3s"]
        })
    }).collect();

    let ssl_self_signed = zeek_ssl_connections.iter().any(|c| c["self_signed"].as_bool().unwrap_or(false));

    let zeek_ssl_json = json!({
        "connections": zeek_ssl_connections,
        "total": raw_ssl.len(),
        "any_self_signed": ssl_self_signed,
        "uid": uid
    });

    let zeek_files_list: Vec<Value> = raw_files.iter().map(|raw| {
        let sha256 = raw["sha256"].as_str().unwrap_or("");
        let vt_link = if !sha256.is_empty() {
            format!("https://www.virustotal.com/gui/file/{}", sha256)
        } else { String::new() };
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        json!({
            "timestamp": unix_to_iso(ts), "filename": raw["filename"],
            "mime_type": raw["mime_type"], "sha256": sha256,
            "md5": raw["md5"], "sha1": raw["sha1"],
            "total_bytes": raw["total_bytes"], "seen_bytes": raw["seen_bytes"],
            "direction": if raw["is_orig"].as_bool().unwrap_or(false) { "upload" } else { "download" },
            "source_protocol": raw["source"], "virustotal_link": vt_link
        })
    }).collect();

    let zeek_files_json = json!({
        "files": zeek_files_list,
        "total": raw_files.len(),
        "uid": uid
    });

    let zeek_weird_events: Vec<Value> = raw_weird.iter().map(|raw| {
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        json!({
            "timestamp": unix_to_iso(ts), "weird_type": raw["name"],
            "detail": raw["addl"], "src_ip": raw["id.orig_h"], "dst_ip": raw["id.resp_h"]
        })
    }).collect();

    let zeek_weird_json = json!({
        "events": zeek_weird_events,
        "total": raw_weird.len(),
        "uid": uid
    });

    // ── Suricata raw events (separate from Zeek, shown as own sub-sections) ──
    let (suri_dns_raw, suri_http_raw, suri_tls_raw, suri_files_raw, suri_anomaly_raw, suri_flow_raw) = tokio::join!(
        query_suricata_events(&http, &ch_url, &ch_user, &ch_pass, &db, community_id, "dns",      20),
        query_suricata_events(&http, &ch_url, &ch_user, &ch_pass, &db, community_id, "http",     20),
        query_suricata_events(&http, &ch_url, &ch_user, &ch_pass, &db, community_id, "tls",      10),
        query_suricata_events(&http, &ch_url, &ch_user, &ch_pass, &db, community_id, "fileinfo", 20),
        query_suricata_events(&http, &ch_url, &ch_user, &ch_pass, &db, community_id, "anomaly",  20),
        query_suricata_events(&http, &ch_url, &ch_user, &ch_pass, &db, community_id, "flow",      1),
    );

    // Enrich alert_obj with connection details from Zeek conn + Suricata flow
    if let Some(obj) = alert_obj.as_object_mut() {
        // Ports and protocol from Zeek conn if not already in alert
        if obj.get("src_port").and_then(|v| v.as_u64()).unwrap_or(0) == 0 {
            if let Some(p) = conn_record["src_port"].as_u64() { obj.insert("src_port".into(), json!(p)); }
        }
        if obj.get("dst_port").and_then(|v| v.as_u64()).unwrap_or(0) == 0 {
            if let Some(p) = conn_record["dst_port"].as_u64() { obj.insert("dst_port".into(), json!(p)); }
        }
        if obj.get("proto").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
            if let Some(p) = conn_record["proto"].as_str() { obj.insert("proto".into(), json!(p)); }
        }
        // Bytes/packets from Suricata flow event
        if let Some(flow_ev) = suri_flow_raw.first() {
            let fl = &flow_ev["flow"];
            let bytes_tc = fl["bytes_toclient"].as_u64().unwrap_or(0);
            let bytes_ts = fl["bytes_toserver"].as_u64().unwrap_or(0);
            let pkts_tc  = fl["pkts_toclient"].as_u64().unwrap_or(0);
            let pkts_ts  = fl["pkts_toserver"].as_u64().unwrap_or(0);
            obj.insert("bytes_total".into(),   json!(bytes_tc + bytes_ts));
            obj.insert("bytes_toclient".into(), json!(bytes_tc));
            obj.insert("bytes_toserver".into(), json!(bytes_ts));
            obj.insert("packets_total".into(),  json!(pkts_tc + pkts_ts));
            obj.insert("pkts_toclient".into(),  json!(pkts_tc));
            obj.insert("pkts_toserver".into(),  json!(pkts_ts));
            obj.insert("flow_start".into(),     fl["start"].clone());
            obj.insert("flow_end".into(),       fl["end"].clone());
            obj.insert("flow_state".into(),     fl["state"].clone());
            obj.insert("app_proto".into(),      flow_ev["app_proto"].clone());
        }
        // User agent from Suricata HTTP
        if obj.get("user_agent").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
            let ua = suri_http_raw.first()
                .and_then(|r| r["http"]["http_user_agent"].as_str())
                .unwrap_or("");
            if !ua.is_empty() { obj.insert("user_agent".into(), json!(ua)); }
        }
    }

    let suricata_dns_queries: Vec<Value> = suri_dns_raw.iter().map(|r| {
        let dns = &r["dns"];
        json!({
            "timestamp":   r["timestamp"],
            "src_ip":      r["src_ip"],
            "dns_server":  r["dest_ip"],
            "query":       dns["rrname"],
            "type":        dns["type"],
            "rcode":       dns["rcode"],
            "answers":     dns["grouped"],
            "proto":       r["proto"]
        })
    }).collect();

    let suri_resolves_to_target = suricata_dns_queries.iter().any(|e| {
        e["answers"].as_object()
            .map(|obj| obj.values().any(|v| {
                v.as_array().map(|a| a.iter().any(|s| s.as_str() == Some(dst_ip.as_str()))).unwrap_or(false)
            }))
            .unwrap_or(false)
    });

    let suricata_dns_json = json!({
        "source": "agent-s",
        "queries": suricata_dns_queries,
        "total":   suri_dns_raw.len(),
        "resolves_to_target_ip": suri_resolves_to_target
    });

    let suricata_http_requests: Vec<Value> = suri_http_raw.iter().map(|r| {
        let h = &r["http"];
        let host = h["hostname"].as_str().unwrap_or(dst_ip.as_str());
        let uri  = h["url"].as_str().unwrap_or("/");
        let port = r["dest_port"].as_u64().unwrap_or(80);
        let scheme = if port == 443 { "https" } else { "http" };
        json!({
            "timestamp":        r["timestamp"],
            "method":           h["http_method"],
            "host":             host,
            "uri":              uri,
            "full_url":         format!("{}://{}{}", scheme, host, uri),
            "user_agent":       h["http_user_agent"],
            "status_code":      h["status"],
            "content_type":     h["http_content_type"],
            "bytes_downloaded": h["length"],
            "protocol":         h["protocol"],
            "src_ip":           r["src_ip"],
            "dest_ip":          r["dest_ip"]
        })
    }).collect();

    let suri_http_ua: String = suricata_http_requests.first()
        .and_then(|r| r["user_agent"].as_str())
        .unwrap_or("").to_string();

    let suricata_http_json = json!({
        "source":   "suricata",
        "requests": suricata_http_requests,
        "total":    suri_http_raw.len()
    });

    let suricata_tls_sessions: Vec<Value> = suri_tls_raw.iter().map(|r| {
        let tls = &r["tls"];
        let issuer  = tls["issuerdn"].as_str().unwrap_or("");
        let subject = tls["subject"].as_str().unwrap_or("");
        json!({
            "timestamp":   r["timestamp"],
            "server_name": tls["sni"],
            "subject":     subject,
            "issuer":      issuer,
            "tls_version": tls["version"],
            "ja3":         tls["ja3"],
            "ja3s":        tls["ja3s"],
            "fingerprint": tls["fingerprint"],
            "not_after":   tls["notafter"],
            "not_before":  tls["notbefore"],
            "self_signed": !issuer.is_empty() && issuer == subject,
            "src_ip":      r["src_ip"],
            "dest_ip":     r["dest_ip"]
        })
    }).collect();

    let suri_ssl_self_signed = suricata_tls_sessions.iter()
        .any(|c| c["self_signed"].as_bool().unwrap_or(false));

    let suricata_tls_json = json!({
        "source":      "suricata",
        "sessions":    suricata_tls_sessions,
        "total":       suri_tls_raw.len(),
        "any_self_signed": suri_ssl_self_signed
    });

    let suricata_files_list: Vec<Value> = suri_files_raw.iter().map(|r| {
        let fi       = &r["fileinfo"];
        let http_ctx = &r["http"];
        let filename = fi["filename"].as_str()
            .filter(|s| !s.is_empty() && *s != "/")
            .or_else(|| http_ctx["url"].as_str())
            .unwrap_or("(unnamed)");
        let mime = http_ctx["http_content_type"].as_str()
            .or_else(|| fi["mimetype"].as_str())
            .unwrap_or("");
        json!({
            "timestamp":   r["timestamp"],
            "filename":    filename,
            "mime_type":   mime,
            "size":        fi["size"],
            "state":       fi["state"],
            "stored":      fi["stored"],
            "http_url":    format!("http://{}{}",
                http_ctx["hostname"].as_str().unwrap_or(""),
                http_ctx["url"].as_str().unwrap_or("")),
            "user_agent":  http_ctx["http_user_agent"],
            "src_ip":      r["src_ip"],
            "dest_ip":     r["dest_ip"]
        })
    }).collect();

    let suricata_files_json = json!({
        "source": "agent-s",
        "files":  suricata_files_list,
        "total":  suri_files_raw.len()
    });

    let suricata_anomaly_events: Vec<Value> = suri_anomaly_raw.iter().map(|r| {
        let an = &r["anomaly"];
        json!({
            "timestamp":  r["timestamp"],
            "type":       an["type"],
            "event":      an["event"],
            "layer":      an["layer"],
            "src_ip":     r["src_ip"],
            "dest_ip":    r["dest_ip"],
            "proto":      r["proto"]
        })
    }).collect();

    let suricata_anomaly_json = json!({
        "source": "agent-s",
        "events": suricata_anomaly_events,
        "total":  suri_anomaly_raw.len()
    });

    // Combined flags for attack summary
    let resolves_to_target = !raw_dns.is_empty() && zeek_dns_events.iter().any(|e| {
        e["answers"].as_array()
            .map(|a| a.iter().any(|ans| ans.as_str() == Some(dst_ip.as_str())))
            .unwrap_or(false)
    }) || suri_resolves_to_target;

    let ssl_self_signed = zeek_ssl_connections.iter().any(|c| c["self_signed"].as_bool().unwrap_or(false))
        || suri_ssl_self_signed;

    let total_files = raw_files.len() + suri_files_raw.len();
    let total_anomalies = raw_weird.len() + suri_anomaly_raw.len();
    let http_user_agent = if !suri_http_ua.is_empty() { suri_http_ua }
        else {
            zeek_http_requests.first()
                .and_then(|r| r["user_agent"].as_str())
                .unwrap_or("").to_string()
        };

    // ── Suricata / NDR alerts ────────────────────────────────────────────────
    let suricata_rows = {
        let rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT src_ip, dst_ip, severity, score, \
             tags, sigma_hits, \
             arrayElement(sigma_hits, 1) as rule_name, \
             src_country, dst_country, toString(timestamp) as timestamp, \
             correlation_status \
             FROM {}.ndr_hits WHERE community_id = '{}' ORDER BY timestamp DESC",
            db, community_id
        )).await;
        fill_rule_names(rows, &http, &ch_url, &ch_user, &ch_pass, &db, &community_id).await
    };

    let suricata_json = json!({
        "source": "suricata_alerts",
        "community_id": community_id,
        "alerts": suricata_rows
    });

    let sigma_rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT severity, tags, sigma_hits, \
         toString(timestamp) as timestamp \
         FROM {}.ndr_hits WHERE community_id = '{}' AND notEmpty(sigma_hits)",
        db, community_id
    )).await;

    let sigma_json = json!({
        "source": "sigma",
        "community_id": community_id,
        "matches": sigma_rows
    });

    // ── Threat intel — permanent IOC hit log (per-tenant ioc_hits) ──────────
    // Querying the immutable table written at detection time by the engine.
    let checked_ips: Vec<&str> = [src_ip.as_str(), dst_ip.as_str()]
        .into_iter().filter(|s| !s.is_empty()).collect();

    // Historical matches for this specific flow (community_id) — per-tenant DB
    let ioc_hits_rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT toString(timestamp) as timestamp, src_ip, dst_ip, \
         matched_ip, ioc_type, feed_source \
         FROM {}.ioc_hits \
         WHERE community_id = '{}' \
         ORDER BY timestamp ASC LIMIT 50",
        db, community_id.replace('\'', "\\'")
    )).await;

    let threat_intel_json = json!({
        "matches": ioc_hits_rows,
        "checked_ips": checked_ips
    });

    // ── Related alerts (same src_ip ±30 min) ─────────────────────────────────
    let related_rows = if !src_ip.is_empty() {
        query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT community_id, severity, src_ip, dst_ip, \
             toString(tags) as tags, toString(timestamp) as timestamp \
             FROM {}.ndr_hits \
             WHERE src_ip = '{}' AND community_id != '{}' \
             AND timestamp BETWEEN \
                 parseDateTimeBestEffort('{}') - INTERVAL 30 MINUTE \
                 AND parseDateTimeBestEffort('{}') + INTERVAL 30 MINUTE \
             ORDER BY timestamp ASC LIMIT 20",
            db, src_ip, community_id, alert_time, alert_time
        )).await
    } else { json!([]) };

    let related_json = json!({
        "community_id": community_id,
        "src_ip": src_ip,
        "window_minutes": 30,
        "alerts": related_rows
    });

    // ── Derive highest severity from suricata rows + sigma rows ──────────────
    // alert_obj["severity"] may be "UNKNOWN" (set before IDS data arrived);
    // always elevate to the highest confirmed severity across all sources.
    fn sev_rank(s: &str) -> u8 {
        match s { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1, _ => 0 }
    }
    let mut best_sev = alert_obj["severity"].as_str().unwrap_or("UNKNOWN").to_string();
    for row in suricata_rows.as_array().unwrap_or(&vec![]) {
        let s = row["severity"].as_str().unwrap_or("");
        if sev_rank(s) > sev_rank(&best_sev) { best_sev = s.to_string(); }
    }
    for row in sigma_rows.as_array().unwrap_or(&vec![]) {
        let s = row["severity"].as_str().unwrap_or("");
        if sev_rank(s) > sev_rank(&best_sev) { best_sev = s.to_string(); }
    }
    if let Some(obj) = alert_obj.as_object_mut() {
        obj.insert("severity".to_string(), json!(best_sev));
    }

    // ── Attack summary ────────────────────────────────────────────────────────
    let now = chrono::Utc::now().to_rfc3339();
    let ioc_hits_arr = ioc_hits_rows.as_array().cloned().unwrap_or_default();
    let attack_summary = build_attack_summary(
        community_id, &alert_obj, &suricata_rows, &Value::Array(ioc_hits_arr),
        &related_rows, false, &now, resolves_to_target, ssl_self_signed,
        total_files, &http_user_agent, total_anomalies,
    );

    json!({
        "attack_summary":    attack_summary,
        "alert":             alert_obj,
        "zeek_conn":         zeek_conn_json,
        "zeek_dns":          zeek_dns_json,
        "zeek_http":         zeek_http_json,
        "zeek_ssl":          zeek_ssl_json,
        "agent_z_files":     zeek_files_json,
        "agent_z_weird":     zeek_weird_json,
        "suricata_dns":      suricata_dns_json,
        "suricata_http":     suricata_http_json,
        "suricata_tls":      suricata_tls_json,
        "suricata_files":    suricata_files_json,
        "suricata_anomaly":  suricata_anomaly_json,
        "suricata_alerts":   suricata_json,
        "sigma_matches":     sigma_json,
        "threat_intel":      threat_intel_json,
        "related_alerts":    related_json
    })
}

/// Build a ZIP evidence bundle for a given community_id.
/// Returns (zip_bytes, sha256_hex, manifest).
pub async fn build_evidence_bundle(
    opensearch_url: &str,
    arkime_url: &str,
    arkime_pass: &str,
    community_id: &str,
    alert_json: Value,
    tenant_id: &str,
    pcap_file_path: Option<String>,
) -> anyhow::Result<(Vec<u8>, String, Value)> {
    build_evidence_bundle_inner(
        opensearch_url, arkime_url, arkime_pass,
        community_id, alert_json, tenant_id, pcap_file_path,
        None, None,
    ).await
}

/// Same as build_evidence_bundle but with fixed bundle_id and created_at for
/// deterministic rebuild — used by verify so the ZIP hash matches the original.
#[allow(dead_code)]
pub async fn build_evidence_bundle_for_verify(
    opensearch_url: &str,
    arkime_url: &str,
    arkime_pass: &str,
    community_id: &str,
    alert_json: Value,
    tenant_id: &str,
    pcap_file_path: Option<String>,
    bundle_id: &str,
    created_at: &str,
) -> anyhow::Result<(Vec<u8>, String, Value)> {
    build_evidence_bundle_inner(
        opensearch_url, arkime_url, arkime_pass,
        community_id, alert_json, tenant_id, pcap_file_path,
        Some(bundle_id), Some(created_at),
    ).await
}

async fn build_evidence_bundle_inner(
    opensearch_url: &str,
    arkime_url: &str,
    arkime_pass: &str,
    community_id: &str,
    alert_json: Value,
    tenant_id: &str,
    pcap_file_path: Option<String>,
    fixed_bundle_id: Option<&str>,
    fixed_created_at: Option<&str>,
) -> anyhow::Result<(Vec<u8>, String, Value)> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let ch_url  = std::env::var("CLICKHOUSE_URL")
        .unwrap_or_else(|_| "http://localhost:8123".to_string());
    let ch_user = std::env::var("CLICKHOUSE_USER")
        .unwrap_or_else(|_| "ndr".to_string());
    // No fallback here on purpose: a missing env var used to silently
    // degrade to a hardcoded, well-known password ("ndr123") instead of
    // failing loudly, which would have quietly used a weak credential in
    // any deployment where this var wasn't wired up correctly.
    let ch_pass = std::env::var("CLICKHOUSE_PASSWORD")
        .context("CLICKHOUSE_PASSWORD must be set")?;

    let db = tenant_db(tenant_id);

    let alert_time = alert_json["timestamp"]
        .as_str()
        .or_else(|| alert_json["auto_captured_at"].as_str())
        .unwrap_or("1970-01-01T00:00:00Z")
        .to_string();

    // ── 1. Session metadata from OpenSearch ──────────────────────────────────
    let session_meta: Value = if !opensearch_url.is_empty() {
        let os_result: Option<Value> = async {
            let resp = http.post(format!("{}/arkime_sessions3-*/_search", opensearch_url))
                .json(&json!({
                    "query": { "term": { "network.community_id": community_id } },
                    "size": 1
                }))
                .send().await.ok()?
                .json::<Value>().await.ok()?;
            Some(resp)
        }.await;

        let hit = os_result
            .as_ref()
            .and_then(|v| v["hits"]["hits"].as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(json!({}));

        json!({
            "arkime_session_id": hit["_id"],
            "index": hit["_index"],
            "source": hit["_source"],
            "community_id": community_id,
            "query_source": "opensearch"
        })
    } else {
        json!({
            "community_id": community_id,
            "query_source": "pcap_sessions",
            "note": "session metadata from uploaded PCAP index"
        })
    };

    // Extract src/dst IPs — prefer alert_json, fall back to session_metadata
    let src_ip = {
        let from_alert = alert_json["src_ip"].as_str().unwrap_or("").to_string();
        if !from_alert.is_empty() { from_alert }
        else { session_meta["source"]["source"]["ip"].as_str().unwrap_or("").to_string() }
    };
    let dst_ip = {
        let from_alert = alert_json["dst_ip"].as_str().unwrap_or("").to_string();
        if !from_alert.is_empty() { from_alert }
        else { session_meta["source"]["destination"]["ip"].as_str().unwrap_or("").to_string() }
    };
    let src_port = alert_json["src_port"]
        .as_u64()
        .unwrap_or_else(|| session_meta["source"]["source"]["port"].as_u64().unwrap_or(0));
    let dst_port = alert_json["dst_port"]
        .as_u64()
        .unwrap_or_else(|| session_meta["source"]["destination"]["port"].as_u64().unwrap_or(0));
    let proto = session_meta["source"]["protocol"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("tcp")
        .to_string();

    let mut alert_json = {
        let mut v = alert_json.clone();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("src_ip".into(), json!(src_ip));
            obj.insert("dst_ip".into(), json!(dst_ip));
            obj.insert("src_port".into(), json!(src_port));
            obj.insert("dst_port".into(), json!(dst_port));
            obj.insert("proto".into(), json!(proto));
            if !session_meta["source"].is_null() {
                let s = &session_meta["source"];
                obj.insert("user_agent".into(), json!(
                    s["http"]["useragent"].as_array()
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                ));
                obj.insert("bytes_total".into(),   json!(s["network"]["bytes"]));
                obj.insert("packets_total".into(), json!(s["network"]["packets"]));
            }
        }
        v
    };

    // ── 2. PCAP bytes ─────────────────────────────────────────────────────────
    let arkime_session_id = session_meta["arkime_session_id"].as_str().unwrap_or("");
    let arkime_node = session_meta["source"]["node"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let pcap_bytes: Vec<u8> = if let Some(ref path) = pcap_file_path {
        tokio::fs::read(path).await.unwrap_or_default()
    } else if !arkime_session_id.is_empty() && !arkime_url.is_empty() {
        async {
            // Arkime requires the node name in the URL; without it the viewer
            // returns its HTML page with a 200 status instead of PCAP data.
            let url = if arkime_node.is_empty() {
                format!("{}/api/session/{}/pcap", arkime_url, arkime_session_id)
            } else {
                format!("{}/api/session/{}/{}/pcap", arkime_url, arkime_node, arkime_session_id)
            };
            let resp = http.get(&url)
                .basic_auth("admin", Some(arkime_pass))
                .send().await.ok()?;
            let ct = resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if ct.contains("html") { return None; }
            let bytes = resp.bytes().await.ok()?;
            // Validate PCAP magic number (d4 c3 b2 a1 or a1 b2 c3 d4)
            if bytes.len() < 4 { return None; }
            let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if magic != 0xa1b2_c3d4 && magic != 0xd4c3_b2a1 && magic != 0x0a0d_0d0a {
                return None;
            }
            Some(bytes.to_vec())
        }.await.unwrap_or_default()
    } else {
        vec![]
    };

    // ── 3. Zeek conn.log record ───────────────────────────────────────────────
    let zeek_conn_rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT src_ip, dst_ip, src_port, dst_port, proto, event_type, \
         toString(timestamp) as timestamp, community_id, source, raw \
         FROM {}.ndr_events \
         WHERE community_id = '{}' AND source = 'agent-z' \
         ORDER BY timestamp DESC LIMIT 1",
        db, community_id
    )).await;

    // Extract Zeek uid from conn record — used to join dns/http/ssl/files/weird logs
    let uid: String = zeek_conn_rows.as_array()
        .and_then(|a| a.first())
        .and_then(|r| r["raw"].as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v["uid"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| community_id.to_string());

    let zeek_conn_json = json!({
        "source": "agent-z-conn",
        "community_id": community_id,
        "uid": uid,
        "record": zeek_conn_rows.as_array().and_then(|a| a.first()).cloned().unwrap_or(json!(null))
    });

    // ── 3a. Zeek DNS (uid join) ───────────────────────────────────────────────
    let raw_dns = query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, &uid, "dns", 20).await;

    let zeek_dns_events: Vec<Value> = raw_dns.iter().map(|raw| {
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        json!({
            "uid":        raw["uid"],
            "timestamp":  unix_to_iso(ts),
            "src_ip":     raw["id.orig_h"],
            "dns_server": raw["id.resp_h"],
            "query":      raw["query"],
            "answers":    raw["answers"],
            "ttls":       raw["TTLs"],
            "rcode":      raw["rcode_name"],
            "opcode":     raw["opcode_name"],
            "trans_id":   raw["trans_id"],
            "proto":      raw["proto"],
            "rejected":   raw["rejected"],
            "flags": {
                "AA": raw["AA"],
                "RA": raw["RA"],
                "RD": raw["RD"],
                "TC": raw["TC"]
            }
        })
    }).collect();

    let resolves_to_target = zeek_dns_events.iter().any(|e| {
        e["answers"].as_array()
            .map(|a| a.iter().any(|ans| ans.as_str() == Some(dst_ip.as_str())))
            .unwrap_or(false)
    });

    let zeek_dns_json = json!({
        "queries": zeek_dns_events,
        "total": zeek_dns_events.len(),
        "resolves_to_target_ip": resolves_to_target,
        "uid": uid
    });

    // ── 3b. Zeek HTTP (uid join) ──────────────────────────────────────────────
    let raw_http = query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, &uid, "http", 20).await;

    let zeek_http_requests: Vec<Value> = raw_http.iter().map(|raw| {
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        let host = raw["host"].as_str().filter(|s| !s.is_empty() && *s != "-").unwrap_or("");
        let uri  = raw["uri"].as_str().filter(|s| !s.is_empty() && *s != "-").unwrap_or("/");
        // Zeek sees asymmetric traffic (responses only) so host/method/uri may be absent.
        // Fall back to the responder IP so full_url is at least navigable.
        let resp_ip   = raw["id.resp_h"].as_str().unwrap_or("");
        let resp_port = raw["id.resp_p"].as_u64().unwrap_or(80);
        let display_host = if !host.is_empty() {
            host.to_string()
        } else if !resp_ip.is_empty() {
            if resp_port == 80 { resp_ip.to_string() } else { format!("{}:{}", resp_ip, resp_port) }
        } else {
            String::new()
        };
        json!({
            "timestamp":      unix_to_iso(ts),
            "method":         raw["method"],
            "host":           display_host,
            "uri":            uri,
            "full_url":       format!("http://{}{}", display_host, uri),
            "user_agent":     raw["user_agent"],
            "status_code":    raw["status_code"],
            "content_type":   raw["resp_mime_types"],
            "bytes_uploaded":   raw["request_body_len"],
            "bytes_downloaded": raw["response_body_len"],
            "referrer":       raw["referrer"],
            "http_version":   raw["version"],
            "src_ip":         raw["id.orig_h"],
            "dst_ip":         raw["id.resp_h"],
            "dst_port":       raw["id.resp_p"]
        })
    }).collect();

    // Zeek only sees server responses so user_agent is absent; fall back to Arkime session UA.
    let http_user_agent = zeek_http_requests.first()
        .and_then(|r| r["user_agent"].as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| alert_json["user_agent"].as_str().unwrap_or("").to_string());

    let zeek_http_json = json!({
        "requests": zeek_http_requests,
        "total": zeek_http_requests.len(),
        "uid": uid
    });

    // ── 3c. Zeek SSL (uid join) ───────────────────────────────────────────────
    let raw_ssl = query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, &uid, "ssl", 10).await;

    let zeek_ssl_connections: Vec<Value> = raw_ssl.iter().map(|raw| {
        let issuer  = raw["issuer"].as_str().unwrap_or("");
        let subject = raw["subject"].as_str().unwrap_or("");
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        json!({
            "timestamp":         unix_to_iso(ts),
            "server_name":       raw["server_name"],
            "subject":           subject,
            "issuer":            issuer,
            "validation_status": raw["validation_status"],
            "is_valid":          raw["validation_status"].as_str() == Some("ok"),
            "self_signed":       !issuer.is_empty() && issuer == subject,
            "cipher":            raw["cipher"],
            "tls_version":       raw["version"],
            "resumed":           raw["resumed"],
            "established":       raw["established"],
            "ja3":               raw["ja3"],
            "ja3s":              raw["ja3s"]
        })
    }).collect();

    let ssl_self_signed = zeek_ssl_connections.iter()
        .any(|c| c["self_signed"].as_bool().unwrap_or(false));

    let zeek_ssl_json = json!({
        "connections": zeek_ssl_connections,
        "total": zeek_ssl_connections.len(),
        "any_self_signed": ssl_self_signed,
        "uid": uid
    });

    // ── 3d. Zeek Files (uid join) ─────────────────────────────────────────────
    let raw_files = query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, &uid, "files", 20).await;

    let zeek_files_list: Vec<Value> = raw_files.iter().map(|raw| {
        let sha256 = raw["sha256"].as_str().unwrap_or("");
        let vt_link = if !sha256.is_empty() {
            format!("https://www.virustotal.com/gui/file/{}", sha256)
        } else {
            String::new()
        };
        let is_orig = raw["is_orig"].as_bool().unwrap_or(false);
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        json!({
            "timestamp":        unix_to_iso(ts),
            "fuid":             raw["fuid"],
            "filename":         raw["filename"],
            "mime_type":        raw["mime_type"],
            "md5":              raw["md5"],
            "sha1":             raw["sha1"],
            "sha256":           sha256,
            "total_bytes":      raw["total_bytes"],
            "seen_bytes":       raw["seen_bytes"],
            "direction":        if is_orig { "upload" } else { "download" },
            "source_protocol":  raw["source"],
            "extracted":        raw["extracted"],
            "virustotal_link":  vt_link
        })
    }).collect();

    let zeek_files_json = json!({
        "files": zeek_files_list,
        "total": zeek_files_list.len(),
        "uid": uid
    });

    // ── 3e. Zeek Weird / anomalies (uid join) ─────────────────────────────────
    let raw_weird = query_raw_events(&http, &ch_url, &ch_user, &ch_pass, &db, &uid, "weird", 20).await;

    let zeek_weird_events: Vec<Value> = raw_weird.iter().map(|raw| {
        let ts = raw["ts"].as_f64().unwrap_or(0.0);
        json!({
            "timestamp":  unix_to_iso(ts),
            "weird_type": raw["name"],
            "detail":     raw["addl"],
            "src_ip":     raw["id.orig_h"],
            "dst_ip":     raw["id.resp_h"],
            "notice":     raw["notice"],
            "peer":       raw["peer"]
        })
    }).collect();

    let zeek_weird_json = json!({
        "events": zeek_weird_events,
        "total": zeek_weird_events.len(),
        "uid": uid
    });

    // ── 4. Suricata / NDR alerts ──────────────────────────────────────────────
    let suricata_rows = {
        let rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT src_ip, dst_ip, severity, score, \
             tags, sigma_hits, \
             arrayElement(sigma_hits, 1) as rule_name, \
             src_country, dst_country, \
             toString(timestamp) as timestamp, \
             correlation_status \
             FROM {}.ndr_hits \
             WHERE community_id = '{}' \
             ORDER BY timestamp DESC",
            db, community_id
        )).await;
        fill_rule_names(rows, &http, &ch_url, &ch_user, &ch_pass, &db, &community_id).await
    };

    let suricata_json = json!({
        "source": "suricata_alerts",
        "community_id": community_id,
        "alerts": suricata_rows
    });

    // ── 5. SIGMA matches ──────────────────────────────────────────────────────
    let sigma_rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT severity, tags, sigma_hits, \
         toString(timestamp) as timestamp \
         FROM {}.ndr_hits \
         WHERE community_id = '{}' \
         AND notEmpty(sigma_hits) \
         ORDER BY timestamp DESC",
        db, community_id
    )).await;

    let sigma_json = json!({
        "source": "sigma",
        "community_id": community_id,
        "matches": sigma_rows
    });

    // ── 6. Threat intel ───────────────────────────────────────────────────────
    let checked_ips: Vec<&str> = [src_ip.as_str(), dst_ip.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();

    let ioc_rows = if !checked_ips.is_empty() {
        let ip_list = checked_ips.iter()
            .map(|ip| format!("'{}'", ip.replace('\'', "")))
            .collect::<Vec<_>>().join(", ");
        query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT ioc_value, ioc_type, confidence, tags, description, \
             toString(first_seen) as first_seen, toString(last_seen) as last_seen \
             FROM ndr.shared_iocs WHERE ioc_value IN ({}) LIMIT 20", ip_list
        )).await
    } else { json!([]) };

    let ti_rows = if !checked_ips.is_empty() {
        let ip_list = checked_ips.iter()
            .map(|ip| format!("'{}'", ip.replace('\'', "")))
            .collect::<Vec<_>>().join(", ");
        query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT ioc_value, attack_type, severity, source, description \
             FROM ndr.threat_intel WHERE ioc_value IN ({}) LIMIT 10", ip_list
        )).await
    } else { json!([]) };

    let all_intel: Vec<Value> = {
        let mut v: Vec<Value> = vec![];
        if let Some(arr) = ioc_rows.as_array() { v.extend(arr.clone()); }
        if let Some(arr) = ti_rows.as_array()  { v.extend(arr.clone()); }
        v
    };

    let threat_intel_json = json!({
        "matches": all_intel,
        "checked_ips": checked_ips
    });

    // ── 7. Related alerts (same src_ip ±30 min) ───────────────────────────────
    let related_rows = if !src_ip.is_empty() {
        query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT community_id, severity, src_ip, dst_ip, \
             toString(tags) as tags, toString(timestamp) as timestamp \
             FROM {}.ndr_hits \
             WHERE src_ip = '{}' \
             AND timestamp BETWEEN \
                 parseDateTimeBestEffort('{}') - INTERVAL 30 MINUTE \
                 AND parseDateTimeBestEffort('{}') + INTERVAL 30 MINUTE \
             AND community_id != '{}' \
             ORDER BY timestamp ASC LIMIT 20",
            db, src_ip, alert_time, alert_time, community_id
        )).await
    } else { json!([]) };

    let related_json = json!({
        "community_id": community_id,
        "src_ip": src_ip,
        "window_minutes": 30,
        "alerts": related_rows
    });

    // ── 8. Attack summary ─────────────────────────────────────────────────────
    // fixed_created_at is set during verify-rebuild so generated_at and
    // manifest.created_at are identical to the original → deterministic ZIP hash.
    let now = fixed_created_at
        .map(|s| s.to_string())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let pcap_captured = !pcap_bytes.is_empty();

    // Elevate severity to highest confirmed across suricata rows + sigma rows
    fn sev_rank2(s: &str) -> u8 {
        match s { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1, _ => 0 }
    }
    let mut best_sev2 = alert_json["severity"].as_str().unwrap_or("UNKNOWN").to_string();
    for row in suricata_rows.as_array().unwrap_or(&vec![]) {
        let s = row["severity"].as_str().unwrap_or("");
        if sev_rank2(s) > sev_rank2(&best_sev2) { best_sev2 = s.to_string(); }
    }
    for row in sigma_rows.as_array().unwrap_or(&vec![]) {
        let s = row["severity"].as_str().unwrap_or("");
        if sev_rank2(s) > sev_rank2(&best_sev2) { best_sev2 = s.to_string(); }
    }
    if let Some(obj) = alert_json.as_object_mut() {
        obj.insert("severity".to_string(), json!(best_sev2));
    }

    let attack_summary = build_attack_summary(
        community_id,
        &alert_json,
        &suricata_rows,
        &Value::Array(all_intel.clone()),
        &related_rows,
        pcap_captured,
        &now,
        resolves_to_target,
        ssl_self_signed,
        zeek_files_list.len(),
        &http_user_agent,
        zeek_weird_events.len(),
    );

    // ── 9. Serialise all files ────────────────────────────────────────────────
    let alert_str        = serde_json::to_string_pretty(&alert_json).unwrap_or_default();
    let session_str      = serde_json::to_string_pretty(&session_meta).unwrap_or_default();
    let zeek_conn_str    = serde_json::to_string_pretty(&zeek_conn_json).unwrap_or_default();
    let zeek_dns_str     = serde_json::to_string_pretty(&zeek_dns_json).unwrap_or_default();
    let zeek_http_str    = serde_json::to_string_pretty(&zeek_http_json).unwrap_or_default();
    let zeek_ssl_str     = serde_json::to_string_pretty(&zeek_ssl_json).unwrap_or_default();
    let zeek_files_str   = serde_json::to_string_pretty(&zeek_files_json).unwrap_or_default();
    let zeek_weird_str   = serde_json::to_string_pretty(&zeek_weird_json).unwrap_or_default();
    let suricata_str     = serde_json::to_string_pretty(&suricata_json).unwrap_or_default();
    let sigma_str        = serde_json::to_string_pretty(&sigma_json).unwrap_or_default();
    let intel_str        = serde_json::to_string_pretty(&threat_intel_json).unwrap_or_default();
    let related_str      = serde_json::to_string_pretty(&related_json).unwrap_or_default();
    let attack_str       = serde_json::to_string_pretty(&attack_summary).unwrap_or_default();

    // ── 10. Build enhanced manifest ───────────────────────────────────────────
    let bundle_id = fixed_bundle_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let suricata_count = suricata_rows.as_array().map(|a| a.len()).unwrap_or(0);
    let highest_severity = suricata_rows.as_array()
        .and_then(|a| a.iter().find(|r| r["severity"].as_str() == Some("CRITICAL")))
        .and_then(|_| Some("CRITICAL"))
        .or_else(|| suricata_rows.as_array()
            .and_then(|a| a.iter().find(|r| r["severity"].as_str() == Some("HIGH")))
            .and_then(|_| Some("HIGH")))
        .unwrap_or(alert_json["severity"].as_str().unwrap_or("UNKNOWN"));

    let manifest = json!({
        "bundle_id": bundle_id,
        "community_id": community_id,
        "tenant_id": tenant_id,
        "created_at": now,
        "ndr_instance": format!("ndr-{}", tenant_id),
        "files": {
            "manifest.json":         { "sha256": "self", "size_bytes": 0 },
            "attack_summary.json":   { "sha256": sha256_of(attack_str.as_bytes()),     "size_bytes": attack_str.len() },
            "alert.json":            { "sha256": sha256_of(alert_str.as_bytes()),       "size_bytes": alert_str.len() },
            "zeek_conn.json":        { "sha256": sha256_of(zeek_conn_str.as_bytes()),   "size_bytes": zeek_conn_str.len() },
            "zeek_dns.json":         { "sha256": sha256_of(zeek_dns_str.as_bytes()),    "size_bytes": zeek_dns_str.len() },
            "zeek_http.json":        { "sha256": sha256_of(zeek_http_str.as_bytes()),   "size_bytes": zeek_http_str.len() },
            "zeek_ssl.json":         { "sha256": sha256_of(zeek_ssl_str.as_bytes()),    "size_bytes": zeek_ssl_str.len() },
            "agent_z_files.json":    { "sha256": sha256_of(zeek_files_str.as_bytes()), "size_bytes": zeek_files_str.len() },
            "agent_z_weird.json":    { "sha256": sha256_of(zeek_weird_str.as_bytes()), "size_bytes": zeek_weird_str.len() },
            "suricata_alerts.json":  { "sha256": sha256_of(suricata_str.as_bytes()),   "size_bytes": suricata_str.len() },
            "sigma_matches.json":    { "sha256": sha256_of(sigma_str.as_bytes()),      "size_bytes": sigma_str.len() },
            "threat_intel.json":     { "sha256": sha256_of(intel_str.as_bytes()),      "size_bytes": intel_str.len() },
            "related_alerts.json":   { "sha256": sha256_of(related_str.as_bytes()),    "size_bytes": related_str.len() },
            "session_metadata.json": { "sha256": sha256_of(session_str.as_bytes()),    "size_bytes": session_str.len() },
            "session.pcap":          {
                "sha256": if pcap_captured { sha256_of(&pcap_bytes) } else { "no_pcap_available".to_string() },
                "size_bytes": pcap_bytes.len()
            }
        },
        "summary": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "severity": highest_severity,
            "rules_fired_count": suricata_count,
            "highest_severity": highest_severity,
            "threat_intel_matches": all_intel.len(),
            "related_alerts_count": related_rows.as_array().map(|a| a.len()).unwrap_or(0),
            "dns_lookup_before_connection": resolves_to_target,
            "ssl_self_signed_cert": ssl_self_signed,
            "files_transferred": zeek_files_list.len(),
            "http_requests": zeek_http_requests.len(),
            "zeek_anomalies": zeek_weird_events.len(),
            "pcap_size_bytes": pcap_bytes.len(),
            "pcap_available": pcap_captured,
            "collection_complete": true
        },
        "chain_of_custody": "This bundle was generated automatically by NDR-Engine. Contents are SHA256 verified. Manifest hash covers all included files."
    });
    let manifest_str = serde_json::to_string_pretty(&manifest).unwrap_or_default();

    // ── 11. Build ZIP (15 files) ──────────────────────────────────────────────
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let opts = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("manifest.json", opts)?;
        zip.write_all(manifest_str.as_bytes())?;

        zip.start_file("attack_summary.json", opts)?;
        zip.write_all(attack_str.as_bytes())?;

        zip.start_file("alert.json", opts)?;
        zip.write_all(alert_str.as_bytes())?;

        zip.start_file("zeek_conn.json", opts)?;
        zip.write_all(zeek_conn_str.as_bytes())?;

        zip.start_file("zeek_dns.json", opts)?;
        zip.write_all(zeek_dns_str.as_bytes())?;

        zip.start_file("zeek_http.json", opts)?;
        zip.write_all(zeek_http_str.as_bytes())?;

        zip.start_file("zeek_ssl.json", opts)?;
        zip.write_all(zeek_ssl_str.as_bytes())?;

        zip.start_file("agent_z_files.json", opts)?;
        zip.write_all(zeek_files_str.as_bytes())?;

        zip.start_file("agent_z_weird.json", opts)?;
        zip.write_all(zeek_weird_str.as_bytes())?;

        zip.start_file("suricata_alerts.json", opts)?;
        zip.write_all(suricata_str.as_bytes())?;

        zip.start_file("sigma_matches.json", opts)?;
        zip.write_all(sigma_str.as_bytes())?;

        zip.start_file("threat_intel.json", opts)?;
        zip.write_all(intel_str.as_bytes())?;

        zip.start_file("related_alerts.json", opts)?;
        zip.write_all(related_str.as_bytes())?;

        zip.start_file("session_metadata.json", opts)?;
        zip.write_all(session_str.as_bytes())?;

        if pcap_captured {
            zip.start_file("session.pcap", opts)?;
            zip.write_all(&pcap_bytes)?;
        }

        zip.finish()?;
    }

    // ── 12. Bundle-level integrity hash ──────────────────────────────────────
    let bundle_sha256 = sha256_of(&buf);

    Ok((buf, bundle_sha256, manifest))
}

/// Verify a stored evidence bundle against its logged SHA256.
#[allow(dead_code)]
pub async fn verify_bundle_integrity(
    file_path: &str,
    stored_sha256: &str,
) -> (bool, String) {
    match tokio::fs::read(file_path).await {
        Ok(bytes) => {
            let computed = sha256_of(&bytes);
            let matches = computed == stored_sha256;
            (matches, computed)
        }
        Err(e) => (false, format!("file_read_error: {}", e))
    }
}
