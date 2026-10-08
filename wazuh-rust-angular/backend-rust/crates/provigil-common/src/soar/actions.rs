use crate::soar::{SoarContext, SoarNativePlaybook, SoarPlaybookRun, SoarStore, ActiveBlock};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;
use tracing::info;
use uuid::Uuid;
use chrono::Utc;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use reqwest::Client;

fn is_routable(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(addr) => !addr.is_loopback() && match addr {
            IpAddr::V4(v4) => !v4.is_private() && !v4.is_link_local() &&
                              !v4.is_broadcast() && !v4.is_multicast() && !v4.is_unspecified(),
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_multicast() && !v6.is_unspecified(),
        },
        Err(_) => false,
    }
}

#[allow(unused_assignments)]
pub async fn execute_action(
    store: &dyn SoarStore,
    pb: &SoarNativePlaybook,
    ctx: &SoarContext,
) {
    let config: Value = serde_json::from_str(&pb.action_config).unwrap_or(json!({}));

    let src = ctx.src_ip.as_str();
    let dst = ctx.dst_ip.as_str();

    let mut status = "failed".to_string();
    let mut detail = String::new();

    match pb.action_type.as_str() {
        "slack" | "discord" => {
            if let Some(url) = config["webhook_url"].as_str() {
                let msg = json!({
                    "text": format!(
                        "🚨 *NDR Native Alert* | *{}*\n\
                        Source: `{}` → Dest: `{}`\n\
                        Score: *{}/100* | Threat Intel: {}\n\
                        Tags: {}",
                        ctx.severity,
                        src, dst,
                        ctx.score as u32,
                        if ctx.is_malicious { "⚠️ YES" } else { "No" },
                        ctx.tags.join(", ")
                    )
                });
                match Client::new().post(url).json(&msg).timeout(Duration::from_secs(5)).send().await {
                    Ok(r) if r.status().is_success() => {
                        status = "success".to_string();
                        detail = "Slack/Discord webhook sent".to_string();
                    }
                    Ok(r) => detail = format!("HTTP error: {}", r.status()),
                    Err(e) => detail = format!("Request failed: {}", e),
                }
            } else {
                detail = "Missing webhook_url".to_string();
            }
        }
        "teams" => {
            if let Some(url) = config["webhook_url"].as_str() {
                let msg = json!({
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": "NDR Native Alert",
                    "themeColor": "FF0000",
                    "title": format!("🚨 NDR Alert: {}", ctx.severity),
                    "sections": [{
                        "facts": [
                            {"name": "Source", "value": src},
                            {"name": "Destination", "value": dst},
                            {"name": "Score", "value": format!("{}/100", ctx.score as u32)},
                            {"name": "Tags", "value": ctx.tags.join(", ")}
                        ]
                    }]
                });
                match Client::new().post(url).json(&msg).timeout(Duration::from_secs(5)).send().await {
                    Ok(r) if r.status().is_success() => {
                        status = "success".to_string();
                        detail = "Teams webhook sent".to_string();
                    }
                    Ok(r) => detail = format!("HTTP error: {}", r.status()),
                    Err(e) => detail = format!("Request failed: {}", e),
                }
            } else {
                detail = "Missing webhook_url".to_string();
            }
        }
        "webhook" => {
            if let Some(url) = config["webhook_url"].as_str() {
                let msg = json!({
                    "alert_type": "ndr_threat",
                    "src_ip": src,
                    "dst_ip": dst,
                    "score": ctx.score,
                    "severity": ctx.severity,
                    "threat_intel": ctx.is_malicious,
                    "tags": ctx.tags,
                    "timestamp": Utc::now().to_rfc3339(),
                });
                match Client::new().post(url).json(&msg).timeout(Duration::from_secs(5)).send().await {
                    Ok(r) if r.status().is_success() => {
                        status = "success".to_string();
                        detail = "Webhook sent".to_string();
                    }
                    Ok(r) => detail = format!("HTTP error: {}", r.status()),
                    Err(e) => detail = format!("Request failed: {}", e),
                }
            } else {
                detail = "Missing webhook_url".to_string();
            }
        }
        "email" => {
            let integrations = store.soar_get_integrations(&pb.tenant_id).await;
            let mut smtp_config = None;
            for i in integrations {
                if i["type"].as_str().unwrap_or("") == "smtp" && i["enabled"] == true {
                    smtp_config = Some(i["config"].clone());
                    break;
                }
            }

            if let Some(sc) = smtp_config {
                let to_addr = config["to_addr"].as_str()
                    .or(sc["to_addr"].as_str())
                    .unwrap_or("");
                let from_addr = sc["from_addr"].as_str().unwrap_or("ndr@localhost");
                let host = sc["smtp_host"].as_str().unwrap_or("localhost");
                let port = sc["smtp_port"].as_u64()
                    .or_else(|| sc["smtp_port"].as_str().and_then(|s| s.parse().ok()))
                    .unwrap_or(587) as u16;
                let user = sc["smtp_user"].as_str().unwrap_or("");
                let pass = sc["smtp_pass"].as_str().unwrap_or("");

                let email = match (|| -> Option<lettre::Message> {
                    let f = from_addr.parse().ok()?;
                    let t = to_addr.parse().ok()?;

                    use lettre::message::{MultiPart, SinglePart, header::ContentType, header::ContentDisposition, header::ContentId};

                    let html_body = format!(
                        r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #0d1420; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: linear-gradient(180deg, #ffffff 0%, #eefbf3 60%, #0d1420 100%); padding: 32px 24px; border-radius: 8px; text-align: center; }}
        .header {{ margin-bottom: 24px; }}
        .title {{ margin: 0; font-size: 24px; font-weight: 800; color: #064e3b; letter-spacing: 0.08em; text-transform: uppercase; }}
        .tagline {{ margin: 4px 0 0 0; font-size: 10px; font-weight: 700; color: #166534; letter-spacing: 0.28em; text-transform: uppercase; }}
        .alert-box {{ background: rgba(255, 255, 255, 0.95); border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 8px; padding: 24px; margin-bottom: 32px; text-align: left; color: #0f172a; box-shadow: 0 4px 12px rgba(34,197,94,0.05); }}
        .alert-title {{ margin-top: 0; color: #b91c1c; font-size: 18px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px; margin-bottom: 16px; }}
        .detail {{ margin: 8px 0; font-size: 14px; line-height: 1.5; }}
        .label {{ font-weight: 700; color: #475569; width: 120px; display: inline-block; }}
        .badge-container {{ display: inline-flex; align-items: center; justify-content: center; gap: 8px; background: rgba(255, 255, 255, 0.7); border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 6px; padding: 8px 14px; box-shadow: 0 4px 12px rgba(34,197,94,0.05); }}
        .badge-text {{ color: #0f172a; font-size: 9px; font-weight: 700; letter-spacing: 0.15em; text-transform: uppercase; opacity: 0.85; margin: 0; padding-right: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">PromaAlpha</h1>
            <p class="tagline">NDR Platform</p>
        </div>
        <div class="alert-box">
            <h2 class="alert-title">🚨 NDR Alert: {}</h2>
            <div class="detail"><span class="label">Source IP:</span> {}</div>
            <div class="detail"><span class="label">Dest IP:</span> {}</div>
            <div class="detail"><span class="label">Risk Score:</span> {}/100</div>
            <div class="detail"><span class="label">Threat Intel:</span> {}</div>
            <div class="detail"><span class="label">Tags:</span> {}</div>
        </div>
        <div class="badge-container">
            <span class="badge-text">powered by</span>
            <img src="cid:promasecure_logo" alt="PromaSecure" style="height: 24px;" />
        </div>
    </div>
</body>
</html>"#,
                        ctx.severity, src, dst, ctx.score as u32,
                        if ctx.is_malicious { "⚠️ Malicious" } else { "Clean" },
                        if ctx.tags.is_empty() { "None".to_string() } else { ctx.tags.join(", ") }
                    );

                    let logo_part = SinglePart::builder()
                        .header(ContentType::parse("image/png").unwrap())
                        .header(ContentDisposition::inline())
                        .header(ContentId::from("<promasecure_logo>".to_string()))
                        .body(include_bytes!("promasecure.png").to_vec());

                    let multi = MultiPart::related()
                        .singlepart(SinglePart::html(html_body))
                        .singlepart(logo_part);

                    Message::builder()
                        .from(f)
                        .to(t)
                        .subject(format!("PromaAlpha NDR Alert: {}", ctx.severity))
                        .multipart(multi)
                        .ok()
                })() {
                    Some(e) => e,
                    None => {
                        tracing::warn!("SOAR email: invalid address (from='{}', to='{}')", from_addr, to_addr);
                        detail = format!("Invalid email address (from='{}', to='{}')", from_addr, to_addr);
                        return;
                    }
                };

                let mut mailer_builder = SmtpTransport::relay(host)
                    .unwrap_or_else(|_| SmtpTransport::builder_dangerous(host))
                    .port(port);
                if !user.is_empty() {
                    mailer_builder = mailer_builder.credentials(Credentials::new(user.to_string(), pass.to_string()));
                }

                let mailer = mailer_builder.build();
                match mailer.send(&email) {
                    Ok(_) => {
                        status = "success".to_string();
                        detail = "Email sent".to_string();
                    }
                    Err(e) => {
                        detail = format!("SMTP error: {}", e);
                    }
                }
            } else {
                detail = "No active SMTP integration found".to_string();
            }
        }
        "create_case" => {
            let sev_rank = |s: &str| match s { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1, _ => 0 };
            let priority = match ctx.severity.as_str() {
                "CRITICAL" => "P1", "HIGH" => "P2", "MEDIUM" => "P3", _ => "P4",
            };

            if let Some((existing_id, existing_num, existing_sev, _existing_pri)) =
                store.soar_find_open_case(src, dst, &pb.tenant_id).await
            {
                let comment = format!(
                    "[AUTO] {} alert corroborated: {} → {} | Score: {}/100 | Tags: {} | CID: {}",
                    ctx.severity, src, dst,
                    ctx.score as u32,
                    ctx.tags.join(", "),
                    ctx.community_id,
                );
                store.soar_add_comment(&existing_id, "SOAR Engine", &comment, &pb.tenant_id).await;

                if sev_rank(ctx.severity.as_str()) > sev_rank(&existing_sev) {
                    store.soar_escalate_case(&existing_id, ctx.severity.as_str(), priority, &pb.tenant_id).await;
                    status = "success".to_string();
                    detail = format!("Alert grouped into {} — escalated to {}", existing_num, ctx.severity);
                } else {
                    status = "success".to_string();
                    detail = format!("Alert grouped into existing case {}", existing_num);
                }
            } else {
                let case_id = Uuid::new_v4().to_string();
                let case_number = store.soar_next_case_number(&pb.tenant_id).await;
                let title = format!("Automated Case: {} -> {} ({})", src, dst, ctx.severity);
                let description = format!("Playbook {} generated this case.", pb.name);

                match store.soar_create_case(
                    &case_id, &case_number, &title, &description,
                    ctx.severity.as_str(), priority, "New", "",
                    src, dst, &ctx.community_id, &ctx.tags, &pb.tenant_id,
                ).await {
                    Ok(_) => {
                        status = "success".to_string();
                        detail = format!("Case {} ({}) created", case_number, case_id);
                    }
                    Err(e) => {
                        detail = format!("Failed to create case: {}", e);
                    }
                }
            }
        }

        "collect_evidence" => {
            let cid = &ctx.community_id;

            let (pcap_sessions_json, pcap_count) = if pb.tenant_id == "default" {
                let opensearch_url = std::env::var("OPENSEARCH_URL")
                    .unwrap_or_else(|_| "http://localhost:9200".to_string());
                let query = json!({
                    "size": 5,
                    "query": {"term": {"network.community_id": cid}},
                    "_source": ["firstPacket","lastPacket","source.ip","source.port",
                                "destination.ip","destination.port","ipProtocol",
                                "network.bytes","network.packets","node"]
                });
                match Client::new()
                    .post(format!("{}/arkime_sessions3-*/_search", opensearch_url))
                    .json(&query)
                    .timeout(Duration::from_secs(5))
                    .send().await
                {
                    Ok(r) => {
                        let data = r.json::<Value>().await.unwrap_or_default();
                        let count = data["hits"]["total"]["value"].as_u64().unwrap_or(0);
                        (data["hits"]["hits"].clone(), count)
                    }
                    Err(_) => (json!([]), 0),
                }
            } else {
                let sessions = store.soar_get_pcap_sessions(&pb.tenant_id, cid, 5).await;
                let count = sessions.len() as u64;
                (json!(sessions), count)
            };

            let ch_events = store.soar_get_events(cid, &pb.tenant_id).await;

            let evidence = json!({
                "community_id": cid,
                "collected_at": Utc::now().to_rfc3339(),
                "flow": {"src": src, "dst": dst},
                "risk": {"score": ctx.score, "severity": ctx.severity, "tags": ctx.tags},
                "threat_intel": ctx.is_malicious,
                "pcap_sessions": pcap_sessions_json,
                "pcap_total": pcap_count,
                "ndr_events": ch_events,
            });

            let sev_rank = |s: &str| match s { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1, _ => 0 };
            let priority = match ctx.severity.as_str() {
                "CRITICAL" => "P1", "HIGH" => "P2", "MEDIUM" => "P3", _ => "P4",
            };
            let event_count = ch_events.as_array().map(|a| a.len()).unwrap_or(0);

            if let Some((existing_id, existing_num, existing_sev, _existing_pri)) =
                store.soar_find_open_case(src, dst, &pb.tenant_id).await
            {
                let comment = format!(
                    "[AUTO] Evidence collected: {} PCAP sessions, {} NDR events | {} alert | CID: {}",
                    pcap_count, event_count, ctx.severity, cid
                );
                store.soar_add_comment(&existing_id, "SOAR Engine", &comment, &pb.tenant_id).await;
                if sev_rank(ctx.severity.as_str()) > sev_rank(&existing_sev) {
                    store.soar_escalate_case(&existing_id, ctx.severity.as_str(), priority, &pb.tenant_id).await;
                }
                status = "success".to_string();
                detail = format!(
                    "Evidence ({} PCAP, {} events) appended to case {}",
                    pcap_count, event_count, existing_num
                );
            } else {
                let case_id = Uuid::new_v4().to_string();
                let case_number = store.soar_next_case_number(&pb.tenant_id).await;
                let title = format!("Evidence: {} → {} [{}]", src, dst, ctx.severity);
                let description = evidence.to_string();

                match store.soar_create_case(
                    &case_id, &case_number, &title, &description,
                    ctx.severity.as_str(), priority, "In Progress", "",
                    src, dst, cid, &ctx.tags, &pb.tenant_id,
                ).await {
                    Ok(_) => {
                        status = "success".to_string();
                        detail = format!(
                            "Evidence collected: {} PCAP sessions, {} NDR events → Case {}",
                            pcap_count, event_count, case_number
                        );
                    }
                    Err(e) => {
                        detail = format!("Evidence collected but case insert failed: {}", e);
                    }
                }
            }
        }

        "block_ip" => {
            let duration_hours = config["duration_hours"].as_u64().unwrap_or(24);
            let agent_url = std::env::var("NDR_AGENT_URL")
                .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string());

            let src_ip    = src;
            let src_port  = ctx.src_port;
            let dst_ip    = dst;
            let dst_port  = ctx.dst_port;

            if !is_routable(src_ip) {
                detail = format!("block_ip skipped — {} is private/internal", src_ip);
            } else {
                let rst_body = json!({
                    "src_ip": src_ip, "src_port": src_port,
                    "dst_ip": dst_ip, "dst_port": dst_port,
                    "community_id": ctx.community_id, "duration_hours": duration_hours,
                });
                let (rst_ok, expires_at) = match Client::new()
                    .post(format!("{}/agent/block", agent_url))
                    .json(&rst_body).timeout(Duration::from_secs(10)).send().await
                {
                    Ok(r) if r.status().is_success() => {
                        let resp = r.json::<Value>().await.unwrap_or_default();
                        (
                            resp["rst_injected"].as_bool().unwrap_or(false),
                            resp["expires_at"].as_str().unwrap_or("").to_string(),
                        )
                    }
                    _ => (false, Utc::now().to_rfc3339()),
                };

                let (fw_type, fw_rule_id) = {
                    let integrations = store.soar_get_integrations(&pb.tenant_id).await;
                    let fw_integration = integrations.iter().find(|i| {
                        matches!(i["type"].as_str(), Some("pfsense"|"fortinet"|"panos"|"opnsense"|"rest"))
                        && i["enabled"] == json!(true)
                    });
                    if let Some(fw) = fw_integration {
                        let fw_type = fw["type"].as_str().unwrap_or("none").to_string();
                        let fw_cfg  = &fw["config"];
                        let host    = fw_cfg["host"].as_str().unwrap_or("");
                        let result  = crate::soar::firewall::push_block(
                            &fw_type, fw_cfg, src_ip, duration_hours).await;
                        info!("FIREWALL [{}@{}] block {}: {} — {}",
                              fw_type, host, src_ip, result.success, result.message);
                        (fw_type, result.rule_id)
                    } else {
                        ("none".to_string(), String::new())
                    }
                };

                let block_id = Uuid::new_v4().to_string();
                let expires_stored = if expires_at.contains('T') {
                    expires_at.replace('T', " ").trim_end_matches('Z').to_string()
                } else {
                    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
                };
                let block = ActiveBlock {
                    id: block_id.clone(),
                    src_ip: src_ip.to_string(), src_port,
                    dst_ip: dst_ip.to_string(), dst_port,
                    community_id: ctx.community_id.clone(),
                    triggered_by: pb.name.clone(),
                    sensor_id: String::new(),
                    firewall_type: fw_type.clone(),
                    firewall_rule_id: fw_rule_id.clone(),
                    rst_injected: if rst_ok { 1 } else { 0 },
                    duration_hours: duration_hours as u16,
                    expires_at: expires_stored,
                    status: "active".to_string(),
                    reason: format!("Playbook: {}", pb.name),
                    tenant_id: pb.tenant_id.clone(),
                    created_at: Utc::now().to_rfc3339(),
                };
                let _ = store.soar_insert_block(&block).await;

                status = "success".to_string();
                detail = format!(
                    "Block #{} | RST: {} | Firewall: {} | rule: {} | expires: {}",
                    &block_id[..8], rst_ok, fw_type,
                    if fw_rule_id.is_empty() { "none" } else { &fw_rule_id },
                    expires_at
                );
            }
        }

        _ => {
            detail = format!("Unknown action_type: {}", pb.action_type);
        }
    }

    info!("SOAR Action [{}] for Playbook {}: {} - {}", pb.action_type, pb.name, status, detail);

    let run = SoarPlaybookRun {
        id: Uuid::new_v4().to_string(),
        playbook_id: pb.id.clone(),
        playbook_name: pb.name.clone(),
        hit_id: ctx.community_id.clone(),
        status,
        detail,
        created_at: Utc::now().to_rfc3339(),
        tenant_id: pb.tenant_id.clone(),
    };
    let _ = store.soar_insert_run(&run).await;
}
