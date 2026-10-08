// NDR Engine — Firewall API Integration for Active Blocking
// Supports: pfSense (fauxapi/REST), Fortinet FortiGate, Palo Alto PAN-OS, OPNsense, Generic REST
// Each firewall returns a rule_id that is stored in ndr.active_blocks for later revocation.

use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::warn;

pub struct FirewallResult {
    pub success:       bool,
    pub rule_id:       String,
    pub firewall_type: String,
    pub message:       String,
}

impl FirewallResult {
    fn ok(fw: &str, rule_id: impl Into<String>, msg: impl Into<String>) -> Self {
        Self { success: true, rule_id: rule_id.into(), firewall_type: fw.to_string(), message: msg.into() }
    }
    fn err(fw: &str, msg: impl Into<String>) -> Self {
        Self { success: false, rule_id: String::new(), firewall_type: fw.to_string(), message: msg.into() }
    }
}

// ── Public entry points ────────────────────────────────────────────────────

pub async fn push_block(
    fw_type: &str,
    config:  &Value,
    src_ip:  &str,
    duration_hours: u64,
) -> FirewallResult {
    let host    = config["host"].as_str().unwrap_or("");
    let api_key = config["api_key"].as_str().unwrap_or("");

    match fw_type {
        "pfsense"  => pfsense_block(host, api_key, src_ip, duration_hours).await,
        "fortinet" => fortinet_block(host, api_key, config, src_ip).await,
        "panos"    => panos_block(host, api_key, src_ip).await,
        "opnsense" => opnsense_block(host, api_key, config, src_ip).await,
        "rest"     => generic_rest_block(host, api_key, src_ip, duration_hours).await,
        _          => FirewallResult::err(fw_type, "unsupported firewall type"),
    }
}

pub async fn revoke_block(
    fw_type: &str,
    config:  &Value,
    src_ip:  &str,
    rule_id: &str,
) -> bool {
    let host    = config["host"].as_str().unwrap_or("");
    let api_key = config["api_key"].as_str().unwrap_or("");

    match fw_type {
        "pfsense"  => pfsense_revoke(host, api_key, rule_id).await,
        "fortinet" => fortinet_revoke(host, api_key, config, src_ip).await,
        "panos"    => panos_revoke(host, api_key, src_ip).await,
        "opnsense" => opnsense_revoke(host, api_key, config, src_ip).await,
        "rest"     => generic_rest_revoke(host, api_key, src_ip, rule_id).await,
        _          => false,
    }
}

// ── pfSense (REST API v2) ──────────────────────────────────────────────────
// Adds src_ip to the NDR_BLOCK alias. API key goes in X-API-Key header.

async fn pfsense_block(host: &str, api_key: &str, src_ip: &str, _duration_hours: u64) -> FirewallResult {
    let fw = "pfsense";
    let client = insecure_client();

    // Ensure NDR_BLOCK alias exists (idempotent)
    let alias_url = format!("https://{}/api/v2/firewall/alias", host);
    let _ = client
        .post(&alias_url)
        .header("X-API-Key", api_key)
        .json(&json!({"name":"NDR_BLOCK","type":"host","descr":"NDR auto-block","address":[]}))
        .timeout(Duration::from_secs(8))
        .send().await;

    // Add IP to alias
    let entry_url = format!("https://{}/api/v2/firewall/alias/entry", host);
    match client
        .post(&entry_url)
        .header("X-API-Key", api_key)
        .json(&json!({"name":"NDR_BLOCK","address":src_ip}))
        .timeout(Duration::from_secs(8))
        .send().await
    {
        Ok(r) if r.status().is_success() => {
            // Apply changes
            let _ = client.post(format!("https://{}/api/v2/firewall/apply", host))
                .header("X-API-Key", api_key).timeout(Duration::from_secs(5)).send().await;
            FirewallResult::ok(fw, format!("pfsense:NDR_BLOCK:{}", src_ip),
                format!("IP {} added to NDR_BLOCK alias on {}", src_ip, host))
        }
        Ok(r) => {
            warn!("[FIREWALL] pfSense alias entry failed: {}", r.status());
            FirewallResult::err(fw, format!("pfSense error: {}", r.status()))
        }
        Err(e) => FirewallResult::err(fw, format!("pfSense unreachable: {}", e)),
    }
}

async fn pfsense_revoke(host: &str, api_key: &str, rule_id: &str) -> bool {
    // rule_id format: "pfsense:NDR_BLOCK:<ip>"
    let parts: Vec<&str> = rule_id.split(':').collect();
    let ip = parts.get(2).copied().unwrap_or("");
    if ip.is_empty() { return false; }

    let client = insecure_client();
    let url    = format!("https://{}/api/v2/firewall/alias/entry", host);
    match client
        .delete(&url)
        .header("X-API-Key", api_key)
        .json(&json!({"name":"NDR_BLOCK","address":ip}))
        .timeout(Duration::from_secs(8))
        .send().await
    {
        Ok(r) if r.status().is_success() => {
            let _ = client.post(format!("https://{}/api/v2/firewall/apply", host))
                .header("X-API-Key", api_key).timeout(Duration::from_secs(5)).send().await;
            true
        }
        _ => false,
    }
}

// ── Fortinet FortiGate (REST API) ─────────────────────────────────────────
// Creates a named address object, adds it to NDR_BLOCK group, policy blocks group.

async fn fortinet_block(host: &str, api_key: &str, config: &Value, src_ip: &str) -> FirewallResult {
    let fw   = "fortinet";
    let vdom = config["vdom"].as_str().unwrap_or("root");
    let name = format!("NDR_BLOCK_{}", src_ip.replace('.', "_").replace(':', "_"));
    let client = insecure_client();

    let url = format!("https://{}/api/v2/cmdb/firewall/address?vdom={}", host, vdom);
    let body = json!({
        "name": name,
        "type": "ipmask",
        "subnet": format!("{}/32", src_ip),
        "comment": "NDR auto-block"
    });

    match client.post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&body).timeout(Duration::from_secs(8)).send().await
    {
        Ok(r) if r.status().is_success() || r.status().as_u16() == 409 => {
            // Add to NDR_BLOCK group (idempotent)
            let grp_url = format!("https://{}/api/v2/cmdb/firewall/addrgrp/NDR_BLOCK?vdom={}&action=add", host, vdom);
            let _ = client.put(&grp_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&json!({"member":[{"name":&name}]}))
                .timeout(Duration::from_secs(8)).send().await;

            FirewallResult::ok(fw, &name, format!("FortiGate: {} added to NDR_BLOCK group on {}", src_ip, host))
        }
        Ok(r) => FirewallResult::err(fw, format!("FortiGate error: {}", r.status())),
        Err(e) => FirewallResult::err(fw, format!("FortiGate unreachable: {}", e)),
    }
}

async fn fortinet_revoke(host: &str, api_key: &str, config: &Value, src_ip: &str) -> bool {
    let vdom = config["vdom"].as_str().unwrap_or("root");
    let name = format!("NDR_BLOCK_{}", src_ip.replace('.', "_").replace(':', "_"));
    let client = insecure_client();

    let url = format!("https://{}/api/v2/cmdb/firewall/address/{}?vdom={}", host, name, vdom);
    client.delete(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .timeout(Duration::from_secs(8)).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// ── Palo Alto PAN-OS (XML API) ────────────────────────────────────────────
// Adds IP to a dynamic address group tag "NDR_BLOCK". API key in X-API-Key.

async fn panos_block(host: &str, api_key: &str, src_ip: &str) -> FirewallResult {
    let fw     = "panos";
    let client = insecure_client();
    let cmd    = format!(
        "<request><user-id><payload><register><entry ip=\"{}\"><tag><member>NDR_BLOCK</member></tag></entry></register></payload></user-id></request>",
        src_ip
    );
    let url = format!("https://{}/api/?type=op&cmd={}&key={}", host, urlencoding::encode(&cmd), api_key);

    match client.get(&url).timeout(Duration::from_secs(8)).send().await {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            if body.contains("success") {
                FirewallResult::ok(fw, format!("panos:{}", src_ip),
                    format!("PAN-OS: {} tagged NDR_BLOCK on {}", src_ip, host))
            } else {
                FirewallResult::err(fw, format!("PAN-OS response: {}", &body[..body.len().min(120)]))
            }
        }
        Ok(r) => FirewallResult::err(fw, format!("PAN-OS error: {}", r.status())),
        Err(e) => FirewallResult::err(fw, format!("PAN-OS unreachable: {}", e)),
    }
}

async fn panos_revoke(host: &str, api_key: &str, src_ip: &str) -> bool {
    let client = insecure_client();
    let cmd = format!(
        "<request><user-id><payload><unregister><entry ip=\"{}\"><tag><member>NDR_BLOCK</member></tag></entry></unregister></payload></user-id></request>",
        src_ip
    );
    let url = format!("https://{}/api/?type=op&cmd={}&key={}", host, urlencoding::encode(&cmd), api_key);
    client.get(&url).timeout(Duration::from_secs(8)).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// ── OPNsense (REST API) ────────────────────────────────────────────────────
// Adds IP to a firewall alias. api_key = "api_key:api_secret" joined with colon.

async fn opnsense_block(host: &str, api_key: &str, config: &Value, src_ip: &str) -> FirewallResult {
    let fw    = "opnsense";
    let alias = config["alias"].as_str().unwrap_or("NDR_BLOCK");
    let (key, secret) = api_key.split_once(':').unwrap_or((api_key, ""));
    let client = insecure_client();

    let url  = format!("https://{}/api/firewall/alias/addHost/{}", host, alias);
    let body = json!({"address": src_ip});

    match client.post(&url)
        .basic_auth(key, Some(secret))
        .json(&body).timeout(Duration::from_secs(8)).send().await
    {
        Ok(r) if r.status().is_success() => {
            // Apply changes
            let _ = client.post(format!("https://{}/api/firewall/alias/reconfigure", host))
                .basic_auth(key, Some(secret)).timeout(Duration::from_secs(5)).send().await;
            FirewallResult::ok(fw, format!("opnsense:{}:{}", alias, src_ip),
                format!("OPNsense: {} added to alias {} on {}", src_ip, alias, host))
        }
        Ok(r) => FirewallResult::err(fw, format!("OPNsense error: {}", r.status())),
        Err(e) => FirewallResult::err(fw, format!("OPNsense unreachable: {}", e)),
    }
}

async fn opnsense_revoke(host: &str, api_key: &str, config: &Value, src_ip: &str) -> bool {
    let alias = config["alias"].as_str().unwrap_or("NDR_BLOCK");
    let (key, secret) = api_key.split_once(':').unwrap_or((api_key, ""));
    let client = insecure_client();

    let url = format!("https://{}/api/firewall/alias/delHost/{}", host, alias);
    let ok = client.post(&url)
        .basic_auth(key, Some(secret))
        .json(&json!({"address": src_ip}))
        .timeout(Duration::from_secs(8)).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if ok {
        let _ = client.post(format!("https://{}/api/firewall/alias/reconfigure", host))
            .basic_auth(key, Some(secret)).timeout(Duration::from_secs(5)).send().await;
    }
    ok
}

// ── Generic REST webhook ───────────────────────────────────────────────────
// POST {"action":"block","ip":"...","duration_hours":N} to host URL.

async fn generic_rest_block(host: &str, api_key: &str, src_ip: &str, duration_hours: u64) -> FirewallResult {
    let fw     = "rest";
    let client = Client::new();
    let body   = json!({"action":"block","ip":src_ip,"duration_hours":duration_hours});

    match client.post(host)
        .header("X-API-Key", api_key)
        .json(&body).timeout(Duration::from_secs(8)).send().await
    {
        Ok(r) if r.status().is_success() => {
            let resp = r.json::<Value>().await.unwrap_or_default();
            let rule_id = resp["rule_id"].as_str().unwrap_or(src_ip).to_string();
            FirewallResult::ok(fw, rule_id, format!("Generic REST: {} blocked", src_ip))
        }
        Ok(r) => FirewallResult::err(fw, format!("REST error: {}", r.status())),
        Err(e) => FirewallResult::err(fw, format!("REST unreachable: {}", e)),
    }
}

async fn generic_rest_revoke(host: &str, api_key: &str, src_ip: &str, rule_id: &str) -> bool {
    let client = Client::new();
    client.post(host)
        .header("X-API-Key", api_key)
        .json(&json!({"action":"unblock","ip":src_ip,"rule_id":rule_id}))
        .timeout(Duration::from_secs(8)).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// ── Cloud Firewall ─────────────────────────────────────────────────────────
// AWS Security Groups, Azure NSG, GCP VPC firewall deny rules.
// All use CLI subprocesses so no extra SDK crates are needed.

pub async fn push_cloud_deny(
    cloud_type: &str,
    config:     &Value,
    src_ip:     &str,
) -> FirewallResult {
    match cloud_type {
        "aws_sg"    => aws_sg_deny(config, src_ip).await,
        "azure_nsg" => azure_nsg_deny(config, src_ip).await,
        "gcp_vpc"   => gcp_vpc_deny(config, src_ip).await,
        _           => FirewallResult::err(cloud_type, "unsupported cloud type"),
    }
}

pub async fn revoke_cloud_deny(
    cloud_type: &str,
    config:     &Value,
    src_ip:     &str,
    rule_id:    &str,
) -> bool {
    match cloud_type {
        "aws_sg"    => aws_sg_revoke(config, src_ip).await,
        "azure_nsg" => azure_nsg_revoke(config, src_ip, rule_id).await,
        "gcp_vpc"   => gcp_vpc_revoke(config, rule_id).await,
        _           => false,
    }
}

// ── AWS Security Group ─────────────────────────────────────────────────────
// Revokes ingress for src_ip on all ports in the given security group.
// config keys: sg_id, region, aws_access_key_id, aws_secret_access_key

async fn aws_sg_deny(config: &Value, src_ip: &str) -> FirewallResult {
    let sg_id      = config["sg_id"].as_str().unwrap_or("");
    let region     = config["region"].as_str().unwrap_or("us-east-1");
    let access_key = config["aws_access_key_id"].as_str().unwrap_or("");
    let secret_key = config["aws_secret_access_key"].as_str().unwrap_or("");

    if sg_id.is_empty() {
        return FirewallResult::err("aws_sg", "sg_id not configured");
    }

    // Revoke existing ingress from this IP (if any), then add explicit DENY
    // AWS SGs use allowlist model — remove any allow rule for the IP
    let cidr = format!("{}/32", src_ip);
    let out  = tokio::process::Command::new("aws")
        .env("AWS_ACCESS_KEY_ID",     access_key)
        .env("AWS_SECRET_ACCESS_KEY", secret_key)
        .env("AWS_DEFAULT_REGION",    region)
        .args([
            "ec2", "revoke-security-group-ingress",
            "--group-id", sg_id,
            "--protocol", "all",
            "--cidr", &cidr,
        ])
        .output()
        .await;

    match out {
        Ok(o) => {
            // AWS returns exit 0 even when rule didn't exist — treat both as success
            let rule_id = format!("aws_sg:{}:{}", sg_id, src_ip);
            if o.status.success() || String::from_utf8_lossy(&o.stderr).contains("InvalidPermission") {
                FirewallResult::ok("aws_sg", &rule_id,
                    format!("AWS SG {}: removed ingress for {}", sg_id, src_ip))
            } else {
                let stderr = String::from_utf8_lossy(&o.stderr);
                warn!("[FIREWALL] aws_sg error: {}", stderr);
                FirewallResult::err("aws_sg", format!("aws cli error: {}", stderr))
            }
        }
        Err(e) => FirewallResult::err("aws_sg", format!("aws cli not found: {}", e)),
    }
}

async fn aws_sg_revoke(config: &Value, src_ip: &str) -> bool {
    // Re-authorize ingress — restore default allow if needed
    // In most deployments "revoke" of a deny just means removing the block entry;
    // since AWS uses allowlist the original allow rule was already there, no-op.
    let sg_id      = config["sg_id"].as_str().unwrap_or("");
    let region     = config["region"].as_str().unwrap_or("us-east-1");
    let access_key = config["aws_access_key_id"].as_str().unwrap_or("");
    let secret_key = config["aws_secret_access_key"].as_str().unwrap_or("");

    if sg_id.is_empty() { return false; }

    // Add back allow rule for the IP (caller decides scope)
    let cidr = format!("{}/32", src_ip);
    tokio::process::Command::new("aws")
        .env("AWS_ACCESS_KEY_ID",     access_key)
        .env("AWS_SECRET_ACCESS_KEY", secret_key)
        .env("AWS_DEFAULT_REGION",    region)
        .args([
            "ec2", "authorize-security-group-ingress",
            "--group-id", sg_id,
            "--protocol", "all",
            "--cidr", &cidr,
        ])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Azure NSG ──────────────────────────────────────────────────────────────
// Creates a Deny inbound rule in the given NSG.
// config keys: resource_group, nsg_name, subscription_id (optional)

async fn azure_nsg_deny(config: &Value, src_ip: &str) -> FirewallResult {
    let rg       = config["resource_group"].as_str().unwrap_or("");
    let nsg_name = config["nsg_name"].as_str().unwrap_or("");
    let sub      = config["subscription_id"].as_str().unwrap_or("");

    if rg.is_empty() || nsg_name.is_empty() {
        return FirewallResult::err("azure_nsg", "resource_group or nsg_name not configured");
    }

    // Rule name: NDR-BLOCK-<ip> (dots replaced with dashes for Azure naming)
    let rule_name = format!("NDR-BLOCK-{}", src_ip.replace('.', "-").replace(':', "-"));
    let cidr      = format!("{}/32", src_ip);

    let mut args = vec![
        "network", "nsg", "rule", "create",
        "--resource-group", rg,
        "--nsg-name",       nsg_name,
        "--name",           &rule_name,
        "--priority",       "100",
        "--direction",      "Inbound",
        "--access",         "Deny",
        "--protocol",       "*",
        "--source-address-prefixes", &cidr,
        "--destination-address-prefixes", "*",
        "--source-port-ranges",      "*",
        "--destination-port-ranges", "*",
    ];

    let sub_args;
    if !sub.is_empty() {
        sub_args = format!("--subscription {}", sub);
        args.push("--subscription");
        args.push(sub);
    }
    let _ = sub_args; // suppress unused warning

    let out = tokio::process::Command::new("az")
        .args(&args)
        .output()
        .await;

    match out {
        Ok(o) if o.status.success() => {
            FirewallResult::ok("azure_nsg", &rule_name,
                format!("Azure NSG {}: deny rule {} created for {}", nsg_name, rule_name, src_ip))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            warn!("[FIREWALL] azure_nsg error: {}", stderr);
            FirewallResult::err("azure_nsg", format!("az cli error: {}", stderr))
        }
        Err(e) => FirewallResult::err("azure_nsg", format!("az cli not found: {}", e)),
    }
}

async fn azure_nsg_revoke(config: &Value, _src_ip: &str, rule_name: &str) -> bool {
    let rg       = config["resource_group"].as_str().unwrap_or("");
    let nsg_name = config["nsg_name"].as_str().unwrap_or("");

    if rg.is_empty() || nsg_name.is_empty() || rule_name.is_empty() { return false; }

    tokio::process::Command::new("az")
        .args([
            "network", "nsg", "rule", "delete",
            "--resource-group", rg,
            "--nsg-name",       nsg_name,
            "--name",           rule_name,
        ])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── GCP VPC Firewall ───────────────────────────────────────────────────────
// Creates a deny-all-ingress firewall rule targeting the source IP.
// config keys: project, network (default "default")

async fn gcp_vpc_deny(config: &Value, src_ip: &str) -> FirewallResult {
    let project = config["project"].as_str().unwrap_or("");
    let network = config["network"].as_str().unwrap_or("default");

    if project.is_empty() {
        return FirewallResult::err("gcp_vpc", "project not configured");
    }

    let rule_name = format!("ndr-block-{}", src_ip.replace('.', "-").replace(':', "-"));
    let cidr      = format!("{}/32", src_ip);

    let out = tokio::process::Command::new("gcloud")
        .args([
            "compute", "firewall-rules", "create", &rule_name,
            "--project",     project,
            "--network",     network,
            "--direction",   "INGRESS",
            "--action",      "DENY",
            "--rules",       "all",
            "--source-ranges", &cidr,
            "--priority",    "900",
            "--description", "NDR auto-block",
        ])
        .output()
        .await;

    match out {
        Ok(o) if o.status.success() => {
            FirewallResult::ok("gcp_vpc", &rule_name,
                format!("GCP VPC: deny rule {} created for {} in project {}", rule_name, src_ip, project))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            // "already exists" is fine — treat as success
            if stderr.contains("already exists") {
                FirewallResult::ok("gcp_vpc", &rule_name,
                    format!("GCP VPC: rule {} already existed", rule_name))
            } else {
                warn!("[FIREWALL] gcp_vpc error: {}", stderr);
                FirewallResult::err("gcp_vpc", format!("gcloud error: {}", stderr))
            }
        }
        Err(e) => FirewallResult::err("gcp_vpc", format!("gcloud not found: {}", e)),
    }
}

async fn gcp_vpc_revoke(config: &Value, rule_name: &str) -> bool {
    let project = config["project"].as_str().unwrap_or("");
    if project.is_empty() || rule_name.is_empty() { return false; }

    tokio::process::Command::new("gcloud")
        .args([
            "compute", "firewall-rules", "delete", rule_name,
            "--project", project,
            "--quiet",
        ])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Helper ─────────────────────────────────────────────────────────────────

fn insecure_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)  // firewalls often use self-signed certs
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default()
}
