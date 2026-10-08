// NDR Engine — Switch Isolation Integration
// Supports: UniFi REST, Cisco IOS SNMP, Aruba CX REST, Generic SNMP
// Moves device port to a quarantine VLAN or blocks it at the AP level.

use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::warn;

pub struct SwitchResult {
    pub success:     bool,
    pub switch_type: String,
    pub detail:      String,   // JSON blob stored in enforcement_detail
    pub message:     String,
}

impl SwitchResult {
    fn ok(sw: &str, detail: impl Into<String>, msg: impl Into<String>) -> Self {
        Self { success: true, switch_type: sw.to_string(), detail: detail.into(), message: msg.into() }
    }
    fn err(sw: &str, msg: impl Into<String>) -> Self {
        Self { success: false, switch_type: sw.to_string(), detail: String::new(), message: msg.into() }
    }
}

/// Query the current access VLAN for the port before quarantine so it can be restored later.
/// Returns None for UniFi (no VLAN concept at AP level) and on any error.
pub async fn get_current_vlan(sw_type: &str, config: &Value) -> Option<u16> {
    let host      = config["host"].as_str().unwrap_or("");
    let community = config["community"].as_str().unwrap_or("public");
    let ifindex   = config["port_ifindex"].as_u64().unwrap_or(0);

    match sw_type {
        "cisco" | "snmp" if !host.is_empty() && ifindex > 0 => {
            let oid = format!("1.3.6.1.2.1.17.7.1.4.5.1.1.{ifindex}");
            let out = tokio::process::Command::new("snmpget")
                .args(["-v2c", "-c", community, host, &oid])
                .output().await.ok()?;
            // snmpget output: "SNMPv2-SMI::mib-2.17.7.1.4.5.1.1.X = Gauge32: 100"
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.split_whitespace().last()?.parse::<u16>().ok()
        }
        _ => None,
    }
}

// ── Public entry points ────────────────────────────────────────────────────

pub async fn quarantine_device(
    sw_type:         &str,
    config:          &Value,
    target_ip:       &str,
    quarantine_vlan: u16,
) -> SwitchResult {
    match sw_type {
        "unifi"   => unifi_block(config, target_ip).await,
        "cisco"   => cisco_snmp_quarantine(config, target_ip, quarantine_vlan).await,
        "aruba"   => aruba_quarantine(config, target_ip, quarantine_vlan).await,
        "snmp"    => generic_snmp_quarantine(config, target_ip, quarantine_vlan).await,
        _         => SwitchResult::err(sw_type, "unsupported switch type"),
    }
}

pub async fn restore_device(
    sw_type:       &str,
    config:        &Value,
    target_ip:     &str,
    original_vlan: u16,
) -> bool {
    match sw_type {
        "unifi"   => unifi_unblock(config, target_ip).await,
        "cisco"   => cisco_snmp_restore(config, target_ip, original_vlan).await,
        "aruba"   => aruba_restore(config, target_ip, original_vlan).await,
        "snmp"    => generic_snmp_restore(config, target_ip, original_vlan).await,
        _         => false,
    }
}

// ── UniFi REST ────────────────────────────────────────────────────────────
// Uses the UniFi Network Application REST API (cookie-session auth).
// config keys: host, username, password, site (default "default")

async fn unifi_block(config: &Value, target_ip: &str) -> SwitchResult {
    let host     = config["host"].as_str().unwrap_or("");
    let username = config["username"].as_str().unwrap_or("admin");
    let password = config["password"].as_str().unwrap_or("");
    let site     = config["site"].as_str().unwrap_or("default");

    if host.is_empty() {
        return SwitchResult::err("unifi", "host not configured");
    }

    let client: Client = match Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return SwitchResult::err("unifi", format!("client build error: {e}")),
    };

    // Login — extract Set-Cookie for session
    let login_resp = match client
        .post(format!("{host}/api/login"))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await
    {
        Ok(r)  => r,
        Err(e) => return SwitchResult::err("unifi", format!("login failed: {e}")),
    };

    let cookie = login_resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Block station by IP — UniFi maps IP → MAC internally
    let block_res: Result<reqwest::Response, _> = client
        .post(format!("{host}/api/s/{site}/cmd/stamgr"))
        .header("Cookie", &cookie)
        .json(&json!({"cmd": "block-sta", "ip": target_ip}))
        .send()
        .await;

    match block_res {
        Ok(r) if r.status().is_success() => {
            let detail = json!({"host": host, "site": site, "ip": target_ip}).to_string();
            SwitchResult::ok("unifi", detail, format!("blocked {target_ip} on UniFi site {site}"))
        }
        Ok(r)  => SwitchResult::err("unifi", format!("API returned {}", r.status())),
        Err(e) => SwitchResult::err("unifi", format!("request error: {e}")),
    }
}

async fn unifi_unblock(config: &Value, target_ip: &str) -> bool {
    let host     = config["host"].as_str().unwrap_or("");
    let username = config["username"].as_str().unwrap_or("admin");
    let password = config["password"].as_str().unwrap_or("");
    let site     = config["site"].as_str().unwrap_or("default");

    let client: Client = match Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let cookie = match client
        .post(format!("{host}/api/login"))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await
    {
        Ok(r) => r.headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        Err(_) => return false,
    };

    client
        .post(format!("{host}/api/s/{site}/cmd/stamgr"))
        .header("Cookie", &cookie)
        .json(&json!({"cmd": "unblock-sta", "ip": target_ip}))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// ── Cisco IOS SNMP ────────────────────────────────────────────────────────
// Moves the port the target IP is on to a quarantine VLAN via snmpset.
// config keys: host, community (write), port_ifindex (discovered externally)

async fn cisco_snmp_quarantine(config: &Value, target_ip: &str, quarantine_vlan: u16) -> SwitchResult {
    let host      = config["host"].as_str().unwrap_or("");
    let community = config["community"].as_str().unwrap_or("private");
    let ifindex   = config["port_ifindex"].as_u64().unwrap_or(0);

    if host.is_empty() || ifindex == 0 {
        return SwitchResult::err("cisco", "host or port_ifindex not configured");
    }

    // OID: dot1qPvid (Q-BRIDGE-MIB) — sets native VLAN on the port
    let oid = format!("1.3.6.1.2.1.17.7.1.4.5.1.1.{ifindex}");
    let out = tokio::process::Command::new("snmpset")
        .args(["-v2c", "-c", community, host, &oid, "u", &quarantine_vlan.to_string()])
        .output()
        .await;

    match out {
        Ok(o) if o.status.success() => {
            let detail = json!({
                "host": host, "ifindex": ifindex,
                "quarantine_vlan": quarantine_vlan, "ip": target_ip
            }).to_string();
            SwitchResult::ok("cisco", detail,
                format!("port ifindex {ifindex} moved to VLAN {quarantine_vlan}"))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            warn!("[SWITCH] cisco snmpset failed: {stderr}");
            SwitchResult::err("cisco", format!("snmpset failed: {stderr}"))
        }
        Err(e) => SwitchResult::err("cisco", format!("snmpset exec error: {e}")),
    }
}

async fn cisco_snmp_restore(config: &Value, _target_ip: &str, original_vlan: u16) -> bool {
    let host      = config["host"].as_str().unwrap_or("");
    let community = config["community"].as_str().unwrap_or("private");
    let ifindex   = config["port_ifindex"].as_u64().unwrap_or(0);

    if host.is_empty() || ifindex == 0 { return false; }

    let oid = format!("1.3.6.1.2.1.17.7.1.4.5.1.1.{ifindex}");
    tokio::process::Command::new("snmpset")
        .args(["-v2c", "-c", community, host, &oid, "u", &original_vlan.to_string()])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Aruba CX REST ─────────────────────────────────────────────────────────
// Uses Aruba CX REST API (token auth) to reassign port access VLAN.
// config keys: host, username, password, port (e.g. "1/1/5")

async fn aruba_quarantine(config: &Value, target_ip: &str, quarantine_vlan: u16) -> SwitchResult {
    let host     = config["host"].as_str().unwrap_or("");
    let username = config["username"].as_str().unwrap_or("admin");
    let password = config["password"].as_str().unwrap_or("");
    let port     = config["port"].as_str().unwrap_or("");

    if host.is_empty() || port.is_empty() {
        return SwitchResult::err("aruba", "host or port not configured");
    }

    let client = match Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return SwitchResult::err("aruba", format!("client error: {e}")),
    };

    // Login to get session cookie
    let login = client
        .post(format!("{host}/rest/v10.10/login"))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await;

    let login_resp = match login {
        Ok(r) if r.status().is_success() => r,
        Ok(r)  => return SwitchResult::err("aruba", format!("login status: {}", r.status())),
        Err(e) => return SwitchResult::err("aruba", format!("login error: {e}")),
    };

    // Extract cookie header for subsequent requests
    let cookie = login_resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Encode port for URL (1/1/5 → 1%2F1%2F5)
    let port_enc = port.replace('/', "%2F");

    // Set access VLAN on the port
    let patch_res = client
        .patch(format!("{host}/rest/v10.10/system/interfaces/{port_enc}"))
        .header("Cookie", &cookie)
        .json(&json!({"vlan_mode": "access", "vlan_tag": quarantine_vlan}))
        .send()
        .await;

    let _ = client
        .post(format!("{host}/rest/v10.10/logout"))
        .header("Cookie", &cookie)
        .send()
        .await;

    match patch_res {
        Ok(r) if r.status().is_success() => {
            let detail = json!({
                "host": host, "port": port,
                "quarantine_vlan": quarantine_vlan, "ip": target_ip
            }).to_string();
            SwitchResult::ok("aruba", detail,
                format!("port {port} set to access VLAN {quarantine_vlan}"))
        }
        Ok(r)  => SwitchResult::err("aruba", format!("PATCH returned {}", r.status())),
        Err(e) => SwitchResult::err("aruba", format!("PATCH error: {e}")),
    }
}

async fn aruba_restore(config: &Value, _target_ip: &str, original_vlan: u16) -> bool {
    let host     = config["host"].as_str().unwrap_or("");
    let username = config["username"].as_str().unwrap_or("admin");
    let password = config["password"].as_str().unwrap_or("");
    let port     = config["port"].as_str().unwrap_or("");

    if host.is_empty() || port.is_empty() { return false; }

    let client = match Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let login = client
        .post(format!("{host}/rest/v10.10/login"))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await;

    let cookie = match login {
        Ok(r) => r.headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        Err(_) => return false,
    };

    let port_enc = port.replace('/', "%2F");

    let ok = client
        .patch(format!("{host}/rest/v10.10/system/interfaces/{port_enc}"))
        .header("Cookie", &cookie)
        .json(&json!({"vlan_mode": "access", "vlan_tag": original_vlan}))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let _ = client
        .post(format!("{host}/rest/v10.10/logout"))
        .header("Cookie", &cookie)
        .send()
        .await;

    ok
}

// ── Generic SNMP ──────────────────────────────────────────────────────────
// Same dot1qPvid approach as Cisco — works for any SNMPv2c-capable switch.
// config keys: host, community, port_ifindex

async fn generic_snmp_quarantine(config: &Value, target_ip: &str, quarantine_vlan: u16) -> SwitchResult {
    let host      = config["host"].as_str().unwrap_or("");
    let community = config["community"].as_str().unwrap_or("private");
    let ifindex   = config["port_ifindex"].as_u64().unwrap_or(0);

    if host.is_empty() || ifindex == 0 {
        return SwitchResult::err("snmp", "host or port_ifindex not configured");
    }

    let oid = format!("1.3.6.1.2.1.17.7.1.4.5.1.1.{ifindex}");
    let out = tokio::process::Command::new("snmpset")
        .args(["-v2c", "-c", community, host, &oid, "u", &quarantine_vlan.to_string()])
        .output()
        .await;

    match out {
        Ok(o) if o.status.success() => {
            let detail = json!({
                "host": host, "ifindex": ifindex,
                "quarantine_vlan": quarantine_vlan, "ip": target_ip
            }).to_string();
            SwitchResult::ok("snmp", detail,
                format!("ifindex {ifindex} moved to VLAN {quarantine_vlan} via SNMP"))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            SwitchResult::err("snmp", format!("snmpset failed: {stderr}"))
        }
        Err(e) => SwitchResult::err("snmp", format!("snmpset exec error: {e}")),
    }
}

async fn generic_snmp_restore(config: &Value, _target_ip: &str, original_vlan: u16) -> bool {
    let host      = config["host"].as_str().unwrap_or("");
    let community = config["community"].as_str().unwrap_or("private");
    let ifindex   = config["port_ifindex"].as_u64().unwrap_or(0);

    if host.is_empty() || ifindex == 0 { return false; }

    let oid = format!("1.3.6.1.2.1.17.7.1.4.5.1.1.{ifindex}");
    tokio::process::Command::new("snmpset")
        .args(["-v2c", "-c", community, host, &oid, "u", &original_vlan.to_string()])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}
