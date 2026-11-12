//! Network segments: the IPv4 subnet(s) each agent sits in, worked out from the addresses and
//! masks its inventory reports (a VLAN is normally one subnet; a PC never sees its VLAN tag),
//! and the names a tenant admin gives subnets ("10.10.0.0/24" = "VLAN 10 Finance"). Also the
//! PC's type (Windows workstation or server, Linux, macOS) for the console's filters.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use axum::{extract::State, http::StatusCode, response::{IntoResponse, Response}, Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tenancy::{self, AuthCtx};
use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_segment_names (cidr String, name String, updated_by String, updated_at UInt64) ENGINE = ReplacingMergeTree(updated_at) ORDER BY cidr";

const MAX_NAMES: usize = 1000;

fn reply(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "status": if code.is_success() { "ok" } else { "error" }, "message": m.into() }))).into_response()
}

/// `a.b.c.d/n` of an address and its mask; None for loopback, link-local and bad input.
pub fn subnet_of(ip: &str, mask: &str) -> Option<String> {
    let ip: Ipv4Addr = ip.trim().parse().ok()?;
    if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
        return None;
    }
    let bits = match mask.trim().parse::<Ipv4Addr>() {
        Ok(m) => {
            let m = u32::from(m);
            // a mask is ones then zeros
            if m.leading_ones() + m.trailing_zeros() != 32 {
                return None;
            }
            m.leading_ones()
        }
        Err(_) => mask.trim().trim_start_matches('/').parse::<u32>().ok().filter(|b| *b <= 32)?,
    };
    let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some(format!("{}/{bits}", Ipv4Addr::from(u32::from(ip) & m)))
}

/// A network card of the machine itself, not a virtual switch, VPN, hotspot or container bridge.
pub fn real_iface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const VIRTUAL: [&str; 14] = ["vethernet", "virtualbox", "vmware", "hyper-v", "wsl", "loopback", "local area connection*", "docker", "br-", "veth", "virbr", "tailscale", "zerotier", "vpn"];
    !(n == "lo" || VIRTUAL.iter().any(|v| n.starts_with(v) || n.contains(v)))
}

/// What kind of PC an OS name and type say it is.
pub fn pc_type(os_type: &str, os: &str) -> &'static str {
    let o = os.to_ascii_lowercase();
    match os_type {
        "windows" if o.contains("server") => "windows-server",
        "windows" => "windows-workstation",
        "linux" => "linux",
        "macos" => "macos",
        _ if o.contains("windows") => if o.contains("server") { "windows-server" } else { "windows-workstation" },
        _ if o.contains("mac") || o.contains("darwin") => "macos",
        _ if !o.is_empty() && !o.contains("registered") => "linux",
        _ => "unknown",
    }
}

/// The subnets of one agent's real, up network cards (sorted, no repeats).
async fn agent_segments(agent_id: &str) -> Vec<String> {
    let Some(id) = agent_id.parse::<u32>().ok().map(|n| format!("{n:03}")) else { return Vec::new() };
    let down: Vec<String> = crate::provigil_manager::agent_sql(&id, "SELECT name, state FROM sys_netiface;")
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r["state"].as_str().is_some_and(|s| s.eq_ignore_ascii_case("down")))
        .filter_map(|r| r["name"].as_str().map(str::to_string))
        .collect();
    let rows = crate::provigil_manager::agent_sql(&id, "SELECT iface, address, netmask FROM sys_netaddr WHERE proto = 'ipv4';").await.unwrap_or_default();
    let mut out: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            let iface = r["iface"].as_str().unwrap_or("");
            if !real_iface(iface) || down.iter().any(|d| d == iface) {
                return None;
            }
            subnet_of(r["address"].as_str()?, r["netmask"].as_str()?)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

async fn names(state: &AppState, tenant: &str) -> Result<BTreeMap<String, String>, String> {
    let rows = state
        .db
        .tenant_client(tenant)
        .query("SELECT cidr, name FROM siem_segment_names FINAL WHERE name != ''")
        .fetch_all::<(String, String)>()
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().collect())
}

/// `GET /api/v1/segments`: every agent's segments and type, and the tenant's segment names.
/// An agent without a network inventory gets its address as a /24, marked `guessed`.
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    if !ctx.has_permission("siem-agents") && !ctx.has_permission("siem-vulnerabilities") {
        return tenancy::forbidden();
    }
    let tenant = ctx.scope();
    let names = names(&state, &tenant).await.unwrap_or_default();
    let mut agents = serde_json::Map::new();
    for a in crate::scoped_agents(&state, &ctx) {
        let mut segs = agent_segments(&a.id).await;
        let guessed = segs.is_empty();
        if guessed {
            segs.extend(subnet_of(&a.ip, "24"));
        }
        agents.insert(a.id.clone(), json!({ "segments": segs, "guessed": guessed, "type": pc_type(&a.os_type, &a.os) }));
    }
    let names: Vec<Value> = names.into_iter().map(|(cidr, name)| json!({ "cidr": cidr, "name": name })).collect();
    Json(json!({ "agents": agents, "names": names, "editable": ctx.can_manage(&tenant) })).into_response()
}

#[derive(Deserialize)]
pub struct NameBody {
    cidr: String,
    #[serde(default)]
    name: String,
}

/// `PUT /api/v1/segments/name` `{cidr, name}` (tenant admin): names a subnet; an empty name
/// removes the name.
pub async fn set_name(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(b): Json<NameBody>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let Some((ip, bits)) = b.cidr.trim().split_once('/') else {
        return reply(StatusCode::BAD_REQUEST, "A subnet like 10.10.0.0/24");
    };
    // stored as its network address, so "10.10.0.7/24" names 10.10.0.0/24
    let Some(cidr) = subnet_of(ip, bits).filter(|_| bits.parse::<u32>().is_ok()) else {
        return reply(StatusCode::BAD_REQUEST, "A subnet like 10.10.0.0/24");
    };
    let name: String = b.name.trim().chars().filter(|c| !c.is_control()).take(60).collect();
    if !name.is_empty() && names(&state, &tenant).await.map(|n| n.len() >= MAX_NAMES && !n.contains_key(&cidr)).unwrap_or(false) {
        return reply(StatusCode::BAD_REQUEST, format!("At most {MAX_NAMES} named subnets"));
    }
    let now = chrono::Utc::now().timestamp_micros().max(0) as u64;
    let r = state
        .db
        .tenant_client(&tenant)
        .query("INSERT INTO siem_segment_names (cidr, name, updated_by, updated_at) VALUES (?, ?, ?, ?)")
        .bind(&cidr)
        .bind(&name)
        .bind(&ctx.username)
        .bind(now)
        .execute()
        .await;
    match r {
        Ok(()) => Json(json!({ "status": "ok", "cidr": cidr, "name": name })).into_response(),
        Err(e) => reply(StatusCode::SERVICE_UNAVAILABLE, format!("The name was not saved: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets_from_address_and_mask() {
        assert_eq!(subnet_of("192.168.1.76", "255.255.255.0").as_deref(), Some("192.168.1.0/24"));
        assert_eq!(subnet_of("172.25.80.1", "255.255.240.0").as_deref(), Some("172.25.80.0/20"));
        assert_eq!(subnet_of("10.10.0.7", "24").as_deref(), Some("10.10.0.0/24"));
        assert_eq!(subnet_of("169.254.183.125", "255.255.0.0"), None, "link-local");
        assert_eq!(subnet_of("127.0.0.1", "255.0.0.0"), None, "loopback");
        assert_eq!(subnet_of("10.0.0.1", "255.0.255.0"), None, "not a mask");
        assert_eq!(subnet_of("fe80::1", "64"), None, "IPv4 only");
    }

    #[test]
    fn virtual_cards_are_skipped() {
        assert!(real_iface("Wi-Fi") && real_iface("Ethernet") && real_iface("eth0") && real_iface("ens33"));
        assert!(!real_iface("vEthernet (WSL (Hyper-V firewall))") && !real_iface("Local Area Connection* 2"));
        assert!(!real_iface("docker0") && !real_iface("lo") && !real_iface("br-1a2b") && !real_iface("Loopback Pseudo-Interface 1"));
    }

    #[test]
    fn pc_types() {
        assert_eq!(pc_type("windows", "Microsoft Windows Server 2022 Standard"), "windows-server");
        assert_eq!(pc_type("windows", "Microsoft Windows 10 Pro"), "windows-workstation");
        assert_eq!(pc_type("linux", "Registered via enrollment"), "linux");
        assert_eq!(pc_type("", "Ubuntu 22.04"), "linux");
        assert_eq!(pc_type("", "Registered via enrollment"), "unknown");
    }
}
