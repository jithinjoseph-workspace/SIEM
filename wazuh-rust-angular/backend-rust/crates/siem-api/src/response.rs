//! Network response for the SIEM, with provigil-common's integrations:
//! * blocking an IP reaches past the agent (Wazuh active response) to the tenant's
//!   perimeter firewall (pfSense, FortiGate, PAN-OS, OPNsense, REST) and cloud
//!   (AWS security group, Azure NSG, GCP VPC) integrations;
//! * isolating a host moves it to a quarantine VLAN on its switch (UniFi, Cisco,
//!   Aruba, SNMP) or denies it in the cloud.
//!
//! Blocks and isolations are kept per tenant (`siem_blocks`, `siem_isolations`),
//! listed and lifted from the SOAR page (`/api/blocks`, `/api/isolations`...), and
//! firewall / cloud blocks are removed when they expire. Integrations are the
//! tenant's SOAR integrations; high-impact automatic actions pass decisions.rs first.

use std::net::IpAddr;
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use provigil_common::soar::{firewall, switch};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

pub const DDL: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS siem_blocks (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
    "CREATE TABLE IF NOT EXISTS siem_isolations (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
];
const FIREWALLS: [&str; 5] = ["pfsense", "fortinet", "panos", "opnsense", "rest"];
const CLOUDS: [&str; 3] = ["aws_sg", "azure_nsg", "gcp_vpc"];
const SWITCHES: [&str; 4] = ["unifi", "cisco", "aruba", "snmp"];
const DEFAULT_QUARANTINE_VLAN: u16 = 999;

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn iso(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0).map(|d| d.to_rfc3339()).unwrap_or_default()
}

/// An active or lifted block (the NDR `ActiveBlock` fields the SOAR page shows, plus the SIEM's).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Block {
    pub id: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub community_id: String,
    pub triggered_by: String,
    pub sensor_id: String,
    pub firewall_type: String,
    pub firewall_rule_id: String,
    pub rst_injected: u8,
    pub duration_hours: u16,
    pub expires_at: String,
    pub status: String,
    pub reason: String,
    pub tenant_id: String,
    pub created_at: String,
    /// The agent that blocked it too (Wazuh active response), and how that went.
    pub agent_id: String,
    pub agent_result: String,
    pub cloud_type: String,
    pub cloud_rule_id: String,
    pub expires_ts: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Isolation {
    pub id: String,
    pub tenant_id: String,
    pub target_ip: String,
    pub gateway_ip: String,
    pub method: String,
    pub enforcement: String,
    pub enforcement_detail: String,
    pub triggered_by: String,
    pub sensor_id: String,
    pub reason: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

async fn integrations(state: &AppState, tenant: &str) -> Vec<Value> {
    crate::soar::Store { db: state.db.clone(), state: None }.integrations(tenant).await.unwrap_or_default()
}

/// The tenant's enabled integration of one of `kinds` (`prefer` first when it is one of them).
fn pick<'a>(list: &'a [Value], kinds: &[&str], prefer: Option<&str>) -> Option<&'a Value> {
    let on = |i: &&Value, k: &str| i["type"].as_str() == Some(k) && i["enabled"] == json!(true);
    if let Some(p) = prefer.filter(|p| kinds.contains(p)) {
        return list.iter().find(|i| on(i, p));
    }
    kinds.iter().find_map(|k| list.iter().find(|i| on(i, k)))
}

fn public(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok_and(provigil_common::soar::is_public)
}

async fn put<T: Serialize>(state: &AppState, tenant: &str, t: DocTable, id: &str, v: &T) -> Result<(), String> {
    state.db.put_doc(tenant, t, id, &serde_json::to_string(v).map_err(|e| e.to_string())?).await
}

async fn all<T: for<'de> Deserialize<'de>>(state: &AppState, tenant: &str, t: DocTable) -> Vec<T> {
    state.db.docs(tenant, t, 10_000).await.unwrap_or_default().iter().filter_map(|d| serde_json::from_str(d).ok()).collect()
}

/// Blocks `ip` for `hours`: on the agent (`enforcement` "both" / "rst" / "agent", when an
/// agent is given) and at the perimeter firewall and cloud ("both" / "firewall").
/// Ok((block, what happened)) when at least one of them took it.
pub async fn block(state: &AppState, tenant: &str, ip: &str, hours: u64, enforcement: &str, agent_id: Option<&str>, triggered_by: &str, reason: &str) -> Result<(Block, String), String> {
    if !public(ip) {
        return Err(format!("{ip} is not a public address; it is not blocked"));
    }
    let hours = hours.clamp(1, 720);
    let on_agent = matches!(enforcement, "both" | "rst" | "agent") && agent_id.is_some_and(|a| !a.is_empty());
    let at_perimeter = matches!(enforcement, "both" | "firewall");
    let mut b = Block { id: uuid::Uuid::new_v4().to_string(), src_ip: ip.into(), triggered_by: triggered_by.into(), reason: reason.into(), tenant_id: tenant.into(), duration_hours: hours as u16, ..Default::default() };
    let mut notes = Vec::new();
    let mut took = false;
    if on_agent {
        let agent = agent_id.unwrap_or_default();
        b.agent_id = agent.into();
        match crate::soar::block_now(state, agent, ip, hours, reason).await {
            Ok(d) => {
                took = true;
                b.agent_result = d.clone();
                notes.push(format!("agent: {d}"));
            }
            Err(e) => {
                b.agent_result = e.clone();
                notes.push(format!("agent: {e}"));
            }
        }
    }
    if at_perimeter {
        let list = integrations(state, tenant).await;
        match pick(&list, &FIREWALLS, None) {
            Some(fw) => {
                let kind = fw["type"].as_str().unwrap_or("");
                let r = firewall::push_block(kind, &fw["config"], ip, hours).await;
                notes.push(format!("{kind}: {}", r.message));
                if r.success {
                    took = true;
                    b.firewall_type = kind.into();
                    b.firewall_rule_id = r.rule_id;
                }
            }
            None => notes.push("no firewall integration".into()),
        }
        if let Some(c) = pick(&list, &CLOUDS, None) {
            let kind = c["type"].as_str().unwrap_or("");
            let r = firewall::push_cloud_deny(kind, &c["config"], ip).await;
            notes.push(format!("{kind}: {}", r.message));
            if r.success {
                took = true;
                b.cloud_type = kind.into();
                b.cloud_rule_id = r.rule_id;
            }
        }
    }
    let detail = notes.join("; ");
    if !took {
        return Err(if detail.is_empty() { "nothing to block it with (no agent, firewall or cloud integration)".into() } else { detail });
    }
    let t = now();
    b.created_at = iso(t);
    b.expires_ts = t + hours * 3600;
    b.expires_at = iso(b.expires_ts);
    b.status = "active".into();
    put(state, tenant, DocTable::Blocks, &b.id, &b).await?;
    Ok((b, detail))
}

/// Lifts a block at the firewall / cloud (the agent's own block runs out by itself).
pub async fn unblock(state: &AppState, tenant: &str, id: &str, status: &str) -> Result<String, String> {
    let mut b: Block = state.db.doc(tenant, DocTable::Blocks, id).await?.and_then(|d| serde_json::from_str(&d).ok()).ok_or("Block not found")?;
    if b.status != "active" {
        return Err(format!("This block is already {}", b.status));
    }
    let list = integrations(state, tenant).await;
    let mut notes = Vec::new();
    if !b.firewall_type.is_empty() {
        match pick(&list, &[b.firewall_type.as_str()], None) {
            Some(fw) => notes.push(format!("{}: {}", b.firewall_type, if firewall::revoke_block(&b.firewall_type, &fw["config"], &b.src_ip, &b.firewall_rule_id).await { "removed" } else { "could not remove the rule" })),
            None => notes.push(format!("{}: integration no longer enabled; remove the rule by hand", b.firewall_type)),
        }
    }
    if !b.cloud_type.is_empty() {
        match pick(&list, &[b.cloud_type.as_str()], None) {
            Some(c) => notes.push(format!("{}: {}", b.cloud_type, if firewall::revoke_cloud_deny(&b.cloud_type, &c["config"], &b.src_ip, &b.cloud_rule_id).await { "removed" } else { "could not remove the rule" })),
            None => notes.push(format!("{}: integration no longer enabled; remove the rule by hand", b.cloud_type)),
        }
    }
    if !b.agent_id.is_empty() && b.status == "active" && status == "revoked" {
        notes.push("the agent's block ends at its own timeout (Wazuh agents have no early unblock)".into());
    }
    b.status = status.into();
    put(state, tenant, DocTable::Blocks, &b.id, &b).await?;
    Ok(notes.join("; "))
}

/// The tenant's Windows Wazuh agent to isolate: `agent_id`, else the agent at `ip`.
async fn windows_agent(state: &AppState, tenant: &str, ip: &str, agent_id: Option<&str>) -> Option<String> {
    let id = {
        let tenants = state.agent_tenants.read().unwrap().clone();
        let agents = state.agents.read().unwrap();
        let mine = |id: &str| crate::tenancy::tenant_of(&tenants, id) == tenant;
        match agent_id.filter(|a| !a.is_empty()) {
            Some(a) => mine(a).then(|| a.to_string()),
            None => agents.values().find(|a| a.ip == ip && mine(&a.id)).map(|a| a.id.clone()),
        }
    }?;
    (crate::agent_is_windows(state, &id) && crate::wazuh_manager::is_wazuh_agent(&id).await).then_some(id)
}

/// How long an agent isolation lasts: the agent lifts it then by itself.
const AGENT_ISOLATION_SECONDS: u64 = 86400;

/// Isolates `ip`: a quarantine VLAN on its switch, else a cloud deny, else the firewall
/// of its Windows agent (`agent_id`, or the agent at `ip`); `enforcement` picks one.
pub async fn isolate(state: &AppState, tenant: &str, ip: &str, enforcement: Option<&str>, vlan: Option<u16>, gateway: &str, triggered_by: &str, reason: &str, agent_id: Option<&str>) -> Result<(Isolation, String), String> {
    if ip.parse::<IpAddr>().is_err() {
        return Err("A valid IP address is required".into());
    }
    if enforcement == Some("arp") {
        return Err("ARP isolation needs an NDR sensor on the host's network; use a switch or cloud integration".into());
    }
    let want_switch = enforcement.is_none_or(|e| SWITCHES.contains(&e));
    let want_cloud = enforcement.is_none_or(|e| CLOUDS.contains(&e));
    let want_agent = enforcement.is_none_or(|e| e == "agent");
    if !want_switch && !want_cloud && !want_agent {
        return Err(format!("Unknown isolation method {}", enforcement.unwrap_or("")));
    }
    let list = integrations(state, tenant).await;
    let sw = if want_switch { pick(&list, &SWITCHES, enforcement) } else { None };
    let cloud = if sw.is_none() && want_cloud { pick(&list, &CLOUDS, enforcement) } else { None };
    let (iso_kind, detail, method) = if let Some(sw) = sw {
        let kind = sw["type"].as_str().unwrap_or("").to_string();
        let vlan = vlan.unwrap_or(DEFAULT_QUARANTINE_VLAN);
        let original = switch::get_current_vlan(&kind, &sw["config"]).await.unwrap_or(1);
        let r = switch::quarantine_device(&kind, &sw["config"], ip, vlan).await;
        if !r.success {
            return Err(format!("{kind}: {}", r.message));
        }
        let mut d: Value = serde_json::from_str(&r.detail).unwrap_or(json!({}));
        d["original_vlan"] = json!(original);
        d["quarantine_vlan"] = json!(vlan);
        (kind, d.to_string(), "switch_vlan")
    } else if let Some(c) = cloud {
        let kind = c["type"].as_str().unwrap_or("").to_string();
        let r = firewall::push_cloud_deny(&kind, &c["config"], ip).await;
        if !r.success {
            return Err(format!("{kind}: {}", r.message));
        }
        (kind, json!({ "rule_id": r.rule_id }).to_string(), "cloud_deny")
    } else if let Some(agent) = if want_agent { windows_agent(state, tenant, ip, agent_id).await } else { None } {
        let (iso, timeout) = crate::wazuh_manager::isolate_agent(&agent, AGENT_ISOLATION_SECONDS).await?;
        ("agent".to_string(), json!({ "agent_id": agent, "isolation_id": iso, "expires_ts": now() + timeout }).to_string(), "agent_firewall")
    } else {
        return Err(match enforcement {
            Some("agent") => format!("No Windows agent of yours at {ip} to isolate with"),
            Some(e) => format!("No enabled {e} integration (SOAR → Integrations)"),
            None => format!("No switch or cloud integration (SOAR → Integrations), and no Windows agent at {ip}, to isolate with"),
        });
    };
    let t = iso(now());
    let i = Isolation {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: tenant.into(),
        target_ip: ip.into(),
        gateway_ip: gateway.into(),
        method: method.into(),
        enforcement: iso_kind.clone(),
        enforcement_detail: detail,
        triggered_by: triggered_by.into(),
        reason: reason.into(),
        status: "active".into(),
        created_at: t.clone(),
        updated_at: t,
        ..Default::default()
    };
    put(state, tenant, DocTable::Isolations, &i.id, &i).await?;
    Ok((i, format!("{ip} isolated with {iso_kind}")))
}

/// The ids of the agent's active firewall isolations.
pub async fn active_agent_isolations(state: &AppState, tenant: &str, agent_id: &str) -> Vec<String> {
    all::<Isolation>(state, tenant, DocTable::Isolations)
        .await
        .into_iter()
        .filter(|i| i.status == "active" && i.method == "agent_firewall")
        .filter(|i| serde_json::from_str::<Value>(&i.enforcement_detail).is_ok_and(|d| d["agent_id"].as_str() == Some(agent_id)))
        .map(|i| i.id)
        .collect()
}

pub async fn unisolate(state: &AppState, tenant: &str, id: &str) -> Result<String, String> {
    let mut i: Isolation = state.db.doc(tenant, DocTable::Isolations, id).await?.and_then(|d| serde_json::from_str(&d).ok()).ok_or("Isolation not found")?;
    if i.status != "active" {
        return Err(format!("This isolation is already {}", i.status));
    }
    let d: Value = serde_json::from_str(&i.enforcement_detail).unwrap_or(json!({}));
    if i.method == "agent_firewall" {
        crate::wazuh_manager::release_agent(d["agent_id"].as_str().unwrap_or("")).await?;
        i.status = "released".into();
        i.updated_at = iso(now());
        put(state, tenant, DocTable::Isolations, &i.id, &i).await?;
        return Ok(format!("Release sent to agent {}", d["agent_id"].as_str().unwrap_or("")));
    }
    let list = integrations(state, tenant).await;
    let Some(integ) = pick(&list, &[i.enforcement.as_str()], None) else {
        return Err(format!("The {} integration is no longer enabled; restore the device by hand", i.enforcement));
    };
    let ok = if i.method == "switch_vlan" {
        switch::restore_device(&i.enforcement, &integ["config"], &i.target_ip, d["original_vlan"].as_u64().unwrap_or(1) as u16).await
    } else {
        firewall::revoke_cloud_deny(&i.enforcement, &integ["config"], &i.target_ip, d["rule_id"].as_str().unwrap_or("")).await
    };
    if !ok {
        return Err(format!("{} did not confirm the restore; the device is still isolated", i.enforcement));
    }
    i.status = "released".into();
    i.updated_at = iso(now());
    put(state, tenant, DocTable::Isolations, &i.id, &i).await?;
    Ok(format!("{} restored", i.target_ip))
}

/// Lifts the expired firewall / cloud blocks of every tenant; the number lifted.
pub async fn sweep(state: &AppState) -> usize {
    let t = now();
    let mut n = 0;
    for tenant in crate::predictions::tenant_ids(state) {
        for b in all::<Block>(state, &tenant, DocTable::Blocks).await.into_iter().filter(|b| b.status == "active" && b.expires_ts > 0 && b.expires_ts <= t) {
            match unblock(state, &tenant, &b.id, "expired").await {
                Ok(d) => {
                    n += 1;
                    tracing::info!("block {} on {} expired: {d}", b.id, b.src_ip);
                }
                Err(e) => tracing::warn!("block {} on {} not lifted: {e}", b.id, b.src_ip),
            }
        }
        // an agent lifts its isolation at its own timeout: the record follows
        for mut i in all::<Isolation>(state, &tenant, DocTable::Isolations).await.into_iter().filter(|i| i.status == "active" && i.method == "agent_firewall") {
            let d: Value = serde_json::from_str(&i.enforcement_detail).unwrap_or(json!({}));
            if d["expires_ts"].as_u64().is_some_and(|e| e <= t) {
                i.status = "expired".into();
                i.updated_at = iso(t);
                if put(state, &tenant, DocTable::Isolations, &i.id, &i).await.is_ok() {
                    n += 1;
                }
            }
        }
    }
    n
}

/// Expired blocks are lifted every minute.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if state.db.is_connected() {
                sweep(&state).await;
            }
        }
    });
}

// ───────────────────────── API (the SOAR page) ─────────────────────────

fn ok_data(v: impl Serialize) -> Json<Value> {
    Json(json!({ "status": "success", "data": v }))
}

fn fail(code: StatusCode, m: impl std::fmt::Display) -> axum::response::Response {
    (code, Json(json!({ "status": "error", "message": m.to_string() }))).into_response()
}

/// `GET /api/blocks`: active blocks.
pub async fn list_blocks(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let mut v: Vec<Block> = all::<Block>(&state, &ctx.scope(), DocTable::Blocks).await.into_iter().filter(|b| b.status == "active").collect();
    v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    ok_data(v)
}

#[derive(Deserialize)]
pub struct ManualBlock {
    pub src_ip: String,
    pub duration_hours: Option<u64>,
    pub enforcement: Option<String>,
    pub reason: Option<String>,
}

/// `POST /api/blocks/manual`: a person blocks an IP at the perimeter (recorded, protected list applies).
pub async fn manual_block(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(b): Json<ManualBlock>) -> axum::response::Response {
    let t = ctx.scope();
    let ip = b.src_ip.trim();
    if ip.parse::<IpAddr>().is_err() {
        return fail(StatusCode::BAD_REQUEST, "A valid IP address is required");
    }
    if b.enforcement.as_deref() == Some("rst") {
        return fail(StatusCode::BAD_REQUEST, "On the SIEM, blocking on a host is done from the agent (Agents → Block IP); choose Firewall here");
    }
    let hours = b.duration_hours.unwrap_or(24);
    if let Err(m) = crate::decisions::gate_manual(&state, &ctx, &t, "manual_block", ip, json!({ "ip": ip, "hours": hours })).await {
        return fail(StatusCode::FORBIDDEN, m);
    }
    let reason = b.reason.clone().filter(|r| !r.trim().is_empty()).unwrap_or_else(|| format!("Manual block by {}", ctx.username));
    match block(&state, &t, ip, hours, "firewall", None, &ctx.username, &reason).await {
        Ok((b, d)) => Json(json!({ "status": "success", "message": d, "data": b })).into_response(),
        Err(e) => fail(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
pub struct ById {
    pub id: String,
}

/// `POST /api/blocks/revoke`
pub async fn revoke_block(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<ById>) -> axum::response::Response {
    match unblock(&state, &ctx.scope(), &r.id, "revoked").await {
        Ok(d) => Json(json!({ "status": "success", "message": format!("Block {} revoked: {d}", r.id) })).into_response(),
        Err(e) => fail(StatusCode::BAD_REQUEST, e),
    }
}

/// `GET /api/isolations`: active isolations.
pub async fn list_isolations(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let mut v: Vec<Isolation> = all::<Isolation>(&state, &ctx.scope(), DocTable::Isolations).await.into_iter().filter(|i| i.status == "active").collect();
    v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    ok_data(v)
}

#[derive(Deserialize)]
pub struct IsolateBody {
    pub target_ip: String,
    pub gateway_ip: Option<String>,
    pub enforcement: Option<String>,
    pub quarantine_vlan: Option<u16>,
    pub reason: Option<String>,
    /// The Windows agent to isolate with its own firewall (else the agent at `target_ip`).
    pub agent_id: Option<String>,
}

/// `POST /api/isolate`: a person isolates a host (recorded, protected list applies).
pub async fn isolate_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(b): Json<IsolateBody>) -> axum::response::Response {
    let t = ctx.scope();
    let ip = b.target_ip.trim();
    if ip.parse::<IpAddr>().is_err() {
        return fail(StatusCode::BAD_REQUEST, "A valid IP address is required");
    }
    if let Err(m) = crate::decisions::gate_manual(&state, &ctx, &t, "manual_isolate", ip, json!({ "ip": ip, "enforcement": b.enforcement })).await {
        return fail(StatusCode::FORBIDDEN, m);
    }
    let reason = b.reason.clone().filter(|r| !r.trim().is_empty()).unwrap_or_else(|| format!("Isolated by {}", ctx.username));
    match isolate(&state, &t, ip, b.enforcement.as_deref(), b.quarantine_vlan, b.gateway_ip.as_deref().unwrap_or(""), &ctx.username, &reason, b.agent_id.as_deref()).await {
        Ok((i, _)) => Json(json!({ "status": "ok", "id": i.id, "target_ip": i.target_ip })).into_response(),
        Err(e) => fail(StatusCode::BAD_GATEWAY, e),
    }
}

/// `POST /api/unisolate`
pub async fn unisolate_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<ById>) -> axum::response::Response {
    match unisolate(&state, &ctx.scope(), &r.id).await {
        Ok(d) => Json(json!({ "status": "ok", "message": d })).into_response(),
        Err(e) => fail(StatusCode::BAD_GATEWAY, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A firewall / switch with its own CA: refused by default, trusted with `ca_cert`,
    /// reachable with `tls_insecure`; a `ca_cert` that is not a certificate fails closed.
    #[tokio::test]
    async fn device_tls_is_verified() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_p = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        ca_p.distinguished_name.push(rcgen::DnType::CommonName, "Test Firewall CA");
        let ca = ca_p.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut srv_p = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
        srv_p.distinguished_name.push(rcgen::DnType::CommonName, "firewall.test");
        let cert = srv_p.signed_by(&key, &ca, &ca_key).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone(), CertificateDer::from(ca.der().to_vec())], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut s) = acceptor.accept(tcp).await {
                        let mut buf = [0u8; 2048];
                        let _ = s.read(&mut buf).await;
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                        let _ = s.shutdown().await;
                    }
                });
            }
        });
        let url = format!("https://127.0.0.1:{port}/");
        let status = |cfg: Value| {
            let url = url.clone();
            async move { provigil_common::soar::firewall::device_client(&cfg, std::time::Duration::from_secs(5)).get(&url).send().await.map(|r| r.status().as_u16()) }
        };
        assert!(status(json!({})).await.is_err(), "a certificate of an unknown CA is refused");
        assert_eq!(status(json!({ "ca_cert": ca.pem() })).await.unwrap(), 200, "the device's CA is trusted");
        assert_eq!(status(json!({ "tls_insecure": true })).await.unwrap(), 200, "verification off on request");
        assert!(status(json!({ "ca_cert": "not a certificate" })).await.is_err(), "a broken ca_cert trusts nothing extra");
    }

    #[test]
    fn integration_choice() {
        let list = vec![
            json!({ "type": "slack", "enabled": true }),
            json!({ "type": "opnsense", "enabled": false }),
            json!({ "type": "fortinet", "enabled": true }),
            json!({ "type": "aruba", "enabled": true }),
            json!({ "type": "unifi", "enabled": true }),
        ];
        assert_eq!(pick(&list, &FIREWALLS, None).unwrap()["type"], "fortinet", "the disabled one is skipped");
        assert_eq!(pick(&list, &SWITCHES, None).unwrap()["type"], "unifi", "the first kind in order");
        assert_eq!(pick(&list, &SWITCHES, Some("aruba")).unwrap()["type"], "aruba", "the one asked for");
        assert!(pick(&list, &SWITCHES, Some("cisco")).is_none(), "asked for one that is not enabled");
        assert!(pick(&list, &CLOUDS, None).is_none());
    }
}
