pub mod actions;
pub mod conditions;
pub mod firewall;
pub mod switch;

use serde::{Deserialize, Serialize};

// ── Playbook definition ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarNativePlaybook {
    pub id:            String,
    pub name:          String,
    pub description:   String,
    pub enabled:       u8,
    pub cond_field:    String,
    pub cond_op:       String,
    pub cond_value:    String,
    pub action_type:   String,
    pub action_config: String,
    pub run_count:     u64,
    pub last_run:      Option<String>,
    pub created_at:    String,
    pub updated_at:    String,
    pub tenant_id:     String,
}

// ── Playbook run log ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarPlaybookRun {
    pub id:            String,
    pub playbook_id:   String,
    pub playbook_name: String,
    pub hit_id:        String,
    pub status:        String,
    pub detail:        String,
    pub created_at:    String,
    pub tenant_id:     String,
}

// ── Active IP block ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBlock {
    pub id:               String,
    pub src_ip:           String,
    pub src_port:         u16,
    pub dst_ip:           String,
    pub dst_port:         u16,
    pub community_id:     String,
    pub triggered_by:     String,
    pub sensor_id:        String,
    pub firewall_type:    String,
    pub firewall_rule_id: String,
    pub rst_injected:     u8,
    pub duration_hours:   u16,
    pub expires_at:       String,
    pub status:           String,
    pub reason:           String,
    pub tenant_id:        String,
    pub created_at:       String,
}

// ── Device isolation ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIsolation {
    pub id:                 String,
    pub tenant_id:          String,
    pub target_ip:          String,
    pub gateway_ip:         String,
    pub method:             String,
    pub enforcement:        String,
    pub enforcement_detail: String,
    pub triggered_by:       String,
    pub sensor_id:          String,
    pub reason:             String,
    pub status:             String,
    pub created_at:         String,
    pub updated_at:         String,
}

// ── Generic event context ─────────────────────────────────────────────────────
//
// Both ndr-engine and siem-engine fill this from their own event types before
// calling evaluate_condition().  No engine-specific imports required here.

#[derive(Debug, Clone, Default)]
pub struct SoarContext {
    /// 0.0 – 100.0 risk score
    pub score: f32,
    /// "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    pub severity: String,
    /// Whether the src/dst IP matched a threat-intel IOC
    pub is_malicious: bool,
    /// Two-letter ISO country code for source IP (empty if unknown)
    pub src_country: String,
    /// Classification tags on the alert (sigma tags, correlation tags, etc.)
    pub tags: Vec<String>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    /// Unique flow identifier (community_id or similar)
    pub community_id: String,
    pub tenant_id: String,
    /// The original SIEM alert (Wazuh alert JSON); `None` for NDR hits.
    /// The `rule_*` / `agent_name` / `location` conditions read it.
    pub alert: Option<serde_json::Value>,
}

// ── Outbound target guard ─────────────────────────────────────────────────────
//
// A multi-tenant deployment turns this on so a tenant's webhook / syslog
// target cannot reach loopback, private or link-local addresses of the platform.

static BLOCK_PRIVATE_TARGETS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_block_private_targets(on: bool) {
    BLOCK_PRIVATE_TARGETS.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Not loopback, private, link-local, CGNAT, multicast or unspecified.
pub fn is_public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified() || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64),
        std::net::IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() || (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80)
                && v6.to_ipv4_mapped().map_or(true, |v4| is_public(std::net::IpAddr::V4(v4)))
        }
    }
}

/// `Err` when the guard is on and `host` (a name or an IP) resolves to a
/// non-public address.
// shortcut: checked once before sending; DNS rebinding between this lookup and the
// request's own lookup is not covered — pin the resolved address if that matters.
pub async fn check_target(host: &str, port: u16) -> Result<(), String> {
    if !BLOCK_PRIVATE_TARGETS.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<_> = tokio::net::lookup_host((host, port)).await.map_err(|e| format!("cannot resolve {host}: {e}"))?.collect();
    if addrs.is_empty() || addrs.iter().any(|a| !is_public(a.ip())) {
        return Err(format!("target {host} is a private or internal address"));
    }
    Ok(())
}

/// [`check_target`] for an http(s) URL.
pub async fn check_url(url: &str) -> Result<(), String> {
    let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err("only http and https URLs are allowed".into());
    }
    check_target(u.host_str().unwrap_or(""), u.port_or_known_default().unwrap_or(443)).await
}

// ── Storage abstraction for SOAR actions ─────────────────────────────────────
//
// Both ndr-engine and siem-engine implement this trait on their ChStorage type.
// execute_action() in provigil-common::soar::actions takes &dyn SoarStore.

#[async_trait::async_trait]
pub trait SoarStore: Send + Sync {
    async fn soar_get_integrations(&self, tenant_id: &str) -> Vec<serde_json::Value>;
    async fn soar_find_open_case(&self, src: &str, dst: &str, tenant_id: &str) -> Option<(String, String, String, String)>;
    async fn soar_add_comment(&self, case_id: &str, author: &str, comment: &str, tenant_id: &str);
    async fn soar_escalate_case(&self, case_id: &str, severity: &str, priority: &str, tenant_id: &str);
    async fn soar_next_case_number(&self, tenant_id: &str) -> String;
    async fn soar_create_case(
        &self, id: &str, case_number: &str, title: &str, description: &str,
        severity: &str, priority: &str, status: &str, assigned_to: &str,
        src_ip: &str, dst_ip: &str, community_id: &str, tags: &[String], tenant_id: &str,
    ) -> anyhow::Result<()>;
    async fn soar_get_pcap_sessions(&self, tenant_id: &str, cid: &str, limit: usize) -> Vec<serde_json::Value>;
    async fn soar_get_events(&self, community_id: &str, tenant_id: &str) -> serde_json::Value;
    async fn soar_insert_block(&self, block: &ActiveBlock) -> anyhow::Result<()>;
    async fn soar_insert_run(&self, run: &SoarPlaybookRun) -> anyhow::Result<()>;
    /// Runs the action the product's own way: `Some((success, detail))`, or
    /// `None` for the generic action in `execute_action`.
    async fn soar_product_action(&self, _pb: &SoarNativePlaybook, _config: &serde_json::Value, _ctx: &SoarContext) -> Option<(bool, String)> {
        None
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn public_addresses() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn guard_only_when_on() {
        assert!(check_url("http://127.0.0.1:8088/x").await.is_ok());
        set_block_private_targets(true);
        assert!(check_url("http://127.0.0.1:8088/x").await.is_err());
        assert!(check_url("http://localhost/x").await.is_err());
        assert!(check_url("file:///etc/passwd").await.is_err());
        assert!(check_target("169.254.169.254", 80).await.is_err());
        set_block_private_targets(false);
    }
}
