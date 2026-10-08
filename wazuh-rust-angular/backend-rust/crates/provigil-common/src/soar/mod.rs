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
}
