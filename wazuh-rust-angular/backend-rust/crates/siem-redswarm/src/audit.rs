use crate::models::{DraftRuleStatus, ExecutionRecord, SynthesizedRuleDraft};
use std::sync::RwLock;
use uuid::Uuid;

/// Thread-safe in-memory audit trail of all swarm execution rounds and open gaps
pub struct AuditStore {
    records: RwLock<Vec<ExecutionRecord>>,
    draft_rules: RwLock<Vec<SynthesizedRuleDraft>>,
}

impl Default for AuditStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditStore {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(Vec::new()),
            draft_rules: RwLock::new(Vec::new()),
        }
    }

    /// Record an execution record immutably
    pub fn record_execution(&self, record: ExecutionRecord) {
        if let Some(ref draft) = record.draft_rule {
            let mut drafts = self.draft_rules.write().unwrap();
            drafts.push(draft.clone());
        }
        let mut records = self.records.write().unwrap();
        records.push(record);
    }

    /// Get recent execution history (newest first)
    pub fn get_history(&self, limit: usize) -> Vec<ExecutionRecord> {
        let records = self.records.read().unwrap();
        records.iter().rev().take(limit).cloned().collect()
    }

    /// Get all open detection gaps with pending draft rules
    pub fn get_pending_gaps(&self) -> Vec<SynthesizedRuleDraft> {
        let drafts = self.draft_rules.read().unwrap();
        drafts
            .iter()
            .filter(|d| d.status == DraftRuleStatus::PendingApproval)
            .cloned()
            .collect()
    }

    /// Get a specific rule draft by ID
    pub fn get_rule(&self, draft_id: Uuid) -> Option<SynthesizedRuleDraft> {
        let drafts = self.draft_rules.read().unwrap();
        drafts.iter().find(|d| d.id == draft_id).cloned()
    }

    /// Get all currently approved and deployed rules
    pub fn get_approved_rules(&self) -> Vec<SynthesizedRuleDraft> {
        let drafts = self.draft_rules.read().unwrap();
        drafts
            .iter()
            .filter(|d| d.status == DraftRuleStatus::ApprovedAndDeployed)
            .cloned()
            .collect()
    }

    /// Approve and deploy a synthesized rule draft
    pub fn approve_rule(&self, draft_id: Uuid) -> Result<SynthesizedRuleDraft, String> {
        let mut drafts = self.draft_rules.write().unwrap();
        if let Some(draft) = drafts.iter_mut().find(|d| d.id == draft_id) {
            draft.status = DraftRuleStatus::ApprovedAndDeployed;
            return Ok(draft.clone());
        }
        Err(format!("Draft rule with ID {} not found", draft_id))
    }

    /// Reject a synthesized rule draft
    pub fn reject_rule(&self, draft_id: Uuid) -> Result<SynthesizedRuleDraft, String> {
        let mut drafts = self.draft_rules.write().unwrap();
        if let Some(draft) = drafts.iter_mut().find(|d| d.id == draft_id) {
            draft.status = DraftRuleStatus::Rejected;
            return Ok(draft.clone());
        }
        Err(format!("Draft rule with ID {} not found", draft_id))
    }

    /// Roll back an approved synthesized rule
    pub fn rollback_rule(&self, draft_id: Uuid) -> Result<SynthesizedRuleDraft, String> {
        let mut drafts = self.draft_rules.write().unwrap();
        if let Some(draft) = drafts.iter_mut().find(|d| d.id == draft_id) {
            draft.status = DraftRuleStatus::RolledBack;
            return Ok(draft.clone());
        }
        Err(format!("Draft rule with ID {} not found", draft_id))
    }

    /// Get total counts
    pub fn get_stats(&self) -> (u64, u64, u64, usize) {
        let records = self.records.read().unwrap();
        let total = records.len() as u64;
        let defended = records
            .iter()
            .filter(|r| r.verification.verdict == crate::models::DetectionVerdict::Defended)
            .count() as u64;
        let gaps = total.saturating_sub(defended);
        let drafts = self.draft_rules.read().unwrap();
        let open_gaps = drafts
            .iter()
            .filter(|d| d.status == DraftRuleStatus::PendingApproval)
            .count();
        (total, defended, gaps, open_gaps)
    }
}
