use crate::models::{DraftRuleStatus, ExecutionRecord, SynthesizedRuleDraft};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use uuid::Uuid;

/// Most recent execution records kept in memory (older ones live only in ClickHouse).
pub const MEM_CAP: usize = 10_000;

/// Thread-safe in-memory audit trail of all swarm execution rounds and open gaps
pub struct AuditStore {
    records: RwLock<Vec<ExecutionRecord>>,
    draft_rules: RwLock<Vec<SynthesizedRuleDraft>>,
    /// Total records ever appended; never decreases even when the in-memory list is trimmed.
    recorded_seq: AtomicU64,
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
            recorded_seq: AtomicU64::new(0),
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
        self.recorded_seq.fetch_add(1, Ordering::SeqCst);
        let overflow = records.len().saturating_sub(MEM_CAP);
        if overflow > 0 {
            records.drain(0..overflow);
        }
    }

    /// Get recent execution history (newest first)
    pub fn get_history(&self, limit: usize) -> Vec<ExecutionRecord> {
        let records = self.records.read().unwrap();
        records.iter().rev().take(limit).cloned().collect()
    }

    /// Get all open detection gaps with pending draft rules
    /// Whether a new round should draft no rule for the technique in the tenant: a draft
    /// still waits for approval (no second draft for the same gap), or the analyst rejected it.
    pub fn drafting_held(&self, tenant_id: &str, technique_id: &str) -> bool {
        let drafts = self.draft_rules.read().unwrap();
        let records = self.records.read().unwrap();
        drafts
            .iter()
            .filter(|d| matches!(d.status, DraftRuleStatus::PendingApproval | DraftRuleStatus::Rejected) && d.technique_id == technique_id)
            .any(|d| records.iter().any(|r| r.id == d.execution_id && r.tenant_id == tenant_id))
    }

    /// Every draft, pending or decided.
    pub fn drafts(&self) -> Vec<SynthesizedRuleDraft> {
        self.draft_rules.read().unwrap().clone()
    }

    /// The XML a draft was deployed with (its rule id is the one given when deployed).
    pub fn set_rule_xml(&self, draft_id: Uuid, xml: &str) {
        if let Some(d) = self.draft_rules.write().unwrap().iter_mut().find(|d| d.id == draft_id) {
            d.rule_xml = xml.to_string();
        }
    }

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

    /// Total records ever appended (the sequence number of the newest record).
    pub fn recorded_seq(&self) -> u64 {
        self.recorded_seq.load(Ordering::SeqCst)
    }

    /// Records appended after sequence `after`, in insertion order, with the new newest
    /// sequence. Survives in-memory trimming: records already trimmed were persisted earlier.
    pub fn records_after_seq(&self, after: u64) -> (Vec<ExecutionRecord>, u64) {
        let records = self.records.read().unwrap();
        let seq_end = self.recorded_seq.load(Ordering::SeqCst);
        let first_seq = seq_end - records.len() as u64; // seq of records[0] is first_seq+1
        let start = after.saturating_sub(first_seq) as usize;
        let slice = records.get(start..).map(|s| s.to_vec()).unwrap_or_default();
        (slice, seq_end)
    }

    /// All draft rules (their status changes on approve/reject/rollback).
    pub fn all_drafts(&self) -> Vec<SynthesizedRuleDraft> {
        self.draft_rules.read().unwrap().clone()
    }

    /// Take the persisted copy of the drafts (ClickHouse is the source of truth), keeping
    /// drafts made since that are not persisted yet (drafts are never deleted).
    pub fn merge_drafts(&self, mut persisted: Vec<SynthesizedRuleDraft>) {
        let mut drafts = self.draft_rules.write().unwrap();
        let known: std::collections::HashSet<Uuid> = persisted.iter().map(|d| d.id).collect();
        persisted.extend(drafts.drain(..).filter(|d| !known.contains(&d.id)));
        *drafts = persisted;
    }

    /// Repopulate the store from persisted state at startup (before the swarm loop runs).
    /// Drafts are kept separate from records' embedded copies, so they are restored explicitly.
    pub fn restore(&self, mut records: Vec<ExecutionRecord>, drafts: Vec<SynthesizedRuleDraft>) {
        let total = records.len() as u64;
        let overflow = records.len().saturating_sub(MEM_CAP);
        if overflow > 0 {
            records.drain(0..overflow);
        }
        self.recorded_seq.store(total, Ordering::SeqCst);
        *self.records.write().unwrap() = records;
        *self.draft_rules.write().unwrap() = drafts;
    }

    #[cfg(test)]
    fn record_count(&self) -> usize {
        self.records.read().unwrap().len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        CleanupStatus, DetectionVerdict, ExecutionRecord, SwarmExecutionMode, VerificationEvidence,
    };

    fn rec() -> ExecutionRecord {
        ExecutionRecord {
            id: Uuid::new_v4(),
            campaign_id: "c".into(),
            tenant_id: "default".into(),
            timestamp: chrono::Utc::now(),
            technique_id: "T1082".into(),
            technique_name: "n".into(),
            tactic: "Discovery".into(),
            mode: SwarmExecutionMode::SafeTelemetryOnly,
            target_agent_id: "001".into(),
            target_agent_name: "a".into(),
            target_agent_ip: "127.0.0.1".into(),
            target_os: "linux".into(),
            execution_success: true,
            execution_output: String::new(),
            cleanup_status: CleanupStatus::NotApplicable,
            cleanup_output: None,
            verification: VerificationEvidence {
                verdict: DetectionVerdict::Defended,
                matched_alert_id: None,
                matched_rule_id: None,
                matched_rule_description: None,
                matched_alert: None,
                retry_count: 0,
                evaluated_signals: vec![],
                reason: String::new(),
                latency_ms: 0,
            },
            draft_rule: None,
        }
    }

    // Only records appended after a given sequence are flushed, and the sequence
    // keeps counting past the in-memory cap so trimming never re-flushes old rows.
    #[test]
    fn records_after_seq_tracks_and_survives_trim() {
        let store = AuditStore::new();
        for _ in 0..3 {
            store.record_execution(rec());
        }
        assert_eq!(store.recorded_seq(), 3);
        let (new, seq) = store.records_after_seq(1);
        assert_eq!(new.len(), 2); // records 2 and 3
        assert_eq!(seq, 3);
        assert!(store.records_after_seq(3).0.is_empty());

        // restore of more than the cap trims the front but keeps the true sequence,
        // so an instance that already flushed up to `total` flushes nothing new.
        let big: Vec<_> = (0..MEM_CAP + 5).map(|_| rec()).collect();
        store.restore(big, vec![]);
        assert_eq!(store.recorded_seq(), (MEM_CAP + 5) as u64);
        assert_eq!(store.record_count(), MEM_CAP);
        assert!(store.records_after_seq((MEM_CAP + 5) as u64).0.is_empty());
        // the last 2 records are still reachable by sequence
        assert_eq!(store.records_after_seq((MEM_CAP + 3) as u64).0.len(), 2);
    }
}
