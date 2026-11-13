use std::collections::HashMap;
use crate::models::{ScaCheckResult, ScaStatus};

#[derive(Debug, Clone, Default)]
pub struct ScaPolicyStore {
    pub policy_id: String,
    pub checks: HashMap<u32, ScaCheckResult>,
}

impl ScaPolicyStore {
    pub fn new(policy_id: String) -> Self {
        Self {
            policy_id,
            checks: HashMap::new(),
        }
    }

    pub fn upsert_check(&mut self, check: ScaCheckResult) {
        self.checks.insert(check.check_id, check);
    }

    pub fn passed_count(&self) -> usize {
        self.checks
            .values()
            .filter(|c| c.status == ScaStatus::Passed)
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.checks
            .values()
            .filter(|c| c.status == ScaStatus::Failed)
            .count()
    }

    pub fn not_applicable_count(&self) -> usize {
        self.checks
            .values()
            .filter(|c| c.status == ScaStatus::NotApplicable)
            .count()
    }

    pub fn compliance_score(&self) -> f32 {
        let passed = self.passed_count() as f32;
        let failed = self.failed_count() as f32;
        let total_applicable = passed + failed;

        if total_applicable == 0.0 {
            100.0
        } else {
            (passed / total_applicable) * 100.0
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScaStore {
    policies: HashMap<String, ScaPolicyStore>,
}

impl ScaStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_policy_mut(&mut self, policy_id: &str) -> &mut ScaPolicyStore {
        self.policies
            .entry(policy_id.to_string())
            .or_insert_with(|| ScaPolicyStore::new(policy_id.to_string()))
    }

    pub fn get_policy(&self, policy_id: &str) -> Option<&ScaPolicyStore> {
        self.policies.get(policy_id)
    }

    pub fn total_policies(&self) -> usize {
        self.policies.len()
    }

    pub fn list_policies(&self) -> Vec<&ScaPolicyStore> {
        self.policies.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sca_compliance_score() {
        let mut store = ScaStore::new();
        let policy = store.get_policy_mut("cis_ubuntu24-04");

        policy.upsert_check(ScaCheckResult {
            policy_id: "cis_ubuntu24-04".to_string(),
            check_id: 1001,
            title: "Ensure /tmp is configured with nodev".to_string(),
            description: "Check fstab for /tmp mount options".to_string(),
            rationale: None,
            remediation: None,
            status: ScaStatus::Passed,
        });

        policy.upsert_check(ScaCheckResult {
            policy_id: "cis_ubuntu24-04".to_string(),
            check_id: 1002,
            title: "Ensure root login via SSH is disabled".to_string(),
            description: "Check sshd_config PermitRootLogin no".to_string(),
            rationale: None,
            remediation: None,
            status: ScaStatus::Failed,
        });

        policy.upsert_check(ScaCheckResult {
            policy_id: "cis_ubuntu24-04".to_string(),
            check_id: 1003,
            title: "Ensure legacy rsh-server is not installed".to_string(),
            description: "Check rsh-server package absence".to_string(),
            rationale: None,
            remediation: None,
            status: ScaStatus::Passed,
        });

        // 2 passed, 1 failed => 2 / 3 * 100 = 66.666%
        let score = policy.compliance_score();
        assert!((score - 66.666).abs() < 0.1);
        assert_eq!(policy.passed_count(), 2);
        assert_eq!(policy.failed_count(), 1);
    }
}
