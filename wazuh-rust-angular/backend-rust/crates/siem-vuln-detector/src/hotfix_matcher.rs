use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// Represents an installed Windows Hotfix (KB update).
/// Ported from Wazuh scanOrchestrator/hotfixInsert.hpp & databaseFeedManager/updateHotfixes.hpp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hotfix {
    pub hotfix_id: String, // e.g., "KB5005565", "KB4012212"
    pub installed_on: Option<String>,
}

impl Hotfix {
    pub fn new(hotfix_id: impl Into<String>) -> Self {
        let mut id = hotfix_id.into().to_uppercase();
        if !id.starts_with("KB") && id.chars().all(|c| c.is_ascii_digit()) {
            id = format!("KB{}", id);
        }
        Self {
            hotfix_id: id,
            installed_on: None,
        }
    }
}

/// Hotfix remediation database that correlates CVE IDs with the KBs that resolve them.
#[derive(Debug, Clone, Default)]
pub struct HotfixDatabase {
    /// Maps CVE ID -> Set of KB identifiers that remediate it
    cve_to_kbs: HashMap<String, HashSet<String>>,
    /// Maps KB identifier -> Set of CVE identifiers it fixes
    kb_to_cves: HashMap<String, HashSet<String>>,
}

impl HotfixDatabase {
    pub fn new() -> Self {
        let mut db = Self::default();
        db.load_builtin_remediations();
        db
    }

    /// Register a remediation mapping: a KB patch that resolves a CVE.
    pub fn add_remediation(&mut self, cve_id: impl Into<String>, hotfix_id: impl Into<String>) {
        let cve = cve_id.into().to_uppercase();
        let mut kb = hotfix_id.into().to_uppercase();
        if !kb.starts_with("KB") && kb.chars().all(|c| c.is_ascii_digit()) {
            kb = format!("KB{}", kb);
        }

        self.cve_to_kbs
            .entry(cve.clone())
            .or_default()
            .insert(kb.clone());

        self.kb_to_cves
            .entry(kb)
            .or_default()
            .insert(cve);
    }

    /// Check if a CVE is remediated given a list of installed hotfixes.
    pub fn is_cve_remediated(&self, cve_id: &str, installed_hotfixes: &[Hotfix]) -> bool {
        let cve = cve_id.to_uppercase();
        if let Some(required_kbs) = self.cve_to_kbs.get(&cve) {
            for installed in installed_hotfixes {
                let inst_id = installed.hotfix_id.to_uppercase();
                if required_kbs.contains(&inst_id) {
                    return true;
                }
            }
        }
        false
    }

    /// Return all CVEs resolved by a specific hotfix.
    pub fn get_cves_for_hotfix(&self, hotfix_id: &str) -> Vec<String> {
        let mut kb = hotfix_id.to_uppercase();
        if !kb.starts_with("KB") && kb.chars().all(|c| c.is_ascii_digit()) {
            kb = format!("KB{}", kb);
        }

        self.kb_to_cves
            .get(&kb)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Pre-load common critical Windows security updates (EternalBlue, PrintNightmare, BlueKeep, Zerologon).
    fn load_builtin_remediations(&mut self) {
        // MS17-010 EternalBlue (CVE-2017-0144, CVE-2017-0145)
        self.add_remediation("CVE-2017-0144", "KB4012212");
        self.add_remediation("CVE-2017-0144", "KB4012215");
        self.add_remediation("CVE-2017-0144", "KB4012606");

        // BlueKeep RDP RCE (CVE-2019-0708)
        self.add_remediation("CVE-2019-0708", "KB4499175");
        self.add_remediation("CVE-2019-0708", "KB4499180");
        self.add_remediation("CVE-2019-0708", "KB4500331");

        // Zerologon Netlogon Elevation of Privilege (CVE-2020-1472)
        self.add_remediation("CVE-2020-1472", "KB4571694");
        self.add_remediation("CVE-2020-1472", "KB4571702");

        // PrintNightmare Windows Print Spooler RCE (CVE-2021-34527)
        self.add_remediation("CVE-2021-34527", "KB5004945");
        self.add_remediation("CVE-2021-34527", "KB5005010");
        self.add_remediation("CVE-2021-34527", "KB5005565");

        // Follina MSDT Remote Code Execution (CVE-2022-30190)
        self.add_remediation("CVE-2022-30190", "KB5014697");
        self.add_remediation("CVE-2022-30190", "KB5014699");

        // HTTP.sys Remote Code Execution (CVE-2022-21907)
        self.add_remediation("CVE-2022-21907", "KB5009543");
        self.add_remediation("CVE-2022-21907", "KB5009566");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotfix_matching_remediates_cve() {
        let db = HotfixDatabase::new();

        // PrintNightmare without patch
        let unpatched_kbs = vec![Hotfix::new("KB5001330")];
        assert!(!db.is_cve_remediated("CVE-2021-34527", &unpatched_kbs));

        // PrintNightmare with KB5005565 installed
        let patched_kbs = vec![Hotfix::new("KB5001330"), Hotfix::new("KB5005565")];
        assert!(db.is_cve_remediated("CVE-2021-34527", &patched_kbs));
    }

    #[test]
    fn test_hotfix_formatting() {
        let hf = Hotfix::new("5005565");
        assert_eq!(hf.hotfix_id, "KB5005565");

        let hf2 = Hotfix::new("kb5005565");
        assert_eq!(hf2.hotfix_id, "KB5005565");
    }
}
