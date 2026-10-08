use crate::cve_model::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Vulnerability Scanner Policy configuration.
/// Ported from Wazuh wazuh_modules/vulnerability_scanner/src/policyManager/policyManager.hpp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerPolicy {
    /// Whether the vulnerability detector is actively enabled
    pub enabled: bool,
    /// Periodic scan interval in seconds (default 3600 = 1 hour)
    pub scan_interval_secs: u64,
    /// Maximum alerts per second to avoid flooding SIEM storage/queues
    pub alerts_max_eps: u32,
    /// Minimum severity to trigger alerts
    pub min_severity: Severity,
    /// Minimum CVSS score threshold (e.g. 7.0 for High/Critical only)
    pub min_cvss_score: Option<f32>,
    /// Set of CVE IDs to ignore (false positives or accepted risks)
    pub ignored_cves: HashSet<String>,
    /// Allowed agent platforms ("linux", "windows", "darwin")
    pub allowed_platforms: HashSet<String>,
    /// Whether to check Windows Hotfix remediations
    pub check_hotfixes: bool,
}

impl Default for ScannerPolicy {
    fn default() -> Self {
        let mut platforms = HashSet::new();
        platforms.insert("linux".to_string());
        platforms.insert("windows".to_string());
        platforms.insert("darwin".to_string());

        Self {
            enabled: true,
            scan_interval_secs: 3600,
            alerts_max_eps: 500,
            min_severity: Severity::Low,
            min_cvss_score: None,
            ignored_cves: HashSet::new(),
            allowed_platforms: platforms,
            check_hotfixes: true,
        }
    }
}

impl ScannerPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ignore a specific CVE ID.
    pub fn ignore_cve(&mut self, cve_id: impl Into<String>) {
        self.ignored_cves.insert(cve_id.into().to_uppercase());
    }

    /// Check if a CVE ID should be skipped based on the ignored list.
    pub fn is_cve_ignored(&self, cve_id: &str) -> bool {
        self.ignored_cves.contains(&cve_id.to_uppercase())
    }

    /// Check if an agent platform is enabled for scanning.
    pub fn is_platform_allowed(&self, platform: &str) -> bool {
        self.allowed_platforms.contains(&platform.to_lowercase())
    }

    /// Check if an alert satisfies both the minimum severity and the optional minimum CVSS score.
    pub fn should_alert(&self, severity: Severity, cvss_score: Option<f32>) -> bool {
        if !self.enabled {
            return false;
        }

        if severity < self.min_severity {
            return false;
        }

        if let Some(min_cvss) = self.min_cvss_score {
            if let Some(score) = cvss_score {
                if score < min_cvss {
                    return false;
                }
            }
        }

        true
    }
}
