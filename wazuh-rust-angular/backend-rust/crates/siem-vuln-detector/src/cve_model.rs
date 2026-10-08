use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

impl Severity {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CvssScore {
    pub score: f32,
    pub vector: Option<String>,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveVulnerability {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub package_name: String,
    /// Version constraint expression, e.g. ">= 5.6.0, < 5.6.2" or "< 1.1.1w"
    pub affected_version_range: String,
    pub fixed_version: Option<String>,
    pub severity: Severity,
    pub cvss: Option<CvssScore>,
    pub references: Vec<String>,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub vendor: Option<String>,
}

impl PackageInfo {
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            architecture: None,
            vendor: None,
        }
    }

    pub fn with_arch(mut self, arch: &str) -> Self {
        self.architecture = Some(arch.to_string());
        self
    }

    pub fn with_vendor(mut self, vendor: &str) -> Self {
        self.vendor = Some(vendor.to_string());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionStatus {
    Active,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnerabilityDetection {
    pub id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub package_name: String,
    pub installed_version: String,
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub fixed_version: Option<String>,
    pub mitre_technique: Option<String>,
    pub detected_at: String,
    pub status: DetectionStatus,
}
