use crate::cve_model::{DetectionStatus, Severity, VulnerabilityDetection};
use crate::hotfix_matcher::{Hotfix, HotfixDatabase};
use crate::version_matcher::matches_version_range;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Operating System information reported by Wazuh syscollector / agent.
/// Ported from Wazuh scanOrchestrator/osScanner.hpp & osDataCache.hpp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub platform: String,              // "linux", "windows", "darwin"
    pub name: String,                  // "Ubuntu", "Microsoft Windows 10 Pro", "Debian"
    pub version: String,               // "22.04", "10.0.19045", "11"
    pub kernel_release: Option<String>, // "5.15.0-89-generic", "10.0.19045.3570"
    pub architecture: Option<String>,  // "x86_64", "arm64"
    pub cpe: Option<String>,           // "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*"
    pub hotfixes: Vec<Hotfix>,         // Installed KBs on Windows systems
}

impl OsInfo {
    pub fn new(platform: impl Into<String>, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            platform: platform.into().to_lowercase(),
            name: name.into(),
            version: version.into(),
            kernel_release: None,
            architecture: Some("x86_64".into()),
            cpe: None,
            hotfixes: Vec::new(),
        }
    }

    pub fn with_kernel(mut self, kernel: impl Into<String>) -> Self {
        self.kernel_release = Some(kernel.into());
        self
    }

    pub fn with_hotfixes(mut self, hotfixes: Vec<Hotfix>) -> Self {
        self.hotfixes = hotfixes;
        self
    }

    pub fn with_cpe(mut self, cpe: impl Into<String>) -> Self {
        self.cpe = Some(cpe.into());
        self
    }
}

/// OS-level vulnerability definition from NVD / vendor advisories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsVulnerability {
    pub cve_id: String,
    pub title: String,
    pub target_platform: String,
    pub target_os_name: Option<String>,
    pub kernel_range: Option<String>,
    pub os_version_range: Option<String>,
    pub required_hotfix: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub description: String,
    pub mitre_technique: Option<String>,
}

/// OS vulnerability scanner ported from Wazuh scanOrchestrator/osScanner.hpp.
pub struct OsScanner {
    os_cves: Vec<OsVulnerability>,
    hotfix_db: HotfixDatabase,
}

impl Default for OsScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl OsScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            os_cves: Vec::new(),
            hotfix_db: HotfixDatabase::new(),
        };
        scanner.load_builtin_os_cves();
        scanner
    }

    pub fn add_os_vulnerability(&mut self, vuln: OsVulnerability) {
        self.os_cves.push(vuln);
    }

    /// Scan an agent's OS and installed hotfixes for OS-level vulnerabilities.
    pub fn scan_os(
        &self,
        os_info: &OsInfo,
        agent_id: &str,
        agent_name: &str,
    ) -> Vec<VulnerabilityDetection> {
        let mut detections = Vec::new();

        for cve in &self.os_cves {
            // Platform check (e.g., "linux" vs "windows")
            if !cve.target_platform.is_empty() && cve.target_platform != os_info.platform {
                continue;
            }

            // OS Name filter if specified (e.g. "Ubuntu", "Windows")
            if let Some(target_os) = &cve.target_os_name {
                if !os_info.name.to_lowercase().contains(&target_os.to_lowercase()) {
                    continue;
                }
            }

            // Windows Hotfix check: If the CVE is resolved by an installed hotfix, skip it!
            if os_info.platform == "windows" {
                if self.hotfix_db.is_cve_remediated(&cve.cve_id, &os_info.hotfixes) {
                    continue;
                }
                if let Some(req_kb) = &cve.required_hotfix {
                    if os_info.hotfixes.iter().any(|h| h.hotfix_id.eq_ignore_ascii_case(req_kb)) {
                        continue;
                    }
                }
            }

            // Check OS Version constraints if defined
            let mut version_matches = true;
            if let Some(range) = &cve.os_version_range {
                version_matches = matches_version_range(&os_info.version, range);
            }

            // Check Kernel release constraints if defined (critical for Linux kernel vulnerabilities)
            let mut kernel_matches = true;
            if let Some(range) = &cve.kernel_range {
                if let Some(kernel) = &os_info.kernel_release {
                    // Extract version prefix before distribution suffix (e.g., "5.15.0-89-generic" -> "5.15.0")
                    let clean_kernel = kernel.split('-').next().unwrap_or(kernel);
                    kernel_matches = matches_version_range(clean_kernel, range);
                } else {
                    kernel_matches = false;
                }
            }

            if version_matches && kernel_matches {
                detections.push(VulnerabilityDetection {
                    id: format!("{}:{}:{}", agent_id, cve.cve_id, os_info.name),
                    agent_id: agent_id.to_string(),
                    agent_name: agent_name.to_string(),
                    package_name: format!("kernel/{}", os_info.name),
                    installed_version: os_info.kernel_release.clone().unwrap_or_else(|| os_info.version.clone()),
                    cve_id: cve.cve_id.clone(),
                    title: cve.title.clone(),
                    description: cve.description.clone(),
                    severity: cve.severity,
                    cvss_score: cve.cvss_score,
                    fixed_version: None,
                    mitre_technique: cve.mitre_technique.clone(),
                    detected_at: Utc::now().to_rfc3339(),
                    status: DetectionStatus::Active,
                });
            }
        }

        detections
    }

    /// Load well-known OS kernel and OS-level vulnerabilities
    fn load_builtin_os_cves(&mut self) {
        // Dirty Pipe (CVE-2022-0847) Linux kernel local privilege escalation
        self.add_os_vulnerability(OsVulnerability {
            cve_id: "CVE-2022-0847".into(),
            title: "Dirty Pipe: Linux Kernel Arbitrary File Overwrite & Privilege Escalation".into(),
            target_platform: "linux".into(),
            target_os_name: None,
            kernel_range: Some(">= 5.8, < 5.16.11".into()),
            os_version_range: None,
            required_hotfix: None,
            severity: Severity::High,
            cvss_score: Some(7.8),
            description: "A flaw in the Linux kernel pipe buffer structure allows unauthorized overwriting of read-only files.".into(),
            mitre_technique: Some("T1068".into()),
        });

        // EternalBlue (CVE-2017-0144) Windows SMBv1 Remote Code Execution
        self.add_os_vulnerability(OsVulnerability {
            cve_id: "CVE-2017-0144".into(),
            title: "EternalBlue: Microsoft SMBv1 Remote Code Execution".into(),
            target_platform: "windows".into(),
            target_os_name: Some("Windows".into()),
            kernel_range: None,
            os_version_range: Some("< 10.0.15063".into()),
            required_hotfix: Some("KB4012212".into()),
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            description: "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets.".into(),
            mitre_technique: Some("T1210".into()),
        });

        // PrintNightmare (CVE-2021-34527) Windows Print Spooler RCE
        self.add_os_vulnerability(OsVulnerability {
            cve_id: "CVE-2021-34527".into(),
            title: "PrintNightmare: Windows Print Spooler Remote Code Execution".into(),
            target_platform: "windows".into(),
            target_os_name: Some("Windows".into()),
            kernel_range: None,
            os_version_range: None,
            required_hotfix: Some("KB5005565".into()),
            severity: Severity::Critical,
            cvss_score: Some(8.8),
            description: "Windows Print Spooler Service contains a remote code execution vulnerability allowing SYSTEM privileges.".into(),
            mitre_technique: Some("T1068".into()),
        });
    }
}
