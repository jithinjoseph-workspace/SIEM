use std::collections::HashMap;
use crate::cve_model::{CveVulnerability, CvssScore, Severity};

#[derive(Debug, Clone)]
pub struct VulnerabilityFeed {
    /// Maps normalized lowercase package name to list of CVE vulnerabilities
    cve_by_package: HashMap<String, Vec<CveVulnerability>>,
}

impl Default for VulnerabilityFeed {
    fn default() -> Self {
        Self::new_with_builtin_feed()
    }
}

impl VulnerabilityFeed {
    pub fn new() -> Self {
        Self {
            cve_by_package: HashMap::new(),
        }
    }

    pub fn add_cve(&mut self, cve: CveVulnerability) {
        let key = cve.package_name.to_lowercase();
        self.cve_by_package.entry(key).or_default().push(cve);
    }

    pub fn find_by_package(&self, package_name: &str) -> Option<&Vec<CveVulnerability>> {
        self.cve_by_package.get(&package_name.to_lowercase())
    }

    pub fn total_cves(&self) -> usize {
        self.cve_by_package.values().map(|v| v.len()).sum()
    }

    pub fn total_packages(&self) -> usize {
        self.cve_by_package.len()
    }

    /// Load CVE definitions from a JSON string (e.g., Wazuh feed format or custom feed)
    pub fn load_from_json(&mut self, json_str: &str) -> Result<usize, serde_json::Error> {
        let cves: Vec<CveVulnerability> = serde_json::from_str(json_str)?;
        let count = cves.len();
        for cve in cves {
            self.add_cve(cve);
        }
        Ok(count)
    }

    /// Initializes feed with comprehensive built-in CVE signatures for common server/desktop software
    pub fn new_with_builtin_feed() -> Self {
        let mut feed = Self::new();

        // 1. xz-utils / liblzma Backdoor (CVE-2024-3094)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2024-3094".to_string(),
            title: "XZ Utils / liblzma Malicious Code Injection (Backdoor)".to_string(),
            description: "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file, which modifies functions in the liblzma code to intercept OpenSSH authentication.".to_string(),
            package_name: "xz-utils".to_string(),
            affected_version_range: ">= 5.6.0, < 5.6.2".to_string(),
            fixed_version: Some("5.6.2".to_string()),
            severity: Severity::Critical,
            cvss: Some(CvssScore {
                score: 10.0,
                vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3094".to_string(),
                "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library".to_string(),
            ],
            mitre_technique: Some("T1195.001".to_string()), // Supply Chain Compromise
        });

        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2024-3094".to_string(),
            title: "XZ Utils / liblzma Malicious Code Injection (Backdoor)".to_string(),
            description: "liblzma package compromised with backdoor".to_string(),
            package_name: "liblzma5".to_string(),
            affected_version_range: ">= 5.6.0, < 5.6.2".to_string(),
            fixed_version: Some("5.6.2".to_string()),
            severity: Severity::Critical,
            cvss: Some(CvssScore {
                score: 10.0,
                vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-3094".to_string()],
            mitre_technique: Some("T1195.001".to_string()),
        });

        // 2. OpenSSH regreSSHion (CVE-2024-6387)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2024-6387".to_string(),
            title: "OpenSSH Server Remote Unauthenticated Code Execution (regreSSHion)".to_string(),
            description: "A signal handler race condition vulnerability in OpenSSH's server (sshd) allows unauthenticated remote attackers to execute arbitrary code with root privileges on glibc-based Linux systems.".to_string(),
            package_name: "openssh-server".to_string(),
            affected_version_range: ">= 8.5, < 9.8".to_string(),
            fixed_version: Some("9.8p1".to_string()),
            severity: Severity::Critical,
            cvss: Some(CvssScore {
                score: 9.8,
                vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec![
                "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt".to_string(),
            ],
            mitre_technique: Some("T1190".to_string()), // Exploit Public-Facing Application
        });

        // 3. Sudo Baron Samedit (CVE-2021-3156)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2021-3156".to_string(),
            title: "Sudo Heap-Based Buffer Overflow Privilege Escalation (Baron Samedit)".to_string(),
            description: "Sudo before 1.9.5p2 has a Heap-based Buffer Overflow, allowing privilege escalation to root via \"sudoedit -s\" and a command-line argument that ends with a single backslash character.".to_string(),
            package_name: "sudo".to_string(),
            affected_version_range: ">= 1.8.2, < 1.9.5p2".to_string(),
            fixed_version: Some("1.9.5p2".to_string()),
            severity: Severity::High,
            cvss: Some(CvssScore {
                score: 7.8,
                vector: Some("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-3156".to_string()],
            mitre_technique: Some("T1068".to_string()), // Exploitation for Privilege Escalation
        });

        // 4. Polkit PwnKit (CVE-2021-4034)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2021-4034".to_string(),
            title: "Polkit Local Privilege Escalation (PwnKit)".to_string(),
            description: "A local privilege escalation vulnerability in Polkit's pkexec utility allows any unprivileged local attacker to gain full root privileges on default installations of major Linux distributions.".to_string(),
            package_name: "policykit-1".to_string(),
            affected_version_range: "< 0.105-31".to_string(),
            fixed_version: Some("0.105-31.1".to_string()),
            severity: Severity::High,
            cvss: Some(CvssScore {
                score: 7.8,
                vector: Some("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-4034".to_string()],
            mitre_technique: Some("T1068".to_string()),
        });

        // 5. Glibc Looney Tunables (CVE-2023-4911)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2023-4911".to_string(),
            title: "GNU C Library Buffer Overflow in ld.so (Looney Tunables)".to_string(),
            description: "A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue allows a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when executing binaries with SUID permission to gain root privileges.".to_string(),
            package_name: "libc6".to_string(),
            affected_version_range: ">= 2.34, < 2.38-3".to_string(),
            fixed_version: Some("2.38-3".to_string()),
            severity: Severity::High,
            cvss: Some(CvssScore {
                score: 7.8,
                vector: Some("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-4911".to_string()],
            mitre_technique: Some("T1068".to_string()),
        });

        // 6. cURL SOCKS5 Heap Buffer Overflow (CVE-2023-38545)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2023-38545".to_string(),
            title: "cURL SOCKS5 Heap Buffer Overflow".to_string(),
            description: "This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake. When curl is asked to pass along the hostname to the SOCKS5 proxy to allow that to resolve the address, the address string can be longer than 255 bytes.".to_string(),
            package_name: "curl".to_string(),
            affected_version_range: ">= 7.69.0, < 8.4.0".to_string(),
            fixed_version: Some("8.4.0".to_string()),
            severity: Severity::High,
            cvss: Some(CvssScore {
                score: 8.1,
                vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://curl.se/docs/CVE-2023-38545.html".to_string()],
            mitre_technique: Some("T1190".to_string()),
        });

        // 7. OpenSSL X.509 Email Address Buffer Overflow (CVE-2022-3602)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2022-3602".to_string(),
            title: "OpenSSL X.509 Email Address 4-byte Buffer Overflow".to_string(),
            description: "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. An attacker can craft a malicious email address in a certificate to cause stack corruption.".to_string(),
            package_name: "openssl".to_string(),
            affected_version_range: ">= 3.0.0, < 3.0.7".to_string(),
            fixed_version: Some("3.0.7".to_string()),
            severity: Severity::High,
            cvss: Some(CvssScore {
                score: 8.8,
                vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://www.openssl.org/news/secadv/20221101.txt".to_string()],
            mitre_technique: Some("T1190".to_string()),
        });

        // 8. Log4j Log4Shell Remote Code Execution (CVE-2021-44228)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2021-44228".to_string(),
            title: "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)".to_string(),
            description: "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.".to_string(),
            package_name: "log4j".to_string(),
            affected_version_range: ">= 2.0.0, < 2.16.0".to_string(),
            fixed_version: Some("2.16.0".to_string()),
            severity: Severity::Critical,
            cvss: Some(CvssScore {
                score: 10.0,
                vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()],
            mitre_technique: Some("T1190".to_string()),
        });

        // 9. NGINX 1-Byte Memory Overwrite (CVE-2021-23017)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2021-23017".to_string(),
            title: "NGINX DNS Resolver 1-Byte Memory Overwrite".to_string(),
            description: "A security issue in nginx resolver allows an attacker who can forge UDP packets from the DNS server to cause 1-byte memory overwrite resulting in worker process crash or potential code execution.".to_string(),
            package_name: "nginx".to_string(),
            affected_version_range: ">= 0.6.18, < 1.20.1".to_string(),
            fixed_version: Some("1.20.1".to_string()),
            severity: Severity::Medium,
            cvss: Some(CvssScore {
                score: 6.8,
                vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23017".to_string()],
            mitre_technique: Some("T1190".to_string()),
        });

        // 10. Git Remote Code Execution via Submodules (CVE-2024-32002)
        feed.add_cve(CveVulnerability {
            cve_id: "CVE-2024-32002".to_string(),
            title: "Git Remote Code Execution via Recursive Clone of Repositories with Submodules".to_string(),
            description: "Repositories with submodules can be crafted in a way that exploits a bug in Git where case-insensitive filesystems write the submodule's worktree to the parent repository's .git/ directory, triggering arbitrary code execution during clone.".to_string(),
            package_name: "git".to_string(),
            affected_version_range: ">= 2.45.0, < 2.45.1".to_string(),
            fixed_version: Some("2.45.1".to_string()),
            severity: Severity::Critical,
            cvss: Some(CvssScore {
                score: 9.0,
                vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H".to_string()),
                version: "3.1".to_string(),
            }),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-32002".to_string()],
            mitre_technique: Some("T1204".to_string()),
        });

        feed
    }
}
