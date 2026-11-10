use std::sync::Arc;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::signatures::RootcheckDatabase;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionType {
    RootkitFile,
    TrojanBinary,
    HiddenPort,
    DevAnomaly,
    HiddenProcess,
    ProcessAnomaly,
    PromiscuousInterface,
    SystemAnomaly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootcheckDetection {
    pub detection_type: DetectionType,
    pub title: String,
    pub details: String,
    pub target: String,
    pub timestamp: String,
    pub mitre_technique: String,
}

pub struct RootcheckScanner {
    db: Arc<RootcheckDatabase>,
}

impl RootcheckScanner {
    pub fn new(db: Arc<RootcheckDatabase>) -> Self {
        Self { db }
    }

    pub fn with_default_db() -> Self {
        Self {
            db: Arc::new(RootcheckDatabase::new_with_builtin_signatures()),
        }
    }

    /// Check if a single filesystem path matches known rootkit artifacts
    pub fn scan_file_path(&self, file_path: &str) -> Option<RootcheckDetection> {
        let normalized = file_path.trim().trim_start_matches('/').to_lowercase();

        for sig in &self.db.file_signatures {
            let sig_norm = sig.pattern.trim_start_matches('/').to_lowercase();
            if normalized.ends_with(&sig_norm) || normalized.contains(&sig_norm) {
                return Some(RootcheckDetection {
                    detection_type: DetectionType::RootkitFile,
                    title: format!("Rootkit detected: {}", sig.rootkit_name),
                    details: format!(
                        "File '{}' matches signature for {} rootkit",
                        file_path, sig.rootkit_name
                    ),
                    target: file_path.to_string(),
                    timestamp: Utc::now().to_rfc3339(),
                    mitre_technique: "T1014".to_string(), // Rootkit
                });
            }
        }
        None
    }

    /// Check if strings extracted from a binary match trojan infection patterns
    pub fn scan_binary_strings(&self, binary_name: &str, text: &str) -> Option<RootcheckDetection> {
        let bin_clean = binary_name.trim().to_lowercase();

        for sig in &self.db.trojan_signatures {
            if sig.binary_name.to_lowercase() == bin_clean {
                if sig.compiled_regex.is_match(text) {
                    return Some(RootcheckDetection {
                        detection_type: DetectionType::TrojanBinary,
                        title: format!("Infected / Trojaned system binary: {}", binary_name),
                        details: format!("{}: '{}'", sig.description, sig.pattern),
                        target: binary_name.to_string(),
                        timestamp: Utc::now().to_rfc3339(),
                        mitre_technique: "T1036".to_string(), // Masquerading
                    });
                }
            }
        }
        None
    }

    /// Check for anomalies in /dev directory (mirroring check_rc_dev.c)
    /// Finds hidden files (starting with dot) or unexpected regular files
    pub fn scan_dev_entry(&self, name: &str, is_dir: bool, is_device_node: bool) -> Option<RootcheckDetection> {
        let trimmed = name.trim();
        if trimmed == "." || trimmed == ".." {
            return None;
        }

        // Hidden files in /dev (e.g. /dev/.hidden or /dev/.shit)
        if trimmed.starts_with('.') {
            return Some(RootcheckDetection {
                detection_type: DetectionType::DevAnomaly,
                title: format!("Hidden file in /dev directory: {}", name),
                details: format!("Rootkits often hide files or binaries under /dev/. File: /dev/{}", name),
                target: format!("/dev/{}", name),
                timestamp: Utc::now().to_rfc3339(),
                mitre_technique: "T1564.001".to_string(), // Hidden Files and Directories
            });
        }

        // Regular non-device file in /dev
        if !is_dir && !is_device_node {
            return Some(RootcheckDetection {
                detection_type: DetectionType::DevAnomaly,
                title: format!("Non-device regular file in /dev: {}", name),
                details: format!("Suspicious file located in /dev that is not a character or block device: /dev/{}", name),
                target: format!("/dev/{}", name),
                timestamp: Utc::now().to_rfc3339(),
                mitre_technique: "T1036".to_string(),
            });
        }

        None
    }

    /// Check for hidden ports (mirroring check_rc_ports.c)
    /// Cross-references raw bind sockets vs visible netstat/ss ports
    pub fn check_hidden_ports(&self, bindable_ports: &[u16], visible_ports: &[u16]) -> Vec<RootcheckDetection> {
        let mut detections = Vec::new();

        // If a port fails to bind (in use), but is not reported in visible ports, it is hidden by a rootkit
        for &port in bindable_ports {
            if !visible_ports.contains(&port) {
                detections.push(RootcheckDetection {
                    detection_type: DetectionType::HiddenPort,
                    title: format!("Hidden listening port detected: {}", port),
                    details: format!("Port {} is active on the kernel interface but hidden from standard process listings", port),
                    target: format!("Port {}", port),
                    timestamp: Utc::now().to_rfc3339(),
                    mitre_technique: "T1564".to_string(), // Hide Artifacts
                });
            }
        }

        detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_rootkit_file() {
        let scanner = RootcheckScanner::with_default_db();

        let detection = scanner
            .scan_file_path("/dev/shm/.reptile")
            .expect("Reptile rootkit should be detected");

        assert_eq!(detection.detection_type, DetectionType::RootkitFile);
        assert!(detection.title.contains("Reptile"));
        assert_eq!(detection.mitre_technique, "T1014");

        // Safe file
        assert!(scanner.scan_file_path("/usr/bin/python3").is_none());
    }

    #[test]
    fn test_detect_trojan_binary() {
        let scanner = RootcheckScanner::with_default_db();

        let infected_ls = "ELF... /bin/sh -c dev/hidden ...";
        let detection = scanner
            .scan_binary_strings("ls", infected_ls)
            .expect("Infected ls should be detected");

        assert_eq!(detection.detection_type, DetectionType::TrojanBinary);
        assert!(detection.title.contains("ls"));
    }

    #[test]
    fn test_detect_dev_anomaly() {
        let scanner = RootcheckScanner::with_default_db();

        let anomaly = scanner
            .scan_dev_entry(".hidden_rootkit_dir", true, false)
            .expect("Hidden directory in /dev should be detected");

        assert_eq!(anomaly.detection_type, DetectionType::DevAnomaly);
        assert!(anomaly.target.contains(".hidden_rootkit_dir"));
    }

    #[test]
    fn test_detect_hidden_ports() {
        let scanner = RootcheckScanner::with_default_db();

        // Port 31337 is active in kernel, but hidden from netstat output
        let in_use_ports = vec![22, 80, 31337];
        let visible_ports = vec![22, 80];

        let detections = scanner.check_hidden_ports(&in_use_ports, &visible_ports);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].target, "Port 31337");
    }
}
