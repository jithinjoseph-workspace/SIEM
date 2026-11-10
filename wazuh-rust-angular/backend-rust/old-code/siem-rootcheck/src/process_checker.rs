//! Hidden Process Anomaly Detector (check_rc_pids.c, unix-process.c, win-process.c)
//!
//! Detects stealth processes hidden from process enumeration (/proc, EnumProcesses)
//! by cross-referencing against kernel process probe responses.

use chrono::Utc;
use std::collections::HashSet;
use crate::scanner::{DetectionType, RootcheckDetection};

#[derive(Debug, Clone, Default)]
pub struct ProcessChecker;

impl ProcessChecker {
    pub fn new() -> Self {
        Self
    }

    /// Check for stealth/hidden PIDs by comparing visible PIDs (from /proc or ps)
    /// against probed responsive PIDs (via direct syscall or kernel probe).
    pub fn detect_hidden_pids(
        &self,
        visible_pids: &[u32],
        probed_responsive_pids: &[u32],
    ) -> Vec<RootcheckDetection> {
        let visible_set: HashSet<u32> = visible_pids.iter().cloned().collect();
        let mut detections = Vec::new();

        for &pid in probed_responsive_pids {
            if pid == 0 {
                continue;
            }
            if !visible_set.contains(&pid) {
                detections.push(RootcheckDetection {
                    detection_type: DetectionType::HiddenProcess,
                    title: format!("Hidden process detected: PID {}", pid),
                    details: format!(
                        "Process ID {} responds to system kernel probe but is hidden from process listings (/proc, ps)",
                        pid
                    ),
                    target: format!("PID:{}", pid),
                    timestamp: Utc::now().to_rfc3339(),
                    mitre_technique: "T1014".to_string(), // Rootkit / Process Hiding
                });
            }
        }

        detections
    }

    /// Inspect a process entry for anomalous attributes (e.g. deleted executable, mismatch).
    pub fn inspect_process_anomaly(
        &self,
        pid: u32,
        exe_path: &str,
        cmdline: &str,
    ) -> Option<RootcheckDetection> {
        // 1. Process running from unlinked / deleted binary
        if exe_path.contains("(deleted)") || exe_path.ends_with(".deleted") {
            return Some(RootcheckDetection {
                detection_type: DetectionType::ProcessAnomaly,
                title: format!("Process running from deleted binary: PID {}", pid),
                details: format!(
                    "PID {} executable was deleted from disk while continuing to run: '{}'",
                    pid, exe_path
                ),
                target: format!("PID:{}", pid),
                timestamp: Utc::now().to_rfc3339(),
                mitre_technique: "T1070.004".to_string(), // File Deletion
            });
        }

        // 2. Binary masquerading or suspicious memory execution (e.g. /dev/shm, /tmp)
        if exe_path.starts_with("/dev/shm/") || exe_path.starts_with("/tmp/") || exe_path.starts_with("/var/tmp/") {
            return Some(RootcheckDetection {
                detection_type: DetectionType::ProcessAnomaly,
                title: format!("Process executing from volatile directory: PID {}", pid),
                details: format!(
                    "PID {} is executing from temporary memory-backed directory: '{}' with cmd: '{}'",
                    pid, exe_path, cmdline
                ),
                target: format!("PID:{}", pid),
                timestamp: Utc::now().to_rfc3339(),
                mitre_technique: "T1036.005".to_string(),
            });
        }

        None
    }
}
