//! Rootcheck Scan Runner & Pipeline Coordinator (run_rk_check.c)
//!
//! Orchestrates the multi-stage rootkit anomaly detection passes based on active configuration
//! and produces aggregated scan results.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::RootcheckConfig;
use crate::network_checker::NetworkChecker;
use crate::process_checker::ProcessChecker;
use crate::scanner::{RootcheckDetection, RootcheckScanner};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootcheckReport {
    pub start_time: String,
    pub end_time: String,
    pub detections: Vec<RootcheckDetection>,
    pub total_alerts: usize,
    pub scan_completed: bool,
}

pub struct RootcheckRunner {
    config: RootcheckConfig,
    scanner: Arc<RootcheckScanner>,
    proc_checker: ProcessChecker,
    net_checker: NetworkChecker,
}

impl RootcheckRunner {
    pub fn new(config: RootcheckConfig, scanner: Arc<RootcheckScanner>) -> Self {
        Self {
            config,
            scanner,
            proc_checker: ProcessChecker::new(),
            net_checker: NetworkChecker::new(),
        }
    }

    /// Run full orchestrated scan pass.
    pub fn run_scan(
        &self,
        files_to_check: &[&str],
        dev_entries: &[(&str, bool, bool)], // (name, is_dir, is_device_node)
        visible_pids: &[u32],
        responsive_pids: &[u32],
        interfaces: &[(&str, bool, bool)], // (name, is_promisc, is_loopback)
        bindable_ports: &[u16],
        visible_ports: &[u16],
    ) -> RootcheckReport {
        let start_time = Utc::now().to_rfc3339();
        let mut detections = Vec::new();

        if self.config.disabled {
            return RootcheckReport {
                start_time,
                end_time: Utc::now().to_rfc3339(),
                detections: Vec::new(),
                total_alerts: 0,
                scan_completed: false,
            };
        }

        // 1. Check Rootkit Files
        if self.config.check_files {
            for &path in files_to_check {
                if let Some(det) = self.scanner.scan_file_path(path) {
                    detections.push(det);
                }
            }
        }

        // 2. Check /dev directory anomalies
        if self.config.check_dev {
            for &(name, is_dir, is_dev_node) in dev_entries {
                if let Some(det) = self.scanner.scan_dev_entry(name, is_dir, is_dev_node) {
                    detections.push(det);
                }
            }
        }

        // 3. Check Hidden Ports
        if self.config.check_ports {
            let port_dets = self.scanner.check_hidden_ports(bindable_ports, visible_ports);
            detections.extend(port_dets);
        }

        // 4. Check Hidden Processes
        if self.config.check_pids {
            let pid_dets = self.proc_checker.detect_hidden_pids(visible_pids, responsive_pids);
            detections.extend(pid_dets);
        }

        // 5. Check Promiscuous Interfaces
        if self.config.check_if {
            for &(if_name, is_promisc, is_loopback) in interfaces {
                if let Some(det) = self.net_checker.check_interface_promiscuous(if_name, is_promisc, is_loopback) {
                    detections.push(det);
                }
            }
        }

        let end_time = Utc::now().to_rfc3339();
        let total_alerts = detections.len();

        RootcheckReport {
            start_time,
            end_time,
            detections,
            total_alerts,
            scan_completed: true,
        }
    }
}
