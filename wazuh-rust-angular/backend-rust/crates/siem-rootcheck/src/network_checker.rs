//! Promiscuous Network Interface & Port Anomaly Detector (check_rc_if.c, check_open_ports.c)
//!
//! Detects network interfaces running in promiscuous/sniffing mode (IFF_PROMISC)
//! and anomalous stealth listening sockets.

use chrono::Utc;
use crate::scanner::{DetectionType, RootcheckDetection};

#[derive(Debug, Clone, Default)]
pub struct NetworkChecker;

impl NetworkChecker {
    pub fn new() -> Self {
        Self
    }

    /// Check if a network interface is running in promiscuous mode.
    /// In Wazuh check_rc_if.c, interfaces with IFF_PROMISC are flagged as potential packet sniffers.
    pub fn check_interface_promiscuous(
        &self,
        interface_name: &str,
        is_promiscuous: bool,
        is_loopback: bool,
    ) -> Option<RootcheckDetection> {
        // Ignore loopback interfaces
        if is_loopback || interface_name.starts_with("lo") {
            return None;
        }

        if is_promiscuous {
            return Some(RootcheckDetection {
                detection_type: DetectionType::PromiscuousInterface,
                title: format!("Interface in promiscuous mode: {}", interface_name),
                details: format!(
                    "Network interface '{}' has the PROMISC flag enabled, indicating active packet sniffing/capture",
                    interface_name
                ),
                target: interface_name.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                mitre_technique: "T1040".to_string(), // Network Sniffing
            });
        }

        None
    }
}
