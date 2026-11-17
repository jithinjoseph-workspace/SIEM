use crate::models::{BusinessProcessDefinition, BusinessTimeWindow, RiskFabricConfig};
use std::fs;
use std::path::Path;
use tracing::info;

pub fn load_config(path: &Path) -> Option<RiskFabricConfig> {
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(cfg) = serde_json::from_str::<RiskFabricConfig>(&content) {
                return Some(cfg);
            }
        }
    }
    None
}

pub fn default_config() -> RiskFabricConfig {
    let processes = vec![
        BusinessProcessDefinition {
            id: "bp-pci-payment".to_string(),
            name: "Payment Settlement & Gateway (PCI-DSS)".to_string(),
            description: "Critical cardholder data environment, checkout APIs, and financial transaction settlement.".to_string(),
            criticality: "Mission-Critical".to_string(),
            asset_weight: 2.4,
            identity_weight: 1.8,
            asset_patterns: vec![
                "*payment*".into(),
                "pay-*".into(),
                "*-pay-*".into(),
                "*swift*".into(),
                "pos-*".into(),
                "*-pos-*".into(),
                "*checkout*".into(),
            ],
            group_patterns: vec![
                "pci*".into(),
                "*payment*".into(),
                "finance".into(),
            ],
            identity_patterns: vec![
                "*cashier*".into(),
                "*finance*".into(),
                "*settlement*".into(),
                "*pci*".into(),
            ],
            impact_template: "Direct threat to payment settlement pipeline; elevated risk of transaction manipulation, wire redirection, or PCI-DSS cardholder data compromise.".to_string(),
            enabled: true,
        },
        BusinessProcessDefinition {
            id: "bp-core-iam".to_string(),
            name: "Core Active Directory & IAM Authority".to_string(),
            description: "Central identity provider, Kerberos domain controllers, and privileged credential vaults.".to_string(),
            criticality: "Mission-Critical".to_string(),
            asset_weight: 2.5,
            identity_weight: 2.0,
            asset_patterns: vec![
                "dc-*".into(),
                "*-dc-*".into(),
                "*-dc".into(),
                "dc0*".into(),
                "dc1*".into(),
                "*domain-controller*".into(),
                "*iam*".into(),
                "auth-*".into(),
                "*-auth-*".into(),
                "*ldap*".into(),
                "*vault*".into(),
                "*kerberos*".into(),
            ],
            group_patterns: vec![
                "*domain-controllers*".into(),
                "*iam*".into(),
                "*active-directory*".into(),
            ],
            identity_patterns: vec![
                "administrator".into(),
                "admin*".into(),
                "root".into(),
                "svc_*".into(),
                "*ciso*".into(),
                "cio".into(),
                "*secops*".into(),
            ],
            impact_template: "Core identity authority or privileged account impacted; high potential for domain-wide golden ticket creation, privilege escalation, and lateral movement.".to_string(),
            enabled: true,
        },
        BusinessProcessDefinition {
            id: "bp-dmz-web".to_string(),
            name: "Customer-Facing Ingress & Web DMZ".to_string(),
            description: "Public reverse proxies, web application servers, and external API gateways.".to_string(),
            criticality: "High".to_string(),
            asset_weight: 1.6,
            identity_weight: 1.2,
            asset_patterns: vec![
                "*web*".into(),
                "*nginx*".into(),
                "*apache*".into(),
                "*ingress*".into(),
                "api-*".into(),
                "*-api*".into(),
                "*portal*".into(),
            ],
            group_patterns: vec![
                "*web*".into(),
                "*dmz*".into(),
                "*ingress*".into(),
            ],
            identity_patterns: vec![
                "www-data".into(),
                "nginx".into(),
                "apache".into(),
            ],
            impact_template: "Perimeter service exploit or unauthorized ingress activity; threat to customer service availability and potential perimeter foothold.".to_string(),
            enabled: true,
        },
        BusinessProcessDefinition {
            id: "bp-corp-erp".to_string(),
            name: "Corporate ERP & Supply Chain".to_string(),
            description: "Enterprise resource planning, relational databases, supply chain logistics, and HR databases.".to_string(),
            criticality: "High".to_string(),
            asset_weight: 1.5,
            identity_weight: 1.3,
            asset_patterns: vec![
                "*erp*".into(),
                "*sap*".into(),
                "*crm*".into(),
                "*database*".into(),
                "*sql*".into(),
                "*postgres*".into(),
            ],
            group_patterns: vec![
                "*erp*".into(),
                "*database*".into(),
                "*sql*".into(),
            ],
            identity_patterns: vec![
                "*operator*".into(),
                "*dba*".into(),
                "*erp*".into(),
            ],
            impact_template: "Corporate ERP or backend database impacted; potential disruption to supply chain logistics or unauthorized business records access.".to_string(),
            enabled: true,
        },
        BusinessProcessDefinition {
            id: "bp-win-corp".to_string(),
            name: "Corporate Windows Workstations & Fleet".to_string(),
            description: "Windows domain hosts, workstations, and endpoint fleet nodes.".to_string(),
            criticality: "High".to_string(),
            asset_weight: 2.1,
            identity_weight: 1.8,
            asset_patterns: vec![
                "*win*".into(),
            ],
            group_patterns: vec![
                "*windows*".into(),
                "*workstation*".into(),
                "default".into(),
            ],
            identity_patterns: vec![
                "administrator".into(),
                "admin*".into(),
            ],
            impact_template: "Windows domain host security event detected; potential active lateral pivot, credential access, or defense evasion.".to_string(),
            enabled: true,
        },
        BusinessProcessDefinition {
            id: "bp-linux-prod".to_string(),
            name: "Enterprise Linux Workload Infrastructure".to_string(),
            description: "Enterprise Linux servers, application containers, and daemon workloads.".to_string(),
            criticality: "High".to_string(),
            asset_weight: 2.0,
            identity_weight: 1.8,
            asset_patterns: vec![
                "*linux*".into(),
                "*ubuntu*".into(),
                "*debian*".into(),
                "*rhel*".into(),
            ],
            group_patterns: vec![
                "*linux*".into(),
                "*server*".into(),
                "default".into(),
            ],
            identity_patterns: vec![
                "root".into(),
                "wheel".into(),
                "admin*".into(),
            ],
            impact_template: "Linux host telemetry alert; elevated potential for privilege escalation, root compromise, or daemon abuse.".to_string(),
            enabled: true,
        },
        BusinessProcessDefinition {
            id: "bp-dev-sandbox".to_string(),
            name: "Non-Production Dev & Lab Sandbox".to_string(),
            description: "Software development staging nodes, QA clusters, and test environments.".to_string(),
            criticality: "Low".to_string(),
            asset_weight: 0.4,
            identity_weight: 0.8,
            asset_patterns: vec![
                "dev-*".into(),
                "*-dev".into(),
                "*-dev-*".into(),
                "*test*".into(),
                "*stage*".into(),
                "qa-*".into(),
                "*-qa".into(),
                "*sandbox*".into(),
                "*lab*".into(),
            ],
            group_patterns: vec![
                "*dev*".into(),
                "*test*".into(),
                "*sandbox*".into(),
            ],
            identity_patterns: vec![
                "*tester*".into(),
                "*intern*".into(),
                "dev-*".into(),
                "*-dev".into(),
            ],
            impact_template: "Isolated development or QA asset activity; low enterprise operational risk, suppressed from high-urgency SOC response.".to_string(),
            enabled: true,
        },
    ];

    let time_windows = vec![
        BusinessTimeWindow {
            id: "tw-financial-close".to_string(),
            name: "Month-End Financial Close Window".to_string(),
            description: "Heightened scrutiny period for accounting, banking, and payment systems during reconciliation.".to_string(),
            multiplier: 1.45,
            window_type: "recurring_schedule".to_string(),
            start_date: None,
            end_date: None,
            active: true,
            target_processes: vec!["bp-pci-payment".into(), "bp-corp-erp".into()],
        },
        BusinessTimeWindow {
            id: "tw-maintenance-window".to_string(),
            name: "Scheduled Infrastructure Maintenance".to_string(),
            description: "Authorized patching and vulnerability assessment window; technical alerts de-escalated to reduce alarm fatigue.".to_string(),
            multiplier: 0.40,
            window_type: "recurring_schedule".to_string(),
            start_date: None,
            end_date: None,
            active: false,
            target_processes: vec![],
        },
        BusinessTimeWindow {
            id: "tw-off-hours".to_string(),
            name: "Unattended Off-Hours Operations".to_string(),
            description: "Night-time and weekend operations when physical offices are unoccupied and SOC staffing is lean.".to_string(),
            multiplier: 1.25,
            window_type: "business_hours".to_string(),
            start_date: None,
            end_date: None,
            active: true,
            target_processes: vec![],
        },
    ];

    info!("Seeding out-of-the-box Business-Process Risk Fabric configuration");
    RiskFabricConfig {
        processes,
        time_windows,
    }
}

/// Entries of earlier default settings that matched far too much or named one test setup (an
/// address, a host name, a LAN range): `(process id, field, old entry, what replaces it)`.
const RETIRED: &[(&str, &str, &str, &[&str])] = &[
    ("bp-pci-payment", "asset", "192.168.10.15", &[]),
    ("bp-pci-payment", "asset", "srv-prod-ubuntu-01", &[]),
    ("bp-pci-payment", "asset", "*pay*", &["*payment*", "pay-*", "*-pay-*"]),
    ("bp-pci-payment", "asset", "*pos*", &["pos-*", "*-pos-*"]),
    ("bp-pci-payment", "identity", "admin*", &[]),
    ("bp-core-iam", "asset", "192.168.1.*", &[]),
    ("bp-core-iam", "asset", "*ad*", &[]),
    ("bp-core-iam", "asset", "*dc*", &["dc-*", "*-dc-*", "*-dc", "dc0*", "dc1*", "*domain-controller*"]),
    ("bp-core-iam", "asset", "*auth*", &["auth-*", "*-auth-*"]),
    ("bp-core-iam", "group", "*dc*", &[]),
    ("bp-core-iam", "identity", "system", &[]),
    ("bp-core-iam", "identity", "*cio*", &["cio"]),
    ("bp-dmz-web", "asset", "dmz-web-nginx", &[]),
    ("bp-dmz-web", "asset", "*api*", &["api-*", "*-api*"]),
    ("bp-dmz-web", "identity", "*app*", &[]),
    ("bp-win-corp", "asset", "win-node-*", &[]),
    ("bp-win-corp", "identity", "system", &[]),
    ("bp-linux-prod", "asset", "linux-node-*", &[]),
    ("bp-dev-sandbox", "asset", "*dev*", &["dev-*", "*-dev", "*-dev-*"]),
    ("bp-dev-sandbox", "asset", "*qa*", &["qa-*", "*-qa"]),
    ("bp-dev-sandbox", "identity", "*dev*", &["dev-*", "*-dev"]),
];

/// Stored settings from an earlier version: the retired default entries are replaced; entries
/// an admin added stay. Whether anything changed (the settings are then stored again).
pub fn retire_old_defaults(processes: &mut [BusinessProcessDefinition]) -> bool {
    let mut changed = false;
    for p in processes.iter_mut() {
        for (id, field, old, new) in RETIRED.iter().filter(|r| r.0 == p.id) {
            let _ = id;
            let list = match *field {
                "asset" => &mut p.asset_patterns,
                "group" => &mut p.group_patterns,
                _ => &mut p.identity_patterns,
            };
            if let Some(i) = list.iter().position(|x| x == old) {
                list.remove(i);
                for (k, n) in new.iter().enumerate() {
                    if !list.iter().any(|x| x == n) {
                        list.insert((i + k).min(list.len()), n.to_string());
                    }
                }
                changed = true;
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::matches_pattern;

    #[test]
    fn defaults_name_no_test_setup_and_old_entries_retire() {
        let d = default_config();
        let all: Vec<&String> = d.processes.iter().flat_map(|p| p.asset_patterns.iter().chain(&p.identity_patterns).chain(&p.group_patterns)).collect();
        for bad in ["192.168.10.15", "srv-prod-ubuntu-01", "192.168.1.*", "*ad*", "win-node-*", "system"] {
            assert!(!all.iter().any(|x| x.as_str() == bad), "{bad} still a default");
        }
        let iam = d.processes.iter().find(|p| p.id == "bp-core-iam").unwrap();
        assert!(!iam.asset_patterns.iter().any(|p| matches_pattern(p, "LAPTOP-ADMIN") || matches_pattern(p, "road-warrior")), "ordinary names are no domain controller");
        assert!(iam.asset_patterns.iter().any(|p| matches_pattern(p, "dc01")) && iam.asset_patterns.iter().any(|p| matches_pattern(p, "corp-dc-2")));

        // settings stored by an earlier version: retired entries go, an admin's own entry stays
        let mut old = default_config().processes;
        let iam = old.iter_mut().find(|p| p.id == "bp-core-iam").unwrap();
        iam.asset_patterns = vec!["*dc*".into(), "*ad*".into(), "192.168.1.*".into(), "hq-ldap-01".into()];
        assert!(retire_old_defaults(&mut old));
        let iam = old.iter().find(|p| p.id == "bp-core-iam").unwrap();
        assert_eq!(iam.asset_patterns, ["dc-*", "*-dc-*", "*-dc", "dc0*", "dc1*", "*domain-controller*", "hq-ldap-01"]);
        assert!(!retire_old_defaults(&mut old), "nothing left to retire");
    }
}
