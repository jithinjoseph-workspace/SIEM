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

pub fn save_config(path: &Path, cfg: &RiskFabricConfig) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        let _ = fs::write(path, json);
    }
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
                "*pay*".into(),
                "*swift*".into(),
                "*pos*".into(),
                "*checkout*".into(),
                "192.168.10.15".into(),
                "srv-prod-ubuntu-01".into(),
            ],
            identity_patterns: vec![
                "*cashier*".into(),
                "*finance*".into(),
                "*settlement*".into(),
                "*pci*".into(),
                "admin*".into(),
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
                "*dc*".into(),
                "*ad*".into(),
                "*iam*".into(),
                "*auth*".into(),
                "*ldap*".into(),
                "*vault*".into(),
                "*kerberos*".into(),
            ],
            identity_patterns: vec![
                "administrator".into(),
                "admin*".into(),
                "root".into(),
                "svc_*".into(),
                "*ciso*".into(),
                "*cio*".into(),
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
                "dmz-web-nginx".into(),
                "*web*".into(),
                "*nginx*".into(),
                "*apache*".into(),
                "*ingress*".into(),
                "*api*".into(),
                "*portal*".into(),
            ],
            identity_patterns: vec![
                "www-data".into(),
                "nginx".into(),
                "apache".into(),
                "*app*".into(),
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
            identity_patterns: vec![
                "*operator*".into(),
                "*dba*".into(),
                "*erp*".into(),
            ],
            impact_template: "Corporate ERP or backend database impacted; potential disruption to supply chain logistics or unauthorized business records access.".to_string(),
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
                "*dev*".into(),
                "*test*".into(),
                "*stage*".into(),
                "*qa*".into(),
                "*sandbox*".into(),
                "*lab*".into(),
            ],
            identity_patterns: vec![
                "*tester*".into(),
                "*intern*".into(),
                "*dev*".into(),
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
