// Detection engine shared by ndr-engine and siem-engine.
// NDR-specific rule updater (updater.rs) and multiflow correlator stay in ndr-engine.
// License: Apache-2.0

pub mod sigma;
pub use sigma::{SigmaRule, DetectionMatch, LogSource, ConditionExpr, parse_rule_content};

use crate::normalizer::{NormalizedEvent, EventSource};
use crate::detection::sigma::LogSource as SigmaLogSource;
use std::collections::{HashMap, HashSet};

fn logsource_matches(ls: &SigmaLogSource, event: &NormalizedEvent) -> bool {
    let has_constraint = ls.product.is_some() || ls.category.is_some() || ls.service.is_some();
    if !has_constraint { return true; }

    let product  = ls.product.as_deref().unwrap_or("").to_lowercase();
    let category = ls.category.as_deref().unwrap_or("").to_lowercase();
    let service  = ls.service.as_deref().unwrap_or("").to_lowercase();

    match &event.event_source {
        EventSource::Zeek => {
            if matches!(product.as_str(), "windows" | "macos" | "linux" | "azure" | "okta" | "aws") {
                return false;
            }
            if !service.is_empty() {
                let log_src = event.log_source.as_deref().unwrap_or("");
                return service == log_src || service == "zeek";
            }
            if matches!(category.as_str(), "network_connection" | "dns" | "proxy" | "firewall" | "webserver") {
                return true;
            }
            if category.is_empty() {
                return true;
            }
            false
        }
        EventSource::Suricata => {
            if matches!(product.as_str(), "windows" | "macos" | "linux" | "azure" | "okta" | "aws") {
                return false;
            }
            true
        }
        EventSource::Linux => {
            if product == "windows" || product == "macos" { return false; }
            if product == "linux" || product.is_empty() { return true; }
            if category == "process_creation" || category == "network_connection" { return true; }
            false
        }
        EventSource::WindowsEvent => {
            if matches!(product.as_str(), "linux" | "macos" | "zeek" | "suricata") { return false; }
            // the rule's Windows log (service / category) and event ids against the event's, when the channel is known
            if let Some(ch) = event.raw.get("Channel").and_then(|v| v.as_str()) {
                if product == "windows" || product.is_empty() {
                    if let Some(logs) = windows_logs(&service, &category) {
                        let id = event.raw.get("EventID").map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
                        return logs.iter().any(|(l, ids)| l.eq_ignore_ascii_case(ch) && (ids.is_empty() || ids.contains(&id.as_str())));
                    }
                }
            }
            if product == "windows" || product.is_empty() { return true; }
            if matches!(category.as_str(), "process_creation" | "network_connection" | "registry_set" | "file_event") {
                return true;
            }
            false
        }
        EventSource::Syslog => {
            if matches!(product.as_str(), "windows" | "macos") { return false; }
            true
        }
        EventSource::CloudTrailAws => {
            product == "aws" || product.is_empty()
        }
        EventSource::AzureAd => {
            product == "azure" || product.is_empty()
        }
        EventSource::Okta => {
            product == "okta" || product.is_empty()
        }
        EventSource::Unknown => true,
    }
}

const SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";

const PS: &str = "Microsoft-Windows-PowerShell/Operational";
const PS_CLASSIC: &str = "Windows PowerShell";

type WinLogs = &'static [(&'static str, &'static [&'static str])];

/// The Windows event log(s) and event ids (empty = any) a Sigma `service` / `category` reads, as
/// SigmaHQ's Windows pipeline maps them; `None` = no constraint (no service, no category).
/// An unknown service or category reads no log this engine knows: it never matches.
fn windows_logs(service: &str, category: &str) -> Option<WinLogs> {
    Some(match service {
        "security" => &[("Security", &[])],
        "system" => &[("System", &[])],
        "application" => &[("Application", &[])],
        "sysmon" => &[(SYSMON, &[])],
        "powershell" => &[(PS, &[])],
        "powershell-classic" => &[(PS_CLASSIC, &[])],
        "taskscheduler" => &[("Microsoft-Windows-TaskScheduler/Operational", &[])],
        "wmi" => &[("Microsoft-Windows-WMI-Activity/Operational", &[])],
        "windefend" => &[("Microsoft-Windows-Windows Defender/Operational", &[])],
        "bits-client" => &[("Microsoft-Windows-Bits-Client/Operational", &[])],
        "firewall-as" => &[("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", &[])],
        "dns-server" => &[("DNS Server", &[])],
        "driver-framework" => &[("Microsoft-Windows-DriverFrameworks-UserMode/Operational", &[])],
        "ntlm" => &[("Microsoft-Windows-NTLM/Operational", &[])],
        "dhcp" => &[("Microsoft-Windows-DHCP-Server/Operational", &[])],
        "applocker" => &[("Microsoft-Windows-AppLocker/MSI and Script", &[]), ("Microsoft-Windows-AppLocker/EXE and DLL", &[]),
                         ("Microsoft-Windows-AppLocker/Packaged app-Deployment", &[]), ("Microsoft-Windows-AppLocker/Packaged app-Execution", &[])],
        "msexchange-management" => &[("MSExchange Management", &[])],
        "printservice-admin" => &[("Microsoft-Windows-PrintService/Admin", &[])],
        "printservice-operational" => &[("Microsoft-Windows-PrintService/Operational", &[])],
        "codeintegrity-operational" => &[("Microsoft-Windows-CodeIntegrity/Operational", &[])],
        "smbclient-security" => &[("Microsoft-Windows-SmbClient/Security", &[])],
        "smbclient-connectivity" => &[("Microsoft-Windows-SmbClient/Connectivity", &[])],
        "terminalservices-localsessionmanager" => &[("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", &[])],
        "security-mitigations" => &[("Microsoft-Windows-Security-Mitigations/Kernel Mode", &[]), ("Microsoft-Windows-Security-Mitigations/User Mode", &[])],
        "diagnosis-scripted" => &[("Microsoft-Windows-Diagnosis-Scripted/Operational", &[])],
        "shell-core" => &[("Microsoft-Windows-Shell-Core/Operational", &[])],
        "openssh" => &[("OpenSSH/Operational", &[])],
        "bitlocker" => &[("Microsoft-Windows-BitLocker/BitLocker Management", &[])],
        "vhdmp" => &[("Microsoft-Windows-VHDMP/Operational", &[])],
        "appxdeployment-server" => &[("Microsoft-Windows-AppXDeploymentServer/Operational", &[])],
        "appxpackaging-om" => &[("Microsoft-Windows-AppxPackaging/Operational", &[])],
        "lsa-server" => &[("Microsoft-Windows-LSA/Operational", &[])],
        "dns-client" => &[("Microsoft-Windows-DNS Client Events/Operational", &[])],
        "appmodel-runtime" => &[("Microsoft-Windows-AppModel-Runtime/Admin", &[])],
        "capi2" => &[("Microsoft-Windows-CAPI2/Operational", &[])],
        "certificateservicesclient-lifecycle-system" => &[("Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational", &[])],
        "kernel-shimengine" => &[("Microsoft-Windows-Kernel-ShimEngine/Operational", &[])],
        "ntfs" => &[("Microsoft-Windows-Ntfs/Operational", &[])],
        "iis-configuration" => &[("Microsoft-IIS-Configuration/Operational", &[])],
        "" => match category {
            "" => return None,
            "process_creation" => &[(SYSMON, &["1"]), ("Security", &["4688"])],
            "file_change" => &[(SYSMON, &["2"])],
            "network_connection" => &[(SYSMON, &["3"])],
            "sysmon_status" => &[(SYSMON, &["4", "16"])],
            "process_termination" => &[(SYSMON, &["5"])],
            "driver_load" => &[(SYSMON, &["6"])],
            "image_load" => &[(SYSMON, &["7"])],
            "create_remote_thread" => &[(SYSMON, &["8"])],
            "raw_access_thread" => &[(SYSMON, &["9"])],
            "process_access" => &[(SYSMON, &["10"])],
            "file_event" => &[(SYSMON, &["11"])],
            "registry_add" | "registry_delete" => &[(SYSMON, &["12"])],
            "registry_set" => &[(SYSMON, &["13"])],
            "registry_rename" => &[(SYSMON, &["14"])],
            "registry_event" => &[(SYSMON, &["12", "13", "14"])],
            "create_stream_hash" => &[(SYSMON, &["15"])],
            "pipe_created" => &[(SYSMON, &["17", "18"])],
            "wmi_event" => &[(SYSMON, &["19", "20", "21"])],
            "dns_query" => &[(SYSMON, &["22"])],
            "file_delete" => &[(SYSMON, &["23", "26"])],
            "clipboard_capture" => &[(SYSMON, &["24"])],
            "process_tampering" => &[(SYSMON, &["25"])],
            "file_block_executable" => &[(SYSMON, &["27"])],
            "file_block_shredding" => &[(SYSMON, &["28"])],
            "file_executable_detected" => &[(SYSMON, &["29"])],
            "sysmon_error" => &[(SYSMON, &["255"])],
            "ps_module" => &[(PS, &["4103"])],
            "ps_script" => &[(PS, &["4104"])],
            "ps_classic_start" => &[(PS_CLASSIC, &["400"])],
            "ps_classic_provider_start" => &[(PS_CLASSIC, &["600"])],
            "ps_classic_script" => &[(PS_CLASSIC, &["800"])],
            _ => &[],
        },
        _ => &[],
    })
}

pub struct DetectionEngine {
    rules: Vec<SigmaRule>,
    disabled_overrides: HashMap<String, HashSet<String>>,
}

impl DetectionEngine {
    pub fn new(_rules_dir: &str) -> Self {
        tracing::info!("Detection engine: starting empty, rules load from ClickHouse");
        Self { rules: Vec::new(), disabled_overrides: HashMap::new() }
    }

    pub fn check(&self, event: &NormalizedEvent) -> Vec<DetectionMatch> {
        self.rules.iter()
            .filter_map(|rule| self.eval(rule, event))
            .collect()
    }

    pub fn check_for_tenant(&self, event: &NormalizedEvent, tenant_id: &str) -> Vec<DetectionMatch> {
        let disabled = self.disabled_overrides.get(tenant_id);
        self.rules.iter()
            .filter(|rule| rule.tenant_id == "*" || rule.tenant_id == tenant_id)
            .filter(|rule| disabled.map_or(true, |d| !d.contains(&rule.id)))
            .filter(|rule| logsource_matches(&rule.logsource, event))
            .filter_map(|rule| self.eval(rule, event))
            .collect()
    }

    fn eval(&self, rule: &SigmaRule, event: &NormalizedEvent) -> Option<DetectionMatch> {
        let matched = rule.condition_expr.eval(&rule.selections, event);
        matched.then(|| DetectionMatch {
            rule_id:  rule.id.clone(),
            title:    rule.title.clone(),
            severity: rule.severity.clone(),
            tags:     rule.tags.clone(),
        })
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
    pub fn get_rules(&self) -> Vec<serde_json::Value> {
        self.rules.iter().map(|r| serde_json::json!({
            "id":        r.id,
            "title":     r.title,
            "severity":  r.severity,
            "tags":      r.tags,
            "tenant_id": r.tenant_id,
            "logsource": {
                "product":  r.logsource.product,
                "category": r.logsource.category,
                "service":  r.logsource.service,
            },
            "conditions": r.conditions.len(),
        })).collect()
    }

    pub fn set_rules(&mut self, rules: Vec<SigmaRule>, disabled: HashMap<String, HashSet<String>>) {
        tracing::info!("Rules updated: {} loaded, {} tenants with overrides", rules.len(), disabled.len());
        self.rules = rules;
        self.disabled_overrides = disabled;
    }
}
