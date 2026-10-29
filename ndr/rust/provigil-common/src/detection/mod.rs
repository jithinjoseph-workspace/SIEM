// Detection engine shared by ndr-engine and siem-engine.
// NDR-specific rule updater (updater.rs) and multiflow correlator stay in ndr-engine.
// License: Apache-2.0

pub mod sigma;
pub use sigma::{SigmaRule, DetectionMatch, LogSource, ConditionExpr, parse_rule_content};

use crate::normalizer::{NormalizedEvent, EventSource};
use crate::detection::sigma::LogSource as SigmaLogSource;
use std::collections::{HashMap, HashSet};

/// A rule's log source as every event is checked against it: lower-cased, with the Windows
/// logs it reads resolved, once when the rules load (not per event and rule).
struct Prepared {
    any: bool,
    product: String,
    category: String,
    service: String,
    /// `windows_logs` of a Windows (or product-less) rule
    win: Option<WinLogs>,
}

impl Prepared {
    fn new(ls: &SigmaLogSource) -> Self {
        let lower = |v: &Option<String>| v.as_deref().unwrap_or("").to_lowercase();
        let (product, category, service) = (lower(&ls.product), lower(&ls.category), lower(&ls.service));
        let win = if product == "windows" || product.is_empty() { windows_logs(&service, &category) } else { None };
        Self { any: ls.product.is_none() && ls.category.is_none() && ls.service.is_none(), product, category, service, win }
    }
}

fn logsource_matches(p: &Prepared, event: &NormalizedEvent) -> bool {
    if p.any { return true; }
    let (product, category, service) = (&p.product, &p.category, &p.service);

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
                if let Some(logs) = p.win {
                    let id = event.raw.get("EventID").map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
                    return logs.iter().any(|(l, ids)| l.eq_ignore_ascii_case(ch) && (ids.is_empty() || ids.contains(&id.as_str())));
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
    /// per rule (same index): its log source, prepared
    prepared: Vec<Prepared>,
    /// Windows rules by the (lower-case) channel they read, and every rule not tied to one
    /// channel: a Windows event of a known channel needs only these (in rule order).
    by_channel: HashMap<String, Vec<usize>>,
    not_channel_bound: Vec<usize>,
}

impl DetectionEngine {
    pub fn new(_rules_dir: &str) -> Self {
        tracing::info!("Detection engine: starting empty, rules load from ClickHouse");
        Self { rules: Vec::new(), disabled_overrides: HashMap::new(), prepared: Vec::new(), by_channel: HashMap::new(), not_channel_bound: Vec::new() }
    }

    /// The rules worth checking for an event, in rule order: for a Windows event of a known
    /// channel, that channel's rules and the ones not bound to a channel (any other rule's
    /// log source cannot match it); else all.
    fn candidates(&self, event: &NormalizedEvent) -> Vec<usize> {
        let ch = match event.event_source {
            EventSource::WindowsEvent => event.raw.get("Channel").and_then(|v| v.as_str()),
            _ => None,
        };
        let Some(ch) = ch else { return (0..self.rules.len()).collect() };
        let mut c: Vec<usize> = self.not_channel_bound.clone();
        if let Some(bound) = self.by_channel.get(&ch.to_lowercase()) {
            c.extend_from_slice(bound);
            c.sort_unstable();
        }
        c
    }

    pub fn check(&self, event: &NormalizedEvent) -> Vec<DetectionMatch> {
        self.rules.iter()
            .filter_map(|rule| self.eval(rule, event))
            .collect()
    }

    pub fn check_for_tenant(&self, event: &NormalizedEvent, tenant_id: &str) -> Vec<DetectionMatch> {
        let disabled = self.disabled_overrides.get(tenant_id);
        self.candidates(event)
            .into_iter()
            .filter(|&i| logsource_matches(&self.prepared[i], event))
            .map(|i| &self.rules[i])
            .filter(|rule| rule.tenant_id == "*" || rule.tenant_id == tenant_id)
            .filter(|rule| disabled.map_or(true, |d| !d.contains(&rule.id)))
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
        self.prepared = rules.iter().map(|r| Prepared::new(&r.logsource)).collect();
        self.by_channel.clear();
        self.not_channel_bound.clear();
        for (i, p) in self.prepared.iter().enumerate() {
            match p.win {
                Some(logs) => {
                    for (ch, _) in logs.iter() {
                        let v = self.by_channel.entry(ch.to_lowercase()).or_default();
                        if v.last() != Some(&i) {
                            v.push(i);
                        }
                    }
                }
                None => self.not_channel_bound.push(i),
            }
        }
        self.rules = rules;
        self.disabled_overrides = disabled;
    }
}

#[cfg(test)]
mod index_tests {
    use super::*;

    fn rule(y: &str) -> SigmaRule { parse_rule_content(y).unwrap() }

    /// The channel index only skips rules that cannot match: same matches, in rule order.
    #[test]
    fn channel_index_keeps_every_match() {
        let r = |id: &str, ls: &str, sel: &str| rule(&format!("title: {id}\nid: {id}\nlogsource:\n{ls}\ndetection:\n    s:\n        {sel}\n    condition: s\nlevel: low\n"));
        let rules = vec![
            r("sysmon-proc", "    product: windows\n    category: process_creation", "Image|endswith: 'x.exe'"),
            r("security", "    product: windows\n    service: security", "Image|endswith: 'x.exe'"),
            r("any-windows", "    product: windows", "Image|endswith: 'x.exe'"),
            r("no-logsource", "    {}", "Image|endswith: 'x.exe'"),
            r("linux", "    product: linux", "Image|endswith: 'x.exe'"),
        ];
        let mut e = DetectionEngine::new("");
        e.set_rules(rules, HashMap::new());
        let ev = |ch: &str, id: &str| {
            let mut n = NormalizedEvent::blank();
            n.event_source = EventSource::WindowsEvent;
            n.raw = serde_json::json!({ "Channel": ch, "EventID": id, "Image": "C:\\a\\x.exe" });
            n
        };
        let ids = |n: &NormalizedEvent| e.check_for_tenant(n, "t").into_iter().map(|m| m.rule_id).collect::<Vec<_>>();
        assert_eq!(ids(&ev("Microsoft-Windows-Sysmon/Operational", "1")), ["sysmon-proc", "any-windows", "no-logsource"]);
        assert_eq!(ids(&ev("Security", "4688")), ["sysmon-proc", "security", "any-windows", "no-logsource"], "4688 is process creation too");
        assert_eq!(ids(&ev("Application", "1")), ["any-windows", "no-logsource"]);
    }
}
