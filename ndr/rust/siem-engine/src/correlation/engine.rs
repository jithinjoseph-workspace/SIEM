// SIEM Correlation Engine — 10 OOTB Detection Rules
// Evaluates a parsed SiemEvent against all built-in rules.
// Returns Vec<RuleMatch> (empty = no rules fired).
// License: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::{Utc, Timelike};

use crate::correlation::types::{SiemEvent, RuleMatch};

// ─────────────────────────────────────────────────────────────────────────────
// State window types for stateful rules (rules that need counters/history)
// ─────────────────────────────────────────────────────────────────────────────

/// Key: (tenant_id, username)  Value: (count, window_start_unix_secs)
type BruteForceState = Arc<Mutex<HashMap<String, (u32, i64)>>>;

/// Key: (tenant_id, username)  Value: unix_secs of last failed login
type PrivEscState = Arc<Mutex<HashMap<String, i64>>>;

/// Key: (tenant_id, src_ip_token)  Value: (HashSet<hostname>, window_start)
type LateralState = Arc<Mutex<HashMap<String, (std::collections::HashSet<String>, i64)>>>;

/// Key: (tenant_id, src_ip_token)  Value: (bytes_total, window_start)
type ExfilState = Arc<Mutex<HashMap<String, (u64, i64)>>>;

/// Key: (tenant_id, src_ip_token → dst_ip_token)  Value: Vec<unix_secs>
type C2BeaconState = Arc<Mutex<HashMap<String, Vec<i64>>>>;

// ─────────────────────────────────────────────────────────────────────────────
// RuleEngine
// ─────────────────────────────────────────────────────────────────────────────

pub struct RuleEngine {
    /// Rule 1 — Brute Force Login: ≥10 failures within 5 min
    brute_force: BruteForceState,
    /// Rule 2 — Privilege Escalation: sudo/runas within 15 min of failed login
    priv_esc: PrivEscState,
    /// Rule 3 — Lateral Movement: same src → ≥3 distinct hosts in 10 min
    lateral: LateralState,
    /// Rule 4 — Data Exfiltration: >500 MB outbound in 10 min
    exfil: ExfilState,
    /// Rule 10 — C2 Beacon: consistent short-interval connections
    c2_beacon: C2BeaconState,
    /// Enabled/disabled state per rule_id (loaded from CH at startup)
    enabled: Arc<tokio::sync::RwLock<HashMap<String, bool>>>,
}

// Known-bad process names for Rule 5 (Malware Execution) & Rule 7 (Credential Dumping)
const MALWARE_PROCESS_NAMES: &[&str] = &[
    "mimikatz", "meterpreter", "cobalt", "empire", "invoke-mimikatz",
    "invoke-kerberoast", "sharphound", "bloodhound", "rubeus",
    "pwdump", "fgdump", "procdump", "vaultcmd",
];

const CREDENTIAL_DUMP_INDICATORS: &[&str] = &[
    "lsass", "mimikatz", "secretsdump", "hashdump", "wce.exe",
    "pwdumpx", "cachedump", "fgdump", "quarkspwdump",
];

// Rule 8 — Suspicious PowerShell indicators
const POWERSHELL_SUSPICIOUS: &[&str] = &[
    "-encodedcommand", "-enc ", "base64", "downloadstring",
    "iex(", "invoke-expression", "bypass", "-w hidden",
    "frombase64string", "system.reflection.assembly",
];

// Rule 6 — Persistence: registry run keys / scheduled task / systemd service patterns
const PERSISTENCE_REGISTRY_PATTERNS: &[&str] = &[
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"system\currentcontrolset\services",
];

const PERSISTENCE_SERVICE_PATTERNS: &[&str] = &[
    "systemctl enable", "systemctl daemon-reload",
    "sc create", "sc config",
    "schtasks /create", "at.exe",
    "/etc/cron", "/etc/systemd",
];

// Business hours window for Rule 9
const BUSINESS_HOUR_START: u32 = 8;   // 08:00 UTC
const BUSINESS_HOUR_END:   u32 = 18;  // 18:00 UTC

// Thresholds
const BRUTE_FORCE_THRESHOLD: u32 = 10;
const BRUTE_FORCE_WINDOW_SECS: i64 = 300;   // 5 min
const PRIV_ESC_WINDOW_SECS: i64 = 900;      // 15 min
const LATERAL_THRESHOLD: usize = 3;
const LATERAL_WINDOW_SECS: i64 = 600;       // 10 min
const EXFIL_THRESHOLD_BYTES: u64 = 500 * 1024 * 1024; // 500 MB
const EXFIL_SINGLE_THRESHOLD: u64 = 100 * 1024 * 1024; // 100 MB
const EXFIL_WINDOW_SECS: i64 = 600;         // 10 min
const C2_BEACON_MIN_COUNT: usize = 5;
const C2_BEACON_WINDOW_SECS: i64 = 3600;    // 1 hour
const C2_BEACON_INTERVAL_TOLERANCE_SECS: i64 = 30; // ±30s consistency

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            brute_force: Arc::new(Mutex::new(HashMap::new())),
            priv_esc:    Arc::new(Mutex::new(HashMap::new())),
            lateral:     Arc::new(Mutex::new(HashMap::new())),
            exfil:       Arc::new(Mutex::new(HashMap::new())),
            c2_beacon:   Arc::new(Mutex::new(HashMap::new())),
            enabled:     Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Load enabled/disabled overrides from ClickHouse at startup or refresh.
    pub async fn set_enabled_rules(&self, enabled: HashMap<String, bool>) {
        let mut guard = self.enabled.write().await;
        *guard = enabled;
    }

    fn is_enabled(&self, rule_id: &str) -> bool {
        // Non-blocking: uses try_read; defaults to enabled if lock busy
        match self.enabled.try_read() {
            Ok(guard) => *guard.get(rule_id).unwrap_or(&true),
            Err(_)    => true,
        }
    }

    /// Evaluate all 10 OOTB rules against a single event.
    /// Returns the list of rules that fired.
    pub async fn evaluate(&self, event: &SiemEvent) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        // ── Rule 1: Brute Force Login ────────────────────────────────────────
        if self.is_enabled("SIEM-001") {
            if let Some(m) = self.rule_brute_force(event).await {
                matches.push(m);
            }
        }

        // ── Rule 2: Privilege Escalation ─────────────────────────────────────
        if self.is_enabled("SIEM-002") {
            if let Some(m) = self.rule_priv_escalation(event).await {
                matches.push(m);
            }
        }

        // ── Rule 3: Lateral Movement ─────────────────────────────────────────
        if self.is_enabled("SIEM-003") {
            if let Some(m) = self.rule_lateral_movement(event).await {
                matches.push(m);
            }
        }

        // ── Rule 4: Data Exfiltration ────────────────────────────────────────
        if self.is_enabled("SIEM-004") {
            if let Some(m) = self.rule_data_exfiltration(event).await {
                matches.push(m);
            }
        }

        // ── Rule 5: Malware Execution ────────────────────────────────────────
        if self.is_enabled("SIEM-005") {
            if let Some(m) = self.rule_malware_execution(event) {
                matches.push(m);
            }
        }

        // ── Rule 6: Persistence Mechanism ───────────────────────────────────
        if self.is_enabled("SIEM-006") {
            if let Some(m) = self.rule_persistence(event) {
                matches.push(m);
            }
        }

        // ── Rule 7: Credential Dumping ───────────────────────────────────────
        if self.is_enabled("SIEM-007") {
            if let Some(m) = self.rule_credential_dumping(event) {
                matches.push(m);
            }
        }

        // ── Rule 8: Suspicious PowerShell ───────────────────────────────────
        if self.is_enabled("SIEM-008") {
            if let Some(m) = self.rule_suspicious_powershell(event) {
                matches.push(m);
            }
        }

        // ── Rule 9: Account Created Outside Business Hours ───────────────────
        if self.is_enabled("SIEM-009") {
            if let Some(m) = self.rule_account_created_outside_hours(event) {
                matches.push(m);
            }
        }

        // ── Rule 10: C2 Beacon Detection ─────────────────────────────────────
        if self.is_enabled("SIEM-010") {
            if let Some(m) = self.rule_c2_beacon(event).await {
                matches.push(m);
            }
        }

        matches
    }

    // ── Rule 1: Brute Force Login ────────────────────────────────────────────
    // ≥10 failed authentication events for the same (tenant, username) in 5 min.
    async fn rule_brute_force(&self, event: &SiemEvent) -> Option<RuleMatch> {
        if event.event_type != "authentication" { return None; }
        let result = event.event_result.as_deref().unwrap_or("").to_lowercase();
        if result != "failure" { return None; }

        let username = event.username.clone().unwrap_or_default();
        if username.is_empty() { return None; }

        let key = format!("{}:{}", event.tenant_id, username);
        let now = Utc::now().timestamp();
        let mut state = self.brute_force.lock().await;
        let entry = state.entry(key).or_insert((0, now));

        if now - entry.1 > BRUTE_FORCE_WINDOW_SECS {
            // Reset window
            *entry = (1, now);
            return None;
        }
        entry.0 += 1;

        if entry.0 >= BRUTE_FORCE_THRESHOLD {
            // Reset counter after firing
            *entry = (0, now);
            return Some(RuleMatch {
                rule_id:   "SIEM-001".to_string(),
                rule_name: "Brute Force Login Attempt".to_string(),
                severity:  "HIGH".to_string(),
                title:     format!("Brute force attack detected on account '{}'", username),
                description: format!(
                    "≥{} failed logins for user '{}' in the last 5 minutes.",
                    BRUTE_FORCE_THRESHOLD, username
                ),
                mitre_techniques: vec!["T1110".to_string(), "T1110.001".to_string()],
            });
        }
        None
    }

    // ── Rule 2: Privilege Escalation ─────────────────────────────────────────
    // sudo/runas/su execution within 15 min of a previous failed login.
    async fn rule_priv_escalation(&self, event: &SiemEvent) -> Option<RuleMatch> {
        let now = Utc::now().timestamp();
        let username = event.username.clone().unwrap_or_default();
        let key = format!("{}:{}", event.tenant_id, username);

        // Track failed logins
        if event.event_type == "authentication" {
            let result = event.event_result.as_deref().unwrap_or("").to_lowercase();
            if result == "failure" && !username.is_empty() {
                let mut state = self.priv_esc.lock().await;
                state.insert(key, now);
                return None;
            }
        }

        // Check for privilege-escalation events after a prior failure
        if event.event_type == "process_activity" || event.event_type == "privileged_activity" {
            let proc = event.process_name.as_deref().unwrap_or("").to_lowercase();
            let cmd  = event.command_line.as_deref().unwrap_or("").to_lowercase();
            let is_priv = matches!(proc.as_str(), "sudo" | "su" | "runas" | "pkexec" | "doas")
                || cmd.contains("sudo ") || cmd.contains("runas /");

            if is_priv && !username.is_empty() {
                let state = self.priv_esc.lock().await;
                if let Some(&last_fail) = state.get(&key) {
                    if now - last_fail <= PRIV_ESC_WINDOW_SECS {
                        return Some(RuleMatch {
                            rule_id:   "SIEM-002".to_string(),
                            rule_name: "Privilege Escalation After Failed Login".to_string(),
                            severity:  "HIGH".to_string(),
                            title: format!(
                                "Privilege escalation attempt by '{}' after failed login",
                                username
                            ),
                            description: format!(
                                "User '{}' ran '{}' within 15 min of a failed authentication.",
                                username, proc
                            ),
                            mitre_techniques: vec!["T1548".to_string(), "T1548.003".to_string()],
                        });
                    }
                }
            }
        }
        None
    }

    // ── Rule 3: Lateral Movement ─────────────────────────────────────────────
    // Same source IP token accessing ≥3 unique hostnames in 10 min.
    async fn rule_lateral_movement(&self, event: &SiemEvent) -> Option<RuleMatch> {
        let src = event.src_ip_token.clone()?;
        let host = event.hostname.clone()?;
        let key = format!("{}:{}", event.tenant_id, src);
        let now = Utc::now().timestamp();

        let mut state = self.lateral.lock().await;
        let entry = state.entry(key).or_insert_with(|| (std::collections::HashSet::new(), now));

        if now - entry.1 > LATERAL_WINDOW_SECS {
            entry.0.clear();
            entry.1 = now;
        }
        entry.0.insert(host.clone());

        if entry.0.len() >= LATERAL_THRESHOLD {
            let hosts: Vec<String> = entry.0.iter().cloned().collect();
            entry.0.clear(); // reset after firing
            return Some(RuleMatch {
                rule_id:   "SIEM-003".to_string(),
                rule_name: "Lateral Movement Detected".to_string(),
                severity:  "HIGH".to_string(),
                title:     "Lateral movement: single source accessed multiple hosts".to_string(),
                description: format!(
                    "Source accessed {} unique hosts in 10 min: {}",
                    hosts.len(),
                    hosts.join(", ")
                ),
                mitre_techniques: vec!["T1021".to_string(), "T1570".to_string()],
            });
        }
        None
    }

    // ── Rule 4: Data Exfiltration ────────────────────────────────────────────
    // Single event >100 MB OR cumulative >500 MB outbound in 10 min.
    async fn rule_data_exfiltration(&self, event: &SiemEvent) -> Option<RuleMatch> {
        let bytes = event.bytes_out?;
        let src = event.src_ip_token.clone().unwrap_or_else(|| event.tenant_id.clone());
        let key = format!("{}:{}", event.tenant_id, src);
        let now = Utc::now().timestamp();

        // Single-event threshold
        if bytes > EXFIL_SINGLE_THRESHOLD {
            return Some(RuleMatch {
                rule_id:   "SIEM-004".to_string(),
                rule_name: "Data Exfiltration Detected".to_string(),
                severity:  "CRITICAL".to_string(),
                title:     "Large single-session data exfiltration".to_string(),
                description: format!(
                    "Single event transferred {} MB outbound (threshold: {} MB).",
                    bytes / 1024 / 1024,
                    EXFIL_SINGLE_THRESHOLD / 1024 / 1024
                ),
                mitre_techniques: vec!["T1041".to_string(), "T1048".to_string()],
            });
        }

        // Cumulative window threshold
        let mut state = self.exfil.lock().await;
        let entry = state.entry(key).or_insert((0, now));
        if now - entry.1 > EXFIL_WINDOW_SECS {
            *entry = (bytes, now);
            return None;
        }
        entry.0 += bytes;

        if entry.0 > EXFIL_THRESHOLD_BYTES {
            let total_mb = entry.0 / 1024 / 1024;
            *entry = (0, now);
            return Some(RuleMatch {
                rule_id:   "SIEM-004".to_string(),
                rule_name: "Data Exfiltration Detected".to_string(),
                severity:  "CRITICAL".to_string(),
                title:     "Cumulative data exfiltration threshold exceeded".to_string(),
                description: format!(
                    "{} MB transferred outbound in 10 min (threshold: {} MB).",
                    total_mb,
                    EXFIL_THRESHOLD_BYTES / 1024 / 1024
                ),
                mitre_techniques: vec!["T1041".to_string(), "T1048".to_string()],
            });
        }
        None
    }

    // ── Rule 5: Malware Execution ────────────────────────────────────────────
    // Process name or command line matches known-malicious tool names.
    fn rule_malware_execution(&self, event: &SiemEvent) -> Option<RuleMatch> {
        if !matches!(event.event_type.as_str(), "process_activity" | "process_creation") {
            return None;
        }
        let proc = event.process_name.as_deref().unwrap_or("").to_lowercase();
        let cmd  = event.command_line.as_deref().unwrap_or("").to_lowercase();

        for bad in MALWARE_PROCESS_NAMES {
            if proc.contains(bad) || cmd.contains(bad) {
                return Some(RuleMatch {
                    rule_id:   "SIEM-005".to_string(),
                    rule_name: "Malware Execution Detected".to_string(),
                    severity:  "CRITICAL".to_string(),
                    title:     format!("Known malware tool executed: '{}'", bad),
                    description: format!(
                        "Process '{}' or command line matches known malware indicator '{}'.",
                        proc, bad
                    ),
                    mitre_techniques: vec!["T1059".to_string(), "T1106".to_string()],
                });
            }
        }

        // Parent process anomaly: cmd.exe spawned from Word/Excel/Outlook
        let parent = event.parent_process.as_deref().unwrap_or("").to_lowercase();
        let suspicious_parents = ["winword", "excel", "outlook", "powerpnt", "onenote", "mspub"];
        let suspicious_children = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"];
        if suspicious_parents.iter().any(|p| parent.contains(p))
            && suspicious_children.iter().any(|c| proc.contains(c))
        {
            return Some(RuleMatch {
                rule_id:   "SIEM-005".to_string(),
                rule_name: "Malware Execution Detected".to_string(),
                severity:  "HIGH".to_string(),
                title:     "Suspicious child process spawned from Office application".to_string(),
                description: format!(
                    "'{}' spawned from '{}' — possible macro-based malware execution.",
                    proc, parent
                ),
                mitre_techniques: vec!["T1566.001".to_string(), "T1204.002".to_string()],
            });
        }
        None
    }

    // ── Rule 6: Persistence Mechanism ───────────────────────────────────────
    // Registry run key write, scheduled task creation, or systemd service install.
    fn rule_persistence(&self, event: &SiemEvent) -> Option<RuleMatch> {
        let event_lower = event.event_type.to_lowercase();
        let is_registry = event_lower.contains("registry") || event_lower.contains("reg_set");
        let is_process  = event_lower.contains("process");
        let is_file     = event_lower.contains("file");

        if is_registry {
            let reg_key = event.registry_key.as_deref().unwrap_or("").to_lowercase();
            for pattern in PERSISTENCE_REGISTRY_PATTERNS {
                if reg_key.contains(pattern) {
                    return Some(RuleMatch {
                        rule_id:   "SIEM-006".to_string(),
                        rule_name: "Persistence Mechanism Detected".to_string(),
                        severity:  "HIGH".to_string(),
                        title:     "Registry persistence key written".to_string(),
                        description: format!(
                            "Write to persistence registry key: '{}'", reg_key
                        ),
                        mitre_techniques: vec!["T1547.001".to_string(), "T1060".to_string()],
                    });
                }
            }
        }

        if is_process || is_file {
            let cmd = event.command_line.as_deref().unwrap_or("").to_lowercase();
            let svc = event.service_name.as_deref().unwrap_or("").to_lowercase();
            let combined = format!("{} {}", cmd, svc);
            for pattern in PERSISTENCE_SERVICE_PATTERNS {
                if combined.contains(pattern) {
                    return Some(RuleMatch {
                        rule_id:   "SIEM-006".to_string(),
                        rule_name: "Persistence Mechanism Detected".to_string(),
                        severity:  "HIGH".to_string(),
                        title:     "Scheduled task or service created for persistence".to_string(),
                        description: format!(
                            "Persistence indicator '{}' found in command/service.", pattern
                        ),
                        mitre_techniques: vec!["T1543".to_string(), "T1053".to_string()],
                    });
                }
            }
        }
        None
    }

    // ── Rule 7: Credential Dumping ───────────────────────────────────────────
    // Access to lsass, mimikatz, secretsdump, or similar tools.
    fn rule_credential_dumping(&self, event: &SiemEvent) -> Option<RuleMatch> {
        let proc = event.process_name.as_deref().unwrap_or("").to_lowercase();
        let cmd  = event.command_line.as_deref().unwrap_or("").to_lowercase();

        for indicator in CREDENTIAL_DUMP_INDICATORS {
            if proc.contains(indicator) || cmd.contains(indicator) {
                return Some(RuleMatch {
                    rule_id:   "SIEM-007".to_string(),
                    rule_name: "Credential Dumping Detected".to_string(),
                    severity:  "CRITICAL".to_string(),
                    title:     format!("Credential dumping tool/technique detected: '{}'", indicator),
                    description: format!(
                        "Process '{}' or command matches credential dump indicator '{}'.",
                        proc, indicator
                    ),
                    mitre_techniques: vec!["T1003".to_string(), "T1003.001".to_string()],
                });
            }
        }
        None
    }

    // ── Rule 8: Suspicious PowerShell ───────────────────────────────────────
    // Base64 encoded commands, download cradles, or execution policy bypasses.
    fn rule_suspicious_powershell(&self, event: &SiemEvent) -> Option<RuleMatch> {
        let proc = event.process_name.as_deref().unwrap_or("").to_lowercase();
        if !proc.contains("powershell") && !proc.contains("pwsh") { return None; }

        let cmd = event.command_line.as_deref().unwrap_or("").to_lowercase();
        for indicator in POWERSHELL_SUSPICIOUS {
            if cmd.contains(indicator) {
                return Some(RuleMatch {
                    rule_id:   "SIEM-008".to_string(),
                    rule_name: "Suspicious PowerShell Execution".to_string(),
                    severity:  "HIGH".to_string(),
                    title:     "Obfuscated or suspicious PowerShell command detected".to_string(),
                    description: format!(
                        "PowerShell command matches suspicious indicator '{}': {}",
                        indicator,
                        // Truncate command line to 200 chars for safety
                        if cmd.len() > 200 { &cmd[..200] } else { &cmd }
                    ),
                    mitre_techniques: vec!["T1059.001".to_string(), "T1027".to_string()],
                });
            }
        }
        None
    }

    // ── Rule 9: Account Created Outside Business Hours ───────────────────────
    // Windows EventID 4720 (user account created) outside 08:00–18:00 UTC.
    fn rule_account_created_outside_hours(&self, event: &SiemEvent) -> Option<RuleMatch> {
        // Match on account/user creation events
        let is_account_creation =
            event.event_type == "account_change"
            || event.event_type == "user_management"
            || event.raw.contains("\"event_id\":4720")
            || event.raw.contains("EventID=4720");

        if !is_account_creation { return None; }

        let hour = event.timestamp.hour(); // UTC hour
        if hour >= BUSINESS_HOUR_START && hour < BUSINESS_HOUR_END {
            return None; // Within business hours — no alert
        }

        let username = event.username.as_deref().unwrap_or("unknown");
        Some(RuleMatch {
            rule_id:   "SIEM-009".to_string(),
            rule_name: "Account Created Outside Business Hours".to_string(),
            severity:  "MEDIUM".to_string(),
            title:     format!("User account '{}' created outside business hours ({}:00 UTC)", username, hour),
            description: format!(
                "Account creation event detected at {:02}:00 UTC, outside business hours ({}:00–{}:00 UTC).",
                hour, BUSINESS_HOUR_START, BUSINESS_HOUR_END
            ),
            mitre_techniques: vec!["T1136".to_string(), "T1136.001".to_string()],
        })
    }

    // ── Rule 10: C2 Beacon Detection ─────────────────────────────────────────
    // Same src→dst pair with consistent short intervals (UEBA beaconing pattern).
    async fn rule_c2_beacon(&self, event: &SiemEvent) -> Option<RuleMatch> {
        let src = event.src_ip_token.as_ref()?;
        let dst = event.dst_ip_token.as_ref()?;
        // Only network-type events
        if !matches!(
            event.event_type.as_str(),
            "network_activity" | "network_connection" | "dns_activity"
        ) { return None; }

        let key = format!("{}:{}:{}", event.tenant_id, src, dst);
        let now = Utc::now().timestamp();

        let mut state = self.c2_beacon.lock().await;
        let times = state.entry(key.clone()).or_insert_with(Vec::new);

        // Prune events outside window
        times.retain(|&t| now - t <= C2_BEACON_WINDOW_SECS);
        times.push(now);

        if times.len() < C2_BEACON_MIN_COUNT { return None; }

        // Compute inter-arrival intervals
        let mut intervals: Vec<i64> = times.windows(2).map(|w| w[1] - w[0]).collect();
        intervals.sort_unstable();

        let mean = intervals.iter().sum::<i64>() / intervals.len() as i64;
        let variance: i64 = intervals.iter()
            .map(|&i| (i - mean).pow(2))
            .sum::<i64>() / intervals.len() as i64;
        let std_dev = (variance as f64).sqrt() as i64;

        // Low std deviation = highly consistent intervals = beacon
        if std_dev <= C2_BEACON_INTERVAL_TOLERANCE_SECS && mean > 0 && mean < 300 {
            let times_len = times.len();
            state.remove(&key); // reset after firing
            return Some(RuleMatch {
                rule_id:   "SIEM-010".to_string(),
                rule_name: "C2 Beacon Pattern Detected".to_string(),
                severity:  "CRITICAL".to_string(),
                title:     "Command-and-Control beacon pattern detected".to_string(),
                description: format!(
                    "Consistent ~{}s interval connections detected over {} occurrences (std_dev={}s). Possible C2 beacon.",
                    mean, times_len, std_dev
                ),
                mitre_techniques: vec!["T1071".to_string(), "T1132".to_string(), "T1095".to_string()],
            });
        }
        None
    }

    /// Periodic cleanup: remove stale entries from all state maps.
    /// Call every 5–10 minutes from a background task.
    pub async fn sweep_expired(&self) {
        let now = Utc::now().timestamp();

        {
            let mut s = self.brute_force.lock().await;
            s.retain(|_, v| now - v.1 <= BRUTE_FORCE_WINDOW_SECS * 2);
        }
        {
            let mut s = self.priv_esc.lock().await;
            s.retain(|_, &mut t| now - t <= PRIV_ESC_WINDOW_SECS * 2);
        }
        {
            let mut s = self.lateral.lock().await;
            s.retain(|_, v| now - v.1 <= LATERAL_WINDOW_SECS * 2);
        }
        {
            let mut s = self.exfil.lock().await;
            s.retain(|_, v| now - v.1 <= EXFIL_WINDOW_SECS * 2);
        }
        {
            let mut s = self.c2_beacon.lock().await;
            s.retain(|_, v| {
                v.retain(|&t| now - t <= C2_BEACON_WINDOW_SECS);
                !v.is_empty()
            });
        }
        tracing::debug!("RuleEngine: state sweep complete");
    }

    /// Return a static list of all OOTB rule metadata for the /api/siem/rules endpoint.
    pub fn rule_catalog() -> Vec<crate::correlation::types::CorrelationRule> {
        vec![
            crate::correlation::types::CorrelationRule {
                id: "SIEM-001".into(), name: "Brute Force Login Attempt".into(),
                description: "≥10 failed logins for the same account within 5 minutes".into(),
                severity: "HIGH".into(), enabled: true,
                mitre_techniques: vec!["T1110".into(), "T1110.001".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-002".into(), name: "Privilege Escalation After Failed Login".into(),
                description: "sudo/runas/su executed within 15 min of a failed authentication".into(),
                severity: "HIGH".into(), enabled: true,
                mitre_techniques: vec!["T1548".into(), "T1548.003".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-003".into(), name: "Lateral Movement Detected".into(),
                description: "Same source IP accessed ≥3 unique hosts within 10 minutes".into(),
                severity: "HIGH".into(), enabled: true,
                mitre_techniques: vec!["T1021".into(), "T1570".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-004".into(), name: "Data Exfiltration Detected".into(),
                description: "Single event >100 MB or cumulative >500 MB outbound in 10 minutes".into(),
                severity: "CRITICAL".into(), enabled: true,
                mitre_techniques: vec!["T1041".into(), "T1048".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-005".into(), name: "Malware Execution Detected".into(),
                description: "Known malware tool name in process or command line; Office spawning shell".into(),
                severity: "CRITICAL".into(), enabled: true,
                mitre_techniques: vec!["T1059".into(), "T1106".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-006".into(), name: "Persistence Mechanism Detected".into(),
                description: "Registry run-key write, scheduled task creation, or systemd service install".into(),
                severity: "HIGH".into(), enabled: true,
                mitre_techniques: vec!["T1547.001".into(), "T1053".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-007".into(), name: "Credential Dumping Detected".into(),
                description: "lsass access, mimikatz, secretsdump, or similar credential theft tools".into(),
                severity: "CRITICAL".into(), enabled: true,
                mitre_techniques: vec!["T1003".into(), "T1003.001".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-008".into(), name: "Suspicious PowerShell Execution".into(),
                description: "Base64-encoded commands, download cradles, or execution policy bypasses".into(),
                severity: "HIGH".into(), enabled: true,
                mitre_techniques: vec!["T1059.001".into(), "T1027".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-009".into(), name: "Account Created Outside Business Hours".into(),
                description: "Windows EventID 4720 user account creation outside 08:00–18:00 UTC".into(),
                severity: "MEDIUM".into(), enabled: true,
                mitre_techniques: vec!["T1136".into(), "T1136.001".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
            crate::correlation::types::CorrelationRule {
                id: "SIEM-010".into(), name: "C2 Beacon Pattern Detected".into(),
                description: "Consistent short-interval connections from same src→dst pair (UEBA beaconing)".into(),
                severity: "CRITICAL".into(), enabled: true,
                mitre_techniques: vec!["T1071".into(), "T1095".into()],
                fitness_score: 0.0, true_positive_rate: 0.0, suppression_rate: 0.0, avg_resolve_minutes: 0.0,
            },
        ]
    }
}
