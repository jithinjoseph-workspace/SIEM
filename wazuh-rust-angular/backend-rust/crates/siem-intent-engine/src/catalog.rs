use std::collections::HashMap;

pub const KILL_CHAIN_STAGES: [&str; 10] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection & Staging",
    "Impact & Exfiltration",
];

pub fn get_stage_index(stage: &str) -> Option<usize> {
    let s = stage.trim().to_lowercase();
    KILL_CHAIN_STAGES.iter().position(|&x| x.to_lowercase() == s || s.contains(&x.to_lowercase()))
}

/// Converts a MITRE ATT&CK Tactic name or ID (TA0001-TA0040) directly into its Kill-Chain stage index
pub fn tactic_to_stage(tactic: &str) -> Option<usize> {
    let t = tactic.trim().to_lowercase().replace(['_', '-'], " ");
    if t.contains("initial access") || t.contains("ta0001") {
        Some(0)
    } else if t.contains("execution") || t.contains("ta0002") {
        Some(1)
    } else if t.contains("persistence") || t.contains("ta0003") {
        Some(2)
    } else if t.contains("privilege escalation") || t.contains("ta0004") {
        Some(3)
    } else if t.contains("defense evasion") || t.contains("ta0005") {
        Some(4)
    } else if t.contains("credential access") || t.contains("ta0006") {
        Some(5)
    } else if t.contains("discovery") || t.contains("ta0007") {
        Some(6)
    } else if t.contains("lateral movement") || t.contains("ta0008") {
        Some(7)
    } else if t.contains("collection") || t.contains("ta0009") {
        Some(8)
    } else if t.contains("exfiltration") || t.contains("ta0010") || t.contains("impact") || t.contains("ta0040") {
        Some(9)
    } else {
        None
    }
}

/// Maps any MITRE Tactic to its adversary intent archetype weights
pub fn get_tactic_affinities() -> HashMap<&'static str, HashMap<&'static str, f64>> {
    let mut map: HashMap<&'static str, HashMap<&'static str, f64>> = HashMap::new();

    let mut persistence = HashMap::new();
    persistence.insert("Long-Term APT & Identity Dominance", 3.8);
    persistence.insert("Ransomware & Double Extortion", 2.6);
    persistence.insert("Data Theft & Exfiltration", 2.2);
    persistence.insert("Destructive Wiper / Sabotage", 2.0);
    map.insert("persistence", persistence);

    let mut priv_esc = HashMap::new();
    priv_esc.insert("Ransomware & Double Extortion", 3.2);
    priv_esc.insert("Long-Term APT & Identity Dominance", 3.4);
    priv_esc.insert("Destructive Wiper / Sabotage", 2.8);
    priv_esc.insert("Data Theft & Exfiltration", 2.2);
    map.insert("privilege_escalation", priv_esc);

    let mut def_evasion = HashMap::new();
    def_evasion.insert("Destructive Wiper / Sabotage", 3.8);
    def_evasion.insert("Ransomware & Double Extortion", 3.6);
    def_evasion.insert("Long-Term APT & Identity Dominance", 3.2);
    def_evasion.insert("Data Theft & Exfiltration", 2.5);
    map.insert("defense_evasion", def_evasion);

    let mut cred_access = HashMap::new();
    cred_access.insert("Long-Term APT & Identity Dominance", 4.2);
    cred_access.insert("Data Theft & Exfiltration", 3.4);
    cred_access.insert("Ransomware & Double Extortion", 3.0);
    map.insert("credential_access", cred_access);

    let mut discovery = HashMap::new();
    discovery.insert("Data Theft & Exfiltration", 3.2);
    discovery.insert("Ransomware & Double Extortion", 2.8);
    discovery.insert("Long-Term APT & Identity Dominance", 2.8);
    map.insert("discovery", discovery);

    let mut lateral = HashMap::new();
    lateral.insert("Ransomware & Double Extortion", 4.0);
    lateral.insert("Long-Term APT & Identity Dominance", 3.6);
    lateral.insert("Data Theft & Exfiltration", 3.0);
    map.insert("lateral_movement", lateral);

    let mut collection = HashMap::new();
    collection.insert("Data Theft & Exfiltration", 4.8);
    collection.insert("Ransomware & Double Extortion", 2.6);
    map.insert("collection", collection);

    let mut exfil = HashMap::new();
    exfil.insert("Data Theft & Exfiltration", 5.0);
    exfil.insert("Ransomware & Double Extortion", 2.8);
    map.insert("exfiltration", exfil);

    let mut impact = HashMap::new();
    impact.insert("Ransomware & Double Extortion", 5.0);
    impact.insert("Destructive Wiper / Sabotage", 5.0);
    impact.insert("Cryptojacking & Resource Hijacking", 3.5);
    map.insert("impact", impact);

    map
}

/// Returns MITRE technique affinities for each Attacker Intent archetype
pub fn get_technique_affinities() -> HashMap<&'static str, HashMap<&'static str, f64>> {
    let mut map: HashMap<&'static str, HashMap<&'static str, f64>> = HashMap::new();

    // Inhibit System Recovery (vssadmin delete shadows, bcdedit, wbadmin)
    let mut t1490 = HashMap::new();
    t1490.insert("Ransomware & Double Extortion", 5.0);
    t1490.insert("Destructive Wiper / Sabotage", 4.0);
    map.insert("T1490", t1490);

    // Data Encrypted for Impact
    let mut t1486 = HashMap::new();
    t1486.insert("Ransomware & Double Extortion", 5.0);
    map.insert("T1486", t1486);

    // Data Destruction / Disk Wipe
    let mut t1485 = HashMap::new();
    t1485.insert("Destructive Wiper / Sabotage", 5.0);
    map.insert("T1485", t1485);

    // Defacement / Internal Defacement
    let mut t1491 = HashMap::new();
    t1491.insert("Destructive Wiper / Sabotage", 4.5);
    map.insert("T1491", t1491);

    // Archive Collected Data (7z, zip, rar, tar)
    let mut t1560 = HashMap::new();
    t1560.insert("Data Theft & Exfiltration", 4.5);
    t1560.insert("Ransomware & Double Extortion", 2.5);
    map.insert("T1560", t1560);

    // Exfiltration Over C2 / Web Service
    let mut t1041 = HashMap::new();
    t1041.insert("Data Theft & Exfiltration", 5.0);
    t1041.insert("Long-Term APT & Identity Dominance", 3.0);
    map.insert("T1041", t1041);

    // Exfiltration Over Alternative Protocol
    let mut t1048 = HashMap::new();
    t1048.insert("Data Theft & Exfiltration", 4.8);
    map.insert("T1048", t1048);

    // OS Credential Dumping (LSASS, sam, ntds.dit)
    let mut t1003 = HashMap::new();
    t1003.insert("Long-Term APT & Identity Dominance", 4.0);
    t1003.insert("Ransomware & Double Extortion", 3.0);
    t1003.insert("Data Theft & Exfiltration", 2.8);
    map.insert("T1003", t1003);

    // Steal or Forge Kerberos Tickets (Kerberoasting, Golden Ticket)
    let mut t1558 = HashMap::new();
    t1558.insert("Long-Term APT & Identity Dominance", 4.8);
    t1558.insert("Ransomware & Double Extortion", 2.5);
    map.insert("T1558", t1558);

    // Credentials from Password Stores / Browsers
    let mut t1555 = HashMap::new();
    t1555.insert("Data Theft & Exfiltration", 3.8);
    t1555.insert("Long-Term APT & Identity Dominance", 3.5);
    map.insert("T1555", t1555);

    // Create or Modify System Process (Windows Services, systemd, launchd)
    let mut t1543 = HashMap::new();
    t1543.insert("Long-Term APT & Identity Dominance", 3.6);
    t1543.insert("Ransomware & Double Extortion", 3.0);
    t1543.insert("Destructive Wiper / Sabotage", 2.5);
    map.insert("T1543", t1543);

    // Account Manipulation (Exchange delegates, group adjustments, credentials)
    let mut t1098 = HashMap::new();
    t1098.insert("Long-Term APT & Identity Dominance", 4.5);
    t1098.insert("Data Theft & Exfiltration", 2.8);
    t1098.insert("Ransomware & Double Extortion", 2.2);
    map.insert("T1098", t1098);

    // Create Account (Backdoor Local/Domain Accounts)
    let mut t1136 = HashMap::new();
    t1136.insert("Long-Term APT & Identity Dominance", 4.2);
    t1136.insert("Ransomware & Double Extortion", 2.5);
    map.insert("T1136", t1136);

    // Server Software Component (Web Shell, IIS backdoor)
    let mut t1505 = HashMap::new();
    t1505.insert("Long-Term APT & Identity Dominance", 4.5);
    t1505.insert("Data Theft & Exfiltration", 3.8);
    map.insert("T1505", t1505);

    // Valid Accounts (Compromised Credential usage)
    let mut t1078 = HashMap::new();
    t1078.insert("Long-Term APT & Identity Dominance", 4.0);
    t1078.insert("Data Theft & Exfiltration", 3.0);
    t1078.insert("Ransomware & Double Extortion", 2.8);
    map.insert("T1078", t1078);

    // Impair Defenses (disable EDR, defender, stop event log)
    let mut t1562 = HashMap::new();
    t1562.insert("Ransomware & Double Extortion", 4.2);
    t1562.insert("Destructive Wiper / Sabotage", 4.2);
    t1562.insert("Long-Term APT & Identity Dominance", 3.2);
    map.insert("T1562", t1562);

    // Indicator Removal (wevtutil clear logs, rm -rf history)
    let mut t1070 = HashMap::new();
    t1070.insert("Destructive Wiper / Sabotage", 4.5);
    t1070.insert("Long-Term APT & Identity Dominance", 3.6);
    t1070.insert("Ransomware & Double Extortion", 3.0);
    map.insert("T1070", t1070);

    // Resource Hijacking (Cryptomining, XMRig)
    let mut t1496 = HashMap::new();
    t1496.insert("Cryptojacking & Resource Hijacking", 5.0);
    map.insert("T1496", t1496);

    // Remote Services (SMB, PsExec, WMI lateral movement)
    let mut t1021 = HashMap::new();
    t1021.insert("Ransomware & Double Extortion", 4.0);
    t1021.insert("Data Theft & Exfiltration", 3.2);
    t1021.insert("Long-Term APT & Identity Dominance", 3.2);
    map.insert("T1021", t1021);

    // Command and Scripting Interpreter (PowerShell, cmd, bash)
    let mut t1059 = HashMap::new();
    t1059.insert("Ransomware & Double Extortion", 2.2);
    t1059.insert("Data Theft & Exfiltration", 2.2);
    t1059.insert("Long-Term APT & Identity Dominance", 2.2);
    t1059.insert("Destructive Wiper / Sabotage", 2.0);
    map.insert("T1059", t1059);

    // Abuse Elevation Control Mechanism (UAC bypass, setuid)
    let mut t1548 = HashMap::new();
    t1548.insert("Ransomware & Double Extortion", 3.5);
    t1548.insert("Long-Term APT & Identity Dominance", 3.5);
    t1548.insert("Destructive Wiper / Sabotage", 2.8);
    map.insert("T1548", t1548);

    // Exploitation for Privilege Escalation
    let mut t1068 = HashMap::new();
    t1068.insert("Long-Term APT & Identity Dominance", 3.8);
    t1068.insert("Ransomware & Double Extortion", 3.4);
    map.insert("T1068", t1068);

    // System Information & Network Discovery
    let mut t1082 = HashMap::new();
    t1082.insert("Data Theft & Exfiltration", 3.0);
    t1082.insert("Ransomware & Double Extortion", 2.8);
    t1082.insert("Long-Term APT & Identity Dominance", 2.6);
    map.insert("T1082", t1082);

    let mut t1087 = HashMap::new();
    t1087.insert("Long-Term APT & Identity Dominance", 3.4);
    t1087.insert("Ransomware & Double Extortion", 2.6);
    t1087.insert("Data Theft & Exfiltration", 2.8);
    map.insert("T1087", t1087);

    // Brute Force (Password Guessing, Spraying)
    let mut t1110 = HashMap::new();
    t1110.insert("Long-Term APT & Identity Dominance", 3.5);
    t1110.insert("Data Theft & Exfiltration", 2.5);
    map.insert("T1110", t1110);

    map
}

/// Converts technique and native MITRE tactic into the correct kill-chain stage index (0-9)
pub fn technique_and_tactic_to_stage(tech_id: &str, tactic: Option<&str>) -> usize {
    // 1. If explicit native tactic is provided, respect it as primary ground truth
    if let Some(t) = tactic {
        if let Some(stage) = tactic_to_stage(t) {
            return stage;
        }
    }

    // 2. Fall back to technique pattern matching
    let t = tech_id.trim().to_uppercase();
    if t.starts_with("T1190") || t.starts_with("T1566") || t.starts_with("T1133") {
        0 // Initial Access
    } else if t.starts_with("T1059") || t.starts_with("T1204") || t.starts_with("T1047") || t.starts_with("T1053") {
        1 // Execution
    } else if t.starts_with("T1547") || t.starts_with("T1543") || t.starts_with("T1136") || t.starts_with("T1098") || t.starts_with("T1505") {
        2 // Persistence
    } else if t.starts_with("T1068") || t.starts_with("T1548") || t.starts_with("T1134") {
        3 // Privilege Escalation
    } else if t.starts_with("T1562") || t.starts_with("T1070") || t.starts_with("T1036") || t.starts_with("T1027") || t.starts_with("T1112") {
        4 // Defense Evasion
    } else if t.starts_with("T1003") || t.starts_with("T1110") || t.starts_with("T1558") || t.starts_with("T1555") || t.starts_with("T1552") {
        5 // Credential Access
    } else if t.starts_with("T1087") || t.starts_with("T1082") || t.starts_with("T1046") || t.starts_with("T1083") || t.starts_with("T1018") || t.starts_with("T1057") {
        6 // Discovery
    } else if t.starts_with("T1021") || t.starts_with("T1570") || t.starts_with("T1550") || t.starts_with("T1563") {
        7 // Lateral Movement
    } else if t.starts_with("T1560") || t.starts_with("T1005") || t.starts_with("T1074") || t.starts_with("T1114") {
        8 // Staging & Collection
    } else if t.starts_with("T1486") || t.starts_with("T1490") || t.starts_with("T1485") || t.starts_with("T1496") || t.starts_with("T1041") || t.starts_with("T1048") {
        9 // Impact & Exfiltration
    } else if t.starts_with("T1078") {
        2 // Valid Accounts (default to Persistence)
    } else {
        1 // Default unknown execution rather than false 100% Impact
    }
}

/// Backward compatibility technique to stage mapper
pub fn technique_to_stage(tech_id: &str) -> usize {
    technique_and_tactic_to_stage(tech_id, None)
}
