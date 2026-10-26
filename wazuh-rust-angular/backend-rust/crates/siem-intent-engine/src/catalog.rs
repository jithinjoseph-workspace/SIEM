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

/// Returns MITRE technique affinities for each Attacker Intent archetype
/// Key: MITRE technique prefix/ID -> HashMap<Intent, Weight>
pub fn get_technique_affinities() -> HashMap<&'static str, HashMap<&'static str, f64>> {
    let mut map: HashMap<&'static str, HashMap<&'static str, f64>> = HashMap::new();

    // Inhibit System Recovery (vssadmin delete shadows, bcdedit, wbadmin)
    let mut t1490 = HashMap::new();
    t1490.insert("Ransomware & Double Extortion", 4.5);
    t1490.insert("Destructive Wiper / Sabotage", 3.8);
    map.insert("T1490", t1490);

    // Data Encrypted for Impact
    let mut t1486 = HashMap::new();
    t1486.insert("Ransomware & Double Extortion", 5.0);
    map.insert("T1486", t1486);

    // Data Destruction / Disk Wipe
    let mut t1485 = HashMap::new();
    t1485.insert("Destructive Wiper / Sabotage", 5.0);
    map.insert("T1485", t1485);

    // Archive Collected Data (7z, zip, rar, tar)
    let mut t1560 = HashMap::new();
    t1560.insert("Data Theft & Exfiltration", 4.2);
    t1560.insert("Ransomware & Double Extortion", 2.5); // double extortion prep
    map.insert("T1560", t1560);

    // Exfiltration Over C2 / Web Service
    let mut t1041 = HashMap::new();
    t1041.insert("Data Theft & Exfiltration", 4.8);
    t1041.insert("Long-Term APT & Identity Dominance", 3.0);
    map.insert("T1041", t1041);

    // OS Credential Dumping (LSASS, sam, ntds.dit)
    let mut t1003 = HashMap::new();
    t1003.insert("Long-Term APT & Identity Dominance", 3.5);
    t1003.insert("Ransomware & Double Extortion", 3.0);
    t1003.insert("Data Theft & Exfiltration", 2.8);
    map.insert("T1003", t1003);

    // Steal or Forge Kerberos Tickets (Kerberoasting, Golden Ticket)
    let mut t1558 = HashMap::new();
    t1558.insert("Long-Term APT & Identity Dominance", 4.5);
    t1558.insert("Ransomware & Double Extortion", 2.5);
    map.insert("T1558", t1558);

    // Impair Defenses (disable EDR, defender, stop event log)
    let mut t1562 = HashMap::new();
    t1562.insert("Ransomware & Double Extortion", 3.8);
    t1562.insert("Destructive Wiper / Sabotage", 3.8);
    t1562.insert("Long-Term APT & Identity Dominance", 3.2);
    map.insert("T1562", t1562);

    // Indicator Removal (wevtutil clear logs, rm -rf history)
    let mut t1070 = HashMap::new();
    t1070.insert("Destructive Wiper / Sabotage", 4.0);
    t1070.insert("Long-Term APT & Identity Dominance", 3.5);
    t1070.insert("Ransomware & Double Extortion", 3.0);
    map.insert("T1070", t1070);

    // Resource Hijacking (Cryptomining)
    let mut t1496 = HashMap::new();
    t1496.insert("Cryptojacking & Resource Hijacking", 5.0);
    map.insert("T1496", t1496);

    // Remote Services (SMB, PsExec, WMI lateral movement)
    let mut t1021 = HashMap::new();
    t1021.insert("Ransomware & Double Extortion", 3.4);
    t1021.insert("Data Theft & Exfiltration", 3.0);
    t1021.insert("Long-Term APT & Identity Dominance", 3.2);
    map.insert("T1021", t1021);

    // Command and Scripting Interpreter (PowerShell, cmd, bash)
    let mut t1059 = HashMap::new();
    t1059.insert("Ransomware & Double Extortion", 2.0);
    t1059.insert("Data Theft & Exfiltration", 2.0);
    t1059.insert("Long-Term APT & Identity Dominance", 2.0);
    t1059.insert("Destructive Wiper / Sabotage", 2.0);
    map.insert("T1059", t1059);

    map
}

/// Technique ID mapping to default stage
pub fn technique_to_stage(tech_id: &str) -> usize {
    let t = tech_id.trim().to_uppercase();
    if t.starts_with("T1190") || t.starts_with("T1566") || t.starts_with("T1133") {
        0 // Initial Access
    } else if t.starts_with("T1059") || t.starts_with("T1204") || t.starts_with("T1047") {
        1 // Execution
    } else if t.starts_with("T1547") || t.starts_with("T1543") || t.starts_with("T1136") {
        2 // Persistence
    } else if t.starts_with("T1068") || t.starts_with("T1548") || t.starts_with("T1134") {
        3 // Privilege Escalation
    } else if t.starts_with("T1562") || t.starts_with("T1070") || t.starts_with("T1036") {
        4 // Defense Evasion
    } else if t.starts_with("T1003") || t.starts_with("T1110") || t.starts_with("T1558") {
        5 // Credential Access
    } else if t.starts_with("T1087") || t.starts_with("T1082") || t.starts_with("T1046") {
        6 // Discovery
    } else if t.starts_with("T1021") || t.starts_with("T1570") || t.starts_with("T1550") {
        7 // Lateral Movement
    } else if t.starts_with("T1560") || t.starts_with("T1005") || t.starts_with("T1074") {
        8 // Staging & Collection
    } else {
        9 // Impact & Exfiltration
    }
}
