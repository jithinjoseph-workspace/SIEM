//! The attacks Red Swarm simulates. Each one's samples are events exactly as the agents send them
//! to the analysis engine: a Windows agent's event-channel payload (`{"Message":..,"Event":"<Event>"}`)
//! or a Linux agent's log line. Placeholders filled when a round runs: `%HOST%` (the target's
//! name), `%NOW%` (ISO time) and `%SYSLOGTIME%` (`Nov 18 10:00:01`).
//!
//! `expected_mitre_ids` are the ATT&CK ids the shipped rules tag these events with: a round is
//! Defended when an alert of its own events carries one of them. The engine test
//! (`siem-api/src/redswarm_engine.rs`) runs every sample through the real ruleset.

use crate::models::{AttackTechnique, CommandPayload, RiskLevel};

/// A Windows event as the agent sends it (`provigil-agent/src/wevt.rs`): the message, then the XML.
fn win_event(provider: &str, guid: &str, channel: &str, event_id: u32, level: u8, message: &str, data: &[(&str, &str)]) -> String {
    win_event_k(provider, guid, channel, event_id, level, AUDIT_SUCCESS, message, data)
}

/// Security events say success or failure in their keywords.
const AUDIT_SUCCESS: &str = "0x8020000000000000";
const AUDIT_FAILURE: &str = "0x8010000000000000";

#[allow(clippy::too_many_arguments)]
fn win_event_k(provider: &str, guid: &str, channel: &str, event_id: u32, level: u8, keywords: &str, message: &str, data: &[(&str, &str)]) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\'', "&apos;");
    let mut xml = format!(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{provider}' Guid='{guid}'/><EventID>{event_id}</EventID><Version>0</Version><Level>{level}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords><TimeCreated SystemTime='%NOW%'/><EventRecordID>1</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>{channel}</Channel><Computer>%HOST%</Computer><Security/></System><EventData>"
    );
    for (k, v) in data {
        xml.push_str(&format!("<Data Name='{k}'>{}</Data>", esc(v)));
    }
    xml.push_str("</EventData></Event>");
    let js = |s: &str| serde_json::Value::from(s).to_string();
    format!("{{\"Message\":{},\"Event\":{}}}", js(message), js(&xml))
}

const SECURITY: (&str, &str) = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-a5ba-3e3b0328c30d}");
const SYSMON: (&str, &str) = ("Microsoft-Windows-Sysmon", "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}");
const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

fn security(event_id: u32, message: &str, data: &[(&str, &str)]) -> String {
    win_event(SECURITY.0, SECURITY.1, "Security", event_id, 0, message, data)
}

fn sysmon(event_id: u32, message: &str, data: &[(&str, &str)]) -> String {
    win_event(SYSMON.0, SYSMON.1, SYSMON_CHANNEL, event_id, 4, message, data)
}

/// A Linux log line as the agent reads it from the file.
fn syslog(rest: &str) -> String {
    format!("%SYSLOGTIME% %HOST% {rest}")
}

/// Simulated only: live modes are off (siem-api has no safe channel to run attack commands).
fn simulated() -> CommandPayload {
    CommandPayload { command: String::new(), timeout_seconds: 0, requires_elevation: false }
}

fn technique(id: &str, name: &str, tactic: &str, platform: &str, mitre: &[&str], groups: &[&str], indicators: &[&str], samples: Vec<String>) -> AttackTechnique {
    let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    AttackTechnique {
        id: id.into(),
        name: name.into(),
        tactic: tactic.into(),
        platforms: vec![platform.into()],
        risk_level: RiskLevel::Low,
        reversible: true,
        cleanup_guaranteed: true,
        execution: simulated(),
        cleanup: simulated(),
        expected_telemetry: v(indicators),
        expected_mitre_ids: v(mitre),
        expected_rule_groups: v(groups),
        detection_indicators: v(indicators),
        banned_in_controlled_live: true,
        sample_raw_logs: samples,
    }
}

/// Returns the curated ATT&CK technique catalog: 8 Windows and 7 Linux attacks.
pub fn get_curated_catalog() -> Vec<AttackTechnique> {
    let failed_logon = |port: &str| {
        win_event_k(SECURITY.0, SECURITY.1, "Security", 4625, 0, AUDIT_FAILURE, "An account failed to log on.", &[
            ("SubjectUserSid", "S-1-0-0"), ("TargetUserName", "administrator"), ("TargetDomainName", "CORP"),
            ("Status", "0xc000006d"), ("SubStatus", "0xc000006a"), ("LogonType", "3"),
            ("WorkstationName", "KALI"), ("IpAddress", "203.0.113.50"), ("IpPort", port),
            ("LogonProcessName", "NtLmSsp"), ("AuthenticationPackageName", "NTLM"),
        ])
    };
    let ssh_failure = |port: u32| syslog(&format!("sshd[4102]: Failed password for root from 203.0.113.50 port {port} ssh2"));
    vec![
        // ---------------- Windows ----------------
        technique("T1110", "Password guessing against a Windows account", "Credential Access", "windows",
            &["T1110", "T1078", "T1531"], &["authentication_failed", "authentication_failures"], &["4625", "administrator"],
            (0..10).map(|i| failed_logon(&format!("{}", 50000 + i))).collect()),
        technique("T1070.004", "Clear the Windows Security log", "Defense Evasion", "windows",
            &["T1070"], &["logs_cleared"], &["1102"],
            vec![win_event("Microsoft-Windows-Eventlog", "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}", "Security", 1102, 4, "The audit log was cleared.", &[
                ("SubjectUserSid", "S-1-5-21-1004336348-1177238915-682003330-1000"), ("SubjectUserName", "attacker"), ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x3e7"),
            ])]),
        technique("T1136.001", "Create a local Windows account", "Persistence", "windows",
            &["T1098", "T1136"], &["adduser", "account_changed"], &["4720", "svc-backup"],
            vec![security(4720, "A user account was created.", &[
                ("TargetUserName", "svc-backup"), ("TargetDomainName", "%HOST%"), ("TargetSid", "S-1-5-21-1004336348-1177238915-682003330-1105"),
                ("SubjectUserSid", "S-1-5-21-1004336348-1177238915-682003330-1000"), ("SubjectUserName", "attacker"), ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x3e7"),
                ("SamAccountName", "svc-backup"), ("DisplayName", "%%1793"), ("UserPrincipalName", "-"),
            ])]),
        technique("T1098.007", "Add an account to the local Administrators group", "Persistence", "windows",
            &["T1484", "T1098"], &["group_changed", "win_group_changed"], &["4732", "Administrators"],
            vec![security(4732, "A member was added to a security-enabled local group.", &[
                ("MemberName", "-"), ("MemberSid", "S-1-5-21-1004336348-1177238915-682003330-1105"),
                ("TargetUserName", "Administrators"), ("TargetDomainName", "Builtin"), ("TargetSid", "S-1-5-32-544"),
                ("SubjectUserSid", "S-1-5-21-1004336348-1177238915-682003330-1000"), ("SubjectUserName", "attacker"), ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x3e7"),
            ])]),
        technique("T1543.003", "Install a new Windows service", "Persistence", "windows",
            &["T1543"], &["windows"], &["7045", "UpdaterSvc"],
            vec![win_event("Service Control Manager", "{555908d1-a6d7-4695-8e1e-26931d2012f4}", "System", 7045, 4, "A service was installed in the system.", &[
                ("ServiceName", "UpdaterSvc"), ("ImagePath", "C:\\Users\\Public\\updater.exe"), ("ServiceType", "user mode service"),
                ("StartType", "auto start"), ("AccountName", "LocalSystem"),
            ])]),
        technique("T1059.001", "Run an encoded PowerShell command", "Execution", "windows",
            &["T1059"], &["sysmon_event1"], &["-EncodedCommand", "powershell.exe"],
            vec![sysmon(1, "Process Create", &[
                ("RuleName", "-"), ("UtcTime", "%NOW%"), ("ProcessGuid", "{8a6e1f3c-0000-0000-0000-000000000001}"), ("ProcessId", "4420"),
                ("Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), ("FileVersion", "10.0.19041.1"),
                ("Description", "Windows PowerShell"), ("Product", "Microsoft Windows Operating System"), ("Company", "Microsoft Corporation"),
                ("OriginalFileName", "PowerShell.EXE"),
                ("CommandLine", "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
                ("CurrentDirectory", "C:\\Users\\Public\\"), ("User", "CORP\\attacker"), ("IntegrityLevel", "High"),
                ("Hashes", "SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C"),
                ("ParentProcessGuid", "{8a6e1f3c-0000-0000-0000-000000000002}"), ("ParentProcessId", "3310"),
                ("ParentImage", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                ("ParentCommandLine", "powershell.exe"), ("ParentUser", "CORP\\attacker"),
            ])]),
        technique("T1003.001", "Read the memory of LSASS (credential dumping)", "Credential Access", "windows",
            &["T1003"], &["sysmon_event_10"], &["lsass.exe"],
            vec![sysmon(10, "Process accessed", &[
                ("RuleName", "-"), ("UtcTime", "%NOW%"), ("SourceProcessGUID", "{8a6e1f3c-0000-0000-0000-000000000003}"), ("SourceProcessId", "5120"),
                ("SourceThreadId", "5124"), ("SourceImage", "C:\\Users\\Public\\procdump64.exe"),
                ("TargetProcessGUID", "{8a6e1f3c-0000-0000-0000-000000000004}"), ("TargetProcessId", "712"),
                ("TargetImage", "C:\\Windows\\system32\\lsass.exe"), ("GrantedAccess", "0x1010"),
                ("CallTrace", "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|UNKNOWN(00000000)"), ("SourceUser", "CORP\\attacker"), ("TargetUser", "NT AUTHORITY\\SYSTEM"),
            ])]),
        technique("T1547.001", "Add a program to the registry Run key", "Persistence", "windows",
            &["T1547"], &["sysmon_event_13"], &["CurrentVersion\\Run"],
            vec![sysmon(13, "Registry value set", &[
                ("RuleName", "-"), ("EventType", "SetValue"), ("UtcTime", "%NOW%"), ("ProcessGuid", "{8a6e1f3c-0000-0000-0000-000000000005}"), ("ProcessId", "6012"),
                ("Image", "C:\\Windows\\system32\\reg.exe"),
                ("TargetObject", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"),
                ("Details", "C:\\Users\\Public\\updater.vbs"), ("User", "CORP\\attacker"),
            ])]),
        // ---------------- Linux ----------------
        technique("T1110.001", "SSH password guessing", "Credential Access", "linux",
            &["T1110"], &["sshd", "authentication_failed"], &["Failed password", "sshd"],
            (0..10).map(|i| ssh_failure(54820 + i)).collect()),
        technique("T1548.003", "Become root with sudo", "Privilege Escalation", "linux",
            &["T1548"], &["sudo"], &["sudo", "USER=root"],
            vec![syslog("sudo:    attacker : TTY=pts/0 ; PWD=/home/attacker ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")]),
        technique("T1136.001", "Create a local Linux account", "Persistence", "linux",
            &["T1136"], &["adduser"], &["new user", "useradd"],
            vec![syslog("useradd[2201]: new user: name=svc-backup, UID=1005, GID=1005, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/0")]),
        technique("T1098", "Add an account to the sudo group", "Persistence", "linux",
            &["T1136", "T1098"], &["adduser"], &["added by", "group sudo"],
            vec![syslog("gpasswd[2202]: user svc-backup added by root to group sudo")]),
        technique("T1053.003", "Change root's crontab", "Persistence", "linux",
            &["T1053"], &["cron"], &["crontab", "REPLACE"],
            vec![syslog("crontab[3301]: (root) REPLACE (root)")]),
        technique("T1547.006", "Load an unsigned kernel module", "Persistence", "linux",
            &["T1547"], &["kernel"], &["module verification failed"],
            vec![syslog("kernel: [ 9182.204115] diamorphine: module verification failed: signature and/or required key missing - tainting kernel")]),
        technique("T1040", "Put a network card in sniffing mode", "Credential Access", "linux",
            &["T1040"], &["promisc"], &["promiscuous mode"],
            vec![syslog("kernel: [ 9200.512331] device eth0 entered promiscuous mode")]),
    ]
}

/// Look up technique by ID
pub fn find_technique(id: &str) -> Option<AttackTechnique> {
    get_curated_catalog().into_iter().find(|t| t.id == id)
}

/// The same technique id is used on both systems for some attacks (password guessing, a new
/// account): the one for `platform`, else the first.
/// The log an attack shows up in, read from its own first sample: a Windows event channel
/// (`Security`, `Microsoft-Windows-Sysmon/Operational`) or a Linux program (`sshd`, `kernel`).
pub fn log_source(t: &AttackTechnique) -> Option<String> {
    let s = t.sample_raw_logs.first()?;
    if let Some((_, rest)) = s.split_once("<Channel>") {
        return rest.split_once("</Channel>").map(|(c, _)| c.to_string());
    }
    let rest = s.strip_prefix("%SYSLOGTIME% %HOST% ")?;
    let end = rest.find(['[', ':'])?;
    Some(rest[..end].to_string())
}

pub fn find_technique_for(id: &str, platform: &str) -> Option<AttackTechnique> {
    let all = get_curated_catalog();
    let fits = |t: &&AttackTechnique| t.id == id && t.platforms.iter().any(|p| p.eq_ignore_ascii_case(platform));
    all.iter().find(fits).or_else(|| all.iter().find(|t| t.id == id)).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_attack_names_the_log_it_shows_up_in() {
        for t in get_curated_catalog() {
            let src = log_source(&t).unwrap_or_else(|| panic!("{} ({}) has no log source", t.id, t.platforms[0]));
            assert!(!src.is_empty() && !src.contains(' '), "{}: {src:?}", t.id);
        }
        let src = |id, os| log_source(&find_technique_for(id, os).unwrap()).unwrap();
        assert_eq!(src("T1110", "windows"), "Security");
        assert_eq!(src("T1059.001", "windows"), "Microsoft-Windows-Sysmon/Operational");
        assert_eq!(src("T1110.001", "linux"), "sshd");
        assert_eq!(src("T1548.003", "linux"), "sudo");
        assert_eq!(src("T1040", "linux"), "kernel");
    }
}
