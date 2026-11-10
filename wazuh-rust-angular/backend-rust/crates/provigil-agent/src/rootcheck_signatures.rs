//! ProVigil's own rootcheck signature lists (compiled in) and the text formats they are written in.
//! Extra lists in the same formats can be added from files (`rootcheck_files_list`,
//! `rootcheck_trojans_list`, `rootcheck_policies` in `provigil-agent.json`).
//!
//! Every format: one entry per line, fields separated by `;` (spaces around fields are trimmed),
//! blank lines and lines starting with `#` ignored. `%NAME%` in paths is replaced by the
//! environment variable's value.
//!
//! **Files list** — `<path> ; <name> ; <reference>`. A path starting with `*` is a file name
//! searched under `%SystemDrive%\` (6 folder levels deep); any other path is checked as written.
//!
//! **Trojans list** — `<program path> ; <name> ; <reference> ; <regex>`. The regular expression
//! is matched against the program's bytes (last field, so it may contain `;`).
//!
//! **Policies** — a header line `<list> ; <name> ; all|any ; <reference>` (`<list>` is `malware`,
//! `application` or `audit`; the reference may be left out), followed by its condition lines:
//! - `f:<path>` the file or folder exists; `f:<path> -> <regex>` and its content matches;
//! - `r:<key>` the registry key exists (`HKLM`, `HKCU`, `HKU`, `HKCR`, 64-bit view);
//!   `r:<key> -> <value name>` the value exists; `r:<key> -> <value name> -> <regex>` its data
//!   matches (text values as text, multi-string values joined by spaces, numbers in decimal,
//!   other types as lowercase hex);
//! - `p:<process name>` a process of that name runs (case-insensitive); `p:r:<regex>` one whose
//!   name matches (case-insensitive).
//!
//! A `!` before a condition negates it. `all`: every condition holds; `any`: at least one does.

use regex::bytes::{Regex, RegexBuilder};

#[derive(Debug, Clone)]
pub struct FileSig {
    pub path: String,
    pub name: String,
    pub reference: String,
}

#[derive(Debug, Clone)]
pub struct TrojanSig {
    pub path: String,
    pub name: String,
    pub reference: String,
    /// The regular expression as written (it is quoted in the finding).
    pub pattern: String,
    pub regex: Regex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyList {
    Malware,
    Application,
    Audit,
}

impl PolicyList {
    pub fn title(self) -> &'static str {
        match self {
            PolicyList::Malware => "Windows Malware:",
            PolicyList::Application => "Application Found:",
            PolicyList::Audit => "Windows Audit:",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Test {
    File { path: String, content: Option<Regex> },
    Registry { key: String, value: Option<String>, data: Option<Regex> },
    Process(Regex),
}

#[derive(Debug, Clone)]
pub struct Condition {
    pub negate: bool,
    pub test: Test,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub list: PolicyList,
    pub name: String,
    pub any: bool,
    /// Empty when none.
    pub reference: String,
    pub conditions: Vec<Condition>,
}

/// The non-comment lines with their line numbers.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().map(|(i, l)| (i + 1, l.trim())).filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// Exactly `n` `;`-separated fields, none empty.
fn fields(line: &str, n: usize) -> Option<Vec<&str>> {
    let f: Vec<&str> = line.splitn(n, ';').map(str::trim).collect();
    (f.len() == n && f.iter().all(|s| !s.is_empty())).then_some(f)
}

fn regex(pattern: &str, case_insensitive: bool) -> Result<Regex, String> {
    RegexBuilder::new(pattern).case_insensitive(case_insensitive).build().map_err(|e| format!("bad regex '{pattern}': {e}"))
}

pub fn parse_files(text: &str) -> Result<Vec<FileSig>, String> {
    lines(text)
        .map(|(n, l)| {
            let f = fields(l, 3).ok_or(format!("line {n}: expected '<path> ; <name> ; <reference>'"))?;
            Ok(FileSig { path: f[0].into(), name: f[1].into(), reference: f[2].into() })
        })
        .collect()
}

pub fn parse_trojans(text: &str) -> Result<Vec<TrojanSig>, String> {
    lines(text)
        .map(|(n, l)| {
            let f = fields(l, 4).ok_or(format!("line {n}: expected '<path> ; <name> ; <reference> ; <regex>'"))?;
            let regex = regex(f[3], false).map_err(|e| format!("line {n}: {e}"))?;
            Ok(TrojanSig { path: f[0].into(), name: f[1].into(), reference: f[2].into(), pattern: f[3].into(), regex })
        })
        .collect()
}

fn parse_condition(line: &str) -> Result<Condition, String> {
    let (negate, c) = match line.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, line),
    };
    let (kind, rest) = (c.get(..2).unwrap_or(""), c.get(2..).unwrap_or("").trim());
    let test = match kind {
        "f:" => {
            let mut p = rest.splitn(2, " -> ").map(str::trim);
            let path = p.next().unwrap_or_default().to_string();
            Test::File { path, content: p.next().map(|r| regex(r, false)).transpose()? }
        }
        "r:" => {
            let mut p = rest.splitn(3, " -> ").map(str::trim);
            let key = p.next().unwrap_or_default().to_string();
            let value = p.next().map(String::from);
            Test::Registry { key, value, data: p.next().map(|r| regex(r, false)).transpose()? }
        }
        "p:" => match rest.strip_prefix("r:") {
            Some(r) => Test::Process(regex(r.trim(), true)?),
            None => Test::Process(regex(&format!("^{}$", regex::escape(rest)), true)?),
        },
        _ => return Err(format!("unknown condition '{line}'")),
    };
    let empty = match &test {
        Test::File { path, .. } => path.is_empty(),
        Test::Registry { key, .. } => key.is_empty(),
        Test::Process(r) => r.as_str() == "^$",
    };
    if empty {
        return Err(format!("empty condition '{line}'"));
    }
    Ok(Condition { negate, test })
}

fn is_condition(line: &str) -> bool {
    let c = line.strip_prefix('!').map(str::trim_start).unwrap_or(line);
    ["f:", "r:", "p:"].iter().any(|k| c.starts_with(k))
}

pub fn parse_policies(text: &str) -> Result<Vec<Policy>, String> {
    let mut out: Vec<Policy> = Vec::new();
    for (n, l) in lines(text) {
        if is_condition(l) {
            let p = out.last_mut().ok_or(format!("line {n}: condition before any header"))?;
            p.conditions.push(parse_condition(l).map_err(|e| format!("line {n}: {e}"))?);
            continue;
        }
        if out.last().is_some_and(|p| p.conditions.is_empty()) {
            return Err(format!("line {n}: the previous entry has no conditions"));
        }
        let mut f: Vec<&str> = l.splitn(4, ';').map(str::trim).collect();
        if f.len() == 3 {
            f.push("");
        }
        let bad = || format!("line {n}: expected '<malware|application|audit> ; <name> ; <all|any> ; <reference>'");
        if f.len() != 4 || f[1].is_empty() {
            return Err(bad());
        }
        let list = match f[0].to_ascii_lowercase().as_str() {
            "malware" => PolicyList::Malware,
            "application" => PolicyList::Application,
            "audit" => PolicyList::Audit,
            _ => return Err(bad()),
        };
        let any = match f[2].to_ascii_lowercase().as_str() {
            "any" => true,
            "all" => false,
            _ => return Err(bad()),
        };
        out.push(Policy { list, name: f[1].into(), any, reference: f[3].into(), conditions: Vec::new() });
    }
    if out.last().is_some_and(|p| p.conditions.is_empty()) {
        return Err("the last entry has no conditions".into());
    }
    Ok(out)
}

pub fn builtin_files() -> Vec<FileSig> {
    parse_files(FILES).expect("built-in files list")
}

pub fn builtin_trojans() -> Vec<TrojanSig> {
    parse_trojans(TROJANS).expect("built-in trojans list")
}

pub fn builtin_policies() -> Vec<Policy> {
    parse_policies(POLICIES).expect("built-in policies")
}

/// Well-known Windows malware, hacktool and rootkit artefacts.
pub const FILES: &str = r"
# Credential theft tools
*mimikatz.exe ; Mimikatz ; https://attack.mitre.org/software/S0002/
*mimilib.dll ; Mimikatz security support provider ; https://attack.mitre.org/software/S0002/
*mimidrv.sys ; Mimikatz kernel driver ; https://attack.mitre.org/software/S0002/
*Invoke-Mimikatz.ps1 ; Mimikatz PowerShell loader ; https://attack.mitre.org/software/S0002/
*SafetyKatz.exe ; SafetyKatz (Mimikatz variant) ; https://attack.mitre.org/techniques/T1003/001/
*lsass.dmp ; LSASS memory dump left on disk ; https://attack.mitre.org/techniques/T1003/001/
*nanodump.exe ; NanoDump LSASS dumper ; https://attack.mitre.org/techniques/T1003/001/
*Outflank-Dumpert.exe ; Dumpert LSASS dumper ; https://attack.mitre.org/techniques/T1003/001/
*wce.exe ; Windows Credential Editor ; https://attack.mitre.org/software/S0005/
*pwdump7.exe ; pwdump ; https://attack.mitre.org/software/S0006/
*fgdump.exe ; fgdump password hash dumper ; https://attack.mitre.org/techniques/T1003/002/
*gsecdump.exe ; gsecdump ; https://attack.mitre.org/software/S0008/
*lazagne.exe ; LaZagne ; https://attack.mitre.org/software/S0349/
*SharpDPAPI.exe ; SharpDPAPI credential decryptor ; https://attack.mitre.org/techniques/T1555/004/
*secretsdump.exe ; Impacket secretsdump ; https://attack.mitre.org/software/S0357/
# Kerberos, Active Directory and privilege escalation tools
*Rubeus.exe ; Rubeus ; https://attack.mitre.org/software/S1071/
*kekeo.exe ; Kekeo Kerberos toolkit ; https://attack.mitre.org/techniques/T1558/
*SharpHound.exe ; SharpHound (BloodHound collector) ; https://attack.mitre.org/software/S0521/
*SharpHound.ps1 ; SharpHound (BloodHound collector) ; https://attack.mitre.org/software/S0521/
*PowerView.ps1 ; PowerSploit PowerView ; https://attack.mitre.org/software/S0194/
*Invoke-Kerberoast.ps1 ; Kerberoasting script ; https://attack.mitre.org/techniques/T1558/003/
*Certify.exe ; Certify certificate abuse tool ; https://attack.mitre.org/techniques/T1649/
*Inveigh.exe ; Inveigh name-resolution poisoner ; https://attack.mitre.org/techniques/T1557/001/
*PetitPotam.exe ; PetitPotam forced authentication ; https://attack.mitre.org/techniques/T1187/
*SpoolSample.exe ; SpoolSample forced authentication ; https://attack.mitre.org/techniques/T1187/
*JuicyPotato.exe ; JuicyPotato token impersonation ; https://attack.mitre.org/techniques/T1134/001/
*PrintSpoofer.exe ; PrintSpoofer token impersonation ; https://attack.mitre.org/techniques/T1134/001/
*PrintSpoofer64.exe ; PrintSpoofer token impersonation ; https://attack.mitre.org/techniques/T1134/001/
*winPEASx64.exe ; winPEAS privilege escalation scanner ; https://attack.mitre.org/techniques/T1082/
*winPEAS.exe ; winPEAS privilege escalation scanner ; https://attack.mitre.org/techniques/T1082/
# Remote execution services left behind
%WINDIR%\PSEXESVC.exe ; PsExec service binary ; https://attack.mitre.org/software/S0029/
%WINDIR%\RemComSvc.exe ; RemCom remote execution service ; https://attack.mitre.org/techniques/T1569/002/
%WINDIR%\csexecsvc.exe ; CSExec remote execution service ; https://attack.mitre.org/techniques/T1569/002/
# Remote access trojans
*msdcsc.exe ; DarkComet ; https://attack.mitre.org/software/S0334/
*remcos.exe ; Remcos ; https://attack.mitre.org/software/S0332/
*dhcpmon.exe ; NanoCore ; https://attack.mitre.org/software/S0336/
# Tunnelling
*chisel.exe ; Chisel tunnel ; https://attack.mitre.org/techniques/T1572/
# Cryptominers
*xmrig.exe ; XMRig cryptominer ; https://attack.mitre.org/techniques/T1496/
*xmr-stak.exe ; XMR-Stak cryptominer ; https://attack.mitre.org/techniques/T1496/
*minerd.exe ; cpuminer cryptominer ; https://attack.mitre.org/techniques/T1496/
# Rootkits and abused drivers
%WINDIR%\System32\drivers\hxdefdrv.sys ; Hacker Defender rootkit driver ; https://attack.mitre.org/techniques/T1014/
*hxdef100.exe ; Hacker Defender rootkit ; https://attack.mitre.org/techniques/T1014/
%WINDIR%\System32\drivers\msdirectx.sys ; FU rootkit driver ; https://attack.mitre.org/techniques/T1014/
*vanquish.dll ; Vanquish rootkit ; https://attack.mitre.org/techniques/T1014/
%WINDIR%\System32\drivers\gdrv.sys ; Vulnerable Gigabyte driver used to load unsigned drivers ; https://attack.mitre.org/techniques/T1068/
";

/// Tampered System32 programs. The `W\x00i\x00...` patterns are UTF-16 version-resource text
/// (the program's description), so a program replaced by another one is recognised.
pub const TROJANS: &str = r"
%WINDIR%\System32\sethc.exe ; Sticky Keys replaced by the command prompt ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00C\x00o\x00m\x00m\x00a\x00n\x00d\x00 \x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00o\x00r\x00
%WINDIR%\System32\utilman.exe ; Utility Manager replaced by the command prompt ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00C\x00o\x00m\x00m\x00a\x00n\x00d\x00 \x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00o\x00r\x00
%WINDIR%\System32\osk.exe ; On-Screen Keyboard replaced by the command prompt ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00C\x00o\x00m\x00m\x00a\x00n\x00d\x00 \x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00o\x00r\x00
%WINDIR%\System32\Magnify.exe ; Magnifier replaced by the command prompt ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00C\x00o\x00m\x00m\x00a\x00n\x00d\x00 \x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00o\x00r\x00
%WINDIR%\System32\Narrator.exe ; Narrator replaced by the command prompt ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00C\x00o\x00m\x00m\x00a\x00n\x00d\x00 \x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00o\x00r\x00
%WINDIR%\System32\DisplaySwitch.exe ; Display Switch replaced by the command prompt ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00C\x00o\x00m\x00m\x00a\x00n\x00d\x00 \x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00o\x00r\x00
%WINDIR%\System32\AtBroker.exe ; Accessibility broker replaced by the command prompt ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00C\x00o\x00m\x00m\x00a\x00n\x00d\x00 \x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00o\x00r\x00
%WINDIR%\System32\sethc.exe ; Sticky Keys replaced by PowerShell ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00P\x00o\x00w\x00e\x00r\x00S\x00h\x00e\x00l\x00l\x00
%WINDIR%\System32\utilman.exe ; Utility Manager replaced by PowerShell ; https://attack.mitre.org/techniques/T1546/008/ ; W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00P\x00o\x00w\x00e\x00r\x00S\x00h\x00e\x00l\x00l\x00
%WINDIR%\System32\cmd.exe ; Command prompt repacked with UPX ; https://attack.mitre.org/techniques/T1027/002/ ; UPX0\x00\x00\x00\x00
%WINDIR%\System32\net.exe ; net.exe repacked with UPX ; https://attack.mitre.org/techniques/T1027/002/ ; UPX0\x00\x00\x00\x00
%WINDIR%\System32\svchost.exe ; svchost.exe repacked with UPX ; https://attack.mitre.org/techniques/T1027/002/ ; UPX0\x00\x00\x00\x00
%WINDIR%\System32\lsass.exe ; lsass.exe carrying Mimikatz code ; https://attack.mitre.org/software/S0002/ ; (?i)sekurlsa::|gentilkiwi|mimikatz
%WINDIR%\System32\svchost.exe ; svchost.exe carrying a reflective loader ; https://attack.mitre.org/techniques/T1620/ ; ReflectiveLoader
%WINDIR%\System32\winlogon.exe ; winlogon.exe carrying a reflective loader ; https://attack.mitre.org/techniques/T1620/ ; ReflectiveLoader
%WINDIR%\explorer.exe ; explorer.exe carrying a cryptominer ; https://attack.mitre.org/techniques/T1496/ ; stratum\+tcp://
";

/// Malware indicators, risky applications and hardening settings.
pub const POLICIES: &str = r"
# --- Windows Malware ---
malware ; Mimikatz running ; any ; https://attack.mitre.org/software/S0002/
p:mimikatz.exe
p:r:^(safetykatz|sharpkatz)\.exe$
malware ; Mimikatz security support provider installed ; any ; https://attack.mitre.org/software/S0002/
f:%WINDIR%\System32\mimilib.dll
f:%WINDIR%\System32\kiwissp.log
f:%WINDIR%\System32\mimilsa.log
malware ; Mimikatz package in LSA security packages ; all ; https://attack.mitre.org/techniques/T1547/005/
r:HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> Security Packages -> (?i)mimilib
malware ; XMRig cryptominer running ; all ; https://attack.mitre.org/techniques/T1496/
p:xmrig.exe
malware ; Cryptominer running ; all ; https://attack.mitre.org/techniques/T1496/
p:r:^(xmr-stak|minerd|cpuminer|nheqminer|ethminer|t-rex|phoenixminer|lolminer|nbminer)\.exe$
malware ; DarkComet remote access trojan ; any ; https://attack.mitre.org/software/S0334/
p:msdcsc.exe
r:HKCU\Software\DC3_FEXEC
malware ; Remcos remote access trojan ; any ; https://attack.mitre.org/software/S0332/
p:remcos.exe
f:%APPDATA%\Remcos\remcos.exe
malware ; NanoCore remote access trojan ; any ; https://attack.mitre.org/software/S0336/
p:dhcpmon.exe
malware ; Credential theft tool running ; any ; https://attack.mitre.org/software/S0349/
p:lazagne.exe
p:r:^(wce|pwdump7|fgdump|gsecdump|nanodump|outflank-dumpert)\.exe$
malware ; Active Directory attack tool running ; any ; https://attack.mitre.org/software/S1071/
p:rubeus.exe
p:r:^(sharphound|kekeo|certify|inveigh|petitpotam|spoolsample)\.exe$
malware ; Sticky Keys debugger backdoor ; all ; https://attack.mitre.org/techniques/T1546/008/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe -> Debugger
malware ; Utility Manager debugger backdoor ; all ; https://attack.mitre.org/techniques/T1546/008/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe -> Debugger
malware ; On-Screen Keyboard debugger backdoor ; all ; https://attack.mitre.org/techniques/T1546/008/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe -> Debugger
malware ; Magnifier debugger backdoor ; all ; https://attack.mitre.org/techniques/T1546/008/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe -> Debugger
malware ; Narrator debugger backdoor ; all ; https://attack.mitre.org/techniques/T1546/008/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe -> Debugger
malware ; Display Switch debugger backdoor ; all ; https://attack.mitre.org/techniques/T1546/008/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\displayswitch.exe -> Debugger
malware ; AppInit DLLs loaded into every process ; all ; https://attack.mitre.org/techniques/T1546/010/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows -> AppInit_DLLs -> \S
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows -> LoadAppInit_DLLs -> ^1$
malware ; Winlogon shell replaced ; all ; https://attack.mitre.org/techniques/T1547/004/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> Shell
!r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> Shell -> (?i)^\s*explorer\.exe\s*$
malware ; Winlogon Userinit changed ; all ; https://attack.mitre.org/techniques/T1547/004/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> Userinit
!r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> Userinit -> (?i)^\s*[a-z]:\\windows\\system32\\userinit\.exe\s*,?\s*$
malware ; LSASS dump on process exit configured ; all ; https://attack.mitre.org/techniques/T1003/001/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe
malware ; Hidden user account ; all ; https://attack.mitre.org/techniques/T1564/002/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList
malware ; Hacker Defender rootkit service ; any ; https://attack.mitre.org/techniques/T1014/
r:HKLM\SYSTEM\CurrentControlSet\Services\HackerDefender100
r:HKLM\SYSTEM\CurrentControlSet\Services\HackerDefenderDrv100
malware ; FU rootkit driver service ; all ; https://attack.mitre.org/techniques/T1014/
r:HKLM\SYSTEM\CurrentControlSet\Services\msdirectx
malware ; Screensaver run from a user-writable folder ; all ; https://attack.mitre.org/techniques/T1546/002/
r:HKCU\Control Panel\Desktop -> SCRNSAVE.EXE -> (?i)\\(temp|appdata|downloads|users\\public)\\
malware ; Office test DLL persistence ; all ; https://attack.mitre.org/techniques/T1137/002/
r:HKCU\Software\Microsoft\Office test\Special\Perf
malware ; .NET profiler set for every process ; all ; https://attack.mitre.org/techniques/T1574/012/
r:HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment -> COR_PROFILER

# --- Application Found ---
application ; TeamViewer ; any ; https://attack.mitre.org/techniques/T1219/
p:TeamViewer.exe
p:TeamViewer_Service.exe
f:%ProgramFiles%\TeamViewer\TeamViewer.exe
f:%ProgramFiles(x86)%\TeamViewer\TeamViewer.exe
application ; AnyDesk ; any ; https://attack.mitre.org/techniques/T1219/
p:AnyDesk.exe
f:%ProgramFiles(x86)%\AnyDesk\AnyDesk.exe
f:%ProgramData%\AnyDesk\service.conf
application ; ngrok tunnel ; any ; https://attack.mitre.org/techniques/T1572/
p:ngrok.exe
f:%LOCALAPPDATA%\ngrok\ngrok.yml
application ; Cloudflare tunnel ; all ; https://attack.mitre.org/techniques/T1572/
p:cloudflared.exe
application ; Chrome Remote Desktop ; any ; https://attack.mitre.org/techniques/T1219/
p:remoting_host.exe
f:%ProgramFiles(x86)%\Google\Chrome Remote Desktop
application ; Splashtop ; any ; https://attack.mitre.org/techniques/T1219/
p:SRService.exe
r:HKLM\SOFTWARE\WOW6432Node\Splashtop Inc.
application ; ScreenConnect ; any ; https://attack.mitre.org/techniques/T1219/
p:ScreenConnect.ClientService.exe
p:ScreenConnect.WindowsClient.exe
application ; LogMeIn ; any ; https://attack.mitre.org/techniques/T1219/
p:LogMeIn.exe
r:HKLM\SOFTWARE\LogMeIn
application ; RustDesk ; any ; https://attack.mitre.org/techniques/T1219/
p:rustdesk.exe
f:%ProgramFiles%\RustDesk\rustdesk.exe
application ; Atera remote management agent ; any ; https://attack.mitre.org/techniques/T1219/
p:AteraAgent.exe
application ; Radmin ; any ; https://attack.mitre.org/techniques/T1219/
p:rserver3.exe
r:HKLM\SOFTWARE\WOW6432Node\Radmin
application ; Ammyy Admin ; any ; https://attack.mitre.org/techniques/T1219/
p:r:^aa_v3\.exe$
application ; UltraVNC server ; any ; https://attack.mitre.org/techniques/T1021/005/
p:winvnc.exe
r:HKLM\SOFTWARE\UltraVNC
application ; TightVNC server ; any ; https://attack.mitre.org/techniques/T1021/005/
p:tvnserver.exe
r:HKLM\SOFTWARE\TightVNC
application ; RealVNC server ; any ; https://attack.mitre.org/techniques/T1021/005/
p:vncserver.exe
r:HKLM\SOFTWARE\RealVNC
application ; Tor ; any ; https://attack.mitre.org/techniques/T1090/003/
p:tor.exe
application ; BitTorrent ; any ; https://attack.mitre.org/techniques/T1048/
p:bittorrent.exe
f:%APPDATA%\BitTorrent\BitTorrent.exe
application ; uTorrent ; any ; https://attack.mitre.org/techniques/T1048/
p:utorrent.exe
f:%APPDATA%\uTorrent\uTorrent.exe
application ; qBittorrent ; any ; https://attack.mitre.org/techniques/T1048/
p:qbittorrent.exe
f:%ProgramFiles%\qBittorrent\qbittorrent.exe
application ; eMule ; any ; https://attack.mitre.org/techniques/T1048/
p:emule.exe

# --- Windows Audit ---
audit ; Guest account enabled ; all ; https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status
# the account flags are at byte 0x38 of the SAM F value; bit 0x0001 (low nibble of hex digit 114) is 'disabled'
r:HKLM\SAM\SAM\Domains\Account\Users\000001F5 -> F -> ^[0-9a-f]{113}[02468ace]
audit ; LM hash storage enabled ; all ; https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password
r:HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> NoLMHash -> ^0$
audit ; NTLMv1 or LM authentication allowed ; all ; https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
r:HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> ^[0-2]$
audit ; WDigest stores clear-text credentials (UseLogonCredential = 1) ; all ; https://attack.mitre.org/techniques/T1003/001/
r:HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -> UseLogonCredential -> ^1$
audit ; LSA protection not enabled ; all ; https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
!r:HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL -> ^[12]$
audit ; Anonymous enumeration of SAM accounts allowed ; all ; https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts
r:HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> RestrictAnonymousSAM -> ^0$
audit ; SMBv1 server enabled ; all ; https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
r:HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -> SMB1 -> ^1$
audit ; SMBv1 client driver enabled ; all ; https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
r:HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10 -> Start -> ^[0-3]$
audit ; SMB server signing not required ; all ; https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always
r:HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -> RequireSecuritySignature -> ^0$
audit ; SMB client signing not required ; all ; https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-client-digitally-sign-communications-always
r:HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -> RequireSecuritySignature -> ^0$
audit ; Unencrypted passwords sent to SMB servers ; all ; https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-client-send-unencrypted-password-to-third-party-smb-servers
r:HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -> EnablePlainTextPassword -> ^1$
audit ; Shares open to anonymous users ; all ; https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-shares-that-can-be-accessed-anonymously
r:HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -> NullSessionShares -> \S
audit ; Remote Desktop without Network Level Authentication ; all ; https://attack.mitre.org/techniques/T1021/001/
r:HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server -> fDenyTSConnections -> ^0$
r:HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp -> UserAuthentication -> ^0$
audit ; Autorun not disabled for all drives ; all ; https://attack.mitre.org/techniques/T1091/
!r:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoDriveTypeAutoRun -> ^255$
audit ; Defender real-time protection disabled by policy ; all ; https://attack.mitre.org/techniques/T1562/001/
r:HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection -> DisableRealtimeMonitoring -> ^1$
audit ; Defender disabled by policy ; all ; https://attack.mitre.org/techniques/T1562/001/
r:HKLM\SOFTWARE\Policies\Microsoft\Windows Defender -> DisableAntiSpyware -> ^1$
audit ; Defender excludes the whole system drive ; any ; https://attack.mitre.org/techniques/T1562/001/
r:HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths -> C:\
r:HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths -> C:\
audit ; User Account Control disabled ; all ; https://attack.mitre.org/techniques/T1548/002/
r:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> EnableLUA -> ^0$
audit ; Administrators elevated without a prompt ; all ; https://attack.mitre.org/techniques/T1548/002/
r:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> ConsentPromptBehaviorAdmin -> ^0$
audit ; Windows Firewall off (domain profile) ; all ; https://attack.mitre.org/techniques/T1562/004/
r:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> EnableFirewall -> ^0$
audit ; Windows Firewall off (private profile) ; all ; https://attack.mitre.org/techniques/T1562/004/
r:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> EnableFirewall -> ^0$
audit ; Windows Firewall off (public profile) ; all ; https://attack.mitre.org/techniques/T1562/004/
r:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> EnableFirewall -> ^0$
audit ; Remote Registry starts automatically ; all ; https://attack.mitre.org/techniques/T1112/
r:HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry -> Start -> ^2$
audit ; Telnet server installed ; all ; https://attack.mitre.org/techniques/T1021/
r:HKLM\SYSTEM\CurrentControlSet\Services\TlntSvr
audit ; Automatic logon password stored in the registry ; all ; https://attack.mitre.org/techniques/T1552/002/
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> AutoAdminLogon -> ^1$
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> DefaultPassword
audit ; Installers always run elevated ; all ; https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated
r:HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer -> AlwaysInstallElevated -> ^1$
r:HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer -> AlwaysInstallElevated -> ^1$
audit ; PowerShell script block logging not enabled ; all ; https://attack.mitre.org/techniques/T1059/001/
!r:HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -> EnableScriptBlockLogging -> ^1$
";
