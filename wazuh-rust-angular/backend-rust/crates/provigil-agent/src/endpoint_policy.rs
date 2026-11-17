//! Endpoint control policies on the PC (specs/compliance-and-endpoint-policy.md part B): the
//! tenant's site and application rules arrive with the group settings (`endpoint_policies`, built
//! by the manager from its rules) and are applied here; attempts are alerted by the manager from
//! the DNS and process events the agent already sends.
//!
//! Enforce mode:
//! - sites: the agent's own section of the hosts file (each domain and `www.`), so the name
//!   still gets looked up (and the attempt seen) but leads nowhere; the browsers' private DNS
//!   and built-in resolvers turned off by policy so they use the hosts file; `strict` rules also
//!   go in the browsers' own block lists (every sub-domain and path);
//! - applications by name: Windows starts this program instead (`--blocked <rule>`), which shows
//!   the tenant's message and exits; by name or SHA-256 when renamed: stopped within 2 seconds;
//! - safe search: forced in Edge and Chrome (Google, Bing, YouTube restricted).
//!
//! Every registry value the agent sets is recorded with what was there before
//! (`data/policy_state.json`) and put back when the rule goes. Every 10 minutes the rules are
//! applied again; a value or the hosts section changed by someone else is reported as tamper.
//! Reports go to the manager as `provigil_policy: {json}` lines.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const STATE_FILE: &str = "data/policy_state.json";
pub const MESSAGES_FILE: &str = "data/policy_messages.json";
const BEGIN: &str = "# BEGIN ProVigil endpoint policy (managed by the ProVigil agent; do not edit)";
const END: &str = "# END ProVigil endpoint policy";
const IFEO: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const EDGE: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Edge";
const CHROME: &str = r"HKLM\SOFTWARE\Policies\Google\Chrome";
const FIREFOX: &str = r"HKLM\SOFTWARE\Policies\Mozilla\Firefox";
/// First number of the agent's entries in the browsers' block lists (theirs stay below).
const LIST_BASE: usize = 9001;

/// The same list as the manager's (`provigil_agent_server::endpoint_policy::PROTECTED_APPS`),
/// checked again here: a rule never stops these.
const PROTECTED_APPS: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "conhost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "runtimebroker.exe", "spoolsv.exe", "fontdrvhost.exe", "logonui.exe", "userinit.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "sc.exe", "reg.exe", "wevtutil.exe", "auditpol.exe", "secedit.exe", "netsh.exe",
    "provigil-agent.exe", "provigil-blocked.exe", "tamper-protect.exe", "restart-agent.exe", "isolate-host.exe", "sysmon.exe", "sysmon64.exe",
];

/// A registry value the rules want.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Data {
    Sz(String),
    Dword(u32),
}

impl Data {
    /// As the registry reader gives it back.
    fn text(&self) -> String {
        match self {
            Data::Sz(s) => s.clone(),
            Data::Dword(n) => n.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegValue {
    pub key: String,
    pub name: String,
    pub data: Data,
}

/// What the rules ask of this PC.
#[derive(Debug, Default, PartialEq)]
pub struct Desired {
    /// hosts file names (domain and www.domain), sorted
    pub hosts: Vec<String>,
    pub values: Vec<RegValue>,
    /// enforced programs: lower-case file name -> rule id
    pub kill_names: BTreeMap<String, String>,
    /// enforced SHA-256 (lower-case hex) -> rule id
    pub kill_hashes: BTreeMap<String, String>,
    /// rule id -> the message shown when blocked
    pub messages: BTreeMap<String, String>,
    /// of the rules, for the reports
    pub version: String,
}

fn rv(key: &str, name: &str, data: Data) -> RegValue {
    RegValue { key: key.into(), name: name.into(), data }
}

/// The hosts of the manager addresses: never blocked.
pub fn manager_hosts(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|u| {
            let rest = u.split("://").nth(1).unwrap_or(u);
            let host = rest.split(['/', '?']).next()?.rsplit_once(':').map_or(rest.split(['/', '?']).next()?, |(h, _)| h);
            Some(host.trim_matches(['[', ']']).to_ascii_lowercase())
        })
        .filter(|h| !h.is_empty())
        .collect()
}

/// The rules (as the group settings give them) turned into what to set; `blocker` = the command
/// Windows runs instead of a blocked program.
pub fn desired(rules: &[Value], blocker: &str, never: &[String]) -> Desired {
    let mut d = Desired { version: hex(&Sha256::digest(Value::Array(rules.to_vec()).to_string().as_bytes())[..8]), ..Default::default() };
    let (mut hosts, mut strict) = (BTreeSet::new(), BTreeSet::new());
    let (mut any_site, mut safe_search) = (false, false);
    let mut ifeo: BTreeMap<String, String> = BTreeMap::new();
    for r in rules {
        let (id, kind, enforce) = (r["id"].as_str().unwrap_or_default(), r["kind"].as_str().unwrap_or_default(), r["mode"] == "enforce");
        let targets = r["targets"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|t| t.trim().to_ascii_lowercase());
        match kind {
            "site" if enforce => {
                for t in targets {
                    // the manager's own address can never be blocked, whatever the rule says
                    if never.iter().any(|h| *h == t || h.ends_with(&format!(".{t}"))) || !t.contains('.') {
                        continue;
                    }
                    any_site = true;
                    hosts.insert(t.clone());
                    hosts.insert(format!("www.{t}"));
                    if r["strict"] == true {
                        strict.insert(t);
                    }
                }
            }
            "app" if enforce => {
                d.messages.insert(id.to_string(), r["message"].as_str().unwrap_or_default().to_string());
                for t in targets {
                    if let Some(h) = t.strip_prefix("sha256:") {
                        d.kill_hashes.insert(h.to_string(), id.to_string());
                    } else if !PROTECTED_APPS.contains(&t.as_str()) && !t.contains(['\\', '/']) {
                        d.kill_names.insert(t.clone(), id.to_string());
                        ifeo.entry(t).or_insert_with(|| id.to_string());
                    }
                }
            }
            "safe_search" => safe_search = true,
            _ => {}
        }
    }
    d.hosts = hosts.into_iter().collect();
    if any_site {
        for b in [EDGE, CHROME] {
            d.values.push(rv(b, "DnsOverHttpsMode", Data::Sz("off".into())));
            d.values.push(rv(b, "BuiltInDnsClientEnabled", Data::Dword(0)));
        }
        d.values.push(rv(&format!(r"{FIREFOX}\DNSOverHTTPS"), "Enabled", Data::Dword(0)));
        d.values.push(rv(&format!(r"{FIREFOX}\DNSOverHTTPS"), "Locked", Data::Dword(1)));
    }
    for (i, t) in strict.iter().enumerate() {
        let n = (LIST_BASE + i).to_string();
        d.values.push(rv(&format!(r"{EDGE}\URLBlocklist"), &n, Data::Sz(t.clone())));
        d.values.push(rv(&format!(r"{CHROME}\URLBlocklist"), &n, Data::Sz(t.clone())));
        d.values.push(rv(&format!(r"{FIREFOX}\WebsiteFilter\Block"), &n, Data::Sz(format!("*://*.{t}/*"))));
    }
    if safe_search {
        for b in [EDGE, CHROME] {
            d.values.push(rv(b, "ForceGoogleSafeSearch", Data::Dword(1)));
            d.values.push(rv(b, "ForceYouTubeRestrict", Data::Dword(1)));
        }
        d.values.push(rv(EDGE, "ForceBingSafeSearch", Data::Dword(1)));
    }
    for (name, id) in ifeo {
        d.values.push(rv(&format!(r"{IFEO}\{name}"), "Debugger", Data::Sz(format!("{blocker} {id}"))));
    }
    d
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The agent's section of a hosts file (`None`: not there).
pub fn section(text: &str) -> Option<String> {
    let start = text.find(BEGIN)?;
    let end = text[start..].find(END).map(|e| start + e + END.len())?;
    Some(text[start..end].to_string())
}

fn section_for(names: &[String]) -> String {
    let mut s = String::from(BEGIN);
    for n in names {
        s.push_str(&format!("\r\n0.0.0.0 {n}\r\n:: {n}"));
    }
    s.push_str("\r\n");
    s.push_str(END);
    s
}

/// The hosts file with the agent's section set to `names` (removed when empty); the rest is kept.
pub fn hosts_with(text: &str, names: &[String]) -> String {
    let mut rest = text.to_string();
    if let Some(old) = section(text) {
        rest = rest.replacen(&old, "", 1);
        rest = rest.replace("\r\n\r\n\r\n", "\r\n\r\n");
    }
    let rest = rest.trim_end().to_string();
    if names.is_empty() {
        return if rest.is_empty() { String::new() } else { format!("{rest}\r\n") };
    }
    format!("{}{}\r\n", if rest.is_empty() { String::new() } else { format!("{rest}\r\n\r\n") }, section_for(names))
}

/// A value the agent set, and what was there before.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Owned {
    pub key: String,
    pub name: String,
    /// the data the agent set (as read back)
    pub set: String,
    /// what was there before; None: nothing
    pub before: Option<String>,
    /// DWORD (restored as one) or text
    pub dword: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub owned: Vec<Owned>,
    /// the hosts section as last written ("" when none)
    #[serde(default)]
    pub hosts: String,
}

impl State {
    pub fn load(p: &Path) -> State {
        std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }
    fn save(&self, p: &Path) -> Result<(), String> {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::write(p, serde_json::to_vec_pretty(self).unwrap_or_default()).map_err(|e| format!("{}: {e}", p.display()))
    }
}

/// The PC: the registry, the hosts file. A fake one in the tests.
pub trait Pc {
    fn get(&self, key: &str, name: &str) -> Option<String>;
    fn set(&mut self, v: &RegValue) -> Result<(), String>;
    fn restore(&mut self, key: &str, name: &str, before: Option<&str>, dword: bool) -> Result<(), String>;
    fn hosts(&self) -> Result<String, String>;
    fn write_hosts(&mut self, text: &str) -> Result<(), String>;
    /// Policy values changed: tell the programs that read them (browsers reload their policies
    /// only when Windows announces a change).
    fn policies_changed(&mut self) {}
}

/// The outcome of one pass: what someone else changed, and whether every step held.
#[derive(Debug, Default)]
pub struct Outcome {
    pub tampered: Vec<String>,
    pub error: Option<String>,
}

/// Brings the PC to `d`: sets what is missing, puts back what is no longer wanted, notes what was
/// changed by someone else since the last pass. Continues past a failed step and reports the first.
pub fn apply(pc: &mut dyn Pc, d: &Desired, st: &mut State) -> Outcome {
    let mut out = Outcome::default();
    let mut policy_changed = false;
    let fail = |e: String, out: &mut Outcome| {
        if out.error.is_none() {
            out.error = Some(e);
        }
    };
    let wanted: HashMap<(String, String), &RegValue> = d.values.iter().map(|v| ((v.key.to_ascii_lowercase(), v.name.to_ascii_lowercase()), v)).collect();
    // values no longer wanted: back to what was there
    let mut keep = Vec::new();
    for o in std::mem::take(&mut st.owned) {
        if wanted.contains_key(&(o.key.to_ascii_lowercase(), o.name.to_ascii_lowercase())) {
            keep.push(o);
        } else if let Err(e) = pc.restore(&o.key, &o.name, o.before.as_deref(), o.dword) {
            fail(format!("{}\\{}: {e}", o.key, o.name), &mut out);
            keep.push(o);
        } else {
            policy_changed |= o.key.to_ascii_lowercase().contains("\\policies\\");
        }
    }
    st.owned = keep;
    for v in &d.values {
        let want = v.data.text();
        let now = pc.get(&v.key, &v.name);
        let mine = st.owned.iter().position(|o| o.key.eq_ignore_ascii_case(&v.key) && o.name.eq_ignore_ascii_case(&v.name));
        if now.as_deref() == Some(want.as_str()) {
            if mine.is_none() {
                // already so (set by the organisation): nothing to restore later
                st.owned.push(Owned { key: v.key.clone(), name: v.name.clone(), set: want, before: now, dword: matches!(v.data, Data::Dword(_)) });
            }
            continue;
        }
        match mine {
            Some(i) if st.owned[i].set == want => out.tampered.push(format!("{}\\{} changed to {}", v.key, v.name, now.as_deref().unwrap_or("(removed)"))),
            Some(i) => st.owned[i].set = want.clone(),
            None => st.owned.push(Owned { key: v.key.clone(), name: v.name.clone(), set: want.clone(), before: now, dword: matches!(v.data, Data::Dword(_)) }),
        }
        match pc.set(v) {
            Ok(()) => policy_changed |= v.key.to_ascii_lowercase().contains("\\policies\\"),
            Err(e) => fail(format!("{}\\{}: {e}", v.key, v.name), &mut out),
        }
    }
    if policy_changed {
        pc.policies_changed();
    }
    match pc.hosts() {
        Ok(text) => {
            let now = section(&text).unwrap_or_default();
            let want = if d.hosts.is_empty() { String::new() } else { section_for(&d.hosts) };
            if now != want {
                if !st.hosts.is_empty() && now != st.hosts {
                    out.tampered.push(if now.is_empty() { "the hosts file section was removed".into() } else { "the hosts file section was edited".into() });
                }
                match pc.write_hosts(&hosts_with(&text, &d.hosts)) {
                    Ok(()) => st.hosts = want,
                    Err(e) => fail(format!("hosts file: {e}"), &mut out),
                }
            } else {
                st.hosts = want;
            }
        }
        Err(e) => fail(format!("hosts file: {e}"), &mut out),
    }
    out
}

/// The report line the manager reads.
pub fn report(kind: &str, version: &str, detail: &str) -> String {
    let field = if kind == "tamper" { "what" } else { "error" };
    format!("provigil_policy: {}", json!({ "kind": kind, "version": version, field: detail }))
}

/// The process of a running program to stop, with the rule.
pub fn to_stop<'a>(d: &'a Desired, path: &str, sha256: impl FnOnce() -> Option<String>) -> Option<&'a str> {
    let file = path.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
    if PROTECTED_APPS.contains(&file.as_str()) {
        return None;
    }
    if let Some(id) = d.kill_names.get(&file) {
        return Some(id);
    }
    if d.kill_hashes.is_empty() {
        return None;
    }
    sha256().and_then(|h| d.kill_hashes.get(&h.to_ascii_lowercase())).map(String::as_str)
}

/// Run in a blocked program's place: `provigil-agent.exe --blocked <rule> <program> [args]`.
/// Shows the tenant's message and ends; the manager alerts on this start.
pub fn blocked(args: &[String]) -> i32 {
    let rule = args.get(2).cloned().unwrap_or_default();
    let program = args.get(3).map(|p| p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()).unwrap_or_default();
    let dir = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_default();
    let messages: BTreeMap<String, String> = std::fs::read_to_string(dir.join(MESSAGES_FILE)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let mut text = messages.get(&rule).cloned().filter(|m| !m.trim().is_empty()).unwrap_or_else(|| "This application is blocked by your organisation's policy.".into());
    if !program.is_empty() {
        text = format!("{program}\n\n{text}");
    }
    show(&text);
    1
}

#[cfg(windows)]
fn show(text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND};
    let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    unsafe { MessageBoxW(std::ptr::null_mut(), w(text).as_ptr(), w("Blocked by ProVigil").as_ptr(), MB_OK | MB_ICONWARNING | MB_SETFOREGROUND) };
}

#[cfg(not(windows))]
fn show(text: &str) {
    eprintln!("{text}");
}

/// Applies the rules now and every 10 minutes, and stops enforced programs every 2 seconds,
/// until the collection loops stop (new settings start it again with the new rules).
#[cfg(windows)]
pub async fn run(rules: Vec<Value>, never: Vec<String>, buffer: std::sync::Arc<crate::buffer::EventBuffer>, agent_id: String, agent_name: String) {
    use std::time::{Duration, SystemTime};
    let state_path = PathBuf::from(STATE_FILE);
    // nothing asked, nothing ever set: nothing to do
    if rules.is_empty() && !state_path.exists() {
        return;
    }
    let blocker = std::env::current_exe().map(|e| format!("\"{}\" --blocked", e.display())).unwrap_or_default();
    let d = std::sync::Arc::new(desired(&rules, &blocker, &never));
    let send = |line: String| {
        buffer.push(json!({
            "event_type": "ar_log",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "agent": { "id": &agent_id, "name": &agent_name },
            "location": "provigil-policy",
            "log": line,
        }));
    };
    if let Err(e) = std::fs::create_dir_all("data").and_then(|_| std::fs::write(MESSAGES_FILE, serde_json::to_vec_pretty(&d.messages).unwrap_or_default())) {
        tracing::warn!(error = %e, "Endpoint policy messages not saved");
    }
    let stopping = !d.kill_names.is_empty() || !d.kill_hashes.is_empty();
    let mut sys = sysinfo::System::new();
    let mut hashes: HashMap<PathBuf, (u64, Option<SystemTime>, Option<String>)> = HashMap::new();
    let mut tick: u32 = 0;
    while crate::collecting() {
        if tick % 300 == 0 {
            let (dd, sp) = (d.clone(), state_path.clone());
            let out = crate::blocking("endpoint policy", move || {
                let mut st = State::load(&sp);
                let o = apply(&mut Windows::new(), &dd, &mut st);
                let saved = st.save(&sp);
                (o, saved, st.owned.is_empty() && st.hosts.is_empty())
            })
            .await;
            if let Ok((o, saved, empty)) = out {
                for t in &o.tampered {
                    tracing::warn!(what = %t, "Endpoint policy changed on this computer; put back");
                    send(report("tamper", &d.version, t));
                }
                match o.error.or(saved.err()) {
                    Some(e) => {
                        tracing::warn!(error = %e, "Endpoint policy not fully applied");
                        send(report("apply_failed", &d.version, &e));
                    }
                    None => {
                        if tick == 0 {
                            tracing::info!(rules = rules.len(), version = %d.version, "Endpoint policy applied");
                        }
                        send(report("applied", &d.version, ""));
                    }
                }
                // every rule gone and everything put back: done
                if rules.is_empty() && empty {
                    let _ = std::fs::remove_file(&state_path);
                    return;
                }
            }
        }
        if stopping {
            sys.refresh_processes();
            for (pid, p) in sys.processes() {
                let Some(path) = p.exe() else { continue };
                let rule = to_stop(&d, &path.to_string_lossy(), || {
                    let m = std::fs::metadata(path).ok()?;
                    let (len, at) = (m.len(), m.modified().ok());
                    match hashes.get(path) {
                        Some((l, t, h)) if *l == len && *t == at => h.clone(),
                        _ => {
                            let h = std::fs::read(path).ok().map(|b| hex(&Sha256::digest(&b)));
                            hashes.insert(path.to_path_buf(), (len, at, h.clone()));
                            h
                        }
                    }
                });
                if let Some(rule) = rule {
                    let ok = p.kill();
                    tracing::info!(pid = %pid, program = %path.display(), rule, stopped = ok, "Program stopped by endpoint policy");
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        tick = tick.wrapping_add(1);
    }
}

/// Only the Windows agent enforces (the Linux agent is siem-agent-linux).
#[cfg(not(windows))]
pub async fn run(_: Vec<Value>, _: Vec<String>, _: std::sync::Arc<crate::buffer::EventBuffer>, _: String, _: String) {}

/// The real PC (Windows).
#[cfg(windows)]
pub struct Windows {
    pub hosts_path: PathBuf,
}

#[cfg(windows)]
impl Windows {
    pub fn new() -> Windows {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        Windows { hosts_path: PathBuf::from(root).join(r"System32\drivers\etc\hosts") }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// The key under HKLM (the rules only ever use HKLM).
    fn sub(key: &str) -> &str {
        key.split_once('\\').map_or(key, |(_, s)| s)
    }

    fn write(key: &str, name: &str, data: &Data) -> Result<(), String> {
        use windows_sys::Win32::System::Registry::{RegSetKeyValueW, HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ};
        let (k, n) = (Self::wide(Self::sub(key)), Self::wide(name));
        let rc = match data {
            Data::Sz(s) => {
                let w = Self::wide(s);
                unsafe { RegSetKeyValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), n.as_ptr(), REG_SZ, w.as_ptr().cast(), (w.len() * 2) as u32) }
            }
            Data::Dword(x) => unsafe { RegSetKeyValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), n.as_ptr(), REG_DWORD, (x as *const u32).cast(), 4) },
        };
        if rc == 0 { Ok(()) } else { Err(format!("registry error {rc}")) }
    }
}

#[cfg(windows)]
impl Pc for Windows {
    fn get(&self, key: &str, name: &str) -> Option<String> {
        crate::rootcheck::reg::value(key, name)
    }
    fn set(&mut self, v: &RegValue) -> Result<(), String> {
        Self::write(&v.key, &v.name, &v.data)
    }
    fn restore(&mut self, key: &str, name: &str, before: Option<&str>, dword: bool) -> Result<(), String> {
        match before {
            Some(b) if dword => Self::write(key, name, &Data::Dword(b.parse().unwrap_or(0))),
            Some(b) => Self::write(key, name, &Data::Sz(b.to_string())),
            None => {
                use windows_sys::Win32::System::Registry::{RegDeleteKeyValueW, HKEY_LOCAL_MACHINE};
                let rc = unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, Self::wide(Self::sub(key)).as_ptr(), Self::wide(name).as_ptr()) };
                // already gone is fine
                if rc == 0 || rc == 2 { Ok(()) } else { Err(format!("registry error {rc}")) }
            }
        }
    }
    fn hosts(&self) -> Result<String, String> {
        match std::fs::read(&self.hosts_path) {
            Ok(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e.to_string()),
        }
    }
    fn policies_changed(&mut self) {
        // like gpupdate: Chrome and Edge reload their policies on this announcement, at once
        use windows_sys::Win32::System::GroupPolicy::{RefreshPolicyEx, RP_FORCE};
        if unsafe { RefreshPolicyEx(1, RP_FORCE) } == 0 {
            tracing::warn!("Policy refresh not announced; browsers pick the change up at their own next check");
        }
    }
    fn write_hosts(&mut self, text: &str) -> Result<(), String> {
        // a read-only hosts file (some tools set it) is made writable for this write only
        if let Ok(m) = std::fs::metadata(&self.hosts_path) {
            let mut p = m.permissions();
            if p.readonly() {
                #[allow(clippy::permissions_set_readonly_false)]
                p.set_readonly(false);
                let _ = std::fs::set_permissions(&self.hosts_path, p);
            }
        }
        let tmp = self.hosts_path.with_extension("provigil-tmp");
        std::fs::write(&tmp, text.as_bytes()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.hosts_path).map_err(|e| e.to_string())?;
        // names cached before the change would still resolve
        let _ = std::process::Command::new("ipconfig").arg("/flushdns").output();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        reg: HashMap<(String, String), String>,
        hosts: String,
        fail_hosts: bool,
        announced: u32,
    }

    impl Pc for Fake {
        fn get(&self, key: &str, name: &str) -> Option<String> {
            self.reg.get(&(key.into(), name.into())).cloned()
        }
        fn set(&mut self, v: &RegValue) -> Result<(), String> {
            self.reg.insert((v.key.clone(), v.name.clone()), v.data.text());
            Ok(())
        }
        fn restore(&mut self, key: &str, name: &str, before: Option<&str>, _: bool) -> Result<(), String> {
            match before {
                Some(b) => self.reg.insert((key.into(), name.into()), b.into()),
                None => self.reg.remove(&(key.into(), name.into())),
            };
            Ok(())
        }
        fn hosts(&self) -> Result<String, String> {
            Ok(self.hosts.clone())
        }
        fn write_hosts(&mut self, text: &str) -> Result<(), String> {
            if self.fail_hosts {
                return Err("access denied".into());
            }
            self.hosts = text.into();
            Ok(())
        }
        fn policies_changed(&mut self) {
            self.announced += 1;
        }
    }

    fn rules() -> Vec<Value> {
        vec![
            json!({ "id": "s1", "kind": "site", "mode": "enforce", "targets": ["chatgpt.com", "manager.acme.com"], "strict": true }),
            json!({ "id": "s2", "kind": "site", "mode": "monitor", "targets": ["poe.com"] }),
            json!({ "id": "a1", "kind": "app", "mode": "enforce", "targets": ["chatgpt.exe", "explorer.exe", format!("sha256:{}", "c".repeat(64))], "message": "No AI apps" }),
            json!({ "id": "q1", "kind": "safe_search", "mode": "enforce", "targets": [] }),
        ]
    }

    #[test]
    fn rules_become_settings() {
        let never = manager_hosts(&["https://manager.acme.com:8443/".into()]);
        assert_eq!(never, vec!["manager.acme.com"]);
        let d = desired(&rules(), "\"C:\\P\\provigil-agent.exe\" --blocked", &never);
        assert_eq!(d.hosts, vec!["chatgpt.com", "www.chatgpt.com"], "monitor rules and the manager are not blocked");
        assert_eq!(d.kill_names.keys().collect::<Vec<_>>(), vec!["chatgpt.exe"], "system programs never");
        assert_eq!(d.kill_hashes.len(), 1);
        assert_eq!(d.messages["a1"], "No AI apps");
        let has = |k: &str, n: &str, v: Data| d.values.contains(&rv(k, n, v));
        assert!(has(EDGE, "DnsOverHttpsMode", Data::Sz("off".into())));
        assert!(has(&format!(r"{CHROME}\URLBlocklist"), "9001", Data::Sz("chatgpt.com".into())));
        assert!(has(&format!(r"{FIREFOX}\WebsiteFilter\Block"), "9001", Data::Sz("*://*.chatgpt.com/*".into())));
        assert!(has(CHROME, "ForceGoogleSafeSearch", Data::Dword(1)));
        assert!(has(&format!(r"{IFEO}\chatgpt.exe"), "Debugger", Data::Sz("\"C:\\P\\provigil-agent.exe\" --blocked a1".into())));
        assert!(desired(&[], "x", &[]).values.is_empty());
    }

    #[test]
    fn hosts_section_added_replaced_removed() {
        let base = "# Copyright\r\n127.0.0.1 my.local\r\n";
        let a = hosts_with(base, &["a.com".into()]);
        assert!(a.starts_with(base.trim_end()) && a.contains("0.0.0.0 a.com") && a.contains(":: a.com"));
        let b = hosts_with(&a, &["b.com".into()]);
        assert!(!b.contains("a.com") && b.contains("0.0.0.0 b.com") && b.contains("my.local"));
        assert_eq!(b.matches(BEGIN).count(), 1);
        assert_eq!(hosts_with(&b, &[]), base, "the user's own lines are kept as they were");
    }

    #[test]
    fn apply_restores_and_notices_tamper() {
        let mut pc = Fake { hosts: "127.0.0.1 x\r\n".into(), ..Default::default() };
        // the organisation's own value, already there
        pc.reg.insert((EDGE.into(), "DnsOverHttpsMode".into()), "automatic".into());
        let mut st = State::default();
        let d = desired(&rules(), "b --blocked", &[]);
        let o = apply(&mut pc, &d, &mut st);
        assert!(o.error.is_none() && o.tampered.is_empty(), "{o:?}");
        assert_eq!(pc.get(EDGE, "DnsOverHttpsMode").as_deref(), Some("off"));
        assert!(pc.hosts.contains("0.0.0.0 chatgpt.com"));
        assert_eq!(pc.announced, 1, "browsers told once");
        // nothing changed: a second pass reports nothing, and announces nothing
        assert!(apply(&mut pc, &d, &mut st).tampered.is_empty());
        assert_eq!(pc.announced, 1);
        // someone edits the hosts file and a policy value
        pc.hosts = "127.0.0.1 x\r\n".into();
        pc.reg.insert((CHROME.into(), "DnsOverHttpsMode".into()), "secure".into());
        let o = apply(&mut pc, &d, &mut st);
        assert_eq!(o.tampered.len(), 2, "{:?}", o.tampered);
        assert!(pc.hosts.contains("chatgpt.com"), "put back");
        // every rule gone: the organisation's value comes back, the agent's are removed
        let o = apply(&mut pc, &desired(&[], "b", &[]), &mut st);
        assert!(o.error.is_none());
        assert_eq!(pc.get(EDGE, "DnsOverHttpsMode").as_deref(), Some("automatic"));
        assert_eq!(pc.get(CHROME, "DnsOverHttpsMode"), None);
        assert!(pc.reg.keys().all(|(k, _)| !k.contains("Image File Execution")));
        assert_eq!(pc.hosts, "127.0.0.1 x\r\n");
        assert!(st.owned.is_empty());
    }

    #[test]
    fn failed_step_reported_others_applied() {
        let mut pc = Fake { fail_hosts: true, ..Default::default() };
        let mut st = State::default();
        let o = apply(&mut pc, &desired(&rules(), "b", &[]), &mut st);
        assert!(o.error.as_deref().unwrap_or("").contains("hosts"));
        assert_eq!(pc.get(EDGE, "DnsOverHttpsMode").as_deref(), Some("off"));
        assert!(report("apply_failed", "v1", "hosts file: access denied").starts_with("provigil_policy: {"));
    }

    #[test]
    fn stops_by_name_or_hash_never_protected() {
        let d = desired(&rules(), "b", &[]);
        assert_eq!(to_stop(&d, r"C:\Users\x\ChatGPT.exe", || None), Some("a1"));
        assert_eq!(to_stop(&d, r"C:\Temp\renamed.exe", || Some("C".repeat(64))), Some("a1"));
        assert_eq!(to_stop(&d, r"C:\Temp\other.exe", || Some("d".repeat(64))), None);
        assert_eq!(to_stop(&d, r"C:\Windows\explorer.exe", || Some("c".repeat(64))), None);
    }
}
