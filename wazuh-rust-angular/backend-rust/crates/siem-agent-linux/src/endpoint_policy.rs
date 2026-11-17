//! Endpoint control policies on Linux (specs/compliance-and-endpoint-policy.md part B, the same
//! rules as the Windows agent): fetched with the group settings (`GET /api/v1/agents/:id/config`,
//! `config.endpoint_policies`) every 5 minutes, the last answer kept for starts without the manager.
//!
//! Enforce mode:
//! - sites: the agent's section of `/etc/hosts` points each blocked name (and `www.`) at a
//!   private loopback address where the agent listens. A browser that tries gets a "blocked" page
//!   (http) or a closed connection (https); either way the agent reads the site's name (the Host
//!   header, or the name in the TLS hello) and who connected, and reports the attempt. Managed
//!   browser policy files (Chrome, Chromium, Edge) turn their private DNS off so they use the hosts
//!   file; strict rules also go in their block lists; Firefox gets its policy file only when the
//!   computer has none of its own;
//! - programs: by file name or SHA-256, checked every second and stopped, reported with the user;
//! - safe search: forced in Chrome, Chromium and Edge.
//!
//! Monitor mode: programs started are reported (not stopped); site rules have no monitor
//! detection on Linux yet (no DNS log like Sysmon's), so they are listed as such in the report.
//! Every 10 minutes the files are checked; a changed hosts section or policy file is put back and
//! reported as tamper. Reports go as `provigil_policy: {json}` events.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siem_core::{EventSource, RawEvent};
use tracing::{info, warn};

use crate::buffer::AgentBuffer;
use crate::lifecycle::LifecycleCoordinator;

/// Where blocked names lead (all of 127/8 is loopback on Linux; this one is unlikely to be used).
pub const SINK: &str = "127.65.43.21";
const BEGIN: &str = "# BEGIN ProVigil endpoint policy (managed by the ProVigil agent; do not edit)";
const END: &str = "# END ProVigil endpoint policy";
const HOSTS: &str = "/etc/hosts";
/// The managed policy files of the Chromium-family browsers (each reads every file in its folder).
const CHROMIUM_FILES: [&str; 4] = [
    "/etc/opt/chrome/policies/managed/provigil.json",
    "/etc/chromium/policies/managed/provigil.json",
    "/etc/chromium-browser/policies/managed/provigil.json",
    "/etc/opt/edge/policies/managed/provigil.json",
];
const FIREFOX_FILE: &str = "/etc/firefox/policies/policies.json";

/// Programs a rule never stops (the same list as the manager's).
const PROTECTED: &[&str] = &[
    "init", "systemd", "sshd", "sh", "bash", "dash", "zsh", "sudo", "su", "login", "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "zypper",
    "provigil-agent", "siem-agent-linux", "journald", "systemd-journald", "systemd-logind", "dbus-daemon", "xorg", "gnome-shell", "kwin_x11", "kwin_wayland",
];

/// What the rules ask of this computer.
#[derive(Debug, Default, PartialEq)]
pub struct Desired {
    /// names led to the sink (domain and www.domain)
    pub hosts: Vec<String>,
    /// the Chromium-family policy (None: no file)
    pub chromium: Option<Value>,
    /// the Firefox policy (None: no file)
    pub firefox: Option<Value>,
    /// program file name -> (rule id, enforce)
    pub names: BTreeMap<String, (String, bool)>,
    /// SHA-256 -> (rule id, enforce)
    pub hashes: BTreeMap<String, (String, bool)>,
    /// blocked domain -> (rule id, message)
    pub sites: BTreeMap<String, (String, String)>,
    pub version: String,
}

/// The hosts of the manager addresses: never blocked.
pub fn manager_hosts(url: &str) -> Vec<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let hostport = rest.split(['/', '?']).next().unwrap_or("");
    let host = hostport.rsplit_once(':').map_or(hostport, |(h, _)| h).trim_matches(['[', ']']).to_ascii_lowercase();
    if host.is_empty() { Vec::new() } else { vec![host] }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn desired(rules: &[Value], never: &[String]) -> Desired {
    let mut d = Desired { version: hex(&Sha256::digest(Value::Array(rules.to_vec()).to_string().as_bytes())[..8]), ..Default::default() };
    let (mut hosts, mut strict) = (BTreeSet::new(), BTreeSet::new());
    let (mut any_site, mut safe) = (false, false);
    for r in rules {
        let (id, kind, enforce) = (r["id"].as_str().unwrap_or_default().to_string(), r["kind"].as_str().unwrap_or_default(), r["mode"] == "enforce");
        let message = r["message"].as_str().unwrap_or_default().to_string();
        let targets = r["targets"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|t| t.trim().to_ascii_lowercase());
        match kind {
            "site" if enforce => {
                for t in targets {
                    if !t.contains('.') || never.iter().any(|h| *h == t || h.ends_with(&format!(".{t}"))) {
                        continue;
                    }
                    any_site = true;
                    hosts.insert(t.clone());
                    hosts.insert(format!("www.{t}"));
                    d.sites.insert(t.clone(), (id.clone(), message.clone()));
                    if r["strict"] == true {
                        strict.insert(t);
                    }
                }
            }
            "app" => {
                for t in targets {
                    if let Some(h) = t.strip_prefix("sha256:") {
                        d.hashes.insert(h.to_string(), (id.clone(), enforce));
                    } else if !PROTECTED.contains(&t.as_str()) && !t.contains('/') {
                        d.names.insert(t, (id.clone(), enforce));
                    }
                }
            }
            "safe_search" => safe = true,
            _ => {}
        }
    }
    d.hosts = hosts.into_iter().collect();
    let mut p = serde_json::Map::new();
    if any_site {
        p.insert("DnsOverHttpsMode".into(), json!("off"));
        p.insert("BuiltInDnsClientEnabled".into(), json!(false));
    }
    if !strict.is_empty() {
        p.insert("URLBlocklist".into(), json!(strict.iter().collect::<Vec<_>>()));
    }
    if safe {
        p.insert("ForceGoogleSafeSearch".into(), json!(true));
        p.insert("ForceYouTubeRestrict".into(), json!(1));
        p.insert("ForceBingSafeSearch".into(), json!(1));
    }
    if !p.is_empty() {
        d.chromium = Some(Value::Object(p));
    }
    if any_site {
        let mut ff = json!({ "DNSOverHTTPS": { "Enabled": false, "Locked": true } });
        if !strict.is_empty() {
            ff["WebsiteFilter"] = json!({ "Block": strict.iter().map(|t| format!("*://*.{t}/*")).collect::<Vec<_>>() });
        }
        d.firefox = Some(json!({ "policies": ff }));
    }
    d
}

/// The agent's section of a hosts file (None: not there).
pub fn section(text: &str) -> Option<String> {
    let start = text.find(BEGIN)?;
    let end = text[start..].find(END).map(|e| start + e + END.len())?;
    Some(text[start..end].to_string())
}

fn section_for(names: &[String]) -> String {
    let mut s = String::from(BEGIN);
    for n in names {
        // the IPv6 form too, so an IPv6 lookup does not go past the hosts file to DNS
        s.push_str(&format!("\n{SINK} {n}\n::ffff:{SINK} {n}"));
    }
    s.push('\n');
    s.push_str(END);
    s
}

/// The hosts file with the agent's section set to `names` (removed when empty); the rest is kept.
pub fn hosts_with(text: &str, names: &[String]) -> String {
    let mut rest = text.to_string();
    if let Some(old) = section(text) {
        rest = rest.replacen(&old, "", 1);
        while rest.contains("\n\n\n") {
            rest = rest.replace("\n\n\n", "\n\n");
        }
    }
    let rest = rest.trim_end().to_string();
    if names.is_empty() {
        return if rest.is_empty() { String::new() } else { format!("{rest}\n") };
    }
    format!("{}{}\n", if rest.is_empty() { String::new() } else { format!("{rest}\n\n") }, section_for(names))
}

/// What the agent wrote last, to notice changes made by others and to know which files are its own.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub hosts: String,
    /// policy file -> the text written
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

/// The files the policy touches (tests use a folder of their own).
pub struct Files {
    pub root: PathBuf,
}

impl Files {
    fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }
    fn read(&self, p: &str) -> Option<String> {
        std::fs::read_to_string(self.path(p)).ok()
    }
    fn write(&self, p: &str, text: &str) -> Result<(), String> {
        let path = self.path(p);
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        let tmp = path.with_extension("provigil-tmp");
        std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, &path)).map_err(|e| format!("{}: {e}", path.display()))
    }
    fn remove(&self, p: &str) -> Result<(), String> {
        match std::fs::remove_file(self.path(p)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{p}: {e}")),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub tampered: Vec<String>,
    pub error: Option<String>,
    /// a Firefox policy file of the organisation's own was left alone
    pub firefox_skipped: bool,
}

/// Brings the files to `d`, putting back what others changed (noted) and removing what is no
/// longer wanted. Goes on past a failed step and reports the first.
pub fn apply(f: &Files, d: &Desired, st: &mut State) -> Outcome {
    let mut out = Outcome::default();
    let fail = |e: String, out: &mut Outcome| {
        if out.error.is_none() {
            out.error = Some(e);
        }
    };
    // hosts
    let text = f.read(HOSTS).unwrap_or_default();
    let now = section(&text).unwrap_or_default();
    let want = if d.hosts.is_empty() { String::new() } else { section_for(&d.hosts) };
    if now != want {
        if !st.hosts.is_empty() && now != st.hosts {
            out.tampered.push(if now.is_empty() { "the hosts file section was removed".into() } else { "the hosts file section was edited".into() });
        }
        match f.write(HOSTS, &hosts_with(&text, &d.hosts)) {
            Ok(()) => st.hosts = want,
            Err(e) => fail(e, &mut out),
        }
    } else {
        st.hosts = want;
    }
    // policy files: (path, wanted text)
    let mut wanted: Vec<(String, Option<String>)> = CHROMIUM_FILES.iter().map(|p| (p.to_string(), d.chromium.as_ref().map(|v| format!("{v:#}\n")))).collect();
    let ff = d.firefox.as_ref().map(|v| format!("{v:#}\n"));
    let ff_present = f.read(FIREFOX_FILE);
    if ff.is_some() && ff_present.is_some() && !st.files.contains_key(FIREFOX_FILE) {
        // the organisation's own Firefox policy: not overwritten
        out.firefox_skipped = true;
    } else {
        wanted.push((FIREFOX_FILE.to_string(), ff));
    }
    for (p, want) in wanted {
        let now = f.read(&p);
        let mine = st.files.get(&p).cloned();
        match want {
            Some(w) => {
                if now.as_deref() == Some(w.as_str()) {
                    st.files.insert(p, w);
                    continue;
                }
                if mine.as_deref().is_some_and(|m| Some(m) != now.as_deref() && m == w) {
                    out.tampered.push(format!("{p} was {}", if now.is_none() { "removed" } else { "edited" }));
                }
                match f.write(&p, &w) {
                    Ok(()) => {
                        st.files.insert(p, w);
                    }
                    Err(e) => fail(e, &mut out),
                }
            }
            None if mine.is_some() => match f.remove(&p) {
                Ok(()) => {
                    st.files.remove(&p);
                }
                Err(e) => fail(e, &mut out),
            },
            None => {}
        }
    }
    out
}

/// The report line the manager reads (siem-api endpoint_policy.rs).
pub fn report(v: Value) -> String {
    format!("provigil_policy: {v}")
}

// ── the sink: who tried which site ──

/// The site name in a connection's first bytes: the Host header of an http request, or the
/// server name of a TLS hello.
pub fn site_of(first: &[u8]) -> Option<String> {
    if first.first() == Some(&0x16) {
        return sni(first);
    }
    let text = String::from_utf8_lossy(first);
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("host").then(|| v.trim().split(':').next().unwrap_or("").to_ascii_lowercase())
    })
}

/// The server name (SNI) of a TLS ClientHello.
fn sni(b: &[u8]) -> Option<String> {
    let u16at = |i: usize| -> Option<usize> { Some(((*b.get(i)? as usize) << 8) | *b.get(i + 1)? as usize) };
    // record header 5, handshake header 4, version 2, random 32
    let mut i = 5 + 4 + 2 + 32;
    i += 1 + *b.get(i)? as usize; // session id
    i += 2 + u16at(i)?; // cipher suites
    i += 1 + *b.get(i)? as usize; // compression
    let end = i + 2 + u16at(i)?;
    i += 2;
    while i + 4 <= end.min(b.len()) {
        let (ty, len) = (u16at(i)?, u16at(i + 2)?);
        if ty == 0 {
            // server name list: list length 2, type 1, name length 2, name
            let n = u16at(i + 7)?;
            return b.get(i + 9..i + 9 + n).map(|s| String::from_utf8_lossy(s).to_ascii_lowercase());
        }
        i += 4 + len;
    }
    None
}

/// The rule a looked-up name falls under.
pub fn site_rule<'a>(d: &'a Desired, name: &str) -> Option<(&'a str, &'a (String, String))> {
    let n = name.trim_end_matches('.');
    let n = n.strip_prefix("www.").unwrap_or(n);
    d.sites.get_key_value(n).map(|(k, v)| (k.as_str(), v))
}

/// The local user owning a connection from `port` to the sink (from /proc/net/tcp), by name.
fn user_of(port: u16) -> String {
    let uid = ["/proc/net/tcp", "/proc/net/tcp6"].iter().find_map(|p| {
        std::fs::read_to_string(p).ok()?.lines().skip(1).find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let local_port = u16::from_str_radix(f.get(1)?.rsplit(':').next()?, 16).ok()?;
            (local_port == port).then(|| f.get(7).map(|u| u.to_string())).flatten()
        })
    });
    let Some(uid) = uid else { return String::new() };
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|t| t.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.get(2) == Some(&uid.as_str())).then(|| f[0].to_string())
        }))
        .unwrap_or(uid)
}

fn page(message: &str) -> String {
    let m: String = message.chars().filter(|c| !matches!(c, '<' | '>' | '&' | '"')).collect();
    let body = format!("<!doctype html><meta charset=utf-8><title>Blocked</title><body style=\"font-family:sans-serif;max-width:40em;margin:4em auto\"><h1>Blocked by ProVigil</h1><p>{}</p></body>", if m.is_empty() { "This site is blocked by your organisation's policy.".to_string() } else { m });
    format!("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

// ── the worker ──

pub fn should_block_pre_exec(desired: &Desired, filename: &str, file_hash: Option<&str>) -> Option<(String, bool)> {
    let lower_name = filename.to_ascii_lowercase();
    if PROTECTED.contains(&lower_name.as_str()) {
        return None;
    }
    if let Some(rule) = desired.names.get(&lower_name) {
        return Some(rule.clone());
    }
    if let Some(h) = file_hash {
        let lower_hash = h.to_ascii_lowercase();
        if let Some(rule) = desired.hashes.get(&lower_hash) {
            return Some(rule.clone());
        }
    }
    None
}

#[cfg(target_os = "linux")]
mod fanotify_blocker {
    use std::fs::File;
    use std::io::Read;
    use std::sync::Arc;
    use tracing::{info, warn};
    use sha2::{Digest, Sha256};
    use super::{Desired, hex, should_block_pre_exec, event, report};
    use crate::buffer::AgentBuffer;

    const FAN_CLOEXEC: u32 = 0x00000001;
    const FAN_NONBLOCK: u32 = 0x00000002;
    const FAN_CLASS_CONTENT: u32 = 0x00000004;

    const FAN_MARK_ADD: u32 = 0x00000001;
    const FAN_MARK_MOUNT: u32 = 0x00000010;

    const FAN_OPEN_EXEC_PERM: u64 = 0x00040000;

    const FAN_ALLOW: u32 = 0x01;
    const FAN_DENY: u32 = 0x02;

    #[repr(C)]
    struct fanotify_event_metadata {
        event_len: u32,
        vers: u8,
        reserved: u8,
        metadata_len: u16,
        mask: u64,
        fd: i32,
        pid: i32,
    }

    #[repr(C)]
    struct fanotify_response {
        fd: i32,
        response: u32,
    }

    pub fn start_fanotify_interceptor(
        desired: Arc<std::sync::RwLock<Desired>>,
        agent_id: String,
        buffer: Arc<AgentBuffer>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        unsafe {
            let fd = libc::fanotify_init(
                FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
                libc::O_RDONLY as u32 | libc::O_LARGEFILE as u32,
            );
            if fd < 0 {
                info!("provigil-policy: fanotify_init unavailable (requires Linux kernel 5.0+ and CAP_SYS_ADMIN). Using /proc poller.");
                return None;
            }

            let path_c = std::ffi::CString::new("/").ok()?;
            let mark_res = libc::fanotify_mark(
                fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                FAN_OPEN_EXEC_PERM,
                libc::AT_FDCWD,
                path_c.as_ptr(),
            );

            if mark_res < 0 {
                warn!("provigil-policy: fanotify_mark root mount failed, closing fanotify fd.");
                libc::close(fd);
                return None;
            }

            info!("provigil-policy: Kernel pre-execution interceptor active via fanotify (FAN_OPEN_EXEC_PERM).");

            Some(tokio::task::spawn_blocking(move || {
                let mut buf = [0u8; 4096];
                loop {
                    let mut pollfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = libc::poll(&mut pollfd, 1, 1000);
                    if ret <= 0 {
                        continue;
                    }

                    let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
                    if n <= 0 {
                        continue;
                    }

                    let mut offset = 0;
                    while offset + std::mem::size_of::<fanotify_event_metadata>() <= n as usize {
                        let meta = &*(buf.as_ptr().add(offset) as *const fanotify_event_metadata);
                        if meta.event_len == 0 {
                            break;
                        }

                        let event_fd = meta.fd;
                        let event_pid = meta.pid;
                        let mut allow = true;
                        let mut blocked_file = String::new();
                        let mut blocked_rule = String::new();

                        if event_fd >= 0 {
                            let proc_path = format!("/proc/self/fd/{}", event_fd);
                            if let Ok(target) = std::fs::read_link(&proc_path) {
                                let filename = target
                                    .file_name()
                                    .map(|f| f.to_string_lossy().to_string())
                                    .unwrap_or_default();

                                let mut file_hash = None;
                                if let Ok(mut f) = File::open(&target) {
                                    let mut hasher = Sha256::new();
                                    let mut fbuf = [0u8; 8192];
                                    while let Ok(bytes_read) = f.read(&mut fbuf) {
                                        if bytes_read == 0 { break; }
                                        hasher.update(&fbuf[..bytes_read]);
                                    }
                                    file_hash = Some(hex(&hasher.finalize()));
                                }

                                let d = desired.read().unwrap();
                                if let Some((rule, enforce)) = should_block_pre_exec(&d, &filename, file_hash.as_deref()) {
                                    if enforce {
                                        allow = false;
                                        blocked_file = target.to_string_lossy().to_string();
                                        blocked_rule = rule;
                                    }
                                }
                            }

                            let resp = fanotify_response {
                                fd: event_fd,
                                response: if allow { FAN_ALLOW } else { FAN_DENY },
                            };
                            libc::write(
                                fd,
                                &resp as *const _ as *const libc::c_void,
                                std::mem::size_of::<fanotify_response>(),
                            );
                            libc::close(event_fd);

                            if !allow {
                                info!(
                                    "provigil-policy: PRE-EXEC BLOCKED by fanotify (PID {}): {} [rule: {}]",
                                    event_pid, blocked_file, blocked_rule
                                );
                                let agent_id_clone = agent_id.clone();
                                let buffer_clone = buffer.clone();
                                let rule_id = blocked_rule.clone();
                                let file_name = blocked_file.clone();
                                tokio::spawn(async move {
                                    let report_obj = serde_json::json!({
                                        "kind": "app_blocked_pre_exec",
                                        "rule_id": rule_id,
                                        "mode": "enforce",
                                        "target": file_name,
                                        "process": file_name,
                                        "pid": event_pid,
                                        "interceptor": "fanotify",
                                        "stopped": true
                                    });
                                    buffer_clone.push(event(&agent_id_clone, report(report_obj))).await;
                                });
                            }
                        }

                        offset += meta.event_len as usize;
                    }
                }
            }))
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod fanotify_blocker {
    use std::sync::Arc;
    use super::Desired;
    use crate::buffer::AgentBuffer;

    pub fn start_fanotify_interceptor(
        _desired: Arc<std::sync::RwLock<Desired>>,
        _agent_id: String,
        _buffer: Arc<AgentBuffer>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        None
    }
}

fn event(agent_id: &str, line: String) -> RawEvent {
    let mut e = RawEvent::new(agent_id, EventSource::ActiveResponse, "provigil-policy", line);
    e.metadata.insert("os_type".into(), "linux".into());
    e
}

/// The folder for the agent's own files (next to client.keys).
fn data_dir() -> PathBuf {
    ["/opt/provigil-agent/etc", "/etc/provigil-agent"].iter().map(PathBuf::from).find(|p| p.is_dir()).unwrap_or_else(|| PathBuf::from("."))
}

async fn fetch(manager_url: &str, agent_id: &str, key: &str) -> Result<Vec<Value>, String> {
    let client = crate::enroll::http_builder().timeout(Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let url = format!("{}/api/v1/agents/{}/config", manager_url.trim_end_matches('/'), agent_id);
    let res = client.get(&url).header("x-agent-id", agent_id).header("x-agent-key", key).header("authorization", format!("Bearer {key}")).send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("HTTP {}", res.status()));
    }
    let v: Value = res.json().await.map_err(|e| e.to_string())?;
    Ok(v["config"]["endpoint_policies"].as_array().cloned().unwrap_or_default())
}

/// Runs until the agent stops: settings every 5 minutes, files every 10, programs every second.
pub fn spawn_worker(agent_id: String, agent_key: String, manager_url: String, buffer: Arc<AgentBuffer>, lifecycle: Arc<LifecycleCoordinator>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let saved = data_dir().join("endpoint_policies.json");
        let state_path = data_dir().join("policy_state.json");
        let key = std::env::var("SIEM_AGENT_KEY").ok().filter(|k| !k.trim().is_empty()).unwrap_or(agent_key);
        let never = manager_hosts(&manager_url);
        // the last rules received, so a start without the manager still enforces them
        let mut rules: Vec<Value> = std::fs::read_to_string(&saved).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        let d = Arc::new(std::sync::RwLock::new(desired(&rules, &never)));
        let _fanotify_worker = fanotify_blocker::start_fanotify_interceptor(
            d.clone(),
            agent_id.clone(),
            buffer.clone(),
        );
        let sink_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut seen: HashMap<u32, ()> = HashMap::new();
        let mut hashes: HashMap<PathBuf, (u64, Option<std::time::SystemTime>, Option<String>)> = HashMap::new();
        let mut reported: HashMap<String, std::time::Instant> = HashMap::new();
        let mut tick: u64 = 0;
        let files = Files { root: PathBuf::from("/") };
        loop {
            if lifecycle.is_terminated() {
                return;
            }
            let mut changed = tick == 0;
            if tick % 300 == 0 {
                match fetch(&manager_url, &agent_id, &key).await {
                    Ok(r) if r != rules => {
                        info!("provigil-policy: {} endpoint policy rule(s) received", r.len());
                        let _ = std::fs::write(&saved, Value::Array(r.clone()).to_string());
                        rules = r;
                        *d.write().unwrap() = desired(&rules, &never);
                        changed = true;
                    }
                    Ok(_) => {}
                    Err(e) => warn!("provigil-policy: settings not fetched: {e}"),
                }
            }
            if changed || tick % 600 == 0 {
                let mut st: State = std::fs::read_to_string(&state_path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
                let o = { apply(&files, &d.read().unwrap(), &mut st) };
                let _ = std::fs::write(&state_path, serde_json::to_vec_pretty(&st).unwrap_or_default());
                let version = d.read().unwrap().version.clone();
                for t in &o.tampered {
                    warn!("provigil-policy: changed on this computer, put back: {t}");
                    buffer.push(event(&agent_id, report(json!({ "kind": "tamper", "version": version, "what": t })))).await;
                }
                let line = match &o.error {
                    Some(e) => json!({ "kind": "apply_failed", "version": version, "error": e }),
                    None if o.firefox_skipped => json!({ "kind": "applied", "version": version, "error": "Firefox has a policy file of the organisation's own: its settings were left alone" }),
                    None => json!({ "kind": "applied", "version": version }),
                };
                buffer.push(event(&agent_id, report(line))).await;
                if !d.read().unwrap().sites.is_empty() && !sink_started.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    for port in [80u16, 443] {
                        tokio::spawn(sink(port, d.clone(), agent_id.clone(), buffer.clone()));
                    }
                }
            }
            // programs: new processes only (a process already checked keeps its pid)
            let (names, wanted_hashes) = {
                let g = d.read().unwrap();
                (g.names.clone(), g.hashes.clone())
            };
            if !names.is_empty() || !wanted_hashes.is_empty() {
                let mut alive = HashMap::new();
                for pid in std::fs::read_dir("/proc").into_iter().flatten().flatten().filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()) {
                    alive.insert(pid, ());
                    if seen.contains_key(&pid) {
                        continue;
                    }
                    let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else { continue };
                    let file = exe.file_name().map(|f| f.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                    if PROTECTED.contains(&file.as_str()) {
                        continue;
                    }
                    let hit = names.get(&file).cloned().or_else(|| {
                        if wanted_hashes.is_empty() {
                            return None;
                        }
                        let m = std::fs::metadata(&exe).ok()?;
                        let (len, at) = (m.len(), m.modified().ok());
                        let h = match hashes.get(&exe) {
                            Some((l, t, h)) if *l == len && *t == at => h.clone(),
                            _ => {
                                let h = std::fs::read(&exe).ok().map(|b| hex(&Sha256::digest(&b)));
                                hashes.insert(exe.clone(), (len, at, h.clone()));
                                h
                            }
                        };
                        wanted_hashes.get(&h?).cloned()
                    });
                    if let Some((rule, enforce)) = hit {
                        let uid = std::fs::read_to_string(format!("/proc/{pid}/status")).ok().and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:").map(|u| u.split_whitespace().next().unwrap_or("").to_string()))).unwrap_or_default();
                        let stopped = enforce && std::process::Command::new("kill").args(["-9", &pid.to_string()]).status().is_ok_and(|s| s.success());
                        info!("provigil-policy: {} (pid {pid}) {} by rule {rule}", exe.display(), if stopped { "stopped" } else { "seen" });
                        let key = format!("{rule}:{file}:{uid}");
                        if reported.get(&key).is_none_or(|t| t.elapsed() > Duration::from_secs(600)) {
                            reported.insert(key, std::time::Instant::now());
                            buffer.push(event(&agent_id, report(json!({ "kind": "app_attempt", "rule_id": rule, "mode": if enforce { "enforce" } else { "monitor" }, "target": file, "process": exe.display().to_string(), "user": uid_name(&uid), "stopped": stopped })))).await;
                        }
                    }
                    seen.insert(pid, ());
                }
                seen.retain(|p, _| alive.contains_key(p));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            tick += 1;
        }
    })
}

fn uid_name(uid: &str) -> String {
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|t| t.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.get(2) == Some(&uid)).then(|| f[0].to_string())
        }))
        .unwrap_or_else(|| uid.to_string())
}

/// Listens where blocked names lead: reads the site and the person, answers "blocked", reports.
async fn sink(port: u16, d: Arc<std::sync::RwLock<Desired>>, agent_id: String, buffer: Arc<AgentBuffer>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = match tokio::net::TcpListener::bind((SINK, port)).await {
        Ok(l) => l,
        Err(e) => {
            warn!("provigil-policy: cannot listen on {SINK}:{port} ({e}); blocked sites are blocked but attempts there are not reported");
            return;
        }
    };
    let reported: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>> = Default::default();
    loop {
        let Ok((mut s, peer)) = l.accept().await else { continue };
        let (d, agent_id, buffer, reported) = (d.clone(), agent_id.clone(), buffer.clone(), reported.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.ok().and_then(Result::ok).unwrap_or(0);
            let user = user_of(peer.port());
            let site = site_of(&buf[..n]).unwrap_or_default();
            let found = site_rule(&d.read().unwrap(), &site).map(|(t, (id, m))| (t.to_string(), id.clone(), m.clone()));
            if port == 80 {
                let _ = s.write_all(page(found.as_ref().map(|f| f.2.as_str()).unwrap_or("")).as_bytes()).await;
            }
            let Some((target, rule, _)) = found else { return };
            let key = format!("{rule}:{target}:{user}");
            {
                let mut r = reported.lock().unwrap();
                if r.get(&key).is_some_and(|t| t.elapsed() < Duration::from_secs(600)) {
                    return;
                }
                r.insert(key, std::time::Instant::now());
            }
            buffer.push(event(&agent_id, report(json!({ "kind": "site_attempt", "rule_id": rule, "mode": "enforce", "target": target, "name": site, "user": user })))).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<Value> {
        vec![
            json!({ "id": "s1", "kind": "site", "mode": "enforce", "targets": ["chatgpt.com", "manager.acme.com"], "strict": true, "message": "No AI" }),
            json!({ "id": "s2", "kind": "site", "mode": "monitor", "targets": ["poe.com"] }),
            json!({ "id": "a1", "kind": "app", "mode": "enforce", "targets": ["chatgpt", "bash", format!("sha256:{}", "c".repeat(64))] }),
            json!({ "id": "a2", "kind": "app", "mode": "monitor", "targets": ["discord"] }),
            json!({ "id": "q1", "kind": "safe_search", "mode": "enforce", "targets": [] }),
        ]
    }

    #[test]
    fn rules_become_settings() {
        let d = desired(&rules(), &manager_hosts("https://manager.acme.com:8443"));
        assert_eq!(d.hosts, vec!["chatgpt.com", "www.chatgpt.com"]);
        assert_eq!(d.names.get("chatgpt"), Some(&("a1".to_string(), true)));
        assert_eq!(d.names.get("discord"), Some(&("a2".to_string(), false)), "monitor: reported, not stopped");
        assert!(!d.names.contains_key("bash"), "a shell is never stopped");
        let c = d.chromium.as_ref().unwrap();
        assert_eq!(c["DnsOverHttpsMode"], "off");
        assert_eq!(c["URLBlocklist"], json!(["chatgpt.com"]));
        assert_eq!(c["ForceGoogleSafeSearch"], true);
        assert_eq!(d.firefox.as_ref().unwrap()["policies"]["WebsiteFilter"]["Block"][0], "*://*.chatgpt.com/*");
        assert_eq!(site_rule(&d, "www.chatgpt.com").map(|x| x.0), Some("chatgpt.com"));
        let none = desired(&[], &[]);
        assert!(none.chromium.is_none() && none.firefox.is_none() && none.hosts.is_empty());
    }

    #[test]
    fn hosts_section_kept_apart() {
        let base = "127.0.0.1 localhost\n::1 localhost\n";
        let a = hosts_with(base, &["a.com".into()]);
        assert!(a.starts_with(base.trim_end()) && a.contains(&format!("{SINK} a.com")) && a.contains(&format!("::ffff:{SINK} a.com")));
        let b = hosts_with(&a, &["b.com".into()]);
        assert!(!b.contains("a.com") && b.contains("b.com") && b.matches(BEGIN).count() == 1);
        assert_eq!(hosts_with(&b, &[]), base);
    }

    #[test]
    fn files_applied_tamper_noticed_and_removed() {
        let dir = std::env::temp_dir().join(format!("pv-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let f = Files { root: dir.clone() };
        f.write(HOSTS, "127.0.0.1 localhost\n").unwrap();
        let mut st = State::default();
        let d = desired(&rules(), &[]);
        let o = apply(&f, &d, &mut st);
        assert!(o.error.is_none() && o.tampered.is_empty() && !o.firefox_skipped, "{o:?}");
        assert!(f.read(HOSTS).unwrap().contains("chatgpt.com"));
        assert!(f.read(CHROMIUM_FILES[0]).unwrap().contains("DnsOverHttpsMode"));
        assert!(apply(&f, &d, &mut st).tampered.is_empty(), "unchanged");
        // someone edits the hosts file and deletes a policy file
        f.write(HOSTS, "127.0.0.1 localhost\n").unwrap();
        f.remove(CHROMIUM_FILES[3]).unwrap();
        let o = apply(&f, &d, &mut st);
        assert_eq!(o.tampered.len(), 2, "{:?}", o.tampered);
        assert!(f.read(CHROMIUM_FILES[3]).is_some(), "put back");
        // all rules gone: everything the agent wrote is removed, the rest stays
        let o = apply(&f, &desired(&[], &[]), &mut st);
        assert!(o.error.is_none());
        assert_eq!(f.read(HOSTS).unwrap(), "127.0.0.1 localhost\n");
        assert!(CHROMIUM_FILES.iter().all(|p| f.read(p).is_none()) && f.read(FIREFOX_FILE).is_none());
        // the organisation's own Firefox policy is never overwritten
        f.write(FIREFOX_FILE, "{\"policies\":{}}").unwrap();
        let o = apply(&f, &d, &mut State::default());
        assert!(o.firefox_skipped);
        assert_eq!(f.read(FIREFOX_FILE).unwrap(), "{\"policies\":{}}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn site_names_from_http_and_tls() {
        assert_eq!(site_of(b"GET / HTTP/1.1\r\nHost: ChatGPT.com:80\r\n\r\n").as_deref(), Some("chatgpt.com"));
        // a minimal ClientHello with server name "chatgpt.com"
        let name = b"chatgpt.com";
        let mut sni_ext = vec![0, 0];
        let list_len = (name.len() + 3) as u16;
        sni_ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut hello = vec![0x16, 3, 1, 0, 0, 1, 0, 0, 0, 3, 3];
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        hello.extend_from_slice(&[1, 0]); // compression
        hello.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&sni_ext);
        assert_eq!(site_of(&hello).as_deref(), Some("chatgpt.com"));
        assert_eq!(site_of(b"\x16\x03"), None, "cut short");
        assert!(page("No <b>AI</b>").contains("No bAI/b"));
    }

    #[test]
    fn test_pre_execution_blocking_rules() {
        let rules = json!([
            {
                "id": "rule-block-nc",
                "kind": "app",
                "mode": "enforce",
                "targets": ["nc", "netcat", "ncat"]
            },
            {
                "id": "rule-block-hash",
                "kind": "app",
                "mode": "enforce",
                "targets": ["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
            },
            {
                "id": "rule-protected-override",
                "kind": "app",
                "mode": "enforce",
                "targets": ["bash", "systemd"]
            }
        ]);

        let d = desired(rules.as_array().unwrap(), &[]);

        // 1. Blocked program should be matched for pre-execution denial
        let hit = should_block_pre_exec(&d, "nc", None);
        assert_eq!(hit, Some(("rule-block-nc".to_string(), true)));

        // 2. Protected OS binaries must NEVER be blocked even if listed in rule
        let protected_hit = should_block_pre_exec(&d, "bash", None);
        assert_eq!(protected_hit, None);
        let systemd_hit = should_block_pre_exec(&d, "systemd", None);
        assert_eq!(systemd_hit, None);

        // 3. Blocked SHA-256 hash
        let hash_hit = should_block_pre_exec(&d, "some_unknown_binary", Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert_eq!(hash_hit, Some(("rule-block-hash".to_string(), true)));

        // 4. Benign binary
        let benign = should_block_pre_exec(&d, "my_custom_service", Some("1111111111111111111111111111111111111111111111111111111111111111"));
        assert_eq!(benign, None);
    }
}
