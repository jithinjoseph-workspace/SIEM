//! The Wazuh manager behind the SIEM: siem-api prepares a manager home
//! (`data/manager`, laid out like `/var/ossec`), runs the ported daemons
//! (`wazuh-db`, `wazuh-analysisd`, `wazuh-remoted`) as child processes and
//! links them to the platform:
//!
//! * enrollment writes `etc/client.keys` (remoted reloads it on change);
//! * `logs/alerts/alerts.json` becomes platform alerts and
//!   `logs/archives/archives.json` platform events, per agent tenant;
//! * agent status, OS and version come from wazuh-db's global database.
//!
//! Agents (`wazuh-agent.exe`, `wazuh-agentd`) connect to remoted on 1514/tcp.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use chrono::Utc;
use siem_core::{Agent, AgentAlertInfo, AgentStatus, Alert, DecodedFields, DecoderAlertInfo, EventSource, ManagerAlertInfo, MitreAttack, RawEvent, RuleAlertInfo};
use siem_ipc::wdbc::WdbQuery;
use tracing::{info, warn};

use crate::{tenancy, AppState};

/// The daemons, in start order.
#[cfg(not(unix))]
const DAEMONS: [&str; 8] = ["wazuh-db", "wazuh-analysisd", "wazuh-remoted", "wazuh-modulesd", "wazuh-monitord", "wazuh-maild", "wazuh-integratord", "wazuh-csyslogd"];
/// On Linux the manager also runs execd for responses with `<location>` local/server,
/// and agentlessd (its expect scripts need a Unix shell).
#[cfg(unix)]
const DAEMONS: [&str; 10] = ["wazuh-db", "wazuh-analysisd", "wazuh-remoted", "wazuh-modulesd", "wazuh-monitord", "wazuh-maild", "wazuh-integratord", "wazuh-csyslogd", "wazuh-execd", "wazuh-agentlessd"];
/// The manager's own response programs (Linux).
#[cfg(unix)]
const MANAGER_AR: [&str; 1] = ["firewall-drop"];
#[cfg(not(unix))]
const MANAGER_AR: [&str; 0] = [];
/// The integration scripts, all served by the `integrations` program.
const INTEGRATIONS: [&str; 5] = ["slack", "pagerduty", "virustotal", "shuffle", "maltiverse"];

/// Where the manager lives (`WAZUH_MANAGER_HOME`, else `data/manager`).
pub fn home() -> PathBuf {
    let p = match std::env::var("WAZUH_MANAGER_HOME") {
        Ok(h) if !h.trim().is_empty() => PathBuf::from(h),
        _ => crate::data_file_path("manager"),
    };
    std::path::absolute(&p).unwrap_or(p)
}

/// Whether siem-api runs the manager (`WAZUH_MANAGER=0` turns it off).
pub fn enabled() -> bool {
    !matches!(std::env::var("WAZUH_MANAGER").as_deref(), Ok("0") | Ok("false") | Ok("no"))
}

fn keys_file(home: &Path) -> PathBuf {
    home.join("etc").join("client.keys")
}

/// The Wazuh 4.14.7 source tree the ruleset is copied from.
fn wazuh_source() -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(s) = std::env::var("WAZUH_SOURCE_DIR") {
        cands.push(PathBuf::from(s));
    }
    for rel in ["../../wazuh/wazuh-4.14.7", "../wazuh/wazuh-4.14.7", "wazuh/wazuh-4.14.7", "../../../wazuh/wazuh-4.14.7"] {
        cands.push(PathBuf::from(rel));
    }
    cands.into_iter().find(|p| p.join("ruleset").join("rules").is_dir() && p.join("etc").join("internal_options.conf").is_file())
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), &to)?;
        }
    }
    Ok(())
}

/// The manager `ossec.conf`: secure remote on 1514/tcp, JSON alerts and
/// archives, the default ruleset.
fn ossec_conf() -> String {
    // The interval backup names its files with ':' (not valid on Windows).
    let wdb = if cfg!(windows) {
        "  <wdb>\n    <backup database=\"global\">\n      <enabled>no</enabled>\n      <interval>1d</interval>\n      <max_files>3</max_files>\n    </backup>\n  </wdb>\n"
    } else {
        ""
    };
    format!(
        "<ossec_config>\n\
  <global>\n\
    <jsonout_output>yes</jsonout_output>\n\
    <alerts_log>yes</alerts_log>\n\
    <logall>no</logall>\n\
    <logall_json>yes</logall_json>\n\
    <email_notification>no</email_notification>\n\
    <agents_disconnection_time>10m</agents_disconnection_time>\n\
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>\n\
  </global>\n\
  <alerts>\n\
    <log_alert_level>3</log_alert_level>\n\
  </alerts>\n\
  <logging>\n\
    <log_format>plain</log_format>\n\
  </logging>\n\
  <remote>\n\
    <connection>secure</connection>\n\
    <port>1514</port>\n\
    <protocol>tcp</protocol>\n\
    <queue_size>131072</queue_size>\n\
  </remote>\n\
{wdb}\
  <ruleset>\n\
    <decoder_dir>ruleset/decoders</decoder_dir>\n\
    <rule_dir>ruleset/rules</rule_dir>\n\
    <rule_exclude>0215-policy_rules.xml</rule_exclude>\n\
    <list>etc/lists/audit-keys</list>\n\
    <list>etc/lists/amazon/aws-eventnames</list>\n\
    <list>etc/lists/security-eventchannel</list>\n\
    <list>etc/lists/malicious-ioc/malware-hashes</list>\n\
    <list>etc/lists/malicious-ioc/malicious-ip</list>\n\
    <list>etc/lists/malicious-ioc/malicious-domains</list>\n\
    <decoder_dir>etc/decoders</decoder_dir>\n\
    <rule_dir>etc/rules</rule_dir>\n\
  </ruleset>\n\
  <vulnerability-detection>\n\
    <enabled>yes</enabled>\n\
    <index-status>yes</index-status>\n\
    <feed-update-interval>60m</feed-update-interval>\n\
  </vulnerability-detection>\n\
</ossec_config>\n"
    )
}

/// Creates the manager home (once) and refreshes the default ruleset.
fn prepare_home(home: &Path) -> Result<(), String> {
    for d in [
        "bin", "etc/decoders", "etc/rules", "etc/lists", "etc/shared/default", "ruleset", "logs/alerts", "logs/archives", "logs/wazuh",
        "logs/firewall", "queue/sockets", "queue/db", "queue/alerts", "queue/rids", "queue/diff", "queue/agentless", "queue/fts", "queue/tasks",
        "var/run", "var/db", "var/multigroups", "var/download", "stats", "backup/db", "tmp",
    ] {
        std::fs::create_dir_all(home.join(d)).map_err(|e| format!("{d}: {e}"))?;
    }
    let src = wazuh_source().ok_or("Wazuh 4.14.7 source tree not found (set WAZUH_SOURCE_DIR)")?;
    // The default ruleset is replaced on every start, like a package upgrade.
    for d in ["decoders", "rules"] {
        let to = home.join("ruleset").join(d);
        let _ = std::fs::remove_dir_all(&to);
        copy_dir(&src.join("ruleset").join(d), &to).map_err(|e| format!("ruleset/{d}: {e}"))?;
    }
    // User files are created once and then kept.
    let once = |rel_src: PathBuf, rel_dst: &str| -> Result<(), String> {
        let to = home.join(rel_dst);
        if !to.exists() {
            if rel_src.is_dir() {
                copy_dir(&rel_src, &to).map_err(|e| format!("{rel_dst}: {e}"))?;
            } else {
                std::fs::copy(&rel_src, &to).map_err(|e| format!("{rel_dst}: {e}"))?;
            }
        }
        Ok(())
    };
    for l in ["audit-keys", "amazon", "security-eventchannel", "malicious-ioc"] {
        once(src.join("ruleset").join("lists").join(l), &format!("etc/lists/{l}"))?;
    }
    once(src.join("etc").join("internal_options.conf"), "etc/internal_options.conf")?;
    install_agentless_scripts(&src, home)?;
    once(src.join("etc").join("local_decoder.xml"), "etc/decoders/local_decoder.xml")?;
    once(src.join("etc").join("local_rules.xml"), "etc/rules/local_rules.xml")?;
    let lio = home.join("etc").join("local_internal_options.conf");
    if !lio.exists() {
        let _ = std::fs::write(&lio, "# Local internal options\n");
    }
    let agent_conf = home.join("etc").join("shared").join("default").join("agent.conf");
    if !agent_conf.exists() {
        let _ = std::fs::write(&agent_conf, "<agent_config>\n\n</agent_config>\n");
    }
    let conf = home.join("etc").join("ossec.conf");
    if !conf.exists() {
        std::fs::write(&conf, ossec_conf()).map_err(|e| format!("ossec.conf: {e}"))?;
    }
    ensure_ar_commands(&conf);
    if !keys_file(home).exists() {
        std::fs::write(keys_file(home), "").map_err(|e| format!("client.keys: {e}"))?;
    }
    Ok(())
}

/// The `agentless/` expect scripts, refreshed on every start (extra files such as
/// `.passlist` are kept). agentlessd refuses a script its user can write.
fn install_agentless_scripts(src: &Path, home: &Path) -> Result<(), String> {
    let from = src.join("src").join("agentlessd").join("scripts");
    let to = home.join("agentless");
    std::fs::create_dir_all(&to).map_err(|e| format!("agentless: {e}"))?;
    for f in std::fs::read_dir(&from).map_err(|e| format!("{}: {e}", from.display()))?.flatten() {
        let dst = to.join(f.file_name());
        let _ = std::fs::remove_file(&dst); // the previous copy is read-only
        std::fs::copy(f.path(), &dst).map_err(|e| format!("agentless/{}: {e}", f.file_name().to_string_lossy()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o550));
        }
    }
    Ok(())
}

/// The files of the Windows agent package (`/downloads/windows/<file>`).
pub const WINDOWS_AGENT_FILES: &[&str] = &[
    "wazuh-agent.exe",
    // active-responsein (siem-active-response)
    "netsh.exe",
    "restart-wazuh.exe",
    "route-null.exe",
    // EDR responses (siem-active-response, not in Wazuh)
    "kill-process.exe",
    "quarantine-file.exe",
    "isolate-host.exe",
    "yara-scan.exe",
    "internal_options.conf",
    "local_internal_options.conf",
    "vista_sec.txt",
    "help.txt",
    "norm_config.json",
    // rulesetsca: the MSI installs the one matching the OS (wazuh-installer.wxs)
    "cis_win10_enterprise.yml",
    "cis_win11_enterprise.yml",
    "cis_win2012r2.yml",
    "cis_win2012_non_r2.yml",
    "cis_win2016.yml",
    "cis_win2019.yml",
    "cis_win2022.yml",
    "cis_win2025.yml",
];

fn agent_dist_dir() -> PathBuf {
    crate::data_file_path("agent-dist").join("windows")
}

/// Fills `data/agent-dist/windows` with the package's text files (the MSI
/// installs them next to `wazuh-agent.exe`).
fn prepare_agent_dist() {
    let dir = agent_dist_dir();
    let _ = std::fs::create_dir_all(&dir);
    let Some(src) = wazuh_source() else { return };
    for (from, to) in [
        (src.join("etc/internal_options.conf"), "internal_options.conf"),
        (src.join("etc/local_internal_options-win.conf"), "local_internal_options.conf"),
        (src.join("src/win32/vista_sec.txt"), "vista_sec.txt"),
        (src.join("src/win32/help.txt"), "help.txt"),
        // the MSI installs it as queue\syscollector\norm_config.json
        (src.join("src/wazuh_modules/syscollector/norm_config.json"), "norm_config.json"),
    ] {
        let dst = dir.join(to);
        if !dst.exists() {
            let _ = std::fs::copy(from, dst);
        }
    }
    for f in WINDOWS_AGENT_FILES.iter().filter(|f| f.ends_with(".yml")) {
        let dst = dir.join(f);
        if !dst.exists() {
            let _ = std::fs::copy(src.join("ruleset/sca/windows").join(f), dst);
        }
    }
}

/// A file of the Windows agent package: `data/agent-dist/windows/<name>`,
/// the agent binary also from the cross-build outputs.
pub fn windows_agent_file(name: &str) -> Option<PathBuf> {
    if !WINDOWS_AGENT_FILES.contains(&name) {
        return None;
    }
    let mut cands = vec![agent_dist_dir().join(name)];
    if name.ends_with(".exe") {
        for rel in ["target/x86_64-pc-windows-gnu/release", "target/release", "backend-rust/target/x86_64-pc-windows-gnu/release"] {
            cands.push(PathBuf::from(rel).join(name));
        }
    }
    cands.into_iter().find(|p| p.is_file())
}

/// The Windows agent's `ossec.conf`: the MSI's default (`src/win32/ossec.conf`)
/// with the manager address (`WAZUH_MANAGER`) set. The key comes from the
/// enrollment API, so the agent does not enroll on 1515 itself.
pub fn windows_agent_conf(manager: &str) -> Option<String> {
    let manager = manager.trim_start_matches('[').trim_end_matches(']');
    // "localhost" resolves to ::1 first on Windows, and remoted listens on IPv4 (0.0.0.0)
    let manager = if manager.eq_ignore_ascii_case("localhost") || manager == "::1" { "127.0.0.1" } else { manager };
    let ok =!manager.is_empty() && manager.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'));
    if !ok {
        return None;
    }
    let src = wazuh_source()?;
    let t = std::fs::read_to_string(src.join("src/win32/ossec.conf")).ok()?;
    let t = t.replace("<address>0.0.0.0</address>", &format!("<address>{manager}</address>"));
    let t = t.replacen(
        "<crypto_method>aes</crypto_method>",
        "<crypto_method>aes</crypto_method>\r\n    <enrollment>\r\n      <enabled>no</enabled>\r\n    </enrollment>",
        1,
    );
    Some(t)
}

pub(crate) fn exe_name(d: &str) -> String {
    if cfg!(windows) {
        format!("{d}.exe")
    } else {
        d.to_string()
    }
}

/// Copies the daemons built next to siem-api into `<home>/bin` (wazuh-db
/// finds its home from there, like an installed manager).
/// Command-line tools of the manager (installed in `bin/`, not supervised).
const MANAGER_TOOLS: &[&str] = &["wazuh-reportd"];

fn install_binaries(home: &Path) -> Result<(), String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = me.parent().ok_or("no exe dir")?;
    let mut search = vec![dir.to_path_buf()];
    if let Some(t) = dir.parent() {
        search.push(t.join("release"));
        search.push(t.join("debug"));
    }
    let targets = DAEMONS.iter().map(|d| (exe_name(d), home.join("bin").join(exe_name(d)))).chain(
        INTEGRATIONS.iter().map(|i| (exe_name("integrations"), home.join("integrations").join(exe_name(i)))),
    ).chain(MANAGER_AR.iter().map(|a| (exe_name(a), home.join("active-response/bin").join(exe_name(a)))))
    .chain(MANAGER_TOOLS.iter().map(|t| (exe_name(t), home.join("bin").join(exe_name(t)))));
    for (n, dst) in targets {
        let found = search.iter().map(|s| s.join(&n)).filter(|p| p.is_file()).max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok());
        let Some(src) = found else {
            return Err(format!("{n} not built (cargo build --release -p siem-wdb -p siem-analysisd -p siem-remoted -p siem-modulesd -p siem-monitord -p siem-maild -p siem-integratord -p siem-csyslogd -p siem-execd -p siem-agentlessd -p siem-active-response)"));
        };
        let newer = match (src.metadata().and_then(|m| m.modified()), dst.metadata().and_then(|m| m.modified())) {
            (Ok(a), Ok(b)) => a > b,
            _ => true,
        };
        if newer {
            if let Some(d) = dst.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            std::fs::copy(&src, &dst).map_err(|e| format!("{n}: {e}"))?;
            // integratord refuses scripts its user can write
            #[cfg(unix)]
            if dst.parent().is_some_and(|p| p.ends_with("integrations")) {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o550));
            }
        }
    }
    Ok(())
}

/// `var/db/mitre.db` (what the package installs with `mitredb.py`), built
/// once from the ruleset's `enterprise-attack.json` with `wazuh-mitredb`.
fn build_mitre_db(home: &Path) {
    let db = home.join("var/db/mitre.db");
    if db.exists() {
        return;
    }
    let Some(src) = wazuh_source() else { return };
    let json = src.join("ruleset/mitre/enterprise-attack.json");
    let Some(tool) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join(exe_name("wazuh-mitredb")))).filter(|p| p.is_file()) else {
        warn!("Wazuh manager: wazuh-mitredb not built (cargo build --release -p siem-wdb); alerts have no MITRE data");
        return;
    };
    // built under another name: a half-built file must not look finished
    let tmp = db.with_extension("db.tmp");
    let _ = std::fs::remove_file(&tmp);
    match Command::new(tool).arg("-d").arg(&tmp).arg("-j").arg(&json).stdout(Stdio::null()).status() {
        Ok(s) if s.success() && std::fs::rename(&tmp, &db).is_ok() => info!("Wazuh manager: built {}", db.display()),
        other => warn!("Wazuh manager: building mitre.db failed: {other:?}"),
    }
}

/// The children of an earlier siem-api run that were left behind.
fn kill_stale(home: &Path) {
    let f = home.join("var/run/siem-api-children.pids");
    if let Ok(s) = std::fs::read_to_string(&f) {
        for pid in s.split_whitespace().filter_map(|p| p.parse::<u32>().ok()) {
            #[cfg(windows)]
            let _ = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string(), "/FI", "IMAGENAME eq wazuh-*"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            // after a reboot the pid may belong to another program
            #[cfg(unix)]
            if std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.starts_with("wazuh-")) {
                let _ = Command::new("kill").args(["-9", &pid.to_string()]).stdout(Stdio::null()).stderr(Stdio::null()).status();
            }
        }
    }
    let _ = std::fs::remove_file(f);
}

static CHILDREN: Mutex<Vec<(String, u32)>> = Mutex::new(Vec::new());

/// `key='value'` lines of a daemon state file (`var/run/<daemon>.state`); numbers as numbers.
fn read_state_file(path: &Path) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for line in std::fs::read_to_string(path).unwrap_or_default().lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        if line.starts_with('#') {
            continue;
        }
        let v = v.trim().trim_matches('\'');
        let val = v.parse::<f64>().map(serde_json::Value::from).unwrap_or_else(|_| serde_json::Value::String(v.to_string()));
        m.insert(k.trim().to_string(), val);
    }
    serde_json::Value::Object(m)
}

/// What the manager is doing: running daemons and the remoted / analysisd counters
/// (queues, events received, discarded and dropped).
/// The daemons siem-api starts and keeps running.
pub fn daemons() -> &'static [&'static str] {
    &DAEMONS
}

/// The daemons running now.
pub fn running() -> Vec<String> {
    CHILDREN.lock().unwrap().iter().map(|(n, _)| n.clone()).collect()
}

pub fn status() -> serde_json::Value {
    let run = home().join("var/run");
    let daemons: Vec<serde_json::Value> = CHILDREN.lock().unwrap().iter().map(|(n, p)| serde_json::json!({ "name": n, "pid": p })).collect();
    serde_json::json!({
        "enabled": enabled(),
        "daemons": daemons,
        "remoted": read_state_file(&run.join("wazuh-remoted.state")),
        "analysisd": read_state_file(&run.join("wazuh-analysisd.state")),
    })
}

fn record_children(home: &Path) {
    let pids: Vec<String> = CHILDREN.lock().unwrap().iter().map(|(_, p)| p.to_string()).collect();
    let _ = std::fs::write(home.join("var/run/siem-api-children.pids"), pids.join(" "));
}

/// The socket a daemon binds once it is ready.
fn ready_marker(home: &Path, d: &str) -> Option<PathBuf> {
    let suffix = if cfg!(unix) { "" } else { ".port" };
    match d {
        "wazuh-db" => Some(home.join(format!("queue/db/wdb{suffix}"))),
        "wazuh-analysisd" => Some(home.join(format!("queue/sockets/queue{suffix}"))),
        _ => None,
    }
}

fn spawn(home: &Path, d: &str) -> std::io::Result<Child> {
    let mut c = Command::new(home.join("bin").join(exe_name(d)));
    c.current_dir(home);
    match d {
        "wazuh-db" | "wazuh-modulesd" | "wazuh-integratord" | "wazuh-csyslogd" => c.arg("-f"),
        _ => c.arg("-f").arg("-D").arg(home),
    };
    let log = |n: &str| std::fs::OpenOptions::new().create(true).append(true).open(home.join("logs").join(n));
    c.stdin(Stdio::null());
    c.stdout(log(&format!("{d}.out")).map(Stdio::from).unwrap_or(Stdio::null()));
    c.stderr(log(&format!("{d}.out")).map(Stdio::from).unwrap_or(Stdio::null()));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW
        c.creation_flags(0x0800_0000);
    }
    c.spawn()
}

/// Runs one daemon for good: restarted 5 seconds after it exits.
fn supervise(home: PathBuf, d: &'static str, first: std::sync::mpsc::Sender<()>) {
    let mut first = Some(first);
    loop {
        // the marker is kept (not deleted): a restarted receiver takes its old port back
        // from it, so senders still connected to that port keep delivering
        let spawned = std::time::SystemTime::now();
        match spawn(&home, d) {
            Ok(mut child) => {
                let pid = child.id();
                {
                    let mut c = CHILDREN.lock().unwrap();
                    c.retain(|(n, _)| n != d);
                    c.push((d.to_string(), pid));
                }
                record_children(&home);
                info!("Wazuh manager: {d} started (pid {pid})");
                if let Some(tx) = first.take() {
                    // The next daemon starts once this one listens.
                    if let Some(m) = ready_marker(&home, d) {
                        for _ in 0..300 {
                            if m.metadata().and_then(|x| x.modified()).is_ok_and(|t| t >= spawned) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                    let _ = tx.send(());
                }
                let st = child.wait();
                // its pid may be reused: restart_daemons must not kill it any more
                CHILDREN.lock().unwrap().retain(|(n, _)| n != d);
                record_children(&home);
                // maild / integratord / csyslogd / agentlessd exit 0 when not configured: start again once ossec.conf changes
                if matches!(d, "wazuh-maild" | "wazuh-integratord" | "wazuh-csyslogd" | "wazuh-agentlessd") && st.as_ref().is_ok_and(|s| s.success()) {
                    info!("Wazuh manager: {d} idle (not configured)");
                    let conf = home.join("etc/ossec.conf");
                    let mtime = |p: &Path| p.metadata().and_then(|m| m.modified()).ok();
                    let seen = mtime(&conf);
                    while mtime(&conf) == seen {
                        std::thread::sleep(Duration::from_secs(2));
                    }
                    continue;
                }
                warn!("Wazuh manager: {d} exited ({st:?}); restarting in 5s (see {}/logs/ossec.log)", home.display());
            }
            Err(e) => {
                warn!("Wazuh manager: cannot start {d}: {e}");
                if let Some(tx) = first.take() {
                    let _ = tx.send(());
                }
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// Every `<rule id="N"` of the ruleset (`ruleset/rules`, `etc/rules`).
fn used_rule_ids(home: &Path) -> std::collections::HashSet<u32> {
    let mut ids = std::collections::HashSet::new();
    for dir in ["ruleset/rules", "etc/rules"] {
        for e in std::fs::read_dir(home.join(dir)).into_iter().flatten().flatten() {
            if let Ok(t) = std::fs::read_to_string(e.path()) {
                ids.extend(t.split("<rule id=\"").skip(1).filter_map(|p| p.split('"').next()?.parse::<u32>().ok()));
            }
        }
    }
    ids
}

static RULES_LOCK: Mutex<()> = Mutex::new(());

/// Writes (or removes) `etc/rules/<file>` once `wazuh-analysisd -t` accepts the whole ruleset
/// with the change, then restarts analysisd so it loads the rules. The check runs on a staged
/// copy (`etc/rules.staging` and its own ossec.conf), so the running or restarting analysisd
/// never reads a file that has not passed it; any ERROR, CRITICAL or duplicate rule id fails it.
fn replace_rules_file(home: &Path, file: &str, content: Option<&str>) -> Result<(), String> {
    let rules = home.join("etc/rules");
    let staging = home.join("etc/rules.staging");
    let conf = home.join("etc/ossec.staging.conf");
    let cleanup = || {
        let _ = std::fs::remove_dir_all(&staging);
        let _ = std::fs::remove_file(&conf);
    };
    cleanup();
    let staged = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(&staging)?;
        for e in std::fs::read_dir(&rules)?.flatten() {
            if e.file_name() != std::ffi::OsStr::new(file) && e.path().is_file() {
                std::fs::copy(e.path(), staging.join(e.file_name()))?;
            }
        }
        if let Some(c) = content {
            std::fs::write(staging.join(file), c)?;
        }
        Ok(())
    })();
    let main_conf = std::fs::read_to_string(home.join("etc/ossec.conf")).unwrap_or_default();
    const RULE_DIR: &str = "<rule_dir>etc/rules</rule_dir>";
    if staged.is_err() || main_conf.matches(RULE_DIR).count() != 1 || std::fs::write(&conf, main_conf.replace(RULE_DIR, "<rule_dir>etc/rules.staging</rule_dir>")).is_err() {
        cleanup();
        return Err(format!("Could not stage the rules for checking ({})", staged.err().map(|e| e.to_string()).unwrap_or_else(|| "ossec.conf".into())));
    }
    let mut c = Command::new(home.join("bin").join(exe_name("wazuh-analysisd")));
    c.arg("-t").arg("-c").arg("etc/ossec.staging.conf").arg("-D").arg(home).current_dir(home).stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    let checked = c.output();
    cleanup();
    let (ok, log) = match checked {
        Ok(o) => {
            let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            let bad = log.lines().any(|l| l.contains("ERROR") || l.contains("CRITICAL") || l.contains("(7612)"));
            (o.status.success() && !bad, log)
        }
        Err(e) => (false, format!("wazuh-analysisd -t: {e}")),
    };
    if !ok {
        let why = log.lines().find(|l| l.contains("ERROR") || l.contains("CRITICAL") || l.contains("(7612)")).unwrap_or(log.trim()).to_string();
        return Err(format!("wazuh-analysisd rejected the rules: {why}"));
    }
    let path = rules.join(file);
    match content {
        Some(c) => std::fs::write(&path, c),
        None => std::fs::remove_file(&path).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) }),
    }
    .map_err(|e| format!("{}: {e}", path.display()))?;
    restart_daemons(&["wazuh-analysisd"]);
    Ok(())
}

/// Adds a rule group to `etc/rules/<file>`, its `<rule id>` set to a free id of `ids`;
/// returns the id and the XML as deployed.
pub fn deploy_rule_group(file: &str, xml: &str, ids: std::ops::RangeInclusive<u32>) -> Result<(u32, String), String> {
    if !enabled() {
        return Err("The Wazuh manager is not running".into());
    }
    let _g = RULES_LOCK.lock().unwrap();
    let home = home();
    let used = used_rule_ids(&home);
    let id = ids.into_iter().find(|i| !used.contains(i)).ok_or("No free rule id left in the Red Swarm range")?;
    let start = xml.find("<rule id=\"").ok_or("The rule has no <rule id>")? + "<rule id=\"".len();
    let end = start + xml[start..].find('"').ok_or("Malformed <rule id>")?;
    let xml = format!("{}{id}{}", &xml[..start], &xml[end..]);
    let cur = std::fs::read_to_string(home.join("etc/rules").join(file)).unwrap_or_default();
    replace_rules_file(&home, file, Some(&format!("{cur}{xml}\n")))?;
    Ok((id, xml))
}

/// Removes the rule group holding `<rule id="id">` from `etc/rules/<file>`.
pub fn remove_rule_group(file: &str, id: u32) -> Result<(), String> {
    if !enabled() {
        return Err("The Wazuh manager is not running".into());
    }
    let _g = RULES_LOCK.lock().unwrap();
    let home = home();
    let cur = std::fs::read_to_string(home.join("etc/rules").join(file)).map_err(|_| "No rule of this kind is deployed".to_string())?;
    let rest = without_group(&cur, id)?;
    replace_rules_file(&home, file, (!rest.trim().is_empty()).then_some(rest.as_str()))
}

/// A rules file without the `<group name=…>` holding `<rule id="id">`.
fn without_group(cur: &str, id: u32) -> Result<String, String> {
    let at = cur.find(&format!("<rule id=\"{id}\"")).ok_or("The rule is no longer deployed")?;
    // the group around the rule (the rule has a <group> element of its own inside)
    let start = cur[..at].rfind("<group name=").ok_or("Malformed rules file")?;
    let after_rule = at + cur[at..].find("</rule>").ok_or("Malformed rules file")?;
    let end = after_rule + cur[after_rule..].find("</group>").ok_or("Malformed rules file")? + "</group>".len();
    Ok(format!("{}{}", &cur[..start], cur[end..].trim_start_matches(['\r', '\n'])))
}

#[cfg(test)]
mod rule_file_tests {
    #[test]
    fn removes_the_whole_group_of_a_rule() {
        let g = |id: u32| format!("<group name=\"rs,m\">\n  <!-- c -->\n  <rule id=\"{id}\" level=\"8\">\n    <match>x</match>\n    <group>attack,purple_team</group>\n  </rule>\n</group>\n");
        let file = format!("{}{}", g(119000), g(119001));
        assert_eq!(super::without_group(&file, 119000).unwrap(), g(119001));
        assert_eq!(super::without_group(&file, 119001).unwrap(), g(119000));
        assert!(super::without_group(&g(119000), 119000).unwrap().trim().is_empty());
        assert!(super::without_group(&file, 5).is_err());
    }

    /// One-shot EDR commands get one `<active-response>` without a timeout (ar.conf
    /// `kill-process0`, what the console sends); isolation gets the three timeouts.
    #[test]
    fn edr_commands_in_ossec_conf() {
        let k = super::ar_conf_section("kill-process", "kill-process.exe", false);
        assert!(k.contains("<timeout_allowed>no</timeout_allowed>") && !k.contains("<timeout>") && k.matches("<active-response>").count() == 1, "{k}");
        let i = super::ar_conf_section("isolate-host", "isolate-host.exe", true);
        assert_eq!(i.matches("<timeout>").count(), super::AR_TIMEOUTS.len());
        assert!(super::AR_COMMANDS.iter().filter(|c| c.1 == "isolate-host.exe").count() == 2, "isolate and release");
    }
}

/// Stops the running daemons named; their supervisors start them again.
pub(crate) fn restart_daemons(names: &[&str]) {
    for (n, pid) in CHILDREN.lock().unwrap().iter() {
        if !names.contains(&n.as_str()) {
            continue;
        }
        #[cfg(windows)]
        let _ = Command::new("taskkill").args(["/F", "/PID", &pid.to_string()]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        #[cfg(unix)]
        let _ = Command::new("kill").arg(pid.to_string()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// `ossec.conf` with the mail settings: the `<global>` e-mail fields and
/// `<alerts><email_alert_level>` (each element on its own line, as written here).
fn ossec_conf_with_mail(t: &str, s: &crate::mail_settings::MailSettings) -> String {
    let mut lines: Vec<String> = t.lines().map(String::from).collect();
    let starts = |l: &str, tags: &[&str]| tags.iter().any(|g| l.trim_start().starts_with(&format!("<{g}>")));
    let section = |lines: &Vec<String>, name: &str| -> Option<(usize, usize)> {
        let a = lines.iter().position(|l| l.trim() == format!("<{name}>"))?;
        let b = lines[a..].iter().position(|l| l.trim() == format!("</{name}>"))? + a;
        Some((a, b))
    };
    let mut global = vec![format!("<email_notification>{}</email_notification>", if s.alert_enabled { "yes" } else { "no" })];
    if !s.host.is_empty() {
        global.push(format!("<smtp_server>{}</smtp_server>", s.host));
    }
    if !s.user.is_empty() {
        global.push(format!("<email_from>{}</email_from>", s.user));
    }
    global.extend(s.alert_to.iter().map(|t| format!("<email_to>{t}</email_to>")));
    global.push(format!("<email_maxperhour>{}</email_maxperhour>", s.max_per_hour));
    let gtags = ["email_notification", "smtp_server", "email_from", "email_to", "email_maxperhour"];
    match section(&lines, "global") {
        Some((a, b)) => {
            let mut body: Vec<String> = lines[a + 1..b].iter().filter(|l| !starts(l, &gtags)).cloned().collect();
            body.extend(global);
            lines.splice(a + 1..b, body);
        }
        None => {
            let end = lines.iter().rposition(|l| l.trim() == "</ossec_config>").unwrap_or(lines.len());
            let mut blk = vec!["<global>".to_string()];
            blk.extend(global);
            blk.push("</global>".into());
            lines.splice(end..end, blk);
        }
    }
    let level = format!("<email_alert_level>{}</email_alert_level>", s.alert_level);
    match section(&lines, "alerts") {
        Some((a, b)) => {
            let mut body: Vec<String> = lines[a + 1..b].iter().filter(|l| !starts(l, &["email_alert_level"])).cloned().collect();
            body.push(level);
            lines.splice(a + 1..b, body);
        }
        None => {
            let end = lines.iter().rposition(|l| l.trim() == "</ossec_config>").unwrap_or(lines.len());
            lines.splice(end..end, ["<alerts>".to_string(), level, "</alerts>".into()]);
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Writes the platform SMTP settings into the manager (`ossec.conf` and the
/// TLS/login file `etc/smtp_auth.conf`) and restarts what reads them.
pub fn apply_mail_settings(s: &crate::mail_settings::MailSettings) {
    if !enabled() {
        return;
    }
    let home = home();
    let mut changed = false;
    let conf = home.join("etc/ossec.conf");
    if let Ok(t) = std::fs::read_to_string(&conf) {
        let n = ossec_conf_with_mail(&t, s);
        if n != t {
            changed |= std::fs::write(&conf, n).is_ok();
        }
    }
    let auth = home.join(siem_maild::smtp_ext::SMTP_AUTH_FILE);
    if s.host.is_empty() {
        changed |= std::fs::remove_file(&auth).is_ok();
    } else {
        let text = format!("# Written by siem-api from the platform SMTP settings\nhost={}\nport={}\nsecurity={}\nuser={}\npassword={}\n", s.host, s.port, s.security(), s.user, s.password);
        if std::fs::read_to_string(&auth).ok().as_deref() != Some(text.as_str()) {
            let tmp = auth.with_extension("conf.tmp");
            if std::fs::write(&tmp, &text).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
                }
                changed |= std::fs::rename(&tmp, &auth).is_ok();
            }
        }
    }
    if changed {
        info!("Wazuh manager: mail settings applied (alerts by e-mail: {})", if s.alert_enabled { "on" } else { "off" });
        // analysisd decides which alerts are mailed; maild and monitord send them
        restart_daemons(&["wazuh-analysisd", "wazuh-maild", "wazuh-monitord"]);
    }
}

static WDB: std::sync::OnceLock<siem_ipc::wdbc::WdbcSocket> = std::sync::OnceLock::new();

fn wdb() -> &'static siem_ipc::wdbc::WdbcSocket {
    WDB.get_or_init(|| siem_ipc::wdbc::WdbcSocket::new(home().join("queue/db/wdb")))
}

/// What authd does for a new key (`wdb_insert_agent` + `wdb_set_agent_groups_csv`):
/// the agent's row in global.db, which remoted and analysisd read.
pub async fn register_agent(id: &str, name: &str, ip: &str, raw_key: &str, groups: &str) {
    if !enabled() {
        return;
    }
    let Ok(n) = id.parse::<i64>() else { return };
    let group = if groups.trim().is_empty() { "default" } else { groups.trim() };
    // A re-enrollment replaces the row (manage_agents -r, then the insert).
    let _ = wdb().query(&format!("global delete-agent {n}")).await;
    let row = serde_json::json!({
        "id": n,
        "name": name,
        "ip": serde_json::Value::Null,
        "register_ip": ip,
        "internal_key": raw_key,
        "group": group,
        "date_add": Utc::now().timestamp(),
    });
    match wdb().query(&format!("global insert-agent {row}")).await {
        Ok(r) if r.starts_with("ok") => {}
        Ok(r) => warn!("Wazuh manager: insert-agent {id}: {r}"),
        Err(e) => warn!("Wazuh manager: insert-agent {id}: {e}"),
    }
    let groups: Vec<&str> = group.split(',').map(str::trim).filter(|g| !g.is_empty()).collect();
    let set = serde_json::json!({ "mode": "override", "sync_status": "synced", "data": [{ "id": n, "groups": groups }] });
    if let Ok(r) = wdb().query(&format!("global set-agent-groups {set}")).await {
        if !r.starts_with("ok") {
            warn!("Wazuh manager: set-agent-groups {id}: {r}");
        }
    }
}

/// Wazuh API `set_agent_group_relationship` (override): the agent's whole group list.
pub async fn set_agent_groups(id: &str, groups: &[String]) -> bool {
    let Ok(n) = id.parse::<i64>() else { return false };
    let set = serde_json::json!({ "mode": "override", "sync_status": "syncreq", "data": [{ "id": n, "groups": groups }] });
    match wdb().query(&format!("global set-agent-groups {set}")).await {
        Ok(r) if r.starts_with("ok") => true,
        Ok(r) => {
            warn!("Wazuh manager: set-agent-groups {id}: {r}");
            false
        }
        Err(e) => {
            warn!("Wazuh manager: set-agent-groups {id}: {e}");
            false
        }
    }
}

/// What wm_database does when it finds a new or removed `etc/shared` folder
/// (`wdb_insert_group` / `wdb_remove_group_db`), done now instead of on its next sync.
pub async fn sync_group(name: &str, exists: bool) -> bool {
    let cmd = if exists { "insert-agent-group" } else { "delete-group" };
    match wdb().query(&format!("global {cmd} {name}")).await {
        Ok(r) if r.starts_with("ok") => true,
        r => {
            warn!("Wazuh manager: {cmd} {name}: {r:?}");
            false
        }
    }
}

/// `wdb_remove_agent`
pub async fn remove_agent(id: &str) {
    if !enabled() {
        return;
    }
    if let Ok(n) = id.parse::<i64>() {
        let _ = wdb().query(&format!("global delete-agent {n}")).await;
        // OS_RemoveCounter (only a well-formed id names a file under queue/rids)
        let _ = std::fs::remove_file(home().join("queue/rids").join(format!("{n:03}")));
    }
}

/// `agent <id> sql <query>`: the rows, or None (no agent DB, not running).
pub(crate) async fn agent_sql(id: &str, sql: &str) -> Option<Vec<serde_json::Value>> {
    let r = wdb().query(&format!("agent {id} sql {sql}")).await.ok()?;
    let json = r.strip_prefix("ok ")?;
    serde_json::from_str::<serde_json::Value>(json).ok()?.as_array().cloned()
}

/// Whether the id is an agent of the Wazuh manager (it has a row in global.db).
pub async fn is_wazuh_agent(agent_id: &str) -> bool {
    let Ok(n) = agent_id.parse::<u32>() else { return false };
    enabled() && wdb().query(&format!("global get-agent-info {n}")).await.is_ok_and(|r| r.starts_with("ok [{"))
}

/// One message to remoted's active-response queue (`queue/alerts/ar`), as
/// the Wazuh API's `WazuhQueue.send_msg_to_agent` writes it.
async fn send_ar_queue(msg: &str) -> Result<(), String> {
    let s = siem_ipc::local::DatagramSender::connect(home().join("queue/alerts/ar")).await.map_err(|e| format!("remoted active-response queue: {e}"))?;
    s.send(msg.as_bytes()).await.map_err(|e| format!("remoted active-response queue: {e}"))
}

/// `send_restart_command` (agents >= 4.2: the JSON `restart-wazuh0` message).
pub async fn restart_agent(agent_id: &str) -> Result<(), String> {
    let id = format!("{:03}", agent_id.parse::<u32>().map_err(|_| "invalid agent id")?);
    let m = r#"{"version": 1, "origin": {"module": "api"}, "command": "restart-wazuh0", "parameters": {"extra_args": [], "alert": {}}}"#;
    send_ar_queue(&format!("(msg_to_agent) [] NNS {id} {m} - null (from_the_server) (no_rule_id)")).await
}

/// `PUT /syscheck` / `PUT /rootcheck`: `syscheck restart` runs a FIM and a rootcheck scan.
pub async fn syscheck_restart(agent_id: &str) -> Result<(), String> {
    let id = format!("{:03}", agent_id.parse::<u32>().map_err(|_| "invalid agent id")?);
    send_ar_queue(&format!("(msg_to_agent) [] N!S {id} syscheck restart")).await
}

/// The block durations the manager defines active responses for (`ar.conf`
/// names are the command name plus the timeout).
pub const AR_TIMEOUTS: [u64; 3] = [600, 3600, 86400];

/// `PUT /active-response`: block `ip` on the agent's firewall (firewall-drop
/// on Unix, netsh on Windows) for `timeout` seconds; the agent's execd removes
/// the rule when it expires.
pub async fn block_ip(agent_id: &str, windows: bool, ip: &str, timeout: u64, method: Option<&str>) -> Result<String, String> {
    let id = format!("{:03}", agent_id.parse::<u32>().map_err(|_| "invalid agent id")?);
    let timeout = AR_TIMEOUTS.iter().copied().find(|t| *t >= timeout).unwrap_or(86400);
    // Windows: a firewall rule (netsh) or a null route; Linux: firewall-drop
    let name = match (windows, method) {
        (true, Some("route-null")) => "route-null",
        (true, _) => "netsh",
        (false, _) => "firewall-drop",
    };
    let command = format!("{name}{timeout}");
    let m = serde_json::json!({
        "version": 1,
        "origin": { "name": serde_json::Value::Null, "module": "api" },
        "command": command,
        "parameters": { "extra_args": [], "alert": { "data": { "srcip": ip } } },
    });
    send_ar_queue(&format!("(msg_to_agent) [] NNS {id} {m}")).await?;
    Ok(command)
}

/// One EDR command to a Windows agent (`extra_args` as `key=value` items, see
/// siem-active-response's edr.rs).
async fn send_edr(agent_id: &str, command: &str, extra_args: &[String]) -> Result<(), String> {
    let id = format!("{:03}", agent_id.parse::<u32>().map_err(|_| "invalid agent id")?);
    let m = serde_json::json!({
        "version": 1,
        "origin": { "name": serde_json::Value::Null, "module": "api" },
        "command": command,
        "parameters": { "extra_args": extra_args, "alert": {} },
    });
    send_ar_queue(&format!("(msg_to_agent) [] NNS {id} {m}")).await
}

/// EDR: ends process `pid` on the agent (with `image`, only while the PID still runs it).
pub async fn kill_process(agent_id: &str, pid: u32, image: Option<&str>) -> Result<(), String> {
    let mut args = vec![format!("pid={pid}")];
    args.extend(image.map(|i| format!("image={i}")));
    send_edr(agent_id, "kill-process0", &args).await
}

/// EDR: scans `path` with the YARA rules the agent has (`yara_edr.rs`).
pub async fn yara_scan(agent_id: &str, path: &str) -> Result<(), String> {
    send_edr(agent_id, "yara-scan0", &[format!("path={path}")]).await
}

/// EDR: moves `path` into the agent's quarantine folder.
pub async fn quarantine_file(agent_id: &str, path: &str) -> Result<(), String> {
    send_edr(agent_id, "quarantine-file0", &[format!("path={path}")]).await
}

/// EDR: puts quarantined file `id` back (the id is in the agent's quarantine log line).
pub async fn restore_file(agent_id: &str, id: &str) -> Result<(), String> {
    send_edr(agent_id, "quarantine-file0", &[format!("restore={id}")]).await
}

/// The manager addresses an isolated host keeps reaching: `SIEM_LAN_IP` (else
/// `MANAGER_IP`) and `EDR_ISOLATION_ALLOW` (comma-separated, e.g. a NAT address).
pub fn isolation_allow() -> Vec<std::net::Ipv4Addr> {
    let own = std::env::var("SIEM_LAN_IP").or_else(|_| std::env::var("MANAGER_IP")).unwrap_or_default();
    let extra = std::env::var("EDR_ISOLATION_ALLOW").unwrap_or_default();
    let mut v: Vec<std::net::Ipv4Addr> = own.split(',').chain(extra.split(',')).filter_map(|a| a.trim().parse().ok()).collect();
    v.dedup();
    v
}

/// EDR: isolates the agent's host for `timeout` s (its execd lifts it then, even
/// with no manager); the isolation id and its timeout.
pub async fn isolate_agent(agent_id: &str, timeout: u64) -> Result<(String, u64), String> {
    let allow = isolation_allow();
    if allow.is_empty() {
        return Err("Set SIEM_LAN_IP (the manager address the agents connect to) first: an isolated host must keep reaching the manager".into());
    }
    let timeout = AR_TIMEOUTS.iter().copied().find(|t| *t >= timeout).unwrap_or(86400);
    let iso = uuid::Uuid::new_v4().simple().to_string();
    let allow = allow.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",");
    send_edr(agent_id, &format!("isolate-host{timeout}"), &[format!("id={iso}"), format!("allow={allow}")]).await?;
    Ok((iso, timeout))
}

/// EDR: lifts the isolation of the agent's host.
pub async fn release_agent(agent_id: &str) -> Result<(), String> {
    send_edr(agent_id, "release-host0", &["release".to_string()]).await
}

/// The active responses the console can send: (command name, agent executable, takes
/// a timeout). `route-null` and the EDR ones are Windows only; `release-host` is
/// isolate-host run with `release`.
const AR_COMMANDS: [(&str, &str, bool); 8] = [
    ("firewall-drop", "firewall-drop", true),
    ("netsh", "netsh.exe", true),
    ("route-null", "route-null.exe", true),
    ("kill-process", "kill-process.exe", false),
    ("quarantine-file", "quarantine-file.exe", false),
    ("isolate-host", "isolate-host.exe", true),
    ("release-host", "isolate-host.exe", false),
    ("yara-scan", "yara-scan.exe", false),
];

/// The `<command>` and `<active-response>` blocks of one console command in the
/// manager's ossec.conf, at level 20 so no rule triggers them (`<name><timeout>` in
/// ar.conf, `<name>0` without one).
fn ar_conf_section(name: &str, exe: &str, timed: bool) -> String {
    let allowed = if timed { "yes" } else { "no" };
    let mut s = format!("  <command>\n    <name>{name}</name>\n    <executable>{exe}</executable>\n    <timeout_allowed>{allowed}</timeout_allowed>\n  </command>\n");
    let ar = |t: &str| format!("  <active-response>\n    <command>{name}</command>\n    <location>local</location>\n    <level>20</level>\n{t}  </active-response>\n");
    if timed {
        for t in AR_TIMEOUTS {
            s.push_str(&ar(&format!("    <timeout>{t}</timeout>\n")));
        }
    } else {
        s.push_str(&ar(""));
    }
    s
}

/// Adds the console's active-response commands an existing ossec.conf lacks.
fn ensure_ar_commands(conf: &Path) {
    let Ok(t) = std::fs::read_to_string(conf) else { return };
    let missing: String = AR_COMMANDS
        .iter()
        .filter(|(name, _, _)| !t.contains(&format!("<name>{name}</name>")))
        .map(|(name, exe, timed)| ar_conf_section(name, exe, *timed))
        .collect();
    if missing.is_empty() {
        return;
    }
    if let Some(p) = t.rfind("</ossec_config>") {
        let mut n = t.clone();
        n.insert_str(p, &missing);
        let _ = std::fs::write(conf, n);
    }
}

fn ts(v: Option<&serde_json::Value>) -> serde_json::Value {
    match v.and_then(|x| x.as_i64()) {
        Some(t) => serde_json::Value::String(chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339()).unwrap_or_default()),
        None => serde_json::Value::Null,
    }
}

/// The FIM entries of a Wazuh agent (`fim_entry` in its wazuh-db database).
pub async fn agent_fim(agent_id: &str) -> Option<serde_json::Value> {
    agent_fim_upto(agent_id, 1000).await
}

/// The agent's FIM entries, the `max` most recently changed (`total`: all of them).
pub async fn agent_fim_upto(agent_id: &str, max: usize) -> Option<serde_json::Value> {
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    let total = agent_sql(&id, "SELECT count(*) AS n FROM fim_entry;").await?.first().and_then(|x| x.get("n")).and_then(|n| n.as_u64()).unwrap_or(0);
    let rows = crate::inventory_store::paged(&id, "SELECT full_path, file, type, date, changes, arch, value_name, size, uname, gname, md5, sha1, sha256, mtime FROM fim_entry ORDER BY date DESC", max).await;
    let entries: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|mut r| {
            let (d, m) = (ts(r.get("date")), ts(r.get("mtime")));
            r["date"] = d;
            r["mtime"] = m;
            // registry entries are keyed by a hash; `file` is the key path (and `value_name` the value)
            let path = match (r["file"].as_str().unwrap_or(""), r["value_name"].as_str().unwrap_or("")) {
                ("", _) => None,
                (f, "") => Some(f.to_string()),
                (f, v) => Some(format!("{f}\\{v}")),
            };
            if let Some(p) = path {
                r["key"] = r["full_path"].take();
                r["full_path"] = serde_json::Value::String(p);
            }
            r
        })
        .collect();
    Some(serde_json::json!({ "agent_id": agent_id, "total": total, "entries": entries, "source": "wazuh-db" }))
}

/// The latest SCA scan of a Wazuh agent (`sca_scan_info` / `sca_check` in its wazuh-db database).
pub async fn agent_sca(agent_id: &str) -> Option<serde_json::Value> {
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    let scan = agent_sql(&id, "SELECT policy_id, pass, fail, invalid, score, end_scan FROM sca_scan_info ORDER BY end_scan DESC LIMIT 1;").await?.into_iter().next()?;
    let policy = scan.get("policy_id")?.as_str()?.to_string();
    let q = policy.replace('\'', "''");
    let name = agent_sql(&id, &format!("SELECT name FROM sca_policy WHERE id = '{q}';")).await.and_then(|r| r.first().and_then(|x| x["name"].as_str().map(String::from)));
    let checks: Vec<serde_json::Value> = crate::inventory_store::paged(&id, &format!("SELECT id, title, result, reason FROM sca_check WHERE policy_id = '{q}' ORDER BY id"), 5000)
        .await
        .into_iter()
        .map(|r| {
            let status = match r["result"].as_str().unwrap_or("") {
                "passed" => "Passed",
                "failed" => "Failed",
                _ => "Not applicable",
            };
            serde_json::json!({ "check_id": r["id"], "title": r["title"], "status": status, "reason": r["reason"] })
        })
        .collect();
    Some(serde_json::json!({
        "agent_id": agent_id, "policy_id": policy, "policy_name": name, "score": scan["score"], "passed": scan["pass"], "failed": scan["fail"],
        "not_applicable": scan["invalid"], "scanned_at": ts(scan.get("end_scan")), "checks": checks, "source": "wazuh-db",
    }))
}

/// The rootcheck findings of a Wazuh agent (`pm_event` in its wazuh-db database).
pub async fn agent_rootcheck(agent_id: &str) -> Option<serde_json::Value> {
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    let rows = agent_sql(&id, "SELECT date_first, date_last, log, pci_dss, cis FROM pm_event ORDER BY date_last DESC LIMIT 1000;").await?;
    let events: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|mut r| {
            let (f, l) = (ts(r.get("date_first")), ts(r.get("date_last")));
            r["date_first"] = f;
            r["date_last"] = l;
            r
        })
        .collect();
    Some(serde_json::json!({ "agent_id": agent_id, "total": events.len(), "events": events, "source": "wazuh-db" }))
}

/// The inventory syscollector reported for an agent, from wazuh-db, in the
/// console's `AgentInventory` shape. None when the agent has no inventory.
pub async fn agent_inventory(agent_id: &str) -> Option<serde_json::Value> {
    if !enabled() {
        return None;
    }
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    let os = agent_sql(&id, "SELECT hostname, os_name, os_version, architecture FROM sys_osinfo LIMIT 1;").await?;
    let os = os.first()?.clone();
    let hw = agent_sql(&id, "SELECT cpu_cores, ram_total FROM sys_hwinfo LIMIT 1;").await.unwrap_or_default();
    let hw = hw.first().cloned().unwrap_or_default();
    let count = |t: &'static str| {
        let id = id.clone();
        async move {
            agent_sql(&id, &format!("SELECT count(*) AS n FROM {t};"))
                .await
                .and_then(|r| r.first().and_then(|x| x.get("n")).and_then(|n| n.as_u64()))
                .unwrap_or(0)
        }
    };
    let list = |sql: &'static str, f: fn(&serde_json::Value) -> String| {
        let id = id.clone();
        async move { agent_sql(&id, sql).await.unwrap_or_default().iter().map(f).filter(|x| !x.trim().is_empty()).collect::<Vec<String>>() }
    };
    let txt = |v: &serde_json::Value, k: &str| match v.get(k) {
        Some(serde_json::Value::String(x)) => x.clone(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(o) => o.to_string(),
    };
    let ports = list("SELECT protocol, local_ip, local_port, process FROM sys_ports WHERE state = 'listening' OR protocol LIKE 'udp%' ORDER BY local_port LIMIT 500;", |r| {
        let t = |k: &str| match r.get(k) {
            Some(serde_json::Value::String(x)) => x.clone(),
            Some(serde_json::Value::Null) | None => String::new(),
            Some(o) => o.to_string(),
        };
        format!("{}/{}:{} ({})", t("protocol"), t("local_ip"), t("local_port"), t("process").trim())
    })
    .await;
    let processes = list("SELECT DISTINCT name FROM sys_processes ORDER BY name LIMIT 500;", |r| r.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string()).await;
    let software = list("SELECT name, version FROM sys_programs ORDER BY name LIMIT 500;", |r| {
        let n = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let v = r.get("version").and_then(|v| v.as_str()).unwrap_or("").trim();
        if v.is_empty() { n.to_string() } else { format!("{n} {v}") }
    })
    .await;
    let services = list("SELECT service_id, service_state FROM sys_services WHERE service_state = 'RUNNING' ORDER BY service_id LIMIT 500;", |r| {
        r.get("service_id").and_then(|v| v.as_str()).unwrap_or("").to_string()
    })
    .await;
    let users = list("SELECT user_name FROM sys_users ORDER BY user_name LIMIT 500;", |r| r.get("user_name").and_then(|v| v.as_str()).unwrap_or("").to_string()).await;
    let adapters = list("SELECT iface, address FROM sys_netaddr ORDER BY iface LIMIT 500;", |r| {
        format!("{} {}", r.get("iface").and_then(|v| v.as_str()).unwrap_or(""), r.get("address").and_then(|v| v.as_str()).unwrap_or(""))
    })
    .await;
    let ram_kb = hw.get("ram_total").and_then(|v| v.as_u64()).unwrap_or(0);
    Some(serde_json::json!({
        "hostname": txt(&os, "hostname"),
        "os": format!("{} {}", txt(&os, "os_name"), txt(&os, "os_version")).trim().to_string(),
        "arch": txt(&os, "architecture"),
        "cpu_cores": hw.get("cpu_cores").and_then(|v| v.as_u64()).unwrap_or(0),
        "ram_mb": ram_kb / 1024,
        "running_processes_count": count("sys_processes").await,
        "open_ports_count": count("sys_ports").await,
        "installed_packages_count": count("sys_programs").await,
        "services_count": count("sys_services").await,
        "users_count": count("sys_users").await,
        "hotfixes_count": count("sys_hotfixes").await,
        "listening_ports": ports,
        "running_processes": processes,
        "installed_software": software,
        "active_services": services,
        "local_users": users,
        "network_adapters": adapters,
        "source": "wazuh-db",
    }))
}

/// Whether the manager runs and its `etc/client.keys` is gone.
pub fn keys_file_missing() -> bool {
    enabled() && home().join("etc").exists() && !keys_file(&home()).exists()
}

/// Writes the platform keystore to `etc/client.keys` (remoted reloads it).
pub fn save_keys(state: &AppState) {
    // the ClickHouse copy (agent_keys_store) follows
    crate::agent_keys_store::VERSION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if !enabled() {
        return;
    }
    let ks = state.auth_keystore.read().unwrap().clone();
    let path = keys_file(&home());
    let tmp = path.with_extension("keys.tmp");
    if let Err(e) = ks.save_file(&tmp).and_then(|_| std::fs::rename(&tmp, &path)) {
        warn!("Wazuh manager: cannot write {}: {e}", path.display());
    }
}

/// Starts the manager: home, keys, daemons, and the alert/event/status links.
pub fn start(state: AppState) {
    if !enabled() {
        info!("Wazuh manager disabled (WAZUH_MANAGER=0)");
        return;
    }
    let home = home();
    prepare_agent_dist();
    if let Err(e) = prepare_home(&home) {
        warn!("Wazuh manager not started: {e}");
        return;
    }
    // Keys of the file not in ClickHouse yet (older installs) join the
    // keystore; the file is then rewritten from it (ClickHouse is the master copy).
    if let Ok(ks) = siem_crypto::keys::KeyStore::load_file(keys_file(&home)) {
        let mut cur = state.auth_keystore.write().unwrap();
        for k in ks.keys {
            if cur.find_by_id(&k.id).is_none() {
                cur.add_key(k);
            }
        }
    }
    save_keys(&state);
    kill_stale(&home);
    if let Err(e) = install_binaries(&home) {
        warn!("Wazuh manager not started: {e}");
        return;
    }
    build_mitre_db(&home);
    info!("Wazuh manager home: {}", home.display());
    let h = home.clone();
    std::thread::spawn(move || {
        for d in DAEMONS {
            let (tx, rx) = std::sync::mpsc::channel();
            let hh = h.clone();
            std::thread::Builder::new().name(format!("supervise-{d}")).spawn(move || supervise(hh, d, tx)).ok();
            let _ = rx.recv_timeout(Duration::from_secs(60));
        }
    });

    let s = state.clone();
    let p = home.join("logs/alerts/alerts.json");
    let o = home.join("var/run/siem-api.alerts.offset");
    tokio::spawn(async move { tail_json(p, o, move |vs| on_alerts(s.clone(), vs)).await });
    let s = state.clone();
    let p = home.join("logs/archives/archives.json");
    let o = home.join("var/run/siem-api.archives.offset");
    tokio::spawn(async move { tail_json(p, o, move |vs| on_events(s.clone(), vs)).await });
    let s = state.clone();
    tokio::spawn(async move { agent_status_loop(s).await });
    // the stored SMTP settings win over the files (a fresh manager home gets them too)
    let s = state.clone();
    tokio::spawn(async move {
        if let Some(m) = crate::mail_settings::load(&s).await {
            apply_mail_settings(&m);
        }
    });
}

/// Follows a JSON-lines file from the saved offset (from the start when
/// the file was truncated or rotated).
async fn tail_json<F, Fut>(path: PathBuf, offset_file: PathBuf, mut f: F)
where
    F: FnMut(Vec<serde_json::Value>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut offset: u64 = std::fs::read_to_string(&offset_file).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let mut partial: Vec<u8> = Vec::new();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let Ok(mut file) = std::fs::File::open(&path) else { continue };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len < offset {
            offset = 0;
            partial.clear();
        }
        if len == offset {
            continue;
        }
        if file.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let mut buf = Vec::new();
        if file.by_ref().take(8 * 1024 * 1024).read_to_end(&mut buf).is_err() {
            continue;
        }
        offset += buf.len() as u64;
        partial.extend_from_slice(&buf);
        let mut start = 0;
        let mut batch = Vec::new();
        while let Some(nl) = partial[start..].iter().position(|&b| b == b'\n') {
            let line = &partial[start..start + nl];
            start += nl + 1;
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) {
                batch.push(v);
            }
        }
        partial.drain(..start);
        if !batch.is_empty() {
            f(batch).await;
        }
        let _ = std::fs::write(&offset_file, (offset - partial.len() as u64).to_string());
    }
}

fn s(v: &serde_json::Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(n) => cur = n,
            None => return String::new(),
        }
    }
    match cur {
        serde_json::Value::String(x) => x.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn timestamp(v: &serde_json::Value) -> chrono::DateTime<Utc> {
    let t = s(v, &["timestamp"]);
    chrono::DateTime::parse_from_str(&t, "%Y-%m-%dT%H:%M:%S%.f%z").map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now())
}

fn tenant_of(state: &AppState, agent_id: &str) -> String {
    tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id)
}

fn flat(data: &serde_json::Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(o) = data.as_object() {
        for (k, v) in o {
            out.insert(
                k.clone(),
                match v {
                    serde_json::Value::String(x) => x.clone(),
                    other => other.to_string(),
                },
            );
        }
    }
    out
}

/// One `alerts.json` line as a platform alert of the agent's tenant.
/// The user of a Windows event: the account logged on / failed / changed, else who acted
/// ("-" is Windows for none; Wazuh doubles the backslash of DOMAIN\user).
fn windows_user(v: &serde_json::Value) -> Option<String> {
    ["targetUserName", "subjectUserName"].iter().find_map(|k| {
        v.pointer(&format!("/data/win/eventdata/{k}")).and_then(|x| x.as_str()).map(|u| u.replace("\\\\", "\\")).filter(|u| !u.is_empty() && u != "-")
    })
}

fn to_alert(state: &AppState, v: &serde_json::Value) -> Alert {
    let data = v.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let first = |path: &[&str]| -> String {
        let mut cur = v;
        for p in path {
            match cur.get(p) {
                Some(n) => cur = n,
                None => return String::new(),
            }
        }
        cur.as_array().and_then(|a| a.first()).and_then(|x| x.as_str()).unwrap_or_default().to_string()
    };
    let mitre_id = first(&["rule", "mitre", "id"]);
    let mitre = (!mitre_id.is_empty()).then(|| MitreAttack {
        id: mitre_id,
        tactic: first(&["rule", "mitre", "tactic"]),
        technique: first(&["rule", "mitre", "technique"]),
    });
    let agent_id = s(v, &["agent", "id"]);
    let mut agent_ip = s(v, &["agent", "ip"]);
    if agent_ip.is_empty() {
        agent_ip = state.agents.read().unwrap().get(&agent_id).map(|a| a.ip.clone()).unwrap_or_else(|| "any".into());
    }
    let sport = |k: &str| s(&data, &[k]).parse::<u16>().ok();
    let opt = |k: &str| Some(s(&data, &[k])).filter(|x| !x.is_empty());
    let mut alert_data: HashMap<String, serde_json::Value> = data.as_object().map(|o| o.clone().into_iter().collect()).unwrap_or_default();
    alert_data.insert("wazuh_alert_id".into(), serde_json::Value::String(s(v, &["id"])));
    if let Some(r) = v.get("rule") {
        alert_data.insert("wazuh_rule".into(), r.clone());
    }
    // FIM details (path, hashes, diff, mode, whodata user/process) for the FIM views
    if let Some(sc) = v.get("syscheck") {
        alert_data.insert("syscheck".into(), sc.clone());
    }
    Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: timestamp(v),
        rule: RuleAlertInfo {
            id: s(v, &["rule", "id"]).parse().unwrap_or(0),
            level: v.pointer("/rule/level").and_then(|x| x.as_u64()).unwrap_or(0).min(15) as u8,
            description: s(v, &["rule", "description"]),
            groups: v
                .pointer("/rule/groups")
                .and_then(|g| g.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            mitre,
        },
        agent: AgentAlertInfo { id: agent_id, name: s(v, &["agent", "name"]), ip: agent_ip },
        manager: Some(ManagerAlertInfo { name: s(v, &["manager", "name"]) }),
        decoder: Some(DecoderAlertInfo { name: s(v, &["decoder", "name"]) }),
        full_log: s(v, &["full_log"]),
        decoded: DecodedFields {
            decoder_name: s(v, &["decoder", "name"]),
            src_ip: opt("srcip"),
            dst_ip: opt("dstip"),
            src_port: sport("srcport"),
            dst_port: sport("dstport"),
            user: opt("dstuser").or_else(|| opt("srcuser")).or_else(|| windows_user(v)),
            program_name: Some(s(v, &["predecoder", "program_name"])).filter(|x| !x.is_empty()),
            process_id: None,
            file_path: Some(s(v, &["syscheck", "path"])).filter(|x| !x.is_empty()),
            action: opt("action"),
            status: opt("status"),
            extra: flat(&data),
        },
        location: s(v, &["location"]),
        data: alert_data,
    }
}

async fn on_alerts(state: AppState, vs: Vec<serde_json::Value>) {
    let alerts: Vec<Alert> = vs
        .iter()
        .map(|v| {
            let alert = to_alert(&state, v);
            let tenant = tenant_of(&state, &alert.agent.id);
            tenancy::tag_alert(alert, &tenant)
        })
        .collect();
    deliver(&state, alerts, vs).await;
}

/// Stores tenant-tagged alerts, then shows them and runs SOAR on them unless suppressed;
/// `soar_json[i]` is what SOAR sees for `alerts[i]` (the original Wazuh alert).
pub async fn deliver(state: &AppState, alerts: Vec<Alert>, soar_json: Vec<serde_json::Value>) {
    // one INSERT per tenant; the file offset moves on only once ClickHouse has every row
    let mut pending: Vec<&Alert> = alerts.iter().collect();
    let mut wait = RETRY_MIN;
    loop {
        let batch: Vec<Alert> = pending.iter().map(|a| (*a).clone()).collect();
        let failed = state.db.insert_alerts(&batch).await;
        if failed.is_empty() {
            break;
        }
        pending.retain(|a| {
            let tenant = a.data.get("tenant_id").and_then(|v| v.as_str()).unwrap_or(tenancy::DEFAULT_TENANT);
            failed.iter().any(|t| t == tenant)
        });
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
    // stored above either way; a suppressed alert is not shown live, kept, or acted on
    let tenants: Vec<String> = alerts.iter().map(|a| a.data.get("tenant_id").and_then(|v| v.as_str()).unwrap_or(tenancy::DEFAULT_TENANT).to_string()).collect();
    let mut shown = Vec::with_capacity(alerts.len());
    let mut soar = Vec::with_capacity(alerts.len());
    for ((a, v), t) in alerts.into_iter().zip(soar_json).zip(tenants) {
        if crate::suppressions::is_suppressed(state, &t, &a).await {
            continue;
        }
        let _ = state.broadcast_tx.send(a.clone());
        shown.push(a);
        soar.push((v, t));
    }
    // each tenant's SOAR playbooks, on the original Wazuh alert
    crate::soar::on_alerts(state, soar);
    crate::keep_alerts(state, shown);
}

/// Backoff of the ClickHouse retries (the alerts/archives files hold the data meanwhile).
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

fn event_source(location: &str, decoder: &str) -> EventSource {
    match (location, decoder) {
        ("EventChannel", _) | (_, "windows_eventchannel") => EventSource::WindowsEvent,
        ("syscheck", _) | (_, "syscheck_integrity_changed") | (_, "syscheck_new_entry") | (_, "syscheck_deleted") => EventSource::Fim,
        ("syscollector", _) => EventSource::Syscollector,
        ("sca", _) => EventSource::Sca,
        ("active-response", _) | (_, "ar_log_json") => EventSource::ActiveResponse,
        (_, d) if d.starts_with("sshd") || d == "pam" || d == "sudo" || d == "su" => EventSource::Auth,
        _ => EventSource::Syslog,
    }
}

/// One `archives.json` line (every event analysisd received) as a platform event.
async fn on_events(state: AppState, vs: Vec<serde_json::Value>) {
    let events: Vec<RawEvent> = vs.iter().map(|v| to_event(&state, v)).collect();
    // retry the tenants that failed until ClickHouse has them; the offset is saved after
    let mut pending: Vec<&RawEvent> = events.iter().collect();
    let mut wait = RETRY_MIN;
    loop {
        let batch: Vec<RawEvent> = pending.iter().map(|e| (*e).clone()).collect();
        let failed = state.db.insert_events(&batch).await;
        if failed.is_empty() {
            break;
        }
        pending.retain(|e| {
            let tenant = e.metadata.get("tenant_id").map(String::as_str).unwrap_or(tenancy::DEFAULT_TENANT);
            failed.iter().any(|t| t == tenant)
        });
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
    // Sigma rules (sigma.rs) and file reputation (file_reputation.rs) on every archived event,
    // besides the Wazuh ruleset
    let tagged: Vec<(serde_json::Value, String)> = vs.into_iter().zip(events.iter().map(|e| e.metadata.get("tenant_id").cloned().unwrap_or_else(|| tenancy::DEFAULT_TENANT.to_string()))).collect();
    let (matched, scans) = tokio::task::spawn_blocking(move || {
        let mut m = crate::sigma::check(&tagged);
        m.extend(crate::file_reputation::check(&tagged));
        let (yara_alerts, scans) = crate::yara_edr::check(&tagged);
        m.extend(yara_alerts);
        (m, scans)
    })
    .await
    .unwrap_or_default();
    for (_, agent, path) in scans {
        if let Err(e) = yara_scan(&agent, &path).await {
            warn!("YARA scan of {path} on agent {agent}: {e}");
        }
    }
    if !matched.is_empty() {
        let (alerts, json): (Vec<Alert>, Vec<serde_json::Value>) = matched
            .into_iter()
            .map(|(a, t)| {
                let a = tenancy::tag_alert(a, &t);
                let j = serde_json::to_value(&a).unwrap_or_default();
                (a, j)
            })
            .unzip();
        deliver(&state, alerts, json).await;
    }
    // the in-memory copy is a recent window; ClickHouse keeps everything
    crate::keep_events(&state, events);
}

fn to_event(state: &AppState, v: &serde_json::Value) -> RawEvent {
    let v = v.clone();
    let agent_id = s(&v, &["agent", "id"]);
    let tenant = tenant_of(state, &agent_id);
    let location = s(&v, &["location"]);
    let decoder = s(&v, &["decoder", "name"]);
    let mut metadata: HashMap<String, String> = HashMap::new();
    metadata.insert("tenant_id".into(), tenant);
    metadata.insert("hostname".into(), s(&v, &["agent", "name"]));
    metadata.insert("decoder".into(), decoder.clone());
    metadata.insert("pipeline".into(), "wazuh-manager".into());
    if let Some(d) = v.get("data") {
        metadata.insert("data_json".into(), d.to_string());
    }
    let rule = s(&v, &["rule", "id"]);
    if !rule.is_empty() {
        metadata.insert("rule_id".into(), rule);
        metadata.insert("rule_level".into(), s(&v, &["rule", "level"]));
    }
    let ip = s(&v, &["agent", "ip"]);
    if !ip.is_empty() {
        metadata.insert("ip".into(), ip);
    }
    RawEvent {
        id: uuid::Uuid::new_v4(),
        timestamp: timestamp(&v),
        agent_id,
        source: event_source(&location, &decoder),
        location,
        message: s(&v, &["full_log"]),
        metadata,
    }
}

/// Agent status, OS, version and keepalive from wazuh-db's global.db.
async fn agent_status_loop(state: AppState) {
    let wdb = wdb();
    let mut last_saved: HashMap<String, (AgentStatus, i64)> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let q ="global sql SELECT id, name, ip, register_ip, os_name, os_version, os_platform, version, last_keepalive, connection_status FROM agent WHERE id > 0;";
        let Ok(resp) = wdb.query(q).await else { continue };
        let Some(json) = resp.strip_prefix("ok ") else { continue };
        let Ok(serde_json::Value::Array(rows)) = serde_json::from_str::<serde_json::Value>(json) else { continue };
        for r in rows {
            let id = format!("{:03}", r.get("id").and_then(|x| x.as_i64()).unwrap_or(0));
            let ka = r.get("last_keepalive").and_then(|x| x.as_i64()).unwrap_or(0);
            let status = match s(&r, &["connection_status"]).as_str() {
                "active" => AgentStatus::Active,
                "pending" => AgentStatus::Pending,
                "never_connected" => AgentStatus::Pending,
                _ => AgentStatus::Disconnected,
            };
            if ka == 0 && status == AgentStatus::Pending {
                continue;
            }
            let os = [s(&r, &["os_name"]), s(&r, &["os_version"])].join(" ").trim().to_string();
            let platform = s(&r, &["os_platform"]);
            let os_type = match platform.as_str() {
                "windows" => "windows",
                "darwin" => "macos",
                "" => "",
                _ => "linux",
            };
            let ip = Some(s(&r, &["ip"])).filter(|x| !x.is_empty()).unwrap_or_else(|| s(&r, &["register_ip"]));
            let last_keepalive = chrono::DateTime::from_timestamp(ka, 0).unwrap_or_else(Utc::now);
            let agent = {
                let mut agents = state.agents.write().unwrap();
                let a = agents.entry(id.clone()).or_insert_with(|| Agent {
                    id: id.clone(),
                    name: s(&r, &["name"]),
                    ip: ip.clone(),
                    os: os.clone(),
                    version: s(&r, &["version"]),
                    status: status.clone(),
                    last_keepalive,
                    os_type: os_type.to_string(),
                });
                if !os.is_empty() {
                    a.os = os.clone();
                }
                if !os_type.is_empty() {
                    a.os_type = os_type.to_string();
                }
                let ver = s(&r, &["version"]);
                if !ver.is_empty() {
                    a.version = ver;
                }
                if !ip.is_empty() && ip != "any" {
                    a.ip = ip.clone();
                }
                a.status = status.clone();
                a.last_keepalive = last_keepalive;
                a.clone()
            };
            let changed = last_saved.get(&id).map(|(st, k)| *st != status || *k != ka).unwrap_or(true);
            if changed {
                let tenant = tenant_of(&state, &id);
                state.db.insert_or_update_agent(&tenant, &agent).await;
                last_saved.insert(id, (status, ka));
            }
        }
    }
}

#[cfg(test)]
mod windows_user_tests {
    use super::windows_user;
    use serde_json::json;

    #[test]
    fn windows_events_give_their_user() {
        let ev = |ed: serde_json::Value| json!({ "data": { "win": { "eventdata": ed } } });
        assert_eq!(windows_user(&ev(json!({ "targetUserName": "alice", "subjectUserName": "SYSTEM" }))).as_deref(), Some("alice"));
        // 4625 at the lock screen: no target name, the subject acted
        assert_eq!(windows_user(&ev(json!({ "targetUserName": "", "subjectUserName": "EVOFOX$" }))).as_deref(), Some("EVOFOX$"));
        assert_eq!(windows_user(&ev(json!({ "targetUserName": "LAB\\\\bob" }))).as_deref(), Some("LAB\\bob"));
        assert_eq!(windows_user(&ev(json!({ "targetUserName": "-", "subjectUserName": "-" }))), None);
        assert_eq!(windows_user(&json!({ "data": { "srcip": "1.2.3.4" } })), None);
    }
}

#[cfg(test)]
mod mail_conf_tests {
    use super::ossec_conf_with_mail;
    use crate::mail_settings::MailSettings;

    #[test]
    fn edits_global_and_alerts() {
        let t = "<ossec_config>\n<global>\n<jsonout_output>yes</jsonout_output>\n<email_notification>no</email_notification>\n<email_to>old@x.com</email_to>\n</global>\n<alerts>\n<log_alert_level>3</log_alert_level>\n</alerts>\n</ossec_config>\n";
        let s = MailSettings { host: "smtp.gmail.com".into(), user: "a@gmail.com".into(), alert_enabled: true, alert_to: vec!["soc@x.com".into(), "b@x.com".into()], alert_level: 10, ..Default::default() };
        let n = ossec_conf_with_mail(t, &s);
        assert_eq!(
            n,
            "<ossec_config>\n<global>\n<jsonout_output>yes</jsonout_output>\n<email_notification>yes</email_notification>\n<smtp_server>smtp.gmail.com</smtp_server>\n<email_from>a@gmail.com</email_from>\n<email_to>soc@x.com</email_to>\n<email_to>b@x.com</email_to>\n<email_maxperhour>12</email_maxperhour>\n</global>\n<alerts>\n<log_alert_level>3</log_alert_level>\n<email_alert_level>10</email_alert_level>\n</alerts>\n</ossec_config>\n"
        );
        // applying again changes nothing
        assert_eq!(ossec_conf_with_mail(&n, &s), n);
    }
}
