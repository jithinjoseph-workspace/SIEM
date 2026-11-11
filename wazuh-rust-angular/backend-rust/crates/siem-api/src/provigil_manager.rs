//! The ProVigil manager behind the SIEM: siem-api prepares a manager home
//! (`data/manager`, laid out like `/var/ossec`), runs the ported daemons
//! (`provigil-db`, `provigil-analysisd`, `provigil-modulesd`) as child processes and
//! links them to the platform:
//!
//! * enrollment stores the agent's key (ClickHouse; the gateway and modulesd read it);
//! * `logs/alerts/alerts.json` becomes platform alerts and
//!   `logs/archives/archives.json` platform events, per agent tenant;
//! * agent status, OS and version come from provigil-db's global database.
//!
//! Agents connect to `provigil-gateway`; the old protocol's port (1514) is retired.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use chrono::Utc;
use siem_core::{
    Agent, AgentAlertInfo, AgentStatus, Alert, DecodedFields, DecoderAlertInfo, EventSource,
    ManagerAlertInfo, MitreAttack, RawEvent, RuleAlertInfo,
};
use siem_ipc::wdbc::WdbQuery;
use tracing::{info, warn};

use crate::agent_commands::{self, table, table::CommandRow};
use crate::{tenancy, AppState};

/// The daemons, in start order.
#[cfg(not(unix))]
// agents connect to provigil-gateway: the old channel (port 1514) is retired
const DAEMONS: [&str; 3] = [
    "provigil-db",
    "provigil-analysisd",
    "provigil-modulesd",
];
/// On Linux the manager also runs execd for responses with `<location>` local/server,
/// and agentlessd (its expect scripts need a Unix shell).
#[cfg(unix)]
const DAEMONS: [&str; 5] = [
    "provigil-db",
    "provigil-analysisd",
    "provigil-modulesd",
    "provigil-execd",
    "provigil-agentlessd",
];
/// The manager's own response programs (Linux).
#[cfg(unix)]
const MANAGER_AR: [&str; 1] = ["firewall-drop"];
#[cfg(not(unix))]
const MANAGER_AR: [&str; 0] = [];
/// The integration scripts (now handled in-process in siem-api soar_integrations).
const INTEGRATIONS: [&str; 0] = [];

/// Where the manager lives (`WAZUH_MANAGER_HOME`, else `data/manager`).
pub fn home() -> PathBuf {
    let p = match std::env::var("PROVIGIL_MANAGER_HOME")
        .or_else(|_| std::env::var("WAZUH_MANAGER_HOME"))
    {
        Ok(h) if !h.trim().is_empty() => PathBuf::from(h),
        _ => crate::data_file_path("manager"),
    };
    std::path::absolute(&p).unwrap_or(p)
}

/// Whether siem-api runs the manager (`WAZUH_MANAGER=0` turns it off).
pub fn enabled() -> bool {
    !matches!(
        std::env::var("PROVIGIL_MANAGER")
            .or_else(|_| std::env::var("WAZUH_MANAGER"))
            .as_deref(),
        Ok("0") | Ok("false") | Ok("no")
    )
}

fn keys_file(home: &Path) -> PathBuf {
    home.join("etc").join("client.keys")
}

/// The upstream 4.14.7 source tree the ruleset is copied from.
fn provigil_source() -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(s) =
        std::env::var("PROVIGIL_SOURCE_DIR").or_else(|_| std::env::var("WAZUH_SOURCE_DIR"))
    {
        cands.push(PathBuf::from(s));
    }
    for rel in [
        "../../wazuh/wazuh-4.14.7",
        "../wazuh/wazuh-4.14.7",
        "wazuh/wazuh-4.14.7",
        "../../../wazuh/wazuh-4.14.7",
    ] {
        cands.push(PathBuf::from(rel));
    }
    cands.into_iter().find(|p| {
        p.join("ruleset").join("rules").is_dir()
            && p.join("etc").join("internal_options.conf").is_file()
    })
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
        "bin",
        "etc/decoders",
        "etc/rules",
        "etc/lists",
        "etc/shared/default",
        "ruleset",
        "logs/alerts",
        "logs/archives",
        "logs/firewall",
        "queue/sockets",
        "queue/db",
        "queue/alerts",
        "queue/rids",
        "queue/diff",
        "queue/agentless",
        "queue/fts",
        "queue/tasks",
        "var/run",
        "var/db",
        "var/multigroups",
        "var/download",
        "stats",
        "backup/db",
        "tmp",
    ] {
        std::fs::create_dir_all(home.join(d)).map_err(|e| format!("{d}: {e}"))?;
    }
    let src = provigil_source()
        .ok_or("Upstream 4.14.7 source tree not found (set PROVIGIL_SOURCE_DIR)")?;
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
    for l in [
        "audit-keys",
        "amazon",
        "security-eventchannel",
        "malicious-ioc",
    ] {
        once(
            src.join("ruleset").join("lists").join(l),
            &format!("etc/lists/{l}"),
        )?;
    }
    once(
        src.join("etc").join("internal_options.conf"),
        "etc/internal_options.conf",
    )?;
    install_agentless_scripts(&src, home)?;
    once(
        src.join("etc").join("local_decoder.xml"),
        "etc/decoders/local_decoder.xml",
    )?;
    once(
        src.join("etc").join("local_rules.xml"),
        "etc/rules/local_rules.xml",
    )?;
    let lio = home.join("etc").join("local_internal_options.conf");
    if !lio.exists() {
        let _ = std::fs::write(&lio, "# Local internal options\n");
    }
    let agent_conf = home
        .join("etc")
        .join("shared")
        .join("default")
        .join("agent.conf");
    if !agent_conf.exists() {
        let _ = std::fs::write(&agent_conf, "<agent_config>\n\n</agent_config>\n");
    }
    let conf = home.join("etc").join("ossec.conf");
    if !conf.exists() {
        std::fs::write(&conf, ossec_conf()).map_err(|e| format!("ossec.conf: {e}"))?;
    }
    ensure_ar_commands(&conf);
    if !platform_keys() && !keys_file(home).exists() {
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
    for f in std::fs::read_dir(&from)
        .map_err(|e| format!("{}: {e}", from.display()))?
        .flatten()
    {
        let dst = to.join(f.file_name());
        let _ = std::fs::remove_file(&dst); // the previous copy is read-only
        std::fs::copy(f.path(), &dst)
            .map_err(|e| format!("agentless/{}: {e}", f.file_name().to_string_lossy()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o550));
        }
    }
    Ok(())
}

pub use provigil_agent_server::published::{exe_version, WINDOWS_AGENT_FILES};

fn agent_dist_dir() -> PathBuf {
    crate::data_file_path("agent-dist").join("windows")
}

/// Where the build puts the package's programs (a Windows build, or the cross-build).
const BUILD_OUTPUTS: [&str; 6] = [
    "target/x86_64-pc-windows-gnu/release",
    "target/release",
    "backend-rust/target/release",
    "backend-rust/target/x86_64-pc-windows-gnu/release",
    "target/debug",
    "backend-rust/target/debug",
];

fn modified(p: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p)
        .ok()
        .filter(|m| m.is_file())
        .and_then(|m| m.modified().ok())
}

/// The newest of `cands` that exists.
fn newest(cands: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    cands
        .into_iter()
        .filter_map(|p| modified(&p).map(|t| (t, p)))
        .max_by_key(|(t, _)| *t)
        .map(|(_, p)| p)
}

/// Fills `data/agent-dist/windows`: the package's programs from the build output when
/// it is newer (so the folder alone is a complete package to ship to a server without
/// the build). The agent's configuration policies are compiled into `provigil-agent.exe`.
fn prepare_agent_dist() {
    let dir = agent_dist_dir();
    let _ = std::fs::create_dir_all(&dir);
    for f in WINDOWS_AGENT_FILES.iter().filter(|f| f.ends_with(".exe")) {
        let dst = dir.join(f);
        let Some(built) = newest(BUILD_OUTPUTS.iter().map(|o| PathBuf::from(o).join(f))) else {
            continue;
        };
        if modified(&built) > modified(&dst) {
            match std::fs::copy(&built, &dst) {
                Ok(_) => info!("Agent package: {f} updated from {}", built.display()),
                Err(e) => warn!(
                    "Agent package: {f} not copied from {}: {e}",
                    built.display()
                ),
            }
        }
    }
}

/// A file of the Windows agent package: `data/agent-dist/windows/<name>`, or for a program the
/// build output when it is newer (a rebuild while siem-api runs).
pub fn windows_agent_file(name: &str) -> Option<PathBuf> {
    provigil_agent_server::published::windows_agent_file(&crate::data_file_path("agent-dist"), name)
}

type Hashed = (std::time::SystemTime, u64, String);

/// SHA-256 of a file; hashed again only when its time or size changes.
fn cached_sha256(path: &std::path::Path, cache: &mut std::collections::HashMap<PathBuf, Hashed>) -> Option<String> {
    use sha2::Digest;
    let meta = std::fs::metadata(path).ok()?;
    let (time, len) = (meta.modified().ok()?, meta.len());
    if let Some((t, l, hash)) = cache.get(path) {
        if (*t, *l) == (time, len) {
            return Some(hash.clone());
        }
    }
    let mut sha = sha2::Sha256::new();
    std::io::copy(&mut std::fs::File::open(path).ok()?, &mut sha).ok()?;
    let hash: String = sha.finalize().iter().map(|b| format!("{b:02x}")).collect();
    cache.insert(path.to_path_buf(), (time, len, hash.clone()));
    Some(hash)
}

/// `{name: sha256}` of the published Windows agent files (`/api/server-info`; the install
/// script checks each download against it). Blocking: the first call hashes the package.
pub fn agent_files() -> std::collections::BTreeMap<String, String> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<PathBuf, Hashed>>> = std::sync::OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    WINDOWS_AGENT_FILES
        .iter()
        .filter_map(|name| Some((name.to_string(), cached_sha256(&windows_agent_file(name)?, &mut cache)?)))
        .collect()
}

/// The Windows agent's `ossec.conf`: the MSI's default (`src/win32/ossec.conf`)
/// with the manager address (`WAZUH_MANAGER`) set. The key comes from the
/// enrollment API, so the agent does not enroll on 1515 itself.
pub fn windows_agent_conf(manager: &str) -> Option<String> {
    let manager = manager.trim_start_matches('[').trim_end_matches(']');
    // "localhost" resolves to ::1 first on Windows, and remoted listens on IPv4 (0.0.0.0)
    let manager = if manager.eq_ignore_ascii_case("localhost") || manager == "::1" {
        "127.0.0.1"
    } else {
        manager
    };
    let ok = !manager.is_empty()
        && manager
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'));
    if !ok {
        return None;
    }
    let src = provigil_source()?;
    let t = std::fs::read_to_string(src.join("src/win32/ossec.conf")).ok()?;
    let t = t.replace(
        "<address>0.0.0.0</address>",
        &format!("<address>{manager}</address>"),
    );
    let t = t.replacen(
        "<crypto_method>aes</crypto_method>",
        "<crypto_method>aes</crypto_method>\r\n    <enrollment>\r\n      <enabled>no</enabled>\r\n    </enrollment>",
        1,
    );
    Some(t)
}

/// The program file of a daemon or tool.
pub(crate) fn exe_name(d: &str) -> String {
    if cfg!(windows) {
        format!("{d}.exe")
    } else {
        d.to_string()
    }
}

/// Copies the daemons built next to siem-api into `<home>/bin` (provigil-db
/// finds its home from there, like an installed manager).
/// Command-line tools of the manager (installed in `bin/`, not supervised).
const MANAGER_TOOLS: &[&str] = &[];

fn install_binaries(home: &Path) -> Result<(), String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = me.parent().ok_or("no exe dir")?;
    let mut search = vec![dir.to_path_buf()];
    if let Some(t) = dir.parent() {
        search.push(t.join("release"));
        search.push(t.join("debug"));
    }
    let targets = DAEMONS
        .iter()
        .map(|d| (exe_name(d), home.join("bin").join(exe_name(d))))
        .chain(INTEGRATIONS.iter().map(|i| {
            (
                exe_name("integrations"),
                home.join("integrations").join(exe_name(i)),
            )
        }))
        .chain(MANAGER_AR.iter().map(|a| {
            (
                exe_name(a),
                home.join("active-response/bin").join(exe_name(a)),
            )
        }))
        .chain(
            MANAGER_TOOLS
                .iter()
                .map(|t| (exe_name(t), home.join("bin").join(exe_name(t)))),
        );
    for (n, dst) in targets {
        let found = search
            .iter()
            .map(|s| s.join(&n))
            .filter(|p| p.is_file())
            .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok());
        let Some(src) = found else {
            return Err(format!("{n} not built (cargo build --release -p siem-wdb -p siem-analysisd -p siem-remoted -p siem-modulesd -p siem-execd -p siem-agentlessd -p siem-active-response)"));
        };
        let newer = match (
            src.metadata().and_then(|m| m.modified()),
            dst.metadata().and_then(|m| m.modified()),
        ) {
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
/// once from the ruleset's `enterprise-attack.json` with `provigil-mitredb`.
fn build_mitre_db(home: &Path) {
    let db = home.join("var/db/mitre.db");
    if db.exists() {
        return;
    }
    let Some(src) = provigil_source() else { return };
    let json = src.join("ruleset/mitre/enterprise-attack.json");
    let Some(tool) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(exe_name("provigil-mitredb"))))
        .filter(|p| p.is_file())
    else {
        warn!("ProVigil manager: provigil-mitredb not built (cargo build --release -p siem-wdb); alerts have no MITRE data");
        return;
    };
    // built under another name: a half-built file must not look finished
    let tmp = db.with_extension("db.tmp");
    let _ = std::fs::remove_file(&tmp);
    match Command::new(tool)
        .arg("-d")
        .arg(&tmp)
        .arg("-j")
        .arg(&json)
        .stdout(Stdio::null())
        .status()
    {
        Ok(s) if s.success() && std::fs::rename(&tmp, &db).is_ok() => {
            info!("ProVigil manager: built {}", db.display())
        }
        other => warn!("ProVigil manager: building mitre.db failed: {other:?}"),
    }
}

/// The children of an earlier siem-api run that were left behind.
fn kill_stale(home: &Path) {
    let f = home.join("var/run/siem-api-children.pids");
    if let Ok(s) = std::fs::read_to_string(&f) {
        for pid in s.split_whitespace().filter_map(|p| p.parse::<u32>().ok()) {
            // after a reboot the pid may belong to another program: only the manager's
            // programs (their names before and after the ProVigil rename)
            #[cfg(windows)]
            for image in ["provigil-*", "wazuh-*"] {
                let _ = Command::new("taskkill")
                    .args([
                        "/F",
                        "/PID",
                        &pid.to_string(),
                        "/FI",
                        &format!("IMAGENAME eq {image}"),
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            // after a reboot the pid may belong to another program
            #[cfg(unix)]
            if std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|c| c.starts_with("wazuh-") || c.starts_with("provigil-"))
            {
                let _ = Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
    let _ = std::fs::remove_file(f);
    // the daemons' pid files (`<daemon>-<pid>.pid`): none of them runs now, so every one is
    // left over (a daemon stopped by force does not remove its own)
    let run = home.join("var/run");
    let mut n = 0;
    for e in std::fs::read_dir(&run).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".pid") && name.contains('-') && std::fs::remove_file(e.path()).is_ok() {
            n += 1;
        }
    }
    if n > 0 {
        info!(
            "ProVigil manager: {n} stale pid file(s) removed from {}",
            run.display()
        );
    }
}

static CHILDREN: Mutex<Vec<(String, u32)>> = Mutex::new(Vec::new());

/// `key='value'` lines of a daemon state file (`var/run/<daemon>.state`); numbers as numbers.
fn read_state_file(path: &Path) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for line in std::fs::read_to_string(path).unwrap_or_default().lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if line.starts_with('#') {
            continue;
        }
        let v = v.trim().trim_matches('\'');
        let val = v
            .parse::<f64>()
            .map(serde_json::Value::from)
            .unwrap_or_else(|_| serde_json::Value::String(v.to_string()));
        m.insert(k.trim().to_string(), val);
    }
    serde_json::Value::Object(m)
}

/// A daemon's counter file; for one release the file of its old name when the new one is missing.
fn counter_file(run: &Path, daemon: &str) -> PathBuf {
    let new = run.join(format!("provigil-{daemon}.state"));
    if new.exists() {
        new
    } else {
        run.join(format!("wazuh-{daemon}.state"))
    }
}

/// What the manager is doing: running daemons and the remoted / analysisd counters
/// (queues, events received, discarded and dropped).
/// The daemons siem-api starts and keeps running.
pub fn daemons() -> &'static [&'static str] {
    &DAEMONS
}

/// The daemons running now.
pub fn running() -> Vec<String> {
    CHILDREN
        .lock()
        .unwrap()
        .iter()
        .map(|(n, _)| n.clone())
        .collect()
}

pub fn status() -> serde_json::Value {
    let run = home().join("var/run");
    let daemons: Vec<serde_json::Value> = CHILDREN
        .lock()
        .unwrap()
        .iter()
        .map(|(n, p)| serde_json::json!({ "name": n, "pid": p }))
        .collect();
    serde_json::json!({
        "enabled": enabled(),
        "daemons": daemons,
        "remoted": read_state_file(&counter_file(&run, "remoted")),
        "analysisd": read_state_file(&counter_file(&run, "analysisd")),
    })
}

fn record_children(home: &Path) {
    let pids: Vec<String> = CHILDREN
        .lock()
        .unwrap()
        .iter()
        .map(|(_, p)| p.to_string())
        .collect();
    let _ = std::fs::write(home.join("var/run/siem-api-children.pids"), pids.join(" "));
}

/// The socket a daemon binds once it is ready.
fn ready_marker(home: &Path, d: &str) -> Option<PathBuf> {
    let suffix = if cfg!(unix) { "" } else { ".port" };
    match d {
        "provigil-db" => Some(home.join(format!("queue/db/wdb{suffix}"))),
        "provigil-analysisd" => Some(home.join(format!("queue/sockets/queue{suffix}"))),
        _ => None,
    }
}

fn spawn(home: &Path, d: &str) -> std::io::Result<Child> {
    let mut c = Command::new(home.join("bin").join(exe_name(d)));
    c.current_dir(home);
    match d {
        "provigil-db" | "provigil-modulesd" | "provigil-integratord" | "provigil-csyslogd" => c.arg("-f"),
        _ => c.arg("-f").arg("-D").arg(home),
    };
    if matches!(d, "provigil-remoted" | "provigil-modulesd") {
        if let Some((addr, token)) = KEYS_SERVICE.get() {
            c.env("SIEM_KEYS_ADDR", addr).env("SIEM_KEYS_TOKEN", token);
        }
    }
    // analysisd streams alerts and events, the scanner in modulesd its results
    if matches!(d, "provigil-analysisd" | "provigil-modulesd") {
        if let Some((addr, token)) = STREAM.get() {
            c.env("SIEM_STREAM_ADDR", addr)
                .env("SIEM_STREAM_TOKEN", token);
        }
    }
    let log = |n: &str| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(home.join("logs").join(n))
    };
    c.stdin(Stdio::null());
    c.stdout(
        log(&format!("{d}.out"))
            .map(Stdio::from)
            .unwrap_or(Stdio::null()),
    );
    c.stderr(
        log(&format!("{d}.out"))
            .map(Stdio::from)
            .unwrap_or(Stdio::null()),
    );
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
                info!("ProVigil manager: {d} started (pid {pid})");
                if let Some(tx) = first.take() {
                    // The next daemon starts once this one listens.
                    if let Some(m) = ready_marker(&home, d) {
                        for _ in 0..300 {
                            if m.metadata()
                                .and_then(|x| x.modified())
                                .is_ok_and(|t| t >= spawned)
                            {
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
                if matches!(
                    d,
                    "provigil-maild" | "provigil-integratord" | "provigil-csyslogd" | "provigil-agentlessd"
                ) && st.as_ref().is_ok_and(|s| s.success())
                {
                    info!("ProVigil manager: {d} idle (not configured)");
                    let conf = home.join("etc/ossec.conf");
                    let mtime = |p: &Path| p.metadata().and_then(|m| m.modified()).ok();
                    let seen = mtime(&conf);
                    while mtime(&conf) == seen {
                        std::thread::sleep(Duration::from_secs(2));
                    }
                    continue;
                }
                warn!("ProVigil manager: {d} exited ({st:?}); restarting in 5s (see {}/logs/ossec.log)", home.display());
            }
            Err(e) => {
                warn!("ProVigil manager: cannot start {d}: {e}");
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
        for e in std::fs::read_dir(home.join(dir))
            .into_iter()
            .flatten()
            .flatten()
        {
            if let Ok(t) = std::fs::read_to_string(e.path()) {
                ids.extend(
                    t.split("<rule id=\"")
                        .skip(1)
                        .filter_map(|p| p.split('"').next()?.parse::<u32>().ok()),
                );
            }
        }
    }
    ids
}

static RULES_LOCK: Mutex<()> = Mutex::new(());

/// Writes (or removes) `etc/rules/<file>` once `provigil-analysisd -t` accepts the whole ruleset
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
    if staged.is_err()
        || main_conf.matches(RULE_DIR).count() != 1
        || std::fs::write(
            &conf,
            main_conf.replace(RULE_DIR, "<rule_dir>etc/rules.staging</rule_dir>"),
        )
        .is_err()
    {
        cleanup();
        return Err(format!(
            "Could not stage the rules for checking ({})",
            staged
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ossec.conf".into())
        ));
    }
    let mut c = Command::new(home.join("bin").join(exe_name("provigil-analysisd")));
    c.arg("-t")
        .arg("-c")
        .arg("etc/ossec.staging.conf")
        .arg("-D")
        .arg(home)
        .current_dir(home)
        .stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    let checked = c.output();
    cleanup();
    let (ok, log) = match checked {
        Ok(o) => {
            let log = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let bad = log
                .lines()
                .any(|l| l.contains("ERROR") || l.contains("CRITICAL") || l.contains("(7612)"));
            (o.status.success() && !bad, log)
        }
        Err(e) => (false, format!("provigil-analysisd -t: {e}")),
    };
    if !ok {
        let why = log
            .lines()
            .find(|l| l.contains("ERROR") || l.contains("CRITICAL") || l.contains("(7612)"))
            .unwrap_or(log.trim())
            .to_string();
        return Err(format!("provigil-analysisd rejected the rules: {why}"));
    }
    let path = rules.join(file);
    match content {
        Some(c) => std::fs::write(&path, c),
        None => std::fs::remove_file(&path).or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        }),
    }
    .map_err(|e| format!("{}: {e}", path.display()))?;
    restart_daemons(&["provigil-analysisd"]);
    Ok(())
}

/// Adds a rule group to `etc/rules/<file>`, its `<rule id>` set to a free id of `ids`;
/// returns the id and the XML as deployed.
pub fn deploy_rule_group(
    file: &str,
    xml: &str,
    ids: std::ops::RangeInclusive<u32>,
) -> Result<(u32, String), String> {
    if !enabled() {
        return Err("The ProVigil manager is not running".into());
    }
    let _g = RULES_LOCK.lock().unwrap();
    let home = home();
    let used = used_rule_ids(&home);
    let id = ids
        .into_iter()
        .find(|i| !used.contains(i))
        .ok_or("No free rule id left in the Red Swarm range")?;
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
        return Err("The ProVigil manager is not running".into());
    }
    let _g = RULES_LOCK.lock().unwrap();
    let home = home();
    let cur = std::fs::read_to_string(home.join("etc/rules").join(file))
        .map_err(|_| "No rule of this kind is deployed".to_string())?;
    let rest = without_group(&cur, id)?;
    replace_rules_file(
        &home,
        file,
        (!rest.trim().is_empty()).then_some(rest.as_str()),
    )
}

/// A rules file without the `<group name=…>` holding `<rule id="id">`.
fn without_group(cur: &str, id: u32) -> Result<String, String> {
    let at = cur
        .find(&format!("<rule id=\"{id}\""))
        .ok_or("The rule is no longer deployed")?;
    // the group around the rule (the rule has a <group> element of its own inside)
    let start = cur[..at]
        .rfind("<group name=")
        .ok_or("Malformed rules file")?;
    let after_rule = at + cur[at..].find("</rule>").ok_or("Malformed rules file")?;
    let end = after_rule
        + cur[after_rule..]
            .find("</group>")
            .ok_or("Malformed rules file")?
        + "</group>".len();
    Ok(format!(
        "{}{}",
        &cur[..start],
        cur[end..].trim_start_matches(['\r', '\n'])
    ))
}

#[cfg(test)]
mod rule_file_tests {
    #[test]
    fn removes_the_whole_group_of_a_rule() {
        let g = |id: u32| {
            format!("<group name=\"rs,m\">\n  <!-- c -->\n  <rule id=\"{id}\" level=\"8\">\n    <match>x</match>\n    <group>attack,purple_team</group>\n  </rule>\n</group>\n")
        };
        let file = format!("{}{}", g(119000), g(119001));
        assert_eq!(super::without_group(&file, 119000).unwrap(), g(119001));
        assert_eq!(super::without_group(&file, 119001).unwrap(), g(119000));
        assert!(super::without_group(&g(119000), 119000)
            .unwrap()
            .trim()
            .is_empty());
        assert!(super::without_group(&file, 5).is_err());
    }

    /// One-shot EDR commands get one `<active-response>` without a timeout (ar.conf
    /// `kill-process0`, what the console sends); isolation gets the three timeouts.
    #[test]
    fn edr_commands_in_ossec_conf() {
        let k = super::ar_conf_section("kill-process", "kill-process.exe", false);
        assert!(
            k.contains("<timeout_allowed>no</timeout_allowed>")
                && !k.contains("<timeout>")
                && k.matches("<active-response>").count() == 1,
            "{k}"
        );
        let i = super::ar_conf_section("isolate-host", "isolate-host.exe", true);
        assert_eq!(i.matches("<timeout>").count(), super::AR_TIMEOUTS.len());
        assert!(
            super::AR_COMMANDS
                .iter()
                .filter(|c| c.1 == "isolate-host.exe")
                .count()
                == 2,
            "isolate and release"
        );
    }
}

/// Stops the running daemons named; their supervisors start them again.
pub(crate) fn restart_daemons(names: &[&str]) {
    for (n, pid) in CHILDREN.lock().unwrap().iter() {
        if !names.contains(&n.as_str()) {
            continue;
        }
        #[cfg(windows)]
        let _ = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        #[cfg(unix)]
        let _ = Command::new("kill")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// `ossec.conf` with the mail settings: the `<global>` e-mail fields and
/// `<alerts><email_alert_level>` (each element on its own line, as written here).
fn ossec_conf_with_mail(t: &str, s: &crate::mail_settings::MailSettings) -> String {
    let mut lines: Vec<String> = t.lines().map(String::from).collect();
    let starts = |l: &str, tags: &[&str]| {
        tags.iter()
            .any(|g| l.trim_start().starts_with(&format!("<{g}>")))
    };
    let section = |lines: &Vec<String>, name: &str| -> Option<(usize, usize)> {
        let a = lines.iter().position(|l| l.trim() == format!("<{name}>"))?;
        let b = lines[a..]
            .iter()
            .position(|l| l.trim() == format!("</{name}>"))?
            + a;
        Some((a, b))
    };
    let mut global = vec![format!(
        "<email_notification>{}</email_notification>",
        if s.alert_enabled { "yes" } else { "no" }
    )];
    if !s.host.is_empty() {
        global.push(format!("<smtp_server>{}</smtp_server>", s.host));
    }
    if !s.user.is_empty() {
        global.push(format!("<email_from>{}</email_from>", s.user));
    }
    global.extend(
        s.alert_to
            .iter()
            .map(|t| format!("<email_to>{t}</email_to>")),
    );
    global.push(format!(
        "<email_maxperhour>{}</email_maxperhour>",
        s.max_per_hour
    ));
    let gtags = [
        "email_notification",
        "smtp_server",
        "email_from",
        "email_to",
        "email_maxperhour",
    ];
    match section(&lines, "global") {
        Some((a, b)) => {
            let mut body: Vec<String> = lines[a + 1..b]
                .iter()
                .filter(|l| !starts(l, &gtags))
                .cloned()
                .collect();
            body.extend(global);
            lines.splice(a + 1..b, body);
        }
        None => {
            let end = lines
                .iter()
                .rposition(|l| l.trim() == "</ossec_config>")
                .unwrap_or(lines.len());
            let mut blk = vec!["<global>".to_string()];
            blk.extend(global);
            blk.push("</global>".into());
            lines.splice(end..end, blk);
        }
    }
    let level = format!("<email_alert_level>{}</email_alert_level>", s.alert_level);
    match section(&lines, "alerts") {
        Some((a, b)) => {
            let mut body: Vec<String> = lines[a + 1..b]
                .iter()
                .filter(|l| !starts(l, &["email_alert_level"]))
                .cloned()
                .collect();
            body.push(level);
            lines.splice(a + 1..b, body);
        }
        None => {
            let end = lines
                .iter()
                .rposition(|l| l.trim() == "</ossec_config>")
                .unwrap_or(lines.len());
            lines.splice(
                end..end,
                ["<alerts>".to_string(), level, "</alerts>".into()],
            );
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

pub const SMTP_AUTH_FILE: &str = "etc/smtp_auth.conf";

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
    let auth = home.join(SMTP_AUTH_FILE);
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
        info!(
            "ProVigil manager: mail settings applied (alerts by e-mail: {})",
            if s.alert_enabled { "on" } else { "off" }
        );
        // analysisd decides which alerts are mailed; maild and monitord send them
        restart_daemons(&["provigil-analysisd", "provigil-maild", "provigil-monitord"]);
    }
}

static WDB: std::sync::OnceLock<siem_ipc::wdbc::WdbcSocket> = std::sync::OnceLock::new();

pub(crate) fn wdb() -> &'static siem_ipc::wdbc::WdbcSocket {
    WDB.get_or_init(|| siem_ipc::wdbc::WdbcSocket::new(home().join("queue/db/wdb")))
}

/// The connection of removals: a mass removal queues here, not in front of enrollments.
fn purge_wdb() -> &'static siem_ipc::wdbc::WdbcSocket {
    static CONN: std::sync::OnceLock<siem_ipc::wdbc::WdbcSocket> = std::sync::OnceLock::new();
    CONN.get_or_init(|| siem_ipc::wdbc::WdbcSocket::new(home().join("queue/db/wdb")))
}

/// What authd does for a new key (`wdb_insert_agent` + `wdb_set_agent_groups_csv`):
/// the agent's row in global.db, which remoted and analysisd read.
pub async fn register_agent(id: &str, name: &str, ip: &str, raw_key: &str, groups: &str) {
    if !enabled() {
        return;
    }
    let Ok(n) = id.parse::<i64>() else { return };
    let group = if groups.trim().is_empty() {
        "default"
    } else {
        groups.trim()
    };
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
        Ok(r) => warn!("ProVigil manager: insert-agent {id}: {r}"),
        Err(e) => warn!("ProVigil manager: insert-agent {id}: {e}"),
    }
    let groups: Vec<&str> = group
        .split(',')
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .collect();
    let set = serde_json::json!({ "mode": "override", "sync_status": "synced", "data": [{ "id": n, "groups": groups }] });
    if let Ok(r) = wdb().query(&format!("global set-agent-groups {set}")).await {
        if !r.starts_with("ok") {
            warn!("ProVigil manager: set-agent-groups {id}: {r}");
        }
    }
}

/// ProVigil API `set_agent_group_relationship` (override): the agent's whole group list.
pub async fn set_agent_groups(id: &str, groups: &[String]) -> bool {
    let Ok(n) = id.parse::<i64>() else {
        return false;
    };
    let set = serde_json::json!({ "mode": "override", "sync_status": "syncreq", "data": [{ "id": n, "groups": groups }] });
    match wdb().query(&format!("global set-agent-groups {set}")).await {
        Ok(r) if r.starts_with("ok") => true,
        Ok(r) => {
            warn!("ProVigil manager: set-agent-groups {id}: {r}");
            false
        }
        Err(e) => {
            warn!("ProVigil manager: set-agent-groups {id}: {e}");
            false
        }
    }
}

/// What wm_database does when it finds a new or removed `etc/shared` folder
/// (`wdb_insert_group` / `wdb_remove_group_db`), done now instead of on its next sync.
pub async fn sync_group(name: &str, exists: bool) -> bool {
    let cmd = if exists {
        "insert-agent-group"
    } else {
        "delete-group"
    };
    match wdb().query(&format!("global {cmd} {name}")).await {
        Ok(r) if r.starts_with("ok") => true,
        r => {
            warn!("ProVigil manager: {cmd} {name}: {r:?}");
            false
        }
    }
}

/// Updates an agent's connection status and keepalive in provigil-db's global.db (agents that
/// reach siem-api over HTTP, such as the Linux agent's events).
pub async fn update_agent_keepalive(id: &str, status: &str) {
    if !enabled() {
        return;
    }
    let Ok(n) = id.parse::<i64>() else { return };
    let q = format!("global update-keepalive {{\"id\":{n},\"connection_status\":\"{status}\",\"sync_status\":\"synced\"}}");
    let _ = wdb().query(&q).await;
}

/// `wdb_remove_agent`, then the agent's own database (`queue/db/<id>.db`: inventory,
/// FIM, SCA, rootcheck), as the ProVigil API's agent removal does (`wazuhdb remove`). With
/// its `global.db` row gone provigil-db never opens (so never re-creates) that database.
pub async fn remove_agent(id: &str) -> bool {
    if !enabled() {
        return false;
    }
    let Ok(n) = id.parse::<u32>() else {
        return false;
    };
    if n == 0 {
        return false; // the manager itself
    }
    let row = purge_wdb().query(&format!("global delete-agent {n}")).await;
    let file = purge_wdb().query(&format!("wazuhdb remove {n:03}")).await;
    // OS_RemoveCounter (only a well-formed id names a file under queue/rids)
    let _ = std::fs::remove_file(home().join("queue/rids").join(format!("{n:03}")));
    let ok = row.as_deref().is_ok_and(|r| r.starts_with("ok"))
        && file.as_deref().is_ok_and(|r| r.starts_with("ok"));
    if !ok {
        warn!(
            "ProVigil manager: agent {n:03} not fully removed from provigil-db: {row:?} / {file:?}"
        );
    }
    ok
}

/// Agents removed from the platform that provigil-db still holds (a `global.db` row or a
/// database file, e.g. removed while the manager was down): removed once provigil-db answers.
pub async fn purge_removed(ids: Vec<String>) {
    if !enabled() || ids.is_empty() {
        return;
    }
    let known = |k: u32| async move { purge_wdb().query(&format!("global get-agent-info {k}")).await.is_ok_and(|r| r.starts_with("ok [{")) };
    for _ in 0..60 {
        if known(0).await {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    let file = |k: u32| home().join("queue/db").join(format!("{k:03}.db"));
    let ids: Vec<u32> = ids
        .iter()
        .filter_map(|i| i.parse::<u32>().ok())
        .filter(|k| *k > 0)
        .collect();
    let mut removed = std::collections::BTreeSet::new();
    // checked again, and removed again, every 30 s, at least 3 times: a file another
    // process still has open is only gone once it closes it (Windows), and a manager
    // starting up may still be opening the databases it listed
    for pass in 0..20 {
        let mut left = Vec::new();
        for &k in &ids {
            if file(k).exists() || known(k).await {
                left.push(k);
            }
        }
        if left.is_empty() && pass >= 2 {
            break;
        }
        for k in left {
            remove_agent(&k.to_string()).await;
            removed.insert(k);
        }
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
    let still: Vec<String> = removed
        .iter()
        .filter(|k| file(**k).exists())
        .map(|k| format!("{k:03}"))
        .collect();
    if !removed.is_empty() {
        info!("ProVigil manager: {} removed agent(s) also removed from provigil-db (row and database file)", removed.len() - still.len());
    }
    if !still.is_empty() {
        warn!("ProVigil manager: database file of removed agent(s) {} still in queue/db (in use by another program)", still.join(", "));
    }
}

/// `agent <id> sql <query>`: the rows, or None (no agent DB, not running).
pub(crate) async fn agent_sql(id: &str, sql: &str) -> Option<Vec<serde_json::Value>> {
    let r = wdb().query(&format!("agent {id} sql {sql}")).await.ok()?;
    let json = r.strip_prefix("ok ")?;
    serde_json::from_str::<serde_json::Value>(json)
        .ok()?
        .as_array()
        .cloned()
}

#[cfg(test)]
pub(crate) async fn wdb_raw(q: &str) -> String {
    wdb().query(q).await.unwrap_or_else(|e| format!("error {e}"))
}

/// Whether the id is an agent of the ProVigil manager (it has a row in global.db).
pub async fn is_provigil_agent(agent_id: &str) -> bool {
    let Ok(n) = agent_id.parse::<u32>() else {
        return false;
    };
    enabled()
        && wdb()
            .query(&format!("global get-agent-info {n}"))
            .await
            .is_ok_and(|r| r.starts_with("ok [{"))
}

/// One message to remoted's active-response queue (`queue/alerts/ar`), as
/// the ProVigil API's `WazuhQueue.send_msg_to_agent` writes it.
async fn send_ar_queue(msg: &str) -> Result<(), String> {
    route_ar(msg, "console").await
}

/// A ProVigil agent (HTTPS) gets the message on its next keepalive, other agents through remoted.
async fn route_ar(msg: &str, origin: &str) -> Result<(), String> {
    if let Some((id, payload)) = ar_target(msg) {
        if is_http_agent(&id) {
            queue_http_command(&id, payload, origin);
            return Ok(());
        }
    }
    let s = siem_ipc::local::DatagramSender::connect(home().join("queue/alerts/ar"))
        .await
        .map_err(|e| format!("remoted active-response queue: {e}"))?;
    s.send(msg.as_bytes())
        .await
        .map_err(|e| format!("remoted active-response queue: {e}"))
}

/// The responses the engine sends for ProVigil agents become their commands.
async fn engine_responses(home: PathBuf) {
    let rx = match siem_ipc::local::DatagramReceiver::bind(home.join(siem_ipc::mq::PROVIGIL_ARQUEUE)).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Engine responses cannot reach ProVigil agents: {e}");
            return;
        }
    };
    loop {
        match rx.recv(siem_ipc::OS_MAXSTR).await {
            Ok(m) => {
                let text = String::from_utf8_lossy(&m);
                if let Err(e) = route_ar(text.trim_end_matches('\0'), "engine").await {
                    warn!("engine response not delivered: {e}");
                }
            }
            Err(e) => {
                warn!("engine response queue: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Agents that talk to a gateway (the ProVigil agent): they never connect to the old channel, so
/// their commands go to the shared queue. The gateways mark them (`agent_commands`).
static HTTP_AGENTS: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);

/// The marks the gateways wrote.
pub(crate) fn restore_http_queue(marks: Vec<String>) {
    HTTP_AGENTS.lock().unwrap().get_or_insert_with(Default::default).extend(marks.iter().map(|m| agent_key(m)));
}

/// A row in a new state, written whole (the last version wins).
fn into_state(mut r: CommandRow, state: &str) -> CommandRow {
    r.state = state.to_string();
    r.state_at = agent_commands::now_ms();
    r.version = agent_commands::next_version();
    r
}

fn agent_key(id: &str) -> String {
    id.parse::<u32>()
        .map(|n| format!("{n:03}"))
        .unwrap_or_else(|_| id.to_string())
}

pub fn is_http_agent(id: &str) -> bool {
    HTTP_AGENTS
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|s| s.contains(&agent_key(id)))
}

/// Queues a remote upgrade for a ProVigil agent (HTTPS): the published `provigil-agent.exe`
/// and its SHA-256; the agent downloads, verifies and replaces itself.
pub fn queue_http_upgrade(id: &str) -> Result<String, String> {
    use sha2::Digest;
    let path = windows_agent_file("provigil-agent.exe").ok_or("provigil-agent.exe is not published")?;
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let hex = |b: &[u8]| -> String { sha2::Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect() };
    let sha = hex(&bytes);
    let version = exe_version(&bytes).ok_or("provigil-agent.exe carries no version mark (rebuild it)")?;
    // the agent and every published response program; `url` and `sha256` for agents before `files`
    let files: Vec<serde_json::Value> = WINDOWS_AGENT_FILES
        .iter()
        .filter_map(|name| {
            let bytes = std::fs::read(windows_agent_file(name)?).ok()?;
            Some(serde_json::json!({ "name": name, "url": format!("/downloads/windows/{name}"), "sha256": hex(&bytes) }))
        })
        .collect();
    push_http_command(id, serde_json::json!({ "command_id": uuid::Uuid::new_v4().to_string(), "type": "upgrade", "url": "/downloads/provigil-agent.exe", "sha256": sha, "version": version, "files": files }));
    Ok(sha)
}

/// The published provigil-agent.exe's version (read again only when the file changes).
pub fn published_agent_version() -> Option<String> {
    provigil_agent_server::published::published_version(&crate::data_file_path("agent-dist"))
}

/// `(msg_to_agent) [] <flags> <id> <payload>` (the engine: `(local_source) []`): the agent and
/// the payload.
fn ar_target(msg: &str) -> Option<(String, &str)> {
    let rest = msg.strip_prefix("(msg_to_agent) [] ").or_else(|| msg.strip_prefix("(local_source) [] "))?;
    let (_flags, rest) = rest.split_once(' ')?;
    let (id, payload) = rest.split_once(' ')?;
    Some((agent_key(id), payload))
}

/// One queued command: `{"type":"scan"}` for `syscheck restart`, else the response
/// message (`{"type":"ar","message":{...}}`, the JSON before any trailing text).
fn http_command(payload: &str) -> Option<serde_json::Value> {
    let id = uuid::Uuid::new_v4().to_string();
    if payload.trim() == "syscheck restart" {
        return Some(serde_json::json!({ "command_id": id, "type": "scan" }));
    }
    let mut message = serde_json::Deserializer::from_str(payload)
        .into_iter::<serde_json::Value>()
        .next()?
        .ok()?;
    // the response configuration still names the restart command after the old agent
    if let Some(rest) = message["command"].as_str().and_then(|c| c.strip_prefix("restart-wazuh")) {
        message["command"] = format!("restart-agent{rest}").into();
    }
    Some(serde_json::json!({ "command_id": id, "type": "ar", "message": message }))
}

fn queue_http_command(id: &str, payload: &str, origin: &str) {
    let Some(cmd) = http_command(payload) else {
        warn!("command for agent {id} not understood, not queued: {payload}");
        return;
    };
    let ttl = agent_commands::ttl_ms(&cmd);
    let _ = enqueue(id, cmd, origin, ttl);
}

pub(crate) fn push_http_command(id: &str, cmd: serde_json::Value) {
    let ttl = agent_commands::ttl_ms(&cmd);
    let _ = enqueue(id, cmd, "console", ttl);
}

/// A queued command's row (the gateway enforces the per-agent limit, it sees every writer's rows).
fn enqueue(id: &str, mut cmd: serde_json::Value, origin: &str, ttl_ms: u64) -> CommandRow {
    let agent = agent_key(id);
    if cmd["command_id"].as_str().is_none() {
        cmd["command_id"] = uuid::Uuid::new_v4().to_string().into();
    }
    let now = agent_commands::now_ms();
    let row = CommandRow {
        tenant_id: agent_commands::tenant_of(&agent),
        command_id: cmd["command_id"].as_str().unwrap_or_default().to_string(),
        agent_id: agent,
        command: cmd.to_string(),
        origin: origin.to_string(),
        created_at: now,
        expires_at: now.saturating_add(ttl_ms),
        state: table::QUEUED.to_string(),
        state_at: now,
        gateway: String::new(),
        attempts: 0,
        result: String::new(),
        version: agent_commands::next_version(),
    };
    agent_commands::save(row.clone());
    row
}

/// How often a live query looks for its answer.
const LIVE_POLL: Duration = Duration::from_millis(500);

/// One live query: ended by its answer, its timeout or a caller that left; a query not handed out
/// by then is cancelled, so an agent that is away does not get it later.
struct LiveQuery(CommandRow);

impl Drop for LiveQuery {
    fn drop(&mut self) {
        let r = self.0.clone();
        tokio::spawn(async move {
            if agent_commands::row(&r.agent_id, &r.command_id).await.is_some_and(|now| now.state == table::QUEUED) {
                agent_commands::save(into_state(r, table::CANCELLED));
            }
        });
    }
}

/// Queues `{"type": kind}` for a ProVigil agent and waits up to `wait` for the result of that
/// command id, which the gateway writes; `None` when none came.
pub async fn live_query(id: &str, kind: &str, wait: Duration) -> Option<serde_json::Value> {
    let row = enqueue(id, serde_json::json!({ "type": kind }), "console", table::LIVE_TTL_MS);
    let query = LiveQuery(row);
    let answer = async {
        loop {
            tokio::time::sleep(LIVE_POLL).await;
            if let Some(r) = agent_commands::row(&query.0.agent_id, &query.0.command_id).await.filter(|r| matches!(r.state.as_str(), table::DONE | table::FAILED)) {
                return serde_json::from_str(&r.result).ok();
            }
        }
    };
    tokio::time::timeout(wait, answer).await.ok()?
}

/// The response programs' result lines a ProVigil agent sends (its
/// `active-response\active-responses.log`), handled like the old agents' lines: live
/// response results, tamper protection, YARA results and their alerts.
pub async fn on_agent_ar_lines(
    state: &AppState,
    agent_id: &str,
    name: &str,
    ip: &str,
    lines: Vec<String>,
) {
    let now = Utc::now().to_rfc3339();
    let vs: Vec<serde_json::Value> = lines
        .into_iter()
        .map(|l| {
            serde_json::json!({
                "timestamp": now,
                "agent": { "id": agent_key(agent_id), "name": name, "ip": ip },
                "location": "active-response\\active-responses.log",
                "decoder": { "name": "ar_log_json" },
                "full_log": l,
            })
        })
        .collect();
    if !vs.is_empty() {
        on_events(state.clone(), vs).await;
    }
}

/// `send_restart_command` (agents >= 4.2: the JSON `restart-wazuh0` message).
pub async fn restart_agent(agent_id: &str) -> Result<(), String> {
    let id = format!(
        "{:03}",
        agent_id.parse::<u32>().map_err(|_| "invalid agent id")?
    );
    let m = r#"{"version": 1, "origin": {"module": "api"}, "command": "restart-agent0", "parameters": {"extra_args": [], "alert": {}}}"#;
    send_ar_queue(&format!(
        "(msg_to_agent) [] NNS {id} {m} - null (from_the_server) (no_rule_id)"
    ))
    .await
}

/// `PUT /syscheck` / `PUT /rootcheck`: `syscheck restart` runs a FIM and a rootcheck scan.
pub async fn syscheck_restart(agent_id: &str) -> Result<(), String> {
    let id = format!(
        "{:03}",
        agent_id.parse::<u32>().map_err(|_| "invalid agent id")?
    );
    send_ar_queue(&format!("(msg_to_agent) [] N!S {id} syscheck restart")).await
}

/// The block durations the manager defines active responses for (`ar.conf`
/// names are the command name plus the timeout).
pub const AR_TIMEOUTS: [u64; 3] = [600, 3600, 86400];

/// `PUT /active-response`: block `ip` on the agent's firewall (firewall-drop
/// on Unix, netsh on Windows) for `timeout` seconds; the agent's execd removes
/// the rule when it expires.
pub async fn block_ip(
    agent_id: &str,
    windows: bool,
    ip: &str,
    timeout: u64,
    method: Option<&str>,
) -> Result<String, String> {
    let id = format!(
        "{:03}",
        agent_id.parse::<u32>().map_err(|_| "invalid agent id")?
    );
    let timeout = AR_TIMEOUTS
        .iter()
        .copied()
        .find(|t| *t >= timeout)
        .unwrap_or(86400);
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
    let id = format!(
        "{:03}",
        agent_id.parse::<u32>().map_err(|_| "invalid agent id")?
    );
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

/// EDR live response: request `id` (`live_response.rs`), `action` with its `path`.
pub async fn live_response(
    agent_id: &str,
    id: &str,
    action: &str,
    path: &str,
) -> Result<(), String> {
    let mut args = vec![format!("id={id}"), format!("action={action}")];
    if !path.is_empty() {
        args.push(format!("path={path}"));
    }
    send_edr(agent_id, "live-response0", &args).await
}

/// EDR tamper protection: locks the agent service (`tamper.rs`).
pub async fn tamper_lock(agent_id: &str) -> Result<(), String> {
    send_edr(agent_id, "tamper-protect0", &["lock".to_string()]).await
}

/// EDR tamper protection off: the service gets its own permissions back.
pub async fn tamper_off(agent_id: &str) -> Result<(), String> {
    send_edr(agent_id, "tamper-protect0", &["off".to_string()]).await
}

/// EDR tamper protection: maintenance window `window` for `secs` (the agent locks again at its end).
pub async fn tamper_window(agent_id: &str, window: &str, secs: u64) -> Result<(), String> {
    let timeout = AR_TIMEOUTS
        .iter()
        .copied()
        .find(|t| *t >= secs)
        .unwrap_or(86400);
    send_edr(
        agent_id,
        &format!("tamper-unlock{timeout}"),
        &[format!("window={window}")],
    )
    .await
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
    let own = std::env::var("SIEM_LAN_IP")
        .or_else(|_| std::env::var("MANAGER_IP"))
        .unwrap_or_default();
    let extra = std::env::var("EDR_ISOLATION_ALLOW").unwrap_or_default();
    let mut v: Vec<std::net::Ipv4Addr> = own
        .split(',')
        .chain(extra.split(','))
        .filter_map(|a| a.trim().parse().ok())
        .collect();
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
    let timeout = AR_TIMEOUTS
        .iter()
        .copied()
        .find(|t| *t >= timeout)
        .unwrap_or(86400);
    let iso = uuid::Uuid::new_v4().simple().to_string();
    let allow = allow
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(",");
    send_edr(
        agent_id,
        &format!("isolate-host{timeout}"),
        &[format!("id={iso}"), format!("allow={allow}")],
    )
    .await?;
    Ok((iso, timeout))
}

/// EDR: lifts the isolation of the agent's host.
pub async fn release_agent(agent_id: &str) -> Result<(), String> {
    send_edr(agent_id, "release-host0", &["release".to_string()]).await
}

/// The active responses the console can send: (command name, agent executable, takes
/// a timeout). `route-null` and the EDR ones are Windows only; `release-host` is
/// isolate-host run with `release`.
const AR_COMMANDS: [(&str, &str, bool); 11] = [
    ("firewall-drop", "firewall-drop", true),
    ("netsh", "netsh.exe", true),
    ("route-null", "route-null.exe", true),
    ("kill-process", "kill-process.exe", false),
    ("quarantine-file", "quarantine-file.exe", false),
    ("isolate-host", "isolate-host.exe", true),
    ("release-host", "isolate-host.exe", false),
    ("yara-scan", "yara-scan.exe", false),
    ("live-response", "live-response.exe", false),
    ("tamper-protect", "tamper-protect.exe", false),
    ("tamper-unlock", "tamper-protect.exe", true),
];

/// The `<command>` and `<active-response>` blocks of one console command in the
/// manager's ossec.conf, at level 20 so no rule triggers them (`<name><timeout>` in
/// ar.conf, `<name>0` without one).
fn ar_conf_section(name: &str, exe: &str, timed: bool) -> String {
    let allowed = if timed { "yes" } else { "no" };
    let mut s = format!("  <command>\n    <name>{name}</name>\n    <executable>{exe}</executable>\n    <timeout_allowed>{allowed}</timeout_allowed>\n  </command>\n");
    let ar = |t: &str| {
        format!("  <active-response>\n    <command>{name}</command>\n    <location>local</location>\n    <level>20</level>\n{t}  </active-response>\n")
    };
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
    let Ok(t) = std::fs::read_to_string(conf) else {
        return;
    };
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
        Some(t) => serde_json::Value::String(
            chrono::DateTime::from_timestamp(t, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default(),
        ),
        None => serde_json::Value::Null,
    }
}

/// The FIM entries of a ProVigil agent (`fim_entry` in its provigil-db database).
pub async fn agent_fim(agent_id: &str) -> Option<serde_json::Value> {
    agent_fim_upto(agent_id, 1000).await
}

/// The agent's FIM entries, the `max` most recently changed (`total`: all of them).
pub async fn agent_fim_upto(agent_id: &str, max: usize) -> Option<serde_json::Value> {
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    let total = agent_sql(&id, "SELECT count(*) AS n FROM fim_entry;")
        .await?
        .first()
        .and_then(|x| x.get("n"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let rows = crate::inventory_store::paged(&id, "SELECT full_path, file, type, date, changes, arch, value_name, size, uname, gname, md5, sha1, sha256, mtime FROM fim_entry ORDER BY date DESC", max).await;
    let entries: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|mut r| {
            let (d, m) = (ts(r.get("date")), ts(r.get("mtime")));
            r["date"] = d;
            r["mtime"] = m;
            // registry entries are keyed by a hash; `file` is the key path (and `value_name` the value)
            let path = match (
                r["file"].as_str().unwrap_or(""),
                r["value_name"].as_str().unwrap_or(""),
            ) {
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
    Some(
        serde_json::json!({ "agent_id": agent_id, "total": total, "entries": entries, "source": "provigil-db" }),
    )
}

/// The latest SCA scan of a ProVigil agent (`sca_scan_info` / `sca_check` in its provigil-db database).
pub async fn agent_sca(agent_id: &str) -> Option<serde_json::Value> {
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    let scan = agent_sql(&id, "SELECT policy_id, pass, fail, invalid, score, end_scan FROM sca_scan_info ORDER BY end_scan DESC LIMIT 1;").await?.into_iter().next()?;
    let policy = scan.get("policy_id")?.as_str()?.to_string();
    let q = policy.replace('\'', "''");
    let name = agent_sql(
        &id,
        &format!("SELECT name FROM sca_policy WHERE id = '{q}';"),
    )
    .await
    .and_then(|r| r.first().and_then(|x| x["name"].as_str().map(String::from)));
    // each check's frameworks as the agent sent them (`sca_check_compliance`: one row per
    // framework, its requirement ids comma-separated)
    let mut compliance: HashMap<String, serde_json::Map<String, serde_json::Value>> =
        HashMap::new();
    for r in crate::inventory_store::paged(
        &id,
        "SELECT id_check, key, value FROM sca_check_compliance ORDER BY id_check",
        50_000,
    )
    .await
    {
        let check = match &r["id_check"] {
            serde_json::Value::String(s) => s.clone(),
            v => v.to_string(),
        };
        let (Some(key), Some(value)) = (r["key"].as_str(), r["value"].as_str()) else {
            continue;
        };
        let ids: Vec<serde_json::Value> = value
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| serde_json::Value::String(v.into()))
            .collect();
        compliance
            .entry(check)
            .or_default()
            .insert(key.to_string(), serde_json::Value::Array(ids));
    }
    let checks: Vec<serde_json::Value> = crate::inventory_store::paged(&id, &format!("SELECT id, title, result, reason, description, rationale, remediation FROM sca_check WHERE policy_id = '{q}' ORDER BY id"), 5000)
        .await
        .into_iter()
        .map(|r| {
            let status = match r["result"].as_str().unwrap_or("") {
                "passed" => "Passed",
                "failed" => "Failed",
                _ => "Not applicable",
            };
            let cid = match &r["id"] {
                serde_json::Value::String(s) => s.clone(),
                v => v.to_string(),
            };
            serde_json::json!({ "check_id": r["id"], "title": r["title"], "status": status, "reason": r["reason"],
                "description": r["description"], "rationale": r["rationale"], "remediation": r["remediation"],
                "compliance": compliance.remove(&cid).map(serde_json::Value::Object).unwrap_or_else(|| serde_json::json!({})) })
        })
        .collect();
    Some(serde_json::json!({
        "agent_id": agent_id, "policy_id": policy, "policy_name": name, "score": scan["score"], "passed": scan["pass"], "failed": scan["fail"],
        "not_applicable": scan["invalid"], "scanned_at": ts(scan.get("end_scan")), "checks": checks, "source": "provigil-db",
    }))
}

/// The rootcheck findings of a ProVigil agent (`pm_event` in its provigil-db database).
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
    Some(
        serde_json::json!({ "agent_id": agent_id, "total": events.len(), "events": events, "source": "provigil-db" }),
    )
}

/// The inventory syscollector reported for an agent, from provigil-db, in the
/// console's `AgentInventory` shape. None when the agent has no inventory.
pub async fn agent_inventory(agent_id: &str) -> Option<serde_json::Value> {
    if !enabled() {
        return None;
    }
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    let os = agent_sql(
        &id,
        "SELECT hostname, os_name, os_version, architecture FROM sys_osinfo LIMIT 1;",
    )
    .await?;
    let os = os.first()?.clone();
    let hw = agent_sql(&id, "SELECT cpu_cores, ram_total FROM sys_hwinfo LIMIT 1;")
        .await
        .unwrap_or_default();
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
        async move {
            agent_sql(&id, sql)
                .await
                .unwrap_or_default()
                .iter()
                .map(f)
                .filter(|x| !x.trim().is_empty())
                .collect::<Vec<String>>()
        }
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
    let processes = list(
        "SELECT DISTINCT name FROM sys_processes ORDER BY name LIMIT 500;",
        |r| {
            r.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        },
    )
    .await;
    let software = list(
        "SELECT name, version FROM sys_programs ORDER BY name LIMIT 500;",
        |r| {
            let n = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let v = r
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if v.is_empty() {
                n.to_string()
            } else {
                format!("{n} {v}")
            }
        },
    )
    .await;
    let services = list("SELECT service_id, service_state FROM sys_services WHERE UPPER(service_state) = 'RUNNING' ORDER BY service_id LIMIT 500;", |r| {
        r.get("service_id").and_then(|v| v.as_str()).unwrap_or("").to_string()
    })
    .await;
    let users = list(
        "SELECT user_name FROM sys_users ORDER BY user_name LIMIT 500;",
        |r| {
            r.get("user_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        },
    )
    .await;
    let adapters = list(
        "SELECT iface, address FROM sys_netaddr ORDER BY iface LIMIT 500;",
        |r| {
            format!(
                "{} {}",
                r.get("iface").and_then(|v| v.as_str()).unwrap_or(""),
                r.get("address").and_then(|v| v.as_str()).unwrap_or("")
            )
        },
    )
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
        "source": "provigil-db",
    }))
}

/// Whether the manager runs, reads its keys from the file, and the file is gone.
pub fn keys_file_missing() -> bool {
    !platform_keys() && enabled() && home().join("etc").exists() && !keys_file(&home()).exists()
}

/// Whether remoted and modulesd read the agent keys from siem-api (ClickHouse), not a file.
pub fn platform_keys() -> bool {
    KEYS_SERVICE.get().is_some()
}

/// Removes `etc/client.keys` once ClickHouse holds every key (platform keys only).
pub fn forget_keys_file() {
    let path = keys_file(&home());
    if platform_keys() && path.exists() {
        match std::fs::remove_file(&path) {
            Ok(()) => info!(
                "Agent keys are read from ClickHouse: {} removed",
                path.display()
            ),
            Err(e) => warn!("{} not removed: {e}", path.display()),
        }
    }
}

/// Writes the platform keystore to `etc/client.keys` (remoted reloads it).
pub fn save_keys(state: &AppState) {
    // the ClickHouse copy (agent_keys_store) follows
    crate::agent_keys_store::VERSION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    crate::agent_keys_store::CHANGED.notify_one();
    if !enabled() {
        return;
    }
    // remoted and modulesd see the new version through the key service: no file
    if platform_keys() {
        return;
    }
    let ks = state.auth_keystore.read().unwrap().clone();
    let path = keys_file(&home());
    let tmp = path.with_extension("keys.tmp");
    if let Err(e) = ks
        .save_file(&tmp)
        .and_then(|_| std::fs::rename(&tmp, &path))
    {
        warn!("ProVigil manager: cannot write {}: {e}", path.display());
    }
}

/// Starts the manager: home, keys, daemons, and the alert/event/status links.
pub fn start(state: AppState, keys_in_clickhouse: bool) {
    if !enabled() {
        info!("ProVigil manager disabled (PROVIGIL_MANAGER=0)");
        return;
    }
    // ClickHouse holds the keys: remoted and modulesd ask siem-api for them (no client.keys)
    if keys_in_clickhouse {
        match start_keys_service(state.clone()) {
            Ok(addr) => info!("Agent keys: remoted and modulesd read them from {addr} (ClickHouse), no etc/client.keys"),
            Err(e) => warn!("Key service not started ({e}): the daemons read etc/client.keys"),
        }
    }
    let home = home();
    prepare_agent_dist();
    if let Err(e) = prepare_home(&home) {
        warn!("ProVigil manager not started: {e}");
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
        warn!("ProVigil manager not started: {e}");
        return;
    }
    build_mitre_db(&home);
    info!("ProVigil manager home: {}", home.display());
    match start_stream(state.clone()) {
        Ok(addr) => {
            info!("Alerts, events and vulnerability results stream to {addr}, straight into ClickHouse (no alerts / archives / result files)");
            crate::vulnerability::fill_if_empty(state.clone());
        }
        Err(e) => warn!(
            "Alert stream not started ({e}): analysisd writes no alerts until siem-api restarts"
        ),
    }
    let h = home.clone();
    std::thread::spawn(move || {
        for d in DAEMONS {
            let (tx, rx) = std::sync::mpsc::channel();
            let hh = h.clone();
            std::thread::Builder::new()
                .name(format!("supervise-{d}"))
                .spawn(move || supervise(hh, d, tx))
                .ok();
            let _ = rx.recv_timeout(Duration::from_secs(60));
        }
    });

    let s = state.clone();
    tokio::spawn(async move { agent_status_loop(s).await });
    tokio::spawn(engine_responses(home));
    // the stored SMTP settings win over the files (a fresh manager home gets them too)
    let s = state.clone();
    tokio::spawn(async move {
        if let Some(m) = crate::mail_settings::load(&s).await {
            apply_mail_settings(&m);
        }
    });
}

/// analysisd's stream (siem-analysisd stream.rs): its loopback address and one-time token.
static STREAM: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

/// The key service for remoted and modulesd (siem_crypto::keystore::platform_fetch).
static KEYS_SERVICE: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

/// The keys' version for the daemons: changes with every key change and every start.
fn keys_version() -> u64 {
    static EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(|| chrono::Utc::now().timestamp_millis().max(0) as u64)
        + crate::agent_keys_store::VERSION.load(std::sync::atomic::Ordering::SeqCst)
}

/// Serves the agent keys (`client.keys` lines, from the platform keystore that
/// ClickHouse holds) to remoted and modulesd over loopback, with the one-time token.
fn start_keys_service(state: AppState) -> std::io::Result<String> {
    use siem_crypto::keystore::{KEYS_REQ, VERSION_REQ};
    use tokio::io::AsyncWriteExt;
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    l.set_nonblocking(true)?;
    let addr = l.local_addr()?.to_string();
    let listener = tokio::net::TcpListener::from_std(l)?;
    let token = uuid::Uuid::new_v4().simple().to_string();
    let _ = KEYS_SERVICE.set((addr.clone(), token.clone()));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, peer)) = listener.accept().await else {
                continue;
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            let (state, token) = (state.clone(), token.clone());
            tokio::spawn(async move {
                let Ok(Ok((kind, t))) =
                    tokio::time::timeout(Duration::from_secs(10), read_frame(&mut sock)).await
                else {
                    return;
                };
                let payload = if t != token.as_bytes() || !matches!(kind, KEYS_REQ | VERSION_REQ) {
                    warn!("key service: request refused (wrong token or kind)");
                    vec![b'X']
                } else {
                    let mut p = vec![kind];
                    p.extend_from_slice(format!("{}\n", keys_version()).as_bytes());
                    if kind == KEYS_REQ {
                        let ks = state.auth_keystore.read().unwrap().clone();
                        for k in &ks.keys {
                            p.extend_from_slice(k.to_key_line().as_bytes());
                            p.push(b'\n');
                        }
                    }
                    p
                };
                let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
                frame.extend_from_slice(&payload);
                let _ = sock.write_all(&frame).await;
            });
        }
    });
    Ok(addr)
}

/// Frames of the stream: `[u32 LE length][kind][u64 LE sequence][JSON]`.
const STREAM_MAX_FRAME: usize = 16 * 1024 * 1024;
/// Lines handed to the pipeline at once (or what came within `STREAM_LINGER`): one
/// ClickHouse INSERT costs about the same for 300 rows as for 5,000.
const STREAM_BATCH: usize = 5_000;
const STREAM_LINGER: Duration = Duration::from_millis(200);
/// Batches of alerts and events stored at the same time per connection.
const STREAM_INFLIGHT: usize = 4;
/// Stored batches remembered per stream: more than can be stored and not yet acknowledged.
const STREAM_MARKS: usize = 16;

/// Opens the loopback listener analysisd streams its alerts and events to.
fn start_stream(state: AppState) -> std::io::Result<String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    l.set_nonblocking(true)?;
    let addr = l.local_addr()?.to_string();
    let listener = tokio::net::TcpListener::from_std(l)?;
    let token = uuid::Uuid::new_v4().simple().to_string();
    let _ = STREAM.set((addr.clone(), token.clone()));
    tokio::spawn(async move {
        loop {
            let Ok((sock, peer)) = listener.accept().await else {
                continue;
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            let (s, t) = (state.clone(), token.clone());
            tokio::spawn(async move {
                match stream_conn(s, sock, &t).await {
                    Ok(()) => info!("analysisd stream closed"),
                    Err(e) => warn!("analysisd stream: {e}"),
                }
            });
        }
    });
    Ok(addr)
}

async fn read_frame(r: &mut (impl tokio::io::AsyncRead + Unpin)) -> std::io::Result<(u8, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n == 0 || n > STREAM_MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame of {n} bytes"),
        ));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    let kind = b[0];
    b.drain(..1);
    Ok((kind, b))
}

/// A stream frame: its kind, sequence and JSON.
async fn read_line(r: &mut (impl tokio::io::AsyncRead + Unpin)) -> std::io::Result<(u8, u64, Vec<u8>)> {
    let (kind, mut b) = read_frame(r).await?;
    let Some(seq) = b.get(..8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes) else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame without a sequence"));
    };
    b.drain(..8);
    Ok((kind, seq, b))
}

/// The batches a daemon's stream had stored lately, (first, last) sequence, oldest first.
static STREAM_STORED: Mutex<Option<StreamMarks>> = Mutex::new(None);
type StreamMarks = HashMap<String, Vec<(u64, u64)>>;

/// What is stored of `source`'s stream, here and in ClickHouse (siem-api restarted).
async fn stream_stored(state: &AppState, source: &str) -> Vec<(u64, u64)> {
    let mut ranges = state.db.stream_marks(source, STREAM_MARKS).await;
    ranges.extend(STREAM_STORED.lock().unwrap().get_or_insert_with(HashMap::new).get(source).into_iter().flatten());
    ranges
}

/// Notes a stored batch, before its acknowledgement: in a replay it is skipped.
async fn stream_mark(state: &AppState, source: &str, first: u64, last: u64) {
    {
        let mut m = STREAM_STORED.lock().unwrap();
        let ranges = m.get_or_insert_with(HashMap::new).entry(source.to_string()).or_default();
        ranges.push((first, last));
        if ranges.len() > STREAM_MARKS {
            ranges.remove(0);
        }
    }
    state.db.add_stream_mark(source, first, last).await;
}

/// One daemon's connection: the token and its name first, then alerts (`A`), events (`E`)
/// and vulnerability results (`V`) in batches to the pipeline (`on_alerts` / `on_events` /
/// `vulnerability::ingest`, which store them in ClickHouse). Frames are read by their own
/// task, so a batch timeout never cuts one in half; while the pipeline waits for ClickHouse
/// the bounded channel stops the reading, and the lines wait in the daemon's spool.
/// `stored up to N` (u64 LE) goes back once every batch up to N is stored; a line of a
/// batch stored before (a replay) is skipped.
async fn stream_conn(
    state: AppState,
    sock: tokio::net::TcpStream,
    token: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let (r, mut acks) = sock.into_split();
    let mut r = tokio::io::BufReader::new(r);
    let (kind, _, hello) = read_line(&mut r).await?;
    let hello = String::from_utf8_lossy(&hello).into_owned();
    let (t, source) = hello.split_once(' ').unwrap_or((&hello, ""));
    if kind != b'H' || t != token || source.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "wrong token",
        ));
    }
    let source = source.to_string();
    let stored = stream_stored(&state, &source).await;
    info!("{source} stream connected");
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u64, Vec<u8>)>(2 * STREAM_BATCH);
    let reader = tokio::spawn(async move {
        loop {
            match read_line(&mut r).await {
                Ok(f) => {
                    if tx.send(f).await.is_err() {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    });
    // alerts and events: up to STREAM_INFLIGHT batches stored at once, acknowledged in order;
    // vulnerability results in order (a delete must find what was stored before it)
    let inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(STREAM_INFLIGHT));
    let mut storing: std::collections::VecDeque<(u64, tokio::task::JoinHandle<()>)> = Default::default();
    let mut batch: Vec<(u8, Vec<u8>)> = Vec::new();
    // the sequences of this batch and how many lines, skipped ones too
    let mut span: Option<(u64, u64)> = None;
    let mut lines = 0;
    loop {
        let mut done = None;
        // shortcut: a batch that panicked counts as done (the panics are in the work after the inserts, and sending it again would stop the stream at it), until a panic can lose rows
        while storing.front().is_some_and(|(_, h)| h.is_finished()) {
            done = storing.pop_front().map(|b| b.0);
        }
        if let Some(n) = done {
            let _ = acks.write_all(&n.to_le_bytes()).await;
        }
        let next = match (span, storing.front_mut()) {
            (Some(_), _) => tokio::time::timeout(STREAM_LINGER, rx.recv())
                .await
                .unwrap_or(Some((0, 0, Vec::new()))),
            (None, Some((_, h))) => tokio::select! {
                f = rx.recv() => f,
                _ = h => continue,
            },
            (None, None) => rx.recv().await,
        };
        let closed = next.is_none();
        if let Some((kind, seq, json)) = next.filter(|(k, _, _)| *k != 0) {
            span = Some((span.map_or(seq, |s| s.0), seq));
            lines += 1;
            if !stored.iter().any(|r| (r.0..=r.1).contains(&seq)) {
                batch.push((kind, json));
            }
            if lines < STREAM_BATCH {
                continue;
            }
        }
        if let Some((first, last)) = span.take() {
            lines = 0;
            let frames = std::mem::take(&mut batch);
            let any = !frames.is_empty();
            let (alerts, events, vulns) = tokio::task::spawn_blocking(move || parse_frames(frames))
                .await
                .unwrap_or_default();
            let permit = inflight.clone().acquire_owned().await;
            if !vulns.is_empty() {
                crate::vulnerability::ingest(&state, vulns).await;
            }
            let (s, src) = (state.clone(), source.clone());
            storing.push_back((
                last,
                tokio::spawn(async move {
                    if !alerts.is_empty() || !events.is_empty() {
                        tokio::join!(on_alerts(s.clone(), alerts), on_events(s.clone(), events));
                    }
                    drop(permit);
                    if any {
                        stream_mark(&s, &src, first, last).await;
                    }
                }),
            ));
        }
        if closed {
            // the batches still being stored finish before the connection counts as done
            for (n, h) in storing.drain(..) {
                let _ = h.await;
                let _ = acks.write_all(&n.to_le_bytes()).await;
            }
            return reader.await.unwrap_or(Ok(()));
        }
    }
}

type Lines = Vec<serde_json::Value>;

/// A batch of stream frames as alerts, events and vulnerability results.
fn parse_frames(frames: Vec<(u8, Vec<u8>)>) -> (Lines, Lines, Lines) {
    let (mut alerts, mut events, mut vulns) = (Vec::new(), Vec::new(), Vec::new());
    for (kind, json) in frames {
        match serde_json::from_slice::<serde_json::Value>(&json) {
            Ok(v) if kind == b'A' => alerts.push(v),
            Ok(v) if kind == b'E' => events.push(v),
            Ok(v) if kind == b'V' => vulns.push(v),
            Ok(_) => {}
            Err(e) => warn!("analysisd stream: line not JSON ({e})"),
        }
    }
    (alerts, events, vulns)
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
    chrono::DateTime::parse_from_str(&t, "%Y-%m-%dT%H:%M:%S%.f%z")
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
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
/// ("-" is Windows for none; ProVigil doubles the backslash of DOMAIN\user).
fn windows_user(v: &serde_json::Value) -> Option<String> {
    ["targetUserName", "subjectUserName"].iter().find_map(|k| {
        v.pointer(&format!("/data/win/eventdata/{k}"))
            .and_then(|x| x.as_str())
            .map(|u| u.replace("\\\\", "\\"))
            .filter(|u| !u.is_empty() && u != "-")
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
        cur.as_array()
            .and_then(|a| a.first())
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
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
        agent_ip = state
            .agents
            .read()
            .unwrap()
            .get(&agent_id)
            .map(|a| a.ip.clone())
            .unwrap_or_else(|| "any".into());
    }
    let sport = |k: &str| s(&data, &[k]).parse::<u16>().ok();
    let opt = |k: &str| Some(s(&data, &[k])).filter(|x| !x.is_empty());
    let mut alert_data: HashMap<String, serde_json::Value> = data
        .as_object()
        .map(|o| o.clone().into_iter().collect())
        .unwrap_or_default();
    alert_data.insert(
        "wazuh_alert_id".into(),
        serde_json::Value::String(s(v, &["id"])),
    );
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
            level: v
                .pointer("/rule/level")
                .and_then(|x| x.as_u64())
                .unwrap_or(0)
                .min(15) as u8,
            description: s(v, &["rule", "description"]),
            groups: v
                .pointer("/rule/groups")
                .and_then(|g| g.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            mitre,
        },
        agent: AgentAlertInfo {
            id: agent_id,
            name: s(v, &["agent", "name"]),
            ip: agent_ip,
        },
        manager: Some(ManagerAlertInfo {
            name: s(v, &["manager", "name"]),
        }),
        decoder: Some(DecoderAlertInfo {
            name: s(v, &["decoder", "name"]),
        }),
        full_log: s(v, &["full_log"]),
        decoded: DecodedFields {
            decoder_name: s(v, &["decoder", "name"]),
            src_ip: opt("srcip"),
            dst_ip: opt("dstip"),
            src_port: sport("srcport"),
            dst_port: sport("dstport"),
            user: opt("dstuser")
                .or_else(|| opt("srcuser"))
                .or_else(|| windows_user(v)),
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

async fn on_alerts(state: AppState, mut vs: Vec<serde_json::Value>) {
    // live response results are data, not alerts (live_response.rs)
    vs.retain(|v| !crate::live_response::is_result(v));
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
/// `soar_json[i]` is what SOAR sees for `alerts[i]` (the original ProVigil alert).
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
            let tenant = a
                .data
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .unwrap_or(tenancy::DEFAULT_TENANT);
            failed.iter().any(|t| t == tenant)
        });
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
    // stored above either way; a suppressed alert is not shown live, kept, or acted on
    let tenants: Vec<String> = alerts
        .iter()
        .map(|a| {
            a.data
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .unwrap_or(tenancy::DEFAULT_TENANT)
                .to_string()
        })
        .collect();
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
    // each tenant's SOAR playbooks, on the original ProVigil alert
    crate::soar::on_alerts(state, soar);
    // each tenant's alert e-mails (alert_mail.rs)
    crate::alert_mail::on_alerts(&shown);
    crate::keep_alerts(state, shown);
}

/// Backoff of the ClickHouse retries (the alerts/archives files hold the data meanwhile).
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

fn event_source(location: &str, decoder: &str) -> EventSource {
    match (location, decoder) {
        ("EventChannel", _) | (_, "windows_eventchannel") => EventSource::WindowsEvent,
        ("syscheck", _)
        | (_, "syscheck_integrity_changed")
        | (_, "syscheck_new_entry")
        | (_, "syscheck_deleted") => EventSource::Fim,
        ("syscollector", _) => EventSource::Syscollector,
        ("sca", _) => EventSource::Sca,
        ("active-response", _) | (_, "ar_log_json") => EventSource::ActiveResponse,
        (_, d) if d.starts_with("sshd") || d == "pam" || d == "sudo" || d == "su" => {
            EventSource::Auth
        }
        _ => EventSource::Syslog,
    }
}

/// One `archives.json` line (every event analysisd received) as a platform event.
pub(crate) async fn on_events(state: AppState, vs: Vec<serde_json::Value>) {
    // an agent's SCA results changed: copied for the compliance audit within seconds
    for v in &vs {
        if v["location"].as_str() == Some("sca") {
            if let Some(a) = v["agent"]["id"].as_str().filter(|a| *a != "000") {
                crate::posture_store::changed(a);
            }
        }
    }
    // live response results go to their own table, not the event archive
    let (live, vs): (Vec<_>, Vec<_>) = vs.into_iter().partition(crate::live_response::is_result);
    if !live.is_empty() {
        crate::live_response::ingest(&state, live).await;
    }
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
            let tenant = e
                .metadata
                .get("tenant_id")
                .map(String::as_str)
                .unwrap_or(tenancy::DEFAULT_TENANT);
            failed.iter().any(|t| t == tenant)
        });
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
    // Sigma rules (sigma.rs) and file reputation (file_reputation.rs) on every archived event,
    // besides the ProVigil ruleset
    let tagged: Vec<(serde_json::Value, String)> = vs
        .into_iter()
        .zip(events.iter().map(|e| {
            e.metadata
                .get("tenant_id")
                .cloned()
                .unwrap_or_else(|| tenancy::DEFAULT_TENANT.to_string())
        }))
        .collect();
    let (matched, scans, tamper) = tokio::task::spawn_blocking(move || {
        let mut m = crate::sigma::check(&tagged);
        let mut tamper = crate::tamper::check(&tagged);
        m.append(&mut tamper.alerts);
        m.extend(crate::file_reputation::check(&tagged));
        let (yara_alerts, scans) = crate::yara_edr::check(&tagged);
        m.extend(yara_alerts);
        (m, scans, tamper)
    })
    .await
    .unwrap_or_default();
    crate::tamper::apply(&state, tamper.started, tamper.results).await;
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
    let agent_id = s(v, &["agent", "id"]);
    let tenant = tenant_of(state, &agent_id);
    let location = s(v, &["location"]);
    let decoder = s(v, &["decoder", "name"]);
    let mut metadata: HashMap<String, String> = HashMap::new();
    metadata.insert("tenant_id".into(), tenant);
    metadata.insert("hostname".into(), s(v, &["agent", "name"]));
    metadata.insert("decoder".into(), decoder.clone());
    metadata.insert("pipeline".into(), "provigil-manager".into());
    if let Some(d) = v.get("data") {
        metadata.insert("data_json".into(), d.to_string());
    }
    let rule = s(v, &["rule", "id"]);
    if !rule.is_empty() {
        metadata.insert("rule_id".into(), rule);
        metadata.insert("rule_level".into(), s(v, &["rule", "level"]));
    }
    let ip = s(v, &["agent", "ip"]);
    if !ip.is_empty() {
        metadata.insert("ip".into(), ip);
    }
    RawEvent {
        id: uuid::Uuid::new_v4(),
        timestamp: timestamp(v),
        agent_id,
        source: event_source(&location, &decoder),
        location,
        message: s(v, &["full_log"]),
        metadata,
    }
}

/// An agent's version as the console shows it: agents report "Wazuh v4.14.7" on the
/// wire (kept for compatibility with the rules and ProVigil agents), shown as ProVigil.
fn display_version(v: &str) -> String {
    match v.strip_prefix("Wazuh ") {
        Some(rest) => format!("ProVigil {rest}"),
        None => v.to_string(),
    }
}

/// Agent status, OS, version and keepalive from provigil-db's global.db.
async fn agent_status_loop(state: AppState) {
    // the database socket takes 64 KiB a message, so the rows come in pages
    const PAGE: usize = 200;
    let wdb = wdb();
    let mut last_saved: HashMap<String, (AgentStatus, i64)> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut rows: Vec<serde_json::Value> = Vec::new();
        loop {
            let after = rows.last().and_then(|r| r.get("id")).and_then(|x| x.as_i64()).unwrap_or(0);
            let q = format!("global sql SELECT id, name, ip, register_ip, os_name, os_version, os_platform, version, last_keepalive, connection_status FROM agent WHERE id > {after} ORDER BY id LIMIT {PAGE};");
            let Ok(resp) = wdb.query(&q).await else {
                break;
            };
            let Some(json) = resp.strip_prefix("ok ") else {
                break;
            };
            let Ok(serde_json::Value::Array(page)) = serde_json::from_str::<serde_json::Value>(json) else {
                break;
            };
            let full = page.len() == PAGE;
            rows.extend(page);
            if !full {
                break;
            }
        }
        for r in rows {
            let id = format!("{:03}", r.get("id").and_then(|x| x.as_i64()).unwrap_or(0));
            let ka = r
                .get("last_keepalive")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            let status = match s(&r, &["connection_status"]).as_str() {
                "active" => AgentStatus::Active,
                "pending" => AgentStatus::Pending,
                "never_connected" => AgentStatus::Pending,
                _ => AgentStatus::Disconnected,
            };
            if ka == 0 && status == AgentStatus::Pending {
                continue;
            }
            let os = [s(&r, &["os_name"]), s(&r, &["os_version"])]
                .join(" ")
                .trim()
                .to_string();
            let platform = s(&r, &["os_platform"]);
            let os_type = match platform.as_str() {
                "windows" => "windows",
                "darwin" => "macos",
                "" => "",
                _ => "linux",
            };
            let ip = Some(s(&r, &["ip"]))
                .filter(|x| !x.is_empty())
                .unwrap_or_else(|| s(&r, &["register_ip"]));
            let last_keepalive = chrono::DateTime::from_timestamp(ka, 0).unwrap_or_else(Utc::now);
            let agent = {
                let mut agents = state.agents.write().unwrap();
                let a = agents.entry(id.clone()).or_insert_with(|| Agent {
                    id: id.clone(),
                    name: s(&r, &["name"]),
                    ip: ip.clone(),
                    os: os.clone(),
                    version: display_version(&s(&r, &["version"])),
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
                let ver = display_version(&s(&r, &["version"]));
                if !ver.is_empty() {
                    a.version = ver;
                }
                if !ip.is_empty() && ip != "any" {
                    a.ip = ip.clone();
                }
                // an agent heard more recently over HTTP keeps that keepalive (active for 180 s)
                if a.last_keepalive > last_keepalive {
                    a.status = if (Utc::now() - a.last_keepalive).num_seconds() < 180 { AgentStatus::Active } else { AgentStatus::Disconnected };
                } else {
                    a.status = status.clone();
                    a.last_keepalive = last_keepalive;
                }
                a.clone()
            };
            let changed = last_saved
                .get(&id)
                .map(|(st, k)| *st != status || *k != ka)
                .unwrap_or(true);
            if changed {
                let tenant = tenant_of(&state, &id);
                state.db.save_agent_row(&tenant, &agent);
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
        assert_eq!(
            windows_user(&ev(
                json!({ "targetUserName": "alice", "subjectUserName": "SYSTEM" })
            ))
            .as_deref(),
            Some("alice")
        );
        // 4625 at the lock screen: no target name, the subject acted
        assert_eq!(
            windows_user(&ev(
                json!({ "targetUserName": "", "subjectUserName": "EVOFOX$" })
            ))
            .as_deref(),
            Some("EVOFOX$")
        );
        assert_eq!(
            windows_user(&ev(json!({ "targetUserName": "LAB\\\\bob" }))).as_deref(),
            Some("LAB\\bob")
        );
        assert_eq!(
            windows_user(&ev(
                json!({ "targetUserName": "-", "subjectUserName": "-" })
            )),
            None
        );
        assert_eq!(
            windows_user(&json!({ "data": { "srcip": "1.2.3.4" } })),
            None
        );
    }
}

#[cfg(test)]
mod mail_conf_tests {
    use super::ossec_conf_with_mail;
    use crate::mail_settings::MailSettings;

    #[test]
    fn edits_global_and_alerts() {
        let t = "<ossec_config>\n<global>\n<jsonout_output>yes</jsonout_output>\n<email_notification>no</email_notification>\n<email_to>old@x.com</email_to>\n</global>\n<alerts>\n<log_alert_level>3</log_alert_level>\n</alerts>\n</ossec_config>\n";
        let s = MailSettings {
            host: "smtp.gmail.com".into(),
            user: "a@gmail.com".into(),
            alert_enabled: true,
            alert_to: vec!["soc@x.com".into(), "b@x.com".into()],
            alert_level: 10,
            ..Default::default()
        };
        let n = ossec_conf_with_mail(t, &s);
        assert_eq!(
            n,
            "<ossec_config>\n<global>\n<jsonout_output>yes</jsonout_output>\n<email_notification>yes</email_notification>\n<smtp_server>smtp.gmail.com</smtp_server>\n<email_from>a@gmail.com</email_from>\n<email_to>soc@x.com</email_to>\n<email_to>b@x.com</email_to>\n<email_maxperhour>12</email_maxperhour>\n</global>\n<alerts>\n<log_alert_level>3</log_alert_level>\n<email_alert_level>10</email_alert_level>\n</alerts>\n</ossec_config>\n"
        );
        // applying again changes nothing
        assert_eq!(ossec_conf_with_mail(&n, &s), n);
    }
}

#[cfg(test)]
mod https_agent_tests {
    use super::{agent_commands, ar_target, exe_version, http_command, is_http_agent, live_query, queue_http_command, restore_http_queue, table};
    use std::time::Duration;

    fn rows(agent: &str) -> Vec<table::CommandRow> {
        agent_commands::SAVED.lock().unwrap().iter().filter(|r| r.agent_id == agent).cloned().collect()
    }

    /// The gateway's part, as it writes it: the agent's answer in the row.
    fn answered(r: &table::CommandRow, result: serde_json::Value) {
        agent_commands::save(table::CommandRow { state: table::DONE.into(), result: result.to_string(), version: agent_commands::next_version(), ..r.clone() });
    }

    #[tokio::test]
    async fn live_query_reads_its_answer_and_cancels_when_unanswered() {
        let q = tokio::spawn(live_query("778", "getstate", Duration::from_secs(5)));
        let r = loop {
            match rows("778").pop() {
                Some(r) => break r,
                None => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        };
        assert_eq!((r.state.as_str(), r.expires_at - r.created_at), (table::QUEUED, table::LIVE_TTL_MS));
        let cmd: serde_json::Value = serde_json::from_str(&r.command).unwrap();
        assert_eq!(cmd["type"], "getstate");
        let answer = serde_json::json!({ "command_id": cmd["command_id"], "status": "done", "state": {} });
        answered(&r, answer.clone());
        assert_eq!(q.await.unwrap(), Some(answer));

        // an agent that never asks: no answer, and the query is cancelled, not left queued
        assert_eq!(live_query("780", "getconfig", Duration::from_millis(700)).await, None);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(rows("780").last().unwrap().state, table::CANCELLED);
    }

    #[test]
    fn upgrade_version_read_from_the_exe() {
        assert_eq!(exe_version(b"MZ..provigil-agent-version:1.2.3\0rest").as_deref(), Some("1.2.3"));
        assert_eq!(exe_version(b"MZ no mark"), None);
    }

    #[test]
    fn https_agents_get_the_old_channel_messages() {
        let restart = r#"(msg_to_agent) [] NNS 058 {"version": 1, "origin": {"module": "api"}, "command": "restart-wazuh0", "parameters": {"extra_args": [], "alert": {}}} - null (from_the_server) (no_rule_id)"#;
        let (id, payload) = ar_target(restart).unwrap();
        assert_eq!(id, "058");
        let c = http_command(payload).unwrap();
        assert_eq!(
            (c["type"].as_str(), c["message"]["command"].as_str()),
            (Some("ar"), Some("restart-wazuh0"))
        );
        let (id, payload) = ar_target("(msg_to_agent) [] N!S 58 syscheck restart").unwrap();
        assert_eq!(
            (id.as_str(), http_command(payload).unwrap()["type"].as_str()),
            ("058", Some("scan"))
        );
        assert!(ar_target("garbage").is_none());
        // the marks the gateways write route it; the command waits in the shared queue
        assert!(!is_http_agent("777"));
        restore_http_queue(vec!["777".into()]);
        assert!(is_http_agent("0777") && is_http_agent("777"));
        queue_http_command(
            "777",
            r#"{"version":1,"origin":{},"command":"kill-process0","parameters":{"extra_args":["pid=42"],"alert":{}}}"#,
            "console",
        );
        let got = rows("777");
        let cmd: serde_json::Value = serde_json::from_str(&got[0].command).unwrap();
        assert_eq!((got.len(), got[0].state.as_str(), cmd["message"]["parameters"]["extra_args"][0].as_str()), (1, table::QUEUED, Some("pid=42")));
    }
}

#[cfg(test)]
mod agent_files_tests {
    use super::cached_sha256;

    #[test]
    fn hashed_again_only_when_the_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("provigil-agent.exe");
        std::fs::write(&f, "abc").unwrap();
        let mut cache = Default::default();
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(cached_sha256(&f, &mut cache).as_deref(), Some(abc));
        // the same time and size: the stored answer, the file is not read
        cache.get_mut(&f).unwrap().2 = "stored".to_string();
        assert_eq!(cached_sha256(&f, &mut cache).as_deref(), Some("stored"));
        std::fs::write(&f, "abcd").unwrap();
        assert_eq!(cached_sha256(&f, &mut cache).as_deref(), Some("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"));
        assert_eq!(cached_sha256(&dir.path().join("missing"), &mut cache), None);
    }
}

#[cfg(test)]
#[path = "provigil_stream_bench.rs"]
mod stream_bench;

#[cfg(test)]
mod stream_tests {
    use siem_ipc::platform_stream::{frame, EVENT, HELLO};
    use std::io::{Read, Write};

    /// A daemon's connection: the lines (sequence, n), then the acknowledgements.
    async fn connection(state: &crate::AppState, source: &str, lines: &[(u64, u32)]) -> Vec<u64> {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let mut wire = frame(HELLO, 0, format!("t0k {source}").as_bytes());
        for (seq, n) in lines {
            wire.extend(frame(EVENT, *seq, format!("{{\"agent\":{{\"id\":\"001\"}},\"location\":\"x\",\"full_log\":\"line {n}\"}}").as_bytes()));
        }
        let daemon = std::thread::spawn(move || {
            let mut c = std::net::TcpStream::connect(addr).unwrap();
            c.write_all(&wire).unwrap();
            // with the connection open: the batch finishes while siem-api waits for more lines
            let mut b = vec![0u8; 8];
            c.read_exact(&mut b).unwrap();
            c.shutdown(std::net::Shutdown::Write).unwrap();
            c.read_to_end(&mut b).unwrap();
            b.chunks(8).map(|a| u64::from_le_bytes(a.try_into().unwrap())).collect::<Vec<u64>>()
        });
        let (sock, _) = l.accept().await.unwrap();
        super::stream_conn(state.clone(), sock, "t0k").await.unwrap();
        daemon.join().unwrap()
    }

    fn stored(state: &crate::AppState) -> Vec<String> {
        let mut v: Vec<String> = state.events.read().unwrap().iter().map(|e| e.message.clone()).collect();
        v.sort();
        v
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_replay_stores_each_line_once_and_acknowledges_up_to_the_end() {
        let state = crate::analyst_tests::state().await;
        let source = uuid::Uuid::new_v4().simple().to_string();
        assert_eq!(connection(&state, &source, &[(11, 1), (12, 2)]).await, [12]);
        assert_eq!(stored(&state), ["line 1", "line 2"]);
        // the same lines again (the answer was lost), then a new one
        assert_eq!(connection(&state, &source, &[(11, 1), (12, 2), (13, 3)]).await, [13]);
        assert_eq!(stored(&state), ["line 1", "line 2", "line 3"]);
        // only a replay: nothing to store, and the daemon may still drop the lines
        assert_eq!(connection(&state, &source, &[(11, 1), (12, 2), (13, 3)]).await, [13]);
        assert_eq!(stored(&state).len(), 3);
    }

}

/// A rule with an active response fires in the real engine for a ProVigil agent: the agent's next
/// keepalive carries the command.
#[cfg(test)]
mod engine_responses_tests {
    use super::*;
    use siem_analysisd::daemon::{run, Analysis, Logger, StderrLogger};
    use siem_analysisd::daemon_config::AnalysisdConfig;
    use siem_ipc::{framing, local::StreamListener};
    use std::sync::Arc;

    const CONF: &str = r#"<ossec_config>
  <ruleset><decoder_dir>ruleset/decoders</decoder_dir><rule_dir>ruleset/rules</rule_dir></ruleset>
  <command><name>firewall-drop</name><executable>firewall-drop</executable><timeout_allowed>yes</timeout_allowed></command>
  <active-response><command>firewall-drop</command><location>local</location><rules_id>100101</rules_id><timeout>600</timeout></active-response>
</ossec_config>"#;

    fn write(home: &Path, file: &str, text: &str) {
        let p = home.join(file);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn make_home(home: &Path) {
        write(home, "etc/ossec.conf", CONF);
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/../../etc/internal_options.conf"), home.join("etc/internal_options.conf")).unwrap();
        write(home, "etc/local_internal_options.conf", "");
        write(home, "ruleset/decoders/d.xml", "<decoder name=\"d\"><prematch>^never</prematch></decoder>");
        write(home, "ruleset/rules/r.xml", "<group name=\"t,\"><rule id=\"1\" level=\"0\" noalert=\"1\"><category>syslog</category><description>any</description></rule><rule id=\"100101\" level=\"7\"><if_sid>1</if_sid><match>block this</match><description>t</description></rule></group>");
        for dir in ["logs/alerts", "logs/archives", "logs/firewall", "queue/alerts", "queue/fts", "queue/sockets", "queue/db", "var/run", "stats"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
    }

    /// provigil-db as the engine asks it about an agent: what siem-api's flush wrote for it.
    async fn agent_db(home: &Path) {
        let l = StreamListener::bind(home.join(siem_ipc::wdbc::WDB_LOCAL_SOCK)).await.unwrap();
        tokio::spawn(async move {
            while let Ok(mut s) = l.accept().await {
                tokio::spawn(async move {
                    while let Ok(q) = framing::recv(&mut s, 65536).await {
                        let answer: &[u8] = if q.starts_with(b"global get-agent-info") {
                            br#"ok [{"id":783,"version":"ProVigil v0.1.0"}]"#
                        } else {
                            b"ok []"
                        };
                        if framing::send(&mut s, answer).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
    }

    #[test]
    fn the_counter_file_of_the_old_name_is_read_until_the_new_one_exists() {
        let run = tempfile::tempdir().unwrap();
        let old = run.path().join("wazuh-analysisd.state");
        std::fs::write(&old, "events_dropped='3'
").unwrap();
        assert_eq!(counter_file(run.path(), "analysisd"), old);
        assert_eq!(read_state_file(&counter_file(run.path(), "analysisd"))["events_dropped"], 3.0);
        let new = run.path().join("provigil-analysisd.state");
        std::fs::write(&new, "events_dropped='0'
").unwrap();
        assert_eq!(counter_file(run.path(), "analysisd"), new);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rule_reaches_the_shared_queue() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        make_home(&home);
        agent_db(&home).await;
        // a gateway marked it at its first keepalive
        restore_http_queue(vec!["783".into()]);

        tokio::spawn(engine_responses(home.clone()));
        let cfg = AnalysisdConfig::load(&home, &home.join("etc/ossec.conf"), false).expect("config");
        let log: Arc<dyn Logger> = Arc::new(StderrLogger);
        let analysis = Analysis::new(cfg, &*log, false).expect("ruleset");
        std::thread::spawn(move || run(analysis, log));

        let t = std::time::Instant::now();
        let sender = loop {
            if let Ok(s) = siem_ipc::local::DatagramSender::connect(home.join(siem_ipc::mq::DEFAULTQUEUE)).await {
                break s;
            }
            assert!(t.elapsed() < Duration::from_secs(30), "the engine did not start");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let command: serde_json::Value = loop {
            sender.send(b"1:[783] (pc) any->/var/log/app:block this").await.unwrap();
            if let Some(r) = agent_commands::SAVED.lock().unwrap().iter().find(|r| r.agent_id == "783" && r.origin == "engine") {
                assert_eq!((r.state.as_str(), r.expires_at - r.created_at), (table::QUEUED, 600_000), "a timed response lives its time");
                break serde_json::from_str(&r.command).unwrap();
            }
            let counters = || std::fs::read_to_string(home.join("var/run/provigil-analysisd.state")).unwrap_or_default();
            assert!(t.elapsed() < Duration::from_secs(30), "no command was queued; the engine's counters:
{}", counters());
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(command["type"], "ar", "{command}");
        assert_eq!(command["message"]["command"], "firewall-drop600", "{command}");
        assert_eq!(command["message"]["origin"]["module"], "provigil-analysisd");
        assert_eq!(command["message"]["parameters"]["alert"]["rule"]["id"], "100101", "{command}");
        assert!(command["command_id"].as_str().is_some_and(|c| !c.is_empty()));
    }
}

#[cfg(test)]
mod restart_name_tests {
    #[test]
    fn provigil_agents_get_the_restart_command_by_its_own_name() {
        let c = super::http_command(r#"{"version":1,"command":"restart-wazuh0","parameters":{}}"#).unwrap();
        assert_eq!(c["message"]["command"], "restart-agent0");
        let c = super::http_command(r#"{"version":1,"command":"netsh600","parameters":{}}"#).unwrap();
        assert_eq!(c["message"]["command"], "netsh600");
    }
}
