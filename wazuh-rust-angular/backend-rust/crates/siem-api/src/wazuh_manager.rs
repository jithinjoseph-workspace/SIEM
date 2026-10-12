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

use crate::{record_alert, tenancy, AppState};

/// The daemons, in start order.
const DAEMONS: [&str; 4] = ["wazuh-db", "wazuh-analysisd", "wazuh-remoted", "wazuh-modulesd"];

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
</ossec_config>\n"
    )
}

/// Creates the manager home (once) and refreshes the default ruleset.
fn prepare_home(home: &Path) -> Result<(), String> {
    for d in [
        "bin", "etc/decoders", "etc/rules", "etc/lists", "etc/shared/default", "ruleset", "logs/alerts", "logs/archives",
        "logs/firewall", "queue/sockets", "queue/db", "queue/alerts", "queue/rids", "queue/diff", "queue/fts", "queue/tasks",
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
    if !keys_file(home).exists() {
        std::fs::write(keys_file(home), "").map_err(|e| format!("client.keys: {e}"))?;
    }
    Ok(())
}

/// The files of the Windows agent package (`/downloads/windows/<file>`).
pub const WINDOWS_AGENT_FILES: [&str; 5] =
    ["wazuh-agent.exe", "internal_options.conf", "local_internal_options.conf", "vista_sec.txt", "help.txt"];

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
    ] {
        let dst = dir.join(to);
        if !dst.exists() {
            let _ = std::fs::copy(from, dst);
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
    if name == "wazuh-agent.exe" {
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
    let ok = !manager.is_empty() && manager.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'));
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

fn exe_name(d: &str) -> String {
    if cfg!(windows) {
        format!("{d}.exe")
    } else {
        d.to_string()
    }
}

/// Copies the daemons built next to siem-api into `<home>/bin` (wazuh-db
/// finds its home from there, like an installed manager).
fn install_binaries(home: &Path) -> Result<(), String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = me.parent().ok_or("no exe dir")?;
    let mut search = vec![dir.to_path_buf()];
    if let Some(t) = dir.parent() {
        search.push(t.join("release"));
        search.push(t.join("debug"));
    }
    for d in DAEMONS {
        let n = exe_name(d);
        let found = search.iter().map(|s| s.join(&n)).filter(|p| p.is_file()).max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok());
        let Some(src) = found else {
            return Err(format!("{n} not built (cargo build --release -p siem-wdb -p siem-analysisd -p siem-remoted -p siem-modulesd)"));
        };
        let dst = home.join("bin").join(&n);
        let newer = match (src.metadata().and_then(|m| m.modified()), dst.metadata().and_then(|m| m.modified())) {
            (Ok(a), Ok(b)) => a > b,
            _ => true,
        };
        if newer {
            std::fs::copy(&src, &dst).map_err(|e| format!("{n}: {e}"))?;
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
    match Command::new(tool).arg("-d").arg(&db).arg("-j").arg(&json).stdout(Stdio::null()).status() {
        Ok(s) if s.success() => info!("Wazuh manager: built {}", db.display()),
        other => warn!("Wazuh manager: building mitre.db failed: {other:?}"),
    }
}

/// The children of an earlier siem-api run that were left behind.
fn kill_stale(home: &Path) {
    let f = home.join("var/run/siem-api-children.pids");
    if let Ok(s) = std::fs::read_to_string(&f) {
        for pid in s.split_whitespace().filter_map(|p| p.parse::<u32>().ok()) {
            #[cfg(windows)]
            let _ = Command::new("taskkill").args(["/F", "/PID", &pid.to_string()]).stdout(Stdio::null()).stderr(Stdio::null()).status();
            #[cfg(unix)]
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
    }
    let _ = std::fs::remove_file(f);
}

static CHILDREN: Mutex<Vec<(String, u32)>> = Mutex::new(Vec::new());

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
        "wazuh-db" | "wazuh-modulesd" => c.arg("-f"),
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
        if let Some(m) = ready_marker(&home, d) {
            let _ = std::fs::remove_file(&m);
        }
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
                            if m.exists() {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                    let _ = tx.send(());
                }
                let st = child.wait();
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

/// `wdb_remove_agent`
pub async fn remove_agent(id: &str) {
    if !enabled() {
        return;
    }
    if let Ok(n) = id.parse::<i64>() {
        let _ = wdb().query(&format!("global delete-agent {n}")).await;
    }
}

/// Writes the platform keystore to `etc/client.keys` (remoted reloads it).
pub fn save_keys(state: &AppState) {
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
    // Keys issued before this run (the file is the source of truth).
    if let Ok(ks) = siem_crypto::keys::KeyStore::load_file(keys_file(&home)) {
        let mut cur = state.auth_keystore.write().unwrap();
        for k in ks.keys {
            if cur.find_by_id(&k.id).is_none() {
                cur.add_key(k);
            }
        }
    }
    if let Err(e) = install_binaries(&home) {
        warn!("Wazuh manager not started: {e}");
        return;
    }
    kill_stale(&home);
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
    tokio::spawn(async move { tail_json(p, o, move |v| on_alert(s.clone(), v)).await });
    let s = state.clone();
    let p = home.join("logs/archives/archives.json");
    let o = home.join("var/run/siem-api.archives.offset");
    tokio::spawn(async move { tail_json(p, o, move |v| on_event(s.clone(), v)).await });
    let s = state.clone();
    tokio::spawn(async move { agent_status_loop(s).await });
}

/// Follows a JSON-lines file from the saved offset (from the start when
/// the file was truncated or rotated).
async fn tail_json<F, Fut>(path: PathBuf, offset_file: PathBuf, mut f: F)
where
    F: FnMut(serde_json::Value) -> Fut,
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
        while let Some(nl) = partial[start..].iter().position(|&b| b == b'\n') {
            let line = &partial[start..start + nl];
            start += nl + 1;
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) {
                f(v).await;
            }
        }
        partial.drain(..start);
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
            user: opt("dstuser").or_else(|| opt("srcuser")),
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

async fn on_alert(state: AppState, v: serde_json::Value) {
    let alert = to_alert(&state, &v);
    let tenant = tenant_of(&state, &alert.agent.id);
    record_alert(&state, &tenant, alert).await;
}

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
async fn on_event(state: AppState, v: serde_json::Value) {
    let agent_id = s(&v, &["agent", "id"]);
    let tenant = tenant_of(&state, &agent_id);
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
    let event = RawEvent {
        id: uuid::Uuid::new_v4(),
        timestamp: timestamp(&v),
        agent_id,
        source: event_source(&location, &decoder),
        location,
        message: s(&v, &["full_log"]),
        metadata,
    };
    state.db.insert_event(&event).await;
    let mut ev = state.events.write().unwrap();
    ev.push(event);
    // The in-memory copy is a recent window; ClickHouse keeps everything.
    let n = ev.len();
    if n > 50_000 {
        ev.drain(..n - 50_000);
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
