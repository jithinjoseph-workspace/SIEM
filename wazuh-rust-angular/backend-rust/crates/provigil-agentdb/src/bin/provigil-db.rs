//! The agent database service (spec § 1): `provigil-db [-d] [-t] [-f]`, run by siem-api
//! from the manager home folder. Serves the local socket, runs the maintenance jobs, opens every
//! agent database once at start and takes the scheduled global backup.
//! `-d` more logging (twice for the most), `-t` check the settings and stop, `-f` stay in the
//! foreground (always).

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use provigil_agentdb::server::{self, Peers};
use provigil_agentdb::{Engine, Env, Settings, TOPIC_AGENT};

const NAME: &str = "provigil-db";

/// Lines of `logs/ossec.log`: `YYYY/MM/DD HH:MM:SS provigil-db: LEVEL: text`.
struct Log {
    file: Mutex<Option<std::fs::File>>,
    debug: u8,
}

impl Log {
    fn write(&self, level: &str, msg: &[u8]) {
        let need = match level {
            "DEBUG" => 1,
            "DEBUG2" => 2,
            _ => 0,
        };
        if self.debug < need {
            return;
        }
        let shown = if level == "DEBUG2" { "DEBUG" } else { level };
        let line = format!("{} {NAME}: {shown}: {}\n", chrono::Local::now().format("%Y/%m/%d %H:%M:%S"), String::from_utf8_lossy(msg));
        if let Ok(mut f) = self.file.lock() {
            if let Some(f) = f.as_mut() {
                let _ = f.write_all(line.as_bytes());
            }
        }
        if level == "CRITICAL" {
            eprint!("{line}");
        }
    }
}

/// Router topics: a connection per topic to `queue/router/<topic>` (port file on Windows),
/// opened on first use and again after a failure; messages are dropped when nobody listens.
struct Router {
    home: PathBuf,
    conns: Mutex<HashMap<&'static str, TcpStream>>,
}

impl Router {
    fn connect(&self, topic: &str) -> Option<TcpStream> {
        let path = self.home.join("queue/router").join(topic);
        let port: u16 = std::fs::read_to_string(path.with_extension("port")).ok()?.trim().parse().ok()?;
        TcpStream::connect(("127.0.0.1", port)).ok()
    }

    fn publish(&self, topic: &'static str, body: &[u8]) {
        // framing: [u32 size][u32 header size][header "P" = publish][body], little endian
        let mut frame = ((body.len() + 5) as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&1u32.to_le_bytes());
        frame.push(b'P');
        frame.extend_from_slice(body);
        let Ok(mut conns) = self.conns.lock() else { return };
        for _ in 0..2 {
            if !conns.contains_key(topic) {
                match self.connect(topic) {
                    Some(s) => {
                        conns.insert(topic, s);
                    }
                    None => return,
                }
            }
            if let Some(s) = conns.get_mut(topic) {
                if s.write_all(&frame).is_ok() {
                    return;
                }
            }
            conns.remove(topic);
        }
    }
}

struct ServiceEnv {
    log: Arc<Log>,
    peers: Arc<Peers>,
    router: Router,
    ossec_conf: PathBuf,
}

impl Env for ServiceEnv {
    fn log(&self, level: &str, msg: &[u8]) {
        self.log.write(level, msg);
    }
    fn time(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
    fn router_send(&self, topic: i32, msg: &[u8]) {
        self.router.publish(if topic == TOPIC_AGENT { "wdb-agent-events" } else { "wdb-inventory-events" }, msg);
    }
    fn send_peer(&self, peer: i32, msg: &[u8]) -> i32 {
        self.peers.send(peer, msg)
    }
    fn set_send_timeout(&self, peer: i32, secs: i32) -> i32 {
        self.peers.set_send_timeout(peer, secs)
    }
    fn is_single_node(&self) -> (i32, i32) {
        cluster_mode(&self.ossec_conf)
    }
    fn close_peer(&self, peer: i32) {
        self.peers.close(peer);
    }
    fn utc_offset(&self, t: i64) -> i64 {
        use chrono::TimeZone;
        chrono::Local.timestamp_opt(t, 0).single().map(|d| d.offset().local_minus_utc() as i64).unwrap_or(0)
    }
}

/// The text between `<tag>` and `</tag>` (first one).
fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let start = xml.find(&format!("<{tag}>")).map(|p| p + tag.len() + 2)?;
    let end = xml[start..].find(&format!("</{tag}>"))?;
    Some(xml[start..start + end].trim())
}

/// (single node, worker): a cluster section that is enabled makes it not single; its
/// `node_type` worker makes it a worker. -1 when the file cannot be read.
fn cluster_mode(conf: &Path) -> (i32, i32) {
    let Ok(xml) = std::fs::read_to_string(conf) else { return (-1, -1) };
    match element(&xml, "cluster") {
        None => (1, 0),
        Some(c) => {
            let disabled = element(c, "disabled").is_some_and(|d| d == "yes");
            let worker = element(c, "node_type").is_some_and(|t| t == "worker");
            (disabled as i32, (!disabled && worker) as i32)
        }
    }
}

/// `1d`, `12h`, `30m`, `45s` or plain seconds.
fn seconds(v: &str) -> Option<i64> {
    let (n, unit) = v.trim().split_at(v.trim().find(|c: char| !c.is_ascii_digit()).unwrap_or(v.trim().len()));
    let n: i64 = n.parse().ok()?;
    let k = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => return None,
    };
    (n > 0).then_some(n * k)
}

/// `provigil_db.<key>=<value>` from `etc/internal_options.conf`, overridden by
/// `etc/local_internal_options.conf`.
fn internal_options(home: &Path) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for f in ["etc/internal_options.conf", "etc/local_internal_options.conf"] {
        for line in std::fs::read_to_string(home.join(f)).unwrap_or_default().lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                if let Some(k) = k.trim().strip_prefix("provigil_db.") {
                    m.insert(k.to_string(), v.trim().to_string());
                }
            }
        }
    }
    m
}

/// The settings, or the reason they are invalid.
fn settings(home: &Path) -> Result<(Settings, u8), String> {
    let opts = internal_options(home);
    let int = |k: &str, def: i64, min: i64, max: i64| -> Result<i64, String> {
        match opts.get(k) {
            None => Ok(def),
            Some(v) => match v.parse::<i64>() {
                Ok(n) if (min..=max).contains(&n) => Ok(n),
                _ => Err(format!("Invalid value for provigil_db.{k}: '{v}' (allowed {min} to {max}).")),
            },
        }
    };
    let mut s = Settings {
        commit_time_min: int("commit_time_min", 10, 1, 3600)?,
        commit_time_max: int("commit_time_max", 60, 1, 3600)?,
        open_db_limit: int("open_db_limit", 64, 1, 4096)? as usize,
        fragmentation_threshold: int("fragmentation_threshold", 75, 0, 100)? as i32,
        fragmentation_delta: int("fragmentation_delta", 5, 0, 100)? as i32,
        free_pages_percentage: int("free_pages_percentage", 0, 0, 99)? as i32,
        max_fragmentation: int("max_fragmentation", 90, 0, 100)? as i32,
        check_fragmentation_interval: int("check_fragmentation_interval", 7200, 1, 30_758_400)?,
        router_agent: true,
        router_inventory: true,
        ..Settings::default()
    };
    let debug = int("debug", 0, 0, 2)? as u8;
    let conf = std::fs::read_to_string(home.join("etc/ossec.conf")).map_err(|e| format!("Cannot read etc/ossec.conf: {e}"))?;
    s.is_worker_node = cluster_mode(&home.join("etc/ossec.conf")).1 == 1;
    if let Some(wdb) = element(&conf, "wdb") {
        if let Some(b) = wdb.find("<backup database=\"global\">").map(|p| &wdb[p..]) {
            let b = &b[..b.find("</backup>").unwrap_or(b.len())];
            if let Some(v) = element(b, "enabled") {
                s.backup_enabled = match v {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(format!("Invalid value for element 'enabled': {v}.")),
                };
            }
            if let Some(v) = element(b, "interval") {
                s.backup_interval = seconds(v).ok_or(format!("Invalid value for element 'interval': {v}."))?;
            }
            if let Some(v) = element(b, "max_files") {
                s.backup_max_files = v.parse::<usize>().ok().filter(|n| *n > 0).ok_or(format!("Invalid value for element 'max_files': {v}."))?;
            }
        }
    }
    Ok((s, debug))
}

fn main() {
    let mut debug_flags = 0u8;
    let mut test_only = false;
    for a in std::env::args().skip(1) {
        let Some(flags) = a.strip_prefix('-') else { break };
        for c in flags.chars() {
            match c {
                'd' => debug_flags += 1,
                't' => test_only = true,
                'f' => {}
                _ => {
                    eprintln!("{NAME}: invalid option -- '{c}'");
                    std::process::exit(1);
                }
            }
        }
    }
    let home = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let _ = std::fs::create_dir_all(home.join("logs"));
    let file = std::fs::OpenOptions::new().create(true).append(true).open(home.join("logs/ossec.log")).ok();
    let (settings, debug_opt) = match settings(&home) {
        Ok(s) => s,
        Err(e) => {
            let log = Log { file: Mutex::new(file), debug: 0 };
            log.write("ERROR", e.as_bytes());
            log.write("CRITICAL", b"Invalid configuration for provigil-db.");
            std::process::exit(1);
        }
    };
    let log = Arc::new(Log { file: Mutex::new(file), debug: if debug_flags > 0 { debug_flags.min(2) } else { debug_opt } });
    log.write("DEBUG", format!("ProVigil home directory: {}", home.display()).as_bytes());
    if test_only {
        std::process::exit(0);
    }
    // the template is made again from the current layout
    let _ = std::fs::remove_file(home.join("queue/db/.template.db"));
    let pid = std::process::id();
    let _ = std::fs::create_dir_all(home.join("var/run"));
    let pid_file = home.join(format!("var/run/{NAME}-{pid}.pid"));
    if std::fs::write(&pid_file, format!("{pid}\n")).is_err() {
        log.write("CRITICAL", b"(1212): Unable to create PID file.");
        std::process::exit(1);
    }
    log.write("INFO", format!("Started (pid: {pid}).").as_bytes());

    let peers = Arc::new(Peers::default());
    let env = Arc::new(ServiceEnv { log: log.clone(), peers: peers.clone(), router: Router { home: home.clone(), conns: Mutex::new(HashMap::new()) }, ossec_conf: home.join("etc/ossec.conf") });
    let engine = Arc::new(Engine::new(&home, settings.clone(), env));
    engine.create_template();
    let running = Arc::new(AtomicBool::new(true));

    let listener = match server::bind(&home) {
        Ok(l) => l,
        Err(e) => {
            log.write("CRITICAL", format!("Unable to bind to socket '{}': '{e}'. Closing local server.", server::SOCKET).as_bytes());
            let _ = std::fs::remove_file(&pid_file);
            std::process::exit(1);
        }
    };
    let mut threads = Vec::new();
    {
        let (e, p, h, r) = (engine.clone(), peers.clone(), home.clone(), running.clone());
        threads.push(std::thread::Builder::new().name("server".into()).spawn(move || server::serve(e, p, listener, h, r)));
    }
    {
        let (e, r) = (engine.clone(), running.clone());
        threads.push(std::thread::Builder::new().name("maintenance".into()).spawn(move || {
            let mut countdown = e.settings.check_fragmentation_interval;
            while r.load(Ordering::SeqCst) {
                e.maintenance_tick(&mut countdown);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }));
    }
    {
        let (e, r) = (engine.clone(), running.clone());
        threads.push(std::thread::Builder::new().name("open-all".into()).spawn(move || e.open_all_agents(&|| r.load(Ordering::SeqCst))));
    }
    if settings.backup_enabled {
        let (e, r) = (engine.clone(), running.clone());
        threads.push(std::thread::Builder::new().name("backup".into()).spawn(move || {
            e.debug2(b"Database backup thread started.".to_vec());
            let mut last = e.newest_backup_time();
            while r.load(Ordering::SeqCst) {
                e.backup_tick(&mut last);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }));
    }
    let mut started = Vec::new();
    for t in threads {
        match t {
            Ok(t) => started.push(t),
            Err(e) => {
                log.write("ERROR", format!("Couldn't create threads: {e}").as_bytes());
                let _ = std::fs::remove_file(&pid_file);
                std::process::exit(1);
            }
        }
    }
    // siem-api stops the service by ending the process; the threads run until then
    for t in started {
        let _ = t.join();
    }
    engine.close_all();
    log.write("INFO", b"Graceful process shutdown.");
    let _ = std::fs::remove_file(&pid_file);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_settings_text() {
        assert_eq!(seconds("1d"), Some(86400));
        assert_eq!(seconds("90"), Some(90));
        assert_eq!(seconds("0"), None);
        assert_eq!(seconds("5x"), None);
        let xml = "<ossec_config><cluster><disabled>no</disabled><node_type>worker</node_type></cluster></ossec_config>";
        assert_eq!(element(xml, "node_type"), Some("worker"));
    }
}
