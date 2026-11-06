//! ProVigil Unified Windows Endpoint Agent.
//!
//! 100% clean-room, high-performance, low-memory, dynamic Rust implementation.
//! The ProVigil endpoint agent for Windows.

/// Read from the published exe by the manager to name the version of an upgrade.
#[used]
pub static VERSION_MARK: &str = concat!("provigil-agent-version:", env!("CARGO_PKG_VERSION"), "\0");

pub mod ar_log;
pub mod buffer;
pub mod commands;
pub mod config;
pub mod diff;
pub mod edr;
pub mod events;
pub mod fim;
pub mod fim_db;
pub mod identity;
pub mod inventory;
pub mod logfiles;
pub mod osinfo;
pub mod osquery;
pub mod realtime;
pub mod registry;
pub mod rootcheck;
pub mod rootcheck_signatures;
pub mod sca;
pub mod sent;
pub mod service;
pub mod syscollector;
pub mod transport;
pub mod upgrade;
pub mod wevt;
pub mod whodata;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use serde_json::json;
use tracing::{error, info, warn};

use crate::buffer::EventBuffer;
use crate::config::{AgentConfig, GroupConfig, GROUP_CONFIG_FILE};
use crate::diff::DiffConfig;
use crate::edr::EdrExecutor;
use crate::fim::FimScanner;
use crate::identity::AgentIdentity;
use crate::registry::RegistryMonitor;
use crate::rootcheck::{RootcheckConfig, RootcheckScanner};
use crate::sca::ScaScanner;
use crate::service::{is_running};
use crate::transport::AgentTransport;

/// Tests that change `HKCU\Software\ProVigilTest` take turns.
#[cfg(test)]
pub(crate) static HKCU_TEST_KEY: Mutex<()> = Mutex::new(());

/// Seconds between group configuration fetches.
const GROUP_CONFIG_EVERY: Duration = Duration::from_secs(300);

/// Cleared while the collection loops stop for a restart with new settings.
static COLLECTING: AtomicBool = AtomicBool::new(true);

/// When each module last finished a scan, for the manager's `getstate`.
static LAST_SCANS: Mutex<BTreeMap<&str, String>> = Mutex::new(BTreeMap::new());

pub(crate) fn scan_done(module: &'static str) {
    LAST_SCANS.lock().unwrap_or_else(|e| e.into_inner()).insert(module, chrono::Utc::now().to_rfc3339());
}

pub(crate) fn last_scans() -> serde_json::Value {
    json!(&*LAST_SCANS.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Collection threads and blocking jobs still running, by name: logged when the stop runs late.
static BUSY: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// `name` is listed in [`still_running`] until this is dropped.
struct Busy(String);

impl Busy {
    fn new(name: String) -> Self {
        BUSY.lock().unwrap_or_else(|e| e.into_inner()).push(name.clone());
        Busy(name)
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let mut busy = BUSY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = busy.iter().position(|n| *n == self.0) {
            busy.swap_remove(i);
        }
    }
}

pub fn still_running() -> Vec<String> {
    BUSY.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A named collection thread, listed in [`still_running`] until it ends.
pub(crate) fn thread(name: String, f: impl FnOnce() + Send + 'static) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new().name(name.clone()).spawn(move || {
        let _busy = Busy::new(name);
        f()
    })
}

/// `spawn_blocking`, listed in [`still_running`] until it ends.
pub(crate) fn blocking<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> tokio::task::JoinHandle<T> {
    let busy = Busy::new(name.to_string());
    tokio::task::spawn_blocking(move || {
        let _busy = busy;
        f()
    })
}

/// The collection loops keep going while this is true; scans check it to end early.
pub(crate) fn collecting() -> bool {
    is_running() && COLLECTING.load(Ordering::SeqCst)
}

/// Sleeps `d`, waking every half second to stop early once `running()` turns false.
pub(crate) fn nap(d: Duration, running: fn() -> bool) {
    let end = std::time::Instant::now() + d;
    while running() && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// [`nap`] for the async loops.
async fn pause(d: Duration, running: fn() -> bool) {
    let end = tokio::time::Instant::now() + d;
    while running() && tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Real-time watches and who-data, started once the first scan has built the baseline.
/// Who-data folders are watched in plain real time when who-data cannot start.
fn start_live_fim(
    mut realtime_dirs: Vec<PathBuf>,
    whodata_dirs: Vec<PathBuf>,
    fim: Arc<Mutex<FimScanner>>,
    buffer: Arc<EventBuffer>,
    agent: (String, String),
) -> Vec<JoinHandle<()>> {
    let mut threads = Vec::new();
    if !whodata_dirs.is_empty() {
        match whodata::start(&whodata_dirs, Path::new("data")) {
            Ok(session) => threads.extend(whodata::spawn(session, fim.clone(), buffer.clone(), agent.clone(), collecting)),
            Err(e) => {
                error!(error = %e, "Who-data not available; its folders are watched in real time without it");
                realtime_dirs.extend(whodata_dirs);
            }
        }
    }
    threads.extend(realtime::spawn(&realtime_dirs, fim, buffer, agent, collecting));
    threads
}

/// The collection loops running with one set of settings.
struct Collection {
    /// Event log subscriptions: they write their bookmarks when they end.
    wevt: Vec<JoinHandle<()>>,
    /// Real-time watches and who-data (who-data restores the audit policy when it ends).
    live_fim: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Registry, log files, commands and osquery.
    threads: Vec<JoinHandle<()>>,
    /// File integrity, configuration assessment and rootcheck scans.
    tasks: Vec<tokio::task::JoinHandle<()>>,
    inventory: tokio::task::JoinHandle<()>,
}

/// Starts the collection loops: event channels, file integrity (scans, real time, who-data),
/// registry, inventory, configuration assessment, rootcheck, log files and commands.
fn start_collection(config: &AgentConfig, identity: &AgentIdentity, buffer: &Arc<EventBuffer>, edr: &EdrExecutor) -> Collection {
    let mut tasks = Vec::new();
    let mut threads = Vec::new();

    // Windows Event Log Collector: one live subscription per channel, on its own thread
    let wevt = wevt::spawn_readers(
        &config.event_channels,
        &config.event_channel_queries,
        Duration::from_secs(config.event_channel_reconnect_secs),
        &PathBuf::from("bookmarks"),
        buffer.clone(),
        json!({ "id": &identity.agent_id, "name": &identity.agent_name }),
        collecting,
    );

    // File integrity monitoring: scheduled scans of every monitored folder (the safety
    // net), then real-time watches and who-data once the baseline is built
    let (mut realtime_dirs, mut whodata_dirs) = (Vec::new(), Vec::new());
    for d in &config.fim_whodata {
        if config.whodata_enabled { whodata_dirs.push(PathBuf::from(d)) } else { realtime_dirs.push(PathBuf::from(d)) }
    }
    for d in &config.fim_realtime {
        if !config.fim_whodata.iter().any(|w| w.eq_ignore_ascii_case(d)) {
            realtime_dirs.push(PathBuf::from(d));
        }
    }
    let mut scan_dirs = config.fim_paths.clone();
    for d in realtime_dirs.iter().chain(&whodata_dirs) {
        if !scan_dirs.contains(d) {
            scan_dirs.push(d.clone());
        }
    }
    let mut fim_builder = FimScanner::new(scan_dirs)
        .with_ignore(&config.fim_ignore)
        .with_recursion_level(config.fim_recursion_level)
        .with_file_limit(config.fim_file_limit)
        .with_database(&PathBuf::from("data").join("fim.db"));
    if config.diff_enabled || !config.fim_report_changes.is_empty() {
        let only = if config.diff_enabled { &[][..] } else { &config.fim_report_changes[..] };
        fim_builder = fim_builder.with_diff_paths(only, &config.fim_nodiff).with_diff_engine(DiffConfig {
            enabled: true,
            storage_dir: PathBuf::from("data").join("diff"),
            max_diff_size: config.diff_max_size,
            max_file_size: 10 * 1024 * 1024,
            disk_quota_bytes: 50 * 1024 * 1024,
            compress_snapshots: true,
        });
    }
    let fim = Arc::new(Mutex::new(fim_builder));
    let live_fim: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
    let fim_interval = Duration::from_secs(config.fim_scan_interval_secs);
    let fim_rate = config.fim_max_files_per_second;
    let fim_agent = (identity.agent_id.clone(), identity.agent_name.clone());
    let fim_now = edr.scan_fim.clone();
    {
        let (fim, buffer_fim, live_fim) = (fim.clone(), buffer.clone(), live_fim.clone());
        let mut live = Some((realtime_dirs, whodata_dirs));
        tasks.push(tokio::spawn(async move {
            while collecting() {
                // hashing and the baseline lock: off the async threads
                let (f, a) = (fim.clone(), fim_agent.clone());
                let fim_events = crate::blocking("fim scan", move || fim::scan_shared(&f, &a.0, &a.1, collecting))
                    .await
                    .unwrap_or_default();
                scan_done("fim");
                if let Some((rt, who)) = live.take().filter(|_| collecting()) {
                    let (f, b, a) = (fim.clone(), buffer_fim.clone(), fim_agent.clone());
                    if let Ok(threads) = crate::blocking("fim live start", move || start_live_fim(rt, who, f, b, a)).await {
                        live_fim.lock().unwrap_or_else(|e| e.into_inner()).extend(threads);
                    }
                }
                let (f, b, a) = (fim.clone(), buffer_fim.clone(), fim_agent.clone());
                let _ = crate::blocking("fim send", move || {
                    fim::push_paced(&b, fim_events, fim_rate, collecting);
                    fim::sync_files(&f, &b, &a, Path::new(fim::SYNCED_FILE), collecting, fim::state_allowed);
                })
                .await;
                // the next scan when the interval is up, or at once when the manager asks
                tokio::select! {
                    _ = pause(fim_interval, collecting) => {}
                    _ = fim_now.notified() => info!("File integrity scan requested by the manager"),
                }
            }
        }));
    }

    // Windows registry monitoring, at start and then on schedule, on its own thread
    let buffer_reg = buffer.clone();
    let mut reg = RegistryMonitor::new(config.registry_keys.clone())
        .with_ignore(&config.registry_ignore)
        .with_recursion_level(config.registry_recursion_level)
        .with_restrict(&config.registry_restrict_key, &config.registry_restrict_value)
        .with_report_changes(&config.registry_report_changes)
        .with_database(&PathBuf::from("data").join("fim.db"));
    let reg_agent = (identity.agent_id.clone(), identity.agent_name.clone());
    let reg_interval = Duration::from_secs(config.registry_scan_interval_secs);
    let spawned = thread("registry".into(), move || {
        while collecting() {
            let reg_events = reg.scan(&reg_agent.0, &reg_agent.1);
            scan_done("registry");
            fim::push_paced(&buffer_reg, reg_events, fim_rate, collecting);
            reg.sync_state(&buffer_reg, &reg_agent, Path::new(fim::SYNCED_FILE), collecting, fim::state_allowed);
            nap(reg_interval, collecting);
        }
    });
    match spawned {
        Ok(t) => threads.push(t),
        Err(e) => error!(error = %e, "Registry monitoring thread not started"),
    }

    // System Inventory Collector Loop (Hardware, OS, Ports, Processes, Services, Software)
    let inventory = syscollector::spawn_syscollector_worker(
        identity.agent_id.clone(),
        identity.agent_name.clone(),
        buffer.clone(),
        Duration::from_secs(config.inventory_interval_secs),
        edr.inventory_full.clone(),
        config.full_send_splay_secs,
    );

    // Security configuration assessment: every policy at start, on schedule and when the
    // manager asks; each policy's check events, then its summary
    if config.sca_enabled {
        let buffer_sca = buffer.clone();
        let sca_interval = Duration::from_secs(config.sca_interval_secs);
        let (sca_id, sca_name) = (identity.agent_id.clone(), identity.agent_name.clone());
        let (sca_now, sca_full) = (edr.scan_sca.clone(), edr.sca_full.clone());
        let sca = Arc::new(Mutex::new(ScaScanner::new().without(&config.sca_disabled_policies).with_state(sent::file(), config.full_send_splay_secs)));
        tasks.push(tokio::spawn(async move {
            while collecting() {
                // registry reads, secedit and auditpol: off the async threads
                let (s, id, name) = (sca.clone(), sca_id.clone(), sca_name.clone());
                let asked = std::mem::take(&mut *sca_full.lock().unwrap_or_else(|e| e.into_inner()));
                let events = crate::blocking("sca scan", move || {
                    let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
                    s.ask_full(asked);
                    s.scan(&id, &name)
                })
                    .await
                    .unwrap_or_default();
                info!(events = events.len(), "Configuration assessment done");
                scan_done("sca");
                for ev in events {
                    buffer_sca.push(ev);
                }
                tokio::select! {
                    _ = pause(sca_interval, collecting) => {}
                    _ = sca_now.notified() => info!("Configuration assessment requested by the manager"),
                }
            }
        }));
    }

    // Rootcheck & Driver Scanner Loop
    if config.rootcheck_enabled {
        let buffer_rootcheck = buffer.clone();
        let rootcheck_scanner = Arc::new(RootcheckScanner::new(RootcheckConfig::from_settings(config)));
        let rootcheck_interval = Duration::from_secs(config.rootcheck_interval_secs);
        let ident_id_rc = identity.agent_id.clone();
        let ident_name_rc = identity.agent_name.clone();
        let rc_now = edr.scan_rootcheck.clone();
        tasks.push(tokio::spawn(async move {
            while collecting() {
                // walks the system drive and reads the registry: off the async threads
                let (s, id, name) = (rootcheck_scanner.clone(), ident_id_rc.clone(), ident_name_rc.clone());
                let rc_events = crate::blocking("rootcheck scan", move || s.scan(&id, &name)).await.unwrap_or_default();
                scan_done("rootcheck");
                for ev in rc_events {
                    buffer_rootcheck.push(ev);
                }
                tokio::select! {
                    _ = pause(rootcheck_interval, collecting) => {}
                    _ = rc_now.notified() => info!("Rootcheck scan requested by the manager"),
                }
            }
        }));
    }

    // Log files and command output (localfiles), on their own threads
    threads.extend(logfiles::spawn(
        &config.localfiles,
        PathBuf::from("data").join("file_positions.json"),
        buffer.clone(),
        json!({ "id": &identity.agent_id, "name": &identity.agent_name }),
        collecting,
    ));
    threads.extend(commands::spawn(&config.commands, buffer.clone(), json!({ "id": &identity.agent_id, "name": &identity.agent_name }), collecting));
    threads.extend(osquery::spawn(
        &config.osquery,
        PathBuf::from("data").join("osquery_positions.json"),
        buffer.clone(),
        json!({ "id": &identity.agent_id, "name": &identity.agent_name }),
        collecting,
    ));
    *edr.repeated_offenders.lock().unwrap_or_else(|e| e.into_inner()) = config.ar_repeated_offenders.clone();

    Collection { wevt, live_fim, threads, tasks, inventory }
}

/// How long the service stop waits for the collection loops (each notices it within ~1 s).
const STOP_WAIT: Duration = Duration::from_secs(5);

impl Collection {
    /// Ends the loops and waits for them: a scan stops early and queues what it found so far,
    /// event channels write their bookmarks, who-data restores the audit policy, a started
    /// osquery daemon is stopped. A restart waits without limit (the old loops must be gone
    /// before new ones start); the service stop [`STOP_WAIT`] at most.
    async fn stop(self) {
        let restart = is_running();
        COLLECTING.store(false, Ordering::SeqCst);
        let Collection { wevt, live_fim, threads, tasks, inventory } = self;
        // the inventory goes whole or not at all
        inventory.abort();
        let wait = async move {
            for t in tasks {
                let _ = t.await;
            }
            // after the FIM task: it may have just started the live watches
            let live = std::mem::take(&mut *live_fim.lock().unwrap_or_else(|e| e.into_inner()));
            let join: Vec<JoinHandle<()>> = wevt.into_iter().chain(live).chain(threads).collect();
            let _ = tokio::task::spawn_blocking(move || join.into_iter().for_each(|t| { let _ = t.join(); })).await;
        };
        if restart {
            wait.await;
        } else if tokio::time::timeout(STOP_WAIT, wait).await.is_err() {
            warn!(running = ?still_running(), "Collection loops still running at stop");
        }
        COLLECTING.store(true, Ordering::SeqCst);
    }
}

/// Waits up to `d`, checking the stop flag every second; false when the service is stopping.
/// Without it a stop during an enrollment retry left the service hanging in STOP_PENDING.
async fn wait_unless_stopped(d: Duration) -> bool {
    let end = tokio::time::Instant::now() + d;
    while is_running() && tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_secs(1).min(end - tokio::time::Instant::now())).await;
    }
    is_running()
}

/// Runs the complete agent background collection and telemetry streaming pipeline; again with
/// a new enrollment when the manager no longer accepts the agent.
pub async fn run_agent_pipeline() -> anyhow::Result<()> {
    // one for every enrollment: its pending undos are armed once
    let edr = Arc::new(EdrExecutor::new());
    edr.restore();
    let mut enroll_again = false;
    loop {
        run_enrolled(&edr, enroll_again).await?;
        if !is_running() {
            return Ok(());
        }
        enroll_again = true;
    }
}

/// The pipeline with one identity: until the service stops, or the manager refused the
/// keepalive 3 times (the identity is then deleted).
async fn run_enrolled(edr: &Arc<EdrExecutor>, enroll_again: bool) -> anyhow::Result<()> {
    info!("Starting ProVigil Unified Windows Endpoint Agent pipeline");

    // Load dynamic configuration
    let mut config = AgentConfig::load_or_default(None);
    while config.manager_url.trim().is_empty() {
        error!("No manager address: set manager_url in provigil-agent.json (the installer writes it) or PROVIGIL_MANAGER_URL; checking again in 60 s");
        if !wait_unless_stopped(Duration::from_secs(60)).await {
            return Ok(());
        }
        config = AgentConfig::load_or_default(None);
    }
    info!(
        manager_url = %config.manager_url,
        agent_name = %config.agent_name,
        "Configuration loaded"
    );

    edr.enabled.store(config.active_response_enabled, Ordering::SeqCst);

    // Resolve agent identity: load local or enroll (not the refused one again, nor client.keys)
    let identity = match (!enroll_again).then(AgentIdentity::load_local).flatten() {
        Some(ident) => {
            info!(agent_id = %ident.agent_id, "Loaded existing agent enrollment identity");
            ident
        }
        None => {
            info!("No local identity found; enrolling with ProVigil manager...");
            // the manager starts a new enrollment empty, also when it gives the same id back
            let _ = std::fs::remove_file(fim::SYNCED_FILE);
            if let Err(e) = sent::Sent::open(&sent::file()).and_then(|s| s.clear()) {
                warn!(error = %e, "What was sent to the last manager not cleared");
            }
            // never run under a made-up id: the manager would not know it and show it disconnected
            let creds = transport::Creds { tenant_key: identity::real_tenant_key(&config.tenant_key).map(String::from), ..Default::default() };
            let managers = transport::managers(&config, &creds);
            let force = identity::force_allowed(config.force_enroll, Path::new(identity::FORCE_USED_FILE));
            'enroll: loop {
                for link in managers.iter().flat_map(|m| m.links()) {
                    match AgentIdentity::enroll(link.as_ref(), &config.tenant_key, &config.agent_name, &config.groups, force).await {
                        Ok(ident) => break 'enroll ident,
                        Err(e) => warn!(error = %e, url = %link.url(), "Enrollment failed"),
                    }
                }
                warn!("Enrollment failed with every manager; trying again in 30 s");
                if !wait_unless_stopped(Duration::from_secs(30)).await {
                    return Ok(());
                }
            }
        }
    };

    // the group settings received last time, until the manager answers
    let mut group = GroupConfig::start(config, GROUP_CONFIG_FILE);
    let config = group.effective.clone();

    // Shared components
    let buffer = Arc::new(EventBuffer::with_limits(
        config.buffer_max_events,
        &config.buffer,
        json!({ "id": &identity.agent_id, "name": &identity.agent_name }),
    ));
    let transport = Arc::new(AgentTransport::new(&config, identity.clone(), buffer.clone(), edr.clone()));
    transport.set_group_version(group.version());
    info!("Manager in use: '{}'.", transport.manager());
    buffer.push(json!({
        "event_type": "agent_status",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "agent": { "id": &identity.agent_id, "name": &identity.agent_name },
        "message": "ProVigil agent started",
    }));
    // the loops below, ended with this identity
    let mut loops = Vec::new();

    // The outcome of an upgrade, once: the helper writes it a minute after starting this agent
    {
        let (t, b, ident) = (transport.clone(), buffer.clone(), identity.clone());
        loops.push(tokio::spawn(async move {
            for _ in 0..30 {
                match t.upgrades.check_previous_upgrade_result() {
                    Some(res) if res.status == "pending" => tokio::time::sleep(Duration::from_secs(10)).await,
                    Some(res) => {
                        info!(version = %res.version, status = %res.status, "Reporting the upgrade result to the manager");
                        b.push(json!({
                            "event_type": "upgrade_notification",
                            "timestamp": res.timestamp,
                            "agent": { "id": &ident.agent_id, "name": &ident.agent_name },
                            "upgrade": res,
                        }));
                        t.send_result(&serde_json::to_value(&res).unwrap_or_default()).await;
                        break;
                    }
                    None => break,
                }
            }
        }));
    }

    // 1. Heartbeat Loop
    let transport_hb = transport.clone();
    let hb_interval = Duration::from_secs(config.heartbeat_interval_secs);
    loops.push(tokio::spawn(async move {
        while is_running() && !transport_hb.must_reenroll() {
            if let Err(e) = transport_hb.send_heartbeat().await {
                warn!(error = %e, "Heartbeat failed");
            }
            tokio::time::sleep(hb_interval).await;
        }
    }));

    // 2. Buffer Flush Loop
    let transport_flush = transport.clone();
    loops.push(tokio::spawn(async move {
        while is_running() {
            // the buffer paces the batches; wait only when there was nothing to send
            if !matches!(transport_flush.flush_events().await, Ok(n) if n > 0) {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }));

    // 3. Event channels, file integrity, registry, inventory, configuration assessment,
    // rootcheck, log files and commands
    let mut collection = start_collection(&config, &identity, &buffer, edr);

    // 4. The response programs' results (active-responses.log): sent to the manager, which
    // turns them into live response results, tamper protection state and YARA alerts
    let buffer_ar = buffer.clone();
    let (ar_id, ar_name) = (identity.agent_id.clone(), identity.agent_name.clone());
    loops.push(tokio::spawn(async move {
        let path = PathBuf::from("active-response").join("active-responses.log");
        // only what is written from now on (older lines were sent before, or are stale)
        let mut pos = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        while is_running() {
            for line in ar_log::new_lines(&path, &mut pos) {
                buffer_ar.push(json!({
                    "event_type": "ar_log",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "agent": { "id": &ar_id, "name": &ar_name },
                    "location": "active-response\\active-responses.log",
                    "log": line,
                }));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }));

    // 5. The YARA rules yara-scan uses (shared\siem-yara.rules), from the manager every hour
    let transport_yara = transport.clone();
    loops.push(tokio::spawn(async move {
        while is_running() {
            match transport_yara.fetch_yara_rules().await {
                Ok(b) => {
                    let path = PathBuf::from("shared").join("siem-yara.rules");
                    if std::fs::read(&path).ok().as_deref() != Some(b.as_slice()) {
                        let _ = std::fs::create_dir_all("shared");
                        match std::fs::write(&path, &b) {
                            Ok(()) => info!(bytes = b.len(), "YARA rules updated from the manager"),
                            Err(e) => warn!(error = %e, "YARA rules not saved"),
                        }
                    }
                }
                Err(e) => warn!(error = %e, "YARA rules not fetched"),
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }));

    // 6. The group configuration (the console's Groups page): at start and every 5 minutes;
    // new settings go to the loop below
    let (new_settings, mut settings) = tokio::sync::mpsc::channel::<AgentConfig>(1);
    let transport_cfg = transport.clone();
    loops.push(tokio::spawn(async move {
        while is_running() {
            match transport_cfg.fetch_group_config().await {
                Ok(answer) => {
                    let changed = group.on_answer(&answer);
                    transport_cfg.set_group_version(group.version());
                    if let Some(cfg) = changed {
                        let _ = new_settings.send(cfg).await;
                    }
                }
                Err(e) => warn!(error = %e, "Group configuration not fetched"),
            }
            pause(GROUP_CONFIG_EVERY, is_running).await;
        }
    }));

    info!("All ProVigil agent services, collectors, diff engines, and rootcheck monitors active");

    // Until stopped: new group settings restart the collection loops; the transport, buffer,
    // keepalive and commands go on
    while is_running() && !transport.must_reenroll() {
        tokio::select! {
            Some(cfg) = settings.recv() => {
                collection.stop().await;
                transport.set_config(cfg.clone());
                buffer.set_limits(&cfg.buffer);
                collection = start_collection(&cfg, &identity, &buffer, edr);
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }

    collection.stop().await;
    loops.iter().for_each(|t| t.abort());

    if is_running() {
        warn!(agent_id = %identity.agent_id, "The manager refused this agent 3 times in a row (key refused or agent removed); enrolling again");
        if let Err(e) = std::fs::remove_file(identity::IDENTITY_FILE) {
            warn!(error = %e, "Agent identity file not deleted");
        }
        return Ok(());
    }

    // Flush remaining buffer on termination
    let _ = transport.flush_events().await;
    transport.send_stopping().await;
    info!("ProVigil Agent pipeline stopped gracefully.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Starts the collection loops as `run_enrolled` does (long scans underway, a command
    /// running), stops them as the service does and measures the stop. Run alone: it stops
    /// the agent's global flag and changes the working folder.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn stop_time_live() {
        let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_test_writer().try_init();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).unwrap();
        std::fs::write(watched.join("a.txt"), "a").unwrap();
        let ping = "ping -n 120 127.0.0.1".to_string();
        let config = AgentConfig {
            fim_paths: vec![PathBuf::from(r"C:\Windows\System32"), watched.clone()],
            fim_realtime: vec![watched.to_string_lossy().into_owned()],
            localfiles: vec![config::LocalFile { log_format: "command".into(), command: ping.clone(), frequency: 1, ..Default::default() }],
            commands: vec![commands::ScheduledCommand { name: "ping".into(), command: ping, ..Default::default() }],
            ..AgentConfig::default()
        };
        let identity = AgentIdentity {
            agent_id: "999".into(),
            agent_name: "stop-test".into(),
            tenant_id: String::new(),
            auth_token: String::new(),
            enrolled_at: chrono::Utc::now(),
        };
        let buffer = Arc::new(EventBuffer::new(1_000_000));
        let edr = EdrExecutor::new();
        // at 2 s every scan is underway; at 12 s the log file command runs too (it starts 10 s in)
        for after in [2, 12] {
            service::RUNNING.store(true, Ordering::SeqCst);
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            let collection = rt.block_on(async {
                let c = start_collection(&config, &identity, &buffer, &edr);
                tokio::time::sleep(Duration::from_secs(after)).await;
                println!("{after} s: running before stop: {:?}", still_running());
                let t = Instant::now();
                service::request_stop();
                c.stop().await;
                t.elapsed()
            });
            let t = Instant::now();
            rt.shutdown_timeout(Duration::from_secs(10));
            let runtime = t.elapsed();
            println!("{after} s: collection stop {collection:?}, runtime shutdown {runtime:?}, still running: {:?}", still_running());
            assert!(collection + runtime < Duration::from_secs(3), "stop took {:?}", collection + runtime);
        }
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
    }
}
