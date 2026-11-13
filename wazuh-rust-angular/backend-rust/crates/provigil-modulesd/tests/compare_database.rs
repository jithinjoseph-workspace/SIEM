//! The database module's start-up, old service vs new: same requests to the agent database, same
//! rows and files afterwards, same log lines.

use std::path::Path;
use std::sync::{Arc, Mutex};

use provigil_agentdb::{Engine, Env, Settings};

struct QuietEnv;
impl Env for QuietEnv {
    fn log(&self, _: &str, _: &[u8]) {}
    fn time(&self) -> i64 {
        1_800_000_000
    }
    fn router_send(&self, _: i32, _: &[u8]) {}
    fn send_peer(&self, _: i32, _: &[u8]) -> i32 {
        0
    }
    fn is_single_node(&self) -> (i32, i32) {
        (1, 0)
    }
}

/// An in-process agent database that records every request.
struct Recorder {
    engine: Engine,
    seen: Mutex<Vec<String>>,
}

impl Recorder {
    fn new(home: &Path) -> Arc<Recorder> {
        Arc::new(Recorder { engine: Engine::new(home, Settings::default(), Arc::new(QuietEnv)), seen: Mutex::default() })
    }
    fn ask(&self, q: &str) -> String {
        self.seen.lock().unwrap().push(q.to_string());
        String::from_utf8_lossy(&self.engine.handle(q.as_bytes(), 0).1).into_owned()
    }
}

impl provigil_ipc::agentdb::AgentDb for Recorder {
    fn query(&self, q: &str) -> Result<String, provigil_ipc::agentdb::DbError> {
        Ok(self.ask(q))
    }
}

struct OldDb(Arc<Recorder>);
#[async_trait::async_trait]
impl siem_ipc::wdbc::WdbQuery for OldDb {
    async fn query(&self, q: &str) -> Result<String, siem_ipc::wdbc::WdbcError> {
        Ok(self.0.ask(q))
    }
}

/// A manager home: keys, groups, a legacy group file, a leftover database, timestamps, and a
/// global.db holding an agent the keys no longer have.
fn home(conf: &str) -> (tempfile::TempDir, Arc<Recorder>) {
    let h = tempfile::tempdir().unwrap();
    let p = |r: &str| h.path().join(r);
    for d in ["etc/shared/default", "etc/shared/grp1", "queue/db", "queue/tasks", "backup/db", "queue/agent-groups", "queue/diff/oldpc", "queue/rids", "logs", "var/run"] {
        std::fs::create_dir_all(p(d)).unwrap();
    }
    std::fs::write(p("etc/ossec.conf"), conf).unwrap();
    std::fs::write(
        p("etc/client.keys"),
        "001 pc-one 10.0.0.1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
         002 pc-two any bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\
         003 pc-three 192.168.1.0/24 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
    )
    .unwrap();
    std::fs::write(p("queue/agents-timestamp"), "001 pc-one 10.0.0.1 2026-11-01 10:20:30\n007 oldpc any 2026-10-01 09:00:00\n003 pc-three any bad-date x\n").unwrap();
    std::fs::write(p("queue/agent-groups/003"), "grp1,grp2\n").unwrap();
    std::fs::write(p("queue/agent-groups/abc"), "grp1\n").unwrap();
    std::fs::write(p("queue/rids/007"), "1:2\n").unwrap();
    std::fs::write(p("queue/db/099.db"), "").unwrap();
    std::fs::write(p("queue/db/strange"), "").unwrap();
    std::fs::write(p("queue/db/5x"), "").unwrap();
    let db = Recorder::new(h.path());
    db.ask(r#"global insert-agent {"id":7,"name":"oldpc","ip":null,"register_ip":"any","internal_key":"k","group":null,"date_add":1}"#);
    db.ask("global insert-agent-group gone");
    db.seen.lock().unwrap().clear();
    (h, db)
}

fn dump(db: &Recorder) -> Vec<String> {
    [
        "global sql SELECT id, name, register_ip, internal_key, CASE WHEN id = 0 THEN 0 ELSE date_add END AS date_add, `group`, connection_status, node_name, version FROM agent ORDER BY id",
        "global sql SELECT name FROM `group` ORDER BY name",
        "global sql SELECT id_agent, id_group FROM belongs ORDER BY id_agent, id_group",
    ]
    .iter()
    .map(|q| db.engine.handle(q.as_bytes(), 0).1)
    .map(|a| String::from_utf8_lossy(&a).into_owned())
    .collect()
}

fn files(home: &Path) -> Vec<String> {
    let mut v = Vec::new();
    for d in ["queue/db", "queue/agent-groups", "queue/diff", "queue/rids"] {
        let mut names: Vec<String> = std::fs::read_dir(home.join(d)).map(|r| r.flatten().map(|e| format!("{d}/{}", e.file_name().to_string_lossy())).collect()).unwrap_or_else(|_| vec![format!("{d} (gone)")]);
        names.sort();
        v.extend(names);
    }
    v.push(std::fs::read_to_string(home.join("queue/agents-timestamp")).unwrap_or_default());
    v
}

/// Log lines without their time stamps.
fn log_lines(home: &Path) -> Vec<String> {
    std::fs::read_to_string(home.join("logs/ossec.log")).unwrap_or_default().lines().map(|l| without_location(l.get(20..).unwrap_or(l))).collect()
}

/// The old logger's debug-mode `[pid] file:line at function():` part, removed.
fn without_location(l: &str) -> String {
    match (l.find('['), l.find("): ")) {
        (Some(a), Some(b)) if a < b => format!("{}{}", &l[..a], &l[b + 1..]),
        _ => l.to_string(),
    }
}

/// The time a sync took varies from run to run.
fn without_times(l: String) -> String {
    match l.find("wm_sync_agents(): ") {
        Some(p) => format!("{}wm_sync_agents(): <ms>", &l[..p]),
        None => l,
    }
}

/// A cluster section without a node type: counts as a worker (legacy group files only deleted).
const WORKER_CONF: &str = "<ossec_config>\n  <cluster>\n    <node_name>node01</node_name>\n    <disabled>yes</disabled>\n  </cluster>\n</ossec_config>\n";
/// No cluster: a master (legacy group files imported).
const MASTER_CONF: &str = "<ossec_config>\n</ossec_config>\n";

#[test]
fn startup_matches_old() {
    // one test: the old service needs the process's working folder
    compare(WORKER_CONF);
    compare(MASTER_CONF);
}

fn compare(conf: &str) {
    let start = std::env::current_dir().unwrap();

    // old: relative paths, so it runs in its home folder
    let (old_home, old_db) = home(conf);
    std::env::set_current_dir(old_home.path()).unwrap();
    {
        let log = Arc::new(siem_log::WLog::new_server("provigil-modulesd", Path::new("")));
        let _ = log.init();
        log.now_daemon();
        log.now_debug();
        log.now_debug();
        let cfg = siem_modulesd::database::WmDatabase { sync_agents: true, real_time: false, interval: 3600, max_queued_events: 0 };
        let d = siem_modulesd::database::Database::new(cfg, log, Arc::new(OldDb(old_db.clone())));
        let rt = tokio::runtime::Runtime::new().unwrap();
        // start-up, then the loop's first wait
        let _ = rt.block_on(async { tokio::time::timeout(std::time::Duration::from_secs(3), d.main()).await });
    }
    std::env::set_current_dir(&start).unwrap();

    let (new_home, new_db) = home(conf);
    {
        let log = Arc::new(provigil_daemon::Log::open(new_home.path(), "provigil-modulesd"));
        log.set_debug(2);
        let s = provigil_modulesd::database::Settings { sync_agents: true, real_time: false, interval: 3600, max_queued_events: 0 };
        let mut d = provigil_modulesd::database::Database::new(s, log, new_db.clone(), new_home.path());
        d.startup();
    }

    let mut diffs = Vec::new();
    let (qo, qn) = (old_db.seen.lock().unwrap().clone(), new_db.seen.lock().unwrap().clone());
    if qo != qn {
        diffs.push(format!("requests\n  old: {qo:#?}\n  new: {qn:#?}"));
    }
    let (ro, rn) = (dump(&old_db), dump(&new_db));
    if ro != rn {
        diffs.push(format!("rows\n  old: {ro:#?}\n  new: {rn:#?}"));
    }
    let (fo, fnw) = (files(old_home.path()), files(new_home.path()));
    if fo != fnw {
        diffs.push(format!("files\n  old: {fo:#?}\n  new: {fnw:#?}"));
    }
    // the old logger adds its start-up lines; the module's lines must match in order
    let keep = |v: Vec<String>| v.into_iter().filter(|l| l.contains("provigil-modulesd")).map(without_times).collect::<Vec<_>>();
    let (lo, ln) = (keep(log_lines(old_home.path())), keep(log_lines(new_home.path())));
    if lo != ln {
        diffs.push(format!("log\n  old: {lo:#?}\n  new: {ln:#?}"));
    }
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
    // the scenario did what it is for
    let rows = dump(&new_db).join(" ");
    if conf == MASTER_CONF {
        assert!(qn.iter().any(|q| q.contains("set-agent-groups")), "legacy group file imported");
        assert!(rows.contains(r#""group":"grp1"#), "{rows}");
    } else {
        assert!(!qn.iter().any(|q| q.contains("set-agent-groups")), "a worker only deletes legacy group files");
    }
}

/// Spec M-4: an empty key list never removes the registered agents; a key list without one
/// agent still removes that one.
#[test]
fn empty_key_list_removes_nothing() {
    let (h, db) = home(MASTER_CONF);
    let log = Arc::new(provigil_daemon::Log::open(h.path(), "provigil-modulesd"));
    let s = provigil_modulesd::database::Settings { sync_agents: true, real_time: false, interval: 3600, max_queued_events: 0 };
    let d = provigil_modulesd::database::Database::new(s, log, db.clone(), h.path());
    d.sync_keys(&siem_crypto::keystore::KeyStore::default());
    assert!(dump(&db)[0].contains(r#""id":7"#), "agent 7 kept");
    assert!(!db.seen.lock().unwrap().iter().any(|q| q.starts_with("global delete-agent")));
    assert!(std::fs::read_to_string(h.path().join("logs/ossec.log")).unwrap().contains("The key list is empty: none of the 1 registered agents is removed."));
    // agent 7 has no key in this list: removed
    let keys = siem_crypto::keystore::KeyStore::read(&h.path().join("etc/client.keys").to_string_lossy(), true, false).unwrap();
    d.sync_keys(&keys);
    assert!(!dump(&db)[0].contains(r#""id":7"#), "agent 7 removed");
}
