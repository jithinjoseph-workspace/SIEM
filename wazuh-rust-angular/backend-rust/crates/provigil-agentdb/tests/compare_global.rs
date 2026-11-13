//! The same `global` requests to the old implementation (siem-wdb) and to provigil-agentdb: every
//! answer, result code, log line, router message, message to the client and table row must match.

use std::sync::{Arc, Mutex};

use provigil_agentdb::{Engine, Env, Settings};

const NOW: i64 = 1_800_000_000;

#[derive(Default)]
struct Seen {
    logs: Mutex<Vec<(String, Vec<u8>)>>,
    router: Mutex<Vec<(i32, Vec<u8>)>>,
    peer: Mutex<Vec<Vec<u8>>>,
}
impl Seen {
    fn take(&self) -> (Vec<(String, Vec<u8>)>, Vec<(i32, Vec<u8>)>, Vec<Vec<u8>>) {
        (std::mem::take(&mut *self.logs.lock().unwrap()), std::mem::take(&mut *self.router.lock().unwrap()), std::mem::take(&mut *self.peer.lock().unwrap()))
    }
}

struct OldEnv(Arc<Seen>);
impl siem_wdb::wdb::WdbEnv for OldEnv {
    fn log(&self, level: &str, msg: &[u8]) {
        self.0.logs.lock().unwrap().push((level.into(), msg.to_vec()));
    }
    fn time(&self) -> i64 {
        NOW
    }
    fn timeofday(&self) -> siem_wdb::wdb::state::Tv {
        siem_wdb::wdb::state::Tv { sec: NOW, usec: 0 }
    }
    fn router_send(&self, h: i32, m: &[u8]) {
        self.0.router.lock().unwrap().push((h, m.to_vec()));
    }
    fn send_peer(&self, _: i32, m: &[u8]) -> i32 {
        self.0.peer.lock().unwrap().push(m.to_vec());
        0
    }
    fn is_single_node(&self) -> (i32, i32) {
        (1, 0)
    }
    fn sleep_ms(&self, _: u64) {}
    fn utc_offset(&self, _: i64) -> i64 {
        0
    }
}

struct NewEnv(Arc<Seen>);
impl Env for NewEnv {
    fn log(&self, level: &str, msg: &[u8]) {
        self.0.logs.lock().unwrap().push((level.into(), msg.to_vec()));
    }
    fn time(&self) -> i64 {
        NOW
    }
    fn router_send(&self, h: i32, m: &[u8]) {
        self.0.router.lock().unwrap().push((h, m.to_vec()));
    }
    fn send_peer(&self, _: i32, m: &[u8]) -> i32 {
        self.0.peer.lock().unwrap().push(m.to_vec());
        0
    }
    fn is_single_node(&self) -> (i32, i32) {
        (1, 0)
    }
    fn sleep_ms(&self, _: u64) {}
}

fn home() -> tempfile::TempDir {
    let h = tempfile::tempdir().unwrap();
    for d in ["queue/db", "queue/tasks", "backup/db"] {
        std::fs::create_dir_all(h.path().join(d)).unwrap();
    }
    h
}

/// Log lines that differ on purpose (texts with old internal names); none yet.
fn same_log(a: &(String, Vec<u8>), b: &(String, Vec<u8>)) -> bool {
    a == b
}

fn show(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

/// Every request of the global actor, valid and invalid.
fn requests() -> Vec<String> {
    let mut r: Vec<String> = Vec::new();
    let mut q = |s: &str| r.push(s.to_string());
    // dispatch errors
    q("global");
    q("nothing here");
    q("global nosuch");
    q("global sql");
    q("global sql SELECT id, name FROM agent ORDER BY id");
    q("global sql SELECT nosuchcolumn FROM agent");
    q("global sql SELECT 1.5 AS a, 2 AS b, NULL AS c, 'x' AS d, 1e20 AS e, -0.25 AS f");
    // agents
    q(r#"global insert-agent {"id":1,"name":"pc1","ip":"10.0.0.1","register_ip":"any","internal_key":"k1","group":"default","date_add":1700000000}"#);
    q(r#"global insert-agent {"id":2,"name":"pc2","ip":"10.0.0.2","register_ip":"10.0.0.2","date_add":1700000001}"#);
    q(r#"global insert-agent {"id":3,"name":"pc3","date_add":1700000002,"group":"web,db"}"#);
    q(r#"global insert-agent {"id":4,"name":"pc4","date_add":1,"group":"bad name"}"#);
    q(r#"global insert-agent {"id":1,"name":"dup","date_add":1}"#);
    q(r#"global insert-agent {"id":"x","name":"pc","date_add":1}"#);
    q(r#"global insert-agent {"id":5,"name":"pc5""#);
    q(r#"global insert-agent {"id":5,"name":"pc5","date_add":1} trailing"#);
    q("global insert-agent");
    q(r#"global update-agent-name {"id":1,"name":"pc1-renamed"}"#);
    q(r#"global update-agent-name {"id":1}"#);
    q(r#"global update-agent-data {"id":1,"os_name":"Windows 11","os_version":"10.0.26100","os_major":"10","os_minor":"0","os_platform":"windows","os_arch":"x86_64","version":"ProVigil v0.1.0","config_sum":"c","merged_sum":"m","manager_host":"mgr","node_name":"node01","agent_ip":"10.0.0.11","connection_status":"active","sync_status":"syncreq","group_config_status":"synced","labels":"env:prod\nteam:it\nnocolon"}"#);
    q(r#"global update-agent-data {"id":2,"os_name":"Ubuntu","connection_status":"active"}"#);
    q(r#"global update-agent-data {"id":0,"version":"ProVigil v0.1.0"}"#);
    q(r#"global update-agent-data {"name":"x"}"#);
    q("global get-labels 1");
    q("global get-labels 2");
    q("global get-labels");
    q(r#"global update-keepalive {"id":2,"connection_status":"active","sync_status":"syncreq_keepalive"}"#);
    q(r#"global update-keepalive {"id":1,"connection_status":"active","sync_status":"syncreq_keepalive"}"#);
    q(r#"global update-keepalive {"id":2,"connection_status":"active"}"#);
    q(r#"global update-connection-status {"id":2,"connection_status":"disconnected","sync_status":"syncreq_status","status_code":3}"#);
    q(r#"global update-connection-status {"id":2,"connection_status":"active","sync_status":"syncreq","status_code":0}"#);
    q(r#"global update-connection-status {"id":2}"#);
    q(r#"global update-status-code {"id":2,"status_code":7,"version":"v1","sync_status":"syncreq"}"#);
    q(r#"global update-status-code {"id":2,"status_code":7,"sync_status":"synced"}"#);
    q(r#"global update-status-code {"id":2,"status_code":7,"version":5,"sync_status":"synced"}"#);
    q("global select-agent-name 1");
    q("global select-agent-name 99");
    q("global select-agent-group 3");
    q(r#"global find-agent {"name":"pc2","ip":"10.0.0.2"}"#);
    q(r#"global find-agent {"name":"pc1","ip":"any"}"#);
    q(r#"global find-agent {"name":"pc1"}"#);
    q("global get-agent-info 1");
    q("global get-agent-info 0");
    q("global get-agent-info 77");
    // groups
    q("global insert-agent-group web");
    q("global insert-agent-group db");
    q("global insert-agent-group default");
    q("global insert-agent-group bad/name");
    q("global insert-agent-group ..");
    q("global insert-agent-group back\\slash");
    q("global find-group web");
    q("global find-group nosuch");
    q("global select-groups");
    q(r#"global set-agent-groups {"mode":"override","sync_status":"syncreq","data":[{"id":1,"groups":["web","db"]},{"id":2,"groups":["default"]}]}"#);
    q(r#"global set-agent-groups {"mode":"append","data":[{"id":1,"groups":["default"]}]}"#);
    q(r#"global set-agent-groups {"mode":"empty_only","data":[{"id":1,"groups":["db"]}]}"#);
    q(r#"global set-agent-groups {"mode":"remove","data":[{"id":1,"groups":["web","nosuch"]}]}"#);
    q(r#"global set-agent-groups {"mode":"override","data":[{"id":9,"name":"newpc","groups":["web"]}]}"#);
    q(r#"global set-agent-groups {"mode":"override","data":[{"id":8,"groups":["web"]}]}"#);
    q(r#"global set-agent-groups {"mode":"override","data":[{"id":1,"groups":["a/b"]}]}"#);
    q(r#"global set-agent-groups {"mode":"weird","data":[]}"#);
    q(r#"global set-agent-groups {"mode":"append"}"#);
    q(r#"global set-agent-groups {"mode":"append","data":[{"groups":["web"]}]}"#);
    q("global select-group-belong 1");
    q("global select-group-belong 2");
    q("global get-group-agents web last_id 0");
    q("global get-group-agents web");
    q("global get-group-agents web last_id");
    q("global get-group-agents");
    q("global get-groups-integrity 0000000000000000000000000000000000000000");
    q("global get-groups-integrity 1234");
    q(r#"global sync-agent-groups-get {"condition":"sync_status","set_synced":true,"get_global_hash":true}"#);
    q("global get-groups-integrity 0000000000000000000000000000000000000000");
    q(r#"global sync-agent-groups-get {"condition":"all","last_id":0,"agent_registration_delta":10}"#);
    q(r#"global sync-agent-groups-get {"get_global_hash":true}"#);
    q(r#"global sync-agent-groups-get {}"#);
    q(r#"global sync-agent-groups-get {"condition":"other"}"#);
    q(r#"global sync-agent-groups-get {"last_id":-1}"#);
    q(r#"global sync-agent-groups-get {"#);
    q("global get-distinct-groups");
    q("global get-distinct-groups 0");
    q("global recalculate-agent-group-hashes");
    q("global delete-group db");
    q("global select-group-belong 1");
    q("global delete-group nosuch");
    // sync
    q("global sync-agent-info-get");
    q("global sync-agent-info-get last_id 1");
    q("global sync-agent-info-get");
    q(r#"global sync-agent-info-set [{"id":2,"name":"pc2","ip":"10.0.0.22","version":"v2","connection_status":"active","last_keepalive":1700000500,"labels":[{"key":"k","value":"v","id":2},{"key":5,"value":"x","id":2}]}]"#);
    q(r#"global sync-agent-info-set [{"name":"x","labels":[]}]"#);
    q("global sync-agent-info-set [");
    q("global get-labels 2");
    // connections
    q("global get-agents-by-connection-status 0 active");
    q("global get-agents-by-connection-status 0 active node01 10");
    q("global get-agents-by-connection-status 0 active node01");
    q("global get-agents-by-connection-status 0");
    q("global disconnect-agents 0 1800000100 syncreq");
    q("global disconnect-agents 0 1800000100");
    q("global disconnect-agents 0");
    q("global get-all-agents last_id 0");
    q("global get-all-agents last_id 2");
    q("global get-all-agents context");
    q("global get-all-agents other");
    q("global get-all-agents last_id");
    q("global reset-agents-connection syncreq");
    q("global get-agent-info 1");
    // maintenance
    q("global get_fragmentation");
    q("global vacuum");
    q("global sql SELECT key, value FROM metadata ORDER BY key");
    q("global sleep 1");
    q("global sleep");
    q("global sleep -1");
    q("global backup");
    q("global backup other");
    q("global backup get");
    q("global backup create");
    q("global backup get");
    q(r#"global backup restore {"snapshot":"nosuch.gz"}"#);
    q("global backup restore {");
    q(r#"global insert-agent {"id":40,"name":"after-backup","date_add":1}"#);
    q("global backup restore");
    q("global get-agent-info 40");
    q(r#"global backup restore {"save_pre_restore_state":true}"#);
    q("global backup get");
    // deletes last
    q("global delete-agent 3");
    q("global delete-agent 77");
    q("global sql SELECT * FROM belongs ORDER BY id_group, id_agent");
    q("global sql SELECT * FROM labels ORDER BY id, key");
    r
}

/// Every table of the global database, rows in a fixed order.
fn dump(ask: &dyn Fn(&str) -> Vec<u8>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for t in ["agent", "labels", "`group`", "belongs", "metadata", "info"] {
        let a = ask(&format!("global sql SELECT * FROM {t} ORDER BY rowid"));
        out.push((t.to_string(), show(&a)));
    }
    out
}

#[test]
fn global_matches_old() {
    let (ho, hn) = (home(), home());
    let (so, sn) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let old = siem_wdb::wdb::Wdbd::new(siem_wdb::wdb::WdbConfig::default(), ho.path().to_path_buf(), Arc::new(OldEnv(so.clone())));
    let new = Engine::new(hn.path(), Settings::default(), Arc::new(NewEnv(sn.clone())));
    let mut diffs = Vec::new();
    // the two home folders differ: show both as <home>
    let (po_, pn_) = (ho.path().to_string_lossy().into_owned(), hn.path().to_string_lossy().into_owned());
    let home_o = |v: Vec<u8>| without_home(&v, &po_);
    let home_n = |v: Vec<u8>| without_home(&v, &pn_);
    for (n, req) in requests().iter().enumerate() {
        // decision D-4: on Windows only the new backups work; covered by `backups_work` below
        if cfg!(windows) && (req.contains("backup create") || req.contains("backup restore")) {
            continue;
        }
        let (ro, ao) = old.parse(req.as_bytes(), 7);
        let (rn, an) = new.handle(req.as_bytes(), 7);
        let (ao, an) = (home_o(ao), home_n(an));
        let (lo, uo, po) = so.take();
        let (ln, un, pn) = sn.take();
        let lo: Vec<_> = lo.into_iter().map(|(l, m)| (l, home_o(m))).collect();
        let ln: Vec<_> = ln.into_iter().map(|(l, m)| (l, home_n(m))).collect();
        if regex_lite_replace(&show(&ao)) != regex_lite_replace(&show(&an)) || ro != rn {
            diffs.push(format!("#{n} {req}\n   answer old {ro} {:?}\n   answer new {rn} {:?}", show(&ao), show(&an)));
        }
        if lo.len() != ln.len() || !lo.iter().zip(&ln).all(|(a, b)| same_log(a, b)) {
            let f = |v: &Vec<(String, Vec<u8>)>| v.iter().map(|(l, m)| format!("{l}: {}", show(m))).collect::<Vec<_>>().join("\n      ");
            diffs.push(format!("#{n} {req}\n   logs old:\n      {}\n   logs new:\n      {}", f(&lo), f(&ln)));
        }
        if uo != un {
            diffs.push(format!("#{n} {req}\n   router old {uo:?}\n   router new {un:?}"));
        }
        if po != pn {
            diffs.push(format!("#{n} {req}\n   to client old {:?}\n   to client new {:?}", po.iter().map(|m| show(m)).collect::<Vec<_>>(), pn.iter().map(|m| show(m)).collect::<Vec<_>>()));
        }
    }
    // the manager row's date_add is the real clock of the database engine
    let norm = |s: String| regex_lite_replace(&s);
    let dold = dump(&|q: &str| old.parse(q.as_bytes(), 0).1);
    let dnew = dump(&|q: &str| new.handle(q.as_bytes(), 0).1);
    so.take();
    sn.take();
    for ((t, a), (_, b)) in dold.into_iter().zip(dnew) {
        if norm(a.clone()) != norm(b.clone()) {
            diffs.push(format!("table {t}\n   old {a}\n   new {b}"));
        }
    }
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

/// Masks the real-clock columns (`date_add` of the manager row, disconnection times set by SQL).
fn regex_lite_replace(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find("\"date_add\":") {
        out.push_str(&rest[..p + 11]);
        rest = &rest[p + 11..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        let v = &rest[..end];
        out.push_str(if v.len() == 10 && v.starts_with("17") { "T" } else { v });
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// The text with the home folder (plain, or JSON-escaped with doubled backslashes) as `<home>`.
fn without_home(v: &[u8], home: &str) -> Vec<u8> {
    let escaped = home.replace('\\', "\\\\");
    show(v).replace(&escaped, "<home>").replace(home, "<home>").into_bytes()
}

#[test]
fn backups_work() {
    let h = home();
    let seen = Arc::new(Seen::default());
    let e = Engine::new(h.path(), Settings::default(), Arc::new(NewEnv(seen.clone())));
    let ask = |q: &str| show(&e.handle(q.as_bytes(), 0).1);
    assert_eq!(ask(r#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#), "ok");
    let created = ask("global backup create");
    assert!(created.starts_with("ok [\"backup/db/global.db-backup-"), "{created}");
    assert!(ask("global backup get").contains("global.db-backup-"));
    assert_eq!(ask(r#"global insert-agent {"id":2,"name":"pc2","date_add":1}"#), "ok");
    assert_eq!(ask("global backup restore"), "ok");
    assert_eq!(ask("global sql SELECT id FROM agent WHERE id = 2"), "ok []", "the restore brought back the state before pc2");
    assert_eq!(ask("global sql SELECT id FROM agent WHERE id = 1"), "ok [{\"id\":1}]");
}
