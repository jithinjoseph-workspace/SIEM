//! End-to-end tests: start sequence, policy changes, scans with a fake agent database and a
//! report collector, postponement and outputs.

use crate::agentdb::{AgentDb, DbError};
use crate::config::{InternalOptions, ModuleConfig};
use crate::event::{Event, Origin};
use crate::inventory::{COL_INITIAL, COL_OS, COL_PACKAGE};
use crate::kvstore::{KvStore, DEFAULT_COLUMN};
use crate::log::{Level, Log, MemoryLogger};
use crate::report::ReportSink;
use crate::scanner::{Scanner, StartOptions};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct FakeDb(Mutex<HashMap<String, Result<Vec<Value>, DbError>>>);
impl FakeDb {
    fn set(&self, q: &str, r: Result<Vec<Value>, DbError>) {
        self.0.lock().unwrap().insert(q.to_string(), r);
    }
}
impl AgentDb for FakeDb {
    fn query(&self, q: &str) -> Result<Vec<Value>, DbError> {
        self.0.lock().unwrap().get(q).cloned().unwrap_or(Ok(Vec::new()))
    }
}

#[derive(Default)]
struct Reports(Mutex<Vec<String>>);
impl ReportSink for Reports {
    fn push(&self, line: String) {
        self.0.lock().unwrap().push(line);
    }
}
impl Reports {
    fn take(&self) -> Vec<String> {
        self.0.lock().unwrap().drain(..).collect()
    }
}

struct Env {
    home: tempfile::TempDir,
    log: Arc<MemoryLogger>,
    db: Arc<FakeDb>,
    reports: Arc<Reports>,
}

impl Env {
    fn new() -> Env {
        Env { home: tempfile::tempdir().unwrap(), log: Arc::default(), db: Arc::default(), reports: Arc::default() }
    }
    fn cfg(&self, vd: Value, opts: InternalOptions) -> ModuleConfig {
        ModuleConfig::new(vd.as_object().unwrap().clone(), &opts, "Host1")
    }
    fn start_with(&self, vd: Value, opts: InternalOptions) -> Option<Scanner> {
        Scanner::start(
            self.home.path(),
            Log::new(self.log.clone()),
            self.cfg(vd, opts),
            StartOptions {
                agent_db: self.db.clone(),
                report_sink: Some(self.reports.clone()),
                report_socket: None,
                manager_name: "mgr".into(),
                content_updater: false,
                router: None,
                stream: None,
                threads: false,
            },
        )
    }
    fn start(&self) -> Scanner {
        self.start_with(json!({"enabled":"yes","index-status":"yes","cti-url":"http://127.0.0.1:1/x"}), InternalOptions::default()).unwrap()
    }
    fn has(&self, l: Level, m: &str) -> bool {
        self.log.has(l, m)
    }
}

fn queued(s: &Scanner) -> Vec<Value> {
    let mut v = Vec::new();
    while let Some(e) = s.take_next() {
        v.push(e.body);
    }
    v
}

// ---- 19.1 start and policy ----------------------------------------------------------------

#[test]
fn start_failures_and_disabled_state() {
    let e = Env::new();
    assert!(e.start_with(json!({"enabled":"true","index-status":"yes","cti-url":"U"}), InternalOptions::default()).is_none());
    assert!(e.has(Level::Error, "Vulnerability scanner start failed: Invalid input.."));
    assert!(e.start_with(json!({"enabled":"yes","index-status":"yes","feed-update-interval":"bogus","cti-url":"U"}), InternalOptions::default()).is_none());
    assert!(e.has(Level::Error, "Vulnerability scanner start failed: Invalid feed update interval.."));

    assert!(e.start_with(json!({"enabled":"no","index-status":"yes","cti-url":"U"}), InternalOptions::default()).is_none());
    assert!(e.has(Level::Info, "Vulnerability scanner module is disabled."));
    {
        let st = KvStore::open(&e.home.path().join("queue/vd/state_track")).unwrap();
        assert_eq!(st.get_text(DEFAULT_COLUMN, "vulnerability_scanner_previous_state").unwrap().as_deref(), Some("disabled"));
    }
    let s = e.start();
    assert_eq!(queued(&s), vec![json!({"action":"reboot","no-index":false})]);
    assert!(e.has(Level::Info, "Vulnerability scanner module started."));
    // Fresh start: no feed maps.
    assert!(e.has(Level::Error, "Error opening the database: Couldn't find column family: 'vendor_map'."));
    assert!(!e.home.path().join("queue/vd_updater").exists());
}

#[test]
fn manager_and_cluster_policy() {
    let e = Env::new();
    let state = |k: &str, v: &str| {
        let st = KvStore::open(&e.home.path().join("queue/vd/state_track")).unwrap();
        st.put_text(DEFAULT_COLUMN, k, v).unwrap();
    };
    let vd = json!({"enabled":"yes","index-status":"yes","cti-url":"U"});
    state("manager_scan_previous_state", "enabled");
    let s = e.start_with(vd.clone(), InternalOptions::default()).unwrap();
    assert_eq!(queued(&s), vec![json!({"action":"deleteAgent","agent_info":{"agent_id":"000"}})]);
    drop(s);
    let s = e.start_with(vd.clone(), InternalOptions { disable_scan_manager: false, ..Default::default() }).unwrap();
    assert_eq!(queued(&s), vec![json!({"action":"scanAgent","agent_info":{"agent_id":"000"}})]);
    drop(s);
    state("manager_scan_previous_state", "disabled");
    state("cluster_node_name", "other");
    let s = e.start_with(vd.clone(), InternalOptions::default()).unwrap();
    assert!(queued(&s).is_empty());
    assert!(e.has(Level::Debug, "Vulnerability scanner in manager still disabled"));
    drop(s);
    state("cluster_previous_name", "a");
    let s = e.start_with(vd, InternalOptions::default()).unwrap();
    assert_eq!(queued(&s), vec![json!({"action":"reboot","no-index":false})]);
    assert!(e.has(Level::Debug, "Cluster name changed (agents re-scan needed)"));
}

// ---- 19.7 scanning ------------------------------------------------------------------------

fn cve(id: &str, product: &str, versions: Value, extra: Value) -> Value {
    let mut cna = json!({
        "providerMetadata":{"orgId":"o","shortName":"nvd"},
        "descriptions":[{"lang":"en","value":format!("{id} text")}],
        "references":[{"url":"https://a"},{"url":"https://b"}],
        "problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}],
        "metrics":[{"format":"CVSS","cvssV3_1":{"baseScore":7.25,"baseSeverity":"HIGH","version":"3.1","attackVector":"NETWORK","scope":"CHANGED"}}],
        "affected":[{"vendor":"acme","product":product,"defaultStatus":"unaffected","versions":versions}]
    });
    if let Some(o) = extra.as_object() {
        for (k, v) in o {
            cna[k] = v.clone();
        }
    }
    json!({"resource":id,"type":"create","offset":5,"payload":{"cveMetadata":{"cveId":id,"state":"PUBLISHED","assignerShortName":"mitre","datePublished":"2099-01-01","dateUpdated":"2099-01-02"},"containers":{"cna":cna}}})
}

fn load_feed(s: &Scanner) {
    let mut c = s.core.lock().unwrap();
    let log = Log::null();
    let lt = |v: &str| json!([{"status":"affected","version":"0","lessThan":v}]);
    let resources = vec![
        json!({"resource":"FEED-GLOBAL","type":"create","payload":{"format":[],"source":[],"prefix":[],"contains":[],"adp_default_array":["nvd"],
            "adp_descriptions":{"nvd":{"adp":"nvd","cvss":"nvd","description":"nvd"},"cisa":{"adp":"cisa","cvss":"cisa","description":"cisa"},"redhat":{"adp":"redhat","cvss":"cisa","description":"nvd"}}}}),
        json!({"resource":"OSCPE-GLOBAL","type":"create","payload":{"Microsoft Windows 10":"microsoft:windows_10_$(DISPLAY_VERSION):$(VERSION)","ubuntu":"canonical:ubuntu_linux:$(VERSION)"}}),
        json!({"resource":"CNA-MAPPING-GLOBAL","type":"create","payload":{"cnaMapping":{},"platformEquivalence":{},"majorVersionEquivalence":{}}}),
        cve("CVE-2024-0001", "openssl", lt("3.0.5"), json!({})),
        cve("CVE-2024-0002", "curl", lt("8.0"), json!({})),
        cve("CVE-2024-0003", "windows_10_22h2", lt("10.0.19045.4000"), json!({"x_remediations":{"windows":[{"anyOf":["KB5001"]}]}})),
        cve("CVE-2024-0004", "windows_10_22h2", lt("10.0.19045.4000"), json!({})),
        cve("CVE-2024-0005", "chrome", lt("120.0.6099.109"), json!({"x_remediations":{"windows":[{"anyOf":["KB9"]}]}})),
        cve("CVE-2024-0006", "express", lt("5.0.0"), json!({})),
        cve("CVE-2024-0007", "onlycvss2", lt("9"), json!({"metrics":[{"format":"CVSS","cvssV2_0":{"baseScore":5.0,"version":"2.0"}}]})),
    ];
    for r in resources {
        c.feed.apply_resource(&r, &log).unwrap();
    }
    c.feed.load_maps(2048).unwrap();
}

fn agent(id: &str) -> Value {
    json!({"agent_id":id,"agent_ip":"10.0.0.1","agent_name":format!("host-{id}"),"agent_version":"v1"})
}
fn delta(id: &str, dt: &str, op: &str, data: Value) -> Event {
    Event { origin: Origin::Delta, body: json!({"agent_info":agent(id),"data_type":dt,"operation":op,"data":data}) }
}
fn pkg(name: &str, version: &str, format: &str, vendor: &str) -> Value {
    json!({"name":name,"version":version,"format":format,"vendor":vendor,"item_id":format!("i{name}"),"architecture":"amd64","source":name,"install_time":"1700000000","size":10})
}
fn ubuntu() -> Value {
    json!({"os_name":"Ubuntu","os_platform":"ubuntu","os_codename":"jammy","os_version":"22.04","os_major":"22","os_minor":"04","architecture":"x86_64"})
}
fn windows() -> Value {
    json!({"os_name":"Microsoft Windows 10 Pro","os_platform":"windows","os_display_version":"22H2","os_version":"10.0.19045.3803","os_major":"10","os_minor":"0","os_build":"19045","architecture":"x86_64","hostname":"w"})
}

fn inv(s: &Scanner, col: &str) -> Vec<String> {
    s.core.lock().unwrap().inventory.keys_text(col, "").unwrap()
}
fn docs(s: &Scanner) -> Vec<String> {
    s.core.lock().unwrap().sink.local_keys()
}

#[test]
fn end_to_end_scans() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    let db = &e.db;
    db.set("agent 001 osinfo get ", Ok(vec![ubuntu()]));
    db.set("agent 003 osinfo get ", Ok(vec![windows()]));
    db.set("agent 003 hotfix get ", Ok(vec![json!({"hotfix":"KB0000001"})]));

    // 1. Linux OS delta: not supported.
    s.process_event(&delta("001", "dbsync_osinfo", "INSERTED", ubuntu()));
    assert!(e.has(Level::Debug, "OS scan for platform 'ubuntu' on Agent '001' is not supported."));

    // 2. Package delta: Active alert, document, inventory key.
    s.process_event(&delta("001", "dbsync_packages", "INSERTED", pkg("openssl", "3.0.2-0ubuntu1", "deb", "acme")));
    let r = e.reports.take();
    assert_eq!(r.len(), 1);
    assert!(r[0].starts_with("1:[001] (host-001) 10.0.0.1->vulnerability-detector:{\"vulnerability\":{"));
    let alert: Value = serde_json::from_str(r[0].split_once("vulnerability-detector:").unwrap().1).unwrap();
    let v = &alert["vulnerability"];
    assert_eq!((v["status"].as_str(), v["title"].as_str(), v["severity"].as_str()), (Some("Active"), Some("CVE-2024-0001 affects openssl"), Some("High")));
    assert_eq!(v["cvss"]["cvss3"]["vector"]["attack_vector"], "NETWORK");
    assert_eq!(v["package"]["condition"], "Package less than 3.0.5");
    assert_eq!(v["score"]["base"].as_f64(), Some(7.25));
    assert_eq!(docs(&s), vec!["001_iopenssl_CVE-2024-0001_5"]);
    assert_eq!(inv(&s, COL_PACKAGE), vec!["001_iopenssl"]);

    // 3. curl inserted then deleted: Solved alert, document and key gone.
    s.process_event(&delta("001", "dbsync_packages", "INSERTED", pkg("curl", "7.81.0-1ubuntu1", "deb", "acme")));
    e.reports.take();
    s.process_event(&delta("001", "dbsync_packages", "DELETED", pkg("curl", "7.81.0-1ubuntu1", "deb", "acme")));
    let r = e.reports.take();
    assert!(r[0].contains("\"status\":\"Solved\"") && r[0].contains("CVE-2024-0002 affecting curl was solved"));
    assert!(!docs(&s).iter().any(|d| d.contains("curl")));
    assert!(!inv(&s, COL_PACKAGE).contains(&"001_icurl".to_string()));

    // 4. rsync state package: documents and inventory, no alert.
    let rs = Event { origin: Origin::Rsync, body: json!({"agent_info":agent("001"),"data_type":"state","data":{"attributes_type":"syscollector_packages","attributes":pkg("curl","7.81.0","deb","acme")}}) };
    s.process_event(&rs);
    assert!(e.reports.take().is_empty());
    assert!(inv(&s, COL_PACKAGE).contains(&"001_icurl".to_string()));

    // 5. Windows OS: first scan has no alert; CVE without remediation data discarded.
    s.process_event(&delta("003", "dbsync_osinfo", "INSERTED", windows()));
    assert!(e.reports.take().is_empty());
    assert!(docs(&s).contains(&"003_Microsoft Windows 10 Pro_10.0.19045.3803_CVE-2024-0003_5".to_string()));
    assert!(!docs(&s).iter().any(|d| d.contains("CVE-2024-0004")));
    s.process_event(&delta("003", "dbsync_osinfo", "MODIFIED", windows()));
    assert!(e.has(Level::Debug2, "No changes in agent element key: 003_Microsoft Windows 10 Pro_10.0.19045.3803"));

    // 6/7. Windows package, then the hotfix that solves it.
    s.process_event(&delta("003", "dbsync_packages", "INSERTED", pkg("chrome", "120.0.6099.71", "win", "acme")));
    assert_eq!(e.reports.take().len(), 1);
    s.process_event(&delta("003", "dbsync_hotfixes", "INSERTED", json!({"hotfix":"KB9"})));
    let r = e.reports.take();
    assert_eq!(r.len(), 1);
    assert!(r[0].contains("CVE-2024-0005 affecting one or many packages was solved by KB9"));
    assert!(!docs(&s).iter().any(|d| d.contains("CVE-2024-0005")));
    // A later scan of the same package is remediated by the cached hotfix.
    s.process_event(&delta("003", "dbsync_packages", "INSERTED", pkg("chrome", "120.0.6099.71", "win", "acme")));
    assert!(e.reports.take().is_empty());

    // 8. Vendor " ": candidates with a vendor are skipped.
    s.process_event(&delta("001", "dbsync_packages", "INSERTED", pkg("express", "4.17.1", "npm", " ")));
    assert!(e.log.has_text("The vendor information is not available for Package: express"));
    assert!(e.reports.take().is_empty());

    // CVSS 2 only: under evaluation, severity '-', score -1.
    s.process_event(&delta("001", "dbsync_packages", "INSERTED", pkg("onlycvss2", "1", "deb", "acme")));
    let a: Value = serde_json::from_str(e.reports.take()[0].split_once("detector:").unwrap().1).unwrap();
    assert_eq!((a["vulnerability"]["severity"].as_str(), a["vulnerability"]["score"]["base"].as_f64()), (Some("-"), Some(-1.0)));

    // 9. Integrity clear of packages for 003: package keys and documents removed, OS documents stay,
    // one clear alert (C4).
    let ic = Event { origin: Origin::Rsync, body: json!({"agent_info":agent("003"),"data_type":"integrity_clear","data":{"attributes_type":"syscollector_packages"}}) };
    s.process_event(&ic);
    assert!(!inv(&s, COL_PACKAGE).iter().any(|k| k.starts_with("003_")));
    assert!(!docs(&s).iter().any(|d| d.starts_with("003_ichrome")));
    assert!(docs(&s).iter().any(|d| d.starts_with("003_Microsoft")));
    let r = e.reports.take();
    assert_eq!(r.len(), 1);
    assert!(r[0].contains("There is no information of installed packages. Vulnerabilities cleared."));

    // 10. Global sync: log line only.
    let gs = Event { origin: Origin::Rsync, body: json!({"agent_info":agent("001"),"data_type":"integrity_check_global","data":{"attributes_type":"syscollector_packages"}}) };
    s.process_event(&gs);
    assert!(e.has(Level::Debug2, "Processing 'GlobalSyncInventory' event to synchronize inventory across nodes"));

    // 11. deletePackage: DELETED documents, no alert.
    s.process_event(&Event::json(json!({"action":"deletePackage","agent_info":{"agent_id":"001"},"data":{"item_id":"iopenssl"}})));
    assert!(e.reports.take().is_empty());
    assert!(!docs(&s).iter().any(|d| d.contains("openssl")));

    // 15. Unknown action.
    s.process_event(&Event::json(json!({"action":"bogus"})));
    assert!(e.has(Level::Error, "Event processing failed: Unable to build scan context. Unknown action."));

    // 16. cleanup: inventory empty.
    s.process_event(&Event::json(json!({"action":"cleanup"})));
    assert!(inv(&s, COL_PACKAGE).is_empty() && inv(&s, COL_OS).is_empty() && inv(&s, COL_INITIAL).is_empty());
    assert!(docs(&s).is_empty());

    // 17. reboot: re-scan from the agent database, no alerts.
    db.set("global get-all-agents context ", Ok(vec![json!({"id":0,"name":"mgr","ip":"127.0.0.1"}), json!({"id":1,"name":"host-001","ip":"10.0.0.1","version":format!("{} v1", crate::legacy_names::VENDOR_NAME)}), json!({"id":3,"name":"host-003","ip":"10.0.0.3"}), json!({"id":"x"})]));
    db.set("agent 001 package get ", Ok(vec![pkg("openssl", "3.0.2-0ubuntu1", "deb", "acme")]));
    db.set("agent 003 package get ", Ok(vec![]));
    s.process_event(&Event::json(json!({"action":"reboot"})));
    run_job(&s);
    assert!(e.has(Level::Debug2, "Fetched 2 agents from provigil-db."));
    assert!(e.has(Level::Debug2, "Skipping manager agent with id 0."));
    assert!(e.reports.take().is_empty());
    let d = docs(&s);
    assert!(d.contains(&"001_iopenssl_CVE-2024-0001_5".to_string()));
    assert!(d.iter().any(|k| k.starts_with("003_Microsoft Windows 10 Pro")));

    // 18. Same OS again after the re-scan: not a first scan, nothing changed, no alert.
    s.process_event(&delta("003", "dbsync_osinfo", "MODIFIED", windows()));
    assert!(e.reports.take().is_empty());

    // 13. deleteAgent: keys removed, os_initial_scan removed.
    s.process_event(&Event::json(json!({"action":"deleteAgent","agent_info":{"agent_id":"3"}})));
    assert!(!inv(&s, COL_OS).iter().any(|k| k.starts_with("003_")));
    assert!(!inv(&s, COL_INITIAL).contains(&"003".to_string()));

    // 19. openssl deleted (delta): Solved alert.
    s.process_event(&delta("001", "dbsync_packages", "DELETED", pkg("openssl", "3.0.2-0ubuntu1", "deb", "acme")));
    assert!(e.reports.take()[0].contains("\"status\":\"Solved\""));
}

// ---- 19.8 postponement --------------------------------------------------------------------

#[test]
fn not_ready_postponement_and_errors() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    e.db.set("agent 007 osinfo get ", Err(DbError::NotSynced));
    let ev = delta("007", "dbsync_packages", "INSERTED", pkg("openssl", "1", "deb", "acme"));
    s.process_event(&ev);
    assert!(e.has(Level::Debug2, "Agent data not ready (Agent 007). Reason: DB query not synced"));
    assert_eq!(s.delayed.count("007"), 1);
    assert!(s.delayed_step());
    assert!(e.has(Level::Debug2, "Postponed delayed event for agent 007"));
    assert!(s.is_postponed("007"));
    assert!(!s.delayed_step());

    s.process_event(&ev);
    assert!(e.has(Level::Debug2, "Agent data not ready (Agent 007). Reason: DB query not synced") && s.delayed.count("007") == 2);
    e.db.set("agent 007 osinfo get ", Ok(vec![ubuntu()]));
    s.process_event(&ev);
    assert!(e.has(Level::Debug2, "Postponing event '1' for agent '007'"));
    assert!(e.has(Level::Debug2, "Event type: 1 processed"));
    s.process_event(&Event::json(json!({"action":"deleteAgent","agent_info":{"agent_id":"007"}})));
    assert_eq!(s.delayed.count("007"), 0);

    e.db.set("agent 008 osinfo get ", Ok(vec![]));
    s.process_event(&delta("008", "dbsync_packages", "INSERTED", pkg("openssl", "1", "deb", "acme")));
    assert!(e.has(Level::Debug2, "Agent data not ready (Agent 008). Reason: Empty OS data from provigil-db."));

    // Re-scan with an agent not ready: scanAgent queued in the delayed queue with no-index.
    e.db.set("global get-all-agents context ", Ok(vec![json!({"id":2,"name":"b","ip":"1"})]));
    e.db.set("agent 002 osinfo get ", Ok(vec![ubuntu()]));
    e.db.set("agent 002 package get ", Err(DbError::NotSynced));
    s.process_event(&Event::json(json!({"action":"reboot","no-index":true})));
    run_job(&s);
    let (_, p, item) = s.delayed.front(|p| p == "002").unwrap();
    assert_eq!(p, "002");
    assert_eq!(Event::decode(&item).unwrap().body, json!({"action":"scanAgent","agent_info":{"agent_id":"002"},"no-index":true}));

    s.process_event(&Event::json(json!({"foo":1})));
    assert!(e.has(Level::Error, "Event processing failed: json exception [403](JSON key 'action' not found) - Event message: {\"foo\":1}"));
    s.process_event(&Event { origin: Origin::Delta, body: json!({"data_type":"dbsync_packages"}) });
    assert!(e.has(Level::Error, "Event processing failed: Operation not found in delta.."));
}

#[test]
fn events_survive_restart_in_order() {
    let e = Env::new();
    {
        let s = e.start();
        let _ = queued(&s);
        s.push_event(&Event::json(json!({"action":"reboot"})));
        s.push_event(&Event::json(json!({"action":"cleanup"})));
        assert_eq!(s.queued(), 2);
    }
    let s = e.start();
    assert_eq!(queued(&s), vec![json!({"action":"reboot"}), json!({"action":"cleanup"})]);
}

// ---- 19.9 outputs ---------------------------------------------------------------------------

#[test]
fn description_fallbacks() {
    let e = Env::new();
    let s = e.start();
    load_feed(&s);
    let c = s.core.lock().unwrap();
    // The cisa column exists but holds nothing for this CVE.
    c.feed.store.create_column("descriptions_cisa").unwrap();
    let ev = Event::json(json!({"action":"scanAgent","agent_info":{"agent_id":"000"}}));
    let mut ctx = crate::event::Ctx::new(&ev, crate::event::EventType::RescanOne, crate::event::Component::Agent).unwrap();
    ctx.vuln_source = ("cisa".into(), "cisa".into());
    let src = c.sources(&ctx).unwrap();
    let d = c.merge("CVE-2024-0001", &src).unwrap();
    assert_eq!((d.t("description"), d.t("severity")), ("CVE-2024-0001 text", "HIGH"));
    assert!(e.has(Level::Debug2, "Unreliable description information for 'CVE-2024-0001' from 'cisa' source."));
    // CVSS source without data: unreliable, the nvd values are used.
    ctx.vuln_source = ("redhat".into(), "redhat".into());
    let d = c.merge("CVE-2024-0001", &c.sources(&ctx).unwrap()).unwrap();
    assert_eq!((d.t("severity"), d.score), ("HIGH", 7.25));
    assert!(e.has(Level::Debug2, "CVSS information could not be obtained for 'CVE-2024-0001' from 'cisa' source."));
    assert!(e.has(Level::Debug2, "Unreliable information for 'CVE-2024-0001' from cisa source."));
    let mut ctx2 = ctx;
    ctx2.vuln_source = ("nvd".into(), "nvd".into());
    let d = c.merge("CVE-2024-0007", &c.sources(&ctx2).unwrap()).unwrap();
    assert_eq!((d.t("severity"), d.score), ("", 0.0));
}

#[test]
fn manager_report_line_and_queue_limit() {
    let ev = Event::json(json!({"action":"scanAgent","agent_info":{"agent_id":"000"}}));
    let mut ctx = crate::event::Ctx::new(&ev, crate::event::EventType::RescanOne, crate::event::Component::Agent).unwrap();
    ctx.agent.name = "mgr".into();
    let line = crate::scan::Core::report_line(&ctx, &json!({"vulnerability":{"b":1,"a":2}}));
    assert_eq!(line, "1:[000] (mgr) ->vulnerability-detector:{\"vulnerability\":{\"a\":2,\"b\":1}}");
    let d = tempfile::tempdir().unwrap();
    let q = Arc::new(crate::queue::DurableQueue::open(d.path()).unwrap());
    let rq = crate::report::ReportQueue::new(q.clone(), 1);
    rq.push("a".into());
    rq.push("b".into());
    assert_eq!(q.len(), 1);
    assert_eq!(crate::scanner::router_publish_frame(b"xy"), vec![7, 0, 0, 0, 1, 0, 0, 0, b'P', b'x', b'y']);
}

// ---- 7.1 router subscriptions -------------------------------------------------------------

type Callbacks = Mutex<HashMap<String, Box<dyn Fn(Value) + Send + Sync>>>;

#[derive(Default)]
struct FakeRouter(Callbacks);
impl crate::scanner::Router for FakeRouter {
    fn subscribe(&self, topic: &str, id: &str, cb: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String> {
        if topic == "rsync" {
            assert_eq!(id, "vulnerability_scanner_rsync");
        }
        self.0.lock().unwrap().insert(topic.to_string(), cb);
        Ok(())
    }
}

#[test]
fn router_filters() {
    let e = Env::new();
    let router = Arc::new(FakeRouter::default());
    let s = Scanner::start(
        e.home.path(),
        Log::new(e.log.clone()),
        e.cfg(json!({"enabled":"yes","index-status":"yes","cti-url":"U"}), InternalOptions::default()),
        StartOptions {
            agent_db: e.db.clone(),
            report_sink: Some(e.reports.clone()),
            report_socket: None,
            manager_name: String::new(),
            content_updater: false,
            router: Some(router.clone()),
            stream: None,
            threads: false,
        },
    )
    .unwrap();
    let _ = queued(&s);
    let call = |t: &str, v: Value| (router.0.lock().unwrap()[t])(v);
    call("deltas-syscollector", json!({"data_type":"dbsync_packages","operation":"INSERTED"}));
    call("deltas-syscollector", json!({"data_type":"dbsync_ports"}));
    call("rsync", json!({"data_type":"state","data":{"attributes_type":"syscollector_osinfo"}}));
    // D16: a state message without a type is dropped silently; integrity messages log it.
    call("rsync", json!({"data_type":"state","data":{}}));
    assert!(!e.log.has_text("attributes_type is null"));
    call("rsync", json!({"data_type":"integrity_clear","data":{}}));
    call("wdb-agent-events", json!({"action":"anything"}));
    call("wdb-inventory-events", json!({"action":"deletePort"}));
    call("wdb-inventory-events", json!({"action":"deleteHotfix"}));
    assert!(e.has(Level::Error, "Inventory sync subscription failed: attributes_type is null"));
    let kinds: Vec<Origin> = std::iter::from_fn(|| s.take_next()).map(|ev| ev.origin).collect();
    assert_eq!(kinds, vec![Origin::Delta, Origin::Rsync, Origin::Json, Origin::Json]);
    assert_eq!(s.core.lock().unwrap().settings.manager_name, "manager");
}

// ---- corrections (specs/vulnscan-fixes.md) ----------------------------------------------------

fn doc_data(e: &Env, id: &str) -> Option<Value> {
    let index = format!("{}host1", crate::legacy_names::INDEX_PREFIX);
    let db = KvStore::open(&e.home.path().join("queue/indexer/db").join(index)).unwrap();
    db.get_text(DEFAULT_COLUMN, id).unwrap().map(|t| serde_json::from_str(&t).unwrap())
}

fn set_vendor(s: &Scanner, key: &str, v: Value) {
    s.core.lock().unwrap().feed.maps.vendor[key] = v;
}

#[test]
fn corrections_rescan_and_inventory() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    let db = &e.db;
    db.set("agent 001 osinfo get ", Ok(vec![ubuntu()]));
    db.set("agent 003 osinfo get ", Ok(vec![windows()]));
    db.set("agent 003 hotfix get ", Ok(vec![json!({"hotfix":"KB0000001"}), json!({"other":1})]));

    // D3: single-agent re-scans strip the agent version like the agent list.
    db.set("global get-agent-info 001 ", Ok(vec![json!({"name":"a","ip":"1","node_name":"n","connection_status":"active","version":format!("{} v1", crate::legacy_names::VENDOR_NAME)})]));
    db.set("agent 001 package get ", Ok(vec![pkg("openssl", "3.0.2-0ubuntu1", "deb", "acme")]));
    s.process_event(&Event::json(json!({"action":"scanAgent","agent_info":{"agent_id":"001"}})));
    assert_eq!(doc_data(&e, "001_iopenssl_CVE-2024-0001_5").unwrap()["agent"]["version"], "v1");

    // D14: clean-up deletions go through the element publisher.
    s.process_event(&Event::json(json!({"action":"cleanup"})));
    assert!(e.has(Level::Debug2, "Processing and publish key: 001_iopenssl_CVE-2024-0001"));

    // D15: one line per removed occurrence, naming `<inventory key>_<cve>`.
    s.process_event(&delta("003", "dbsync_packages", "INSERTED", pkg("chrome", "120.0.6099.71", "win", "acme")));
    s.process_event(&delta("003", "dbsync_hotfixes", "INSERTED", json!({"hotfix":"KB9"})));
    assert!(e.has(Level::Debug2, "CVE 'CVE-2024-0005' was remediated by hotfix 'KB9' for '003_ichrome_CVE-2024-0005'."));
}

#[test]
fn corrections_scan_rules() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    e.db.set("agent 001 osinfo get ", Ok(vec![ubuntu()]));
    e.db.set("agent 003 osinfo get ", Ok(vec![windows()]));
    e.db.set("agent 003 hotfix get ", Ok(vec![]));
    {
        let c = s.core.lock().unwrap();
        let mut r = cve("CVE-2024-0009", "rpmonly", json!([]), json!({}));
        r["payload"]["containers"]["cna"]["affected"][0]["defaultStatus"] = "affected".into();
        c.feed.apply_resource(&r, &Log::null()).unwrap();
    }

    // D7: an installed version that fails to parse ends the candidate before the default status.
    s.process_event(&delta("001", "dbsync_packages", "INSERTED", pkg("rpmonly", "x:1", "rpm", "acme")));
    assert!(e.has(Level::Debug, "Failed to scan package: 'rpmonly', CVE Numbering Authorities (CNA): 'nvd', Error: 'Invalid integer value'"));
    assert!(e.reports.take().is_empty());
    s.process_event(&delta("001", "dbsync_packages", "INSERTED", pkg("rpmonly", "1.0", "rpm", "acme")));
    assert_eq!(e.reports.take().len(), 1);

    // D22: a CNA list that is not a list scans nothing, without error.
    set_vendor(&s, "adp_default_array", json!("x"));
    s.process_event(&delta("001", "dbsync_packages", "INSERTED", pkg("curl", "7.0", "deb", "acme")));
    assert!(e.reports.take().is_empty());
    assert!(!e.log.has_text("Event processing failed"));

    // D23: the OS CNA line comes right before the scan with that CNA.
    set_vendor(&s, "adp_default_array", json!(["nvd", "cisa"]));
    s.process_event(&delta("003", "dbsync_osinfo", "INSERTED", windows()));
    let lines = e.log.lines();
    let first_scan = lines.iter().position(|l| l.starts_with("Scanning OS - 'windows_10_22h2'")).unwrap();
    let cisa = lines.iter().position(|l| l == "Using CNA 'cisa' from CNA array for OS.").unwrap();
    assert!(first_scan < cisa);

    // D21: the id keeps the offset suffix when the document fails after the merge.
    set_vendor(&s, "adp_default_array", json!(["nvd"]));
    s.core.lock().unwrap().feed.maps.vendor["adp_descriptions"]["nvd"] = json!({"cvss":"nvd","description":"nvd"});
    s.process_event(&delta("001", "dbsync_packages", "INSERTED", pkg("openssl", "3.0.2", "deb", "acme")));
    assert!(e.has(Level::Error, "Error message: JSON key 'adp' not found"));
    assert!(e.log.has_text("\"id\":\"001_iopenssl_CVE-2024-0001_5\""));
}

/// A router whose subscriptions live only while the router object does.
#[derive(Default)]
struct OwnedRouter(Callbacks);
impl crate::scanner::Router for OwnedRouter {
    fn subscribe(&self, topic: &str, _: &str, cb: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String> {
        self.0.lock().unwrap().insert(topic.to_string(), cb);
        Ok(())
    }
}

/// Publishes through the router if it still exists; false when the message is lost.
fn publish(r: &std::sync::Weak<OwnedRouter>, topic: &str, v: Value) -> bool {
    match r.upgrade() {
        Some(r) => {
            (r.0.lock().unwrap()[topic])(v);
            true
        }
        None => false,
    }
}

#[test]
fn scanner_owns_the_router() {
    // D54: the host drops its handle right after start; messages still arrive until stop.
    let e = Env::new();
    let router = Arc::new(OwnedRouter::default());
    let weak = Arc::downgrade(&router);
    let s = Scanner::start(
        e.home.path(),
        Log::new(e.log.clone()),
        e.cfg(json!({"enabled":"yes","index-status":"yes","cti-url":"U"}), InternalOptions::default()),
        StartOptions {
            agent_db: e.db.clone(),
            report_sink: Some(e.reports.clone()),
            report_socket: None,
            manager_name: String::new(),
            content_updater: false,
            router: Some(router),
            stream: None,
            threads: false,
        },
    )
    .unwrap();
    let _ = queued(&s);
    assert!(publish(&weak, "wdb-agent-events", json!({"action":"reboot"})));
    assert_eq!(queued(&s), vec![json!({"action":"reboot"})]);
    s.stop();
    assert!(!publish(&weak, "wdb-agent-events", json!({"action":"reboot"})));
}

/// Runs the background re-scan job to its end.
fn run_job(s: &Scanner) {
    while s.core.lock().unwrap().job_step() {}
}

// ---- changes C1-C4 (spec section 22) ----------------------------------------------------------

#[test]
fn c1_agent_cleanup_is_whole_id() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    for id in ["100", "1000"] {
        e.db.set(&format!("agent {id} osinfo get "), Ok(vec![ubuntu()]));
        s.process_event(&delta(id, "dbsync_packages", "INSERTED", pkg("openssl", "3.0.2", "deb", "acme")));
    }
    s.process_event(&Event::json(json!({"action":"deleteAgent","agent_info":{"agent_id":"100"}})));
    assert!(!docs(&s).iter().any(|d| d.starts_with("100_")));
    assert!(docs(&s).iter().any(|d| d.starts_with("1000_")));
    assert_eq!(inv(&s, COL_PACKAGE), vec!["1000_iopenssl"]);
}

#[test]
fn c2_no_change_no_rescan() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    let slot = Arc::new(crate::scanner::CoreSlot::default());
    slot.set(s.core.clone());
    let cb = Scanner::feed_callback(slot, s.events.clone(), Arc::new(crate::updater::StopSignal::default()), false, Log::new(e.log.clone()));
    let page = e.home.path().join("page.json");
    std::fs::write(&page, r#"{"data":[{"resource":"TCPE","type":"create","offset":4,"payload":{}}]}"#).unwrap();
    let msg = json!({"paths":[page.to_string_lossy()],"type":"offsets","offset":0}).to_string();
    assert!(cb(&msg).2);
    assert!(e.has(Level::Info, "Feed update changed no vulnerability data; no re-scan."));
    assert!(queued(&s).is_empty());
    std::fs::write(&page, r#"{"data":[{"resource":"TID-5","type":"create","offset":5,"payload":{}}]}"#).unwrap();
    assert!(cb(&msg).2);
    assert_eq!(queued(&s), vec![json!({"action":"reboot","no-index":false})]);
}

#[test]
fn c2_background_job_yields_and_restarts() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    let agents: Vec<Value> = (1..=3).map(|i| json!({"id":i,"name":format!("h{i}"),"ip":"1"})).collect();
    e.db.set("global get-all-agents context ", Ok(agents));
    for id in ["001", "002", "003"] {
        e.db.set(&format!("agent {id} osinfo get "), Ok(vec![ubuntu()]));
    }
    e.db.set("global get-agent-info 003 ", Ok(vec![json!({"name":"h3","ip":"1","node_name":"n","connection_status":"active"})]));
    s.process_event(&Event::json(json!({"action":"reboot"})));
    let job = s.core.lock().unwrap().job.clone();
    assert_eq!(job.len(), 3);
    // A second update during the job leaves exactly one job.
    s.process_event(&Event::json(json!({"action":"reboot"})));
    assert_eq!(job.len(), 3);
    // A real-time event is handled before the job's next agent.
    s.push_event(&Event::json(json!({"action":"scanAgent","agent_info":{"agent_id":"003"}})));
    assert!(s.work_step(std::time::Duration::ZERO));
    assert!(e.has(Level::Debug2, "Processing 'ReScanSingleAgent' event for agent '003'"));
    assert_eq!(job.len(), 3);
    while s.work_step(std::time::Duration::ZERO) && !job.is_empty() {}
    assert!(job.is_empty());
    assert!(e.has(Level::Info, "Re-scan after feed update: 3/3 agents."));
}

#[test]
fn c3_rescan_change_alerts() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    e.db.set("agent 001 osinfo get ", Ok(vec![ubuntu()]));
    e.db.set("global get-agent-info 001 ", Ok(vec![json!({"name":"a","ip":"1","node_name":"n","connection_status":"active"})]));
    let scan = || s.process_event(&Event::json(json!({"action":"scanAgent","agent_info":{"agent_id":"001"}})));
    // First scan of an agent: no alerts.
    e.db.set("agent 001 package get ", Ok(vec![pkg("openssl", "3.0.2", "deb", "acme"), pkg("curl", "7.0", "deb", "acme")]));
    scan();
    assert!(e.reports.take().is_empty());
    // {openssl/CVE-1, curl/CVE-2} -> {curl/CVE-2, onlycvss2/CVE-7}: one Active, one Solved.
    e.db.set("agent 001 package get ", Ok(vec![pkg("curl", "7.0", "deb", "acme"), pkg("onlycvss2", "1", "deb", "acme")]));
    scan();
    let r = e.reports.take();
    assert_eq!(r.len(), 2);
    assert!(r[0].contains("\"cve\":\"CVE-2024-0007\"") && r[0].contains("\"status\":\"Active\""));
    assert!(r[1].contains("\"cve\":\"CVE-2024-0001\"") && r[1].contains("\"status\":\"Solved\""));
    // A failed re-scan sends nothing.
    e.db.set("agent 001 package get ", Err(DbError::Failed("down".into())));
    scan();
    assert!(e.reports.take().is_empty());
}

#[test]
fn c3_alert_cap() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    {
        let c = s.core.lock().unwrap();
        for i in 0..600 {
            c.feed.apply_resource(&cve(&format!("CVE-2030-{i:04}"), "big", json!([{"status":"affected","version":"0","lessThan":"9"}]), json!({})), &Log::null()).unwrap();
        }
    }
    e.db.set("agent 001 osinfo get ", Ok(vec![ubuntu()]));
    e.db.set("global get-agent-info 001 ", Ok(vec![json!({"name":"a","ip":"1","node_name":"n","connection_status":"active"})]));
    let scan = || s.process_event(&Event::json(json!({"action":"scanAgent","agent_info":{"agent_id":"001"}})));
    e.db.set("agent 001 package get ", Ok(vec![pkg("openssl", "3.0.2", "deb", "acme")]));
    scan();
    e.db.set("agent 001 package get ", Ok(vec![pkg("openssl", "3.0.2", "deb", "acme"), pkg("big", "1", "deb", "acme")]));
    scan();
    assert_eq!(e.reports.take().len(), 500);
    assert!(e.has(Level::Warning, "Re-scan of agent 001: 100 more vulnerability changes were not alerted."));
}

#[test]
fn c4_os_clear_keeps_packages() {
    let e = Env::new();
    let s = e.start();
    let _ = queued(&s);
    load_feed(&s);
    e.db.set("agent 003 osinfo get ", Ok(vec![windows()]));
    e.db.set("agent 003 hotfix get ", Ok(vec![]));
    s.process_event(&delta("003", "dbsync_osinfo", "INSERTED", windows()));
    s.process_event(&delta("003", "dbsync_packages", "INSERTED", pkg("chrome", "120.0.6099.71", "win", "acme")));
    e.reports.take();
    let ic = Event { origin: Origin::Rsync, body: json!({"agent_info":agent("003"),"data_type":"integrity_clear","data":{"attributes_type":"syscollector_osinfo"}}) };
    s.process_event(&ic);
    assert!(!docs(&s).iter().any(|d| d.starts_with("003_Microsoft")));
    assert!(docs(&s).iter().any(|d| d.starts_with("003_ichrome")));
    assert!(!inv(&s, COL_INITIAL).contains(&"003".to_string()));
    let r = e.reports.take();
    assert_eq!(r.len(), 1);
    assert!(r[0].contains("There is no information of the operating system. Vulnerabilities cleared."));
    assert!(!e.log.has_text("DELETED_BY_QUERY"));
}
