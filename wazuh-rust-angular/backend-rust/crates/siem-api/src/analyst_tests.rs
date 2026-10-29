//! The SIEM analyst AI features end to end, against the local ClickHouse and
//! the running manager's analysisd (logtest), in a scratch tenant database
//! that is dropped afterwards. The tenant's AI is off, so no AI provider is called.
//!
//! `cargo test -p siem-api analyst_tests -- --ignored --nocapture`

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use axum::extract::{Extension, Path, Query, State};
use axum::Json;
use serde_json::json;

use crate::tenancy::AuthCtx;
use crate::AppState;

async fn state() -> AppState {
    // decision anchors go to a temp file, never into the source tree (one file: writes are serialized by the chain lock)
    std::env::set_var("SIEM_DECISION_ANCHORS", std::env::temp_dir().join(format!("siem-test-anchors-{}.json", std::process::id())));
    let (broadcast_tx, _) = tokio::sync::broadcast::channel(16);
    AppState {
        engine: siem_engine::AnalysisEngine::new(),
        events: Arc::new(RwLock::new(Vec::new())),
        alerts: Arc::new(RwLock::new(Vec::new())),
        agents: Arc::new(RwLock::new(HashMap::new())),
        broadcast_tx,
        pending_commands: Arc::new(RwLock::new(HashMap::new())),
        db: crate::db::ClickHouseDb::init().await,
        vulnerabilities: Arc::new(RwLock::new(Vec::new())),
        wdb: Arc::new(siem_wdb::WazuhDbManager::new()),
        threat_intel: Arc::new(siem_cdb::ThreatIntelManager::new_with_builtin_feeds()),
        rootcheck: Arc::new(siem_rootcheck::RootcheckScanner::with_default_db()),
        active_responses: Arc::new(RwLock::new(Vec::new())),
        parser_registry: Arc::new(siem_parser_gen::DynamicParserRegistry::new("")),
        parser_tenants: Arc::new(RwLock::new(HashMap::new())),
        auth_keystore: Arc::new(RwLock::new(siem_crypto::keys::KeyStore::new())),
        tenants: Arc::new(RwLock::new(Vec::new())),
        agent_keys: Arc::new(crate::tenancy::AgentKeys::new()),
        agent_tenants: Arc::new(RwLock::new(HashMap::new())),
        enrolled: Arc::new(RwLock::new(HashMap::new())),
        max_agent_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        deleted_agents: Arc::new(RwLock::new(HashSet::new())),
        deleted_agent_names: Arc::new(RwLock::new(HashSet::new())),
        risk_fabric: Arc::new(siem_risk_fabric::RiskFabricEngine::new("")),
        redswarm: Arc::new(siem_redswarm::RedSwarmService::new()),
        // it writes its config file on start: a temp one, not the source tree
        intent_engine: Arc::new(siem_intent_engine::IntentEngine::new(std::env::temp_dir().join(format!("siem-test-intent-{}.json", std::process::id())))),
        deception_engine: Arc::new(siem_deception::DeceptionEngine::new(std::env::temp_dir().join(format!("siem-test-deception-{}.json", std::process::id())))),
    }
}

fn ctx(tenant: &str) -> AuthCtx {
    AuthCtx { username: "tester".into(), role: "tenant_admin".into(), tenant_id: tenant.into(), permissions: Vec::new(), features: Vec::new(), requested_tenant: None }
}

fn alert(rule: u32, level: u8, desc: &str, agent: &str, src: &str, ts_ms: u64) -> siem_core::Alert {
    siem_core::Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::DateTime::from_timestamp_millis(ts_ms as i64).unwrap(),
        rule: siem_core::RuleAlertInfo { id: rule, level, description: desc.into(), groups: Vec::new(), mitre: None },
        agent: siem_core::AgentAlertInfo { id: agent.into(), name: format!("host-{agent}"), ip: "10.0.0.5".into() },
        manager: None,
        decoder: None,
        full_log: format!("{desc} log"),
        decoded: siem_core::DecodedFields {
            decoder_name: "sshd".into(),
            src_ip: Some(src.to_string()).filter(|s| !s.is_empty()),
            dst_ip: None,
            src_port: None,
            dst_port: None,
            user: None,
            program_name: None,
            process_id: None,
            file_path: None,
            action: None,
            status: None,
            extra: HashMap::new(),
        },
        location: "/var/log/auth.log".into(),
        data: HashMap::new(),
    }
}

#[tokio::test]
#[ignore]
async fn analyst_ai_end_to_end() {
    let home = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager");
    std::env::set_var("WAZUH_MANAGER_HOME", std::path::absolute(&home).unwrap());
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let tenant = format!("aitest{}", std::process::id());
    let dbname = st.db.provision_tenant_db(&tenant).await.unwrap();
    st.tenants.write().unwrap().push(serde_json::from_value(json!({ "id": tenant, "name": tenant, "ai_enabled": false })).unwrap());
    let c = ctx(&tenant);

    let r = std::panic::AssertUnwindSafe(async {
        // ── alerts: routine, tampering, an unknown burst, and one host's kill chain ──
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let tc = st.db.tenant_client(&tenant);
        let ins = |rule: u32, level: u8, desc: &'static str, agent: &'static str, src: &'static str, tactic: &'static str, mitre: &'static str, ago_s: u64| {
            let tc = tc.clone();
            async move {
                tc.query("INSERT INTO siem_alerts (id, timestamp, agent_id, agent_name, agent_ip, rule_id, rule_level, rule_description, mitre_id, mitre_tactic, mitre_technique, full_log, src_ip, dst_ip, user, location) VALUES (?, ?, ?, ?, '10.0.0.5', ?, ?, ?, ?, ?, '', ?, ?, '', '', '/var/log/auth.log')")
                    .bind(uuid::Uuid::new_v4().to_string()).bind(now_ms - ago_s * 1000).bind(agent).bind(format!("host-{agent}")).bind(rule).bind(level).bind(desc).bind(mitre).bind(tactic).bind(format!("{desc} log")).bind(src)
                    .execute().await.unwrap();
            }
        };
        for i in 0..3 {
            ins(503, 3, "Wazuh agent started.", "001", "", "", "", 600 + i).await;
        }
        ins(593, 9, "Microsoft Event log cleared.", "002", "", "Defense Evasion", "T1070", 500).await;
        for i in 0..5 {
            ins(5710, 5, "sshd: Attempt to login using a non-existent user", "001", "203.0.113.9", "", "", 400 + i).await;
        }
        ins(100100, 6, "Phishing attachment opened", "003", "", "Initial Access", "T1566", 3000).await;
        ins(100101, 7, "Encoded PowerShell", "003", "", "Execution", "T1059.001", 2000).await;
        ins(100102, 10, "LSASS memory read", "003", "", "Credential Access", "T1003.001", 1000).await;

        // ── triage (rules only) ──
        let s = crate::triage::run_for_tenant(&st, &tenant, false).await.unwrap();
        let by_rule = |id: u32| s.recs.iter().find(|r| r.rule_id == id).unwrap_or_else(|| panic!("no group for rule {id}: {:?}", s.recs));
        assert_eq!(by_rule(503).verdict, siem_triage::Verdict::Benign);
        assert_eq!(by_rule(503).alert_count, 3);
        assert_eq!(by_rule(593).verdict, siem_triage::Verdict::Suspicious);
        assert_eq!(by_rule(5710).verdict, siem_triage::Verdict::Unknown);
        assert_eq!(by_rule(100102).verdict, siem_triage::Verdict::Suspicious, "credential access");
        let page = crate::triage::get(State(st.clone()), Extension(c.clone())).await.0;
        assert_eq!(page["summary"]["benign"], 1);
        assert_eq!(page["ai"]["enabled"], false);

        // suspicious groups cannot be suppressed; benign ones can
        let sus = by_rule(593).id.clone();
        let r = crate::triage::apply(State(st.clone()), Extension(c.clone()), Path(sus), None).await.0;
        assert_eq!(r["status"], "error");
        let ben = by_rule(503).id.clone();
        let r = crate::triage::apply(State(st.clone()), Extension(c.clone()), Path(ben), Some(Json(crate::triage::ApplyBody { hours: Some(2) }))).await.0;
        assert_eq!(r["summary"]["applied"], 1, "{r}");

        // ── suppressions ──
        let list = crate::suppressions::all(&st, &tenant).await;
        assert_eq!((list.len(), list[0].rule_id, list[0].agent_id.as_deref(), list[0].source.as_str()), (1, Some(503), Some("001"), "triage"));
        assert!(crate::suppressions::is_suppressed(&st, &tenant, &alert(503, 3, "Wazuh agent started.", "001", "", now_ms)).await);
        assert!(!crate::suppressions::is_suppressed(&st, &tenant, &alert(503, 3, "Wazuh agent started.", "009", "", now_ms)).await, "other agent");
        let manual = crate::suppressions::create_manual(State(st.clone()), Extension(c.clone()), Json(crate::suppressions::ManualBody { src_ip: "203.0.113.9".into(), tag: Some("5710".into()), duration_hours: Some(1), ..Default::default() })).await.0;
        assert_eq!(manual["ok"], true, "{manual}");
        let id = manual["id"].as_str().unwrap().to_string();
        assert!(crate::suppressions::is_suppressed(&st, &tenant, &alert(5710, 5, "x", "007", "203.0.113.9", now_ms)).await);
        assert!(!crate::suppressions::is_suppressed(&st, &tenant, &alert(5710, 12, "x", "007", "203.0.113.9", now_ms)).await, "critical never hidden");
        let _ = crate::suppressions::deactivate(State(st.clone()), Extension(c.clone()), Path(id.clone())).await;
        assert!(!crate::suppressions::is_suppressed(&st, &tenant, &alert(5710, 5, "x", "007", "203.0.113.9", now_ms)).await, "deactivated");
        let act = crate::suppressions::activity(State(st.clone()), Extension(c.clone())).await.0;
        assert_eq!(act["suppressions"].as_array().unwrap().len(), 2);
        let _ = crate::suppressions::delete(State(st.clone()), Extension(c.clone()), Path(id)).await;
        assert_eq!(crate::suppressions::all(&st, &tenant).await.len(), 1);

        // ── threat predictions ──
        let n = crate::predictions::run_for_tenant(&st, &tenant).await.unwrap();
        assert!(n >= 1);
        let p = crate::predictions::latest(State(st.clone()), Extension(c.clone())).await.0;
        let preds = p["predictions"].as_array().unwrap();
        let disc = preds.iter().find(|x| x["attack_type"] == "Discovery").unwrap_or_else(|| panic!("{p}"));
        assert!(disc["probability"].as_f64().unwrap() > 0.3);
        assert!(disc["explanation"].as_str().unwrap().contains("Initial Access -> Execution -> Credential Access"));
        assert_eq!(disc["aria_briefing"], "", "AI is off for this tenant");

        // ── retrospective: the running analysisd re-decides a stored event ──
        let line = "Oct 23 06:15:11 web-01 sshd[1234]: Failed password for root from 203.0.113.9 port 51022 ssh2";
        tc.query("INSERT INTO siem_events (id, timestamp, agent_id, source, location, message, raw_metadata) VALUES (?, ?, '001', 'syslog', '/var/log/auth.log', ?, '')")
            .bind("ev-1").bind(now_ms - 100_000).bind(line).execute().await.unwrap();
        let ev = siem_retro::Event { id: "ev-1".into(), location: "/var/log/auth.log".into(), message: line.into(), ..Default::default() };
        let v = siem_retro::parse_logtest_response(&crate::retro::logtest(&siem_retro::logtest_request(&ev, None)).await.expect("analysisd logtest")).unwrap();
        assert!(v.rule_id > 0 && v.description.contains("sshd"), "{v:?}");
        let _ = crate::retro::logtest(&siem_retro::remove_session_request(&v.token)).await;
        for (rule, kw, want) in [(v.rule_id.to_string(), String::new(), 1usize), (String::new(), "Failed password".to_string(), 1), ("1".to_string(), String::new(), 0)] {
            let r = crate::retro::start(State(st.clone()), Extension(c.clone()), Json(siem_retro::ScanRequest { rule_id: rule.clone(), rule_name: String::new(), rule_content: kw.clone(), hours_back: 24 })).await.0;
            let sid = r["scan_id"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();
            let mut scan = serde_json::Value::Null;
            for _ in 0..100 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                scan = crate::retro::get(State(st.clone()), Extension(c.clone()), Path(sid.clone())).await.0["scan"].clone();
                if scan["status"] != "running" {
                    break;
                }
            }
            assert_eq!(scan["status"], "done", "{scan}");
            assert_eq!(scan["match_count"].as_u64().unwrap() as usize, want, "rule '{rule}' keyword '{kw}': {scan}");
        }
        let fired = crate::retro::fired_rules(State(st.clone()), Extension(c.clone())).await.0;
        assert!(fired["rules"].as_array().unwrap().iter().any(|r| r["id"] == "5710" && r["hit_count"] == 5));
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    st.db.root().query(&format!("DROP DATABASE IF EXISTS `{dbname}`")).execute().await.unwrap();
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

/// An analyst who hides AI suggestions within seconds without looking: triage
/// makes them open the alerts first. Who sees the numbers: the analyst, the
/// tenant admin; not the super admin; nobody once the tenant admin turns it off.
#[tokio::test]
#[ignore]
async fn analyst_insights_end_to_end() {
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let tenant = format!("instest{}", std::process::id());
    let dbname = st.db.provision_tenant_db(&tenant).await.unwrap();
    st.tenants.write().unwrap().push(serde_json::from_value(json!({ "id": tenant, "name": tenant, "ai_enabled": false })).unwrap());
    let analyst = AuthCtx { role: "analyst".into(), ..ctx(&tenant) };
    let admin = ctx(&tenant); // tenant_admin
    let sup = AuthCtx { role: "super_admin".into(), requested_tenant: Some(tenant.clone()), ..ctx(&tenant) };
    let body = |r: axum::response::Response| async move {
        let s = r.status();
        let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        (s, serde_json::from_slice::<serde_json::Value>(&b).unwrap_or_default())
    };

    let r = std::panic::AssertUnwindSafe(async {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let tc = st.db.tenant_client(&tenant);
        for (rule, agent) in [(503u32, "001"), (503, "001"), (591, "002")] {
            tc.query("INSERT INTO siem_alerts (id, timestamp, agent_id, agent_name, agent_ip, rule_id, rule_level, rule_description, mitre_id, mitre_tactic, mitre_technique, full_log, src_ip, dst_ip, user, location) VALUES (?, ?, ?, ?, '', ?, 3, 'routine', '', '', '', 'log line', '', '', '', 'ossec')")
                .bind(uuid::Uuid::new_v4().to_string()).bind(now_ms - 60_000).bind(agent).bind(format!("host-{agent}")).bind(rule).execute().await.unwrap();
        }
        let s = crate::triage::run_for_tenant(&st, &tenant, false).await.unwrap();
        let rec = s.recs.iter().find(|r| r.rule_id == 503).unwrap().clone();

        // 12 AI "benign" suggestions hidden 3 s after opening the page, never looked at
        let t0 = chrono::Utc::now().timestamp() as u64 - 1800;
        for i in 0..12u64 {
            for (dt, action) in [(0, "view"), (3, "apply")] {
                tc.query("INSERT INTO siem_analyst_actions (ts, user, action, rec_id, verdict, source, confidence) VALUES (?, 'tester', ?, ?, 'benign', 'ai', 90)")
                    .bind(t0 + i * 60 + dt).bind(action).bind(format!("old-{i}")).execute().await.unwrap();
            }
        }
        let (code, me) = body(crate::insights::me(State(st.clone()), Extension(analyst.clone())).await).await;
        assert_eq!(code, 200);
        let c = &me["calibration"];
        assert_eq!((c["trust"].as_str(), c["require_inspect"].as_bool(), c["depth"].as_str()), (Some("over_reliance"), Some(true), Some("detailed")), "{me}");
        assert!(c["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("without opening")));

        // triage shows the calibration and makes them look first
        let page = crate::triage::get(State(st.clone()), Extension(analyst.clone())).await.0;
        assert_eq!(page["calibration"]["hide_ai_verdict_until_inspect"], true);
        let r1 = crate::triage::apply(State(st.clone()), Extension(analyst.clone()), Path(rec.id.clone()), None).await.0;
        assert!(r1["message"].as_str().unwrap_or("").contains("View alerts"), "{r1}");
        let ins = crate::triage::inspect(State(st.clone()), Extension(analyst.clone()), Path(rec.id.clone())).await.0;
        assert_eq!(ins["alerts"].as_array().unwrap().len(), 2, "{ins}");
        let r2 = crate::triage::apply(State(st.clone()), Extension(analyst.clone()), Path(rec.id.clone()), None).await.0;
        assert_eq!(r2["summary"]["applied"], 1, "{r2}");

        // who sees what
        let (code, team) = body(crate::insights::team(State(st.clone()), Extension(admin.clone())).await).await;
        assert_eq!(code, 200);
        let tester = team["analysts"].as_array().unwrap().iter().find(|a| a["metrics"]["user"] == "tester").unwrap_or_else(|| panic!("{team}"));
        assert!(tester["metrics"]["decisions_7d"].as_u64().unwrap() >= 13);
        assert_eq!(body(crate::insights::team(State(st.clone()), Extension(analyst.clone())).await).await.0, 403, "an analyst does not see the team");
        assert_eq!(body(crate::insights::team(State(st.clone()), Extension(sup.clone())).await).await.0, 403, "the super admin does not see a tenant's analysts");
        assert_eq!(body(crate::insights::me(State(st.clone()), Extension(sup.clone())).await).await.0, 403);
        assert_eq!(body(crate::insights::put_settings(State(st.clone()), Extension(analyst.clone()), Json(crate::insights::Settings { enabled: false })).await).await.0, 403);

        // the tenant admin turns it off: no calibration, no logging, no extra checks
        let (code, _) = body(crate::insights::put_settings(State(st.clone()), Extension(admin.clone()), Json(crate::insights::Settings { enabled: false })).await).await;
        assert_eq!(code, 200);
        let (_, me) = body(crate::insights::me(State(st.clone()), Extension(analyst.clone())).await).await;
        assert_eq!(me["enabled"], false);
        assert!(crate::triage::get(State(st.clone()), Extension(analyst.clone())).await.0["calibration"].is_null());
        let rec2 = crate::triage::load(&st, &tenant).await.recs.iter().find(|r| r.rule_id == 591).unwrap().clone();
        let r3 = crate::triage::apply(State(st.clone()), Extension(analyst.clone()), Path(rec2.id), None).await.0;
        assert_eq!(r3["summary"]["applied"], 2, "no inspect needed when off: {r3}");
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    st.db.root().query(&format!("DROP DATABASE IF EXISTS `{dbname}`")).execute().await.unwrap();
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

/// History pages and agent inventory read ClickHouse: full alerts round-trip,
/// a restarted siem-api (empty memory) still sees them, tenants stay apart,
/// and inventory syncs from a siem-agent and from the running wazuh-db.
#[tokio::test]
#[ignore]
async fn history_and_inventory_from_clickhouse() {
    let home = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager");
    std::env::set_var("WAZUH_MANAGER_HOME", std::path::absolute(&home).unwrap());
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let (ta, tb) = (format!("histA{}", std::process::id()), format!("histB{}", std::process::id()));
    let (da, db_b) = (st.db.provision_tenant_db(&ta).await.unwrap(), st.db.provision_tenant_db(&tb).await.unwrap());
    let r = std::panic::AssertUnwindSafe(async {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut a = alert(5710, 5, "sshd: attempt to login using a non-existent user", "901", "203.0.113.9", now - 60_000);
        a.rule.groups = vec!["syslog".into(), "sshd".into(), "authentication_failed".into()];
        a.rule.mitre = Some(siem_core::MitreAttack { id: "T1110".into(), tactic: "Credential Access".into(), technique: "Brute Force".into() });
        a.decoded.file_path = Some("/etc/passwd".into());
        a.data.insert("syscheck".into(), json!({ "path": "/etc/passwd", "event": "modified" }));
        // the compliance groups Wazuh's rule 5710 carries
        a.data.insert("wazuh_rule".into(), json!({ "id": "5710", "pci_dss": ["10.2.4", "10.2.5"], "gdpr": ["IV_35.7.d"], "tsc": ["CC6.1"] }));
        let a = crate::tenancy::tag_alert(a, &ta);
        let mut other = crate::tenancy::tag_alert(alert(100200, 3, "tenant B only", "902", "", now - 30_000), &tb);
        other.rule.groups = vec!["b".into()];
        assert!(st.db.insert_alerts(&[a.clone(), other]).await.is_empty(), "insert failed");

        // memory is empty (a fresh siem-api): the history comes from ClickHouse, complete
        assert!(st.alerts.read().unwrap().is_empty());
        let ca = AuthCtx { role: "analyst".into(), ..ctx(&ta) };
        let h = crate::history::alerts(&st, &ca, 24).await;
        assert_eq!(h.len(), 1, "tenant A sees only its alert");
        let back = &h[0];
        assert_eq!((back.id, back.rule.groups.clone(), back.decoded.file_path.clone()), (a.id, a.rule.groups.clone(), Some("/etc/passwd".to_string())));
        assert_eq!(back.data["syscheck"]["event"], "modified");
        assert_eq!(crate::history::alert(&st, &ca, &a.id.to_string()).await.map(|x| x.rule.id), Some(5710));

        // pages: compliance (PCI DSS 10.2.4 from rule 5710's tags) and MITRE (T1110)
        let body = |r: axum::response::Response| async move { String::from_utf8_lossy(&axum::body::to_bytes(r.into_body(), 1 << 22).await.unwrap()).to_string() };
        use axum::response::IntoResponse;
        let comp: serde_json::Value = serde_json::from_str(&body(crate::compliance::get(State(st.clone()), Extension(ca.clone())).await).await).unwrap();
        let pci = comp["frameworks"].as_array().unwrap().iter().find(|f| f["name"] == "PCI_DSS").unwrap();
        let req = pci["requirements"].as_array().unwrap().iter().find(|r| r["id"] == "10.2.4").expect("PCI DSS 10.2.4 from the alert's tags");
        assert_eq!((req["alerts_count"].as_u64(), req["status"].as_str(), req["source"].as_str()), (Some(1), Some("warning"), Some("alerts")));
        assert!(pci["score_percent"].is_null(), "no configuration checks in this tenant: no score");
        assert_eq!(comp["evidence"].as_array().unwrap().len(), 1, "tenant B's alert is not evidence for A");
        let mitre = body(crate::get_mitre_matrix_handler(State(st.clone()), Extension(ca.clone())).await.into_response()).await;
        assert!(mitre.contains("T1110"), "MITRE from ClickHouse: {}", &mitre[..mitre.len().min(400)]);

        // inventory of a siem-agent: stored in ClickHouse, read back by the endpoint
        st.agent_tenants.write().unwrap().insert("901".into(), ta.clone());
        {
            let db = st.wdb.get_or_create("901", "host-901");
            db.write().unwrap().syscollector.set_os_info(siem_wdb::SysOsInfo { hostname: "host-901".into(), architecture: "x86_64".into(), os_name: "Ubuntu".into(), os_version: "24.04".into(), os_codename: None, os_major: None, os_minor: None, os_build: None, platform: "ubuntu".into(), release: "6.8".into() });
        }
        assert!(crate::inventory_store::sync_agent(&st, "901").await);
        assert!(!crate::inventory_store::sync_agent(&st, "901").await, "unchanged: not written again");
        let os = crate::get_agent_os_handler(State(st.clone()), Path("901".into())).await.into_response();
        let os = body(os).await;
        assert!(os.contains("Ubuntu") && os.contains("siem-agent"), "{os}");
        let stored = st.db.doc(&ta, crate::db::DocTable::Inventory, "901").await.unwrap().unwrap();
        assert!(stored.contains("24.04"));

        // inventory of a real Wazuh agent from the running wazuh-db (if one has reported)
        let mut found = None;
        for n in 1..200u32 {
            let id = format!("{n:03}");
            if crate::wazuh_manager::agent_inventory(&id).await.is_some() {
                found = Some(id);
                break;
            }
        }
        match found {
            Some(id) => {
                st.agent_tenants.write().unwrap().insert(id.clone(), ta.clone());
                let inv = crate::inventory_store::get(&st, &id).await.expect("synced on first read");
                assert_eq!(inv["source"], "wazuh-db");
                let pk = body(crate::get_agent_packages_handler(State(st.clone()), Path(id.clone())).await.into_response()).await;
                eprintln!("wazuh agent {id}: {} packages, {} ports, {} processes from ClickHouse", inv["packages"].as_array().map_or(0, |a| a.len()), inv["ports"].as_array().map_or(0, |a| a.len()), inv["processes"].as_array().map_or(0, |a| a.len()));
                assert!(pk.contains("\"source\":\"wazuh-db\""));
            }
            None => eprintln!("no Wazuh agent with inventory in the running wazuh-db: skipped that part"),
        }
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    for d in [da, db_b] {
        st.db.root().query(&format!("DROP DATABASE IF EXISTS `{d}`")).execute().await.unwrap();
    }
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

/// Organizational memory: a decided triage group and a closed case are found
/// again for similar new activity, with the reasons; search; the one-time import.
#[tokio::test]
#[ignore]
async fn org_memory_end_to_end() {
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let (tenant, t2) = (format!("memtest{}", std::process::id()), format!("memimp{}", std::process::id()));
    let (dbname, db2) = (st.db.provision_tenant_db(&tenant).await.unwrap(), st.db.provision_tenant_db(&t2).await.unwrap());
    st.tenants.write().unwrap().push(serde_json::from_value(json!({ "id": tenant, "name": tenant, "ai_enabled": false })).unwrap());
    let c = AuthCtx { role: "analyst".into(), username: "priya".into(), ..ctx(&tenant) };
    let r = std::panic::AssertUnwindSafe(async {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mk = |agent: &str, ts: u64| {
            let mut a = alert(5710, 5, "sshd: Attempt to login using a non-existent user", agent, "203.0.113.9", ts);
            a.rule.groups = vec!["syslog".into(), "sshd".into(), "authentication_failed".into()];
            a.rule.mitre = Some(siem_core::MitreAttack { id: "T1110".into(), tactic: "Credential Access".into(), technique: "Brute Force".into() });
            crate::tenancy::tag_alert(a, &tenant)
        };
        assert!(st.db.insert_alerts(&[mk("001", now - 120_000)]).await.is_empty());

        // 1. an analyst keeps a triage group for review: a lesson with the alert's groups and technique
        let s = crate::triage::run_for_tenant(&st, &tenant, false).await.unwrap();
        let first = s.recs.iter().find(|r| r.agent_id == "001").unwrap().clone();
        let _ = crate::triage::dismiss(State(st.clone()), Extension(c.clone()), Path(first.id.clone())).await;
        let all = crate::org_memory::search(State(st.clone()), Extension(c.clone()), Query(crate::org_memory::SearchQuery::default())).await.0;
        assert_eq!(all["total"], 1, "{all}");
        let l = &all["lessons"][0];
        assert_eq!((l["outcome"].as_str(), l["decided_by"].as_str(), l["techniques"][0].as_str()), (Some("kept_for_review"), Some("priya"), Some("T1110")), "{l}");

        // 2. the same source hits another host: the earlier decision is a precedent
        assert!(st.db.insert_alerts(&[mk("002", now - 60_000)]).await.is_empty());
        let s = crate::triage::run_for_tenant(&st, &tenant, false).await.unwrap();
        let second = s.recs.iter().find(|r| r.agent_id == "002").unwrap().clone();
        let p = crate::org_memory::triage_precedents(State(st.clone()), Extension(c.clone()), Path(second.id)).await.0;
        let top = &p["precedents"][0];
        assert_eq!(top["lesson"]["id"], format!("triage:{}", first.key), "{p}");
        let why: Vec<&str> = top["reasons"].as_array().unwrap().iter().filter_map(|x| x.as_str()).collect();
        assert!(why.contains(&"same rule 5710") && why.contains(&"same source IP 203.0.113.9") && why.contains(&"same MITRE technique T1110"), "{why:?}");
        // its own lesson is never its precedent
        let own = crate::org_memory::triage_precedents(State(st.clone()), Extension(c.clone()), Path(first.id)).await.0;
        assert!(own["precedents"].as_array().unwrap().iter().all(|x| x["lesson"]["id"] != format!("triage:{}", first.key)));

        // 3. a case closed as a confirmed incident keeps the analyst's reasoning
        let cr = crate::soar::create_case(State(st.clone()), Extension(c.clone()), Json(json!({ "title": "Rule 5710 brute force against web servers", "src_ip": "198.51.100.77", "tags": ["sshd", "T1110"], "severity": "HIGH" }))).await.0;
        let cid = cr["id"].as_str().unwrap().to_string();
        let _ = crate::soar::add_case_comment(State(st.clone()), Extension(c.clone()), Path(cid.clone()), Json(json!({ "comment": "Confirmed attack from a known botnet, blocked at the perimeter firewall" }))).await;
        let _ = crate::soar::update_case_status(State(st.clone()), Extension(c.clone()), Path(cid.clone()), Json(json!({ "status": "Resolved" }))).await;
        let sim = crate::org_memory::similar(State(st.clone()), Extension(c.clone()), Json(serde_json::from_value(json!({ "techniques": ["T1110"], "src_ips": ["198.51.100.77"] })).unwrap())).await.0;
        let case = sim["precedents"].as_array().unwrap().iter().find(|x| x["lesson"]["id"] == format!("case:{cid}")).unwrap_or_else(|| panic!("{sim}"));
        assert_eq!(case["lesson"]["outcome"], "true_positive");
        assert_eq!(case["outcome_label"], "Confirmed incident");
        assert_eq!(case["lesson"]["rule_ids"][0], 5710, "rule id read from the title");
        assert!(case["lesson"]["rationale"].as_str().unwrap().contains("perimeter firewall"));
        let found = crate::org_memory::search(State(st.clone()), Extension(c.clone()), Query(crate::org_memory::SearchQuery { q: "botnet".into(), ..Default::default() })).await.0;
        assert_eq!(found["lessons"].as_array().unwrap().len(), 1, "{found}");

        // 4. another tenant's history: only its own, and the one-time import of a case closed earlier
        let c2 = AuthCtx { role: "analyst".into(), ..ctx(&t2) };
        let cr2 = crate::soar::create_case(State(st.clone()), Extension(c2.clone()), Json(json!({ "title": "Old phishing case", "src_ip": "192.0.2.5" }))).await.0;
        st.db.tenant_client(&t2).query("INSERT INTO soar_cases (id, case_number, title, status, src_ip, tenant_id) SELECT id, case_number, title, 'False Positive', src_ip, tenant_id FROM soar_cases FINAL WHERE id = ?").bind(cr2["id"].as_str().unwrap()).execute().await.unwrap();
        assert_eq!(crate::org_memory::backfill(&st, &t2).await, 1);
        assert_eq!(crate::org_memory::backfill(&st, &t2).await, 0, "only once");
        let other = crate::org_memory::search(State(st.clone()), Extension(c2.clone()), Query(crate::org_memory::SearchQuery::default())).await.0;
        assert_eq!((other["total"].as_u64(), other["lessons"][0]["outcome"].as_str()), (Some(1), Some("false_positive")), "{other}");
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    for d in [dbname, db2] {
        st.db.root().query(&format!("DROP DATABASE IF EXISTS `{d}`")).execute().await.unwrap();
    }
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

/// The federated swarm: two sharing organisations see the same attacker, the hub
/// publishes it (k = 2), a receive-only organisation's alert matches; an "off"
/// tenant shares nothing; nothing raw leaves; member tokens; a round over HTTP.
#[tokio::test]
#[ignore]
async fn swarm_end_to_end() {
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let pid = std::process::id();
    let names: Vec<String> = ["swplat", "swacme", "swglobex", "swinitech", "swumbrella"].iter().map(|n| format!("{n}{pid}")).collect();
    let mut dbs = Vec::new();
    for n in &names {
        dbs.push(st.db.provision_tenant_db(n).await.unwrap());
        st.tenants.write().unwrap().push(serde_json::from_value(json!({ "id": n, "name": n, "ai_enabled": false })).unwrap());
    }
    let (plat, acme, globex, initech, umbrella) = (&names[0], &names[1], &names[2], &names[3], &names[4]);
    crate::swarm::set_platform_for_tests(plat);
    let sup = AuthCtx { role: "super_admin".into(), ..ctx(plat) };
    let admin = |t: &str| ctx(t);
    let body = |r: axum::response::Response| async move {
        let s = r.status();
        (s, serde_json::from_slice::<serde_json::Value>(&axum::body::to_bytes(r.into_body(), 1 << 22).await.unwrap()).unwrap_or_default())
    };
    let r = std::panic::AssertUnwindSafe(async {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mk = |t: &str, ip: &str, level: u8, agent: &str| {
            let mut a = alert(5712, level, "sshd: brute force", agent, ip, now - 60_000);
            a.rule.mitre = Some(siem_core::MitreAttack { id: "T1110".into(), tactic: "Credential Access".into(), technique: "Brute Force".into() });
            crate::tenancy::tag_alert(a, t)
        };
        for (t, ip, lvl) in [(acme, "203.0.113.50", 10), (globex, "203.0.113.50", 9), (acme, "198.51.100.20", 10), (acme, "198.51.100.66", 13), (umbrella, "192.0.2.99", 13), (initech, "203.0.113.50", 7)] {
            assert!(st.db.insert_alerts(&[mk(t, ip, lvl, "agent-secret-host")]).await.is_empty());
        }
        // participation: tenant admins choose; an analyst cannot
        assert_eq!(body(crate::swarm::put_tenant(State(st.clone()), Extension(AuthCtx { role: "analyst".into(), ..ctx(acme) }), Json(crate::swarm::TenantSetting { level: "share".into() })).await).await.0, 403);
        for (t, l) in [(acme, "share"), (globex, "share"), (initech, "receive"), (umbrella, "off")] {
            assert_eq!(body(crate::swarm::put_tenant(State(st.clone()), Extension(admin(t)), Json(crate::swarm::TenantSetting { level: l.into() })).await).await.0, 200);
        }
        // the platform: this deployment is its own hub
        let cfg = |hub_url: &str, token: &str| crate::swarm::ConfigBody { enabled: true, hub_url: hub_url.into(), member_token: token.into(), community_key: "test-community-key-0123456789".into(), epsilon: Some(1.0), hub_enabled: true, k: Some(2), fast_track_critical: Some(true) };
        let (code, c) = body(crate::swarm::put_config(State(st.clone()), Extension(sup.clone()), Json(cfg("", ""))).await).await;
        assert_eq!(code, 200, "{c}");
        assert!(c["config"].get("community_key").is_none() && c["config"]["community_key_set"] == true, "secrets are not returned");

        // what acme would share: anonymous only
        let (_, pv) = body(crate::swarm::preview(State(st.clone()), Extension(admin(acme))).await).await;
        let s = pv.to_string();
        for secret in ["203.0.113.50", "198.51.100.20", "agent-secret-host", "host-agent", acme.as_str(), "brute force log"] {
            assert!(!s.contains(secret), "{secret} would leave: {s}");
        }
        assert!(pv["count"].as_u64().unwrap() >= 3);

        // a round: send, pull, match
        let (sent, feed, matched) = crate::swarm::sync(&st).await.unwrap();
        assert!(sent == 4 && feed >= 2 && matched == 3, "sent {sent} feed {feed} matched {matched}");
        let key = b"test-community-key-0123456789";
        let tok = |ip: &str| siem_swarm::token(key, siem_swarm::Kind::ExternalIp, ip);
        let c = crate::swarm::config(&st).await;
        let published: std::collections::BTreeMap<String, siem_swarm::FeedEntry> = crate::swarm::hub_feed(&st, &c).await.into_iter().map(|e| (e.token.clone(), e)).collect();
        assert_eq!(published[&tok("203.0.113.50")].orgs, 2, "two organisations");
        assert!(published[&tok("198.51.100.66")].fast_tracked, "critical, one organisation");
        assert!(!published.contains_key(&tok("198.51.100.20")), "one organisation, not critical: not published");
        assert!(!published.contains_key(&tok("192.0.2.99")), "the tenant that is off shared nothing");

        // the receive-only tenant: its alert matched; the matched IP stays in its own database
        let m = crate::swarm::matches(State(st.clone()), Extension(admin(initech))).await.0;
        let hit = m["matches"].as_array().unwrap().iter().find(|x| x["value"] == "203.0.113.50").unwrap_or_else(|| panic!("{m}"));
        assert_eq!(hit["feed"]["orgs"], 2);
        let v = serde_json::to_value(mk(initech, "203.0.113.50", 7, "x")).unwrap();
        assert!(crate::swarm::known(initech, &v), "SOAR's threat-intel signal");
        assert!(!crate::swarm::known(umbrella, &v), "an 'off' tenant does not receive");
        assert!(crate::soar::context(&v, initech).is_malicious);
        // a sharing tenant: the attacker another organisation saw too matches; its own lone report does not
        let am = crate::swarm::matches(State(st.clone()), Extension(admin(acme))).await.0;
        let vals: Vec<&str> = am["matches"].as_array().unwrap().iter().filter_map(|x| x["value"].as_str()).collect();
        assert_eq!(vals, vec!["203.0.113.50"], "{am}");
        assert!(!crate::swarm::known(acme, &serde_json::to_value(mk(acme, "198.51.100.66", 13, "x")).unwrap()));

        // member tokens for other deployments
        let (_, mem) = body(crate::swarm::add_member(State(st.clone()), Extension(sup.clone()), Json(crate::swarm::MemberBody { name: "Partner SOC".into() })).await).await;
        let token = mem["token"].as_str().unwrap().to_string();
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", "Bearer swm_wrong_wrong_wrong_wrong_wrong_wrong".parse().unwrap());
        assert_eq!(crate::swarm::hub_feed_handler(State(st.clone()), h).await.status(), 401);
        let (_, cfgv) = body(crate::swarm::get_config(State(st.clone()), Extension(sup.clone())).await).await;
        assert!(!cfgv.to_string().contains(&token), "the token is shown once only");

        // the same round over HTTP, as a remote member
        let app = axum::Router::new()
            .route("/api/v1/swarm/hub/submit", axum::routing::post(crate::swarm::hub_submit))
            .route("/api/v1/swarm/hub/feed", axum::routing::get(crate::swarm::hub_feed_handler))
            .with_state(st.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let _ = body(crate::swarm::put_config(State(st.clone()), Extension(sup.clone()), Json(cfg(&url, &token))).await).await;
        let (sent2, feed2, _) = crate::swarm::sync(&st).await.unwrap();
        assert!(sent2 == 4 && feed2 >= 2, "over HTTP: sent {sent2} feed {feed2}");
        let (_, cfgv) = body(crate::swarm::get_config(State(st.clone()), Extension(sup.clone())).await).await;
        assert!(cfgv["members"][0]["last_seen"].as_u64().unwrap() > 0, "the member was seen");
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    for d in dbs {
        st.db.root().query(&format!("DROP DATABASE IF EXISTS `{d}`")).execute().await.unwrap();
    }
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

#[tokio::test]
#[ignore]
async fn decisions_end_to_end() {
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let tenant = format!("dectest{}", std::process::id());
    let dbname = st.db.provision_tenant_db(&tenant).await.unwrap();
    st.tenants.write().unwrap().push(serde_json::from_value(json!({ "id": tenant, "name": tenant, "ai_enabled": false })).unwrap());
    let analyst = AuthCtx { username: "ana".into(), role: "analyst".into(), permissions: vec!["siem-alerts".into()], ..ctx(&tenant) };
    let admin2 = AuthCtx { username: "admin2".into(), ..ctx(&tenant) };
    let body = |r: axum::response::Response| async move {
        let s = r.status();
        (s, serde_json::from_slice::<serde_json::Value>(&axum::body::to_bytes(r.into_body(), 1 << 24).await.unwrap()).unwrap_or_default())
    };
    let r = std::panic::AssertUnwindSafe(async {
        // ── hiding alerts on a triage verdict ──
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut alerts = Vec::new();
        for agent in ["001", "004"] {
            for i in 0..3 {
                alerts.push(alert(503, 3, "Wazuh agent started.", agent, "", now - 600_000 - i));
            }
        }
        alerts.push(alert(593, 9, "Microsoft Event log cleared.", "002", "", now - 500_000));
        let alerts: Vec<_> = alerts.into_iter().map(|a| crate::tenancy::tag_alert(a, &tenant)).collect();
        assert!(st.db.insert_alerts(&alerts).await.is_empty());
        let s = crate::triage::run_for_tenant(&st, &tenant, false).await.unwrap();
        let rec = |rule: u32, agent: &str| s.recs.iter().find(|r| r.rule_id == rule && r.agent_id == agent).unwrap_or_else(|| panic!("no group {rule}/{agent}")).id.clone();
        let apply = |id: String, hours: u32, who: AuthCtx| crate::triage::apply(State(st.clone()), Extension(who), Path(id), Some(Json(crate::triage::ApplyBody { hours: Some(hours) })));

        let r = apply(rec(503, "001"), 2, ctx(&tenant)).await.0;
        assert_eq!(r["summary"]["applied"], 1, "benign, short: allowed {r}");
        let r = apply(rec(593, "002"), 2, ctx(&tenant)).await.0;
        assert!(r["message"].as_str().unwrap().contains("Denied by G5"), "suspicious: refused by the guardrail {r}");
        let r = apply(rec(503, "004"), 100, ctx(&tenant)).await.0;
        assert!(r["message"].as_str().unwrap().contains("Waiting for your tenant admin") && r["message"].as_str().unwrap().contains("P4"), "long: held {r}");
        assert_eq!(crate::suppressions::all(&st, &tenant).await.len(), 1, "the held one is not applied yet");

        let (_, l) = body(crate::decisions::list(State(st.clone()), Extension(analyst.clone())).await).await;
        assert_eq!(l["pending"].as_array().unwrap().len(), 1);
        let held = l["pending"][0]["id"].as_str().unwrap().to_string();
        // four eyes, and only tenant admins review
        assert_eq!(body(crate::decisions::approve(State(st.clone()), Extension(analyst.clone()), Path(held.clone())).await).await.0, 403);
        assert_eq!(body(crate::decisions::approve(State(st.clone()), Extension(ctx(&tenant)), Path(held.clone())).await).await.0, 403, "the requester cannot approve");
        let (s2, a) = body(crate::decisions::approve(State(st.clone()), Extension(admin2.clone()), Path(held.clone())).await).await;
        assert_eq!((s2.as_u16(), a["outcome"].as_str(), a["result"]["ok"].as_bool()), (200, Some("allowed"), Some(true)), "{a}");
        let sup = crate::suppressions::all(&st, &tenant).await;
        assert!(sup.len() == 2 && sup.iter().any(|x| x.agent_id.as_deref() == Some("004") && x.reason.contains(&held)), "approved and traceable");
        assert_eq!(body(crate::decisions::approve(State(st.clone()), Extension(admin2.clone()), Path(held.clone())).await).await.0, 409, "once only");

        // ── SOAR block_ip ──
        let policy = |p: serde_json::Value| Json(serde_json::from_value::<crate::decisions::Settings>(p).unwrap());
        assert_eq!(body(crate::decisions::put_policy(State(st.clone()), Extension(analyst.clone()), policy(json!({ "protected": ["198.51.100.0/24"] }))).await).await.0, 403);
        assert_eq!(body(crate::decisions::put_policy(State(st.clone()), Extension(ctx(&tenant)), policy(json!({ "protected": ["not-an-ip"] }))).await).await.0, 400);
        assert_eq!(body(crate::decisions::put_policy(State(st.clone()), Extension(ctx(&tenant)), policy(json!({ "protected": ["198.51.100.0/24"], "max_blocks_per_hour": 1 }))).await).await.0, 200);

        let pb: provigil_common::soar::SoarNativePlaybook = serde_json::from_value(json!({
            "id": "pb1", "name": "Block attackers", "description": "", "enabled": 1, "cond_field": "score", "cond_op": ">", "cond_value": "0",
            "action_type": "block_ip", "action_config": "{\"duration_hours\": 12}", "run_count": 0, "last_run": null, "created_at": "", "updated_at": "", "tenant_id": tenant,
        }))
        .unwrap();
        let gate = |ip: &str, level: u8| {
            let mut a = serde_json::to_value(alert(5712, level, "sshd: brute force", "001", ip, now)).unwrap();
            a["data"]["srcip"] = json!(ip);
            let c = crate::soar::context(&a, &tenant);
            let (st, pb) = (st.clone(), pb.clone());
            async move { crate::decisions::gate_network(&st, &pb, &c).await }
        };
        assert!(gate("10.1.2.3", 12).await.unwrap_err().1.contains("G1"), "internal address");
        assert!(gate("10.1.2.3", 12).await.unwrap_err().1.starts_with("Refused again"), "a repeated refusal is one record");
        // a policy that cannot be read: the protected check is missing evidence, so blocks wait and a person's block is refused
        st.db.put_doc(&tenant, crate::db::DocTable::AnalystState, "decision_policy", "{not json").await.unwrap();
        let unread = gate("203.0.113.99", 12).await.unwrap_err();
        assert!(unread.0 == "awaiting_approval" && unread.1.contains("missing evidence for G2"), "{unread:?}");
        assert!(crate::decisions::gate_manual(&st, &ctx(&tenant), &tenant, "manual_block", "10.6.6.6", json!({})).await.is_err());
        assert_eq!(body(crate::decisions::put_policy(State(st.clone()), Extension(ctx(&tenant)), policy(json!({ "protected": ["198.51.100.0/24"], "max_blocks_per_hour": 1 }))).await).await.0, 200);
        assert!(gate("198.51.100.7", 15).await.unwrap_err().1.contains("G2"), "protected range");
        assert_eq!(gate("203.0.113.77", 6).await.unwrap_err().0, "awaiting_approval", "weak evidence");
        assert!(gate("203.0.113.77", 5).await.unwrap_err().1.starts_with("Already waiting"), "one request per target, not one per alert");
        assert!(gate("192.0.2.10", 12).await.is_ok(), "strong evidence, public, not protected");
        // G3 counts from the decision table (survives restarts): the 2nd strong block this hour waits
        let g3 = gate("192.0.2.11", 12).await.unwrap_err();
        assert!(g3.0 == "awaiting_approval" && g3.1.contains("G3"), "{g3:?}");
        // the same request from 5 alerts at once: one approval request, not five
        let burst = futures_util::future::join_all((0..5).map(|_| gate("203.0.113.88", 6))).await;
        let new = burst.iter().filter(|r| r.as_ref().unwrap_err().1.starts_with("Needs a person's approval")).count();
        let merged = burst.iter().filter(|r| r.as_ref().unwrap_err().1.starts_with("Already waiting")).count();
        assert_eq!((new, merged), (1, 4), "{burst:?}");

        // a person's block: recorded; a protected asset is refused, an internal host is not
        let m = crate::decisions::gate_manual(&st, &ctx(&tenant), &tenant, "manual_block", "198.51.100.9", json!({})).await;
        assert!(m.as_ref().unwrap_err().contains("G2"), "{m:?}");
        assert!(crate::decisions::gate_manual(&st, &ctx(&tenant), &tenant, "manual_block", "10.5.5.5", json!({})).await.is_ok());

        // the real SOAR path: a block_ip playbook on an internal-address alert records a denied run
        let req: crate::soar::PlaybookReq = serde_json::from_value(json!({ "name": "Block attackers", "cond_field": "score", "cond_op": ">", "cond_value": "0", "action_type": "block_ip", "action_config": "{}" })).unwrap();
        let store = crate::soar::Store { db: st.db.clone(), state: Some(st.clone()) };
        store.insert_playbook(&tenant, "pb-real", &req).await.unwrap();
        let mut a = serde_json::to_value(alert(5712, 12, "sshd: brute force", "001", "172.16.9.9", now)).unwrap();
        a["data"]["srcip"] = json!("172.16.9.9");
        crate::soar::run_playbooks(&store, vec![(a, tenant.clone())]).await;
        let runs = store.runs(&tenant).await.unwrap();
        assert!(runs.iter().any(|r| r["status"] == "denied" && r["detail"].as_str().unwrap().contains("G1")), "{runs:?}");

        // reject the held block
        let (_, l) = body(crate::decisions::list(State(st.clone()), Extension(analyst.clone())).await).await;
        let held_block = l["pending"].as_array().unwrap().iter().find(|p| p["target"] == "203.0.113.77").unwrap()["id"].as_str().unwrap().to_string();
        let (_, rj) = body(crate::decisions::reject(State(st.clone()), Extension(admin2.clone()), Path(held_block)).await).await;
        assert_eq!(rj["outcome"], "denied", "{rj}");
        // two admins at the same moment: one review, one "already reviewed" (reject: nothing is run)
        let (_, l) = body(crate::decisions::list(State(st.clone()), Extension(analyst.clone())).await).await;
        let race = l["pending"].as_array().unwrap().iter().find(|p| p["target"] == "203.0.113.88").unwrap()["id"].as_str().unwrap().to_string();
        let admin3 = AuthCtx { username: "admin3".into(), ..ctx(&tenant) };
        let (a, b) = tokio::join!(
            crate::decisions::reject(State(st.clone()), Extension(admin2.clone()), Path(race.clone())),
            crate::decisions::reject(State(st.clone()), Extension(admin3.clone()), Path(race.clone()))
        );
        let mut codes = [a.status().as_u16(), b.status().as_u16()];
        codes.sort();
        assert_eq!(codes, [200, 409]);

        // ── the chain: valid, exportable, and tampering is found ──
        let (_, v) = body(crate::decisions::verify(State(st.clone()), Extension(analyst.clone())).await).await;
        assert_eq!(v["valid"], true, "{v}");
        let n = v["checked"].as_u64().unwrap();
        assert!(n >= 11, "every decision, review and policy change is recorded: {n}");
        let (_, one) = body(crate::decisions::get_one(State(st.clone()), Extension(analyst.clone()), Path(held.clone())).await).await;
        assert!(one["verified"].is_null() && one["record"]["facts"]["neural.verdict"]["origin"] == "symbolic", "{one}");
        let (_, ex) = body(crate::decisions::export(State(st.clone()), Extension(analyst.clone())).await).await;
        assert_eq!(ex["records"].as_array().unwrap().len() as u64, n);

        // the newest record removed from the database: found through the anchor
        let last: siem_decision::Record = serde_json::from_value(ex["records"].as_array().unwrap().last().unwrap().clone()).unwrap();
        st.db.delete_doc(&tenant, crate::db::DocTable::Decisions, &last.id).await.unwrap();
        let (_, v) = body(crate::decisions::verify(State(st.clone()), Extension(analyst.clone())).await).await;
        assert!(v["valid"] == false && v["reason"].as_str().unwrap().contains("chain ends at"), "{v}");
        st.db.put_doc(&tenant, crate::db::DocTable::Decisions, &last.id, &serde_json::to_string(&last).unwrap()).await.unwrap();
        let (_, v) = body(crate::decisions::verify(State(st.clone()), Extension(analyst.clone())).await).await;
        assert_eq!(v["valid"], true, "restored: {v}");

        // a self-consistent "waiting" record put into the database on its own is never acted on
        let mut f = siem_decision::Facts::new();
        f.insert("x".into(), siem_decision::fact(siem_decision::Val::Bool(true), siem_decision::Origin::Context, ""));
        let rules = vec![siem_decision::Rule { id: "Z".into(), title: "z".into(), when: siem_decision::cmp("x", siem_decision::Op::Eq, siem_decision::Val::Bool(true)), effect: siem_decision::Effect::RequireApproval, hard: true, reference: "".into() }];
        let fake = siem_decision::decide("dec-fake", Some((n + 40, "00")), last.ts, "block_ip", "8.8.8.8", "soar:x", f, rules, json!({ "agent_id": "001", "ip": "8.8.8.8", "hours": 1 }), "");
        assert!(siem_decision::verify(&fake).is_ok());
        st.db.put_doc(&tenant, crate::db::DocTable::Decisions, &fake.id, &serde_json::to_string(&fake).unwrap()).await.unwrap();
        assert_eq!(body(crate::decisions::approve(State(st.clone()), Extension(admin2.clone()), Path(fake.id.clone())).await).await.0, 409);
        st.db.delete_doc(&tenant, crate::db::DocTable::Decisions, &fake.id).await.unwrap();

        let mut forged: siem_decision::Record = serde_json::from_value(one["record"].clone()).unwrap();
        forged.outcome = siem_decision::Outcome::Allowed;
        st.db.put_doc(&tenant, crate::db::DocTable::Decisions, &forged.id, &serde_json::to_string(&forged).unwrap()).await.unwrap();
        let (_, v) = body(crate::decisions::verify(State(st.clone()), Extension(analyst.clone())).await).await;
        assert_eq!((v["valid"].as_bool(), v["bad_seq"].as_u64()), (Some(false), Some(forged.seq)), "{v}");
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    st.db.root().query(&format!("DROP DATABASE IF EXISTS `{dbname}`")).execute().await.unwrap();
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

#[tokio::test]
#[ignore]
async fn lost_replica_metadata_is_restored() {
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let db = format!("reptest{}", std::process::id());
    let root = st.db.root();
    let zk = format!("/clickhouse/tables/test/{db}/t");
    let q = |sql: String| async move { root.query(&sql).execute().await };
    q(format!("CREATE DATABASE {db}")).await.unwrap();
    let r = std::panic::AssertUnwindSafe(async {
        q(format!("CREATE TABLE {db}.t (x UInt8) ENGINE = ReplicatedMergeTree('{zk}', 'r1') ORDER BY x")).await.unwrap();
        q(format!("INSERT INTO {db}.t VALUES (7)")).await.unwrap();
        // what a Keeper that started over looks like: the table's metadata is gone
        q(format!("DETACH TABLE {db}.t")).await.unwrap();
        q(format!("SYSTEM DROP REPLICA 'r1' FROM ZKPATH '{zk}'")).await.unwrap();
        q(format!("ATTACH TABLE {db}.t")).await.unwrap();
        assert!(q(format!("INSERT INTO {db}.t VALUES (8)")).await.is_err(), "read-only without its metadata");
        // tests running in parallel restore too (every ClickHouseDb::init does), so the check is
        // that the table is writable again, whichever call restored it
        let restored = crate::db::restore_lost_replicas(root).await;
        if let Err(e) = q(format!("INSERT INTO {db}.t VALUES (8)")).await {
            panic!("still read-only after the restore ({restored:?}): {e}");
        }
        let sum = root.query(&format!("SELECT toUInt64(sum(x)) FROM {db}.t")).fetch_one::<u64>().await.unwrap();
        assert_eq!(sum, 15, "the old row is kept and new ones are written");
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    let _ = root.query(&format!("DROP DATABASE IF EXISTS {db} SYNC")).execute().await;
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

#[tokio::test]
#[ignore]
async fn intel_and_investigation_end_to_end() {
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let tenant = format!("invtest{}", std::process::id());
    let dbname = st.db.provision_tenant_db(&tenant).await.unwrap();
    st.tenants.write().unwrap().push(serde_json::from_value(json!({ "id": tenant, "name": tenant, "ai_enabled": false })).unwrap());
    let analyst = AuthCtx { username: "ana".into(), role: "analyst".into(), permissions: vec!["siem-alerts".into()], ..ctx(&tenant) };
    let r = std::panic::AssertUnwindSafe(async {
        // the feeds list one attacker IP and one exploited CVE
        let row = |source: &str, kind: &str, value: &str| (source.to_string(), "botnet_c2".to_string(), "HIGH".to_string(), kind.to_string(), value.to_string(), format!("{source} lists {value}"));
        crate::intel::set_index_for_tests(vec![row("feodo", "ip:port", "198.51.100.66:443"), row("cisa_kev", "cve", "CVE-2024-3400")]);

        // the host and its tenant
        let agent = siem_core::Agent { id: "077".into(), name: "web-77".into(), ip: "10.0.0.77".into(), os: "Ubuntu".into(), version: "4.14".into(), status: siem_core::AgentStatus::Active, last_keepalive: chrono::Utc::now(), os_type: "linux".into() };
        st.agents.write().unwrap().insert("077".into(), agent);
        st.agent_tenants.write().unwrap().insert("077".into(), tenant.clone());
        st.vulnerabilities.write().unwrap().push(serde_json::from_value(json!({ "cve": "CVE-2024-3400", "title": "PAN-OS", "severity": "Critical", "cvss_score": 10.0, "package_name": "panos", "installed_version": "10.2", "fixed_version": null, "agent_id": "077", "agent_name": "web-77", "status": "Active", "detected_at": "", "description": "", "reference": "", "category": "" })).unwrap());

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut a1 = alert(5760, 5, "sshd: authentication failed", "077", "198.51.100.66", now - 60_000);
        a1.agent.name = "web-77".into();
        a1.rule.mitre = Some(siem_core::MitreAttack { id: "T1110".into(), tactic: "Credential Access".into(), technique: "Brute Force".into() });
        let mut a2 = alert(5715, 3, "sshd: authentication success", "077", "10.0.0.9", now - 30_000);
        a2.agent.name = "web-77".into();
        assert!(st.db.insert_alerts(&[crate::tenancy::tag_alert(a1, &tenant), crate::tenancy::tag_alert(a2, &tenant)]).await.is_empty());

        // SOAR sees the feed hit, so a block on a level-5 alert is not "weak evidence"
        let mut a = serde_json::to_value(alert(5760, 5, "sshd: authentication failed", "077", "198.51.100.66", now)).unwrap();
        a["data"]["srcip"] = json!("198.51.100.66");
        let c = crate::soar::context(&a, &tenant);
        assert!(c.is_malicious, "the feeds list the source");
        let pb: provigil_common::soar::SoarNativePlaybook = serde_json::from_value(json!({
            "id": "pb1", "name": "Block C2", "description": "", "enabled": 1, "cond_field": "threat_intel", "cond_op": "==", "cond_value": "true",
            "action_type": "block_ip", "action_config": "{}", "run_count": 0, "last_run": null, "created_at": "", "updated_at": "", "tenant_id": tenant,
        }))
        .unwrap();
        assert!(provigil_common::soar::conditions::evaluate_condition(&pb, &c), "the threat-intel playbook condition matches");
        assert!(crate::decisions::gate_network(&st, &pb, &c).await.is_ok(), "threat intel is enough evidence for the policy");

        // the investigation of the IP
        let inv = |q: &str| crate::investigate::investigate(State(st.clone()), Extension(analyst.clone()), Query(crate::investigate::InvestigateQuery { q: q.into(), days: Some(1) }));
        let v = inv("198.51.100.66").await.0;
        assert_eq!(v["kind"], "ip", "{v}");
        assert_eq!(v["summary"]["alerts"], 1);
        assert_eq!(v["summary"]["verdict"], "malicious");
        assert_eq!(v["intel"][0]["hits"][0]["source"], "feodo");
        assert!(v["timeline"].as_array().unwrap().iter().any(|e| e["type"] == "decision"), "the block decision is on the timeline");
        assert!(v["summary"]["techniques"]["T1110"] == 1);

        // the investigation of the host
        let h = inv("WEB-77").await.0;
        assert_eq!(h["kind"], "host", "{h}");
        assert_eq!(h["summary"]["alerts"], 2);
        assert_eq!(h["intel"][0]["value"], "198.51.100.66", "a remote IP the host dealt with is listed");
        assert_eq!(h["host"]["vulnerabilities"][0]["known_exploited"], true, "CISA KEV");
        assert_eq!(h["summary"]["verdict"], "suspicious");

        // another tenant's analyst sees nothing of it
        let other = AuthCtx { tenant_id: "default".into(), ..analyst.clone() };
        let o = crate::investigate::investigate(State(st.clone()), Extension(other), Query(crate::investigate::InvestigateQuery { q: "web-77".into(), days: Some(1) })).await.0;
        assert_ne!(o["kind"], "host", "web-77 is not an agent of the other tenant");
        assert_eq!(crate::investigate::investigate(State(st.clone()), Extension(analyst.clone()), Query(crate::investigate::InvestigateQuery { q: "x".into(), days: None })).await.0["status"], "error");
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    crate::intel::set_index_for_tests(Vec::new());
    st.db.root().query(&format!("DROP DATABASE IF EXISTS `{dbname}`")).execute().await.unwrap();
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

#[tokio::test]
#[ignore]
async fn network_response_end_to_end() {
    let st = state().await;
    assert!(st.db.is_connected(), "ClickHouse is not reachable");
    let tenant = format!("resptest{}", std::process::id());
    let dbname = st.db.provision_tenant_db(&tenant).await.unwrap();
    st.tenants.write().unwrap().push(serde_json::from_value(json!({ "id": tenant, "name": tenant, "ai_enabled": false })).unwrap());
    let body = |r: axum::response::Response| async move {
        let s = r.status();
        (s, serde_json::from_slice::<serde_json::Value>(&axum::body::to_bytes(r.into_body(), 1 << 22).await.unwrap()).unwrap_or_default())
    };
    // a firewall (generic REST) and a UniFi controller that record what they are asked
    let calls: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Arc::default();
    let rec = |path: &'static str| {
        let calls = calls.clone();
        move |Json(b): Json<serde_json::Value>| {
            let calls = calls.clone();
            async move {
                calls.lock().unwrap().push(json!({ "path": path, "body": b }));
                ([("set-cookie", "unifises=x")], Json(json!({ "rule_id": "fw-rule-7" })))
            }
        }
    };
    let app = axum::Router::new()
        .route("/fw", axum::routing::post(rec("fw")))
        .route("/unifi/api/login", axum::routing::post(rec("login")))
        .route("/unifi/api/s/default/cmd/stamgr", axum::routing::post(rec("stamgr")));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let seen = |path: &str, field: &str, value: &str| calls.lock().unwrap().iter().any(|c| c["path"] == path && c["body"][field] == value);

    let r = std::panic::AssertUnwindSafe(async {
        let store = crate::soar::Store { db: st.db.clone(), state: Some(st.clone()) };
        store.put_integration(&tenant, "i-fw", "Edge firewall", "rest", &json!({ "host": format!("{base}/fw"), "api_key": "k" }), true).await.unwrap();
        store.put_integration(&tenant, "i-sw", "Office switch", "unifi", &json!({ "host": format!("{base}/unifi"), "username": "admin", "password": "p", "site": "default" }), true).await.unwrap();

        // ── blocks at the perimeter ──
        assert!(crate::response::block(&st, &tenant, "10.1.1.1", 1, "both", None, "t", "r").await.is_err(), "private addresses are not blocked");
        let (b, d) = crate::response::block(&st, &tenant, "203.0.113.50", 2, "both", Some("000"), "soar:test", "test").await.unwrap();
        assert!(seen("fw", "action", "block") && seen("fw", "ip", "203.0.113.50"), "the firewall got the block");
        assert_eq!((b.firewall_type.as_str(), b.firewall_rule_id.as_str(), b.status.as_str()), ("rest", "fw-rule-7", "active"));
        assert!(b.agent_result.contains("cannot run active responses") && d.contains("rest:"), "the agent part is reported, the firewall part done: {d}");
        let analyst = AuthCtx { role: "analyst".into(), permissions: vec!["soar".into()], ..ctx(&tenant) };
        let list = crate::response::list_blocks(State(st.clone()), Extension(analyst.clone())).await.0;
        assert_eq!(list["data"][0]["src_ip"], "203.0.113.50");
        let (s, rv) = body(crate::response::revoke_block(State(st.clone()), Extension(analyst.clone()), Json(crate::response::ById { id: b.id.clone() })).await).await;
        assert!(s == 200 && seen("fw", "action", "unblock"), "revoked at the firewall: {rv}");
        assert_eq!(crate::response::list_blocks(State(st.clone()), Extension(analyst.clone())).await.0["data"].as_array().unwrap().len(), 0);

        // an expired block is lifted by the sweeper
        let (mut b2, _) = crate::response::block(&st, &tenant, "203.0.113.51", 1, "firewall", None, "t", "r").await.unwrap();
        b2.expires_ts = 1;
        st.db.put_doc(&tenant, crate::db::DocTable::Blocks, &b2.id, &serde_json::to_string(&b2).unwrap()).await.unwrap();
        assert!(crate::response::sweep(&st).await >= 1);
        let after: crate::response::Block = serde_json::from_str(&st.db.doc(&tenant, crate::db::DocTable::Blocks, &b2.id).await.unwrap().unwrap()).unwrap();
        assert_eq!(after.status, "expired");

        // a person's block: protected list, and no host-level "rst" from here
        let policy = |p: serde_json::Value| Json(serde_json::from_value::<crate::decisions::Settings>(p).unwrap());
        assert_eq!(body(crate::decisions::put_policy(State(st.clone()), Extension(ctx(&tenant)), policy(json!({ "protected": ["198.51.100.0/24"], "max_isolations_per_hour": 1 }))).await).await.0, 200);
        let mb = |ip: &str, e: &str| crate::response::manual_block(State(st.clone()), Extension(analyst.clone()), Json(crate::response::ManualBlock { src_ip: ip.into(), duration_hours: Some(1), enforcement: Some(e.into()), reason: None }));
        assert_eq!(mb("198.51.100.9", "firewall").await.status(), 403, "protected");
        assert_eq!(mb("203.0.113.60", "rst").await.status(), 400);
        assert_eq!(mb("203.0.113.60", "firewall").await.status(), 200);

        // ── isolation on the switch ──
        assert!(crate::response::isolate(&st, &tenant, "10.0.0.77", Some("aws_sg"), None, "", "t", "r", None).await.unwrap_err().contains("No enabled aws_sg"));
        let (i, _) = crate::response::isolate(&st, &tenant, "10.0.0.77", None, Some(999), "", "t", "r", None).await.unwrap();
        assert!(seen("stamgr", "cmd", "block-sta") && seen("stamgr", "ip", "10.0.0.77"), "the controller got block-sta");
        assert_eq!((i.method.as_str(), i.enforcement.as_str()), ("switch_vlan", "unifi"));
        let isos = crate::response::list_isolations(State(st.clone()), Extension(analyst.clone())).await.0;
        assert_eq!(isos["data"][0]["target_ip"], "10.0.0.77");
        let (s, _) = body(crate::response::unisolate_handler(State(st.clone()), Extension(analyst.clone()), Json(crate::response::ById { id: i.id.clone() })).await).await;
        assert!(s == 200 && seen("stamgr", "cmd", "unblock-sta"), "restored on the controller");

        // ── SOAR isolate_host, through the guardrails ──
        let pb: provigil_common::soar::SoarNativePlaybook = serde_json::from_value(json!({
            "id": "pb-iso", "name": "Quarantine host", "description": "", "enabled": 1, "cond_field": "score", "cond_op": ">", "cond_value": "0",
            "action_type": "isolate_host", "action_config": "{\"quarantine_vlan\": 999}", "run_count": 0, "last_run": null, "created_at": "", "updated_at": "", "tenant_id": tenant,
        }))
        .unwrap();
        let alert_on = |host_ip: &str, level: u8| {
            let mut a = serde_json::to_value(alert(100300, level, "Ransomware note written", "000", "", chrono::Utc::now().timestamp_millis() as u64)).unwrap();
            a["agent"]["ip"] = json!(host_ip);
            a
        };
        let gate = |a: serde_json::Value| {
            let c = crate::soar::context(&a, &tenant);
            let (st, pb) = (st.clone(), pb.clone());
            async move { crate::decisions::gate_network(&st, &pb, &c).await }
        };
        assert!(gate(alert_on("198.51.100.20", 13)).await.unwrap_err().1.contains("G6"), "protected host");
        assert!(gate(alert_on("8.8.4.4", 13)).await.unwrap_err().1.contains("G7"), "a public address is not one of the tenant's hosts");
        assert_eq!(gate(alert_on("10.0.0.80", 8)).await.unwrap_err().0, "awaiting_approval", "weak evidence (P6)");
        assert!(gate(alert_on("10.0.0.81", 13)).await.is_ok(), "critical, internal, not protected");
        let g8 = gate(alert_on("10.0.0.82", 13)).await.unwrap_err();
        assert!(g8.0 == "awaiting_approval" && g8.1.contains("G8"), "1 isolation per hour: {g8:?}");
        // the real SOAR path runs the isolation for an allowed alert
        let req: crate::soar::PlaybookReq = serde_json::from_value(json!({ "name": "Quarantine host", "cond_field": "rule_level", "cond_op": ">=", "cond_value": "13", "action_type": "isolate_host", "action_config": "{}" })).unwrap();
        store.insert_playbook(&tenant, "pb-real-iso", &req).await.unwrap();
        assert_eq!(body(crate::decisions::put_policy(State(st.clone()), Extension(ctx(&tenant)), policy(json!({ "protected": ["198.51.100.0/24"], "max_isolations_per_hour": 10 }))).await).await.0, 200);
        crate::soar::run_playbooks(&store, vec![(alert_on("10.0.0.90", 14), tenant.clone())]).await;
        let runs = store.runs(&tenant).await.unwrap();
        assert!(runs.iter().any(|r| r["status"] == "success" && r["detail"].as_str().unwrap().contains("10.0.0.90 isolated with unifi")), "{runs:?}");
        assert!(seen("stamgr", "ip", "10.0.0.90"));
    });
    let res = futures_util::FutureExt::catch_unwind(r).await;
    st.db.root().query(&format!("DROP DATABASE IF EXISTS `{dbname}`")).execute().await.unwrap();
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

/// EDR actions refuse what they must before the decision gate and before anything is
/// sent to an agent: a non-Windows agent, a missing / system pid, a missing path, an
/// id that could be a path.
#[tokio::test]
#[ignore]
async fn edr_actions_refuse_before_sending() {
    let st = state().await;
    let c = ctx("t_edr_test");
    for (id, os) in [("901", "linux"), ("902", "windows")] {
        st.agents.write().unwrap().insert(
            id.into(),
            siem_core::Agent { id: id.into(), name: format!("h{id}"), ip: "10.0.0.9".into(), os: os.into(), version: "v4.14.7".into(), status: siem_core::AgentStatus::Active, last_keepalive: chrono::Utc::now(), os_type: os.into() },
        );
        st.agent_tenants.write().unwrap().insert(id.into(), "t_edr_test".into());
    }
    let run = |agent: &'static str, p: serde_json::Value| {
        let (st, c) = (st.clone(), c.clone());
        async move {
            let r = crate::edr_agent_action(&st, &c, agent, p["action"].as_str().unwrap(), &p).await;
            let code = r.status();
            let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
            (code.as_u16(), String::from_utf8_lossy(&b).to_string())
        }
    };
    let (code, m) = run("901", json!({ "action": "kill_process", "pid": 1234 })).await;
    assert!(code == 400 && m.contains("Windows"), "{m}");
    for p in [
        json!({ "action": "kill_process" }),
        json!({ "action": "kill_process", "pid": 4 }),
        json!({ "action": "kill_process", "pid": "abc" }),
        json!({ "action": "quarantine_file", "path": "  " }),
        json!({ "action": "restore_file", "quarantine_id": r"..\..\x" }),
    ] {
        let (code, m) = run("902", p.clone()).await;
        assert_eq!(code, 400, "{p}: {m}");
    }
}
