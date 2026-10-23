//! The SIEM analyst AI features end to end, against the local ClickHouse and
//! the running manager's analysisd (logtest), in a scratch tenant database
//! that is dropped afterwards. The tenant's AI is off, so no AI provider is called.
//!
//! `cargo test -p siem-api analyst_tests -- --ignored --nocapture`

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use axum::extract::{Extension, Path, State};
use axum::Json;
use serde_json::json;

use crate::tenancy::AuthCtx;
use crate::AppState;

async fn state() -> AppState {
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
