//! Red Swarm rounds through the real analysis engine: a round's sample events go into the
//! engine's event queue exactly as an agent's events do (the gateway's hand-off: the agent's
//! label, the queue of a Windows event or of a log line), with the location
//! `redswarm/<round id>/<technique>`. Only rounds this server started count: an event whose
//! location names an unknown or finished round is an ordinary event (an agent cannot hide its
//! events by naming them so).
//!
//! What the engine finds for a round is a simulation (`on_alerts`): shown live and to the round's
//! verifier, never stored, scored, grouped into cases or answered with an active response; the
//! round's events are not archived as the computer's own (`on_events`).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use provigil_ipc::queue;

/// A round's events and alerts are recognised this long after it started.
const ROUND_LIFE: Duration = Duration::from_secs(15 * 60);
const PREFIX: &str = "redswarm/";

/// round id -> (agent id, started)
static ROUNDS: Mutex<Option<HashMap<String, (String, Instant)>>> = Mutex::new(None);

fn same_agent(a: &str, b: &str) -> bool {
    match (a.parse::<u32>(), b.parse::<u32>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// The location of a round's events.
pub fn location(round: &str, technique: &str) -> String {
    format!("{PREFIX}{round}/{technique}")
}

/// The round a location names, when this server started it for that agent and it is recent.
pub fn round_of(location: &str, agent_id: &str) -> Option<String> {
    let round = location.strip_prefix(PREFIX)?.split('/').next()?;
    let mut g = ROUNDS.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    map.retain(|_, (_, at)| at.elapsed() < ROUND_LIFE);
    map.get(round).filter(|(a, _)| same_agent(a, agent_id)).map(|_| round.to_string())
}

pub fn register(round: &str, agent_id: &str) {
    let mut g = ROUNDS.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    map.retain(|_, (_, at)| at.elapsed() < ROUND_LIFE);
    map.insert(round.to_string(), (agent_id.to_string(), Instant::now()));
}

/// A sample with its placeholders filled for the target.
pub fn fill(sample: &str, host: &str) -> String {
    let now = chrono::Utc::now();
    sample
        .replace("%HOST%", host)
        .replace("%NOW%", &now.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
        .replace("%SYSLOGTIME%", &now.format("%b %e %H:%M:%S").to_string())
}

/// The engine queue of a sample: a Windows agent's event payload, or a log line.
pub fn queue_of(sample: &str) -> u8 {
    if sample.starts_with("{\"Message\"") || sample.starts_with("{\"Event\"") {
        queue::ids::WIN_EVT
    } else {
        queue::ids::LOCALFILE
    }
}

/// One sample as the engine's datagram, labelled as the target agent's.
pub fn datagram(agent_id: &str, name: &str, ip: &str, location: &str, sample: &str) -> Option<Vec<u8>> {
    let source = provigil_agent_server::engine::source(agent_id, name, ip)?;
    let mut msg = vec![queue_of(sample), b':'];
    msg.extend(queue::escape(location.as_bytes(), queue::LOCATION_ROOM));
    msg.push(b':');
    msg.extend_from_slice(fill(sample, name).as_bytes());
    queue::message(&msg, &source, queue::ids::SECURE)
}

/// Sends a round's events (`RawEvent`s from the executor: their messages are the samples, their
/// metadata the round and technique) to the engine of `home`. Err when the engine is not there.
pub async fn inject(home: &Path, agent_id: &str, name: &str, ip: &str, events: &[siem_core::RawEvent]) -> Result<usize, String> {
    let Some(first) = events.first() else { return Ok(0) };
    let round = first.metadata.get("redswarm_round").cloned().ok_or("the round has no id")?;
    let technique = first.metadata.get("technique_id").cloned().unwrap_or_default();
    register(&round, agent_id);
    let loc = location(&round, &technique);
    let tx = provigil_ipc::aio::DatagramSender::connect(home.join(queue::EVENT_QUEUE)).await.map_err(|e| format!("the analysis engine is not running: {e}"))?;
    let mut sent = 0;
    for e in events {
        let d = datagram(agent_id, name, ip, &loc, &e.message).ok_or_else(|| format!("agent id '{agent_id}' cannot be sent to the engine"))?;
        tx.send(&d).await.map_err(|e| e.to_string())?;
        sent += 1;
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_rounds_this_server_started() {
        let round = uuid::Uuid::new_v4().to_string();
        let loc = location(&round, "T1110");
        assert_eq!(round_of(&loc, "007"), None, "not started: an ordinary event");
        register(&round, "7");
        assert_eq!(round_of(&loc, "007").as_deref(), Some(round.as_str()));
        assert_eq!(round_of(&loc, "008"), None, "another agent's event naming the round");
        assert_eq!(round_of("/var/log/auth.log", "007"), None);
    }

    #[test]
    fn samples_in_the_agents_form() {
        let win = siem_redswarm::find_technique_for("T1059.001", "windows").unwrap();
        let s = &win.sample_raw_logs[0];
        assert_eq!(queue_of(s), queue::ids::WIN_EVT);
        let filled = fill(s, "PC-01");
        assert!(!filled.contains('%') || filled.contains("%%"), "placeholders filled: {filled}");
        let v: serde_json::Value = serde_json::from_str(&filled).unwrap();
        assert!(v["Event"].as_str().unwrap().contains("<Computer>PC-01</Computer>"));
        let lin = siem_redswarm::find_technique_for("T1110.001", "linux").unwrap();
        assert_eq!(queue_of(&lin.sample_raw_logs[0]), queue::ids::LOCALFILE);
        assert!(fill(&lin.sample_raw_logs[0], "web01").contains(" web01 sshd[4102]: Failed password"));
        let d = datagram("7", "web01", "10.0.0.5", &location("r", "T1110.001"), &lin.sample_raw_logs[0]).unwrap();
        let d = String::from_utf8_lossy(&d);
        assert!(d.starts_with("1:[007] (web01) 10.0.0.5->redswarm/r/T1110.001:"), "{d}");
    }
}

/// Every catalog attack, through the real analysis engine with the shipped ruleset: each must be
/// caught with one of its expected ATT&CK ids. This is what makes a Defended round mean that the
/// rules running on the PCs' events catch the attack.
#[cfg(test)]
mod engine_tests {
    use super::*;
    use provigil_analysisd::config::Config;
    use provigil_analysisd::daemon::{run, Service, ServiceLog};
    use provigil_ipc::aio::{framing, StreamListener};
    use std::sync::Arc;

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                copy_dir(&p, &to.join(e.file_name()));
            } else {
                std::fs::copy(&p, to.join(e.file_name())).unwrap();
            }
        }
    }

    async fn agent_db(home: &Path) {
        let l = StreamListener::bind(home.join(provigil_ipc::agentdb::DB_SOCKET)).await.unwrap();
        tokio::spawn(async move {
            while let Ok(mut s) = l.accept().await {
                tokio::spawn(async move {
                    while let Ok(_q) = framing::recv(&mut s, 65536).await {
                        if framing::send(&mut s, b"ok []").await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_attack_is_caught_by_the_shipped_rules() {
        let backend = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        copy_dir(&backend.join("ruleset/decoders"), &home.join("ruleset/decoders"));
        copy_dir(&backend.join("ruleset/rules"), &home.join("ruleset/rules"));
        copy_dir(&backend.join("data/manager/etc/lists"), &home.join("etc/lists"));
        std::fs::copy(backend.join("etc/internal_options.conf"), home.join("etc/internal_options.conf")).unwrap();
        std::fs::write(home.join("etc/local_internal_options.conf"), "").unwrap();
        std::fs::write(
            home.join("etc/ossec.conf"),
            "<ossec_config><global><jsonout_output>yes</jsonout_output><alerts_log>no</alerts_log><logall_json>no</logall_json></global>\
             <alerts><log_alert_level>3</log_alert_level></alerts>\
             <ruleset><decoder_dir>ruleset/decoders</decoder_dir><rule_dir>ruleset/rules</rule_dir><rule_exclude>0215-policy_rules.xml</rule_exclude>\
             <list>etc/lists/audit-keys</list><list>etc/lists/amazon/aws-eventnames</list><list>etc/lists/security-eventchannel</list>\
             <list>etc/lists/malicious-ioc/malware-hashes</list><list>etc/lists/malicious-ioc/malicious-ip</list><list>etc/lists/malicious-ioc/malicious-domains</list></ruleset></ossec_config>",
        )
        .unwrap();
        for d in ["logs/alerts", "logs/archives", "logs/firewall", "queue/alerts", "queue/fts", "queue/sockets", "queue/db", "var/run", "stats"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        agent_db(&home).await;
        let cfg = Config::load(&home, &home.join("etc/ossec.conf"), false).expect("config");
        let log = Arc::new(ServiceLog::new(provigil_daemon::Log::open(&home, "provigil-analysisd"), true));
        let service = Service::new(cfg, &log, false).expect("ruleset");
        std::thread::spawn(move || run(service, log));
        let t = Instant::now();
        let tx = loop {
            if let Ok(s) = provigil_ipc::aio::DatagramSender::connect(home.join(queue::EVENT_QUEUE)).await {
                break s;
            }
            assert!(t.elapsed() < Duration::from_secs(60), "the engine did not start");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };

        let catalog = siem_redswarm::get_curated_catalog();
        for (i, t) in catalog.iter().enumerate() {
            let agent = format!("{}", 100 + i);
            let loc = location(&format!("round{i}"), &t.id);
            for s in &t.sample_raw_logs {
                tx.send(&datagram(&agent, "pc01", "10.0.0.5", &loc, s).unwrap()).await.unwrap();
            }
        }
        // the ATT&CK ids of each rule, from the rule files (the live server reads them from its
        // ATT&CK database, which a test home does not have)
        let mut mitre: HashMap<String, Vec<String>> = HashMap::new();
        let id_re = regex::Regex::new(r"<id>(T[0-9.]+)</id>").unwrap();
        for f in std::fs::read_dir(home.join("ruleset/rules")).unwrap().flatten() {
            let text = std::fs::read_to_string(f.path()).unwrap_or_default();
            for chunk in text.split("<rule id=\"").skip(1) {
                let id = chunk.split('"').next().unwrap_or("").to_string();
                let body = chunk.split("</rule>").next().unwrap_or("");
                mitre.insert(id, id_re.captures_iter(body).map(|c| c[1].to_string()).collect());
            }
        }
        let mitre_of = |a: &serde_json::Value| mitre.get(a["rule"]["id"].as_str().unwrap_or("")).cloned().unwrap_or_default();
        // the engine's alerts, by round
        let alerts_file = home.join("logs/alerts/alerts.json");
        let mut missing: Vec<String> = Vec::new();
        let start = Instant::now();
        loop {
            let text = std::fs::read_to_string(&alerts_file).unwrap_or_default();
            let alerts: Vec<serde_json::Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
            missing.clear();
            let mut report = String::new();
            for (i, t) in catalog.iter().enumerate() {
                let loc = location(&format!("round{i}"), &t.id);
                let mine: Vec<&serde_json::Value> = alerts.iter().filter(|a| a["location"] == loc.as_str()).collect();
                let caught = mine.iter().any(|a| mitre_of(a).iter().any(|m| t.expected_mitre_ids.iter().any(|e| m.starts_with(e.as_str()))));
                let fired: Vec<String> = mine.iter().map(|a| format!("{} {:?} {}", a["rule"]["id"], mitre_of(a), a["rule"]["description"])).collect();
                report.push_str(&format!("{} {} ({}): {}\n", t.id, t.name, t.platforms[0], if fired.is_empty() { "nothing".into() } else { fired.join("; ") }));
                if !caught {
                    missing.push(format!("{} {}", t.id, t.platforms[0]));
                }
            }
            if missing.is_empty() {
                println!("{report}");
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(20), "not caught: {missing:?}\n{report}");
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}
