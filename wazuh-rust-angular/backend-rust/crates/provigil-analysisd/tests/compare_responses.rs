//! Active responses, old against new: alerts of the shipped ruleset on the test logs, each
//! sent through responses of every location kind to agents of every version kind; the
//! messages sent and logged must be identical.

use std::path::{Path, PathBuf};

use provigil_analysisd::config::{Command, Config, Response};
use provigil_analysisd::engine::{Engine as NewEngine, EngineSettings};
use provigil_analysisd::event::Instant;
use provigil_analysisd::messages::Messages;
use provigil_analysisd::responses as nr;
use provigil_analysisd::rules::RuleSettings;
use siem_analysisd::ar as oar;
use siem_analysisd::engine::{Engine as OldEngine, EngineConfig};
use siem_analysisd::event::TimeSpec;
use siem_analysisd::logmsg::LogList;
use siem_analysisd::rules::RuleConfig;
use siem_config::active_response as oc;

#[derive(Default)]
struct Sink(Vec<String>);

fn version(id: i32) -> (u8, &'static str) {
    match id % 7 {
        0 => (0, "Wazuh v4.7.1"),
        1 => (0, "Wazuh v4.2.3"),
        2 => (0, "Wazuh v3.13.0"),
        3 => (0, "ProVigil v1.0.0"),
        4 => (1, ""),
        5 => (2, ""),
        _ => (0, "odd"),
    }
}

impl oar::ArBackend for Sink {
    fn agent_version(&mut self, id: i32) -> oar::AgentVersion {
        match version(id) {
            (0, v) => oar::AgentVersion::Found(v.into()),
            (1, _) => oar::AgentVersion::NoInfo,
            _ => oar::AgentVersion::NoVersion,
        }
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        Some((1..9).collect())
    }
    fn node_name(&mut self) -> String {
        "node01".into()
    }
    fn send_exec(&mut self, m: &[u8]) {
        self.0.push(format!("exec {}", String::from_utf8_lossy(m)));
    }
    fn send_ar(&mut self, m: &[u8]) {
        self.0.push(format!("ar {}", String::from_utf8_lossy(m)));
    }
    fn send_provigil_ar(&mut self, m: &[u8]) {
        self.0.push(format!("pv {}", String::from_utf8_lossy(m)));
    }
}

impl nr::ResponseSink for Sink {
    fn agent_version(&mut self, id: i32) -> nr::AgentVersion {
        match version(id) {
            (0, v) => nr::AgentVersion::Found(v.into()),
            (1, _) => nr::AgentVersion::NoInfo,
            _ => nr::AgentVersion::NoVersion,
        }
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        Some((1..9).collect())
    }
    fn node_name(&mut self) -> String {
        "node01".into()
    }
    fn send_exec(&mut self, m: &[u8]) {
        self.0.push(format!("exec {}", String::from_utf8_lossy(m)));
    }
    fn send_ar(&mut self, m: &[u8]) {
        self.0.push(format!("ar {}", String::from_utf8_lossy(m)));
    }
    fn send_provigil_ar(&mut self, m: &[u8]) {
        self.0.push(format!("pv {}", String::from_utf8_lossy(m)));
    }
}

fn manager() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager")
}

#[test]
fn responses_for_test_alerts() {
    let home = manager();
    let cfg = Config::load(&home, &home.join("etc/ossec.conf"), false).unwrap();
    let mut o = OldEngine::new(EngineConfig { rule: RuleConfig { home: home.clone(), ..RuleConfig::default() }, ..EngineConfig::default() });
    let mut n = NewEngine::new(EngineSettings { rules: RuleSettings { home: home.clone(), ..RuleSettings::default() }, ..EngineSettings::default() });
    let (mut ol, mut nl) = (LogList::default(), Messages::default());
    assert!(o.load_ruleset(&cfg.ruleset.decoders, &cfg.ruleset.lists, &cfg.ruleset.rules, None, &mut ol));
    assert!(n.load_ruleset(&cfg.ruleset.decoders, &cfg.ruleset.lists, &cfg.ruleset.rules, None, &mut nl));

    // every location kind, with and without a timeout and an agent id
    let kinds: [(i32, Option<&str>, i32); 7] = [
        (oc::AS_ONLY, None, 0),
        (oc::REMOTE_AGENT, None, 600),
        (oc::SPECIFIC_AGENT, Some("002"), 0),
        (oc::ALL_AGENTS, None, 60),
        (oc::REMOTE_AGENT | oc::ALL_AGENTS, None, 0),
        (oc::SPECIFIC_AGENT, Some("x"), 0),
        (0, None, 0),
    ];
    let extra = Some("-a $x 'y' !z `q`".to_string());
    let ocmd = oc::ArCommand { name: "fw".into(), executable: "fw.cmd".into(), timeout_allowed: true, extra_args: extra.clone() };
    let ncmd = Command { name: "fw".into(), executable: "fw.cmd".into(), timeout_allowed: true, extra_args: extra };
    let ips: Vec<_> = ["10.0.0.0/8", "1.2.3.4"].iter().map(|i| provigil_regex::is_valid_ip(i).1.unwrap()).collect();
    let hosts = vec![provigil_regex::OsMatch::compile("^bad", 0).unwrap()];
    let owl = oar::ArWhitelist { ips: ips.clone(), hostnames: hosts.clone() };
    let nwl = nr::WhiteList { ips, hostnames: hosts };

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ruleset/testing/tests");
    let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
    files.sort();
    let lines: Vec<String> = files.iter().flat_map(|p| std::fs::read_to_string(p).unwrap_or_default().lines().map(String::from).collect::<Vec<_>>()).filter(|l| l.starts_with("log ")).collect();
    let (otree, ntree) = (o.rules.tree.clone(), n.rules.tree.clone());
    let mut sent = 0;
    for (k, line) in lines.iter().enumerate() {
        let Some((_, log)) = line.split_once(" = ") else { continue };
        let loc = ["1:stdin:", "1:[001] (agent1) 10.0.0.1->/var/log/secure:", "1:[002] (a2) 8.8.8.8->x:", "1:[000] (m) any->y:"][k % 4];
        let msg = format!("{loc}{log}");
        let (mut oe, mut ne) = (o.new_event(), n.new_event());
        if oe.clean_msg(msg.as_bytes(), b"m", TimeSpec { sec: 1_700_000_000, nsec: 0 }).is_err() {
            continue;
        }
        ne.clean(msg.as_bytes(), b"m", Instant { sec: 1_700_000_000, nsec: 0 }).unwrap();
        o.decode(&mut oe);
        n.decode(&mut ne);
        let (mut od, mut nd) = (None, None);
        let a = otree.iter().find_map(|t| o.check_if_rule_match(&mut oe, t, false, &mut od));
        let b = ntree.iter().find_map(|t| n.match_rule(&mut ne, t, false, &mut nd));
        let (Some(a), Some(b)) = (a, b) else { continue };
        oe.generated_rule = Some(a);
        ne.generated_rule = Some(b);
        for (i, (where_, agent, timeout)) in kinds.iter().enumerate() {
            let oa = oc::ActiveResponse { name: format!("fw{timeout}"), command: "fw".into(), agent_id: agent.map(String::from), location: *where_, timeout: *timeout, ..Default::default() };
            let na = Response { name: format!("fw{timeout}"), command: "fw".into(), agent_id: agent.map(String::from), location: *where_, timeout: *timeout, ..Default::default() };
            let flags = [3, 1, 2, 0][(k + i) % 4];
            let (mut os, mut ns) = (Sink::default(), Sink::default());
            let (mut ol2, mut nl2) = (LogList::default(), Messages::default());
            oar::os_exec(&o, &oe, &oa, &ocmd, flags, &owl, &mut os, &mut ol2);
            nr::run(&n, &ne, &na, &ncmd, flags, &nwl, &mut ns, &mut nl2);
            assert_eq!(os.0, ns.0, "{msg}");
            assert_eq!(ol2.msgs.iter().map(|m| m.msg.clone()).collect::<Vec<_>>(), nl2.list.iter().map(|m| m.text.clone()).collect::<Vec<_>>());
            sent += os.0.len();
        }
    }
    assert!(sent > 10_000, "{sent} messages");
    for (s, b) in [("a;b", "a\\;b"), ("a\\;b", "a\\;b"), ("x\\", "x\\\\")] {
        assert_eq!(oar::os_shell_escape(s.as_bytes()), nr::shell_escape(s.as_bytes()));
        assert_eq!(nr::shell_escape(s.as_bytes()), b.as_bytes());
    }
    for v in ["Wazuh v4.7.1", "v4.7.1", "Wazuh v4.2", "vv", "", "x v1.2.3.4", "ProVigil v1", "Wazuh v4.x.1"] {
        assert_eq!(oar::parse_agent_version(v), nr::agent_version(v), "{v}");
    }
}
