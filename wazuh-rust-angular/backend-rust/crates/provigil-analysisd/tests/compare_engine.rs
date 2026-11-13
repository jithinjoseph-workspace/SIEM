//! Rule matching, old against new: both engines load the shipped ruleset and process the same
//! stream of ruleset test logs (several agents and locations, a clock moving forward); every
//! outcome (alert, rule, context logs, firewall and archive copies, active responses, ignore
//! lines, warnings) and the engine state must be identical.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use provigil_analysisd::config::{Config, Response};
use provigil_analysisd::engine::{self as ne, Engine as NewEngine, EngineSettings};
use provigil_analysisd::event::{Event as NewEvent, Instant};
use provigil_analysisd::messages::Messages;
use provigil_analysisd::process as np;
use provigil_analysisd::rules::RuleSettings;
use siem_analysisd::analysis as oa;
use siem_analysisd::engine::{self as oe, Engine as OldEngine, EngineConfig};
use siem_analysisd::event::{Event as OldEvent, TimeSpec};
use siem_analysisd::logmsg::LogList;
use siem_analysisd::rules::{self as or, RuleConfig};

const ORDER: usize = 256;

#[derive(Clone)]
struct Fixed(Arc<AtomicI64>);
impl oe::Clock for Fixed {
    fn now(&self) -> TimeSpec {
        TimeSpec { sec: self.0.load(Ordering::SeqCst), nsec: 0 }
    }
}
impl ne::Clock for Fixed {
    fn now(&self) -> Instant {
        Instant { sec: self.0.load(Ordering::SeqCst), nsec: 0 }
    }
}

fn manager() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager")
}

fn test_logs() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ruleset/testing/tests");
    let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
    names.sort();
    let mut out = Vec::new();
    for p in names {
        for line in std::fs::read_to_string(&p).unwrap_or_default().lines() {
            if let (true, Some((_, v))) = (line.starts_with("log "), line.split_once(" = ")) {
                out.push(v.to_string());
            }
        }
    }
    out
}

/// What a writer gets of an event.
fn old_event(e: &OldEvent, o: &OldEngine) -> String {
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {} {} {:?} {:?} {:?} {:?} {}",
        e.generated_rule.map(|r| o.rules.infos[r].sigid),
        e.comment,
        e.last_events,
        e.previous,
        e.f,
        e.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(),
        (e.decoder, e.log, &e.buf),
        e.matched,
        e.r_firedtimes,
        e.prev_rule.map(|r| o.rules.infos[r].sigid),
        (&e.hostname, &e.agent_id, &e.program_name),
        (e.sid_node_to_delete.is_some(), e.group_node_to_delete.as_ref().map(|v| v.len())),
        e.labels.len(),
        e.is_a_copy
    )
}

fn new_event(e: &NewEvent, n: &NewEngine) -> String {
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {} {} {:?} {:?} {:?} {:?} {}",
        e.generated_rule.map(|r| n.rules.rules[r].sigid),
        e.comment,
        e.last_events,
        e.previous,
        e.f,
        e.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(),
        (e.decoder, e.log_start, &e.buf),
        e.matched,
        e.fired_times,
        e.prev_rule.map(|r| n.rules.rules[r].sigid),
        (&e.hostname, &e.agent_id, &e.program_name),
        (e.sid_node_to_delete.is_some(), e.group_node_to_delete.as_ref().map(|v| v.len())),
        e.labels.len(),
        e.is_a_copy
    )
}

fn old_outcome(x: &oa::Outcome, o: &OldEngine) -> Vec<String> {
    let ev = |e: &Option<OldEvent>| e.as_ref().map(|e| old_event(e, o));
    vec![
        format!("alert {:?}", ev(&x.alert)),
        format!("stats {:?}", ev(&x.stats_alert)),
        format!("fw {:?} {}", ev(&x.firewall), x.firewall_event),
        format!("archive {:?}", ev(&x.archive)),
        format!("ar {:?}", x.ar.iter().map(|(i, e)| (*i, old_event(e, o))).collect::<Vec<_>>()),
        format!("ignore {:?} warn {:?}", x.ignore_line, x.warnings),
    ]
}

fn new_outcome(x: &np::Outcome, n: &NewEngine) -> Vec<String> {
    let ev = |e: &Option<NewEvent>| e.as_ref().map(|e| new_event(e, n));
    vec![
        format!("alert {:?}", ev(&x.alert)),
        format!("stats {:?}", ev(&x.stats_alert)),
        format!("fw {:?} {}", ev(&x.firewall), x.firewall_event),
        format!("archive {:?}", ev(&x.archive)),
        format!("ar {:?}", x.ar.iter().map(|(i, e)| (*i, new_event(e, n))).collect::<Vec<_>>()),
        format!("ignore {:?} warn {:?}", x.ignore_line, x.warnings),
    ]
}

fn state(o: &OldEngine, n: &NewEngine) -> (String, String) {
    let fired = |v: Vec<i32>| v.iter().filter(|&&f| f != 0).count();
    (
        format!(
            "{} {} {} {} {:?} {}",
            o.last_events.len(),
            o.hourly_alerts,
            o.fts_writes.len(),
            fired(o.rules.infos.iter().map(|r| r.firedtimes).collect()),
            o.rules.lists.iter().map(|l| l.nodes.len()).collect::<Vec<_>>(),
            o.events.len()
        ),
        format!(
            "{} {} {} {} {:?} {}",
            n.recent.len(),
            n.hourly_alerts,
            n.fts_lines.len(),
            fired(n.rules.rules.iter().map(|r| r.firedtimes).collect()),
            n.rules.event_lists.iter().map(|l| l.nodes.len()).collect::<Vec<_>>(),
            n.events.len()
        ),
    )
}

#[test]
fn shipped_ruleset_on_test_logs() {
    let home = manager();
    let cfg = Config::load(&home, &home.join("etc/ossec.conf"), false).unwrap();
    let work = tempfile::tempdir().unwrap();
    let (od, nd) = (work.path().join("old"), work.path().join("new"));
    for d in [&od, &nd] {
        std::fs::create_dir_all(d.join("diff")).unwrap();
        std::fs::write(d.join("ignore"), "\nsshd   \n").unwrap();
    }
    let clock = Fixed(Arc::new(AtomicI64::new(1_700_000_000)));

    let mut o = OldEngine::new(EngineConfig {
        rule: RuleConfig { decoder_order_size: ORDER, mailbylevel: 12, logbylevel: 3, default_timeframe: 360, rulepath: "ruleset/rules".into(), home: home.clone() },
        memorysize: 600,
        diff_dir: od.join("diff"),
        ignore_file: Some(od.join("ignore")),
        ..EngineConfig::default()
    });
    let mut n = NewEngine::new(EngineSettings {
        rules: RuleSettings { order_size: ORDER, email_level: 12, log_level: 3, default_timeframe: 360, rule_dir: "ruleset/rules".into(), home: home.clone() },
        memory_size: 600,
        diff_dir: nd.join("diff"),
        ignore_file: Some(nd.join("ignore")),
        ..EngineSettings::default()
    });
    o.clock = Box::new(clock.clone());
    n.clock = Box::new(clock.clone());
    let spec: [(i32, Option<&str>, Option<&str>); 3] = [(6, None, None), (0, Some("authentication_failed|sshd"), None), (0, None, Some("5712,31151,5503"))];
    let oars: Vec<or::ActiveResponse> = spec.iter().map(|(l, g, i)| or::ActiveResponse { level: *l, rules_group: g.map(String::from), rules_id: i.map(String::from), ..Default::default() }).collect();
    let nars: Vec<Response> = spec.iter().map(|(l, g, i)| Response { level: *l, rules_group: g.map(String::from), rules_id: i.map(String::from), ..Default::default() }).collect();
    let (mut ol, mut nl) = (LogList::default(), Messages::default());
    assert!(o.load_ruleset(&cfg.ruleset.decoders, &cfg.ruleset.lists, &cfg.ruleset.rules, Some(&oars), &mut ol));
    assert!(n.load_ruleset(&cfg.ruleset.decoders, &cfg.ruleset.lists, &cfg.ruleset.rules, Some(&nars), &mut nl));

    // the same MITRE table in both: most techniques the rules name, each with one or two tactics
    let mut techs: Vec<String> = n.rules.rules.iter().flat_map(|r| r.mitre_technique_id.iter().flatten().chain(r.mitre_id.iter().flatten()).cloned()).collect();
    techs.sort();
    techs.dedup();
    let tactic = |i: usize| (format!("TA{:04}", i % 14 + 1), format!("Tactic {}", i % 14 + 1));
    let mut om = siem_analysisd::mitre::MitreDb::default();
    let mut nm = provigil_analysisd::mitre::Mitre::default();
    for (i, t) in techs.iter().enumerate().filter(|(i, _)| i % 9 != 0) {
        let tacs: Vec<(String, String)> = (0..1 + i % 2).map(|k| tactic(i + k * 3)).collect();
        om.add(siem_analysisd::mitre::Technique { technique_id: t.clone(), technique_name: format!("Technique {t}"), tactics: tacs.iter().map(|(a, b)| siem_analysisd::mitre::Tactic { tactic_id: a.clone(), tactic_name: b.clone() }).collect() });
        nm.add(provigil_analysisd::mitre::Technique { id: t.clone(), name: format!("Technique {t}"), tactics: tacs.iter().map(|(a, b)| provigil_analysisd::mitre::Tactic { id: a.clone(), name: b.clone() }).collect() });
    }
    o.mitre = Some(Arc::new(om));
    n.mitre = Some(Arc::new(nm));
    let mut jsons = 0;
    let (oopt, nopt) = (oa::ProcessOptions { logfw: true, logall: true, stats: 0 }, np::Options { logfw: true, logall: true, stats: 0 });
    let (mut os, mut ns) = (oa::Stats::default(), np::Stats::default());
    let logs = test_logs();
    let mut alerts = 0;
    let mut contexts = 0;
    let mut r: u64 = 0x9E3779B97F4A7C15;
    // rounds 0-5 go through the logs once each; rounds 6-7 repeat each log 12 times from
    // one agent, so frequency and context rules fire
    let mut stream: Vec<(usize, usize, &String)> = Vec::new();
    for round in 0..8 {
        for (k, log) in logs.iter().enumerate() {
            for _ in 0..if round >= 6 { 12 } else { 1 } {
                stream.push((round, k, log));
            }
        }
    }
    {
        for &(round, k, log) in &stream {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            // the clock moves 0-3 seconds per event, sometimes a jump
            clock.0.fetch_add(if r % 500 == 0 { 400 } else if round >= 6 { (r % 2) as i64 } else { (r % 4) as i64 }, Ordering::SeqCst);
            let loc = ["1:stdin:", "1:[001] (agent1) 10.0.0.1->/var/log/secure:", "1:[002] (agent2) 10.0.0.2->/var/log/auth.log:", "f:[003] (win) any->EventChannel:"][(round + k) % 4];
            let msg = format!("{loc}{log}");
            let now = clock.0.load(Ordering::SeqCst);
            let mut oev = o.new_event();
            let mut nev = n.new_event();
            let a = oev.clean_msg(msg.as_bytes(), b"manager", TimeSpec { sec: now, nsec: 0 });
            let b = nev.clean(msg.as_bytes(), b"manager", Instant { sec: now, nsec: 0 });
            assert_eq!(a, b);
            if a.is_err() {
                continue;
            }
            o.decode(&mut oev);
            n.decode(&mut nev);
            // agent 001 has labels (an address, a nested key, a hidden one, a system one)
            let x = o.process_event(oev, &oopt, &mut os, None, 10, 3, &mut |e| {
                if e.agent_id.as_deref() != Some(b"001") {
                    return Vec::new();
                }
                let l = |k: &str, v: &str, hidden, system| siem_analysisd::labels::Label { key: k.into(), value: v.into(), flags: siem_analysisd::labels::LabelFlags { hidden, system } };
                vec![l("_agent_ip", "10.9.9.9", false, true), l("env", "prod", false, false), l("team.name", "sec", true, false), l("x", "[1,2]", false, false)]
            });
            let y = n.process(nev, &nopt, &mut ns, None, 10, 3, &mut |e| {
                if e.agent_id.as_deref() != Some(b"001") {
                    return Vec::new();
                }
                let l = |k: &str, v: &str, hidden, system| provigil_analysisd::event::Label { key: k.into(), value: v.into(), hidden, system };
                vec![l("_agent_ip", "10.9.9.9", false, true), l("env", "prod", false, false), l("team.name", "sec", true, false), l("x", "[1,2]", false, false)]
            });
            if let (Some(a), Some(b)) = (&x.alert, &y.alert) {
                let (mut ol2, mut nl2) = (LogList::default(), Messages::default());
                let ja = siem_analysisd::to_json::eventinfo_to_json(&o, a, false, &mut ol2);
                let jb = provigil_analysisd::alert_json::alert(&n, b, false, &mut nl2);
                assert_eq!(String::from_utf8_lossy(&ja), String::from_utf8_lossy(&jb), "{msg}");
                assert_eq!(ol2.msgs.iter().map(|m| m.msg.clone()).collect::<Vec<_>>(), nl2.list.iter().map(|m| m.text.clone()).collect::<Vec<_>>());
                jsons += 1;
                // alerts.log, the custom format and the json lines
                let (mut wa, mut wb) = (Vec::new(), Vec::new());
                siem_analysisd::output::os_log(&o, a, &mut wa).unwrap();
                provigil_analysisd::text_logs::alert(&n, b, &mut wb).unwrap();
                let fmt = b"$TIMESTAMP $FTELL $RULEALERT$HOSTNAME $LOCATION $RULEID $RULELEVEL $SRCIP $DSTUSER $FULLLOG $RULECOMMENT $RULEGROUP $X";
                siem_analysisd::output::os_custom_log(&o, a, fmt, &mut wa).unwrap();
                provigil_analysisd::text_logs::custom_alert(&n, b, fmt, &mut wb).unwrap();
                assert_eq!(String::from_utf8_lossy(&wa), String::from_utf8_lossy(&wb), "{msg}");
            }
            for (p, q) in [(&x.archive, &y.archive), (&x.firewall, &y.firewall)] {
                if let (Some(a), Some(b)) = (p, q) {
                    let (mut wa, mut wb) = (Vec::new(), Vec::new());
                    siem_analysisd::output::os_store(a, &mut wa).unwrap();
                    provigil_analysisd::text_logs::archive(b, &mut wb).unwrap();
                    let (mut a2, mut b2) = (a.clone(), b.clone());
                    siem_analysisd::output::fw_log(&mut a2, &mut wa).unwrap();
                    provigil_analysisd::text_logs::firewall(&mut b2, &mut wb).unwrap();
                    let (mut ol3, mut nl3) = (LogList::default(), Messages::default());
                    wa.extend(siem_analysisd::output::json_archive(&o, a, &mut ol3).unwrap_or_default());
                    wb.extend(provigil_analysisd::text_logs::json_archive(&n, b, &mut nl3).unwrap_or_default());
                    assert_eq!(String::from_utf8_lossy(&wa), String::from_utf8_lossy(&wb), "{msg}");
                }
            }
            let (xa, ya) = (old_outcome(&x, &o), new_outcome(&y, &n));
            for (p, q) in xa.iter().zip(&ya) {
                assert_eq!(p, q, "round {round}: {msg}");
            }
            let (sa, sb) = state(&o, &n);
            assert_eq!(sa, sb, "state after {msg}");
            alerts += usize::from(x.alert.is_some());
            contexts += usize::from(x.alert.as_ref().is_some_and(|e| e.last_events.as_ref().is_some_and(|l| !l.is_empty())));
        }
    }
    eprintln!("events {} alerts {alerts} with context {contexts}, json {jsons}", stream.len());
    assert!(alerts > 5000 && contexts > 50, "alerts {alerts} with context {contexts}");
}
