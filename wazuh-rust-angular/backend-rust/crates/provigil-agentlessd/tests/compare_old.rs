//! Agentless monitoring, old against new: the settings (every `<agentless>` rule and the check of
//! the other sections), the requests, and runs of sections against a stand-in script (the
//! events sent, the files kept, the log lines).
//!
//! The old code works relative to the working folder, so everything runs in one test, in turn.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use provigil_daemon::Log;

const SCRIPT: &str = if cfg!(windows) { "lessprobe.exe" } else { "lessprobe" };

fn script() -> PathBuf {
    let out = std::env::temp_dir().join(format!("provigil-agentlessd-probe-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let exe = out.join(SCRIPT);
    if !exe.exists() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/lessprobe.rs");
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
        assert!(std::process::Command::new(rustc).arg("-O").arg("-o").arg(&exe).arg(&src).status().unwrap().success());
    }
    exe
}

fn home(conf: &str) -> tempfile::TempDir {
    let h = tempfile::tempdir().unwrap();
    for d in ["etc", "agentless", "logs", "queue/agentless", "queue/diff", "queue/sockets"] {
        std::fs::create_dir_all(h.path().join(d)).unwrap();
    }
    std::fs::write(h.path().join("etc/ossec.conf"), conf).unwrap();
    for s in [SCRIPT, "ssh_integrity_check_linux", "ssh_generic_diff"] {
        std::fs::copy(script(), h.path().join("agentless").join(s)).unwrap();
    }
    h
}

fn log_lines(home: &Path) -> Vec<String> {
    std::fs::read_to_string(home.join("logs/ossec.log"))
        .unwrap_or_default()
        .lines()
        .map(|l| {
            let l = l.get(20..).unwrap_or(l);
            let l = match (l.find('['), l.find("): ")) {
                (Some(a), Some(b)) if a < b => format!("{}{}", &l[..a], &l[b + 1..]),
                _ => l.to_string(),
            };
            l.split_once(": ").map(|(_, r)| r.to_string()).unwrap_or(l)
        })
        // the old logger's own lines, and the old Windows start-up code's command lines
        .filter(|l| !l.contains("Logging module auto-initialized") && !l.contains("'log_format' without any option") && !l.starts_with("DEBUG: path = '"))
        .collect()
}

fn entry_old(e: &siem_agentlessd::Entry) -> String {
    format!("{} {} {} {} {:?} {:?} {:?} {:?}", e.state, e.frequency, e.port, e.error_flag, e.type_, e.server, e.options, e.command)
}

fn entry_new(e: &provigil_agentlessd::Entry) -> String {
    format!("{} {} {} {} {:?} {:?} {:?} {:?}", e.state, e.frequency, e.port, e.errors, e.kind, e.hosts, e.arguments, e.command)
}

fn level(l: siem_config::LogLevel) -> &'static str {
    match l {
        siem_config::LogLevel::Error => "ERROR",
        siem_config::LogLevel::Warn => "WARNING",
        siem_config::LogLevel::Info => "INFO",
        _ => "DEBUG",
    }
}

/// Files under the diff and entries folders, the numbers in state/diff names masked.
fn files(home: &Path) -> Vec<String> {
    let mut v = Vec::new();
    for d in ["queue/agentless", "queue/diff"] {
        for e in walk(&home.join(d)) {
            let rel = e.strip_prefix(home).unwrap().to_string_lossy().replace('\\', "/");
            let masked: String = rel.split('/').map(|p| if p.starts_with("state.") || p.starts_with("diff.") { p.split('.').next().unwrap().to_string() + ".N" } else { p.to_string() }).collect::<Vec<_>>().join("/");
            v.push(format!("{masked}: {:?}", std::fs::read_to_string(&e).unwrap_or_default()));
        }
    }
    v.sort();
    v
}

fn walk(d: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
        if e.path().is_dir() {
            out.extend(walk(&e.path()));
        } else {
            out.push(e.path());
        }
    }
    out
}

fn sections(conf_body: &str) -> String {
    format!("<ossec_config>\n{conf_body}\n</ossec_config>\n")
}

#[test]
fn old_and_new_agree() {
    let start = std::env::current_dir().unwrap();
    let old_log = Arc::new(siem_log::WLog::new_server("provigil-agentlessd", Path::new("")));
    let _ = old_log.init();
    old_log.now_daemon();
    old_log.now_debug();
    old_log.now_debug();
    siem_agentlessd::set_logger(old_log.clone());

    // ---------------------------------------------------------------- settings
    let s = |t: &str, extra: &str| format!("<agentless>{extra}<type>{t}</type></agentless>");
    let ok = "<frequency>600</frequency><host>root@10.0.0.1</host><state>periodic</state>";
    let cases: Vec<String> = vec![
        sections(&s("ssh_integrity_check_linux", ok)),
        sections(&format!("{}{}", s("ssh_generic_diff", "<frequency>3600</frequency><host>use_sudo admin@h</host><host>use_su r@h2</host><state>periodic_diff</state><arguments>ls  -la /etc</arguments><run_command>x</run_command><port>22</port>"), s(SCRIPT, "<host>a@b</host><state>stay_connected</state>"))),
        sections(&s("nothere", ok)),
        sections(&s("../x", ok)),
        sections(&s("ssh_generic_diff", "<frequency>abc</frequency><host>h</host><state>periodic</state>")),
        sections(&s("ssh_generic_diff", "<frequency>0</frequency><host>h</host><state>periodic</state>")),
        sections(&s("ssh_generic_diff", "<frequency>0</frequency><host>h</host><state>periodic_diff</state>")),
        sections(&s("ssh_generic_diff", "<host>h</host><state>sometimes</state>")),
        sections(&s("ssh_generic_diff", "<host>h</host><state>periodic</state><color>red</color>")),
        sections(&s("ssh_generic_diff", "<state>periodic</state>")),
        sections(&s("ssh_generic_diff", "<host>h</host>")),
        sections("<agentless><host>h</host><state>periodic</state></agentless>"),
        sections("<agentless></agentless>"),
        sections("<global/>"),
        sections("<global><email_notification>no</email_notification></global><syscheck/><rootcheck></rootcheck><database_output><x>1</x></database_output><logging/>"),
        sections("<nonsense>1</nonsense>"),
        sections("<ruleset><list>x</list></ruleset><wodle name=\"x\"/><sca/><cluster><node_name>n</node_name></cluster><wdb><x/></wdb><fluent-forward/><auth/>"),
        format!("<other><nonsense/></other>{}", sections(&s("ssh_integrity_check_linux", ok))),
        format!("{}<ossec_config><bad/></ossec_config>", sections(&s("ssh_integrity_check_linux", ok))),
        sections(&format!("<agentless><var name=\"x\">1</var>{ok}<type>ssh_generic_diff</type></agentless>")),
        sections(&format!("<global><a/></global><var><agentless>{ok}</agentless></var>")),
        "<ossec_config><agentless>".to_string(),
        sections("<agentless><frequency>-5</frequency><host>h</host><state>periodic</state><type>ssh_generic_diff</type></agentless>"),
        sections("<agentless><frequency> 60</frequency><host>h</host><state>periodic</state><type>ssh_generic_diff</type></agentless>"),
    ];
    for (i, conf) in cases.iter().enumerate() {
        let ho = home(conf);
        std::env::set_current_dir(ho.path()).unwrap();
        let mut msgs = Vec::new();
        let old = siem_agentlessd::config::read_agentless_conf(Path::new(""), "etc/ossec.conf", &mut msgs);
        let old = (old.map(|l| l.iter().map(entry_old).collect::<Vec<_>>()), msgs.into_iter().map(|(l, m)| (level(l), m)).collect::<Vec<_>>());
        std::env::set_current_dir(&start).unwrap();
        let hn = home(conf);
        let mut notes = Vec::new();
        let new = provigil_agentlessd::config::read(hn.path(), "etc/ossec.conf", &mut notes);
        let new = (new.map(|l| l.iter().map(entry_new).collect::<Vec<_>>()), notes);
        assert_eq!(old, new, "settings case {i}: {conf}");
    }

    // ---------------------------------------------------------------- requests
    let ho = home(&cases[1]);
    std::env::set_current_dir(ho.path()).unwrap();
    let old_list = siem_agentlessd::config::read_agentless_conf(Path::new(""), "etc/ossec.conf", &mut Vec::new()).unwrap();
    let reqs: [&[u8]; 6] = [b"getconfig agentless", b"getconfig", b"getconfig other", b"other x", b"", b"getconfig agentless\0x"];
    let old_answers: Vec<String> = reqs.iter().map(|r| siem_agentlessd::config::lessdcom_dispatch(&old_list, r)).collect();
    let old_logs = log_lines(ho.path());
    std::env::set_current_dir(&start).unwrap();
    let hn = home(&cases[1]);
    let new_list = provigil_agentlessd::config::read(hn.path(), "etc/ossec.conf", &mut Vec::new()).unwrap();
    let new_log = Log::open(hn.path(), "provigil-agentlessd");
    new_log.set_debug(2);
    let new_answers: Vec<String> = reqs.iter().map(|r| provigil_agentlessd::config::dispatch(&new_list, r, &|t| new_log.debug(t))).collect();
    assert_eq!(old_answers, new_answers);
    assert_eq!(old_logs, log_lines(hn.path()));

    // ---------------------------------------------------------------- runs
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let runs: Vec<(&str, i32, Vec<(&str, i32, bool)>)> = vec![
        // (script output, section state, [(when, exit code, test round)])
        ("INFO: hello\nFWD: integrity one\nLOG: a log line\r\nFWD:\nsomething else\nERROR: boom\nLOG: after error\n", 2, vec![("", 0, false)]),
        ("INFO: checking\n", 2, vec![("", 0, true), ("", 3, true), ("", 0, false)]),
        ("STORE: now\na=1\nb=2\nLOG: inside\n", 6, vec![("first", 0, false), ("same", 0, false)]),
        ("STORE: now\na=1\nb=3\n", 6, vec![("changed", 0, false)]),
        ("STORE: now\nstored but no diff state\n", 2, vec![("", 0, false)]),
        ("", 2, vec![("", 0, false)]),
    ];
    let conf = sections(&s(SCRIPT, "<frequency>60</frequency><host>root@10.0.0.1</host><host>use_sudo admin@h2</host><state>periodic</state><arguments>-x  y</arguments>"));
    let mut traces = Vec::new();
    for side in ["old", "new"] {
        let h = home(&conf);
        let receiver = rt.block_on(provigil_ipc::aio::DatagramReceiver::bind(h.path().join("queue/sockets/queue"))).unwrap();
        let drain = |steps: &mut Vec<String>| {
            while let Ok(Ok(m)) = rt.block_on(async { tokio::time::timeout(Duration::from_millis(300), receiver.recv(70000)).await }) {
                steps.push(format!("event {:?}", String::from_utf8_lossy(&m)));
            }
        };
        let mut steps = Vec::new();
        if side == "old" {
            std::env::set_current_dir(h.path()).unwrap();
            let mut lessd = siem_agentlessd::Lessd { queue: siem_agentlessd::Queue::start(), entries: Vec::new() };
            for (out, state, rounds) in &runs {
                for (_, code, test) in rounds {
                    std::fs::write(h.path().join("lessprobe.out"), out).unwrap();
                    std::fs::write(h.path().join("lessprobe.code"), code.to_string()).unwrap();
                    lessd.entries = vec![siem_agentlessd::Entry { state: *state, frequency: 60, current_state: 0, port: 0, error_flag: 0, type_: SCRIPT.into(), server: vec![" root@10.0.0.1".into(), "oadmin@h2".into()], options: "-x  y".into(), command: None }];
                    let r = lessd.run_periodic_cmd(0, *test);
                    steps.push(format!("result {r} errors {}", lessd.entries[0].error_flag));
                    drain(&mut steps);
                    steps.push(std::fs::read_to_string(h.path().join("lessprobe.args")).unwrap_or_default());
                    let _ = std::fs::remove_file(h.path().join("lessprobe.args"));
                }
            }
            std::env::set_current_dir(&start).unwrap();
        } else {
            let log = Arc::new(Log::open(h.path(), "provigil-agentlessd"));
            log.set_debug(2);
            let queue = provigil_agentlessd::Queue::open(h.path(), rt.handle().clone(), log.clone());
            let mut lessd = provigil_agentlessd::Lessd { home: h.path().to_path_buf(), log, events: queue, entries: Vec::new() };
            for (out, state, rounds) in &runs {
                for (_, code, test) in rounds {
                    std::fs::write(h.path().join("lessprobe.out"), out).unwrap();
                    std::fs::write(h.path().join("lessprobe.code"), code.to_string()).unwrap();
                    lessd.entries = vec![provigil_agentlessd::Entry { state: *state, frequency: 60, last_run: 0, port: 0, errors: 0, kind: SCRIPT.into(), hosts: vec![" root@10.0.0.1".into(), "oadmin@h2".into()], arguments: "-x  y".into(), command: None }];
                    let r = lessd.run_section(0, *test);
                    steps.push(format!("result {r} errors {}", lessd.entries[0].errors));
                    drain(&mut steps);
                    steps.push(std::fs::read_to_string(h.path().join("lessprobe.args")).unwrap_or_default());
                    let _ = std::fs::remove_file(h.path().join("lessprobe.args"));
                }
            }
        }
        steps.extend(files(h.path()));
        // new-only start-up line of the queue connection
        let logs: Vec<String> = log_lines(h.path()).into_iter().filter(|l| !l.starts_with("DEBUG: Connected to 'queue/sockets/queue'")).collect();
        traces.push((steps, logs));
    }
    let (old, new) = (&traces[0], &traces[1]);
    for (what, a, b) in [("step", &old.0, &new.0), ("log line", &old.1, &new.1)] {
        if let Some(i) = (0..a.len().max(b.len())).find(|&i| a.get(i) != b.get(i)) {
            panic!("runs: {what} {i} differs\n old: {:?}\n new: {:?}", a.get(i), b.get(i));
        }
    }
}
