//! Throughput of the analysis thread (spec: scaling, step 1): the real service and the shipped
//! ruleset, fed realistic Windows events from many agents, timed per stage. Read-only on the
//! manager home (no start: no sockets, no output files); its log goes to a temporary folder.
//!
//!   cargo test --release -p provigil-analysisd --test bench_throughput -- --ignored --nocapture

use std::path::{Path, PathBuf};

use provigil_analysisd::config::Config;
use provigil_analysisd::daemon::{Service, ServiceLog};
use provigil_analysisd::event::Label;
use provigil_analysisd::host::Host;
use provigil_analysisd::responses::{AgentVersion, ResponseSink};

struct Bench;

impl ResponseSink for Bench {
    fn agent_version(&mut self, _: i32) -> AgentVersion {
        AgentVersion::NoVersion
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        None
    }
    fn node_name(&mut self) -> String {
        "undefined".into()
    }
    fn send_exec(&mut self, _: &[u8]) {}
    fn send_ar(&mut self, _: &[u8]) {}
}

impl Host for Bench {
    fn labels(&mut self, _: &[u8]) -> Vec<Label> {
        Vec::new()
    }
    fn log(&self, _: &str, _: &[u8]) {}
    fn responses(&mut self) -> &mut dyn ResponseSink {
        self
    }
    fn agents_of_node(&mut self, _: i32, _: i32) -> Option<Vec<i32>> {
        None
    }
}

fn manager() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager")
}

/// A JSON string (quotes and backslashes escaped; the events here have no control characters)
fn js(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// One Windows event as the gateway hands it to the engine.
fn message(agent: u32, kind: u32, seq: u64) -> Vec<u8> {
    let pc = format!("pc-{agent:05}");
    let sys = |provider: &str, guid: &str, id: u32, channel: &str| {
        format!("<System><Provider Name='{provider}' Guid='{{{guid}}}'/><EventID>{id}</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-11-25T10:00:00.000000Z'/><EventRecordID>{seq}</EventRecordID><Correlation/><Execution ProcessID='640' ThreadID='4000'/><Channel>{channel}</Channel><Computer>{pc}</Computer><Security/></System>")
    };
    let (msg, xml) = match kind {
        // an application crash
        0 => (format!("Faulting application name: app{seq}.exe, version: 10.0.22621.1"), format!("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>{}<EventData><Data Name='AppName'>app{seq}.exe</Data><Data Name='AppVersion'>10.0.22621.1</Data></EventData></Event>", sys("Application Error", "a0e9b465-b939-57d7-b27d-95d8e925ff57", 1000, "Application"))),
        // a failed logon
        1 => ("An account failed to log on.".into(), format!("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>{}<EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>user{}</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>10.1.{}.{}</Data><Data Name='IpPort'>51515</Data></EventData></Event>", sys("Microsoft-Windows-Security-Auditing", "54849625-5478-4994-a5ba-3e3b0328c30d", 4625, "Security"), seq % 50, agent % 250, seq % 250)),
        // a logon
        2 => ("An account was successfully logged on.".into(), format!("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>{}<EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='TargetUserName'>user{}</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='LogonType'>2</Data><Data Name='LogonProcessName'>User32</Data><Data Name='IpAddress'>127.0.0.1</Data></EventData></Event>", sys("Microsoft-Windows-Security-Auditing", "54849625-5478-4994-a5ba-3e3b0328c30d", 4624, "Security"), seq % 50)),
        // a process start (Sysmon)
        _ => ("Process Create".into(), format!("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>{}<EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-11-25 10:00:00.000</Data><Data Name='ProcessGuid'>{{0000-{seq}}}</Data><Data Name='ProcessId'>{}</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='CommandLine'>cmd.exe /c whoami /all {seq}</Data><Data Name='CurrentDirectory'>C:\\Users\\user\\</Data><Data Name='User'>CORP\\user</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>SHA256=0123456789ABCDEF</Data><Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data><Data Name='ParentCommandLine'>C:\\Windows\\Explorer.EXE</Data></EventData></Event>", sys("Microsoft-Windows-Sysmon", "5770385f-c22a-43e0-bf4c-06f5698ffbd9", 1, "Microsoft-Windows-Sysmon/Operational"), 4000 + seq % 1000)),
    };
    let payload = format!("{{\"Message\":{},\"Event\":{}}}", js(&msg), js(&xml));
    format!("f:[{:03}] ({pc}) any->EventChannel:{payload}", agent % 1000).into_bytes()
}

#[test]
#[ignore]
fn analysis_thread_throughput() {
    std::env::set_var("PROVIGIL_ANALYSISD_PROFILE", "1");
    let home = manager();
    let logs = tempfile::tempdir().unwrap();
    let log = ServiceLog::new(provigil_daemon::Log::open(logs.path(), "provigil-analysisd"), false);
    let cfg = Config::load(&home, &home.join("etc/ossec.conf"), true).expect("manager settings");
    let mut service = Service::new(cfg, &log, true).expect("ruleset");
    let mut host = Bench;
    service.load_mitre(&mut host);
    service.init_decoders(&mut host);
    const AGENTS: u32 = 500;
    const N: u64 = 40_000;
    for kind in 0..4 {
        let t = std::time::Instant::now();
        for seq in 0..N / 4 {
            service.receive(&mut host, &message((seq as u32) % AGENTS + 1, kind, seq));
            service.pump(&mut host);
        }
        let secs = t.elapsed().as_secs_f64();
        let name = ["application error (1000)", "failed logon (4625)", "logon (4624)", "Sysmon process start (1)"][kind as usize];
        println!("{name:28} {:>7.0} events/s   {}", (N / 4) as f64 / secs, service.profile_now().unwrap_or_default());
    }
    let t = std::time::Instant::now();
    for seq in 0..N {
        service.receive(&mut host, &message((seq as u32) % AGENTS + 1, (seq % 4) as u32, seq));
        service.pump(&mut host);
    }
    println!("{:28} {:>7.0} events/s   {}", "mixed (all four)", N as f64 / t.elapsed().as_secs_f64(), service.profile_now().unwrap_or_default());
}

/// The same mixed events through 0 (one thread, as before), 1, 2, 4, 6 and 12 analysis workers,
/// streamed to a spool of the benchmark's own (a receiver that reads and drops): the time until
/// every event went through the rules and its archive line was streamed.
#[test]
#[ignore]
fn analysis_workers_scaling() {
    use provigil_ipc::platform_stream::Stream;
    let home = manager();
    let sink = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = sink.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for c in sink.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let _ = std::io::copy(&mut c, &mut std::io::sink());
            });
        }
    });
    const N: u64 = 40_000;
    let msgs: Vec<Vec<u8>> = (0..N).map(|seq| message((seq as u32) % 500 + 1, (seq % 4) as u32, seq)).collect();
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!("{cores} CPU cores; automatic: {} worker(s)", provigil_analysisd::analysis::auto(cores));
    let mut single = 0.0;
    for workers in [0usize, 1, 2, 3, 4, 5, 6, 8, 12] {
        let logs = tempfile::tempdir().unwrap();
        let spool = tempfile::tempdir().unwrap();
        let log = std::sync::Arc::new(ServiceLog::new(provigil_daemon::Log::open(logs.path(), "provigil-analysisd"), false));
        let cfg = Config::load(&home, &home.join("etc/ossec.conf"), true).expect("manager settings");
        let mut service = Service::new(cfg, &log, true).expect("ruleset");
        let mut host = Bench;
        service.load_mitre(&mut host);
        service.init_decoders(&mut host);
        service.stream_to(Stream::start(addr.clone(), "bench".into(), spool.path(), 8 << 30).expect("a stream"));
        if workers > 0 {
            service.start_analysis(workers, log.clone());
        }
        let t = std::time::Instant::now();
        for m in &msgs {
            service.receive(&mut host, m);
            while service.input_full() {
                service.pump_some(&mut host, 256);
            }
            service.pump_some(&mut host, 256);
        }
        while service.pending() {
            service.pump_some(&mut host, 256);
        }
        service.finish_decoding(&mut host);
        if workers > 0 {
            let mut last = (0, std::time::Instant::now());
            while service.archived() < N && last.1.elapsed() < std::time::Duration::from_secs(2) {
                let a = service.archived();
                if a != last.0 {
                    last = (a, std::time::Instant::now());
                }
                std::thread::yield_now();
            }
        }
        let rate = N as f64 / t.elapsed().as_secs_f64();
        if workers == 0 {
            single = rate;
        }
        println!(
            "{:>2} worker(s): {:>7.0} events/s ({:.1}x){}",
            workers,
            rate,
            rate / single,
            if workers > 0 { format!(", {} archive lines streamed by the workers", service.archived()) } else { " (one thread, as before)".into() }
        );
    }
}

/// The same messages with and without analysis workers fire the same rules the same number of
/// times (rule matching is one ordered stage either way).
#[test]
fn workers_fire_the_same_rules() {
    let home = manager();
    if !home.join("etc/ossec.conf").is_file() {
        return;
    }
    let msgs: Vec<Vec<u8>> = (0..8_000u64).map(|seq| message((seq as u32) % 200 + 1, (seq % 4) as u32, seq)).collect();
    let fired = |workers: usize| {
        let logs = tempfile::tempdir().unwrap();
        let log = std::sync::Arc::new(ServiceLog::new(provigil_daemon::Log::open(logs.path(), "provigil-analysisd"), false));
        let cfg = Config::load(&home, &home.join("etc/ossec.conf"), true).expect("manager settings");
        let mut service = Service::new(cfg, &log, true).expect("ruleset");
        let mut host = Bench;
        service.init_decoders(&mut host);
        if workers > 0 {
            service.start_analysis(workers, log.clone());
        }
        for m in &msgs {
            service.receive(&mut host, m);
            while service.input_full() {
                service.pump_some(&mut host, 256);
            }
            service.pump_some(&mut host, 256);
        }
        while service.pending() {
            service.pump_some(&mut host, 256);
        }
        service.finish_decoding(&mut host);
        let mut stats = service.engine.rule_stats(0);
        stats.sort();
        stats
    };
    let single = fired(0);
    assert!(!single.is_empty(), "the events fire rules");
    for w in [1, 3, 4] {
        assert_eq!(fired(w), single, "{w} worker(s): the same rules fired the same number of times");
    }
}
