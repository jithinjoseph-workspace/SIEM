//! The daemon's real main loop under more than it can take: messages come far faster than the
//! engine decodes them, into a small queue. They wait before the queue, the queue's usage shows
//! it (what siem-api's backpressure reads) and nothing is dropped.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use siem_analysisd::daemon::{run, Analysis, Logger, StderrLogger};
use siem_analysisd::daemon_config::AnalysisdConfig;
use siem_cjson::Json;
use siem_ipc::local::{DatagramSender, LocalStream, StreamListener};
use siem_ipc::{framing, platform_stream::FROM_API};

const MESSAGES: u64 = 20_000;

fn write(home: &Path, file: &str, text: &str) {
    let p = home.join(file);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn make_home(home: &Path) {
    write(home, "etc/ossec.conf", "<ossec_config><ruleset><decoder_dir>ruleset/decoders</decoder_dir><rule_dir>ruleset/rules</rule_dir></ruleset></ossec_config>");
    let options = concat!(env!("CARGO_MANIFEST_DIR"), "/../../etc/internal_options.conf");
    std::fs::create_dir_all(home.join("etc")).unwrap();
    std::fs::copy(options, home.join("etc/internal_options.conf")).unwrap();
    write(home, "etc/local_internal_options.conf", "analysisd.decode_winevt_queue_size=128\n");
    write(home, "ruleset/decoders/d.xml", "<decoder name=\"d\"><prematch>^never</prematch></decoder>");
    write(home, "ruleset/rules/r.xml", "<group name=\"t,\"><rule id=\"100001\" level=\"0\"><description>t</description></rule></group>");
    for dir in ["logs", "queue/alerts", "queue/fts", "queue/sockets", "var/run", "stats"] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
}

/// provigil-db for the start of the daemon: nothing to tell it.
async fn empty_db(home: &Path) {
    let l = StreamListener::bind(home.join(siem_ipc::wdbc::WDB_LOCAL_SOCK)).await.unwrap();
    tokio::spawn(async move {
        while let Ok(mut s) = l.accept().await {
            tokio::spawn(async move {
                while framing::recv(&mut s, 65536).await.is_ok() {
                    if framing::send(&mut s, b"err").await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

async fn ask(home: &Path, command: &str) -> Option<Json> {
    let mut s = LocalStream::connect(home.join(siem_analysisd::asyscom::ANLSYS_LOCAL_SOCK)).await.ok()?;
    framing::send(&mut s, format!("{{\"command\":\"{command}\"}}").as_bytes()).await.ok()?;
    let r = framing::recv(&mut s, 1 << 20).await.ok()?;
    siem_cjson::parse(&r)?.get("data").cloned()
}

fn number(j: &Json, key: &str) -> f64 {
    match j.get(key) {
        Some(Json::Number { double, .. }) => *double,
        other => panic!("{key}: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_overloaded_engine_drops_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    make_home(&home);
    empty_db(&home).await;
    let cfg = AnalysisdConfig::load(&home, &home.join("etc/ossec.conf"), false).expect("config");
    let log: Arc<dyn Logger> = Arc::new(StderrLogger);
    let analysis = Analysis::new(cfg, &*log, false).expect("ruleset");
    std::thread::spawn(move || run(analysis, log));

    let queue = home.join(siem_ipc::mq::DEFAULTQUEUE);
    let t = Instant::now();
    let sender = loop {
        if let Ok(s) = DatagramSender::connect(&queue).await {
            if ask(&home, "getload").await.is_some() {
                break s;
            }
        }
        assert!(t.elapsed() < Duration::from_secs(30), "the daemon did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let peak = {
        let home = home.clone();
        tokio::spawn(async move {
            let (mut peak, mut read, t) = (0f64, 0.0, Instant::now());
            while read < MESSAGES as f64 || peak == 0.0 {
                let load = ask(&home, "getload").await.expect("the daemon answers while overloaded");
                peak = peak.max(number(&load, "queue_usage"));
                read = number(&load, "received");
                assert!(t.elapsed() < Duration::from_secs(60), "read {read} of {MESSAGES}");
            }
            peak
        })
    };
    // the agent's own format: a local message of agent 000, so no provigil-db lookup
    let event = br#"{"Message":"m","Event":"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='T'/><EventID>1</EventID><Level>4</Level><Channel>Application</Channel><Computer>c</Computer></System><EventData><Data>d</Data></EventData></Event>"}"#;
    for _ in 0..MESSAGES {
        let m = [&[FROM_API][..], b"f:EventChannel:", event].concat();
        sender.send(&m).await.unwrap();
    }
    let peak = peak.await.unwrap();
    assert!(peak > 0.25, "the queue filled up to {peak}, which is what closes ingest");

    // the state file is what `--verify` and the console read
    let state = home.join("var/run/provigil-analysisd.state");
    let t = Instant::now();
    let text = loop {
        let text = std::fs::read_to_string(&state).unwrap_or_default();
        if text.contains(&format!("events_processed='{MESSAGES}'")) {
            break text;
        }
        assert!(t.elapsed() < Duration::from_secs(30), "{text}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(text.contains("events_dropped='0'"), "{text}");
    assert!(text.contains(&format!("events_received='{MESSAGES}'")), "{text}");
}
