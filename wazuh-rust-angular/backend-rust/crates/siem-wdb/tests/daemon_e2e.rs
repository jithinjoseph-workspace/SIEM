//! End to end test of the wazuh-db daemon runtime (Linux): the dealer and
//! worker threads on queue/db/wdb with the OS_SendSecureTCP framing, the
//! router (broker, remote provider, remote subscriber) carrying the
//! deleteAgent event, and the HTTP API on queue/sockets/wdb-http.sock.
//! (main()'s privilege separation needs root and is not exercised.)

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use siem_log::WLog;
use siem_wdb::wdb::daemon::*;
use siem_wdb::wdb::*;

fn query(s: &mut UnixStream, q: &[u8]) -> Vec<u8> {
    let mut m = (q.len() as u32).to_le_bytes().to_vec();
    m.extend_from_slice(q);
    s.write_all(&m).unwrap();
    let mut h = [0u8; 4];
    s.read_exact(&mut h).unwrap();
    let mut b = vec![0u8; u32::from_le_bytes(h) as usize];
    s.read_exact(&mut b).unwrap();
    b
}

#[test]
fn daemon_end_to_end() {
    let home: PathBuf = std::env::temp_dir().join(format!("siem_wdb_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    for d in ["queue/db", "queue/tasks", "queue/sockets", "queue/router", "backup/db", "logs", "etc"] {
        std::fs::create_dir_all(home.join(d)).unwrap();
    }
    // the logger reads it (and exits without it, like w_logging_init)
    std::fs::write(home.join("etc/ossec.conf"), "<ossec_config>\n  <logging><log_format>plain</log_format></logging>\n</ossec_config>\n").unwrap();
    std::env::set_current_dir(&home).unwrap();
    let base = PathBuf::new();
    let wlog = Arc::new(WLog::new("wazuh-db", &base));

    // the broker (wazuh-modulesd's side) and a remote subscriber
    router_initialize(wlog.clone());
    assert_eq!(siem_router::router_start(), 0);
    let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    let sub = siem_router::RouterSubscriber::new("wdb-agent-events", "e2e", false);
    sub.subscribe(Arc::new(move |d: &[u8]| g.lock().push(d.to_vec())), Arc::new(|| {})).unwrap();

    // the daemon
    let router: Arc<dyn RouterSink> = Arc::new(WazuhRouter::default());
    let env = Arc::new(DaemonEnv { log: wlog.clone(), router: router.clone(), ossecconf: PathBuf::from("etc/ossec.conf") });
    let mut d = Wdbd::new(WdbConfig::default(), base.clone(), env);
    d.router_agent = router.create(WDB_AGENT_EVENTS_TOPIC);
    d.router_inventory = router.create(WDB_INVENTORY_EVENTS_TOPIC);
    d.create_profile();
    let d = Arc::new(d);
    let notify = Arc::new(Notify::init().unwrap());
    let dealer = {
        let (d, n) = (d.clone(), notify.clone());
        std::thread::spawn(move || run_dealer(d, n))
    };
    let q = Arc::new(Mutex::new(()));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let (d, n, q) = (d.clone(), notify.clone(), q.clone());
            std::thread::spawn(move || run_worker(d, n, q))
        })
        .collect();
    let api = siem_wdb::wdb::http::start_api(d.clone(), wlog.clone() as Arc<dyn siem_wdb::wdb::http::ApiLog>).unwrap();

    // a client of queue/db/wdb
    let mut s = None;
    for _ in 0..100 {
        if let Ok(c) = UnixStream::connect(WDB_LOCAL_SOCK) {
            s = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut s = s.expect("connect to queue/db/wdb");
    assert_eq!(query(&mut s, b"global insert-agent {\"id\":1,\"name\":\"a1\",\"ip\":\"1.1.1.1\",\"date_add\":1}"), b"ok");
    assert_eq!(query(&mut s, b"global insert-agent {\"id\":2,\"name\":\"a2\",\"date_add\":1}\n"), b"ok\n");
    let r = query(&mut s, b"global sql SELECT id, name FROM agent ORDER BY id");
    assert_eq!(r, br#"ok [{"id":0,"name":"localhost"},{"id":1,"name":"a1"},{"id":2,"name":"a2"}]"#.to_vec());
    let r = query(&mut s, b"{\"command\":\"getconfig\",\"parameters\":{\"section\":\"internal\"}}");
    assert!(r.starts_with(b"{\"error\":0,\"message\":\"ok\",\"data\":{"), "{}", String::from_utf8_lossy(&r));

    // the HTTP API
    let mut h = UnixStream::connect("queue/sockets/wdb-http.sock").unwrap();
    h.write_all(b"GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    h.read_to_end(&mut resp).unwrap();
    assert!(resp.ends_with(b"\r\n\r\n[1,2]"), "{}", String::from_utf8_lossy(&resp));

    // delete-agent publishes on wdb-agent-events (once the provider is connected)
    let mut delivered = false;
    for _ in 0..50 {
        let r = query(&mut s, b"global delete-agent 2");
        assert!(r == b"ok" || r.starts_with(b"err"), "{}", String::from_utf8_lossy(&r));
        std::thread::sleep(Duration::from_millis(100));
        if got.lock().iter().any(|m| m == br#"{"agent_info":{"agent_id":"002"},"action":"deleteAgent"}"#) {
            delivered = true;
            break;
        }
        // reinsert to delete again
        query(&mut s, b"global insert-agent {\"id\":2,\"name\":\"a2\",\"date_add\":1}");
    }
    assert!(delivered, "router messages: {:?}", got.lock().iter().map(|m| String::from_utf8_lossy(m).into_owned()).collect::<Vec<_>>());

    // shutdown
    RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(s);
    let _ = dealer.join();
    for w in workers {
        let _ = w.join();
    }
    api.stop();
    d.close_all();
    drop(sub);
    std::env::set_current_dir(std::env::temp_dir()).unwrap();
    let _ = std::fs::remove_dir_all(&home);
}
