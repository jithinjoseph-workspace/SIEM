//! The local server end to end: port file, framing, newline answers, answers in pieces,
//! JSON commands and refused oversize messages.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use provigil_agentdb::server::{self, Peers};
use provigil_agentdb::{Engine, Env, Settings};

struct TestEnv(Arc<Peers>);
impl Env for TestEnv {
    fn log(&self, _: &str, _: &[u8]) {}
    fn time(&self) -> i64 {
        1_800_000_000
    }
    fn router_send(&self, _: i32, _: &[u8]) {}
    fn send_peer(&self, peer: i32, msg: &[u8]) -> i32 {
        self.0.send(peer, msg)
    }
    fn is_single_node(&self) -> (i32, i32) {
        (1, 0)
    }
}

fn send(s: &mut TcpStream, msg: &[u8]) {
    let mut f = (msg.len() as u32).to_le_bytes().to_vec();
    f.extend_from_slice(msg);
    s.write_all(&f).unwrap();
}

fn recv(s: &mut TcpStream) -> Option<String> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).ok()?;
    let mut b = vec![0u8; u32::from_le_bytes(h) as usize];
    s.read_exact(&mut b).ok()?;
    Some(String::from_utf8_lossy(&b).into_owned())
}

#[test]
fn serves_over_the_port_file() {
    let home = tempfile::tempdir().unwrap();
    for d in ["queue/db", "queue/tasks", "backup/db"] {
        std::fs::create_dir_all(home.path().join(d)).unwrap();
    }
    let peers = Arc::new(Peers::default());
    let engine = Arc::new(Engine::new(home.path(), Settings::default(), Arc::new(TestEnv(peers.clone()))));
    let running = Arc::new(AtomicBool::new(true));
    let listener = server::bind(home.path()).unwrap();
    {
        let (e, p, h, r) = (engine.clone(), peers.clone(), home.path().to_path_buf(), running.clone());
        std::thread::spawn(move || server::serve(e, p, listener, h, r));
    }
    let port: u16 = std::fs::read_to_string(home.path().join("queue/db/wdb.port")).unwrap().trim().parse().unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();

    send(&mut s, br#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#);
    assert_eq!(recv(&mut s).unwrap(), "ok");
    send(&mut s, b"global sql SELECT name FROM agent WHERE id = 1\n");
    assert_eq!(recv(&mut s).unwrap(), "ok [{\"name\":\"pc1\"}]\n");
    send(&mut s, b"nonsense");
    assert!(recv(&mut s).unwrap().starts_with("err Invalid DB query syntax"));

    // a list answered in pieces: "due" parts then "ok"
    for id in 2..=60 {
        send(&mut s, format!(r#"global insert-agent {{"id":{id},"name":"pc-with-a-longer-name-{id:04}","date_add":1}}"#).as_bytes());
        assert_eq!(recv(&mut s).unwrap(), "ok");
    }
    send(&mut s, b"agent 1 sql SELECT 1 AS n");
    assert_eq!(recv(&mut s).unwrap(), "ok [{\"n\":1}]");
    for n in ["a", "b"] {
        send(&mut s, format!(r#"agent 1 dbsync packages INSERTED {{"name":"{n}","version":"1","architecture":"x","format":"deb","location":"","checksum":"c{n}"}}"#).as_bytes());
        assert_eq!(recv(&mut s).unwrap(), "ok ");
    }
    send(&mut s, b"agent 1 sql UPDATE sync_info SET last_attempt = 1, last_completion = 2 WHERE component = 'syscollector-packages'");
    assert_eq!(recv(&mut s).unwrap(), "ok []");
    send(&mut s, b"agent 1 package get");
    let parts: Vec<String> = (0..3).map(|_| recv(&mut s).unwrap()).collect();
    assert!(parts[0].starts_with("due {") && parts[0].contains("\"name\":\"a\""), "{parts:?}");
    assert!(parts[1].starts_with("due {") && parts[1].contains("\"name\":\"b\""), "{parts:?}");
    assert_eq!(parts[2], r#"ok {"status":"SUCCESS"}"#);

    send(&mut s, br#"{"command":"getstats"}"#);
    let stats = recv(&mut s).unwrap();
    assert!(stats.starts_with(r#"{"error":0,"message":"ok","data":{"uptime":1800000000"#), "{stats}");
    assert!(stats.contains(r#""global_breakdown":{"insert-agent":60"#), "{stats}");
    send(&mut s, br#"{"command":"getconfig","parameters":{"section":"wdb"}}"#);
    assert!(recv(&mut s).unwrap().contains(r#""backup":[{"database":"global","enabled":true,"interval":86400,"max_files":3}]"#));
    send(&mut s, br#"{"command":"nope"}"#);
    assert_eq!(recv(&mut s).unwrap(), r#"{"error":3,"message":"Unrecognized command","data":{}}"#);

    // too big: the server drops the client
    s.write_all(&(70_000u32).to_le_bytes()).unwrap();
    assert!(recv(&mut s).is_none());
    running.store(false, std::sync::atomic::Ordering::SeqCst);
}
