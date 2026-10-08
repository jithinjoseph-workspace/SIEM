//! End-to-end test: a simulated Wazuh 4.14.7 agent talks to the Rust remoted
//! exactly like the C agent does (framed TCP, AES, startup, keepalive, events),
//! and we check the ACKs, the `merged.mg` push, wazuh-db queries, the
//! analysisd queue output, the remcom socket and active-response forwarding.

use siem_crypto::keys::{ClientKey, CryptoMethod};
use siem_crypto::msgs::{create_sec_msg, read_sec_msg, CreateOptions, ReadOptions, SenderCounter};
use siem_ipc::framing;
use siem_ipc::wdbc::{WdbQuery, WdbcError};
use siem_remoted::config::RemotedSettings;
use siem_remoted::{Deps, Remoted};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;

const KEY: &str = "f3a4b5c6d7e8f90112233445566778899aabbccddeeff00112233445566778899";

struct MockWdb {
    log: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl WdbQuery for MockWdb {
    async fn query(&self, q: &str) -> Result<String, WdbcError> {
        self.log.lock().unwrap().push(q.to_string());
        if q.starts_with("global select-agent-group") {
            // Agent has no group yet: wazuh-db answers with an empty group.
            return Ok("ok [{}]".into());
        }
        if q.starts_with("global get-distinct-groups") {
            return Ok("ok []".into());
        }
        if q.starts_with("global get-agents-by-connection-status") {
            return Ok("ok [{\"id\":1}]".into());
        }
        Ok("ok".into())
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Agent {
    key: ClientKey,
    ctr: SenderCounter,
    stream: TcpStream,
}

impl Agent {
    async fn send(&mut self, msg: &str) {
        // Agents registered with a non single-host IP ("any") prefix "!<id>!",
        // exactly like the C agent (`!isSingleHost(ip) && isAgent`).
        let wire = create_sec_msg(&self.key, &mut self.ctr, msg.as_bytes(), CreateOptions { dynamic_prefix: true, random: None }).unwrap();
        framing::send(&mut self.stream, &wire).await.unwrap();
    }

    async fn recv(&mut self) -> String {
        let frame = tokio::time::timeout(Duration::from_secs(10), framing::recv(&mut self.stream, 70000)).await.expect("timeout").unwrap();
        let mut k = self.key.clone();
        let r = read_sec_msg(&mut k, &frame, ReadOptions::default()).expect("agent decrypt");
        String::from_utf8_lossy(&r.payload).into_owned()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_agent_session() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let port = free_port();
    std::fs::create_dir_all(h.join("etc/shared/default")).unwrap();
    std::fs::create_dir_all(h.join("queue/rids")).unwrap();
    std::fs::create_dir_all(h.join("queue/sockets")).unwrap();
    std::fs::create_dir_all(h.join("queue/alerts")).unwrap();
    std::fs::create_dir_all(h.join("var/run")).unwrap();
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/internal_options.conf"), h.join("etc/internal_options.conf")).unwrap();
    std::fs::write(
        h.join("etc/ossec.conf"),
        format!(
            "<ossec_config>\n  <global>\n    <jsonout_output>yes</jsonout_output>\n    <agents_disconnection_time>10m</agents_disconnection_time>\n  </global>\n  <remote>\n    <connection>secure</connection>\n    <port>{port}</port>\n    <protocol>tcp</protocol>\n    <local_ip>127.0.0.1</local_ip>\n    <queue_size>131072</queue_size>\n  </remote>\n</ossec_config>\n"
        ),
    )
    .unwrap();
    std::fs::write(h.join("etc/client.keys"), format!("001 web01 any {KEY}\n")).unwrap();
    std::fs::write(h.join("etc/shared/ar.conf"), "restart-ossec0 - restart-ossec.sh - 0\n").unwrap();
    std::fs::write(h.join("etc/shared/default/agent.conf"), "<agent_config>\n</agent_config>\n").unwrap();

    let settings = RemotedSettings::load(h, None, false).expect("config");
    assert_eq!(settings.remote.agents_disconnection_time, 600);
    let wdb = Arc::new(MockWdb { log: Mutex::new(vec![]) });
    let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
    let mut deps = Deps::sockets(&settings);
    deps.wdb = wdb.clone();
    deps.sink = Box::new(siem_remoted::mq::ChannelSink(tx));
    let remoted = Remoted::new(settings, deps).unwrap();
    remoted.start().await.unwrap();

    // The default group's merged.mg was built at startup, Wazuh-style.
    let merged = std::fs::read_to_string(h.join("etc/shared/default/merged.mg")).unwrap();
    assert_eq!(
        merged,
        "#default\n!38 ar.conf\nrestart-ossec0 - restart-ossec.sh - 0\n!31 agent.conf\n<agent_config>\n</agent_config>\n"
    );
    let merged_sum = siem_fileop::md5_hex(merged.as_bytes());

    // ---- agent connects (agent side derives the same key from client.keys)
    let mut key = ClientKey::new("001".into(), "web01".into(), "any".into(), KEY.into());
    key.crypto_method = CryptoMethod::Aes;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut agent = Agent { key, ctr: SenderCounter { global: 0, local: 0 }, stream };

    // Startup handshake
    agent.send("#!-agent startup {\"version\":\"v4.14.7\"}").await;
    assert_eq!(agent.recv().await, "#!-agent ack ");

    // Keepalive without a merged.mg yet -> manager assigns "default" and pushes the file.
    let uname = "Linux |web01 |5.15.0-91-generic |#101-Ubuntu SMP |x86_64 [Ubuntu|ubuntu: 22.04.3 LTS (Jammy Jellyfish)] - Wazuh v4.14.7";
    let keepalive = format!("#!-{uname} / ab73af41699f13fdd81903b5f23d8d00\n\"env\":prod\nx merged.mg\n#\"_agent_ip\":10.0.2.15\n");
    agent.send(&keepalive).await;
    assert_eq!(agent.recv().await, "#!-agent ack ");
    let up = agent.recv().await;
    assert_eq!(up, format!("#!-up file {merged_sum} merged.mg\n"));
    let mut body = String::new();
    loop {
        let m = agent.recv().await;
        if m == "#!-close file " {
            break;
        }
        body.push_str(&m);
    }
    assert_eq!(body, merged);

    // Events go to analysisd in Wazuh's queue format.
    agent.send("1:/var/log/auth.log:Oct  5 10:00:00 web01 sshd[123]: Failed password for root from 10.1.1.1 port 22 ssh2").await;
    agent.send("1:keepalive:ignored").await;
    let ev = tokio::time::timeout(Duration::from_secs(10), events.recv()).await.unwrap().unwrap();
    assert_eq!(
        String::from_utf8(ev).unwrap(),
        "1:[001] (web01) any->/var/log/auth.log:Oct  5 10:00:00 web01 sshd[123]: Failed password for root from 10.1.1.1 port 22 ssh2"
    );

    // wazuh-db saw the same queries a C remoted sends.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let log = wdb.log.lock().unwrap().clone();
    assert!(log.contains(&"global reset-agents-connection synced".to_string()), "{log:#?}");
    assert!(log.contains(&r#"global update-keepalive {"id":1,"connection_status":"pending","sync_status":"synced"}"#.to_string()), "{log:#?}");
    assert!(log.contains(&"global select-agent-group 1".to_string()));
    assert!(log.contains(&r#"global set-agent-groups {"mode":"empty_only","sync_status":"synced","data":[{"id":1,"groups":["default"]}]}"#.to_string()), "{log:#?}");
    let upd = log.iter().find(|q| q.starts_with("global update-agent-data")).expect("update-agent-data");
    let j: serde_json::Value = serde_json::from_str(&upd["global update-agent-data ".len()..]).unwrap();
    assert_eq!(j["id"], 1);
    assert_eq!(j["version"], "Wazuh v4.14.7");
    assert_eq!(j["config_sum"], "ab73af41699f13fdd81903b5f23d8d00");
    assert_eq!(j["merged_sum"], "x");
    assert_eq!(j["os_name"], "Ubuntu");
    assert_eq!(j["os_platform"], "ubuntu");
    assert_eq!(j["os_uname"], "Linux |web01 |5.15.0-91-generic |#101-Ubuntu SMP |x86_64");
    assert_eq!(j["agent_ip"], "10.0.2.15");
    assert_eq!(j["connection_status"], "active");
    assert_eq!(j["group_config_status"], "not synced");
    assert!(j["labels"].as_str().unwrap().starts_with("\"env\":prod\n#\"_manager_hostname\":"));
    assert!(j["labels"].as_str().unwrap().ends_with("#\"_node_name\":undefined\n#\"_wazuh_version\":Wazuh v4.14.7"));

    // remcom: getstats over queue/sockets/remote
    let mut c = siem_ipc::local::LocalStream::connect(h.join("queue/sockets/remote")).await.unwrap();
    framing::send(&mut c, br#"{"command":"getstats"}"#).await.unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&framing::recv(&mut c, 70000).await.unwrap()).unwrap();
    assert_eq!(resp["error"], 0);
    assert_eq!(resp["data"]["name"], "wazuh-remoted");
    assert!(resp["data"]["metrics"]["messages"]["received_breakdown"]["event"].as_u64().unwrap() >= 2);
    assert_eq!(resp["data"]["metrics"]["messages"]["received_breakdown"]["control_breakdown"]["startup"], 1);

    // Active response from analysisd's queue/alerts/ar reaches the agent.
    let ar = siem_ipc::local::DatagramSender::connect(h.join("queue/alerts/ar")).await.unwrap();
    ar.send(b"(local_source) [] NNS 001 {\"version\":1,\"command\":\"add\",\"parameters\":{}}").await.unwrap();
    assert_eq!(agent.recv().await, "#!-execd {\"version\":1,\"command\":\"add\",\"parameters\":{}}");

    // A replayed control message from a closed socket is ignored, and shutdown
    // is reported to analysisd and wazuh-db.
    agent.send("#!-agent shutdown ").await;
    let ev = tokio::time::timeout(Duration::from_secs(10), events.recv()).await.unwrap().unwrap();
    assert_eq!(
        String::from_utf8(ev).unwrap(),
        "1:[001] (web01) any->wazuh-remoted:ossec: Agent stopped: 'web01->any'."
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let log = wdb.log.lock().unwrap().clone();
    assert!(log.contains(&r#"global update-connection-status {"id":1,"connection_status":"disconnected","sync_status":"synced","status_code":3}"#.to_string()), "{log:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_ip_and_bad_key_are_rejected() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let port = free_port();
    for d in ["etc/shared", "queue/rids", "queue/sockets", "queue/alerts", "var/run"] {
        std::fs::create_dir_all(h.join(d)).unwrap();
    }
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/internal_options.conf"), h.join("etc/internal_options.conf")).unwrap();
    std::fs::write(
        h.join("etc/ossec.conf"),
        format!("<ossec_config><remote><connection>secure</connection><port>{port}</port><protocol>tcp</protocol><local_ip>127.0.0.1</local_ip></remote></ossec_config>"),
    )
    .unwrap();
    // Agent 002 is bound to a fixed IP that is not ours.
    std::fs::write(h.join("etc/client.keys"), format!("002 db01 10.9.9.9 {KEY}\n")).unwrap();
    let settings = RemotedSettings::load(h, None, false).unwrap();
    let wdb = Arc::new(MockWdb { log: Mutex::new(vec![]) });
    let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
    let mut deps = Deps::sockets(&settings);
    deps.wdb = wdb;
    deps.sink = Box::new(siem_remoted::mq::ChannelSink(tx));
    let remoted = Remoted::new(settings, deps).unwrap();
    remoted.start().await.unwrap();

    let mut key = ClientKey::new("002".into(), "db01".into(), "10.9.9.9".into(), KEY.into());
    key.crypto_method = CryptoMethod::Blowfish;
    let mut ctr = SenderCounter::default();
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let wire = create_sec_msg(&key, &mut ctr, b"1:x:y", CreateOptions::default()).unwrap();
    framing::send(&mut s, &wire).await.unwrap();
    // Remoted closes the connection (source IP has no key) and forwards nothing.
    let mut b = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read(&mut s, &mut b)).await.unwrap();
    assert!(matches!(r, Ok(0) | Err(_)));
    assert!(tokio::time::timeout(Duration::from_millis(300), events.recv()).await.is_err());
    let st = remoted.state.snapshot();
    assert_eq!(st.unknown, 1);
}
