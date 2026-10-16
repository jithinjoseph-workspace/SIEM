//! Simulated Windows agents for load tests: each one connects to remoted (TCP),
//! sends the startup handshake, a keepalive every 10 s and Windows events at a
//! fixed rate, encrypted exactly like the agent (siem-crypto CreateSecMSG).
//!
//! loadgen <keys file> <manager host:port> <agents> <eps per agent> <ramp s> <duration s> <merged.mg path>
//! keys file: client.keys lines (`id name ip key`) from the enrollment script.

use siem_crypto::keys::{ClientKey, CryptoMethod};
use siem_crypto::msgs::{create_sec_msg, CreateOptions, SenderCounter};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

static CONNECTED: AtomicU64 = AtomicU64::new(0);
static CONNECT_FAIL: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static EVENTS: AtomicU64 = AtomicU64::new(0);
static KEEPALIVES: AtomicU64 = AtomicU64::new(0);
static BYTES_OUT: AtomicU64 = AtomicU64::new(0);
static BYTES_IN: AtomicU64 = AtomicU64::new(0);
static SLOW_WRITES: AtomicU64 = AtomicU64::new(0);

const UNAME: &str = "Microsoft Windows 11 Pro [Ver: 10.0.22631] - Wazuh v4.14.7";

/// An Application event as the agent's eventchannel reader sends it ({"Message","Event": XML});
/// `error` ones (Level 2) raise rule 60602 (level 9).
fn event(name: &str, n: u64, error: bool) -> String {
    let (id, level, msg) = if error { ("1000", "2", "Faulting application name: loadtest.exe") } else { ("1001", "4", "Load test informational event") };
    format!(
        "f:EventChannel:{{\"Message\":\"{msg} #{n}\",\"Event\":\"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='LoadTest'/><EventID Qualifiers='0'>{id}</EventID><Version>0</Version><Level>{level}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-10-16T00:00:00.0000000Z'/><EventRecordID>{n}</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='0'/><Channel>Application</Channel><Computer>{name}</Computer><Security/></System><EventData><Data>{msg} #{n}</Data></EventData></Event>\"}}"
    )
}

struct Agent {
    key: ClientKey,
    counter: SenderCounter,
}

impl Agent {
    fn frame(&mut self, msg: &str) -> Vec<u8> {
        let enc = create_sec_msg(&self.key, &mut self.counter, msg.as_bytes(), CreateOptions { dynamic_prefix: true, random: None }).expect("encrypt");
        let mut out = (enc.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&enc);
        out
    }
}

async fn run_agent(mut a: Agent, addr: String, eps: f64, start_delay: Duration, end: Instant, merged: String, ip: String) {
    tokio::time::sleep(start_delay).await;
    let s = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(_) => {
            CONNECT_FAIL.fetch_add(1, Relaxed);
            return;
        }
    };
    let _ = s.set_nodelay(true);
    let (mut rd, mut wr) = s.into_split();
    CONNECTED.fetch_add(1, Relaxed);
    // the manager's acks and shared files are read and discarded
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok(n) = rd.read(&mut buf).await {
            if n == 0 {
                break;
            }
            BYTES_IN.fetch_add(n as u64, Relaxed);
        }
    });
    let name = a.key.name.clone();
    let send = |a: &mut Agent, msg: &str| a.frame(msg);
    let first = send(&mut a, "#!-agent startup {\"version\":\"v4.14.7\"}");
    let keepalive = format!("#!-{UNAME} / ab3e9c1b8b2b1b5e0d7c4f1e2a3b4c5d\n{merged}#\"_agent_ip\":{ip}\n");
    let mut ok = wr.write_all(&first).await.is_ok();
    let period = Duration::from_secs_f64(1.0 / eps.max(0.001));
    let mut ev_tick = tokio::time::interval_at(tokio::time::Instant::now() + period.mul_f64(rand::random::<f64>()), period);
    ev_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ka_tick = tokio::time::interval(Duration::from_secs(10));
    let mut n = 0u64;
    while ok && Instant::now() < end {
        let msg = tokio::select! {
            _ = ka_tick.tick() => { KEEPALIVES.fetch_add(1, Relaxed); keepalive.clone() }
            _ = ev_tick.tick() => { n += 1; EVENTS.fetch_add(1, Relaxed); event(&name, n, n % 20 == 0) }
        };
        let buf = send(&mut a, &msg);
        let t = Instant::now();
        ok = wr.write_all(&buf).await.is_ok();
        if t.elapsed() > Duration::from_millis(500) {
            SLOW_WRITES.fetch_add(1, Relaxed);
        }
        BYTES_OUT.fetch_add(buf.len() as u64, Relaxed);
    }
    if !ok {
        DROPPED.fetch_add(1, Relaxed);
    }
    CONNECTED.fetch_sub(1, Relaxed);
    reader.abort();
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 8 {
        eprintln!("loadgen <keys file> <host:port> <agents> <eps per agent> <ramp s> <duration s> <merged.mg path>");
        std::process::exit(2);
    }
    let keys = std::fs::read_to_string(&a[1]).expect("keys file");
    let addr = a[2].clone();
    let n: usize = a[3].parse().unwrap();
    let eps: f64 = a[4].parse().unwrap();
    let ramp: f64 = a[5].parse().unwrap();
    let dur: u64 = a[6].parse().unwrap();
    // the agent reports the merged.mg it has; the right hash stops remoted from resending it
    let mg = std::fs::read(&a[7]).expect("merged.mg");
    let merged = format!("{} merged.mg\n", hex::encode(<md5::Md5 as md5::Digest>::digest(&mg)));
    let end = Instant::now() + Duration::from_secs(dur);
    let mut started = 0usize;
    for (i, line) in keys.lines().filter(|l| !l.trim().is_empty()).take(n).enumerate() {
        let p: Vec<&str> = line.split_whitespace().collect();
        let mut key = ClientKey::new(p[0].into(), p[1].into(), p[2].into(), p[3].into());
        key.crypto_method = CryptoMethod::Aes;
        let ip = format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255);
        let delay = Duration::from_secs_f64(ramp * i as f64 / n.max(1) as f64);
        tokio::spawn(run_agent(Agent { key, counter: SenderCounter { global: 1, local: 0 } }, addr.clone(), eps, delay, end, merged.clone(), ip));
        started += 1;
    }
    println!("t_s,agents_started,connected,connect_fail,dropped,events,eps,keepalives,slow_writes,mb_out,kb_in");
    let t0 = Instant::now();
    let mut last = 0u64;
    while Instant::now() < end + Duration::from_secs(2) {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let ev = EVENTS.load(Relaxed);
        println!(
            "{},{},{},{},{},{},{:.0},{},{},{:.1},{}",
            t0.elapsed().as_secs(),
            started,
            CONNECTED.load(Relaxed),
            CONNECT_FAIL.load(Relaxed),
            DROPPED.load(Relaxed),
            ev,
            (ev - last) as f64 / 10.0,
            KEEPALIVES.load(Relaxed),
            SLOW_WRITES.load(Relaxed),
            BYTES_OUT.load(Relaxed) as f64 / 1e6,
            BYTES_IN.load(Relaxed) / 1000
        );
        last = ev;
    }
}
