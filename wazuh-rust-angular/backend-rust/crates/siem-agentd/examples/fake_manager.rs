//! A minimal stand-in for wazuh-remoted, used to compare the C and Rust
//! `wazuh-agentd` (TCP only).
//!
//! It decrypts every message an agent sends and logs it, acknowledges the
//! startup and keep-alive control messages, and plays a script of
//! manager-to-agent messages.
//!
//! ```text
//! fake_manager <port> <client.keys> <out.log> [script]
//! ```
//!
//! Script lines (seconds are counted from the first ACK):
//! `<secs> send <payload with \n escapes>`, `<secs> file <name> <local path>`,
//! `<secs> close` (drop the connection), `<secs> exit`.

#[cfg(not(unix))]
fn main() {}

#[cfg(unix)]
fn main() {
    imp::main();
}

#[cfg(unix)]
mod imp {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use siem_crypto::keys::ClientKey;
    use siem_crypto::msgs::{create_sec_msg, read_sec_msg, CreateOptions, ReadOptions, SenderCounter};

    struct Shared {
        out: std::fs::File,
        start: Instant,
        first_ack: Option<Instant>,
        conn: Option<TcpStream>,
        key: ClientKey,
        counter: SenderCounter,
    }

    fn escape(b: &[u8]) -> String {
        let mut s = String::new();
        for &c in b {
            match c {
                b'\n' => s.push_str("\\n"),
                b'\\' => s.push_str("\\\\"),
                0x20..=0x7e => s.push(c as char),
                _ => s.push_str(&format!("\\x{c:02x}")),
            }
        }
        s
    }

    fn log(sh: &mut Shared, what: &str) {
        let t = sh.start.elapsed().as_secs_f64();
        let _ = writeln!(sh.out, "{t:9.3} {what}");
        let _ = sh.out.flush();
    }

    fn send(sh: &mut Shared, payload: &[u8]) {
        let key = sh.key.clone();
        let mut c = sh.counter;
        let msg = create_sec_msg(&key, &mut c, payload, CreateOptions::default()).expect("encrypt");
        sh.counter = c;
        let mut frame = (msg.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&msg);
        let ok = sh.conn.as_mut().map(|s| s.write_all(&frame).is_ok()).unwrap_or(false);
        log(sh, &format!("OUT{} {}", if ok { "" } else { "(failed)" }, escape(payload)));
    }

    fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).ok()?;
        let n = u32::from_le_bytes(hdr) as usize;
        let mut b = vec![0u8; n];
        s.read_exact(&mut b).ok()?;
        Some(b)
    }

    fn handle_conn(sh: Arc<Mutex<Shared>>, mut s: TcpStream) {
        loop {
            let Some(frame) = read_frame(&mut s) else {
                log(&mut sh.lock().unwrap(), "DISCONNECT");
                return;
            };
            // "!<id>!" prefix of agents with a dynamic IP
            let mut body: &[u8] = &frame;
            let mut prefix = String::new();
            if body.first() == Some(&b'!') {
                if let Some(p) = body[1..].iter().position(|&c| c == b'!') {
                    prefix = String::from_utf8_lossy(&body[..p + 2]).into_owned();
                    body = &body[p + 2..];
                }
            }
            let mut g = sh.lock().unwrap();
            let mut key = g.key.clone();
            match read_sec_msg(&mut key, body, ReadOptions { verify_counter: false }) {
                Ok(r) => {
                    let p = r.payload;
                    log(&mut g, &format!("IN {prefix}[{}:{}] {}", r.global, r.local, escape(&p)));
                    let control = p.starts_with(b"#!-");
                    let shutdown = p.starts_with(b"#!-agent shutdown");
                    let req = p.starts_with(b"#!-req");
                    if control && !shutdown && !req {
                        send(&mut g, b"#!-agent ack ");
                        if g.first_ack.is_none() {
                            g.first_ack = Some(Instant::now());
                        }
                    }
                }
                Err(e) => log(&mut g, &format!("IN-ERROR {e}")),
            }
        }
    }

    fn unescape(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 1 < b.len() {
                match b[i + 1] {
                    b'n' => out.push(b'\n'),
                    b'\\' => out.push(b'\\'),
                    c => {
                        out.push(b'\\');
                        out.push(c);
                    }
                }
                i += 2;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    fn run_script(sh: Arc<Mutex<Shared>>, script: String) {
        let lines: Vec<String> = std::fs::read_to_string(&script).unwrap_or_default().lines().map(String::from).collect();
        // wait for the first ACK
        let base = loop {
            if let Some(t) = sh.lock().unwrap().first_ack {
                break t;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        for l in lines {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let mut it = l.splitn(3, ' ');
            let secs: f64 = it.next().unwrap_or("0").parse().unwrap_or(0.0);
            let cmd = it.next().unwrap_or("");
            let arg = it.next().unwrap_or("");
            let at = base + Duration::from_secs_f64(secs);
            let now = Instant::now();
            if at > now {
                std::thread::sleep(at - now);
            }
            let mut g = sh.lock().unwrap();
            match cmd {
                "send" => send(&mut g, &unescape(arg)),
                "file" => {
                    let mut p = arg.splitn(2, ' ');
                    let name = p.next().unwrap_or("");
                    let path = p.next().unwrap_or("");
                    let data = std::fs::read(path).unwrap_or_default();
                    let md5: String = siem_crypto::hashes::md5_bytes(&data).iter().map(|b| format!("{b:02x}")).collect();
                    send(&mut g, format!("#!-up file {md5} {name}\n").as_bytes());
                    for chunk in data.chunks(900) {
                        send(&mut g, chunk);
                    }
                    send(&mut g, b"#!-close file ");
                }
                "close" => {
                    if let Some(c) = g.conn.take() {
                        let _ = c.shutdown(std::net::Shutdown::Both);
                    }
                    log(&mut g, "CLOSE");
                }
                "exit" => {
                    log(&mut g, "EXIT");
                    std::process::exit(0);
                }
                _ => log(&mut g, &format!("BAD-SCRIPT {l}")),
            }
        }
    }

    pub fn main() {
        let a: Vec<String> = std::env::args().collect();
        let port: u16 = a[1].parse().expect("port");
        let keys = std::fs::read_to_string(&a[2]).expect("client.keys");
        let line = keys.lines().next().expect("key line");
        let f: Vec<&str> = line.split(' ').collect();
        let key = ClientKey::new(f[0].into(), f[1].into(), f[2].into(), f[3].into());
        let out = std::fs::File::create(&a[3]).expect("out");
        let sh = Arc::new(Mutex::new(Shared {
            out,
            start: Instant::now(),
            first_ack: None,
            conn: None,
            key,
            counter: SenderCounter::default(),
        }));
        if let Some(script) = a.get(4).cloned() {
            let s = Arc::clone(&sh);
            std::thread::spawn(move || run_script(s, script));
        }
        let l = TcpListener::bind(("127.0.0.1", port)).expect("bind");
        for s in l.incoming().flatten() {
            {
                let mut g = sh.lock().unwrap();
                g.conn = s.try_clone().ok();
                log(&mut g, "CONNECT");
            }
            let s2 = Arc::clone(&sh);
            std::thread::spawn(move || handle_conn(s2, s));
        }
    }
}
