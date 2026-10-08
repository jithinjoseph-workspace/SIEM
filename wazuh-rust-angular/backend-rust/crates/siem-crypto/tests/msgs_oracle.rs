//! Differential test against Wazuh's C `msgs.c` (see `tools/README.md`).
//!
//! Skipped unless `SIEM_MSGS_ORACLE` points to a built `msgs_harness`.

use siem_crypto::keys::{ClientKey, CryptoMethod};
use siem_crypto::msgs::{create_sec_msg, read_sec_msg, CreateOptions, KeyState, ReadOptions, SenderCounter};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Oracle {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    fn start() -> Option<Self> {
        let exe = std::env::var("SIEM_MSGS_ORACLE").ok()?;
        let dir = tempfile::tempdir().unwrap().keep();
        let mut child = Command::new(exe)
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn msgs oracle");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Some(Self { _child: child, stdin, stdout })
    }

    fn call(&mut self, line: &str) -> String {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
        let mut out = String::new();
        self.stdout.read_line(&mut out).unwrap();
        out.trim_end().to_string()
    }

    fn create(&mut self, method: CryptoMethod, k: &ClientKey, raw: &str, g: u32, l: u32, rand: u16, dynamic: bool, msg: &[u8]) -> Vec<u8> {
        let m = if method == CryptoMethod::Aes { 1 } else { 0 };
        let line = format!("C\t{m}\t{}\t{}\t{raw}\t{g}\t{l}\t{rand}\t{}\t{}", k.id, k.name, dynamic as u8, hex::encode(msg));
        hex::decode(self.call(&line)).unwrap()
    }

    /// Returns (key_state, payload)
    fn read(&mut self, k: &ClientKey, raw: &str, g: u32, l: u32, wire: &[u8]) -> (u8, Option<Vec<u8>>) {
        let line = format!("R\t{}\t{}\t{raw}\t{g}\t{l}\t{}", k.id, k.name, hex::encode(wire));
        let out = self.call(&line);
        let (st, payload) = out.split_once(' ').unwrap();
        let st: u8 = st.parse().unwrap();
        (st, if payload == "-" { None } else { Some(hex::decode(payload).unwrap()) })
    }
}

fn payloads() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        b"#!-agent startup {\"version\":\"v4.14.7\"}".to_vec(),
        b"1:/var/log/syslog:Oct  5 10:00:00 host sshd[123]: Failed password for root from 10.1.1.1 port 22 ssh2".to_vec(),
        b"x".to_vec(),
        "8:syscheck:{\"type\":\"event\",\"data\":{\"path\":\"/etc/\u{e9}\"}}".as_bytes().to_vec(),
    ];
    // Lengths 1..300 hit every padding size and both ciphers' block edges.
    for n in 1..300usize {
        v.push((0..n).map(|i| b"abcdefghij0123456789:/ "[(i * 7 + n) % 23]).collect());
    }
    // Incompressible data.
    let mut x: u32 = 12345;
    v.push((0..5000).map(|_| { x = x.wrapping_mul(1103515245).wrapping_add(12345); (x >> 16) as u8 | 1 }).collect());
    // Near the maximum size.
    v.push(vec![b'A'; 65536 - 128]);
    v
}

#[test]
fn rust_and_c_interoperate() {
    let Some(mut oracle) = Oracle::start() else {
        eprintln!("SIEM_MSGS_ORACLE not set; skipping C differential test");
        return;
    };
    let raw = "3c2f6e9a1b8d4e7f0a5c2b9d8e1f4a7b6c3d0e9f8a7b6c5d4e3f2a1b0c9d8e7f";
    let mut checked = 0;
    for (id, name) in [("001", "agent1"), ("1234", "web-server-01"), ("000", "manager")] {
        for method in [CryptoMethod::Blowfish, CryptoMethod::Aes] {
            let mut k = ClientKey::new(id.into(), name.into(), "10.0.0.1".into(), raw.into());
            k.crypto_method = method;
            for (i, msg) in payloads().iter().enumerate() {
                let g = (i as u32) * 3;
                let l = (i as u32 * 37) % 9997;
                let rand = (i as u16).wrapping_mul(2654) ^ 0x5a5a;

                // C -> Rust
                let wire = oracle.create(method, &k, raw, g, l, rand, false, msg);
                let mut rk = k.clone();
                let r = read_sec_msg(&mut rk, &wire, ReadOptions { verify_counter: true })
                    .unwrap_or_else(|e| panic!("Rust failed to read C message ({method:?}, len {}): {e}", msg.len()));
                assert_eq!(&r.payload, msg);
                let (eg, el) = if l >= 9997 { (g + 1, 1) } else { (g, l + 1) };
                assert_eq!((r.global, r.local), (eg, el));

                // C with dynamic-IP prefix: remoted strips "!<id>!" before ReadSecMSG.
                let wire_dyn = oracle.create(method, &k, raw, g, l, rand, true, msg);
                let prefix = format!("!{id}!");
                assert!(wire_dyn.starts_with(prefix.as_bytes()));
                let mut rk = k.clone();
                assert_eq!(&read_sec_msg(&mut rk, &wire_dyn[prefix.len()..], ReadOptions::default()).unwrap().payload, msg);

                // Rust -> C
                let mut ctr = SenderCounter { global: g, local: l };
                let ours = create_sec_msg(&k, &mut ctr, msg, CreateOptions { dynamic_prefix: false, random: Some(rand) }).unwrap();
                let (st, payload) = oracle.read(&k, raw, 0, 0, &ours);
                assert_eq!(st, 0, "C rejected Rust message ({method:?}, len {})", msg.len());
                assert_eq!(payload.as_deref(), Some(msg.as_slice()));

                // Same envelope as C (zlib output itself may legitimately differ
                // between zlib and miniz_oxide, so lengths are not compared).
                let token_len = if method == CryptoMethod::Aes { 5 } else { 1 };
                assert_eq!(&ours[..token_len], &wire[..token_len]);
                assert_eq!((ours.len() - token_len) % 8, 0);

                // Replay / old counter / wrong key: both sides agree on the key state.
                for (sg, sl) in [(eg, el), (eg, el + 5), (eg + 1, 0)] {
                    let (cst, _) = oracle.read(&k, raw, sg, sl, &ours);
                    let mut rk = k.clone();
                    rk.global_counter = sg;
                    rk.local_counter = sl;
                    let rst = match read_sec_msg(&mut rk, &ours, ReadOptions { verify_counter: true }) {
                        Ok(_) => 0,
                        Err(e) => e.key_state().unwrap() as u8,
                    };
                    assert_eq!(rst, cst, "state mismatch saved={sg}:{sl}");
                }
                let mut wrong = ClientKey::new(id.into(), name.into(), "10.0.0.1".into(), "wrongkey".into());
                wrong.crypto_method = method;
                let (cst, _) = oracle.read(&wrong, "wrongkey", 0, 0, &ours);
                let rst = match read_sec_msg(&mut wrong.clone(), &ours, ReadOptions::default()) {
                    Ok(_) => 0,
                    Err(e) => e.key_state().unwrap() as u8,
                };
                assert_eq!(rst, cst, "wrong-key state mismatch ({method:?}, len {})", msg.len());
                assert_ne!(cst, KeyState::Valid as u8);
                checked += 1;
            }
        }
    }
    eprintln!("{checked} message cases interoperate with C msgs.c");
}
