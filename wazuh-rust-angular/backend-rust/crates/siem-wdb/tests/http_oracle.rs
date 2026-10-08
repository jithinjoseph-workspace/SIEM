//! Differential test of the wazuh-db HTTP API (wdb-http.sock) against
//! tools/oracle/http_harness.cpp (the router's API code, cpp-httplib 0.14.2,
//! nlohmann 3.11.2 and the real endpoints over the real wazuh-db library).
//!
//! Environment:
//!   SIEM_HTTP_ORACLE  command line of the oracle, e.g.
//!                     "env TZ=UTC /home/u/wdb_oracle/http_oracle /home/u/wdb_oracle/hhome"
//!   SIEM_HTTP_FUZZ    number of mutated requests (default 300)
//!   SIEM_HTTP_SEED    fuzz seed (default 1)
//!   SIEM_HTTP_KEEP    keep the input and both outputs in this directory

#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use siem_wdb::wdb::http::{start_api, ApiLog};

/// The router logs of the harness: error/warning/info only.
struct Capture(Arc<Env>);

impl ApiLog for Capture {
    fn log(&self, level: &str, msg: &[u8]) {
        if matches!(level, "ERROR" | "WARNING" | "INFO" | "CRITICAL") {
            self.0.out.lock().push(format!("M {level} {}", hex(msg)));
        }
    }
}

/// The client of an H line: connect, send, read until EOF or 300 ms of
/// silence, then half-close and read until the server closes.
fn exchange(home: &Path, request: &[u8]) -> Vec<u8> {
    let path = home.join("queue/sockets/wdb-http.sock");
    let mut got = Vec::new();
    let mut s = None;
    for _ in 0..100 {
        match UnixStream::connect(&path) {
            Ok(c) => {
                s = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    if let Some(mut s) = s {
        let _ = s.write_all(request);
        let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
        let mut buf = vec![0u8; 65536];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        // then half-close and wait for the server to close the connection,
        // so the exchange (and its logs) ends when the server is done
        let _ = s.shutdown(std::net::Shutdown::Write);
        let _ = s.set_read_timeout(Some(Duration::from_millis(8000)));
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    }
    got
}

fn run_rust(home: &Path, input: &str) -> Vec<String> {
    let mut sess = Session::new(home);
    let api = start_api(sess.d.clone(), Arc::new(Capture(sess.env.clone())) as Arc<dyn ApiLog>);
    for l in input.lines() {
        if let Some(h) = l.strip_prefix("H ") {
            let got = exchange(home, &unhex(h));
            sess.env.out.lock().push(format!("H {}", hex(&got)));
        } else {
            sess.line(l);
        }
    }
    if let Some(api) = api {
        api.stop();
    }
    sess.finish()
}

// ------------------------------------------------------------------ corpus

struct Corpus {
    lines: Vec<String>,
    http: Vec<Vec<u8>>,
}

impl Corpus {
    fn q(&mut self, s: &str) {
        self.lines.push(format!("Q {}", hex(s.as_bytes())));
    }
    fn h(&mut self, r: impl AsRef<[u8]>) {
        let r = r.as_ref().to_vec();
        self.lines.push(format!("H {}", hex(&r)));
        self.http.push(r);
    }
    /// A request with Connection: close.
    fn req(&mut self, method: &str, path: &str, headers: &[&str], body: &[u8]) {
        let mut r = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n").into_bytes();
        for h in headers {
            r.extend_from_slice(h.as_bytes());
            r.extend_from_slice(b"\r\n");
        }
        if !body.is_empty() && !headers.iter().any(|h| h.to_ascii_lowercase().starts_with("content-length") || h.to_ascii_lowercase().starts_with("transfer-encoding")) {
            r.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        r.extend_from_slice(b"\r\n");
        r.extend_from_slice(body);
        self.h(r);
    }
}

fn corpus() -> Corpus {
    let mut c = Corpus { lines: Vec::new(), http: Vec::new() };
    // ---- state
    for (id, name, ip, os) in [(1, "a1", "1.1.1.1", "ubuntu"), (2, "a2", "2.2.2.2", "windows"), (3, "a3", "3.3.3.3", "ubuntu"), (4, "a4", "4.4.4.4", ""), (5, "a\"5", "5.5.5.5", "centos")] {
        c.q(&format!("global insert-agent {{\"id\":{id},\"name\":\"{name}\",\"ip\":\"{ip}\",\"register_ip\":\"any\",\"internal_key\":\"k\",\"date_add\":{}}}", 1600000000 + id));
        if !os.is_empty() {
            c.q(&format!("global update-agent-data {{\"id\":{id},\"os_name\":\"OS {id}\",\"os_platform\":\"{os}\",\"version\":\"Wazuh v4.{id}\",\"node_name\":\"node01\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"labels\":\"env:prod\\nteam:t{id}\"}}"));
        }
    }
    for g in ["g1", "g2", "g with space", "default"] {
        c.q(&format!("global insert-agent-group {g}"));
    }
    c.q("global set-agent-groups {\"mode\":\"append\",\"data\":[{\"id\":1,\"groups\":[\"g1\",\"g2\"]},{\"id\":2,\"groups\":[\"g2\"]},{\"id\":3,\"groups\":[\"default\"]}]}");
    c.q("global update-keepalive {\"id\":2,\"connection_status\":\"active\",\"sync_status\":\"syncreq_keepalive\"}");
    c.q("global update-connection-status {\"id\":3,\"connection_status\":\"disconnected\",\"sync_status\":\"syncreq_status\",\"status_code\":4}");

    // ---- GET endpoints
    for p in [
        "/v1/agents/ids",
        "/v1/agents/ids/groups",
        "/v1/agents/ids/groups/g2",
        "/v1/agents/ids/groups/g%20with%20space",
        "/v1/agents/ids/groups/none",
        "/v1/agents/ids/groups/",
        "/v1/agents/1/groups",
        "/v1/agents/%31/groups",
        "/v1/agents/abc/groups",
        "/v1/agents/99999999999/groups",
        "/v1/agents/-1/groups",
        "/v1/agents/ 2/groups",
        "/v1/agents/2x/groups",
        "/v1/agents//groups",
        "/v1/agents/1/groups/",
        "/v1/agents/ids?x=1&y=%20#frag",
        "/v1/agents/ids/",
        "//v1/agents/ids",
        "/v1/agents/%69ds",
        "/nothing",
        "/v1/agents/sync",
        "/v1/agents/sync",
    ] {
        c.req("GET", p, &[], b"");
    }
    c.req("HEAD", "/v1/agents/ids", &[], b"");
    c.req("POST", "/v1/agents/ids", &[], b"");
    c.req("PUT", "/v1/agents/ids", &["Content-Length: 0"], b"");
    c.req("DELETE", "/v1/agents/ids", &[], b"");
    c.req("OPTIONS", "/v1/agents/ids", &[], b"");
    c.req("PATCH", "/v1/agents/ids", &["Content-Length: 0"], b"");
    c.req("CONNECT", "/v1/agents/ids", &[], b"");
    c.req("TRACE", "/v1/agents/ids", &[], b"");
    c.req("PRI", "/v1/agents/ids", &["Content-Length: 0"], b"");
    c.req("get", "/v1/agents/ids", &[], b"");
    // ---- request lines
    for raw in [
        "GET /v1/agents/ids HTTP/1.0\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n",
        "GET /v1/agents/ids HTTP/2.0\r\n\r\n",
        "GET /v1/agents/ids\r\n\r\n",
        "GET  /v1/agents/ids   HTTP/1.1\r\nConnection: close\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\n\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: clos%65\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nRange: bytes=0-2\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nRange: bytes=2-\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nRange: bytes=-2\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nRange: bytes=50-60\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nRange: bytes=3-1\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nRange: items=0-1\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nRange: bytes=99999999999999999999-\r\n\r\n",
        "HEAD /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nRange: bytes=0-0\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nExpect: 100-continue\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nbad header line\r\nX: \r\n:empty\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nHost: x\r\n\r\nGET /v1/agents/ids/groups HTTP/1.1\r\nConnection: close\r\n\r\n",
        "GET /v1/agents/ids HTTP/1.1\r\nHost: x\r\n\r\n",
        "\r\n",
        "",
    ] {
        c.h(raw);
    }
    // URI and header limits
    c.h(format!("GET /{} HTTP/1.1\r\nConnection: close\r\n\r\n", "a".repeat(8200)));
    c.h(format!("GET /v1/agents/ids HTTP/1.1\r\nConnection: close\r\nX-Long: {}\r\n\r\n", "b".repeat(8200)));
    // ---- POST summary
    for body in ["", "1,2,3", "[1, 2]", "-1,abc,2", "2147483648,1", "--5,5-3", "x", "3", "1,2,3,4,5"] {
        c.req("POST", "/v1/agents/summary", &[], body.as_bytes());
    }
    // ---- POST sync
    for body in [
        "{\"syncreq\":[{\"id\":1,\"name\":\"n1\",\"ip\":\"9.9.9.9\",\"os_name\":\"x\",\"last_keepalive\":1759658000,\"connection_status\":\"active\",\"disconnection_time\":0,\"status_code\":0,\"labels\":[{\"key\":\"k1\",\"value\":\"v1\"},{\"key\":\"k2\",\"value\":\"v2\"}]}]}",
        "{\"syncreq\":[{\"id\":2,\"labels\":[{\"key\":\"dup\",\"value\":\"1\"},{\"key\":\"dup\",\"value\":\"2\"},{\"key\":\"after\",\"value\":\"x\"}]}]}",
        "{\"syncreq_keepalive\":[{\"id\":3,\"version\":\"Wazuh v9\"},{\"id\":4}]}",
        "{\"syncreq_status\":[{\"id\":4,\"connection_status\":\"disconnected\",\"disconnection_time\":1759650000,\"status_code\":2,\"version\":\"v\"}]}",
        "{\"syncreq\":[{\"name\":\"no id\"}]}",
        "{\"syncreq\":[{\"id\":\"1\"}]}",
        "{\"syncreq\":[{\"id\":1,\"name\":5}]}",
        "{\"syncreq\":[{\"id\":1,\"last_keepalive\":\"x\"}]}",
        "{\"syncreq\":[{\"id\":1,\"last_keepalive\":true}]}",
        "{\"syncreq\":[{\"id\":1.9,\"last_keepalive\":1e300}]}",
        "{\"syncreq\":{\"a\":{\"id\":5,\"name\":\"obj\"}}}",
        "{\"syncreq\":\"str\"}",
        "{\"syncreq\":null}",
        "{\"syncreq\":[{\"id\":5,\"labels\":\"notarray\"}]}",
        "{\"syncreq\":[{\"id\":5,\"labels\":[1,{\"key\":3}]}]}",
        "[1,2]",
        "{}",
        "",
        "{\"a\":",
        "{\"a\" 1}",
        "{\"a\":1,}",
        "{\"a\":[1 2]}",
        "{\"a\":\"\\x\"}",
        "{\"a\":\"\\u12\"}",
        "{\"a\":\"\\ud800\"}",
        "{\"a\":\"\\udc00\"}",
        "{\"a\":\"\\ud800\\u0041\"}",
        "{\"a\":\"tab\there\"}",
        "{\"a\":\"\u{1}\"}",
        "{\"a\":-}",
        "{\"a\":1.}",
        "{\"a\":1e}",
        "{\"a\":1e+}",
        "{\"a\":01}",
        "{\"a\":1e999}",
        "{\"a\":tru}",
        "{\"a\":nul}",
        "{\"a\":1}\n x",
        "{\"a\":1}\n\n {",
        "\u{feff}{}",
        "{\"a\":\"open",
        "\n\n   \n",
        "{\"syncreq\":[{\"id\":18446744073709551615}]}",
        "{\"syncreq\":[{\"id\":-9223372036854775809}]}",
    ] {
        c.req("POST", "/v1/agents/sync", &[], body.as_bytes());
    }
    c.req("POST", "/v1/agents/sync", &[], b"{\"a\":\"\xff\"}");
    c.req("POST", "/v1/agents/sync", &[], b"{\"a\":\"\xc3\x28\"}");
    c.req("POST", "/v1/agents/sync", &[], b"{}\x00junk");
    c.req("POST", "/v1/agents/sync", &[], b"\xef\xbb{}");
    // ---- POST restartinfo
    for body in [
        "",
        "{}",
        "{\"ids\":[1,2]}",
        "{\"ids\":[1,2],\"negate\":true}",
        "{\"ids\":[1,2],\"negate\":\"yes\"}",
        "{\"ids\":[]}",
        "{\"ids\":5}",
        "{\"ids\":[\"1\"]}",
        "{\"ids\":[null]}",
        "{\"ids\":[1.7, true]}",
        "[{\"ids\":[1]}]",
        "nope",
    ] {
        c.req("POST", "/v1/agents/restartinfo", &[], body.as_bytes());
    }
    // ---- bodies
    c.req("POST", "/v1/agents/summary", &["Transfer-Encoding: chunked"], b"3\r\n1,2\r\n0\r\n\r\n");
    c.req("POST", "/v1/agents/summary", &["Transfer-Encoding: chunked"], b"3\r\n1,2\r\n0\r\nX-T: 1\r\n\r\n");
    c.req("POST", "/v1/agents/summary", &["Transfer-Encoding: chunked"], b"zz\r\n1\r\n0\r\n\r\n");
    c.req("POST", "/v1/agents/summary", &["Transfer-Encoding: chunked"], b"3\r\n1,2XX0\r\n\r\n");
    c.req("POST", "/v1/agents/restartinfo", &["Transfer-Encoding: Chunked"], b"0x8\r\n{\"ids\":[\r\n4\r\n1,2]\r\n1\r\n}\r\n0\r\n\r\n");
    c.req("POST", "/v1/agents/summary", &["Content-Encoding: gzip"], b"1");
    c.req("POST", "/v1/agents/summary", &["Content-Encoding: abroad"], b"1");
    c.req("POST", "/v1/agents/summary", &["Content-Type: multipart/form-data; boundary=XX"], b"--XX\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1,2\r\n--XX--\r\n");
    c.req("POST", "/v1/agents/summary", &["Content-Type: multipart/form-data; boundary=XX"], b"--XX\r\nContent-Disposition: form-data; filename=\"a\"\r\n\r\n1\r\n--XX--\r\n");
    c.req("POST", "/v1/agents/summary", &["Content-Type: multipart/form-data"], b"x");
    c.req("POST", "/v1/agents/summary", &["Content-Type: multipart/form-data; boundary=XX"], b"no boundary here");
    c.req("POST", "/v1/agents/summary", &["Content-Type: application/x-www-form-urlencoded"], b"1,2");
    c.req("POST", "/v1/agents/summary", &["Content-Type: application/x-www-form-urlencoded"], "9,".repeat(4200).as_bytes());
    c.req("POST", "/v1/agents/summary", &["Content-Length: abc"], b"");
    c.req("POST", "/v1/agents/summary", &["Content-Length: 1%32"], b"1,2,3,4,5,6,");
    c.req("POST", "/v1/agents/summary", &["Content-Length: 50"], b"1,2");
    c.req("POST", "/v1/agents/summary", &["Content-Length: 0", "Expect: 100-continue"], b"");
    c.h("POST /v1/agents/summary HTTP/1.1\r\nContent-Length: 3\r\nConnection: close\r\nExpect: 100-continue\r\n\r\n1,2");
    // ---- state after the API calls
    c.q("global sql SELECT id, name, ip, sync_status, connection_status, last_keepalive, status_code, version FROM agent ORDER BY id");
    c.q("global sql SELECT * FROM labels ORDER BY id, key");
    c.q("global commit");
    c
}

// -------------------------------------------------------------------- fuzz

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const TOKENS: [&[u8]; 18] = [
    b"\r\n", b"\n", b" ", b"%", b"%2", b"%00", b"\"", b"{", b"}", b"[", b"]", b",", b":", b"\\u", b"-1", b"1e9", b"null", b"\x00",
];

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut r = base.to_vec();
    // keep the request line and the Connection: close header
    let protect = r.windows(19).position(|w| w == b"Connection: close\r\n").map(|p| p + 19).unwrap_or(0);
    for _ in 0..1 + rng.below(3) {
        if r.len() <= protect {
            break;
        }
        let p = protect + rng.below(r.len() - protect);
        match rng.below(4) {
            0 => {
                r.remove(p);
            }
            1 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                r.splice(p..p, t.iter().copied());
            }
            2 => {
                const SET: &[u8] = b"0123456789abcxyz\"{}[]:,- \r\n%";
                r[p] = SET[rng.below(SET.len())];
            }
            _ => r.truncate(p.max(protect)),
        }
    }
    // keep a Content-Length consistent with the body (most of the time)
    if let Some(he) = r.windows(4).position(|w| w == b"\r\n\r\n") {
        let body_len = r.len() - he - 4;
        if let Some(cl) = r[..he].windows(16).position(|w| w == b"Content-Length: ") {
            let s = cl + 16;
            let e = r[s..he].iter().position(|&c| c == b'\r').map(|x| x + s).unwrap_or(he);
            if rng.below(8) != 0 {
                r.splice(s..e, body_len.to_string().into_bytes());
            }
        }
    }
    r
}

#[test]
fn http_api_matches_c_oracle() {
    let Ok(cmd) = std::env::var("SIEM_HTTP_ORACLE") else {
        eprintln!("SIEM_HTTP_ORACLE not set; skipping");
        return;
    };
    let fuzz: usize = std::env::var("SIEM_HTTP_FUZZ").ok().and_then(|v| v.parse().ok()).unwrap_or(300);
    let seed: u64 = std::env::var("SIEM_HTTP_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let mut c = corpus();
    let base: Vec<Vec<u8>> = c.http.iter().filter(|r| r.windows(19).any(|w| w == b"Connection: close\r\n")).cloned().collect();
    let mut rng = Rng(0x2545_F491_4F6C_DD1D ^ seed);
    for _ in 0..fuzz {
        let b = &base[rng.below(base.len())];
        let m = mutate(&mut rng, b);
        c.h(m);
    }
    c.q("global sql SELECT * FROM agent ORDER BY id");
    let input = c.lines.join("\n") + "\n";

    let home: PathBuf = std::env::temp_dir().join(format!("siem_wdb_http_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let rust = run_rust(&home, &input);
    let oracle = run_oracle(&cmd, &input);
    let _ = std::fs::remove_dir_all(&home);

    if let Ok(keep) = std::env::var("SIEM_HTTP_KEEP") {
        let k = PathBuf::from(keep);
        let _ = std::fs::create_dir_all(&k);
        std::fs::write(k.join("input.txt"), &input).unwrap();
        std::fs::write(k.join("rust.txt"), rust.join("\n")).unwrap();
        std::fs::write(k.join("oracle.txt"), oracle.join("\n")).unwrap();
    }
    let diffs = compare(&rust, &oracle, &c.lines);
    eprintln!("{} lines, {diffs} diffs", c.lines.len());
    assert_eq!(diffs, 0, "the Rust HTTP API differs from the C++ oracle");
}
