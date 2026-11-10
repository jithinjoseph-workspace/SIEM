//! Replays `specs/vectors/siem-crypto/*.json`, recorded from the crate this one replaces.

use provigil_crypto::ciphers::*;
use provigil_crypto::hashes::*;
use provigil_crypto::keys::{derive_encryption_key, ClientKey, CryptoMethod, KeyStore as Keys};
use provigil_crypto::keystore::{self, *};
use provigil_crypto::msgs::{self, *};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{env, fs, thread};
use tracing::field::{Field, Visit};
use tracing::span;

type Logs = Arc<Mutex<Vec<(String, String)>>>;

/// Collects log events of the current thread.
struct Capture(Logs);

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        struct Msg(String);
        impl Visit for Msg {
            fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
                if f.name() == "message" {
                    self.0 = format!("{v:?}");
                }
            }
        }
        let mut m = Msg(String::new());
        e.record(&mut m);
        self.0.lock().unwrap().push((e.metadata().level().to_string(), m.0));
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

fn logged<T>(f: impl FnOnce() -> T) -> (T, Value) {
    let logs = Logs::default();
    let r = tracing::subscriber::with_default(Capture(logs.clone()), f);
    let got: Vec<Value> = logs.lock().unwrap().iter().map(|(l, m)| json!([l, m])).collect();
    (r, Value::Array(got))
}

/// Cases, mismatches and the keys left out on purpose for one vector file.
struct Run {
    name: &'static str,
    cases: Vec<Value>,
    passed: usize,
    failed: Vec<String>,
    errs: Vec<String>,
}

impl Run {
    fn new(name: &'static str) -> Run {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/vectors/siem-crypto").join(format!("{name}.json"));
        let mut doc: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let cases = doc["cases"].as_array_mut().map(std::mem::take).unwrap();
        assert_eq!(doc["meta"]["count"].as_u64(), Some(cases.len() as u64), "{name}: case count");
        Run { name, cases, passed: 0, failed: vec![], errs: vec![] }
    }

    fn eq(&mut self, what: &str, got: impl Into<Value>, want: &Value) {
        let got = got.into();
        if &got != want {
            let cut = |v: &Value| v.to_string().chars().take(300).collect::<String>();
            self.errs.push(format!("{what}: got {} want {}", cut(&got), cut(want)));
        }
    }

    fn done(&mut self, label: impl std::fmt::Display) {
        if self.errs.is_empty() {
            self.passed += 1;
        } else {
            self.failed.push(format!("[{label}] {}", self.errs.join(" | ")));
            self.errs.clear();
        }
    }

    fn finish(self) {
        let checked = self.passed + self.failed.len();
        println!("VECTORS {}: {}/{} passed", self.name, self.passed, checked);
        for f in self.failed.iter().take(25) {
            println!("  FAIL {f}");
        }
        assert!(self.failed.is_empty(), "{}: {} failed", self.name, self.failed.len());
        assert!(checked > 0, "{}: nothing checked", self.name);
    }
}

fn scratch(tag: &str) -> PathBuf {
    let d = env::temp_dir().join(format!("pv-crypto-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn data(v: &Value) -> Vec<u8> {
    match v.get("hex") {
        Some(h) => unhex(h.as_str().unwrap()),
        None => unhex(v["repeat_hex"].as_str().unwrap()).repeat(v["times"].as_u64().unwrap() as usize),
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn key_json(k: &ClientKey) -> Value {
    json!({"crypto_method": format!("{:?}", k.crypto_method), "encryption_key": k.encryption_key,
        "global_counter": k.global_counter, "id": k.id, "ip": k.ip, "key_line": k.to_key_line(),
        "local_counter": k.local_counter, "name": k.name, "raw_key": k.raw_key})
}

fn opt_key(k: Option<&ClientKey>) -> Value {
    k.map_or(Value::Null, key_json)
}

#[test]
fn hashes() {
    let mut r = Run::new("hashes");
    let dir = scratch("hashes");
    let file = dir.join("input");
    for c in std::mem::take(&mut r.cases) {
        if c.get("missing_file").is_some() {
            let none = dir.join("none");
            let kinds = [
                ("md5_file", md5_file(&none).unwrap_err()),
                ("sha1_file", sha1_file(&none).unwrap_err()),
                ("sha256_file", sha256_file(&none).unwrap_err()),
                ("sha512_file", sha512_file(&none).unwrap_err()),
                ("hmac_sha1_file", hmac_sha1_file("k", &none).unwrap_err()),
                ("multi_hash_file", multi_hash_file(&none, 0).unwrap_err()),
            ];
            for (name, e) in kinds {
                r.eq(name, format!("{:?}", e.kind()), &c[name]["error_kind"]);
            }
            r.done("missing file");
            continue;
        }
        let input = data(&c["input"]);
        r.eq("md5_bytes", hex::encode(md5_bytes(&input)), &c["md5_bytes"]);
        r.eq("sha1_bytes", hex::encode(sha1_bytes(&input)), &c["sha1_bytes"]);
        r.eq("sha256_bytes", hex::encode(sha256_bytes(&input)), &c["sha256_bytes"]);
        r.eq("sha512_bytes", hex::encode(sha512_bytes(&input)), &c["sha512_bytes"]);
        fs::write(&file, &input).unwrap();
        r.eq("md5_file", md5_file(&file).unwrap(), &c["md5_file"]);
        r.eq("sha1_file", sha1_file(&file).unwrap(), &c["sha1_file"]);
        r.eq("sha256_file", sha256_file(&file).unwrap(), &c["sha256_file"]);
        r.eq("sha512_file", sha512_file(&file).unwrap(), &c["sha512_file"]);
        // Key texts of 0, 1, 10, 64, 65 and 80 bytes.
        let hmac_keys = [String::new(), "k".into(), "secret-key".into(), "K".repeat(64), "K".repeat(65), "é".repeat(40)];
        for k in &hmac_keys {
            r.eq("hmac_file", hmac_sha1_file(k, &file).unwrap(), &c[format!("hmac_sha1_file key={}", k.len())]);
        }
        if let Ok(t) = std::str::from_utf8(&input) {
            r.eq("md5_str", md5_str(t), &c["md5_str"]);
            r.eq("sha1_str", sha1_str(t), &c["sha1_str"]);
            r.eq("sha256_str", sha256_str(t), &c["sha256_str"]);
            r.eq("sha512_str", sha512_str(t), &c["sha512_str"]);
            // Not recorded for the 1 MB input.
            for k in hmac_keys.iter().filter(|k| c.get(format!("hmac_sha1_str key={}", k.len())).is_some()) {
                r.eq("hmac_str", hmac_sha1_str(k, t).unwrap(), &c[format!("hmac_sha1_str key={}", k.len())]);
            }
        }
        for m in c["multi_hash_file"].as_array().unwrap() {
            let got = match multi_hash_file(&file, m["max_size"].as_u64().unwrap() as usize) {
                Ok((a, b, d)) => json!([a, b, d]),
                Err(e) => json!({"display": e.to_string(), "error_kind": format!("{:?}", e.kind())}),
            };
            r.eq("multi", got, &m["result"]);
        }
        r.done(c["input"].to_string().chars().take(30).collect::<String>());
    }
    r.finish();
}

fn cipher_json(x: Result<Vec<u8>, CipherError>) -> Value {
    match x {
        Ok(b) => json!({"hex": hex::encode(b)}),
        Err(CipherError::Encryption(_)) => json!({"error": "encryption"}),
        Err(CipherError::Decryption(_)) => json!({"error": "decryption"}),
        Err(e) => json!({"error": e.to_string()}),
    }
}

#[test]
fn ciphers() {
    let mut r = Run::new("ciphers");
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        let plain = unhex(s(&c["plain_hex"]));
        if c["fn"] == "os_str" {
            let key = s(&c["charkey"]);
            let enc = os_aes_str(&plain, key, true);
            r.eq("aes", cipher_json(enc.clone()), &c["aes_encrypt"]);
            r.eq("aes back", cipher_json(os_aes_str(&enc.unwrap(), key, false)), &c["aes_decrypt_of_that"]);
            let enc = os_bf_str(&plain, key, true);
            r.eq("bf", cipher_json(enc.clone()), &c["bf_encrypt"]);
            let back = enc.map_or(Value::Null, |e| cipher_json(os_bf_str(&e, key, false)));
            r.eq("bf back", back, &c["bf_decrypt_of_that"]);
            r.done(n);
            continue;
        }
        let (key, iv) = (unhex(s(&c["key_hex"])), unhex(s(&c["iv_hex"])));
        let aes = c["fn"] == "aes";
        let enc = if aes { Ok(encrypt_aes(&plain, &key, &iv)) } else { encrypt_blowfish(&plain, &key, &iv) };
        r.eq("encrypt", cipher_json(enc), &c["encrypt"]);
        for d in c["decrypt"].as_array().unwrap() {
            let input = unhex(s(&d["input_hex"]));
            let got = if aes { decrypt_aes(&input, &key, &iv) } else { decrypt_blowfish(&input, &key, &iv) };
            r.eq("decrypt", cipher_json(got), &d["result"]);
        }
        r.done(n);
    }
    r.finish();
}

#[test]
fn keys() {
    let mut r = Run::new("keys");
    let dir = scratch("keys");
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        match s(&c["fn"]) {
            "derive_encryption_key" => {
                let (id, name, raw) = (s(&c["id"]), s(&c["name"]), s(&c["raw_key"]));
                r.eq("derive", derive_encryption_key(name, id, raw), &c["result"]);
                let k = ClientKey::new(id.into(), name.into(), "any".into(), raw.into());
                r.eq("new", key_json(&k), &c["client_key_new"]);
            }
            "KeyStore::parse_line" => r.eq("parse", opt_key(Keys::parse_line(s(&c["line"])).as_ref()), &c["result"]),
            "KeyStore::load_file" if c.get("missing").is_some() => {
                let e = Keys::load_file(dir.join("none")).unwrap_err();
                r.eq("kind", format!("{:?}", e.kind()), &c["result"]["error_kind"]);
            }
            "KeyStore::load_file" => load_file_case(&mut r, &c, &dir),
            "KeyStore::generate_raw_key" => {
                let k = Keys::generate_raw_key();
                let shape = k.len() == 64 && k.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                r.eq("shape", shape, &json!(true));
            }
            _ => {
                let mut ks = Keys::new();
                r.eq("empty next", ks.next_id(), &c["empty_next_id"]);
                for st in c["steps"].as_array().unwrap() {
                    ks.add_key(ClientKey::new(s(&st["added"]).into(), "n".into(), "any".into(), "k".into()));
                    r.eq("next", ks.next_id(), &st["next_id"]);
                }
            }
        }
        r.done(n);
    }
    r.finish();
}

fn load_file_case(r: &mut Run, c: &Value, dir: &Path) {
    let file = dir.join("client.keys");
    fs::write(&file, s(&c["content"])).unwrap();
    let mut ks = Keys::load_file(&file).unwrap();
    r.eq("keys", ks.keys.iter().map(key_json).collect::<Vec<_>>(), &c["keys"]);
    r.eq("len", ks.len(), &c["len"]);
    r.eq("empty", ks.keys.is_empty(), &c["is_empty"]);
    r.eq("next_id", ks.next_id(), &c["next_id"]);
    for l in c["lookups"].as_array().unwrap() {
        if let Some(v) = l.get("find_by_id") {
            r.eq("by id", ks.find_by_id(s(v)).map(|k| k.name.clone()), &l["result_name"]);
        } else if let Some(v) = l.get("find_by_name") {
            r.eq("by name", ks.find_by_name(s(v)).map(|k| k.id.clone()), &l["result_id"]);
        } else {
            r.eq("by ip", ks.find_by_ip(s(&l["find_by_ip"])).map(|k| k.id.clone()), &l["result_id"]);
        }
    }
    for d in c["deletes"].as_array().unwrap() {
        r.eq("removed", opt_key(ks.delete_key(s(&d["delete_key"])).as_ref()), &d["removed"]);
        r.eq("after", ks.find_by_id("001").map(|k| k.name.clone()), &d["find_by_id_001_after"]);
        r.eq("left", ks.keys.iter().map(|k| k.id.clone()).collect::<Vec<_>>(), &d["keys_after"]);
    }
    ks.save_file(&file).unwrap();
    r.eq("saved", fs::read_to_string(&file).unwrap(), &c["save_file_after_deletes"]);
}

fn entry_json(e: &KeyEntry) -> Value {
    let st = e.state.lock().unwrap();
    json!({"id": e.id, "ip_is_ipv6": e.ip.is_ipv6, "ip_str": e.ip_str, "ip_text": e.ip.ip,
        "is_single_host": e.is_single_host(), "keyid": e.keyid, "name": e.name, "raw_key": e.raw_key,
        "state": {"key": key_json(&st.key), "net_protocol": format!("{:?}", st.net_protocol),
            "peer": st.peer.map(|p| p.to_string()), "post_startup": st.post_startup, "rcvd": st.rcvd, "sock": st.sock},
        "time_added": e.time_added})
}

fn store_json(ks: &keystore::KeyStore) -> Value {
    json!({"entries": ks.entries.iter().map(|e| entry_json(e)).collect::<Vec<_>>(), "id_counter": ks.id_counter,
        "is_empty": ks.entries.is_empty(), "len": ks.entries.len(), "removed_keys": ks.removed_keys})
}

fn error_text<T>(x: &Result<T, KeysError>) -> Value {
    x.as_ref().err().map_or(Value::Null, |e| e.to_string().into())
}

fn parse_case(r: &mut Run, c: &Value) {
    let mut ks = keystore::KeyStore::default();
    ks.save_removed = c["save_removed"] == true;
    let (res, logs) = logged(|| ks.parse(s(&c["text"])));
    r.eq("result", error_text(&res), &c["result"]);
    r.eq("logs", logs, &c["logs"]);
    r.eq("store", store_json(&ks), &c["store"]);
    r.eq("len", ks.len(), &c["store"]["len"]);
    r.eq("is_empty", ks.is_empty(), &c["store"]["is_empty"]);
    for l in c["lookups"].as_array().unwrap_or(&vec![]) {
        if let Some(v) = l.get("allowed_ip") {
            r.eq("allowed_ip", ks.allowed_ip(s(v)).map(|e| e.id.clone()), &l["id"]);
        } else if let Some(v) = l.get("allowed_id") {
            let e = ks.allowed_id(s(v));
            r.eq("allowed_id", e.map(|e| e.name.clone()), &l["id"]);
            r.eq("protocol", ks.net_protocol(s(v)).map(|p| format!("{p:?}")), &l["net_protocol"]);
        } else if let Some(v) = l.get("allowed_dynamic_id") {
            r.eq("dynamic", ks.allowed_dynamic_id(s(v), s(&l["srcip"])).map(|e| e.id.clone()), &l["id"]);
        } else {
            r.eq("allowed_name", ks.allowed_name(s(&l["allowed_name"])).map(|e| e.id.clone()), &l["id"]);
        }
    }
    if let Some(snap) = c.get("snapshot_first") {
        let n = ks.entries[0].snapshot();
        r.eq("snapshot", json!({"id": n.id, "ip": n.ip, "name": n.name, "peer": n.peer.map(|p| p.to_string())}), snap);
    }
    if let Some(w) = c.get("sockets") {
        let set = |v| ks.entries[0].state.lock().unwrap().sock = v;
        let get = || ks.entries[0].state.lock().unwrap().sock;
        set(5);
        r.eq("add_new", ks.add_socket(0, 5), &w["add_new"]);
        r.eq("add_again", ks.add_socket(0, 5), &w["add_again"]);
        r.eq("delete", ks.delete_socket(5), &w["delete"]);
        r.eq("sock after", get(), &w["sock_after_delete"]);
        r.eq("delete again", ks.delete_socket(5), &w["delete_again"]);
        set(9);
        ks.add_socket(0, 7);
        r.eq("delete other", ks.delete_socket(7), &w["delete_other_sock"]);
        r.eq("sock kept", get(), &w["sock_kept_when_different"]);
    }
}

fn read_case(r: &mut Run, c: &Value, dir: &Path) {
    let file = dir.join("read.keys");
    let path = file.to_string_lossy().into_owned();
    for x in c["cases"].as_array().unwrap() {
        let _ = fs::remove_file(&file);
        if let Some(t) = x["content"].as_str() {
            fs::write(&file, t).unwrap();
        }
        let (res, logs) = logged(|| keystore::KeyStore::read(&path, x["pass_empty_keyfile"] == true, true));
        r.eq("logs", logs, &x["logs"]);
        match res {
            Err(e) => r.eq("error", e.to_string().replace(&path, "<file>"), &x["result"]["error"]),
            Ok(ks) => {
                r.eq("ok", store_json(&ks), &x["result"]["ok"]);
                r.eq("file", ks.file == path, &x["result"]["file"]);
                r.eq("save_removed", ks.save_removed, &x["result"]["save_removed"]);
                r.eq("stamp", ks.stamp.is_some(), &x["result"]["stamp_set"]);
            }
        }
    }
}

fn reload_case(r: &mut Run, c: &Value, dir: &Path) {
    let file = dir.join("reload.keys");
    let path = file.to_string_lossy().into_owned();
    fs::write(&file, "001 a any k\n002 b 10.0.0.2 k\n003 c 10.0.0.3 k\n").unwrap();
    let old = keystore::KeyStore::read(&path, false, false).unwrap();
    for (i, e) in old.entries.iter().enumerate() {
        let mut st = e.state.lock().unwrap();
        st.rcvd = 100 + i as i64;
        st.sock = if i == 2 { -1 } else { 20 + i as i64 };
        st.peer = Some(format!("10.9.9.{i}:1514").parse().unwrap());
        st.post_startup = true;
        st.net_protocol = NetProtocol::Tcp;
        st.key.global_counter = 5;
    }
    r.eq("unchanged", old.needs_reload(), &c["needs_reload_unchanged"]);
    fs::write(&file, "001 a any k2\n002 b 10.0.0.22 k\n003 c 10.0.0.3 k\n004 d any k\n").unwrap();
    r.eq("changed", old.needs_reload(), &c["needs_reload_after_write"]);
    let new = old.reload(false).unwrap();
    r.eq("new", store_json(&new), &c["new"]);
    for m in c["socket_map_after"].as_array().unwrap() {
        r.eq("socket", new.delete_socket(m["delete_socket"].as_i64().unwrap()), &m["found"]);
    }
}

/// Answers `count` connections with the bytes the closure gives; returns the last request.
fn fake_service(count: usize, answer: impl Fn(usize, u8) -> Vec<u8> + Send + 'static) -> (String, thread::JoinHandle<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let t = thread::spawn(move || {
        let mut last = Vec::new();
        for n in 0..count {
            let (mut c, _) = l.accept().unwrap();
            let mut head = [0u8; 4];
            c.read_exact(&mut head).unwrap();
            let mut body = vec![0u8; u32::from_le_bytes(head) as usize];
            c.read_exact(&mut body).unwrap();
            c.write_all(&answer(n, body[0])).unwrap();
            last = [&head[..], &body[..]].concat();
        }
        last
    });
    (addr, t)
}

fn set_service(addr: &str, token: &str) {
    env::set_var("SIEM_KEYS_ADDR", addr);
    env::set_var("SIEM_KEYS_TOKEN", token);
}

fn clear_service() {
    env::remove_var("SIEM_KEYS_ADDR");
    env::remove_var("SIEM_KEYS_TOKEN");
}

fn platform_case(r: &mut Run, c: &Value) {
    let answer = unhex(s(&c["answer_hex"]));
    let (addr, server) = fake_service(1, move |_, _| answer.clone());
    set_service(&addr, s(&c["token"]));
    let got = platform_fetch(c["kind"].as_u64().unwrap() as u8);
    clear_service();
    r.eq("request", hex::encode(server.join().unwrap()), &c["request_hex"]);
    match got {
        Ok((version, text)) => r.eq("result", json!({"text": text, "version": version}), &c["result"]),
        Err(e) => r.eq("result", json!({"error": e}), &c["result"]),
    }
}

fn platform_read_case(r: &mut Run, c: &Value) {
    let reply = |body: &[u8]| [&(body.len() as u32).to_le_bytes()[..], body].concat();
    let (addr, server) = fake_service(3, move |n, _| match n {
        0 => reply(b"K3\n001 a any k\n"),
        1 => reply(b"V3\n"),
        _ => reply(b"V4\n"),
    });
    set_service(&addr, "tok");
    r.eq("source token", platform_source().map(|p| p.1), &c["platform_source"][1]);
    let ks = keystore::KeyStore::read("unused", false, false).unwrap();
    r.eq("store", store_json(&ks), &c["store"]);
    let st = ks.stamp.unwrap();
    r.eq("stamp", json!([st.mtime, st.inode]), &c["stamp"]);
    r.eq("same", ks.needs_reload(), &c["needs_reload_same_version"]);
    r.eq("new", ks.needs_reload(), &c["needs_reload_new_version"]);
    clear_service();
    server.join().unwrap();
}

/// One test: the key service is configured through process-wide environment variables.
#[test]
fn keystore() {
    let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Run::new("keystore");
    let dir = scratch("keystore");
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        match s(&c["fn"]) {
            "keystore::KeyStore::parse" => parse_case(&mut r, &c),
            "keystore::KeyStore::add_key" => {
                let mut ks = keystore::KeyStore::default();
                let ok = ks.add_key("010", "x", "10.0.0.1/8", "k", 1234);
                r.eq("first", ok.unwrap(), &c["results"][0]);
                let bad = ks.add_key("011", "y", "nope", "k", 0);
                r.eq("second", error_text(&bad), &c["results"][1]);
                r.eq("store", store_json(&ks), &c["store"]);
            }
            "keystore::KeyStore::read" => read_case(&mut r, &c, &dir),
            "keystore::KeyStore::reload" => reload_case(&mut r, &c, &dir),
            "keystore::platform_stamp" => {
                let f = dir.join("stamped");
                fs::write(&f, "x").unwrap();
                r.eq("missing", file_stamp(&dir.join("none").to_string_lossy()).is_none(), &c["file_stamp_missing"]);
                r.eq("some", file_stamp(&f.to_string_lossy()).is_some(), &c["file_stamp_of_file_is_some"]);
                let st = platform_stamp(c["version"].as_u64().unwrap());
                r.eq("mtime", st.mtime, &c["mtime"]);
                r.eq("inode", st.inode, &c["inode"]);
            }
            "constants" => {
                r.eq("KEYS_REQ", KEYS_REQ, &c["KEYS_REQ"]);
                r.eq("VERSION_REQ", VERSION_REQ, &c["VERSION_REQ"]);
                r.eq("UDP_SOCK", UDP_SOCK, &c["UDP_SOCK"]);
                r.eq("OS_MAXSTR", OS_MAXSTR, &c["OS_MAXSTR"]);
                r.eq("OS_HEADER_SIZE", OS_HEADER_SIZE, &c["OS_HEADER_SIZE"]);
                r.eq("MSG_OVERHEAD", MSG_OVERHEAD, &c["MSG_OVERHEAD"]);
                r.eq("SENDER_COUNTER", SENDER_COUNTER, &c["SENDER_COUNTER"]);
                let texts = [
                    KeysError::Open("F".into(), "E".into()).to_string(),
                    KeysError::InvalidIp("I".into()).to_string(),
                    KeysError::NoClientKeys.to_string(),
                ];
                r.eq("texts", json!(texts), &c["KeysError_texts"]);
                r.eq("KEYSIZE", KEYSIZE, &c["KEYSIZE"]);
            }
            "keystore::platform_fetch" => platform_case(&mut r, &c),
            "keystore::KeyStore::read via platform" => platform_read_case(&mut r, &c),
            _ => {
                set_service("", "tok");
                r.eq("empty addr", platform_source().map(|p| p.0), &c["addr_empty"]);
                r.eq("no service", platform_fetch(KEYS_REQ).unwrap_err(), &c["fetch_error"]);
                clear_service();
            }
        }
        r.done(format!("{n} {}", s(&c["fn"])));
    }
    r.finish();
}

fn method(v: &Value) -> CryptoMethod {
    if v == "Aes" {
        CryptoMethod::Aes
    } else {
        CryptoMethod::Blowfish
    }
}

fn check_read(r: &mut Run, key: &Value, raw: &str, wire: &[u8], x: &Value) {
    let mut k = ClientKey::new(s(&key["id"]).into(), s(&key["name"]).into(), "any".into(), raw.into());
    k.crypto_method = method(&x["key_method_before"]);
    k.global_counter = x["saved"][0].as_u64().unwrap() as u32;
    k.local_counter = x["saved"][1].as_u64().unwrap() as u32;
    let opts = ReadOptions { verify_counter: x["verify_counter"] == true, client: x["client"] == true };
    match read_sec_msg(&mut k, wire, opts) {
        Ok(m) => r.eq(
            "ok",
            json!({"global": m.global, "local": m.local, "payload": hex::encode(m.payload)}),
            &json!({"global": x["result"]["ok"]["global"], "local": x["result"]["ok"]["local"],
                "payload": x["result"]["ok"].get("payload").map(|p| hex::encode(data(p)))}),
        ),
        Err(e) => {
            r.eq("error", format!("{:?}", e.key_state()), &x["result"]["error"]);
            r.eq("reason", format!("{:?}", last_reject_reason()), &x["result"]["reason"]);
            // The wording is ours; the state name it ends with must still match.
            let state = s(&x["result"]["error_display"]).rsplit(' ').next().unwrap_or_default().to_string();
            r.eq("display", e.to_string().ends_with(&state), &json!(true));
        }
    }
    let after = json!({"global": k.global_counter, "local": k.local_counter, "method": format!("{:?}", k.crypto_method)});
    r.eq("key after", after, &x["key_after"]);
}

fn check_reads(r: &mut Run, c: &Value, wire: &[u8]) {
    check_reads_of(r, c, wire, true)
}

/// `exact`: the wire is the recorded one, so a wrong key's reject reason must match too; with
/// other bytes (another zlib engine) the junk a wrong key decrypts to fails a different check
/// first, so only the rejection itself counts.
fn check_reads_of(r: &mut Run, c: &Value, wire: &[u8], exact: bool) {
    let (key, raw) = (&c["key"], s(&c["key"]["raw_key"]));
    for x in c["reads"].as_array().unwrap_or(&vec![]) {
        match x.get("read") {
            Some(inner) if !exact => {
                let mut k = ClientKey::new(s(&key["id"]).into(), s(&key["name"]).into(), "any".into(), "wrongkey".into());
                k.crypto_method = method(&inner["key_method_before"]);
                let opts = ReadOptions { verify_counter: inner["verify_counter"] == true, client: inner["client"] == true };
                r.eq("wrong key rejected", read_sec_msg(&mut k, wire, opts).is_err(), &json!(true));
            }
            // The recorder used this raw key; with AES the reject reason depends on it (padding can pass).
            Some(inner) => check_read(r, key, "wrongkey", wire, inner),
            // read with the other cipher: junk too, so only the rejection counts on other bytes
            None if !exact && x["result"].get("error").is_some() => {
                let mut k = ClientKey::new(s(&key["id"]).into(), s(&key["name"]).into(), "any".into(), raw.into());
                k.crypto_method = method(&x["key_method_before"]);
                k.global_counter = x["saved"][0].as_u64().unwrap() as u32;
                k.local_counter = x["saved"][1].as_u64().unwrap() as u32;
                let opts = ReadOptions { verify_counter: x["verify_counter"] == true, client: x["client"] == true };
                r.eq("rejected", read_sec_msg(&mut k, wire, opts).is_err(), &json!(true));
            }
            None => check_read(r, key, raw, wire, x),
        }
    }
}

#[test]
fn msgs() {
    // it loads key files too: a key-service address set by another test would be used instead
    let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Run::new("msgs");
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        match s(&c["fn"]) {
            "create_sec_msg" => {
                let key = &c["key"];
                let mut k = ClientKey::new(s(&key["id"]).into(), s(&key["name"]).into(), "any".into(), s(&key["raw_key"]).into());
                k.crypto_method = method(&key["method"]);
                let before = &c["counter_before"];
                let mut counter = SenderCounter { global: before[0].as_u64().unwrap() as u32, local: before[1].as_u64().unwrap() as u32 };
                let dynamic = c["dynamic_prefix"] == true;
                let opts = CreateOptions { dynamic_prefix: dynamic, random: Some(c["random"].as_u64().unwrap() as u16) };
                match msgs::create_sec_msg_sized(&k, &mut counter, &data(&c["payload"]), opts) {
                    Err(e) => r.eq("error", json!({"error": e.to_string()}), &c["result"]),
                    Ok((wire, size)) => {
                        // Readers get the message with any "!<id>!" already removed.
                        let id_len = key["id"].as_str().unwrap().len();
                        let body = |w: &[u8]| if dynamic { w[id_len + 2..].to_vec() } else { w.to_vec() };
                        let got = json!({"cmp_size": size, "wire_hex": hex::encode(&wire)});
                        let want = &c["result"];
                        // Another zlib engine (Cargo unifies flate2's features when siem-api is in the
                        // same build) compresses to other bytes: then both messages must read back.
                        if &got != want && want["wire_hex"].is_string() {
                            check_reads(&mut r, &c, &body(&unhex(s(&want["wire_hex"]))));
                            check_reads_of(&mut r, &c, &body(&wire), false);
                        } else {
                            r.eq("wire", got, want);
                            check_reads(&mut r, &c, &body(&wire));
                        }
                    }
                }
                r.eq("counter", json!([counter.global, counter.local]), &c["counter_after"]);
            }
            "read_sec_msg hostile" => check_reads(&mut r, &c, &unhex(s(&c["wire_hex"]))),
            _ => {
                for x in c["cases"].as_array().unwrap() {
                    let mut sc = SenderCounter {
                        global: x["start"][0].as_u64().unwrap() as u32,
                        local: x["start"][1].as_u64().unwrap() as u32,
                    };
                    let steps: Vec<Value> = (0..3)
                        .map(|_| {
                            sc.next();
                            json!([sc.global, sc.local])
                        })
                        .collect();
                    r.eq("next", steps, &x["after_each_next"]);
                }
            }
        }
        r.done(format!("{n} {}", s(&c["label"])));
    }
    r.finish();
}

#[test]
fn counters() {
    let mut r = Run::new("counters");
    let root = scratch("counters");
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        let dir = root.join(n.to_string());
        fs::create_dir_all(&dir).unwrap();
        let name = s(&c["fn"]).to_string();
        let pair = |p: (u32, u32)| json!([p.0, p.1]);
        if name.starts_with("CounterStore::load / start_agent") {
            fs::write(dir.join("009"), s(&c["file_content"])).unwrap();
            let store = CounterStore::new(&dir, 0);
            r.eq("load", pair(store.load("009")), &c["load"]);
            let mut k = ClientKey::new("009".into(), "n".into(), "any".into(), "k".into());
            store.start_agent(&mut k);
            r.eq("start", json!([k.global_counter, k.local_counter]), &c["start_agent"]);
            r.eq("parse", parse_counter(s(&c["file_content"])).map_or(Value::Null, pair), &c["parse_counter"]);
        } else if name.starts_with("SenderCounterFile::open + store") {
            let f = dir.join("sc");
            fs::write(&f, s(&c["file_content_before"])).unwrap();
            let (mut file, got) = SenderCounterFile::open(&f).unwrap();
            r.eq("opened", json!([got.global, got.local]), &c["opened_counter"]);
            file.store(&SenderCounter { global: 1, local: 2 });
            drop(file);
            r.eq("after", hex::encode(fs::read(&f).unwrap()), &c["file_after_hex"]);
        } else if name.starts_with("SenderCounterFile::open missing") {
            let f = dir.join("sc");
            let (mut file, got) = SenderCounterFile::open(&f).unwrap();
            r.eq("opened", json!([got.global, got.local]), &c["opened_counter"]);
            r.eq("created", hex::encode(fs::read(&f).unwrap()), &c["created_content_hex"]);
            file.store(&SenderCounter { global: 123456, local: 789 });
            file.store(&SenderCounter { global: 1, local: 2 });
            drop(file);
            r.eq("after", fs::read_to_string(&f).unwrap(), &c["file_after"]);
        } else if name == "CounterStore::load missing" {
            let store = CounterStore::new(&dir, 0);
            r.eq("load", pair(store.load("none")), &c["load"]);
            let sender = store.load_sender();
            r.eq("sender", json!([sender.global, sender.local]), &c["load_sender"]);
        } else if name.starts_with("CounterStore::store") {
            let sub = dir.join("new").join("dir");
            let store = CounterStore::new(&sub, 0);
            r.eq("dir", store.dir() == sub, &c["dir_is_given"]);
            store.store("009", 7, 42).unwrap();
            store.store_sender(&SenderCounter { global: 3, local: 4 }).unwrap();
            r.eq("file", fs::read_to_string(sub.join("009")).unwrap(), &c["file_009"]);
            r.eq("sender", fs::read_to_string(sub.join(SENDER_COUNTER)).unwrap(), &c["file_sender_counter"]);
        } else if name == "CounterStore::on_received" {
            let mut store = CounterStore::new(&dir, c["recv_flush"].as_u64().unwrap() as u32);
            let mut k = ClientKey::new("001".into(), "n".into(), "any".into(), "k".into());
            for st in c["steps"].as_array().unwrap() {
                k.global_counter = st["counters"][0].as_u64().unwrap() as u32;
                k.local_counter = st["counters"][1].as_u64().unwrap() as u32;
                store.on_received(&k).unwrap();
                r.eq("file", fs::read_to_string(dir.join("001")).ok(), &st["file"]);
            }
        } else {
            let store = CounterStore::new(&dir, 0);
            store.store("009", 1, 2).unwrap();
            store.remove("009").unwrap();
            r.eq("existing", true, &c["existing"]);
            r.eq("exists after", dir.join("009").exists(), &c["exists_after"]);
            r.eq("missing ok", store.remove("009").is_ok(), &c["missing_ok"]);
        }
        r.done(format!("{n} {name}"));
    }
    r.finish();
}

#[test]
fn signature() {
    use provigil_crypto::signature::*;
    let mut r = Run::new("signature");
    let dir = scratch("signature");
    let sig: Vec<u8> = (0..=255u8).collect();
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        if c.get("missing_file").is_some() {
            r.eq("magic", String::from_utf8_lossy(WPK_MAGIC).into_owned(), &c["WPK_MAGIC"]);
            r.eq("len", WPK_SIGNATURE_LEN, &c["WPK_SIGNATURE_LEN"]);
            let got = read_wpk_header(dir.join("none"));
            r.eq("missing", matches!(got, Err(SignatureError::Io(_))), &json!(true));
            r.done("constants");
            continue;
        }
        let bytes: Vec<u8> = match s(&c["file"]) {
            "magic + NUL + 256 + payload" => [&b"WPK256\0"[..], &sig, b"payload"].concat(),
            "magic + 256 + payload (no NUL)" => [&b"WPK256"[..], &sig, b"payload"].concat(),
            "magic + NUL + 255" => [&b"WPK256\0"[..], &sig[..255]].concat(),
            "magic only" => b"WPK256".to_vec(),
            "bad magic" => b"XPK256".to_vec(),
            "short" => b"WPK".to_vec(),
            "empty" => Vec::new(),
            "lower case magic" => [&b"wpk256\0"[..], &sig].concat(),
            other => panic!("unknown file {other}"),
        };
        r.eq("length", bytes.len(), &c["file_hex_len"]);
        let f = dir.join("pkg.wpk");
        fs::write(&f, &bytes).unwrap();
        let got = match read_wpk_header(&f) {
            Ok(h) => json!({"certificate_len": h.certificate_der.len(), "content_offset": h.content_offset,
                "signature_hex": hex::encode(h.signature)}),
            Err(e) => json!({"display": e.to_string(),
                "error": format!("{e:?}").split('(').next().unwrap_or_default().to_string()}),
        };
        r.eq("result", got, &c["result"]);
        r.done(n);
    }
    r.finish();
}

// ---- Review fixes 1-13: one test each, input -> output. ----

/// The key service is configured through process-wide environment variables.
static ENV: Mutex<()> = Mutex::new(());

#[test]
fn fix01_root_reexports() {
    use provigil_crypto as c;
    assert_eq!(c::md5_file(env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml").unwrap().len(), 32);
    assert_eq!(c::sha256_str("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(c::os_aes_str(&c::encrypt_aes(b"x", b"k", c::PROVIGIL_AES_IV), "k", false).unwrap(), b"x");
    assert_eq!(c::PROVIGIL_BLOWFISH_IV.len(), 8);
    assert_eq!(c::derive_encryption_key("n", "1", "k").len(), 47);
    let _: Option<(c::CounterStore, c::MsgError, c::ReadResult, c::WpkHeader)> = None;
    assert_eq!((c::WPK_MAGIC, c::WPK_SIGNATURE_LEN), (b"WPK256", 256));
    assert!(matches!(c::read_wpk_header("none.wpk"), Err(c::SignatureError::Io(_))));
}

#[test]
fn fix02_hashes() {
    let dir = scratch("fix02");
    let f = dir.join("f");
    fs::write(&f, "abc").unwrap();
    assert_eq!(hex::encode(sha1_bytes(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(sha512_str("").len(), 128);
    assert_eq!(sha256_file(&f).unwrap(), sha256_str("abc"));
    let fox = "The quick brown fox jumps over the lazy dog";
    assert_eq!(hmac_sha1_str("key", fox).unwrap(), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    assert_eq!(hmac_sha1_str("", "").unwrap(), "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");
    assert!(multi_hash_file(&f, 3).is_ok(), "equal size is fine");
    let e = multi_hash_file(&f, 2).unwrap_err();
    assert_eq!((e.kind(), e.to_string()), (io::ErrorKind::InvalidData, "File size exceeded max allowed size of 2 bytes".into()));
}

#[test]
fn fix03_non_utf8_client_keys_fail() {
    let dir = scratch("fix03");
    let f = dir.join("client.keys");
    fs::write(&f, b"001 a any k\n002 \xff any k\n").unwrap();
    assert_eq!(Keys::load_file(&f).unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn fix04_small_lookups() {
    let mut ks = Keys::new();
    assert!(ks.is_empty());
    ks.add_key(ClientKey::new("001".into(), "a".into(), "any".into(), "k".into()));
    ks.find_by_id_mut("001").unwrap().global_counter = 9;
    assert_eq!(ks.keys[0].global_counter, 9);

    let mut table = keystore::KeyStore::default();
    assert!(table.is_empty());
    table.parse("001 web any k\n002 web any k\n003 db any k\n").unwrap();
    assert_eq!(table.len(), 3);
    assert_eq!(table.allowed_name("web").unwrap().id, "001", "first in table order");
    assert!(table.allowed_name("none").is_none());

    let dir = scratch("fix04");
    let store = CounterStore::new(&dir, 0);
    store.store("009", 1, 2).unwrap();
    store.remove("009").unwrap();
    assert!(!dir.join("009").exists());
    assert!(store.remove("009").is_ok(), "missing file is fine");
    fs::create_dir(dir.join("dir")).unwrap();
    assert!(store.remove("dir").is_err(), "other errors are returned");
}

#[test]
fn fix05_keysize() {
    assert_eq!(KEYSIZE, 128);
    let mut table = keystore::KeyStore::default();
    table.parse(&format!("{} n any k\n", "7".repeat(200))).unwrap();
    assert_eq!(table.entries[0].id.len(), KEYSIZE - 1);
}

#[test]
fn fix06_log_shows_id_before_the_cut() {
    let long = "1".repeat(200);
    let mut table = keystore::KeyStore::default();
    let (_, logs) = logged(|| table.parse(&format!("{long} onlyname\n")));
    assert_eq!(logs, json!([["ERROR", format!("(1401): Error reading authentication key: '{long}'.")]]));
}

#[test]
fn fix07_key_service_waits_after_every_failure() {
    let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
    set_service(&free, "tok");
    let start = std::time::Instant::now();
    let got = keystore::KeyStore::read("unused", false, false);
    clear_service();
    let waited = start.elapsed();
    assert!(waited >= std::time::Duration::from_secs(30), "30 waits of 1 s, the last included: {waited:?}");
    assert!(error_text(&got).as_str().unwrap().starts_with("(1103): Could not open file 'the platform's key service': "));
}

#[test]
fn fix08_cipher_error_texts() {
    let e = encrypt_blowfish(b"x", b"abc", b"").unwrap_err();
    assert_eq!(e.to_string(), "Encryption error: InvalidLength");
    assert_eq!(decrypt_blowfish(b"12345678", b"abc", b"").unwrap_err().to_string(), "Decryption error: InvalidLength");
    assert_eq!(CipherError::InvalidKeyLength { expected: 4, got: 3 }.to_string(), "Invalid key length: expected at least 4, got 3");
    let mut k = ClientKey::new("1".into(), "a".into(), "any".into(), "k".into());
    k.encryption_key = "abc".into();
    let e = create_sec_msg(&k, &mut SenderCounter::default(), b"m", CreateOptions::default()).unwrap_err();
    assert_eq!(e.to_string(), "Encryption failed: Encryption error: InvalidLength");
}

/// A legacy (uncompressed) Blowfish message for `body` (the text from offset 33 on).
fn legacy_wire(key: &ClientKey, body: &[u8]) -> Vec<u8> {
    let mut plain = [&b":"[..], &[b'0'; 32], body].concat();
    plain.resize(plain.len().div_ceil(8) * 8, 0);
    // The checksum covers offset 33 up to 1 + size, zero bytes past the text included.
    let region = [&plain[33..], &[0u8]].concat();
    plain[1..33].copy_from_slice(hex::encode(md5_bytes(&region)).as_bytes());
    [&b":"[..], &os_bf_str(&plain, &key.encryption_key, true).unwrap()].concat()
}

#[test]
fn fix09_legacy_nul_before_offset_49_does_not_end_the_text() {
    let mut k = ClientKey::new("001".into(), "a".into(), "any".into(), "k".into());
    // offsets: 33 time, 43 ':', 44 count (NUL at 46), 48 ':', 49 'x', 50 ':', 51 payload
    let wire = legacy_wire(&k, b"1700000000:00\x002:x:hello");
    let got = read_sec_msg(&mut k, &wire, ReadOptions::default()).unwrap();
    assert_eq!((got.payload.as_slice(), got.global), (&b"hello"[..], 1700000000));
}

#[test]
fn fix10_failed_flush_is_retried() {
    let dir = scratch("fix10");
    let blocked = dir.join("counters");
    fs::write(&blocked, "a file, not a directory").unwrap();
    let mut store = CounterStore::new(&blocked, 2);
    let k = ClientKey::new("001".into(), "a".into(), "any".into(), "k".into());
    store.on_received(&k).unwrap();
    store.on_received(&k).unwrap();
    assert!(store.on_received(&k).is_err(), "third call writes and fails");
    fs::remove_file(&blocked).unwrap();
    store.on_received(&k).unwrap();
    assert!(blocked.join("001").exists(), "the next call writes again");
}

#[test]
fn fix11_sender_counter_file() {
    let dir = scratch("fix11");
    let f = dir.join("sc");
    fs::write(&f, b"7:42\xff").unwrap();
    assert_eq!(SenderCounterFile::open(&f).unwrap().1, SenderCounter::default(), "not UTF-8: 0:0");
    let missing = dir.join("new");
    assert_eq!(SenderCounterFile::open(&missing).unwrap().1, SenderCounter::default());
    assert!(missing.exists(), "created");
    let e = SenderCounterFile::open(dir.join("no/such/dir/sc")).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound, "only the create error is returned");
}

#[test]
fn fix12_parse_counter_unicode_space() {
    assert_eq!(parse_counter("\u{2003}7:\u{a0}42"), Some((7, 42)));
    assert_eq!(parse_counter("\u{3000}+5:\u{2028}6"), Some((5, 6)));
}

#[test]
fn fix13_wpk_header() {
    let dir = scratch("fix13");
    let f = dir.join("p.wpk");
    let sig: Vec<u8> = (1..=255u8).chain([7]).collect();
    fs::write(&f, [&b"WPK256"[..], &sig, b"data"].concat()).unwrap();
    let h = provigil_crypto::read_wpk_header(&f).unwrap();
    assert_eq!((h.content_offset, h.signature, h.certificate_der.len()), (262, sig, 0));
}

// ---- Review round 2 ----

#[test]
fn r2_1_blowfish_length_checked_before_key() {
    let length = "Decryption error: Data length must be multiple of 8";
    assert_eq!(decrypt_blowfish(b"1234567", b"abc", b"").unwrap_err().to_string(), length, "bad length and bad key");
    assert_eq!(decrypt_blowfish(b"1234567", b"abcd", b"").unwrap_err().to_string(), length);
    assert_eq!(decrypt_blowfish(b"12345678", b"abc", b"").unwrap_err().to_string(), "Decryption error: InvalidLength");
}

#[test]
fn r2_2_multi_hash_limit_is_usize() {
    let dir = scratch("r2_2");
    let f = dir.join("f");
    fs::write(&f, "abcd").unwrap();
    let limit: usize = 4;
    assert!(multi_hash_file(&f, limit).is_ok());
    assert_eq!(multi_hash_file(&f, limit - 1).unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn r2_3_wpk_error_kinds() {
    use provigil_crypto::SignatureError;
    assert_eq!(SignatureError::IncompleteHeader.to_string(), "Incomplete WPK signature or header");
    assert_eq!(SignatureError::VerificationFailed.to_string(), "Signature verification failed");
}
