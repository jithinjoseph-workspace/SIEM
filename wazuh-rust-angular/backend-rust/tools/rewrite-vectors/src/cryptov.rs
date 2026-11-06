use crate::{h, logs, Out, Rng};
use serde_json::{json, Value};
use siem_crypto::ciphers::*;
use siem_crypto::hashes::*;
use siem_crypto::keys::{derive_encryption_key, ClientKey, CryptoMethod};
use siem_crypto::keystore;
use siem_crypto::msgs::*;
use std::path::Path;

const K: &str = "siem-crypto";

/// A byte input, written short when it is one repeated byte.
fn inp(b: &[u8]) -> Value {
    if b.len() > 512 && b.iter().all(|&x| x == b[0]) {
        json!({"repeat_hex": h(&b[..1]), "times": b.len()})
    } else {
        json!({"hex": h(b)})
    }
}

fn io_err(e: &std::io::Error) -> Value {
    json!({"error_kind": format!("{:?}", e.kind()), "display": e.to_string()})
}

pub fn run(out: &Out, work: &Path) -> usize {
    let mut n = 0;
    let mut r = Rng::new(0x5EED_0002);
    n += hashes(out, work, &mut r);
    n += ciphers(out, &mut r);
    n += keys(out, work);
    n += keystore_v(out, work);
    n += msgs(out, &mut r);
    n += counters(out, work);
    n += signature(out, work);
    n
}

fn hash_inputs(r: &mut Rng) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![vec![], b"a".to_vec(), b"abc".to_vec(), b"hello wazuh".to_vec(), b"\xff\xfe\x00\x80".to_vec(), "é€".as_bytes().to_vec()];
    for n in [1usize, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127, 128, 129, 4095, 4096, 4097, 8191, 8192, 8193, 16384] {
        v.push((0..n).map(|i| (i * 31 % 251) as u8).collect());
    }
    for _ in 0..60 {
        v.push(r.bytes(&(0..=255u8).collect::<Vec<_>>(), 300));
    }
    v.push(vec![b'a'; 1_000_000]);
    v
}

fn hashes(out: &Out, work: &Path, r: &mut Rng) -> usize {
    let mut cases = Vec::new();
    for (i, b) in hash_inputs(r).iter().enumerate() {
        let f = work.join(format!("hash{i}"));
        std::fs::write(&f, b).unwrap();
        let mut c = json!({"input": inp(b),
            "md5_bytes": h(&md5_bytes(b)), "sha1_bytes": h(&sha1_bytes(b)), "sha256_bytes": h(&sha256_bytes(b)), "sha512_bytes": h(&sha512_bytes(b)),
            "md5_file": md5_file(&f).unwrap(), "sha1_file": sha1_file(&f).unwrap(), "sha256_file": sha256_file(&f).unwrap(), "sha512_file": sha512_file(&f).unwrap()});
        if let Ok(s) = std::str::from_utf8(b) {
            c["md5_str"] = json!(md5_str(s));
            c["sha1_str"] = json!(sha1_str(s));
            c["sha256_str"] = json!(sha256_str(s));
            c["sha512_str"] = json!(sha512_str(s));
        }
        let len = b.len();
        let mut mh = Vec::new();
        for max in [0usize, len.saturating_sub(1), len, len + 1, 1] {
            mh.push(json!({"max_size": max, "result": match multi_hash_file(&f, max) { Ok((a, b2, c2)) => json!([a, b2, c2]), Err(e) => io_err(&e) }}));
        }
        c["multi_hash_file"] = json!(mh);
        for key in ["", "k", "secret-key", &"K".repeat(64), &"K".repeat(65), &"é".repeat(40)] {
            if let Ok(s) = std::str::from_utf8(b) {
                if s.len() < 400 {
                    c[format!("hmac_sha1_str key={}", key.len())] = json!(hmac_sha1_str(key, s).unwrap());
                }
            }
            c[format!("hmac_sha1_file key={}", key.len())] = json!(hmac_sha1_file(key, &f).unwrap());
        }
        cases.push(c);
        let _ = std::fs::remove_file(&f);
    }
    let missing = work.join("no-such-file");
    cases.push(json!({"missing_file": true,
        "md5_file": io_err(&md5_file(&missing).unwrap_err()), "sha1_file": io_err(&sha1_file(&missing).unwrap_err()),
        "sha256_file": io_err(&sha256_file(&missing).unwrap_err()), "sha512_file": io_err(&sha512_file(&missing).unwrap_err()),
        "multi_hash_file": io_err(&multi_hash_file(&missing, 0).unwrap_err()), "hmac_sha1_file": io_err(&hmac_sha1_file("k", &missing).unwrap_err())}));
    out.write(K, "hashes", "Digests (lower-case hex) of each input via the bytes / str / file functions; multi_hash_file with several max sizes; HMAC-SHA1 with keys of the given byte length (key text: '', 'k', 'secret-key', 64 x 'K', 65 x 'K', 40 x 'é')", cases)
}

fn cerr(e: &CipherError) -> Value {
    json!({"error": match e { CipherError::InvalidKeyLength { .. } => "invalid_key_length", CipherError::Encryption(_) => "encryption", CipherError::Decryption(_) => "decryption" }})
}

fn ciphers(out: &Out, r: &mut Rng) -> usize {
    let mut cases = Vec::new();
    let key = |n: usize| -> Vec<u8> { (0..n).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect() };
    let pt = |n: usize| -> Vec<u8> { (0..n).map(|i| b"abcdefghijklmnopqrstuvwxyz0123456789"[i % 36]).collect() };
    for kl in [0usize, 1, 16, 31, 32, 33, 47, 64] {
        for iv in [vec![], key(8), PROVIGIL_AES_IV.to_vec(), key(16), key(20)] {
            for pl in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
                let k = key(kl);
                let p = pt(pl);
                let c = encrypt_aes(&k, &iv, &p);
                let mut v = json!({"fn": "aes", "key_hex": h(&k), "iv_hex": h(&iv), "plain_hex": h(&p),
                    "encrypt": match &c { Ok(x) => json!({"hex": h(x)}), Err(e) => cerr(e) }});
                if let Ok(ct) = c {
                    let mut dec = Vec::new();
                    let mut muts: Vec<(&str, Vec<u8>)> = vec![("as is", ct.clone()), ("empty", vec![]), ("drop last byte", ct[..ct.len() - 1].to_vec()), ("first block only", ct[..16].to_vec())];
                    let mut f = ct.clone();
                    *f.last_mut().unwrap() ^= 0x01;
                    muts.push(("flip last byte", f));
                    let mut f = ct.clone();
                    f[0] ^= 0x80;
                    muts.push(("flip first byte", f));
                    let mut f = ct.clone();
                    f.extend_from_slice(&[0u8; 16]);
                    muts.push(("extra zero block", f));
                    for (what, m) in muts {
                        dec.push(json!({"input": what, "input_hex": h(&m), "result": match decrypt_aes(&k, &iv, &m) { Ok(x) => json!({"hex": h(&x)}), Err(e) => cerr(&e) }}));
                    }
                    v["decrypt"] = json!(dec);
                }
                cases.push(v);
            }
        }
    }
    for kl in [0usize, 1, 3, 4, 5, 8, 16, 47, 56, 57, 64] {
        for iv in [vec![], key(4), PROVIGIL_BLOWFISH_IV.to_vec(), key(8), key(10)] {
            for pl in [0usize, 1, 7, 8, 9, 16, 17, 64] {
                let k = key(kl);
                let p = pt(pl);
                let c = encrypt_blowfish(&k, &iv, &p);
                let mut v = json!({"fn": "blowfish", "key_hex": h(&k), "iv_hex": h(&iv), "plain_hex": h(&p),
                    "encrypt": match &c { Ok(x) => json!({"hex": h(x)}), Err(e) => cerr(e) }});
                let mut dec = Vec::new();
                let src = c.as_ref().map(|x| x.clone()).unwrap_or_else(|_| p.clone());
                for m in [src.clone(), src.iter().chain([1u8, 2, 3].iter()).copied().collect::<Vec<_>>(), vec![]] {
                    dec.push(json!({"input_hex": h(&m), "result": match decrypt_blowfish(&k, &iv, &m) { Ok(x) => json!({"hex": h(&x)}), Err(e) => cerr(&e) }}));
                }
                v["decrypt"] = json!(dec);
                cases.push(v);
            }
        }
    }
    for charkey in ["", "short", "01234567890123456789012345678901", "a1b2c3d4e5f60718293a4b5c6d7e8f9046c4c2f5ab1e2d3", &"z".repeat(60), "é"] {
        for _ in 0..4 {
            let p = r.bytes(&(0..=255u8).collect::<Vec<_>>(), 40);
            let ea = os_aes_str(&p, charkey, true);
            let eb = os_bf_str(&p, charkey, true);
            cases.push(json!({"fn": "os_str", "charkey": charkey, "plain_hex": h(&p),
                "aes_encrypt": match &ea { Ok(x) => json!({"hex": h(x)}), Err(e) => cerr(e) },
                "aes_decrypt_of_that": ea.as_ref().ok().map(|x| match os_aes_str(x, charkey, false) { Ok(y) => json!({"hex": h(&y)}), Err(e) => cerr(&e) }),
                "bf_encrypt": match &eb { Ok(x) => json!({"hex": h(x)}), Err(e) => cerr(e) },
                "bf_decrypt_of_that": eb.as_ref().ok().map(|x| match os_bf_str(x, charkey, false) { Ok(y) => json!({"hex": h(&y)}), Err(e) => cerr(&e) })}));
        }
    }
    out.write(K, "ciphers", "AES-256-CBC (encrypt_aes/decrypt_aes) and Blowfish-CBC (encrypt_blowfish/decrypt_blowfish) with the given key/iv bytes, plus decrypts of mutated ciphertext; os_aes_str/os_bf_str with a text key and the fixed IVs", cases)
}

fn ck_json(k: &ClientKey) -> Value {
    json!({"id": k.id, "name": k.name, "ip": k.ip, "raw_key": k.raw_key, "encryption_key": k.encryption_key,
           "crypto_method": format!("{:?}", k.crypto_method), "global_counter": k.global_counter, "local_counter": k.local_counter, "key_line": k.to_key_line()})
}

fn keys(out: &Out, work: &Path) -> usize {
    use siem_crypto::keys::KeyStore;
    let mut cases = Vec::new();
    for (name, id, raw) in [
        ("agent-001", "001", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"),
        ("agent1", "001", "supersecretkey123456789"),
        ("", "", ""),
        ("web-server-01", "1234", "k"),
        ("é", "007", "ключ"),
        ("manager", "000", "3c2f6e9a1b8d4e7f0a5c2b9d8e1f4a7b6c3d0e9f8a7b6c5d4e3f2a1b0c9d8e7f"),
    ] {
        cases.push(json!({"fn": "derive_encryption_key", "name": name, "id": id, "raw_key": raw, "result": derive_encryption_key(name, id, raw),
            "client_key_new": ck_json(&ClientKey::new(id.into(), name.into(), "any".into(), raw.into()))}));
    }
    let lines = [
        "005 server-ny 10.0.0.5 8e7d6c5b4a3928170f1e2d3c4b5a6978",
        "005 server-ny 10.0.0.5",
        "005\tserver-ny\t10.0.0.5\tkey\textra",
        "  001   a   any   k  ",
        "",
        "# 001 a any k",
        "001 !removed any k",
        "001 a any k\r",
    ];
    for l in lines {
        cases.push(json!({"fn": "KeyStore::parse_line", "line": l, "result": KeyStore::parse_line(l).as_ref().map(ck_json)}));
    }
    let files = [
        "001 web01 any 5c6f\n002 db01 10.0.0.5 0123\n",
        "# comment\n\n   \n001 a any k\n#002 b any k\n003 c 1.2.3.4 k3 extra\nbad line\n",
        "001 a any k\r\n002 b any k\r\n",
        "001 a any k1\n001 b 1.1.1.1 k2\n",
        "009 a any k\n010 b any k\nabc c any k\n",
        "",
        "001 a any k\n002 b any k\n003 !removed any k\n",
        "1 a 10.0.0.1 k\n2 b 10.0.0.1 k\n",
    ];
    for (i, text) in files.iter().enumerate() {
        let f = work.join(format!("keys{i}"));
        std::fs::write(&f, text).unwrap();
        let mut ks = KeyStore::load_file(&f).unwrap();
        let mut v = json!({"fn": "KeyStore::load_file", "content": text, "keys": ks.keys.iter().map(ck_json).collect::<Vec<_>>(), "len": ks.len(), "is_empty": ks.is_empty(), "next_id": ks.next_id()});
        let mut look = Vec::new();
        for q in ["001", "002", "003", "009", "010", "abc", "1", "x"] {
            look.push(json!({"find_by_id": q, "result_name": ks.find_by_id(q).map(|k| k.name.clone())}));
        }
        for q in ["a", "b", "c", "removed", "!removed"] {
            look.push(json!({"find_by_name": q, "result_id": ks.find_by_name(q).map(|k| k.id.clone())}));
        }
        for q in ["any", "10.0.0.5", "10.0.0.1", "1.1.1.1", "1.2.3.4"] {
            look.push(json!({"find_by_ip": q, "result_id": ks.find_by_ip(q).map(|k| k.id.clone())}));
        }
        v["lookups"] = json!(look);
        let mut del = Vec::new();
        for q in ["001", "001", "002", "nope"] {
            let d = ks.delete_key(q);
            del.push(json!({"delete_key": q, "removed": d.as_ref().map(ck_json), "keys_after": ks.keys.iter().map(|k| k.id.clone()).collect::<Vec<_>>(),
                "find_by_id_001_after": ks.find_by_id("001").map(|k| k.name.clone())}));
        }
        v["deletes"] = json!(del);
        if let Some(k) = ks.find_by_id_mut("003") {
            k.local_counter = 9;
        }
        let saved = work.join(format!("keys{i}.saved"));
        ks.save_file(&saved).unwrap();
        v["save_file_after_deletes"] = json!(String::from_utf8_lossy(&std::fs::read(&saved).unwrap()));
        cases.push(v);
    }
    cases.push(json!({"fn": "KeyStore::load_file", "missing": true, "result": io_err(&KeyStore::load_file(work.join("missing")).unwrap_err())}));
    let mut ks = KeyStore::new();
    let mut ids = Vec::new();
    for id in ["001", "1000", "abc", "007", "0099"] {
        ks.add_key(ClientKey::new(id.into(), format!("n{id}"), "any".into(), "k".into()));
        ids.push(json!({"added": id, "next_id": ks.next_id()}));
    }
    cases.push(json!({"fn": "KeyStore::next_id sequence (empty store gives)", "empty_next_id": KeyStore::new().next_id(), "steps": ids}));
    let g = KeyStore::generate_raw_key();
    assert!(g.len() == 64 && g.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    cases.push(json!({"fn": "KeyStore::generate_raw_key", "shape": "64 lower-case hex characters (32 random bytes)", "example": g}));
    out.write(K, "keys", "keys module: derive_encryption_key, ClientKey::new, KeyStore (client.keys lines) parse_line / load_file / lookups / delete_key / save_file / next_id / generate_raw_key", cases)
}

fn entry_json(e: &keystore::KeyEntry) -> Value {
    let st = e.state.lock().unwrap();
    json!({"keyid": e.keyid, "id": e.id, "name": e.name, "ip_str": e.ip_str, "ip_text": e.ip.ip, "ip_is_ipv6": e.ip.is_ipv6,
        "is_single_host": e.is_single_host(), "raw_key": e.raw_key, "time_added": e.time_added,
        "state": {"rcvd": st.rcvd, "sock": st.sock, "net_protocol": format!("{:?}", st.net_protocol), "peer": st.peer.map(|p| p.to_string()), "post_startup": st.post_startup, "key": ck_json(&st.key)}})
}

fn ks_json(ks: &keystore::KeyStore) -> Value {
    json!({"entries": ks.entries.iter().map(|e| entry_json(e)).collect::<Vec<_>>(), "id_counter": ks.id_counter, "removed_keys": ks.removed_keys, "len": ks.len(), "is_empty": ks.is_empty()})
}

fn keystore_v(out: &Out, work: &Path) -> usize {
    use keystore::KeyStore;
    std::env::remove_var("SIEM_KEYS_ADDR");
    std::env::remove_var("SIEM_KEYS_TOKEN");
    let mut cases = Vec::new();
    let texts = [
        "001 web01 any 5c6f\n002 db01 10.0.0.5 0123\n003 !removed any deadbeef\n# comment\n004 net 192.168.0.0/24 cafebabe\n",
        "001 a any k\n002 b 999.1.1.1 k\n003 c any k\n",
        "noseparator\n001 onlyname\n001 name ip-without-key\n005 n 10.0.0.1 k\n",
        " 001 a any k\n#002 b any k\n003 #c any k\n004 !d any k\n",
        "001 a any k\r\n002 b 10.0.0.2 k2\r\n",
        "001 a any k\n001 b 10.0.0.9 k2\n002 c 10.0.0.9 k3\n",
        "001 a 2001:db8::1 k\n002 b ::ffff:10.0.0.7 k\n003 c 10.0.0.0/255.0.0.0 k\n004 d 2001:db8::/32 k\n005 e !10.0.0.1 k\n",
        "abc a any k\n0042 b any k\n-5 c any k\n99999999999 d any k\n",
        "001 a any k with spaces in key\n002  double any k\n",
        "",
        "001 a any k",
        &format!("{} n any k\n002 {} any k\n003 x any {}\n", "9".repeat(200), "N".repeat(200), "K".repeat(200)),
        "001 é any κλειδί\n",
        "001 a any\n",
        "001 a any \n",
    ];
    for t in texts {
        for save_removed in [false, true] {
            let mut ks = KeyStore::default();
            ks.save_removed = save_removed;
            let res = ks.parse(t);
            let lg = logs();
            let mut v = json!({"fn": "keystore::KeyStore::parse", "text": t, "save_removed": save_removed, "result": res.as_ref().err().map(|e| e.to_string()), "store": ks_json(&ks), "logs": lg});
            let mut look = Vec::new();
            for q in ["any", "10.0.0.5", "192.168.0.0", "192.168.0.0/24", "10.0.0.9", "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1", "10.0.0.7", "10.0.0.0"] {
                look.push(json!({"allowed_ip": q, "id": ks.allowed_ip(q).map(|e| e.id.clone())}));
            }
            for q in ["001", "002", "003", "004", "005", "0042", "abc", "x"] {
                look.push(json!({"allowed_id": q, "id": ks.allowed_id(q).map(|e| e.name.clone()), "net_protocol": ks.net_protocol(q).map(|p| format!("{p:?}"))}));
            }
            for q in ["a", "b", "c", "web01", "removed"] {
                look.push(json!({"allowed_name": q, "id": ks.allowed_name(q).map(|e| e.id.clone())}));
            }
            for (id, ip) in [("001", "8.8.8.8"), ("004", "192.168.0.77"), ("004", "192.168.1.77"), ("002", "10.0.0.5"), ("002", "10.0.0.6"), ("003", "10.200.0.1"), ("004", "2001:db8:5::1"), ("005", "10.0.0.1"), ("005", "10.0.0.2"), ("x", "1.1.1.1"), ("001", "not-an-ip")] {
                look.push(json!({"allowed_dynamic_id": id, "srcip": ip, "id": ks.allowed_dynamic_id(id, ip).map(|e| e.id.clone())}));
            }
            v["lookups"] = json!(look);
            if save_removed {
                if let Some(e) = ks.entries.first() {
                    let keyid = e.keyid;
                    let s1 = ks.add_socket(keyid, 7);
                    let s2 = ks.add_socket(keyid, 7);
                    e.state.lock().unwrap().sock = 7;
                    let d1 = ks.delete_socket(7);
                    let sock_after = e.state.lock().unwrap().sock;
                    let d2 = ks.delete_socket(7);
                    ks.add_socket(keyid, 8);
                    e.state.lock().unwrap().sock = 9;
                    let d3 = ks.delete_socket(8);
                    let sock_after2 = e.state.lock().unwrap().sock;
                    v["sockets"] = json!({"add_new": s1, "add_again": s2, "delete": d1, "sock_after_delete": sock_after, "delete_again": d2, "delete_other_sock": d3, "sock_kept_when_different": sock_after2});
                    let snap = e.snapshot();
                    v["snapshot_first"] = json!({"id": snap.id, "name": snap.name, "ip": snap.ip, "peer": snap.peer.map(|p| p.to_string())});
                }
            }
            cases.push(v);
        }
    }
    let mut ks = KeyStore::default();
    let r1 = ks.add_key("010", "x", "10.0.0.1/8", "k", 1234);
    let r2 = ks.add_key("011", "y", "nope", "k", 0);
    cases.push(json!({"fn": "keystore::KeyStore::add_key", "results": [r1.as_ref().ok(), r2.as_ref().err().map(|e| e.to_string())], "store": ks_json(&ks)}));

    // read() from a file
    let f = work.join("client.keys");
    let fs_ = f.to_string_lossy().replace('\\', "/");
    let mut rd = Vec::new();
    for (content, pass_empty) in [(None, false), (None, true), (Some(""), false), (Some(""), true), (Some("001 a any k\n"), false), (Some("001 a 999.9.9.9 k\n"), true), (Some("#only comment\n"), false)] {
        let _ = std::fs::remove_file(&f);
        if let Some(c) = content {
            std::fs::write(&f, c).unwrap();
        }
        let res = KeyStore::read(&fs_, pass_empty, true);
        let lg = logs();
        rd.push(json!({"content": content, "pass_empty_keyfile": pass_empty, "result": match &res { Ok(ks) => json!({"ok": ks_json(ks), "file": ks.file == fs_, "stamp_set": ks.stamp.is_some(), "save_removed": ks.save_removed}), Err(e) => json!({"error": e.to_string().replace(&fs_, "<file>")}) }, "logs": lg}));
    }
    cases.push(json!({"fn": "keystore::KeyStore::read", "cases": rd}));

    // needs_reload / reload carry over network state
    std::fs::write(&f, "001 a any k\n002 b 10.0.0.2 k\n003 c 10.0.0.3 k\n").unwrap();
    let ks = KeyStore::read(&fs_, false, false).unwrap();
    let nr0 = ks.needs_reload();
    for (i, e) in ks.entries.iter().enumerate() {
        let mut st = e.state.lock().unwrap();
        st.rcvd = 100 + i as i64;
        st.sock = if i == 2 { -1 } else { 20 + i as i64 };
        st.peer = Some(format!("10.9.9.{i}:1514").parse().unwrap());
        st.post_startup = true;
        st.net_protocol = keystore::NetProtocol::Tcp;
        st.key.global_counter = 5;
    }
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&f, "001 a any k2\n002 b 10.0.0.22 k\n003 c 10.0.0.3 k\n004 d any k\n").unwrap();
    let nr1 = ks.needs_reload();
    let new = ks.reload(false).unwrap();
    let new_json = ks_json(&new);
    let socks: Vec<Value> = [20i64, 21, 22, -1].iter().map(|s| json!({"delete_socket": s, "found": new.delete_socket(*s)})).collect();
    cases.push(json!({"fn": "keystore::KeyStore::reload", "before": "001 a any k / 002 b 10.0.0.2 / 003 c 10.0.0.3; states set rcvd=100+i, sock=20+i (third -1), peer, post_startup, tcp, global counter 5",
        "after_file": "001 a any k2 / 002 b 10.0.0.22 / 003 c 10.0.0.3 / 004 d any", "needs_reload_unchanged": nr0, "needs_reload_after_write": nr1, "new": new_json, "socket_map_after": socks}));

    let st = keystore::platform_stamp(42);
    cases.push(json!({"fn": "keystore::platform_stamp", "version": 42, "mtime": st.mtime, "inode": st.inode, "file_stamp_missing": keystore::file_stamp("no/such/file").is_none(), "file_stamp_of_file_is_some": keystore::file_stamp(&fs_).is_some()}));
    cases.push(json!({"fn": "constants", "KEYSIZE": keystore::KEYSIZE, "UDP_SOCK": keystore::UDP_SOCK, "KEYS_REQ": keystore::KEYS_REQ, "VERSION_REQ": keystore::VERSION_REQ,
        "OS_MAXSTR": OS_MAXSTR, "OS_HEADER_SIZE": OS_HEADER_SIZE, "MSG_OVERHEAD": MSG_OVERHEAD, "SENDER_COUNTER": SENDER_COUNTER,
        "KeysError_texts": [keystore::KeysError::Open("F".into(), "E".into()).to_string(), keystore::KeysError::InvalidIp("I".into()).to_string(), keystore::KeysError::NoClientKeys.to_string()]}));

    cases.extend(platform(work));
    out.write(K, "keystore", "keystore module (the manager-side key table): parse, lookups, sockets, read, reload, platform key service", cases)
}

/// The platform key service: a local listener that records the request and sends a canned answer.
fn platform(work: &Path) -> Vec<Value> {
    use std::io::{Read, Write};
    use keystore::KeyStore;
    let mut cases = Vec::new();
    let answers: Vec<(&str, Vec<u8>)> = vec![
        ("keys answer", { let p = b"K7\n001 a any k\n002 b 10.0.0.2 k2\n".to_vec(); let mut f = (p.len() as u32).to_le_bytes().to_vec(); f.extend(p); f }),
        ("version answer", { let p = b"V 12 \n".to_vec(); let mut f = (p.len() as u32).to_le_bytes().to_vec(); f.extend(p); f }),
        ("refused", { let mut f = 1u32.to_le_bytes().to_vec(); f.push(b'X'); f }),
        ("zero length", 0u32.to_le_bytes().to_vec()),
        ("too long", (64u32 * 1024 * 1024 + 1).to_le_bytes().to_vec()),
        ("bad version", { let p = b"Kxx\nlines".to_vec(); let mut f = (p.len() as u32).to_le_bytes().to_vec(); f.extend(p); f }),
        ("no newline", { let p = b"K9".to_vec(); let mut f = (p.len() as u32).to_le_bytes().to_vec(); f.extend(p); f }),
        ("short body", { let mut f = 10u32.to_le_bytes().to_vec(); f.extend_from_slice(b"K1"); f }),
    ];
    for (what, ans) in answers {
        for kind in [keystore::KEYS_REQ, keystore::VERSION_REQ] {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap().to_string();
            std::env::set_var("SIEM_KEYS_ADDR", &addr);
            std::env::set_var("SIEM_KEYS_TOKEN", "tok");
            let a2 = ans.clone();
            let t = std::thread::spawn(move || {
                let (mut s, _) = l.accept().unwrap();
                let mut req = vec![0u8; 4 + 4];
                s.read_exact(&mut req).unwrap();
                s.write_all(&a2).unwrap();
                req
            });
            let res = keystore::platform_fetch(kind);
            let req = t.join().unwrap();
            cases.push(json!({"fn": "keystore::platform_fetch", "token": "tok", "kind": kind, "answer": what, "answer_hex": h(&ans), "request_hex": h(&req),
                "result": match res { Ok((v, s)) => json!({"version": v, "text": s}), Err(e) => json!({"error": e}) }}));
        }
    }
    // read() and needs_reload() through the service
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std::env::set_var("SIEM_KEYS_ADDR", l.local_addr().unwrap().to_string());
    let t = std::thread::spawn(move || {
        for ans in [&b"K3\n001 a any k\n"[..], b"V3\n", b"V4\n"] {
            let (mut s, _) = l.accept().unwrap();
            let mut req = [0u8; 8];
            s.read_exact(&mut req).unwrap();
            let mut f = (ans.len() as u32).to_le_bytes().to_vec();
            f.extend_from_slice(ans);
            s.write_all(&f).unwrap();
        }
    });
    let ks = KeyStore::read(&work.join("ignored").to_string_lossy(), false, false).unwrap();
    let st = ks.stamp.unwrap();
    let a = ks.needs_reload();
    let b = ks.needs_reload();
    t.join().unwrap();
    cases.push(json!({"fn": "keystore::KeyStore::read via platform", "store": ks_json(&ks), "stamp": [st.mtime, st.inode], "needs_reload_same_version": a, "needs_reload_new_version": b, "platform_source": keystore::platform_source()}));
    std::env::set_var("SIEM_KEYS_ADDR", "");
    cases.push(json!({"fn": "keystore::platform_source", "addr_empty": keystore::platform_source(), "fetch_error": keystore::platform_fetch(b'K').err()}));
    std::env::remove_var("SIEM_KEYS_ADDR");
    std::env::remove_var("SIEM_KEYS_TOKEN");
    cases
}

fn mkkey(id: &str, name: &str, raw: &str, m: CryptoMethod) -> ClientKey {
    let mut k = ClientKey::new(id.into(), name.into(), "any".into(), raw.into());
    k.crypto_method = m;
    k
}

fn read_case(k: &ClientKey, wire: &[u8], saved: (u32, u32), verify: bool, client: bool, preset: CryptoMethod) -> Value {
    let mut rk = k.clone();
    rk.global_counter = saved.0;
    rk.local_counter = saved.1;
    rk.crypto_method = preset;
    let res = read_sec_msg(&mut rk, wire, ReadOptions { verify_counter: verify, client });
    let r = match res {
        Ok(r) => json!({"ok": {"payload": inp(&r.payload), "global": r.global, "local": r.local}}),
        Err(e) => json!({"error": format!("{:?}", e.key_state()), "error_display": e.to_string(), "reason": format!("{:?}", last_reject_reason())}),
    };
    json!({"saved": [saved.0, saved.1], "verify_counter": verify, "client": client, "key_method_before": format!("{preset:?}"), "result": r,
           "key_after": {"method": format!("{:?}", rk.crypto_method), "global": rk.global_counter, "local": rk.local_counter}})
}

fn msgs(out: &Out, r: &mut Rng) -> usize {
    let mut cases = Vec::new();
    let raw = "3c2f6e9a1b8d4e7f0a5c2b9d8e1f4a7b6c3d0e9f8a7b6c5d4e3f2a1b0c9d8e7f";
    let keys = [("001", "agent1", raw), ("1234", "web-server-01", "k"), ("123456789012", "long-id", raw)];
    let mut payloads: Vec<Vec<u8>> = vec![vec![], b"x".to_vec(), b"#!-agent startup {\"version\":\"v4.14.7\"}".to_vec(), "8:syscheck:{\"path\":\"/etc/\u{e9}\"}".as_bytes().to_vec(), b"a\x00b\xff".to_vec()];
    for n in [2usize, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 255, 1000] {
        payloads.push((0..n).map(|i| b"abcdefghij0123456789:/ "[(i * 7 + n) % 23]).collect());
    }
    payloads.push(r.bytes(&(1..=255u8).collect::<Vec<_>>(), 0).into_iter().chain((0..3000).map(|_| (r.next() >> 16) as u8)).collect());
    payloads.push(vec![b'A'; OS_MAXSTR - OS_HEADER_SIZE]);
    payloads.push(vec![b'A'; OS_MAXSTR - OS_HEADER_SIZE + 1]);
    let counters = [(0u32, 0u32), (0, 9996), (0, 9997), (5, 9998), (u32::MAX, 9997), (7, 42), (0, 20000)];
    for (id, name, raw) in keys {
        for m in [CryptoMethod::Blowfish, CryptoMethod::Aes] {
            let k = mkkey(id, name, raw, m);
            for (pi, p) in payloads.iter().enumerate() {
                for (ci, &(g, l)) in counters.iter().enumerate() {
                    if ci > 1 && pi % 3 != 0 {
                        continue;
                    }
                    for dynamic in [false, true] {
                        let rand = (pi as u16).wrapping_mul(2654) ^ 0x5a5a ^ ci as u16;
                        let mut ctr = SenderCounter { global: g, local: l };
                        let res = create_sec_msg_sized(&k, &mut ctr, p, CreateOptions { dynamic_prefix: dynamic, random: Some(rand) });
                        let mut v = json!({"fn": "create_sec_msg", "key": {"id": id, "name": name, "raw_key": raw, "method": format!("{m:?}")},
                            "counter_before": [g, l], "random": rand, "dynamic_prefix": dynamic, "payload": inp(p), "counter_after": [ctr.global, ctr.local]});
                        match res {
                            Err(e) => v["result"] = json!({"error": e.to_string()}),
                            Ok((wire, cmp)) => {
                                let mut ctr2 = SenderCounter { global: g, local: l };
                                assert_eq!(create_sec_msg(&k, &mut ctr2, p, CreateOptions { dynamic_prefix: dynamic, random: Some(rand) }).unwrap(), wire);
                                v["result"] = json!({"wire_hex": h(&wire), "cmp_size": cmp});
                                if !dynamic && (p.len() < 2000 || ci == 0) {
                                    let (eg, el) = (ctr.global, ctr.local);
                                    let mut reads = Vec::new();
                                    for saved in [(0, 0), (eg, el), (eg, el.wrapping_sub(1)), (eg, el + 5), (eg.wrapping_add(1), 0), (eg.wrapping_sub(1), 9999)] {
                                        for (verify, client) in [(false, false), (true, false), (true, true)] {
                                            reads.push(read_case(&k, &wire, saved, verify, client, CryptoMethod::Blowfish));
                                        }
                                    }
                                    reads.push(read_case(&k, &wire, (0, 0), false, true, if m == CryptoMethod::Aes { CryptoMethod::Blowfish } else { CryptoMethod::Aes }));
                                    let wrong = mkkey(id, name, "wrongkey", m);
                                    reads.push(json!({"wrong_key": true, "read": read_case(&wrong, &wire, (0, 0), false, false, m)}));
                                    v["reads"] = json!(reads);
                                }
                            }
                        }
                        cases.push(v);
                    }
                }
            }
        }
    }
    // hostile buffers
    let k_bf = mkkey("001", "agent1", raw, CryptoMethod::Blowfish);
    let k_aes = mkkey("001", "agent1", raw, CryptoMethod::Aes);
    let mut ctr = SenderCounter::default();
    let good_bf = create_sec_msg(&k_bf, &mut ctr, b"1:/var/log/x:hello world", CreateOptions { dynamic_prefix: false, random: Some(1) }).unwrap();
    let good_aes = create_sec_msg(&k_aes, &mut ctr, b"1:/var/log/x:hello world", CreateOptions { dynamic_prefix: false, random: Some(1) }).unwrap();
    let mut hostile: Vec<(String, &ClientKey, Vec<u8>)> = Vec::new();
    for (label, k, good) in [("bf", &k_bf, &good_bf), ("aes", &k_aes, &good_aes)] {
        hostile.push((format!("{label}: empty"), k, vec![]));
        hostile.push((format!("{label}: only token"), k, good[..if label == "aes" { 5 } else { 1 }].to_vec()));
        for cut in [1usize, 7, 8, 9, 16] {
            if good.len() > cut {
                hostile.push((format!("{label}: drop last {cut}"), k, good[..good.len() - cut].to_vec()));
            }
        }
        for pos in [0usize, 1, 5, 6, 10, 20] {
            if pos < good.len() {
                let mut b = good.clone();
                b[pos] ^= 0x10;
                hostile.push((format!("{label}: flip byte {pos}"), k, b));
            }
        }
        let mut b = good.clone();
        b.extend_from_slice(b"garbage!");
        hostile.push((format!("{label}: 8 bytes appended"), k, b));
        let mut b = good.clone();
        b.extend_from_slice(b"xyz");
        hostile.push((format!("{label}: 3 bytes appended"), k, b));
        hostile.push((format!("{label}: no colon"), k, good[1..].to_vec()));
        hostile.push((format!("{label}: wire with dynamic prefix not removed"), k, [b"!001!".to_vec(), good.clone()].concat()));
    }
    hostile.push(("#AES without colon".into(), &k_aes, [b"#AES".to_vec(), good_aes[5..].to_vec()].concat()));
    hostile.push(("aes body read as blowfish".into(), &k_bf, good_aes[4..].to_vec()));
    hostile.push(("blowfish body with #AES token".into(), &k_aes, [b"#AES".to_vec(), good_bf.clone()].concat()));
    // crafted plaintexts encrypted with the agent key
    let enc = |k: &ClientKey, plain: &[u8]| -> Vec<u8> {
        match k.crypto_method {
            CryptoMethod::Blowfish => [b":".to_vec(), os_bf_str(plain, &k.encryption_key, true).unwrap()].concat(),
            CryptoMethod::Aes => [b"#AES:".to_vec(), os_aes_str(plain, &k.encryption_key, true).unwrap()].concat(),
        }
    };
    let md5hex = |b: &[u8]| -> String { md5_bytes(b).iter().map(|x| format!("{x:02x}")).collect() };
    let zlib = |b: &[u8]| -> Vec<u8> { siem_shared_zlib(b) };
    let pad = |mut v: Vec<u8>| -> Vec<u8> {
        let rem = (v.len() + 1) % 8;
        let bangs = if rem == 0 { 1 } else { 1 + 8 - rem };
        let mut o = vec![b'!'; bangs];
        o.append(&mut v);
        o
    };
    let body = |t: &str| -> Vec<u8> { format!("{}{}", md5hex(t.as_bytes()), t).into_bytes() };
    for k in [&k_bf, &k_aes] {
        let crafted: Vec<(&str, Vec<u8>)> = vec![
            ("good crafted", pad(zlib(&body("123450000000007:0042:payload")))),
            ("bad checksum", pad(zlib(&format!("{}{}", "0".repeat(32), "123450000000007:0042:payload").into_bytes()))),
            ("upper-case checksum", pad(zlib(&format!("{}{}", md5hex(b"12345000000000700042:payload").to_uppercase(), "123450000000007:0042:payload").into_bytes()))),
            ("no colon at 15", pad(zlib(&body("123450000000007-0042:payload")))),
            ("no colon at 20", pad(zlib(&body("123450000000007:0042-payload")))),
            ("too short", pad(zlib(&body("123450000000007:004")))),
            ("empty payload", pad(zlib(&body("123450000000007:0042:")))),
            ("counters with spaces", pad(zlib(&body("12345         7:  42:x")))),
            ("negative global", pad(zlib(&body("12345-000000007:0042:x")))),
            ("global overflow", pad(zlib(&body("123459999999999:0042:x")))),
            ("not zlib", pad(b"this is not zlib data".to_vec())),
            ("empty zlib", pad(zlib(b""))),
            ("zlib trailing garbage", pad([zlib(&body("123450000000007:0042:p")), b"junk".to_vec()].concat())),
            ("many bangs", [vec![b'!'; 16], zlib(&body("123450000000007:0042:p"))].concat()),
            ("first byte not ! or :", [b"?".to_vec(), zlib(&body("123450000000007:0042:p"))].concat()),
            ("legacy good", { let t = "1700000000:0042:hello"; let mut v = format!(":{}{}", md5hex(t.as_bytes()), t).into_bytes(); while v.len() % 8 != 0 { v.push(0) } v }),
            ("legacy no colon", { let t = "1700000000:0042x"; let mut v = format!(":{}{}", md5hex(t.as_bytes()), t).into_bytes(); while v.len() % 8 != 0 { v.push(0) } v }),
            ("legacy bad sum", { let t = "1700000000:0042:hello"; let mut v = format!(":{}{}", "1".repeat(32), t).into_bytes(); while v.len() % 8 != 0 { v.push(0) } v }),
            ("legacy unpadded", { let t = "1700000000:0042:hello!"; format!(":{}{}", md5hex(t.as_bytes()), t).into_bytes() }),
        ];
        for (what, plain) in crafted {
            let label = format!("{:?}: {what} (plaintext before encryption: {})", k.crypto_method, h(&plain));
            let w = enc(k, &plain);
            hostile.push((label, k, w));
        }
    }
    for (label, k, wire) in &hostile {
        let mut reads = Vec::new();
        for saved in [(0u32, 0u32), (7, 42), (1700000000, 42), (7, 41)] {
            for (verify, client) in [(false, false), (true, false), (false, true)] {
                reads.push(read_case(k, wire, saved, verify, client, k.crypto_method));
            }
        }
        cases.push(json!({"fn": "read_sec_msg hostile", "label": label, "key": {"id": k.id, "name": k.name, "raw_key": k.raw_key, "method": format!("{:?}", k.crypto_method)}, "wire_hex": h(wire), "reads": reads}));
    }
    // SenderCounter::next
    let mut seq = Vec::new();
    for start in [(0u32, 0u32), (3, 9996), (3, 9997), (3, 9998), (3, 50000), (u32::MAX, 9997)] {
        let mut c = SenderCounter { global: start.0, local: start.1 };
        let mut steps = Vec::new();
        for _ in 0..3 {
            c.next();
            steps.push([c.global, c.local]);
        }
        seq.push(json!({"start": [start.0, start.1], "after_each_next": steps}));
    }
    cases.push(json!({"fn": "SenderCounter::next", "cases": seq}));
    out.write(K, "msgs", "create_sec_msg(key, counter, payload, {dynamic_prefix, random}) -> wire bytes; read_sec_msg(key with saved counters and preset method, wire, {verify_counter, client}) -> payload or key state (Rids/Corrupt/EncKey) + reject reason; key_after = key fields after the call. Key method in 'key' is the sender's. payload: {hex} or {repeat_hex, times}", cases)
}

fn siem_shared_zlib(b: &[u8]) -> Vec<u8> {
    // the same compressor the old message code uses
    siem_shared::zlib::os_zlib_compress(b).unwrap()
}

fn counters(out: &Out, work: &Path) -> usize {
    let mut cases = Vec::new();
    let dir = work.join("rids");
    let store = CounterStore::new(&dir, 3);
    for content in ["7:42:", "7:42", " 7 : 42", "7: 42", "-1:5", "abc", "", "4294967296:1", "99999999999:1", "18446744073709551616:1", "1:2:3", "+5:+6", "5:", ":5", "5:x", "0x10:1", "\n12:\n13"] {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("001"), content).unwrap();
        let mut k = mkkey("001", "a", "k", CryptoMethod::Blowfish);
        store.start_agent(&mut k);
        cases.push(json!({"fn": "CounterStore::load / start_agent + parse_counter", "file_content": content, "load": store.load("001"), "start_agent": [k.global_counter, k.local_counter], "parse_counter": parse_counter(content)}));
        // SenderCounterFile
        let p = dir.join("sender_file_test");
        std::fs::write(&p, content).unwrap();
        let (mut f, c) = SenderCounterFile::open(&p).unwrap();
        f.store(&SenderCounter { global: 1, local: 2 });
        drop(f);
        cases.push(json!({"fn": "SenderCounterFile::open + store(1,2)", "file_content_before": content, "opened_counter": [c.global, c.local], "file_after_hex": h(&std::fs::read(&p).unwrap())}));
    }
    let p = dir.join("new_sender");
    let _ = std::fs::remove_file(&p);
    let (mut f, c) = SenderCounterFile::open(&p).unwrap();
    let created = std::fs::read(&p).unwrap();
    f.store(&SenderCounter { global: 123456, local: 789 });
    f.store(&SenderCounter { global: 1, local: 2 });
    drop(f);
    cases.push(json!({"fn": "SenderCounterFile::open missing file then store(123456,789), store(1,2)", "opened_counter": [c.global, c.local], "created_content_hex": h(&created), "file_after": String::from_utf8_lossy(&std::fs::read(&p).unwrap())}));
    let _ = std::fs::remove_dir_all(&dir);
    cases.push(json!({"fn": "CounterStore::load missing", "load": store.load("nope"), "load_sender": [store.load_sender().global, store.load_sender().local]}));
    store.store("009", 7, 42).unwrap();
    store.store_sender(&SenderCounter { global: 3, local: 4 }).unwrap();
    cases.push(json!({"fn": "CounterStore::store / store_sender (creates the directory)", "file_009": std::fs::read_to_string(dir.join("009")).unwrap(), "file_sender_counter": std::fs::read_to_string(dir.join(SENDER_COUNTER)).unwrap(), "dir_is_given": store.dir() == dir.as_path()}));
    for flush in [0u32, 1, 3] {
        let mut s = CounterStore::new(&dir, flush);
        let mut k = mkkey("077", "a", "k", CryptoMethod::Blowfish);
        let _ = std::fs::remove_file(dir.join("077"));
        let mut steps = Vec::new();
        for i in 1..=7u32 {
            k.global_counter = i;
            k.local_counter = i * 10;
            s.on_received(&k).unwrap();
            steps.push(json!({"call": i, "counters": [i, i * 10], "file": std::fs::read_to_string(dir.join("077")).ok()}));
        }
        cases.push(json!({"fn": "CounterStore::on_received", "recv_flush": flush, "steps": steps}));
    }
    cases.push(json!({"fn": "CounterStore::remove", "existing": store.remove("009").is_ok(), "exists_after": dir.join("009").exists(), "missing_ok": store.remove("never").is_ok()}));
    out.write(K, "counters", "Counter files: CounterStore (load/store/start_agent/on_received/remove), SenderCounterFile (open/store), parse_counter", cases)
}

fn signature(out: &Out, work: &Path) -> usize {
    use siem_crypto::signature::*;
    let mut cases = Vec::new();
    let p = work.join("pkg.wpk");
    let sig: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("magic + NUL + 256 + payload", [WPK_MAGIC.to_vec(), vec![0], sig.clone(), b"payload".to_vec()].concat()),
        ("magic + 256 + payload (no NUL)", [WPK_MAGIC.to_vec(), sig.clone(), b"payload".to_vec()].concat()),
        ("magic + NUL + 255", [WPK_MAGIC.to_vec(), vec![0], sig[..255].to_vec()].concat()),
        ("magic only", WPK_MAGIC.to_vec()),
        ("bad magic", b"NOTWPK".to_vec()),
        ("short", b"WPK".to_vec()),
        ("empty", vec![]),
        ("lower case magic", [b"wpk256".to_vec(), vec![0], sig.clone()].concat()),
    ];
    for (what, data) in files {
        std::fs::write(&p, &data).unwrap();
        let r = read_wpk_header(&p);
        cases.push(json!({"fn": "read_wpk_header", "file": what, "file_hex_len": data.len(), "result": match r {
            Ok(hd) => json!({"signature_hex": h(&hd.signature), "content_offset": hd.content_offset, "certificate_len": hd.certificate_der.len()}),
            Err(e) => json!({"error": format!("{e:?}").split('(').next().unwrap().to_string(), "display": e.to_string()}) }}));
    }
    cases.push(json!({"WPK_MAGIC": String::from_utf8_lossy(WPK_MAGIC), "WPK_SIGNATURE_LEN": WPK_SIGNATURE_LEN, "missing_file": read_wpk_header(work.join("none")).is_err()}));
    out.write(K, "signature", "read_wpk_header (unused by callers; kept for the record)", cases)
}
