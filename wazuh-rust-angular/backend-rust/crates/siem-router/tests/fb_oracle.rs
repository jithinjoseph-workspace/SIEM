//! Differential test of the flatbuffers path (`router_provider_send_fb_json`
//! and `router_provider_send_fb`) against `tools/oracle/fb_harness.cpp`
//! (router.cpp's code over the real SchemaAdapter, flatbuffers 23.5.26 and
//! simdjson 3.13.0): logged messages, sent buffers and return values must be
//! identical.
//!
//! `SIEM_FB_ORACLE` is the oracle command (`~/fb_oracle/fb_oracle`, built by
//! `tools/oracle/fb_build.sh`); without it the test only runs the Rust side.
//! `SIEM_FB_FUZZ` (mutations, default 2000), `SIEM_FB_SEED`, `SIEM_FB_KEEP`
//! (a directory for the inputs and outputs).

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use siem_router::adapter::AgentCtx;
use siem_router::sjson::{self, Element};

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn opt(b: Option<&[u8]>) -> String {
    b.map(hex).unwrap_or_else(|| "-".into())
}

#[derive(Clone)]
enum Case {
    /// handle valid, schema, agent context (None: NULL), message (None: NULL)
    J(bool, i32, Option<[Vec<u8>; 3]>, Option<Vec<u8>>, Option<Vec<u8>>),
    /// handle valid, schema text, message
    F(bool, Vec<u8>, Option<Vec<u8>>),
}

impl Case {
    fn line(&self) -> String {
        match self {
            Case::J(h, s, ctx, ver, msg) => {
                let (a, b, c) = match ctx {
                    Some([a, b, c]) => (hex(a), hex(b), hex(c)),
                    None => ("!".into(), "".into(), "".into()),
                };
                format!("J {} {s} {a} {b} {c} {} {}", *h as u8, opt(ver.as_deref()), opt(msg.as_deref()))
            }
            Case::F(h, schema, msg) => format!("F {} {} {}", *h as u8, hex(schema), opt(msg.as_deref())),
        }
    }
}

fn logs() -> &'static Mutex<Vec<String>> {
    static L: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(Vec::new()))
}

fn level_num(l: &str) -> i32 {
    match l {
        "DEBUG" => 0,
        "INFO" => 1,
        "WARNING" => 2,
        "ERROR" => 3,
        "ERROR_EXIT" => 4,
        _ => 5,
    }
}

fn run_rust(cases: &[Case]) -> Vec<String> {
    siem_router::router_initialize(Arc::new(|level: &str, msg: &[u8]| {
        logs().lock().unwrap().push(format!("M {} {}", level_num(level), hex(msg)));
    }));
    logs().lock().unwrap().clear();
    let mut out = Vec::new();
    for c in cases {
        let mut sent: Vec<String> = Vec::new();
        let r = match c {
            Case::J(h, schema, ctx, ver, msg) => {
                let ctx = ctx.as_ref().map(|[a, b, c]| AgentCtx { agent_id: a, agent_name: b, agent_ip: c, agent_version: ver.as_deref() });
                let mut send = |d: &[u8]| {
                    if !*h {
                        return Err(b"map::at".to_vec());
                    }
                    sent.push(format!("D {}", hex(d)));
                    Ok(())
                };
                siem_router::send_fb_json_with(msg.as_deref(), ctx.as_ref(), *schema, &mut send)
            }
            Case::F(h, schema, msg) => {
                let mut send = |d: &[u8]| {
                    if !*h {
                        return Err(b"map::at".to_vec());
                    }
                    sent.push(format!("D {}", hex(d)));
                    Ok(())
                };
                siem_router::send_fb_with(msg.as_deref(), schema, &mut send)
            }
        };
        // the oracle prints the logs and the data as they happen; a case
        // logs either before failing or not at all, and sends last
        out.append(&mut logs().lock().unwrap());
        out.append(&mut sent);
        out.push(format!("R {r}"));
    }
    out
}

fn run_oracle(cmd: &str, input: &str) -> Vec<String> {
    let args: Vec<&str> = cmd.split_whitespace().collect();
    let mut child = Command::new(args[0]).args(&args[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn oracle");
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_string();
    let w = std::thread::spawn(move || {
        let _ = stdin.write_all(data.as_bytes());
    });
    let mut s = String::new();
    child.stdout.take().unwrap().read_to_string(&mut s).unwrap();
    w.join().unwrap();
    child.wait().unwrap();
    s.lines().map(String::from).collect()
}

/// Output grouped per case (each group ends with its R line).
fn groups(lines: &[String]) -> Vec<Vec<String>> {
    let mut g = Vec::new();
    let mut cur = Vec::new();
    for l in lines {
        cur.push(l.clone());
        if l.starts_with("R ") {
            g.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        g.push(cur);
    }
    g
}

fn decode(l: &str) -> String {
    let p: Vec<&str> = l.splitn(3, ' ').collect();
    match p.as_slice() {
        ["M", lvl, h] => format!("M {lvl} {:?}", String::from_utf8_lossy(&unhex(h)).chars().take(700).collect::<String>()),
        ["D", h] => format!("D {}", h.chars().take(700).collect::<String>()),
        _ => l.to_string(),
    }
}

// ----------------------------------------------------------------- corpus

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn ctx() -> Option<[Vec<u8>; 3]> {
    Some([b"001".to_vec(), b"agent-1".to_vec(), b"192.168.0.10".to_vec()])
}

fn j(schema: i32, msg: &str) -> Case {
    Case::J(true, schema, ctx(), Some(b"v4.14.7".to_vec()), Some(msg.as_bytes().to_vec()))
}

const SYS: i32 = 1;
const SYNC: i32 = 2;
const FIM: i32 = 3;

fn deltas() -> Vec<String> {
    let mut v = vec![
        r#"{"type":"dbsync_packages","data":{"architecture":"amd64","checksum":"ab12","description":"GNU C Library","format":"deb","groups":"libs","install_time":"","item_id":"ff00","location":"","multiarch":"same","name":"libc6","priority":"required","scan_time":"2025/01/01 10:00:00","size":13045,"source":"glibc","vendor":"Ubuntu Developers","version":"2.31-0ubuntu9"},"operation":"INSERTED"}"#.to_string(),
        r#"{"type":"dbsync_processes","data":{"argvs":"-c","checksum":"1","cmd":"/bin/bash","egroup":"root","euser":"root","fgroup":"root","name":"bash","nice":0,"nlwp":1,"pgrp":10,"pid":"10","ppid":1,"priority":20,"processor":3,"resident":1000,"rgroup":"root","ruser":"root","scan_time":"2025/01/01 10:00:00","session":10,"sgroup":"root","share":800,"size":5000,"start_time":1700000000,"state":"S","stime":5,"suser":"root","tgid":10,"tty":34816,"utime":3,"vm_size":20000},"operation":"MODIFIED"}"#.into(),
        r#"{"type":"dbsync_ports","data":{"checksum":"c","inode":12345,"item_id":"i","local_ip":"0.0.0.0","local_port":22,"pid":0,"process":null,"protocol":"tcp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"scan_time":"t","state":"listening","tx_queue":0},"operation":"DELETED"}"#.into(),
        r#"{"type":"dbsync_osinfo","data":{"architecture":"x86_64","checksum":"x","hostname":"h","os_build":null,"os_codename":"focal","os_major":"20","os_minor":"04","os_name":"Ubuntu","os_patch":"6","os_platform":"ubuntu","os_release":null,"os_version":"20.04.6 LTS (Focal Fossa)","release":"5.15","scan_time":"t","sysname":"Linux","version":"1 SMP x"},"operation":"MODIFIED"}"#.into(),
        r#"{"type":"dbsync_hwinfo","data":{"board_serial":"0","checksum":"x","cpu_cores":8,"cpu_mhz":2904.0,"cpu_name":"Intel(R) Core(TM)","ram_free":1000.5,"ram_total":16000000,"ram_usage":40,"scan_time":"t"},"operation":"MODIFIED"}"#.into(),
        r#"{"type":"dbsync_network_iface","data":{"adapter":null,"checksum":"x","item_id":"y","mac":"00:15:5d:00:00:01","mtu":1500,"name":"eth0","rx_bytes":123456789012,"rx_dropped":0,"rx_errors":0,"rx_packets":5,"scan_time":"t","state":"up","tx_bytes":1,"tx_dropped":0,"tx_errors":0,"tx_packets":1,"type":"ethernet"},"operation":"INSERTED"}"#.into(),
        r#"{"type":"dbsync_network_protocol","data":{"checksum":"x","dhcp":"enabled","gateway":"172.17.0.1","iface":"eth0","item_id":"y","metric":"100","scan_time":"t","type":"ipv4"},"operation":"INSERTED"}"#.into(),
        r#"{"type":"dbsync_network_address","data":{"address":"172.17.0.5","broadcast":"172.17.255.255","checksum":"x","dhcp":"x","iface":"eth0","item_id":"y","metric":"5","netmask":"255.255.0.0","proto":0,"scan_time":"t"},"operation":"INSERTED"}"#.into(),
        r#"{"type":"dbsync_hotfixes","data":{"checksum":"x","hotfix":"KB5000001","scan_time":"t"},"operation":"INSERTED"}"#.into(),
        r#"{"type":"dbsync_users","data":{"scan_time":"t","user_name":"root","user_id":0,"user_uid_signed":0,"user_group_id":0,"user_created":1.5,"user_is_hidden":0,"user_last_login":null,"user_shell":"/bin/bash","login_status":1,"checksum":"c"},"operation":"INSERTED"}"#.into(),
        r#"{"type":"dbsync_groups","data":{"scan_time":"t","group_id":1000,"group_name":"users","group_is_hidden":0,"group_users":"a,b","checksum":"c"},"operation":"INSERTED"}"#.into(),
        r#"{"type":"dbsync_browser_extensions","data":{"browser_name":"chrome","package_enabled":1,"package_visible":0,"browser_profile_referenced":1,"package_name":"x","checksum":"c","item_id":"i"},"operation":"INSERTED"}"#.into(),
        r#"{"type":"dbsync_services","data":{"service_id":"ssh","service_name":"ssh","service_frequency":5,"service_starts_on_mount":1,"process_pid":123,"service_exit_code":0,"service_win32_exit_code":0,"service_target_ephemeral_id":7,"checksum":"c","item_id":"i"},"operation":"MODIFIED"}"#.into(),
    ];
    // scalar conversions on long / double / int fields
    for val in [
        "1", "-1", "0", "1.5", "-2.5e3", "1e400", "9223372036854775807", "9223372036854775808", "-9223372036854775808",
        "18446744073709551615", "18446744073709551616", "\"12\"", "\" 12 \"", "\"12 \"", "\"0x1f\"", "\"-0x10\"", "\"1e5\"",
        "\"abc\"", "\"\"", "\"null\"", "null", "true", "false", "\"true\"", "[1]", "{}", "\"1.5\"", "\"\\u0031\"", "\"0b1\"",
        "0.0", "-0.0", "123456789012345678901234567890", "1E2", "\"   \"", "\"+5\"", "\"- 5\"",
    ] {
        v.push(format!(r#"{{"type":"dbsync_hwinfo","data":{{"cpu_cores":{val},"cpu_mhz":{val},"ram_free":{val}}},"operation":"MODIFIED"}}"#));
        v.push(format!(r#"{{"type":"dbsync_users","data":{{"user_id":{val},"user_is_hidden":{val},"user_created":{val}}},"operation":"MODIFIED"}}"#));
    }
    v
}

fn syncs() -> Vec<String> {
    vec![
        r#"{"component":"syscollector_packages","data":{"attributes":{"architecture":"amd64","checksum":"x","name":"libc6","size":13045,"version":"2.31"},"index":"0123abcd","timestamp":""},"type":"state"}"#.into(),
        r#"{"component":"syscollector_processes","data":{"attributes":{"name":"bash","pid":"10","nice":-5,"vm_size":20000},"index":"10","timestamp":""},"type":"state"}"#.into(),
        r#"{"component":"syscollector_hwinfo","data":{"attributes":{"cpu_mhz":2904.123,"cpu_cores":8,"ram_total":16000000},"index":"x","timestamp":""},"type":"state"}"#.into(),
        r#"{"component":"fim_file","data":{"attributes":{"checksum":"c","gid":"0","inode":5,"mtime":1700000000,"size":10,"type":"file","uid":"0","user_name":"root","hash_md5":"d41d8cd98f00b204e9800998ecf8427e"},"index":"/etc/passwd","path":"/etc/passwd","timestamp":""},"type":"state"}"#.into(),
        r#"{"component":"fim_registry_key","data":{"attributes":{"checksum":"c","type":"registry_key","mtime":5},"index":"k","path":"HKEY_LOCAL_MACHINE\\System","arch":"[x64]","timestamp":""},"type":"state"}"#.into(),
        r#"{"component":"fim_registry_value","data":{"attributes":{"checksum":"c","type":"registry_value","size":4,"value_type":"REG_DWORD"},"index":"k","path":"HKEY_LOCAL_MACHINE\\System","value_name":"v","arch":"[x32]","timestamp":""},"type":"state"}"#.into(),
        r#"{"component":"syscollector_packages","data":{"begin":"a","checksum":"abc","end":"z","id":1700000000},"type":"integrity_check_global"}"#.into(),
        r#"{"component":"syscollector_packages","data":{"id":1700000000},"type":"integrity_clear"}"#.into(),
        r#"{"component":"syscollector_packages","data":{"begin":"a","checksum":"abc","end":"m","id":1,"tail":"n"},"type":"integrity_check_left"}"#.into(),
        r#"{"component":"syscollector_packages","data":{"begin":"a","checksum":"abc","end":"m","id":1},"type":"integrity_check_right"}"#.into(),
        r#"{"component":"syscollector_packages","data":{"id":1},"type":"scan_start"}"#.into(),
        r#"{"component":"syscollector_packages","data":{},"type":"state"}"#.into(),
        r#"{"component":"syscollector_packages","data":[],"type":"state"}"#.into(),
        r#"{"component":"syscollector_packages","data":"x","type":"state"}"#.into(),
        r#"{"component":"syscollector_packages","type":"state"}"#.into(),
        r#"{"data":{"id":1},"type":"integrity_clear"}"#.into(),
        r#"{"component":5,"data":{"id":1},"type":"integrity_clear"}"#.into(),
        r#"{"component":"x","data":{"id":1},"type":"modified"}"#.into(),
        r#"{"component":"syscollector_osinfo","data":{"attributes":{"os_name":"x"},"index":"i","timestamp":""},"type":"state"}"#.into(),
        r#"{"component":"no_such_table","data":{"attributes":{"a":1},"index":"i"},"type":"state"}"#.into(),
        r#"{"component":"syscollector_packages","data":{"attributes_type":"syscollector_packages","attributes":{}},"type":"state"}"#.into(),
        r#"{"component":"syscollector_packages","data":{"attributes":{"name":"x"},"index":"i","nested":{"a":[1,2,{"b":null}],"c":1e300,"d":-0.0,"e":"\u00e9\n\"\\"}},"type":"state"}"#.into(),
        r#"{"component":"syscollector_packages","data":{"attributes":{"name":"x","size":1.5e20,"description":"\u0000zero"}},"type":"state"}"#.into(),
        r#"{"component":"syscollector_packages","ID":5,"timestamp":"t","data":{"id":1},"type":"integrity_clear"}"#.into(),
        r#"{"component":"syscollector_packages","ID":5,"data":{"id":1},"type":"integrity_clear"}"#.into(),
        r#"{"component":"dbsync","data":{"id":12345678901234567890},"type":"integrity_clear"}"#.into(),
        r#"{"component":"syscollector_ports","data":{"attributes":{"local_port":"22","inode":"0x10","pid":"-5"},"index":"i"},"type":"state"}"#.into(),
    ]
}

fn fims() -> Vec<String> {
    vec![
        r#"{"type":"event","data":{"path":"/etc/hosts","version":2.0,"mode":"realtime","type":"modified","arch":"[x64]","value_name":"v","timestamp":1700000000,"attributes":{"type":"file","size":120,"perm":"rw-r--r--","uid":"0","gid":"0","user_name":"root","group_name":"root","inode":131,"mtime":1700000000,"hash_md5":"a","hash_sha1":"b","hash_sha256":"c","checksum":"d","attributes":"x"},"changed_attributes":["size","mtime","md5","sha1","sha256"],"old_attributes":{"type":"file","size":100,"mtime":1600000000},"tags":"t","content_changes":"x"}}"#.into(),
        r#"{"type":"event","data":{"path":"/etc/x","mode":"scheduled","type":"added","timestamp":5,"attributes":{"type":"file"},"changed_attributes":[]}}"#.into(),
        r#"{"type":"event","data":{"path":"/etc/x","changed_attributes":["a",1]}}"#.into(),
        r#"{"type":"event","data":{"path":"/etc/x","changed_attributes":"a"}}"#.into(),
        r#"{"type":"event","data":{"path":"/etc/x","changed_attributes":[null]}}"#.into(),
        r#"{"type":"event","data":{"path":"/etc/x","changed_attributes":null,"attributes":null}}"#.into(),
        r#"{"type":"event","data":{"path":["a"]}}"#.into(),
        r#"{"type":"event","data":{"timestamp":"5"}}"#.into(),
        r#"{"type":"event","data":{"timestamp":5.5}}"#.into(),
        r#"{"type":"event","data":{"timestamp":cos(0)}}"#.into(),
        r#"{"type":"event","data":{}}"#.into(),
        r#"{"type":"event","data_type":"x","data":{}}"#.into(),
        r#"{"type":"event"}"#.into(),
        r#"{"type":"integrity_check_global","data":{"id":5}}"#.into(),
        r#"{"type":"event","ID":1,"timestamp":2,"data":{}}"#.into(),
    ]
}

/// Messages that stress the JSON readers (simdjson first, flatbuffers then).
fn edge_messages() -> Vec<(i32, Vec<u8>)> {
    let mut v: Vec<(i32, Vec<u8>)> = Vec::new();
    let mut s = |schema: i32, m: &str| v.push((schema, m.as_bytes().to_vec()));
    for m in [
        "", " ", "{", "}", "[]", "null", "\"x\"", "5", "{}", "{\"type\":1}", "{\"type\":null}", "{\"type\":\"\"}", "{\"type\":[]}",
        "{\"type\":\"dbsync_osinfo\"}", "{\"type\":\"dbsync_osinfo\",}", "{\"type\":\"dbsync_osinfo\"} ", " {\"type\":\"dbsync_osinfo\"}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{}}", "{\"type\":\"dbsync_osinfo\",\"data\":null}", "{\"type\":\"dbsync_osinfo\",\"data\":5}",
        "{\"type\":\"nope\",\"data\":{}}", "{\"type\":\"NONE\",\"data\":{}}", "{\"type\":\"dbsync_osinfo dbsync_hwinfo\",\"data\":{}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"a\",\"os_name\":\"b\"}}", "{\"type\":\"a\\\"b\",\"data\":{}}",
        "{\"type\":\"a\\u0000b\",\"data\":{}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"x\":{\"y\":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}}}",
        "{\"type\":\"dbsync_osinfo\",\"type\":\"dbsync_hwinfo\",\"data\":{}}", "{\"type\":\"dbsync_osinfo\",\"data\":{},\"data\":{}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"\\ud83d\\ude00\"}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"\\ud83d\"}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"\u{7f}\u{e9}\"}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"a\tb\"}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"\\/\\b\\f\\n\\r\\t\"}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":'x'}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":1e5}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":01}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":-}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":tru}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":true}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":{\"a\":1}}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"$schema\":\"x\"}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"$schema\":5}}",
        "{\"type\":\"dbsync_osinfo\",\"data\":[\"a\"]}", "{\"type\":\"dbsync_hotfixes\",\"data\":[\"a\",\"b\",\"c\"]}",
        "{\"type\":\"dbsync_hotfixes\",\"data\":[\"a\",\"b\",\"c\",\"d\"]}", "{\"type\":\"dbsync_hotfixes\",\"data\":[]}",
        "{\"type\":\"dbsync_hotfixes\",\"data\":[null,\"b\",\"c\"]}", "{\"type\":\"dbsync_hwinfo\",\"data\":{\"cpu_mhz\":1.7976931348623157e308}}",
        "{\"type\":\"dbsync_hwinfo\",\"data\":{\"cpu_mhz\":4.9e-324,\"cpu_cores\":-0}}", "{\"type\":\"dbsync_hwinfo\",\"data\":{\"cpu_mhz\":0.1e-5}}",
        "{\"type\":\"dbsync_hwinfo\",\"data\":{\"cpu_mhz\":12345678901234567890123}}", "{\"type\":\"dbsync_hwinfo\",\"data\":{\"cpu_cores\":1.0}}",
        "{\"type\":\"dbsync_osinfo\"\n,\"data\":{\n\"os_name\":5}}", "{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"x\"}}\n",
        "{\"type\":\"dbsync_osinfo\",\"data\":{\"agent_info\":5}}", "{\"type\":\"dbsync_osinfo\",\"agent_info\":{}}",
        "{\"type\":\"dbsync_osinfo\",\"data_type\":\"dbsync_hwinfo\"}", "{\"type\":\"dbsync_osinfo\",\"data_type\":5}",
    ] {
        s(SYS, m);
        s(SYNC, m);
        s(FIM, m);
    }
    v.push((SYS, b"{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"\xff\"}}".to_vec()));
    v.push((SYS, b"{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"\xc3\xa9\"}}".to_vec()));
    v.push((SYS, b"{\"type\":\"dbsync_osinfo\",\"data\":{\"os_name\":\"\xed\xa0\x80\"}}".to_vec()));
    v.push((SYS, b"{\"type\":\"db\x00sync\"}".to_vec()));
    let deep = format!("{{\"type\":\"dbsync_osinfo\",\"data\":{{\"x\":{}1{}}}}}", "[".repeat(1022), "]".repeat(1022));
    v.push((SYS, deep.into_bytes()));
    let deeper = format!("{{\"type\":\"dbsync_osinfo\",\"data\":{{\"x\":{}1{}}}}}", "[".repeat(1023), "]".repeat(1023));
    v.push((SYS, deeper.into_bytes()));
    let fb_deep = format!("{{\"type\":\"dbsync_osinfo\",\"data\":{{\"x\":{}1{}}}}}", "[".repeat(62), "]".repeat(62));
    v.push((SYS, fb_deep.into_bytes()));
    let fb_deep2 = format!("{{\"type\":\"dbsync_osinfo\",\"data\":{{\"x\":{}1{}}}}}", "[".repeat(61), "]".repeat(61));
    v.push((SYS, fb_deep2.into_bytes()));
    v
}

/// Schemas and messages for `router_provider_send_fb` (arbitrary JSON and
/// schema text).
fn fb_cases() -> Vec<Case> {
    let schemas: Vec<String> = vec![
        "table T { a:string; b:long; c:int = null; d:double = 1.5; e:[string]; f:bool; g:short = 7; h:ubyte; i:float; j:ulong; k:[long]; } root_type T;".into(),
        "namespace N.M; enum Color : byte { Red = 1, Green, Blue = 8 } table S { x:int; } union U { S, T2 } table T2 { y:string; } table T { c:Color = Green; u:U; v:[S]; w:S; } root_type T;".into(),
        "table T (original_order) { a:byte; b:long; c:string; d:short; } root_type T;".into(),
        "table T { b:long (id: 1); a:string (id: 0); u:U (id: 3); } table X { z:int; } union U { X } root_type T;".into(),
        "table T { a:string (deprecated); b:int (required); } root_type T;".into(),
        "table T { a:string (required); b:int; } root_type T;".into(),
        "table T { a:int; } root_type T; file_identifier \"ABCD\";".into(),
        "table T { a:int; a:int; } root_type T;".into(),
        "table T { a:Unknown; } root_type T;".into(),
        "table T { a:int; } root_type X;".into(),
        "table T { a:int = 2147483648; } root_type T;".into(),
        "enum E : ubyte { A = 300 } table T { e:E; } root_type T;".into(),
        "// comment\ntable T { /* c */ a:int; }\nroot_type T;".into(),
        "attribute \"priority\"; table T { a:int (priority: 1); } root_type T;".into(),
        "table T { a:int (bogus); } root_type T;".into(),
        "".into(),
        "table T { a:int; }".into(),
        "union U { A, B } table A { x:int; } table B { y:string; } table T { u:U; u2:U; } root_type T;".into(),
        "enum E : int { A, B, C } table T { e:E = B; v:[E]; } root_type T;".into(),
        "table Inner { s:string; n:long; } table T { i:Inner; l:[Inner]; } root_type T;".into(),
    ];
    let msgs: Vec<String> = vec![
        "{}".into(),
        "{a:\"x\",b:5,c:0,d:1.5,e:[\"p\",\"q\"],f:true,g:7,h:255,i:1.25,j:18446744073709551615,k:[1,-2,3]}".into(),
        "{\"a\":\"x\",\"b\":\"0x10\",\"c\":null,\"d\":nan,\"f\":\"false\",\"g\":-32768,\"h\":256,\"i\":-inf,\"j\":-1}".into(),
        "{\"b\":1,\"b\":2}".into(),
        "{\"u\":{\"x\":1},\"u_type\":\"S\"}".into(),
        "{\"u_type\":\"S\",\"u\":{\"x\":1}}".into(),
        "{\"u_type\":\"T2\",\"u\":{\"y\":\"yy\"},\"c\":\"Red Blue\",\"v\":[{\"x\":1},{\"x\":2}],\"w\":[5]}".into(),
        "{\"u\":{\"x\":1}}".into(),
        "{\"u\":{\"x\":1},\"zz\":1}".into(),
        "{\"u\":{\"x\":1},\"u_type\":5}".into(),
        "{\"u_type\":0,\"u\":{}}".into(),
        "{\"c\":\"N.M.Color.Red\",\"c2\":1}".into(),
        "{\"c\":\"Purple\"}".into(),
        "{\"c\":Green}".into(),
        "{\"c\":3}".into(),
        "{a:1,b:\"2\",c:\"x\",d:2,e:[],k:[\"1\",2.5]}".into(),
        "{\"a\":\"x\",}".into(),
        "{\"a\":\"x\" \"b\":1}".into(),
        "{\"d\":deg(1),\"i\":rad(180)}".into(),
        "{\"d\":-sin(1)}".into(),
        "{\"d\":cos(\"0\")}".into(),
        "{\"d\":tan(1,2)}".into(),
        "{\"b\":cos(0)}".into(),
        "{\"d\":0x1p4,\"i\":0x10}".into(),
        "{\"d\":\"0x10\"}".into(),
        "{\"d\":.5,\"b\":-.5}".into(),
        "{\"d\":1.,\"b\":1e5}".into(),
        "{\"b\":1.2.3}".into(),
        "{\"b\":+5,\"d\":+inf}".into(),
        "{\"a\":'single',\"b\":\"\\x41\"}".into(),
        "{\"a\":\"\\xff\"}".into(),
        "{\"a\":\"\\q\"}".into(),
        "{\"a\":\"\\ud800x\"}".into(),
        "{\"a\":\"\\udc00\"}".into(),
        "{\"a\":\"\\ud800\\ud800\"}".into(),
        "{\"a\":\"\\u12\"}".into(),
        "/// doc\n{\"a\":\"x\"}".into(),
        "{\"a\":\"x\"} /// doc".into(),
        "{\"a\":\"x\"} // trailing".into(),
        "{\"a\":\"x\"} /* open".into(),
        "{\"a\":\"x\"} {}".into(),
        "{\"a\":\"x\"};".into(),
        "{\"a\":@}".into(),
        "{\"a\":\"\u{e9}\"}".into(),
        "[1,2]".into(),
        "{\"i\":[\"s\",5,null]}".into(),
        "{\"l\":[{\"s\":\"a\",\"n\":1},{\"s\":\"b\",\"n\":2},[\"c\",3]],\"i\":{\"s\":\"z\"}}".into(),
        "{\"l\":[[\"c\",3,4]]}".into(),
        "{\"l\":[[\"c\"]]}".into(),
        "{\"i\":null,\"l\":null}".into(),
        "{\"a\":null,\"b\":null}".into(),
        "{\"e\":[1,2],\"v\":[\"Red\",\"B\",2]}".into(),
        "{\"x\":{\"a\":{\"b\":{\"c\":{\"d\":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}}}}}".into(),
        "{\"x\":[{},[],\"s\",1,1.5,true,false,null,inf,-inf]}".into(),
        "{\"x\":nan}".into(),
        "{\"x\":-}".into(),
        "{\"x\":?}".into(),
        "{\"u\":{\"x\":1},\"u_type\":\"X\"}".into(),
        "{\"u\":{\"x\":1}".into(),
        "{\"u\":{\"x\":1},}".into(),
        "{\"u\":{\"x\":1},\"other\":2,\"u_type\":\"X\"}".into(),
        "{u:{z:3},u_type:X,b:2,a:\"s\"}".into(),
        "{\"u2\":{\"y\":\"q\"},\"u2_type\":\"B\",\"u\":{\"x\":1},\"u_type\":\"A\"}".into(),
        "{\"u_type\":\"A B\",\"u\":{}}".into(),
        "{\"e\":\"A\",\"v\":\"B\"}".into(),
        "{\"e\":\"E.C\",\"v\":[\"E.A\",\"C\"]}".into(),
        "table Z { q:int; } root_type Z; {\"q\":5}".into(),
        "namespace Q;".into(),
    ];
    let mut v = Vec::new();
    for s in &schemas {
        for m in &msgs {
            v.push(Case::F(true, s.as_bytes().to_vec(), Some(m.as_bytes().to_vec())));
        }
    }
    v.push(Case::F(true, schemas[0].as_bytes().to_vec(), None));
    v.push(Case::F(false, schemas[0].as_bytes().to_vec(), Some(b"{}".to_vec())));
    v
}

fn corpus() -> Vec<Case> {
    let mut v = Vec::new();
    for m in deltas() {
        v.push(j(SYS, &m));
        v.push(j(SYNC, &m));
    }
    for m in syncs() {
        v.push(j(SYNC, &m));
        v.push(j(SYS, &m));
    }
    for m in fims() {
        v.push(j(FIM, &m));
    }
    for (s, m) in edge_messages() {
        v.push(Case::J(true, s, ctx(), Some(b"v4.14.7".to_vec()), Some(m)));
    }
    // the context and the call's own errors
    let m = deltas()[0].as_bytes().to_vec();
    v.push(Case::J(true, SYS, ctx(), None, Some(m.clone())));
    v.push(Case::J(true, SYS, None, None, Some(m.clone())));
    v.push(Case::J(true, SYS, ctx(), Some(b"v".to_vec()), None));
    v.push(Case::J(false, SYS, ctx(), Some(b"v".to_vec()), Some(m.clone())));
    v.push(Case::J(true, 0, ctx(), Some(b"v".to_vec()), Some(m.clone())));
    v.push(Case::J(true, 4, ctx(), Some(b"v".to_vec()), Some(m.clone())));
    v.push(Case::J(true, -1, ctx(), Some(b"v".to_vec()), None));
    v.push(Case::J(true, SYS, Some([b"0\"1".to_vec(), b"n\\".to_vec(), b"".to_vec()]), Some(b"v\"".to_vec()), Some(m.clone())));
    v.push(Case::J(true, SYS, Some([b"0\x001".to_vec(), b"\xff".to_vec(), b"x".to_vec()]), Some(b"\x00".to_vec()), Some(m.clone())));
    v.push(Case::J(true, SYS, Some([b"".to_vec(), b"".to_vec(), b"".to_vec()]), Some(b"".to_vec()), Some(m)));
    v.extend(fb_cases());
    v
}

const CHARSET: &[u8] = b"{}[],:\"\\ 0123456789.-+eExabnulltrufs_/*'\n\t\x00\xff\xc3";

fn mutate(rng: &mut Rng, m: &[u8]) -> Vec<u8> {
    let mut m = m.to_vec();
    let n = 1 + rng.below(4);
    for _ in 0..n {
        let op = rng.below(5);
        let pos = if m.is_empty() { 0 } else { rng.below(m.len() + 1) };
        let c = CHARSET[rng.below(CHARSET.len())];
        match op {
            0 if pos < m.len() => m[pos] = c,
            1 => m.insert(pos, c),
            2 if pos < m.len() => {
                m.remove(pos);
            }
            3 if pos < m.len() => {
                // duplicate a slice
                let end = (pos + 1 + rng.below(12)).min(m.len());
                let s = m[pos..end].to_vec();
                let at = rng.below(m.len() + 1);
                for (k, b) in s.into_iter().enumerate() {
                    m.insert(at + k, b);
                }
            }
            _ => {
                // swap in a token
                const TOK: &[&str] = &["null", "1.5", "-1", "\"x\"", "{}", "[]", "1e999", "cos(1)", "\"0x1f\"", "nan", "\"dbsync_hwinfo\"", "\"state\""];
                let t = TOK[rng.below(TOK.len())];
                for (k, b) in t.bytes().enumerate() {
                    m.insert(pos + k, b);
                }
            }
        }
    }
    m
}

const KEYS: &[&str] = &[
    "data_type", "attributes_type", "attributes", "type", "data", "$schema", "component", "ID", "timestamp", "index", "path",
    "agent_info", "agent_id", "id", "begin", "end", "checksum", "cpu_mhz", "cpu_cores", "size", "name", "version", "pid",
    "user_id", "user_created", "login_status", "changed_attributes", "old_attributes", "mode", "value_name", "arch", "inode",
    "mtime", "process_pid", "tail", "zz", "", "a b", "\u{e9}",
];

fn random_value(rng: &mut Rng, depth: usize) -> Element {
    const STRS: &[&str] = &[
        "", "x", "\0", "\u{e9}", "\"", "12", " 12", "12 ", "0x1f", "-0x1f", "true", "null", "nan", "inf", "-inf", "1e5", "1.5",
        "dbsync_osinfo", "dbsync_packages", "state", "integrity_clear", "syscollector_packages", "fim_file", "fim_registry_key",
        "NONE", "dbsync_osinfo dbsync_hwinfo", "cos(1)", "18446744073709551615", "-9223372036854775809", "a\\b", "\n",
    ];
    match rng.below(if depth > 3 { 9 } else { 12 }) {
        0 => Element::Null,
        1 => Element::Bool(rng.below(2) == 0),
        2 => Element::Int64([0, 1, -1, 255, 256, 65536, i64::MAX, i64::MIN, 2147483648, -129][rng.below(10)]),
        3 => Element::Uint64(u64::MAX - rng.below(3) as u64),
        4 => Element::Double([0.5, -0.0, 1e300, 1e-300, 3.0, 2.5e15, 123456.789, -1e20, 5e-324][rng.below(9)]),
        5..=8 => Element::Str(STRS[rng.below(STRS.len())].as_bytes().to_vec()),
        9 => Element::Array((0..rng.below(4)).map(|_| random_value(rng, depth + 1)).collect()),
        _ => Element::Object((0..rng.below(4)).map(|_| (KEYS[rng.below(KEYS.len())].as_bytes().to_vec(), random_value(rng, depth + 1))).collect()),
    }
}

/// A structural mutation that keeps the JSON valid.
fn smutate(rng: &mut Rng, e: &mut Element, depth: usize) {
    match e {
        Element::Object(o) if !o.is_empty() && (depth == 0 || rng.below(3) != 0) => {
            let i = rng.below(o.len());
            match rng.below(6) {
                0 => o[i].1 = random_value(rng, depth),
                1 => o[i].0 = KEYS[rng.below(KEYS.len())].as_bytes().to_vec(),
                2 => {
                    o.remove(i);
                }
                3 => {
                    let k = (KEYS[rng.below(KEYS.len())].as_bytes().to_vec(), random_value(rng, depth));
                    let at = rng.below(o.len() + 1);
                    o.insert(at, k);
                }
                4 => {
                    let d = o[i].clone();
                    o.push(d);
                }
                _ => smutate(rng, &mut o[i].1, depth + 1),
            }
        }
        Element::Array(a) if !a.is_empty() && rng.below(3) != 0 => {
            let i = rng.below(a.len());
            smutate(rng, &mut a[i], depth + 1)
        }
        _ => *e = random_value(rng, depth),
    }
}

fn smutate_text(rng: &mut Rng, m: &[u8]) -> Option<Vec<u8>> {
    let mut e = sjson::parse(m).ok()?;
    for _ in 0..1 + rng.below(3) {
        smutate(rng, &mut e, 0);
    }
    let mut out = Vec::new();
    e.append_to(&mut out);
    Some(out)
}

#[test]
fn fb_matches_oracle() {
    let mut cases = corpus();
    let base = cases.clone();
    let fuzz: usize = std::env::var("SIEM_FB_FUZZ").ok().and_then(|s| s.parse().ok()).unwrap_or(2000);
    let seed: u64 = std::env::var("SIEM_FB_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x2545_F491_4F6C_DD1D));
    let js: Vec<Case> = base.iter().filter(|c| matches!(c, Case::J(..))).cloned().collect();
    // F cases over the schemas that parse
    let fs: Vec<Case> = base
        .iter()
        .filter(|c| match c {
            Case::F(_, s, _) => siem_router::fb::Parser::new().parse(s),
            _ => false,
        })
        .cloned()
        .collect();
    for _ in 0..fuzz {
        let pick = if rng.below(10) < 7 { &js[rng.below(js.len())] } else { &fs[rng.below(fs.len())] };
        match pick.clone() {
            Case::J(h, s, c, v, Some(m)) => {
                let m2 = if rng.below(3) != 0 { smutate_text(&mut rng, &m) } else { None };
                cases.push(Case::J(h, s, c, v, Some(m2.unwrap_or_else(|| mutate(&mut rng, &m)))))
            }
            Case::F(h, s, Some(m)) => {
                if rng.below(4) == 0 {
                    cases.push(Case::F(h, mutate(&mut rng, &s), Some(m)));
                } else {
                    cases.push(Case::F(h, s, Some(mutate(&mut rng, &m))));
                }
            }
            c => cases.push(c),
        }
    }
    let input: String = cases.iter().map(|c| c.line() + "\n").collect();
    let rust = run_rust(&cases);
    assert_eq!(groups(&rust).len(), cases.len());
    let Ok(cmd) = std::env::var("SIEM_FB_ORACLE") else {
        eprintln!("SIEM_FB_ORACLE not set: {} cases run on the Rust side only", cases.len());
        return;
    };
    let oracle = run_oracle(&cmd, &input);
    if let Ok(dir) = std::env::var("SIEM_FB_KEEP") {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(format!("{dir}/input.txt"), &input);
        let _ = std::fs::write(format!("{dir}/rust.txt"), rust.join("\n"));
        let _ = std::fs::write(format!("{dir}/oracle.txt"), oracle.join("\n"));
    }
    let (rg, og) = (groups(&rust), groups(&oracle));
    let mut diffs = 0;
    for (i, c) in cases.iter().enumerate() {
        let r = rg.get(i).cloned().unwrap_or_default();
        let o = og.get(i).cloned().unwrap_or_default();
        if r != o {
            diffs += 1;
            if diffs <= 20 {
                eprintln!("--- diff #{diffs} case {i}: {}", String::from_utf8_lossy(&unhex(c.line().rsplit(' ').next().unwrap())).chars().take(400).collect::<String>());
                for l in &r {
                    eprintln!("  rust:   {}", decode(l));
                }
                for l in &o {
                    eprintln!("  oracle: {}", decode(l));
                }
            }
        }
    }
    eprintln!("{} cases, {} with differences", cases.len(), diffs);
    assert_eq!(diffs, 0);
}
