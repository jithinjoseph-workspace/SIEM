//! Differential test of the daemon's event path against Wazuh's real
//! analysisd code compiled from C (tools/oracle/ad_harness.c): queue
//! message -> OS_CleanMSG -> DecodeEvent -> w_process_event_thread ->
//! alerts.log, alerts.json, archives.log, archives.json, firewall.log,
//! active-response messages, runtime errors/warnings and ar.conf, compared
//! byte for byte with a pinned clock and UTC.
//!
//! Env:
//!   SIEM_AD_ORACLE       command line of the oracle, e.g.
//!                        "wsl -d Ubuntu-20.04 --cd /home/u/oracle_build -- env TZ=UTC ./ad_oracle home_ad"
//!                        (ORACLE_TIME is appended by the test through `env`)
//!   SIEM_TEST_HOME       Rust-side Wazuh home (same ruleset and etc/ossec.conf
//!                        as the oracle's, including the AR blocks)
//!   SIEM_TEST_CASES      cases.json from tools/make_test_home.py
//!   SIEM_ORACLE_MANAGER  hostname of the oracle machine (manager.name)
//!   SIEM_AD_REPEAT       times the case stream is fed (default 2)
//!   SIEM_AD_FUZZ         number of mutated messages (default 5000)

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use siem_analysisd::ar::{AgentVersion, ArBackend};
use siem_analysisd::daemon::{Analysis, Env};
use siem_analysisd::daemon_config::AnalysisdConfig;
use siem_analysisd::engine::Clock;
use siem_analysisd::event::TimeSpec;
use siem_analysisd::labels::{Label, LabelFlags};
use siem_cjson::Json;

const ORACLE_TIME: i64 = 1759658400; // 2025-10-05 10:00:00 UTC (a Sunday)

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct FixedClock(i64);
impl Clock for FixedClock {
    fn now(&self) -> TimeSpec {
        TimeSpec { sec: self.0, nsec: 0 }
    }
}

/// The harness's fake world (labels_find, wazuh-db, node name, AR queues).
#[derive(Default)]
struct TestEnv {
    ar_log: Vec<u8>,
    mq_log: Vec<u8>,
    local_log: Vec<u8>,
    wdb_log: Vec<u8>,
    wdb_seen: std::collections::HashSet<Vec<u8>>,
}

/// `atoi` (int overflow wraps like the C conversion of a long)
fn atoi(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'-') | Some(b'+')) {
        i += 1;
    }
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() && v < (1 << 40) {
        v = v * 10 + (s[i] - b'0') as i64;
        i += 1;
    }
    (if neg { -v } else { v }) as i32
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

impl TestEnv {
    /// The harness's fake wazuh-db (`wdbc_query_ex` in ad_harness.c).
    fn wdb(&mut self, q: &[u8], len: usize) -> Result<Vec<u8>, i32> {
        self.wdb_log.extend_from_slice(q);
        self.wdb_log.push(b'\n');
        if sysc_query(q) {
            if find(q, b"wdbfail").is_some() {
                return Err(-1);
            }
            let mut r: Vec<u8> = if find(q, b"wdberr").is_some() {
                b"err db".to_vec()
            } else if find(q, b"wdbbad").is_some() {
                b"bad response".to_vec()
            } else if find(q, b"wdbok").is_some() {
                b"ok".to_vec()
            } else {
                b"ok done".to_vec()
            };
            r.truncate(len - 1);
            return Ok(r);
        }
        let mut r: Vec<u8> = if let Some(p) = find(q, b" rootcheck save ") {
            let rest = &q[p + b" rootcheck save ".len()..];
            let after = rest.iter().position(|&c| c == b' ').map(|i| &rest[i + 1..]).unwrap_or(b"");
            let agent_end = q[6..].iter().position(|&c| c == b' ').map(|i| 6 + i).unwrap_or(q.len());
            let key = [&q[6..agent_end], b"|", after].concat();
            if self.wdb_seen.insert(key) {
                b"ok 2".to_vec()
            } else {
                b"ok 1".to_vec()
            }
        } else if let Some(p) = find(q, b" syscheck load ") {
            let f = &q[p + 15..];
            let has = |n: &[u8]| find(f, n).is_some();
            let r: &[u8] = if has(b"nodb") {
                b"err db"
            } else if has(b"badresp") {
                b"okay"
            } else if has(b"new") {
                b"ok "
            } else if has(b"win") {
                b"ok 100:|Administrators,0,2032127:S-1-5:S-1-5-18:aaa:bbb:root:root:1600000000:10:ccc:ARCHIVE!0:1600000000"
            } else if has(b"same") {
                b"ok 100:33188:0:0:aaa:bbb:root:root:1600000000:10:ccc"
            } else {
                b"ok 100:33188:0:0:aaa:bbb:root:root:1600000000:10:ccc!2:1600000000:/sym\\:old"
            };
            r.to_vec()
        } else if find(q, b" syscheck scan_info_get ").is_some() {
            let a = &q[6..];
            let start = find(q, b"start_scan").is_some();
            let r: &[u8] = if a.starts_with(b"001 ") {
                if start { b"ok 5" } else { b"ok 1600000000" }
            } else if a.starts_with(b"002 ") {
                b"ok 0"
            } else if a.starts_with(b"003 ") {
                b"err"
            } else if start {
                b"ok 5"
            } else {
                b"ok 1759658401"
            };
            r.to_vec()
        } else if let Some(p) = find(q, b" sca ") {
            let a = &q[p + 5..];
            let has = |n: &[u8]| find(a, n).is_some();
            let r: &[u8] = if a.starts_with(b"query ") {
                let id = atoi(&a[6..]);
                if id == 13 {
                    b"err db"
                } else if id % 3 == 0 {
                    b"ok not found"
                } else if id % 3 == 1 {
                    b"ok found passed"
                } else {
                    b"ok found failed"
                }
            } else if a.starts_with(b"query_scan ") {
                if has(b"_new") {
                    b"ok not found"
                } else if has(b"bad") {
                    b"err db"
                } else {
                    b"ok found aaaa 7"
                }
            } else if a.starts_with(b"query_policy_sha256 ") {
                b"ok found hf1"
            } else if a.starts_with(b"query_policy ") {
                if has(b"_new") { b"ok not found" } else { b"ok found" }
            } else if a.starts_with(b"query_results ") {
                if has(b"_empty") {
                    b"ok not found"
                } else if has(b"bad") {
                    b"err db"
                } else {
                    b"ok found aaaa"
                }
            } else if a.starts_with(b"query_policies ") {
                b"ok found cis_debian,old_policy,keep_policy"
            } else if a.starts_with(b"delete_policy ") {
                if has(b"keep") { b"err no" } else { b"ok" }
            } else {
                b"ok"
            };
            r.to_vec()
        } else if find(q, b" save2 ").is_some() || find(q, b" integrity_clear ").is_some() || find(q, b" integrity_check_").is_some() {
            if find(q, b"Agent404").is_some() {
                b"err Agent not found".to_vec()
            } else if find(q, b"dberr").is_some() {
                b"err broken".to_vec()
            } else if find(q, b"noanswer").is_some() {
                b"ok ".to_vec()
            } else if find(q, b"\"checksum\":\"bad").is_some() {
                b"ok checksum_fail".to_vec()
            } else {
                b"ok".to_vec()
            }
        } else if find(q, b" ciscat save ").is_some() {
            if find(q, b" ciscat save NULL|").is_some() {
                b"err no scan id".to_vec()
            } else {
                b"ok".to_vec()
            }
        } else {
            b"err unknown query".to_vec()
        };
        r.truncate(len - 1);
        Ok(r)
    }
}

/// The syscollector queries ("agent <id> <command> ...").
fn sysc_query(q: &[u8]) -> bool {
    const CMDS: &[&[u8]] = &[
        b"netinfo ", b"netproto ", b"netaddr ", b"osinfo ", b"hardware ", b"port ", b"package ", b"hotfix ", b"process ", b"dbsync ",
    ];
    if !q.starts_with(b"agent ") {
        return false;
    }
    let Some(sp) = q[6..].iter().position(|&c| c == b' ').map(|i| 6 + i) else {
        return false;
    };
    CMDS.iter().any(|c| q[sp + 1..].starts_with(c))
}

fn agent_version(id: &[u8]) -> Option<&'static str> {
    match id {
        b"002" => Some("Wazuh v4.1.0"),
        b"003" => Some("Wazuh v4.2.3"),
        b"004" => None,
        _ => Some("Wazuh v4.14.7"),
    }
}

fn label(k: &str, v: &str, hidden: bool, system: bool) -> Label {
    Label { key: k.as_bytes().to_vec(), value: v.as_bytes().to_vec(), flags: LabelFlags { hidden, system } }
}

impl TestEnv {
    /// labels_find: agent 000 has the (empty) configured labels
    fn labels(&self, agent_id: &[u8]) -> Vec<Label> {
        if agent_id == b"000" {
            return Vec::new();
        }
        let mut l = Vec::new();
        if let Some(v) = agent_version(agent_id) {
            l.push(label("_wazuh_version", v, false, true));
        }
        l.push(label("env", "test", false, false));
        l.push(label("secret", "s3", true, false));
        l
    }
}

/// Collects what `Env::log` receives (needs `&self`, so log through a cell).
struct LoggingEnv {
    inner: TestEnv,
    log: std::cell::RefCell<Vec<u8>>,
}

impl Env for LoggingEnv {
    fn labels(&mut self, agent_id: &[u8]) -> Vec<Label> {
        self.inner.labels(agent_id)
    }
    fn wdb_query_ex(&mut self, query: &[u8], len: usize) -> Result<Vec<u8>, i32> {
        self.inner.wdb(query, len)
    }
    fn send_mq(&mut self, path: &str, msg: &[u8]) -> bool {
        let l = &mut self.inner.mq_log;
        l.extend_from_slice(path.as_bytes());
        l.push(b'|');
        l.extend_from_slice(msg);
        l.push(b'\n');
        true
    }
    fn send_local(&mut self, path: &str, msg: &[u8]) -> Result<(), (i32, String)> {
        let l = &mut self.inner.local_log;
        l.extend_from_slice(path.as_bytes());
        l.push(b'|');
        l.extend_from_slice(msg);
        l.push(b'\n');
        Ok(())
    }
    fn log(&self, level: &str, msg: &[u8]) {
        // the harness records errors and warnings only
        if level != "ERROR" && level != "WARNING" {
            return;
        }
        let mut l = self.log.borrow_mut();
        l.extend_from_slice(format!("{level}: ").as_bytes());
        l.extend_from_slice(msg);
        l.push(b'\n');
    }
    fn ar(&mut self) -> &mut dyn ArBackend {
        &mut self.inner
    }
    fn agents_of_node(&mut self, _last_id: i32, _limit: i32) -> Option<Vec<i32>> {
        Some(vec![1, 2, 3, 4])
    }
    fn wdb_json(&mut self, query: &str) -> Option<Json> {
        fake_mitre(query).and_then(|r| siem_cjson::parse(r.as_bytes()))
    }
}

/// The harness's MITRE matrix (`fake_mitre` in ad_harness.c).
fn fake_mitre(q: &str) -> Option<String> {
    if q.contains("OFFSET 0;") {
        return Some(
            r#"[{"id":"ap-1","name":"Password Guessing","external_id":"T1110.001"},{"id":"ap-2","name":"SSH","external_id":"T1021.004"},{"id":"ap-3","name":"Valid Accounts","external_id":"T1078"},{"id":"ap-4","name":"Brute Force","external_id":"T1110"},{"id":"ap-5","name":"Broken","external_id":"T1484"}]"#
                .into(),
        );
    }
    if q.contains("OFFSET") {
        return Some("[]".into());
    }
    if q.contains("tech_id = 'ap-1'") || q.contains("tech_id = 'ap-4'") {
        return Some(r#"[{"tactic_id":"ta-6"}]"#.into());
    }
    if q.contains("tech_id = 'ap-2'") {
        return Some(r#"[{"tactic_id":"ta-8"}]"#.into());
    }
    if q.contains("tech_id = 'ap-3'") {
        return Some(r#"[{"tactic_id":"ta-1"},{"tactic_id":"ta-3"},{"tactic_id":"ta-4"},{"tactic_id":"ta-5"}]"#.into());
    }
    if q.contains("tech_id = ") {
        return Some("[]".into());
    }
    if let Some(p) = q.find("tactic.id = 'ta-") {
        let rest = &q[p + "tactic.id = 'ta-".len()..];
        let n: i32 = rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0);
        return Some(format!(r#"[{{"name":"Tactic {n}","external_id":"TA{n:04}"}}]"#));
    }
    None
}

impl ArBackend for TestEnv {
    fn agent_version(&mut self, agent_id: i32) -> AgentVersion {
        let id = format!("{agent_id:03}");
        match agent_version(id.as_bytes()) {
            Some(v) => AgentVersion::Found(v.to_string()),
            None => AgentVersion::NoInfo,
        }
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        Some(vec![1, 2, 3, 4])
    }
    fn node_name(&mut self) -> String {
        "node01".into()
    }
    fn send_exec(&mut self, msg: &[u8]) {
        self.ar_log.extend_from_slice(msg);
        self.ar_log.push(b'\n');
    }
    fn send_ar(&mut self, msg: &[u8]) {
        self.ar_log.extend_from_slice(msg);
        self.ar_log.push(b'\n');
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn n(&mut self, m: usize) -> usize {
        if m == 0 {
            0
        } else {
            (self.next() % m as u64) as usize
        }
    }
}

const LOCATIONS: &[&str] = &[
    "stdin",
    "/var/log/auth.log",
    "[001] (agent1) 10.0.0.5->/var/log/secure",
    "[002] (web) any->/var/log/nginx/access.log",
    "[003] (db) 10.0.0.7->/var/log/messages",
    "[004] (win) any->EventChannel",
    "(agentless) root@10.0.0.1->ssh_integrity_check",
    "[005] (bad",
    "ossec-keepalive",
    "[001] (agent1) any->ossec-keepalive",
];

const MQ: &[u8] = b"1124";

/// Syscollector agent messages (legacy inventory and dbsync deltas)
const SYSCOLLECTOR_LOGS: &[&str] = &[
    r#"{"type":"network","ID":1001,"timestamp":"2025/01/01 00:00:00","iface":{"name":"eth0","adapter":"Intel","type":"ethernet","state":"up","MAC":"02:42:ac:11:00:02","tx_packets":10,"rx_packets":20,"tx_bytes":3000,"rx_bytes":4000,"tx_errors":0,"rx_errors":1,"tx_dropped":2,"rx_dropped":3,"MTU":1500,"IPv4":{"address":["10.0.0.2","10.0.0.3"],"netmask":["255.255.255.0"],"broadcast":["10.0.0.255","10.0.0.254"],"gateway":"10.0.0.1","dhcp":"enabled","metric":100},"IPv6":{"address":["fe80::1","fe80::2"],"netmask":["ffff:ffff:ffff:ffff::","ffff::"],"broadcast":["x"],"gateway":"fe80::ff","dhcp":"disabled","metric":5}}}"#,
    r#"{"type":"network","ID":1002,"iface":{"name":"wdberr0","MTU":1e12,"tx_packets":-3.7}}"#,
    r#"{"type":"network","timestamp":"t","iface":{"name":"lo","IPv4":{"address":["127.0.0.1",5,"x"],"netmask":{"a":"255.0.0.0"},"broadcast":"b","metric":"1"}}}"#,
    r#"{"type":"network","ID":1003,"iface":{"name":"eth1","IPv4":{"address":["1.1.1.1"],"gateway":"wdberr"},"IPv6":{"address":["::1"]}}}"#,
    r#"{"type":"network","ID":1004,"iface":{"name":"eth2","IPv4":{"address":["1.1.1.1","wdbfail"],"netmask":["a,b",""]}}}"#,
    r#"{"type":"network","ID":1005,"iface":{"IPv6":{"address":["::1",""],"netmask":["",""],"broadcast":["",""]}}}"#,
    r#"{"type":"network_end","ID":1001}"#,
    r#"{"type":"network_end","ID":"1001"}"#,
    r#"{"type":"network_end","ID":1006,"x":"wdberr"}"#,
    r#"{"type":"network"}"#,
    r##"{"type":"OS","ID":7,"timestamp":"2025/01/01","inventory":{"os_name":"Ubuntu","os_version":"20.04.6 LTS (Focal Fossa)","os_codename":"focal","hostname":"host1","architecture":"x86_64","os_major":"20","os_minor":"04","os_build":"b","os_platform":"ubuntu","sysname":"Linux","release":"5.4.0","version":"#1 SMP","os_release":"r","os_patch":"6","os_display_version":"dv"}}"##,
    r#"{"type":"OS","inventory":{"os_name":"wdbfail","os_major":20}}"#,
    r#"{"type":"OS","ID":8,"inventory":{"hostname":"wdbbad"}}"#,
    r#"{"type":"OS","ID":9}"#,
    r#"{"type":"hardware","ID":3,"timestamp":"t","inventory":{"board_serial":"SN1","cpu_name":"Intel Xeon","cpu_cores":8,"cpu_mhz":2394.456,"ram_total":16384000,"ram_free":1e20,"ram_usage":42}}"#,
    r#"{"type":"hardware","ID":"3","inventory":{"cpu_mhz":-0.0000005,"ram_usage":99.9,"board_serial":"wdberr"}}"#,
    r#"{"type":"hardware"}"#,
    r#"{"type":"port","ID":77,"timestamp":"t","port":{"protocol":"tcp","local_ip":"0.0.0.0","local_port":22,"remote_ip":"1.2.3.4","remote_port":5555,"tx_queue":0,"rx_queue":1,"inode":12345,"state":"listening","PID":900,"process":"sshd"}}"#,
    r#"{"type":"port","ID":78,"port":{"protocol":"wdberr","local_port":"22"}}"#,
    r#"{"type":"port","ID":78,"port":{"protocol":"udp"}}"#,
    r#"{"type":"port_end","ID":78}"#,
    r#"{"type":"port","ID":79,"port":{"protocol":"udp","local_port":true}}"#,
    r#"{"type":"port_end","ID":79,"x":"wdbfail"}"#,
    r#"{"type":"port_end","ID":79}"#,
    r#"{"type":"port","port":{}}"#,
    r#"{"type":"port","ID":80}"#,
    r#"{"type":"program","ID":55,"timestamp":"t","program":{"format":"deb","name":"openssl","priority":"optional","group":"utils","size":1234,"vendor":"Ubuntu","install_time":"2024","version":"1.1.1f","architecture":"amd64","multi-arch":"same","source":"openssl","description":"Secure Sockets Layer toolkit","location":"/usr"}}"#,
    r#"{"type":"program","ID":56,"program":{"name":"wdberr"}}"#,
    r#"{"type":"program","ID":56,"program":{"name":"x"}}"#,
    r#"{"type":"program_end","ID":56}"#,
    r#"{"type":"program","ID":57,"program":{"version":5}}"#,
    r#"{"type":"program_end","ID":57}"#,
    r#"{"type":"program_end","ID":"57"}"#,
    r#"{"type":"hotfix","ID":9,"timestamp":"t","hotfix":"KB12345"}"#,
    r#"{"type":"hotfix","ID":9,"timestamp":"t","hotfix":"wdbfail"}"#,
    r#"{"type":"hotfix","ID":9,"hotfix":"KB1"}"#,
    r#"{"type":"hotfix_end","ID":9}"#,
    r#"{"type":"hotfix_end","ID":9.5,"x":"wdberr"}"#,
    r#"{"type":"hotfix_end"}"#,
    r#"{"type":"process","ID":11,"timestamp":"t","process":{"pid":1,"name":"systemd","state":"S","ppid":0,"utime":10,"stime":20,"cmd":"/sbin/init","argvs":["splash","--x",""],"euser":"root","ruser":"root","suser":"root","egroup":"root","rgroup":"root","sgroup":"root","fgroup":"root","priority":20,"nice":0,"size":100,"vm_size":200,"resident":300,"share":400,"start_time":500,"pgrp":1,"session":1,"nlwp":1,"tgid":1,"tty":0,"processor":3}}"#,
    r#"{"type":"process","ID":12,"process":{"name":"a","argvs":[]}}"#,
    r#"{"type":"process","ID":12,"process":{"name":"b","argvs":[1,{"a":"b"},"c"]}}"#,
    r#"{"type":"process","ID":13,"process":{"name":"wdberr"}}"#,
    r#"{"type":"process_end","ID":13}"#,
    r#"{"type":"process_end","ID":14}"#,
    r#"{"type":"process","ID":14,"process":"x"}"#,
    r#"{"type":"dbsync_packages","operation":"INSERTED","data":{"name":"curl","version":"7.68","size":123,"install_time":"t","multiarch":null,"groups":["a"],"scan_time":"x","checksum":"c"}}"#,
    r#"{"type":"dbsync_network_address","operation":"MODIFIED","data":{"iface":"eth0","proto":0,"address":"10.0.0.1","netmask":"255.0.0.0"}}"#,
    r#"{"type":"dbsync_network_address","operation":"DELETED","data":{"iface":"eth0","PROTO":1,"address":"::1"}}"#,
    r#"{"type":"dbsync_network_address","operation":"DELETED","data":{"iface":"eth0","proto":"ipv4"}}"#,
    r#"{"type":"dbsync_hwinfo","operation":"MODIFIED","data":{"cpu_mhz":2400.5,"ram_total":1e30,"cpu_cores":4,"ram_usage":-2.0}}"#,
    r##"{"type":"dbsync_osinfo","operation":"INSERTED","data":{"os_version":"20.04","version":"#1","hostname":"h"}}"##,
    r#"{"type":"dbsync_hotfixes","operation":"INSERTED","data":{"hotfix":"wdbok"}}"#,
    r#"{"type":"dbsync_hotfixes","operation":"INSERTED","data":{"hotfix":"wdberr"}}"#,
    r#"{"type":"dbsync_hotfixes","operation":"INSERTED","data":{"hotfix":"wdbfail"}}"#,
    r#"{"type":"dbsync_hotfixes","operation":"INSERTED","data":{"hotfix":"wdbbad"}}"#,
    r#"{"type":"dbsync_users","operation":"INSERTED","data":{"user_name":"root","user_id":0,"user_groups":"root,adm"}}"#,
    r#"{"type":"dbsync_groups","operation":"DELETED","data":{"group_id":0,"group_name":"root"}}"#,
    r#"{"type":"dbsync_browser_extensions","operation":"INSERTED","data":{"browser_name":"chrome","package_enabled":1}}"#,
    r#"{"type":"dbsync_services","operation":"INSERTED","data":{"service_id":"ssh","service_state":"running"}}"#,
    r#"{"type":"dbsync_processes","operation":"INSERTED","data":{"pid":"1","argvs":"a b"}}"#,
    r#"{"type":"dbsync_ports","operation":"INSERTED","data":{"local_port":22,"protocol":"tcp"}}"#,
    r#"{"type":"dbsync_network_iface","operation":"INSERTED","data":{"name":"eth0","mtu":1500}}"#,
    r#"{"type":"dbsync_network_protocol","operation":"INSERTED","data":{"iface":"eth0","type":"ipv4"}}"#,
    r#"{"type":"dbsync_unknown","operation":"INSERTED","data":{}}"#,
    r#"{"type":"dbsync_","operation":"INSERTED","data":{}}"#,
    r#"{"type":"dbsync__x","operation":"INSERTED","data":{}}"#,
    r#"{"type":"dbsync_osinfo","data":{}}"#,
    r#"{"type":"dbsync_osinfo","operation":"X","data":[]}"#,
    r#"{"type":"dbsync_hotfixes","operation":"OPERATION_THAT_IS_VERY_LONG_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","data":{"hotfix":"KB2"}}"#,
    r#"{"type":"foo"}"#,
    r#"{"type":5}"#,
    r#"{"ID":5}"#,
    r#"not json"#,
    r#"{"TYPE":"port","id":81,"PORT":{"Protocol":"tcp"}}"#,
];

/// Syscheck agent messages (legacy checksums, scan control and JSON events)
const SYSCHECK_LOGS: &[&str] = &[
    "fim-db-start-first-scan",
    "fim-db-end-first-scan",
    "fim-db-start-scan",
    "fim-db-end-scan",
    "syscheck-db-completed",
    "unknown-control",
    "100:33188:0:0:aaa:bbb:root:root:1600000000:10:ccc /etc/same",
    "200:33261:1000:1000:aa2:bb2:user:group:1600000500:11:cc2 /etc/passwd",
    "200:33188:0:0:aaa:bbb:ro\\ot:root:1600000000:10:ccc!0:root:0:root:/bin/vi:0:root:0:root:123:456:mytag:/sym\\:new: /etc/whodata",
    "100:420:0:0:aaa:bbb!0:r\\ oot:0:root:p\\!x:0:a:0:e:-:9:t:/s:+ /etc/silent",
    "-1 /etc/deleted",
    "-1!0:root:0:root:x:0:a:0:b:1:2 /etc/new_del",
    "300:33188:0:0:a:b:root:root:1:2:c /etc/new_file",
    "300:33188:0:0:a:b:root:root:1:2:c:16416 /etc/new_attrs",
    "300:|Users,0,1180063|Admins,1,268435456:S-1-5-32:S-1-5-18:a:b:Administrators:SYSTEM:1600000000:0:c:32 c:/windows/system32/x.dll",
    "300:|Users,0,1180063:S-1-5-32:S-1-5-18:aaa:bbb:root:root:1600000000:10:ccc:32 C:/win/same.dll",
    "a:b /etc/malformed",
    "100:33188:0:0:aaa:bbb:root:root:1600000000:10:ccc /etc/nodb",
    "100 /etc/badresp",
    "100:x:0:0:aaa:bbb:root:root:1700000000:99:ccc /etc/old/legacy\nchanged / content here",
    "999999999999:777:5:6:aaa:bbb:root:root:99999999999999:10:ccc /etc/huge",
    r#"{"type":"event","data":{"path":"/etc/hosts","version":2,"mode":"realtime","type":"modified","timestamp":1600000000,"attributes":{"type":"file","size":120,"perm":"rw-r--r--","uid":"0","gid":"0","user_name":"root","group_name":"root","inode":"123","mtime":1600000500,"hash_md5":"m2","hash_sha1":"s2","hash_sha256":"h2","checksum":"c","attributes":"ARCHIVE"},"old_attributes":{"type":"file","size":100,"perm":"rw-------","uid":"1","gid":"1","user_name":"bob","group_name":"bob","inode":122,"mtime":1600000000,"hash_md5":"m1","hash_sha1":"s1","hash_sha256":"h1","attributes":"HIDDEN","symlink_path":"/x"},"changed_attributes":["size","permission","uid","md5",5],"hard_links":["/a","/b"],"tags":"t1","content_changes":"diff","audit":{"user_id":"0","user_name":"root","process_name":"/bin/vi","ppid":1,"process_id":4321.7,"cwd":"/root","parent_name":"bash","parent_cwd":"/","audit_uid":"1","audit_name":"a","effective_uid":"0","effective_name":"root","group_id":"0","group_name":"root"}}}"#,
    r#"{"type":"event","data":{"path":"/etc/added","mode":"scheduled","type":"added","attributes":{"type":"file","size":1,"perm":{"S-1-5-18":{"name":"SYSTEM","allowed":["read_data","write_data"],"denied":["delete"]},"S-1-1":{"allowed":"x"},"S-1-2":{"denied":[]}},"mtime":1e30,"inode":-5}}}"#,
    r#"{"type":"event","data":{"path":"/etc/gone","mode":"whodata","type":"deleted","attributes":{"type":"file"},"audit":{"ppid":-1e30}}}"#,
    r#"{"type":"event","data":{"path":"HKEY_LOCAL_MACHINE\\System\\Key","version":3,"index":"abc123","arch":"[x64]","mode":"scheduled","type":"modified","attributes":{"type":"registry_key","perm":"x","uid":"S-1"},"old_attributes":{"type":"registry_key","perm":"y","uid":"S-2"}}}"#,
    r#"{"type":"event","data":{"path":"HKEY_LOCAL_MACHINE\\System\\Key","version":3,"index":"v1","arch":"[x32]","value_name":"Val","mode":"scheduled","type":"added","attributes":{"type":"registry_value","value_type":"REG_SZ","hash_md5":"m"}}}"#,
    r#"{"type":"event","data":{"path":"HKEY_LOCAL_MACHINE\\K","version":2,"mode":"scheduled","type":"deleted","attributes":{"type":"registry_value"}}}"#,
    r#"{"type":"event","data":{"path":"HKEY\\K","version":3,"type":"deleted","attributes":{"type":"registry_key"}}}"#,
    r#"{"type":"event","data":{"path":"/x","type":"renamed","attributes":{"type":"file"}}}"#,
    r#"{"type":"event","data":{"path":"/x","type":"added","attributes":{"type":"socket"}}}"#,
    r#"{"type":"event","data":{"path":"/x","type":"added"}}"#,
    r#"{"type":"event","data":[1]}"#,
    r#"{"type":"event","data":{"type":"added","attributes":{"type":"file"}}}"#,
    r#"{"type":"event","data":{"path":"/x","type":"added","attributes":{"type":"file","perm":["a"],"size":"s"},"audit":{"ppid":"7"}}}"#,
    r#"{"type":"scan_start","data":{"timestamp":1600000000}}"#,
    r#"{"type":"scan_end","data":{"timestamp":1.6e9}}"#,
    r#"{"type":"scan_end","data":{"timestamp":"x"}}"#,
    r#"{"type":"other","data":{}}"#,
    r#"{"data":{}}"#,
    r#"{"type":"event"}"#,
    r#"{bad json"#,
    r#"{"type":"event","data":{"path":"/very/long/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/file.txt","mode":"realtime","type":"modified","attributes":{"type":"file","size":2},"old_attributes":{"type":"file","size":1}}}"#,
    r#"{"type":"event","data":{"path":"/very/long/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/file.txt","version":3,"index":"i","arch":"[x64]","value_name":"vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv","mode":"realtime","type":"added","attributes":{"type":"registry_value"}}}"#,
    r#"{"type":"event","data":{"path":"/very/long/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/directory/file.txt","version":3,"index":"i","type":"added","attributes":{"type":"registry_key"}}}"#,
];

/// Agent upgrade module messages
const UPGRADE_LOGS: &[&str] = &[
    r#"{"command":"upgrade_update_status","parameters":{"error":0,"message":"Upgrade was successful","status":"Done"}}"#,
    r#"{"command":"upgrade_update_status","parameters":{"error":1,"agents":[3],"status":"Failed"}}"#,
    r#"{"command":"x","parameters":[1,2]}"#,
    r#"{"command":"x","parameters":"p"}"#,
    r#"{"command":"x"}"#,
    r#"broken"#,
];

/// Security configuration assessment agent messages
const SCA_LOGS: &[&str] = &[
    r#"{"type":"check","id":1234567,"policy":"CIS Benchmark for Debian/Linux","policy_id":"cis_debian","check":{"id":1001,"title":"Ensure separate partition exists for /tmp","description":"The /tmp directory is a world-writable directory.","rationale":"Making /tmp its own file system allows an administrator to set noexec.","remediation":"Configure /etc/fstab as appropriate.","compliance":{"cis":"1.1.2","cis_csc":"5.1","pci_dss":"2.2.4","nist_800_53":"CM.1","level":1,"weight":1.5},"rules":["c:mount -> r:\s/tmp\s","f:/etc/fstab -> r:/tmp","d:/etc -> x","r:HKLM -> y","p:sshd","n:x","z:bad",""],"condition":"all","command":"mount","file":"/etc/fstab,/etc/mtab","result":"failed"}}"#,
    r#"{"type":"check","id":1234567,"policy":"CIS","policy_id":"cis_debian","check":{"id":1002,"title":"Ensure nodev","directory":"/etc,,/var","registry":"HKLM\\x","process":"sshd","result":"passed","reason":"why"}}"#,
    r#"{"type":"check","id":-5,"policy":"CIS","policy_id":"cis_debian","check":{"id":1003,"title":"No result"}}"#,
    r#"{"type":"check","id":7.5,"policy":"CIS","policy_id":"cis_debian","check":{"id":1004.25,"title":"T","result":"not applicable","compliance":["a","b"]}}"#,
    r#"{"type":"check","id":7,"policy":"CIS","policy_id":"cis_debian","check":{"id":13,"title":"db error","result":"failed"}}"#,
    r#"{"type":"check","id":7,"policy":"CIS","policy_id":"cis_debian","check":{"id":1005,"title":"T","result":5}}"#,
    r#"{"type":"check","id":7,"policy":"CIS","policy_id":"cis_debian","check":{"id":1006,"title":3}}"#,
    r#"{"type":"check","id":"7","policy":"CIS","policy_id":"cis_debian","check":{"id":1006}}"#,
    r#"{"type":"check","id":7,"policy_id":"cis_debian"}"#,
    r#"{"type":"check","id":7,"policy":"CIS","policy_id":"cis_debian","check":{"id":1007,"title":"T","description":1}}"#,
    r#"{"type":"summary","scan_id":4242,"name":"CIS Benchmark for Debian/Linux","policy_id":"cis_debian","file":"cis_debian.yml","description":"desc","references":"https://x","passed":50,"failed":30,"invalid":2,"total_checks":82,"score":62,"start_time":1600000000,"end_time":1600000100,"hash":"bbbb","hash_file":"hf2","force_alert":"1"}"#,
    r#"{"type":"summary","scan_id":4243,"name":"New policy","policy_id":"cis_new_empty","file":"n.yml","passed":1,"failed":0,"invalid":0,"total_checks":1,"score":100,"start_time":1,"end_time":2,"hash":"aaaa","hash_file":"hf1","first_scan":1}"#,
    r#"{"type":"summary","scan_id":4244,"name":"New","policy_id":"x_new","file":"n.yml","description":5,"passed":-1,"failed":"x","invalid":0,"total_checks":1,"score":1.5,"start_time":1,"end_time":2,"hash":"zz","hash_file":"hf1"}"#,
    r#"{"type":"summary","scan_id":4245,"name":"Bad","policy_id":"bad_policy","file":"b.yml","passed":1,"failed":1,"invalid":1,"total_checks":3,"score":33,"start_time":1,"end_time":2,"hash":"aaaa","hash_file":"hf1"}"#,
    r#"{"type":"summary","scan_id":4246,"name":"Keep","policy_id":"keep_policy","file":"k.yml","passed":1,"failed":1,"invalid":1,"total_checks":3,"score":33,"start_time":1,"end_time":2,"hash":"aaaa","hash_file":"hfX","first_scan":0}"#,
    r#"{"type":"summary","scan_id":-1,"policy_id":"p"}"#,
    r#"{"type":"summary","scan_id":1,"policy_id":"p","start_time":1,"end_time":2,"passed":1,"failed":1,"invalid":1,"total_checks":1,"score":1,"hash":1}"#,
    r#"{"type":"summary","scan_id":"1","policy_id":"p"}"#,
    r#"{"type":"policies","policies":["cis_debian","keep_policy"]}"#,
    r#"{"type":"policies","policies":"cis_debian"}"#,
    r#"{"type":"policies"}"#,
    r#"{"type":"dump_end","elements_sent":3,"policy_id":"cis_debian","scan_id":4242}"#,
    r#"{"type":"dump_end","elements_sent":3,"policy_id":"x_empty","scan_id":"s"}"#,
    r#"{"type":"dump_end","policy_id":"cis_debian"}"#,
    r#"{"type":"other"}"#,
    r#"{"type":1}"#,
    r#"not json"#,
];

/// Windows eventchannel agent messages
const WINEVT_LOGS: &[&str] = &[
    r#"{"Message":"An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n\r\nFailure Information:\r\n\tFailure Reason:\t\tUnknown user name or bad password.\r\n   ","Event":"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2019-05-27T08:43:44.546418100Z'/><EventRecordID>8783</EventRecordID><Correlation ActivityID='{c4dca72a-1462-0000-1ea8-dcc46214d501}'/><Execution ProcessID='572' ThreadID='4920'/><Channel>Security</Channel><Computer>WIN-ABC</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='TargetUserName'>administrator</Data><Data Name='TargetDomainName'>WIN-ABC</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>10.0.0.9</Data><Data Name='IpPort'>0</Data><Data Name='ProcessName'>(NULL)</Data></EventData></Event>"}"#,
    r#"{"Message":"An account was successfully logged on.","Event":"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2019-05-27T08:43:44.546418100Z'/><EventRecordID>8784</EventRecordID><Execution ProcessID='572' ThreadID='4920'/><Channel>Security</Channel><Computer>WIN-ABC</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>bob  </Data><Data Name='LogonType'>10</Data><Data Name='IpAddress'>-</Data></EventData></Event>"}"#,
    r#"{"Message":"System audit policy was changed.","Event":"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4719</EventID><Level>0</Level><Keywords>0x8020000000000000</Keywords><Channel UserID='x'>Security</Channel></System><EventData><Data Name='SubjectUserName'>WIN$</Data><Data Name='CategoryId'>%%8274</Data><Data Name='SubcategoryId'>%%12801</Data><Data Name='SubcategoryGuid'>{0CCE921E-69AE-11D9-BED3-505054503030}</Data><Data Name='AuditPolicyChanges'>%%8449, %%8451, %%8448</Data></EventData></Event>"}"#,
    r#"{"Message":"Process Create:","Event":"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-01-01T00:00:00.000Z'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='CommandLine'>cmd.exe /c whoami</Data><Data Name='Hashes'>SHA1=AAAA</Data></EventData></Event>"}"#,
    r#"{"Message":"x","Event":"<Event><System><EventID>7036</EventID><Level>4</Level><Keywords>0x8080000000000000</Keywords><Provider EventSourceName='Service Control Manager'/></System><EventData><Data>Windows Update</Data><Data>running</Data><Data>(NULL)</Data><Data>-</Data><Binary>4100</Binary></EventData></Event>"}"#,
    r#"{"Event":"<Event><System><EventID>1102</EventID><Level>4</Level><Keywords>0x4020000000000000</Keywords></System><UserData><LogFileCleared xmlns='http://manifests'><SubjectUserName>admin</SubjectUserName><SubjectDomainName>-</SubjectDomainName></LogFileCleared></UserData></Event>"}"#,
    r#"{"Event":"<Event><System><EventID>4</EventID><Level>2</Level><Keywords>zz</Keywords></System><RenderingInfo Culture='en-US'><Message>m</Message><Level>Error</Level></RenderingInfo><UserData><A><B>c</B></A></UserData></Event>"}"#,
    r#"{"Event":"<Event><System><Level>0</Level><Keywords>0x10000000000000</Keywords><Provider/><TimeCreated/><Correlation/><Version></Version></System><EventData><Data Name='CategoryId'>%%8280</Data><Data Name='SubcategoryId'>%%99</Data><Data Other='q'>val</Data><Data Name='a' Other='b'>(NULL)</Data></EventData></Event>"}"#,
    r#"{"Event":"<Event><System><Level>9</Level><Keywords>1</Keywords></System><EventData><Data Name='auditPolicyChanges'>%%1, x</Data></EventData></Event>"}"#,
    r#"{"Event":5,"Message":7}"#,
    r#"{"Event":"<Event><System><Level>1</Level>"}"#,
    r#"{"event":"<x/>","message":"\"q\" \\t"}"#,
    r#"{"Message":"no event"}"#,
    r#"[1,2]"#,
];

/// Agent database synchronization messages
const DBSYNC_LOGS: &[&str] = &[
    r#"{"component":"fim_file","type":"integrity_check_global","data":{"id":1700000000,"begin":"/a","end":"/z","checksum":"bad0","tail":"/m"}}"#,
    r#"{"component":"syscollector_packages","type":"integrity_check_left","data":{"id":5,"begin":"a","end":"m","checksum":"abc","tail":"n","checksum":"x"}}"#,
    r#"{"component":"syscollector_processes","type":"integrity_check_right","data":{"id":6,"begin":"n","end":"z","checksum":"noanswer"}}"#,
    r#"{"component":"syscheck","type":"integrity_check_global","data":{"id":7,"checksum":"bad","Tail":"q"}}"#,
    r#"{"component":"fim_registry_key","type":"integrity_check_global","data":{"id":8,"checksum":"bad"}}"#,
    r#"{"component":"syscollector_hwinfo","type":"state","data":{"index":"0","attributes":{"cpu_name":"Intel"},"timestamp":"2024"}}"#,
    r#"{"component":"syscollector_osinfo","type":"state","data":{"id":"Agent404"}}"#,
    r#"{"component":"fim_file","type":"integrity_clear","data":{"id":9,"x":"dberr"}}"#,
    r#"{"component":"fim_file","type":"integrity_clear"}"#,
    r#"{"component":"syscollector_ports","type":"bogus","data":{}}"#,
    r#"{"component":"nope","type":"state","data":{}}"#,
    r#"{"component":5,"type":"state","data":{}}"#,
    r#"{"component":"fim_file"}"#,
    r#"{"COMPONENT":"syscheck","TYPE":"integrity_check_x","DATA":[1,2]}"#,
    r#"not json"#,
];

/// wodle_cis-cat messages
const CISCAT_LOGS: &[&str] = &[
    r#"{"type":"scan_info","scan_id":1468785238,"cis":{"benchmark":"CIS Ubuntu Linux 16.04 LTS Benchmark","profile":"Level 2 - Server","hostname":"ubuntu","timestamp":"2018-06-18T09:21:53.749+00:00","pass":96,"fail":79,"error":0,"unknown":1,"notchecked":71,"score":"54%"}}"#,
    r#"{"type":"scan_result","scan_id":1468785238,"cis":{"rule_id":"1.1.1.1","rule_title":"Ensure mounting of cramfs filesystems is disabled","group":"Initial Setup","description":"The cramfs filesystem type is a compressed read-only Linux filesystem.","rationale":"Removing support for unneeded filesystem types reduces the local attack surface.","remediation":"Edit or create the file /etc/modprobe.d/CIS.conf","result":"fail"}}"#,
    r#"{"type":"scan_result","scan_id":1468785238,"cis":{"rule_id":"1.1.2","rule_title":"Ensure separate partition exists for /tmp","group":"Initial Setup","result":"pass"}}"#,
    r#"{"type":"scan_info","cis":{"benchmark":"B","profile":"P","pass":"1","fail":2.9,"score":" -3"}}"#,
    r#"{"type":"scan_info","scan_id":"7","cis":"x"}"#,
    r#"{"type":"scan_info","scan_id":12}"#,
    r#"{"Type":"SCAN_INFO","scan_id":5,"CIS":{"pass":1}}"#,
    r#"{"type":5}"#,
    r#"{"type":"scan_result"} trailing"#,
    r#"not json"#,
];

/// Rootcheck agent messages (rootcheck/*.c, the system audit policies).
const ROOTCHECK_LOGS: &[&str] = &[
    "Starting rootcheck scan.",
    "Ending rootcheck scan.",
    "File '/dev/.blKb' present on /dev. Possible hidden file.",
    "Trojaned version of file '/bin/netstat' detected. Signature used: 'bash|^/bin/sh|/dev/[^n]|/usr/lib/libc.so' (Generic).",
    "Process '1234' hidden from /proc. Possible kernel level rootkit.",
    "Rootkit 'Adore' detected by the presence of file '/dev/.shit/red.tgz'.",
    "System Audit: CIS - RHEL 6 - 1.1.1: /tmp: No separate partition {CIS: 1.1.1 RHEL6} {PCI_DSS: 2.2.4}. File: /etc/fstab. Reference: https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.2.0.pdf .",
    "System Audit: SSH Hardening - 3: Root can log in. File: /etc/ssh/sshd_config. Reference: 3 .",
    "Port '1524' hidden. Kernel-level rootkit or trojaned version of netstat.",
    "Anomaly detected in file 'C:\\Windows\\x.dll'. Hidden from stats, but showing up on readdir. Possible kernel level rootkit.",
    "Windows Malware: Possible Malware - Inside: C:\\Windows\\cmd.exe. File: C:\\Windows\\cmd.exe.",
    " {PCI_DSS: 2.2.4}",
    "System Audit: x - y File: z.",
    "Files hidden inside directory '/usr'. Link count does not match number of files (10,9).",
];

const PREFIXES: &[&str] = &[
    "Dec 29 10:00:01 ",
    "2015 Dec 29 10:00:01 ",
    "2007-06-14T15:48:55-04:00 ",
    "Jan  1 00:00:00 host prog: ",
    "Jan  1 00:00:00 host prog[12]: [ID 123 auth.info] ",
    "",
];

fn mutate(r: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..1 + r.n(3) {
        match r.n(6) {
            0 => {
                let p = r.n(v.len() + 1);
                v.truncate(p);
            }
            1 => {
                if !v.is_empty() {
                    let p = r.n(v.len());
                    const SET: &[u8] = b" :[]{}\",.=-|/\\()<>0123456789aZ\t;$'`!";
                    v[p] = if r.n(4) == 0 { 0x80 + r.n(0x7f) as u8 } else { SET[r.n(SET.len())] };
                }
            }
            2 => {
                let pre = PREFIXES[r.n(PREFIXES.len())].as_bytes();
                let mut nv = pre.to_vec();
                nv.extend_from_slice(&v);
                v = nv;
            }
            3 => {
                if v.len() > 2 {
                    let a = r.n(v.len());
                    let b = (a + 1 + r.n(16)).min(v.len());
                    v.drain(a..b);
                }
            }
            4 => {
                if !v.is_empty() {
                    let a = r.n(v.len());
                    let b = (a + 1 + r.n(24)).min(v.len());
                    let seg = v[a..b].to_vec();
                    let p = r.n(v.len() + 1);
                    v.splice(p..p, seg);
                }
            }
            _ => {
                let p = r.n(v.len() + 1);
                v.insert(p, if r.n(2) == 0 { b'\n' } else { 0xc3 });
            }
        }
    }
    v.retain(|&c| c != 0);
    v
}

fn load_events(path: &str) -> Vec<String> {
    let data = std::fs::read(path).unwrap();
    let Json::Array(items) = siem_cjson::parse(&data).unwrap() else { panic!() };
    items
        .iter()
        .flat_map(|o| {
            o.get_exact("events")
                .unwrap()
                .children()
                .iter()
                .map(|e| String::from_utf8(e.as_bytes().unwrap().to_vec()).unwrap())
                .filter(|e| !e.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

const SECTIONS: &[&str] = &[
    "out/alerts.log",
    "out/alerts.json",
    "out/archives.log",
    "out/archives.json",
    "out/firewall.log",
    "out/ar.log",
    "out/messages.log",
    "etc/shared/ar.conf",
    "out/state.json",
    "var/run/wazuh-analysisd.state",
    "queue/fts/fts-queue",
    "out/getconfig.json",
    "out/asyscom.log",
    "out/wdb.log",
    "queue/fts/hostinfo",
    "out/local.log",
    "out/mq.log",
];

/// Split the oracle's "=== name" dump into sections.
fn parse_sections(out: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut m = HashMap::new();
    let mut cur: Option<String> = None;
    let mut buf = Vec::new();
    for line in out.split_inclusive(|&c| c == b'\n') {
        if let Some(name) = line.strip_prefix(b"=== ") {
            let name = String::from_utf8_lossy(name).trim_end().to_string();
            if SECTIONS.contains(&name.as_str()) {
                if let Some(c) = cur.take() {
                    m.insert(c, std::mem::take(&mut buf));
                }
                cur = Some(name);
                continue;
            }
        }
        buf.extend_from_slice(line);
    }
    if let Some(c) = cur {
        m.insert(c, buf);
    }
    m
}

/// Run the oracle; on a C crash drop the input that crashed and retry.
/// (b'A', queue message) or (b'Q', analysis socket request)
type Item = (u8, Vec<u8>);

fn run_oracle(cmd: &str, msgs: &mut Vec<Item>) -> HashMap<String, Vec<u8>> {
    loop {
        let mut input = Vec::new();
        for (k, m) in msgs.iter() {
            input.extend_from_slice(format!("{} {}\n", *k as char, hex(m)).as_bytes());
        }
        let mut parts = cmd.split_whitespace();
        let prog = parts.next().unwrap();
        let mut args: Vec<String> = parts.map(String::from).collect();
        // insert ORACLE_TIME right after "env" (or prefix with env)
        if let Some(p) = args.iter().position(|a| a == "env") {
            args.insert(p + 1, format!("ORACLE_TIME={ORACLE_TIME}"));
        }
        let mut child = Command::new(prog)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("oracle");
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        let sections = parse_sections(&out.stdout);
        if out.status.success() && sections.contains_key("etc/shared/ar.conf") {
            return sections;
        }
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err
            .lines()
            .filter_map(|l| l.strip_prefix("P "))
            .last()
            .and_then(|n| n.trim().parse::<usize>().ok())
            .unwrap_or_else(|| panic!("oracle failed before processing: {}", &err[err.len().saturating_sub(2000)..]));
        eprintln!("C oracle crashed on message {last} ({:?}); dropping it", String::from_utf8_lossy(&msgs[last].1));
        msgs.remove(last);
    }
}

fn first_diff(name: &str, c: &[u8], r: &[u8]) -> Option<String> {
    if c == r {
        return None;
    }
    let cl: Vec<&[u8]> = c.split(|&b| b == b'\n').collect();
    let rl: Vec<&[u8]> = r.split(|&b| b == b'\n').collect();
    for i in 0..cl.len().max(rl.len()) {
        let a = cl.get(i).copied().unwrap_or(b"<eof>");
        let b = rl.get(i).copied().unwrap_or(b"<eof>");
        if a != b {
            return Some(format!(
                "{name}: first difference at line {} (C {} lines, Rust {} lines)\n  C:    {}\n  Rust: {}",
                i + 1,
                cl.len(),
                rl.len(),
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b)
            ));
        }
    }
    Some(format!("{name}: differs"))
}

#[test]
fn analysisd_matches_c() {
    let Ok(cmd) = std::env::var("SIEM_AD_ORACLE") else {
        eprintln!("SIEM_AD_ORACLE not set; skipping");
        return;
    };
    let home = PathBuf::from(std::env::var("SIEM_TEST_HOME").expect("SIEM_TEST_HOME"));
    let cases = std::env::var("SIEM_TEST_CASES").expect("SIEM_TEST_CASES");
    let manager = std::env::var("SIEM_ORACLE_MANAGER").unwrap_or_else(|_| "localhost".into());
    let repeat: usize = std::env::var("SIEM_AD_REPEAT").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let fuzz: usize = std::env::var("SIEM_AD_FUZZ").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);

    // queue messages
    let events = load_events(&cases);
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut msgs: Vec<Item> = Vec::new();
    let mk = |rng: &mut Rng, ev: &[u8]| {
        let mut m = vec![MQ[rng.n(MQ.len())], b':'];
        m.extend_from_slice(LOCATIONS[rng.n(LOCATIONS.len())].as_bytes());
        m.push(b':');
        m.extend_from_slice(ev);
        m
    };
    for _ in 0..repeat {
        for e in &events {
            let m = mk(&mut rng, e.as_bytes());
            msgs.push((b'A', m));
        }
    }
    for _ in 0..fuzz {
        let base = events[rng.n(events.len())].as_bytes().to_vec();
        let ev = mutate(&mut rng, &base);
        let m = mk(&mut rng, &ev);
        msgs.push((b'A', m));
    }
    // host information events: a few hosts whose port lists change
    let hi_locs: &[&[u8]] = &[b"hostinfo", b"[001] (agent1) any->hostinfo"];
    let ports: &[&str] = &["22 (tcp) 80 (tcp)", "22 (tcp)", "22 (tcp) 80 (tcp)", "53 (udp)", ""];
    let n_hi = (fuzz / 10).max(60);
    for i in 0..n_hi {
        let ip = ["192.168.0.1", "192.168.0.10", "10.0.0.5", "fe80::1", "192.168.0.1 (gw)"][rng.n(5)];
        let mut log = format!("Host: {ip}, open ports: {}", ports[rng.n(ports.len())]).into_bytes();
        if i % 7 == 6 {
            log = mutate(&mut rng, &log);
        }
        let mut m = b"3:".to_vec();
        m.extend_from_slice(hi_locs[rng.n(hi_locs.len())]);
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // syscheck messages
    let sk_locs: &[&[u8]] = &[
        b"syscheck",
        b"[001] (agent1) any->syscheck",
        b"[002] (web) any->syscheck",
        b"[003] (db) any->syscheck-registry",
        b"[004] (win) any->syscheck",
    ];
    let n_sk = (fuzz / 3).max(SYSCHECK_LOGS.len() * 3);
    let sys_logs: Vec<Vec<u8>> = SYSCHECK_LOGS.iter().map(|l| l.as_bytes().to_vec()).collect();
    for i in 0..n_sk {
        let base = &sys_logs[i % sys_logs.len()][..];
        let log = if i < SYSCHECK_LOGS.len() * 3 { base.to_vec() } else { mutate(&mut rng, base) };
        let mut m = b"8:".to_vec();
        m.extend_from_slice(sk_locs[rng.n(sk_locs.len())]);
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // upgrade module messages
    for i in 0..(fuzz / 20).max(UPGRADE_LOGS.len() * 2) {
        let base = UPGRADE_LOGS[i % UPGRADE_LOGS.len()].as_bytes();
        let log = if i < UPGRADE_LOGS.len() * 2 { base.to_vec() } else { mutate(&mut rng, base) };
        let mut m = b"u:".to_vec();
        m.extend_from_slice(if i % 2 == 0 { b"[007] (lin) any->upgrade_module" } else { b"upgrade_module" });
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // SCA events
    let sca_locs: &[&[u8]] = &[b"[001] (agent1) any->sca", b"sca"];
    let n_sca = (fuzz / 6).max(SCA_LOGS.len() * 2);
    for i in 0..n_sca {
        let base = SCA_LOGS[i % SCA_LOGS.len()].as_bytes();
        let log = if i < SCA_LOGS.len() * 2 { base.to_vec() } else { mutate(&mut rng, base) };
        let mut m = b"p:".to_vec();
        m.extend_from_slice(sca_locs[if i < SCA_LOGS.len() * 2 { i % 2 } else { rng.n(sca_locs.len()) }]);
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // Syscollector events
    let sy_locs: &[&[u8]] = &[
        b"[001] (agent1) any->syscollector",
        b"syscollector",
        b"[002] (web) any->other",
        b"elsewhere",
        b"[003] (db) any>syscollector",
    ];
    let n_sy = (fuzz / 4).max(SYSCOLLECTOR_LOGS.len() * 2);
    for i in 0..n_sy {
        let base = SYSCOLLECTOR_LOGS[i % SYSCOLLECTOR_LOGS.len()].as_bytes();
        let log = if i < SYSCOLLECTOR_LOGS.len() * 2 { base.to_vec() } else { mutate(&mut rng, base) };
        let mut m = b"d:".to_vec();
        let loc = if i < SYSCOLLECTOR_LOGS.len() * 2 { i % 2 } else if rng.n(10) == 0 { rng.n(sy_locs.len()) } else { rng.n(2) };
        m.extend_from_slice(sy_locs[loc]);
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // Windows eventchannel events
    let we_locs: &[&[u8]] = &[b"[004] (win) any->EventChannel", b"EventChannel"];
    let n_we = (fuzz / 4).max(WINEVT_LOGS.len() * 2);
    for i in 0..n_we {
        let base = WINEVT_LOGS[i % WINEVT_LOGS.len()].as_bytes();
        let log = if i < WINEVT_LOGS.len() * 2 { base.to_vec() } else { mutate(&mut rng, base) };
        let mut m = b"f:".to_vec();
        m.extend_from_slice(we_locs[rng.n(we_locs.len())]);
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // dbsync messages
    let db_locs: &[&[u8]] = &[b"syscheck", b"[001] (agent1) any->syscheck", b"[002] (web) any->syscollector"];
    let n_db = (fuzz / 10).max(DBSYNC_LOGS.len() * 2);
    for i in 0..n_db {
        let base = DBSYNC_LOGS[i % DBSYNC_LOGS.len()].as_bytes();
        let log = if i < DBSYNC_LOGS.len() * 2 { base.to_vec() } else { mutate(&mut rng, base) };
        let mut m = b"5:".to_vec();
        m.extend_from_slice(db_locs[if i < DBSYNC_LOGS.len() * 2 { i % 2 } else { rng.n(db_locs.len()) }]);
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // CIS-CAT events
    let cc_locs: &[&[u8]] = &[b"wodle_cis-cat", b"[001] (agent1) any->wodle_cis-cat", b"[002] (web) any->wodle_cis", b"cis-cat", b"[003] (db)"];
    let n_cc = (fuzz / 10).max(CISCAT_LOGS.len() * 3);
    for i in 0..n_cc {
        let base = CISCAT_LOGS[i % CISCAT_LOGS.len()].as_bytes();
        let log = if i < CISCAT_LOGS.len() * 3 { base.to_vec() } else { mutate(&mut rng, base) };
        let mut m = b"e:".to_vec();
        m.extend_from_slice(if i < CISCAT_LOGS.len() * 2 { cc_locs[i % 2] } else { cc_locs[rng.n(cc_locs.len())] });
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // rootcheck events (each sent twice so both "inserted" and "updated" occur)
    let rk_locs: &[&[u8]] = &[b"rootcheck", b"[001] (agent1) any->rootcheck", b"[002] (web) 10.0.0.9->rootcheck"];
    let n_rk = (fuzz / 4).max(ROOTCHECK_LOGS.len() * 2);
    for i in 0..n_rk {
        let base = ROOTCHECK_LOGS[i % ROOTCHECK_LOGS.len()].as_bytes();
        let log = if i < ROOTCHECK_LOGS.len() * 2 { base.to_vec() } else { mutate(&mut rng, base) };
        let mut m = b"9:".to_vec();
        m.extend_from_slice(rk_locs[rng.n(rk_locs.len())]);
        m.push(b':');
        m.extend_from_slice(&log);
        let at = rng.n(msgs.len() + 1);
        msgs.insert(at, (b'A', m));
    }
    // analysis socket requests spread over the stream
    let requests: Vec<&str> = vec![
        r#"{"command":"getstats"}"#,
        r#"{"command":"getagentsstats","parameters":{"agents":[1,2,3,5]}}"#,
        r#"{"command":"getagentsstats","parameters":{"agents":"all","last_id":0}}"#,
        r#"{"command":"reload-ruleset"}"#,
        r#"{"command":"getconfig","parameters":{"section":"global"}}"#,
        r#"{"command":"getconfig","parameters":{"section":"active_response"}}"#,
        r#"{"command":"getconfig","parameters":{"section":"alerts"}}"#,
        r#"{"command":"getconfig","parameters":{"section":"internal"}}"#,
        r#"{"command":"getconfig","parameters":{"section":"command"}}"#,
        r#"{"command":"getconfig","parameters":{"section":"labels"}}"#,
        r#"{"command":"getconfig","parameters":{"section":"rule_test"}}"#,
        r#"{"command":"getconfig","parameters":{"section":"decoders"}}"#,
        r#"{"command":"getconfig","parameters":{"section":"rules"}}"#,
        "not json",
        "{}",
        r#"{"command":5}"#,
        r#"{"command":"nope"}"#,
        r#"{"command":"getconfig"}"#,
        r#"{"command":"getconfig","parameters":[]}"#,
        r#"{"command":"getconfig","parameters":{}}"#,
        r#"{"command":"getconfig","parameters":{"section":"nope"}}"#,
        r#"{"command":"getagentsstats"}"#,
        r#"{"command":"getagentsstats","parameters":{"agents":"x"}}"#,
        r#"{"command":"getagentsstats","parameters":{"agents":"all"}}"#,
        r#"{"command":"getagentsstats","parameters":{"agents":"all","last_id":-1}}"#,
        r#"{"command":"getagentsstats","parameters":{"agents":[1,"2"]}}"#,
        r#"{"command":"getagentsstats","parameters":{"agents":[]}}"#,
        r#"{"COMMAND":"GetStats"}"#,
        r#"{"Command":"getstats"} trailing"#,
        r#"{"command":"getstats\u0000x"}"#,
        r#"{"command":"reload-ruleset"}"#,
        r#"{"command":"getstats"}"#,
    ];
    let mut too_many = String::from(r#"{"command":"getagentsstats","parameters":{"agents":["#);
    too_many.push_str(&(1..=75).map(|i| i.to_string()).collect::<Vec<_>>().join(","));
    too_many.push_str("]}}");
    let mut reqs: Vec<Vec<u8>> = requests.iter().map(|r| r.as_bytes().to_vec()).collect();
    reqs.insert(3, too_many.into_bytes());
    let step = (msgs.len() / (reqs.len() + 1)).max(1);
    for (i, r) in reqs.into_iter().enumerate() {
        let at = ((i + 1) * step + i).min(msgs.len());
        msgs.insert(at, (b'Q', r));
    }
    eprintln!("{} queue messages and requests", msgs.len());

    let c = run_oracle(&cmd, &mut msgs);

    // Rust side, same configuration as the harness
    siem_analysisd::localtime::set_fixed_offset(Some(0));
    for d in ["logs", "queue/fts", "queue/diff"] {
        let _ = std::fs::remove_dir_all(home.join(d));
    }
    let mut cfg = AnalysisdConfig::load(&home, &home.join("etc/ossec.conf"), true).expect("config");
    cfg.global.logall = 1;
    cfg.global.logall_json = 1;
    cfg.global.jsonout_output = 1;
    cfg.global.alerts_log = 1;
    cfg.global.stats = 0;
    cfg.global.hide_cluster_info = 1;
    cfg.global.memorysize = 8192;
    cfg.global.custom_alert_output = 0;
    cfg.global.forwarders_list.clear();
    cfg.internal.decoder_order_size = 256;
    cfg.internal.log_fw = 1;
    cfg.labels.clear();
    cfg.cluster.node_name = Some("node01".into());
    let mut analysis = Analysis::new(cfg, &siem_analysisd::daemon::StderrLogger, true).unwrap_or_else(|e| panic!("ruleset: {e}"));
    analysis.engine.clock = Box::new(FixedClock(ORACLE_TIME));
    analysis.engine.cfg.shost = b"manager".to_vec();
    analysis.engine.cfg.manager_name = manager.into_bytes();
    analysis.start().expect("log files");
    let mut env = LoggingEnv { inner: TestEnv::default(), log: Default::default() };
    analysis.load_mitre(&mut env);
    analysis.init_decoders(&mut env);
    let mut asys = Vec::new();
    for (k, m) in &msgs {
        if *k == b'Q' {
            asys.extend_from_slice(&siem_analysisd::asyscom::dispatch(&mut analysis, &mut env, m));
            asys.push(b'\n');
        } else {
            analysis.handle_message(&mut env, m);
        }
    }
    analysis.files.flush();
    // state reports (getstats / getagentsstats JSON and the state file)
    let _ = std::fs::create_dir_all(home.join("var/run"));
    analysis.write_state(&mut env);
    let mut state_json = analysis.state_json().print_unformatted();
    state_json.push(b'\n');
    state_json.extend_from_slice(&analysis.state.agents_json(ORACLE_TIME, &[1, 2, 3, 4, 5]).print_unformatted());
    state_json.push(b'\n');

    let read = |p: &str| std::fs::read(home.join(p)).unwrap_or_default();
    let mut r: HashMap<&str, Vec<u8>> = HashMap::new();
    r.insert("out/alerts.log", read("logs/alerts/alerts.log"));
    r.insert("out/alerts.json", read("logs/alerts/alerts.json"));
    r.insert("out/archives.log", read("logs/archives/archives.log"));
    r.insert("out/archives.json", read("logs/archives/archives.json"));
    r.insert("out/firewall.log", read("logs/firewall/firewall.log"));
    r.insert("out/ar.log", env.inner.ar_log.clone());
    r.insert("out/messages.log", env.log.borrow().clone());
    r.insert("etc/shared/ar.conf", read("etc/shared/ar.conf"));
    r.insert("out/state.json", state_json);
    r.insert("var/run/wazuh-analysisd.state", read("var/run/wazuh-analysisd.state"));
    r.insert("queue/fts/fts-queue", read("queue/fts/fts-queue"));
    {
        use siem_analysisd::config_json as cj;
        let cfg = &analysis.cfg;
        let mut g = Vec::new();
        for j in [
            cj::global(cfg),
            cj::active_response(cfg),
            cj::alerts(cfg),
            cj::decoders(&analysis.engine.decoders, cfg.internal.decoder_order_size as usize),
            cj::rules(&analysis.engine.rules),
            cj::internal(cfg),
            cj::commands(cfg),
            cj::labels(cfg),
            cj::rule_test(cfg),
        ] {
            g.extend_from_slice(&j.print_unformatted());
            g.push(b'\n');
        }
        r.insert("out/getconfig.json", g);
        r.insert("out/asyscom.log", asys);
        r.insert("out/wdb.log", env.inner.wdb_log.clone());
        r.insert("queue/fts/hostinfo", read("queue/fts/hostinfo"));
        r.insert("out/local.log", env.inner.local_log.clone());
        r.insert("out/mq.log", env.inner.mq_log.clone());
    }

    let mut failures = Vec::new();
    for s in SECTIONS {
        let cv = c.get(*s).cloned().unwrap_or_default();
        let rv = r.get(s).cloned().unwrap_or_default();
        eprintln!("{s}: C {} bytes, Rust {} bytes", cv.len(), rv.len());
        if let Some(d) = first_diff(s, &cv, &rv) {
            failures.push(d);
        }
    }
    if let Ok(dir) = std::env::var("SIEM_AD_DUMP") {
        let _ = std::fs::create_dir_all(&dir);
        for s in SECTIONS {
            let n = s.replace('/', "_");
            let _ = std::fs::write(format!("{dir}/c_{n}"), c.get(*s).cloned().unwrap_or_default());
            let _ = std::fs::write(format!("{dir}/r_{n}"), r.get(s).cloned().unwrap_or_default());
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
