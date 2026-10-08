//! Differential test of the wazuh-db port against the real C library
//! (tools/oracle/wdb_harness.c), driven with the same request stream.
//!
//! Environment:
//!   SIEM_WDB_ORACLE   command line of the oracle, e.g.
//!                     "wsl -d Ubuntu-20.04 --cd /home/u/wdb_oracle -- env TZ=UTC ./wdb_oracle home"
//!                     (ORACLE_TIME is inserted after `env`)
//!   SIEM_WDB_FUZZ     number of mutated requests to append (default 3000)
//!   SIEM_WDB_SEED     fuzz seed (default 1)
//!   SIEM_WDB_KEEP     keep the request stream and both outputs in this directory
//!
//! Both sides print: P <n> before a request, R <hex> the answer, S <hex>
//! streamed messages, E <n> <hex> router publications, M <level> <hex>
//! error/warning/info logs, then a dump of every database file.

mod common;

use std::path::PathBuf;

use common::*;
use siem_wdb::wdb::tables::{FieldType, TABLE_MAP};

// ------------------------------------------------------------------ corpus

struct Corpus {
    lines: Vec<String>,
    reqs: Vec<Vec<u8>>,
}

impl Corpus {
    fn q(&mut self, r: impl AsRef<[u8]>) {
        let r = r.as_ref().to_vec();
        self.lines.push(format!("Q {}", hex(&r)));
        self.reqs.push(r);
    }
    fn t(&mut self, t: i64) {
        self.lines.push(format!("T {t}"));
    }
    fn g(&mut self) {
        self.lines.push("G".into());
    }
}

/// A JSON object with every column of a dbsync table.
fn table_json(kv: &siem_wdb::wdb::tables::Kv, k: i64, aux_null: bool) -> String {
    let mut parts = Vec::new();
    for f in kv.column_list {
        let name = f.source_name.unwrap_or(f.target_name);
        if name == "scan_id" {
            continue;
        }
        let v = match f.type_ {
            FieldType::Integer => format!("{}", (k * 7 + f.index as i64) % 1000),
            FieldType::IntegerLong => format!("{}", 1_000_000_000_000i64 + k * 13 + f.index as i64),
            FieldType::Real => format!("{}.5", k + f.index as i64),
            FieldType::Text => {
                if aux_null && f.is_aux_field {
                    "null".into()
                } else if f.target_name == "dhcp" {
                    "\"enabled\"".into()
                } else if f.index % 5 == 0 && f.target_name != "checksum" && !f.is_pk {
                    "\"\"".into()
                } else {
                    format!("\"{}_{}\"", f.target_name, k)
                }
            }
        };
        parts.push(format!("\"{name}\":{v}"));
    }
    format!("{{{}}}", parts.join(","))
}

fn corpus() -> Corpus {
    let mut c = Corpus { lines: Vec::new(), reqs: Vec::new() };

    // ---- actors and malformed requests
    for r in [
        "", " ", "\n", "nothing", "bogus actor x", "agent", "agent 001", "agent abc sql SELECT 1", "agent 0x1 sql SELECT 1",
        "agent 999 sql SELECT 1", "global", "global unknown-cmd", "task", "task nothing", "mitre sql SELECT 1", "wazuhdb",
        "wazuhdb remove", "wazuhdb foo 001", "agent 000 sql SELECT 1",
    ] {
        c.q(r);
        c.q(format!("{r}\n"));
    }
    // ---- wazuh-db JSON commands
    for r in [
        "{", "{}", "{\"command\":1}", "{\"command\":\"nope\"}", "{\"command\":\"getstats\"}", "{\"command\":\"getconfig\"}",
        "{\"command\":\"getconfig\",\"parameters\":{}}", "{\"command\":\"getconfig\",\"parameters\":{\"section\":\"internal\"}}",
        "{\"command\":\"getconfig\",\"parameters\":{\"section\":\"wdb\"}}", "{\"command\":\"getconfig\",\"parameters\":{\"section\":\"x\"}}",
    ] {
        c.q(r);
    }

    // ---- global: agents
    for (id, name, ip, group) in [
        (1, "agent1", "1.1.1.1", "default"),
        (2, "agent2", "2.2.2.2", "default,group1"),
        (3, "agent3", "any", ""),
        (4, "agent4", "4.4.4.4", "g2"),
        (5, "agent5", "5.5.5.5", "default"),
    ] {
        c.q(format!(
            "global insert-agent {{\"id\":{id},\"name\":\"{name}\",\"ip\":\"{ip}\",\"register_ip\":\"any\",\"internal_key\":\"key{id}\",\"group\":\"{group}\",\"date_add\":{}}}",
            1600000000 + id
        ));
    }
    for r in [
        "global insert-agent {\"id\":1,\"name\":\"dup\",\"date_add\":1}",
        "global insert-agent {\"id\":\"x\",\"name\":\"bad\",\"date_add\":1}",
        "global insert-agent {\"id\":9,\"date_add\":1}",
        "global insert-agent not json",
        "global insert-agent {\"id\":6,\"name\":\"n6\",\"date_add\":1} trailing",
        "global insert-agent",
        "global update-agent-name {\"id\":1,\"name\":\"renamed1\"}",
        "global update-agent-name {\"id\":1}",
        "global update-agent-name {bad",
        "global update-agent-data {\"id\":1,\"os_name\":\"Ubuntu\",\"os_version\":\"20.04\",\"os_major\":\"20\",\"os_minor\":\"04\",\"os_codename\":\"focal\",\"os_platform\":\"ubuntu\",\"os_build\":\"b\",\"os_uname\":\"Linux\",\"os_arch\":\"x86_64\",\"version\":\"Wazuh v4.14.7\",\"config_sum\":\"c\",\"merged_sum\":\"m\",\"manager_host\":\"mgr\",\"node_name\":\"node01\",\"agent_ip\":\"1.1.1.1\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"labels\":\"env:prod\\nteam:sec\\nnocolon\\n\",\"group_config_status\":\"synced\"}",
        "global update-agent-data {\"id\":2,\"version\":\"Wazuh v4.0.0\",\"labels\":\"a:b\"}",
        "global update-agent-data {\"id\":3}",
        "global update-agent-data {\"version\":\"x\"}",
        "global get-labels 1",
        "global get-labels 2",
        "global get-labels x",
        "global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}",
        "global update-keepalive {\"id\":2,\"connection_status\":\"disconnected\",\"sync_status\":\"syncreq\"}",
        "global update-keepalive {\"id\":2}",
        "global update-connection-status {\"id\":3,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}",
        "global update-connection-status {\"id\":4,\"connection_status\":\"disconnected\",\"sync_status\":\"syncreq\",\"status_code\":2}",
        "global update-connection-status {\"id\":4,\"connection_status\":\"x\"}",
        "global update-status-code {\"id\":1,\"status_code\":3,\"version\":\"Wazuh v4.15.0\",\"sync_status\":\"syncreq\"}",
        "global update-status-code {\"id\":2,\"status_code\":1,\"sync_status\":\"synced\"}",
        "global update-status-code {\"id\":2,\"status_code\":1,\"version\":5,\"sync_status\":\"synced\"}",
        "global select-agent-name 1",
        "global select-agent-name 99",
        "global select-agent-group 2",
        "global find-agent {\"name\":\"agent2\",\"ip\":\"2.2.2.2\"}",
        "global find-agent {\"name\":\"agent2\",\"ip\":\"9.9.9.9\"}",
        "global find-agent {\"name\":\"agent2\"}",
        "global find-group default",
        "global find-group nogroup",
        "global insert-agent-group newgroup",
        "global insert-agent-group default",
        "global select-group-belong 2",
        "global select-group-belong 1",
        "global get-group-agents default last_id 0",
        "global get-group-agents default last_id 1",
        "global get-group-agents default",
        "global get-group-agents default foo 1",
        "global get-group-agents default last_id",
        "global select-groups",
        "global insert-agent-group g3",
        "global insert-agent-group g4",
        "global insert-agent-group g5",
        "global insert-agent-group g6",
        "global set-agent-groups {\"mode\":\"append\",\"sync_status\":\"syncreq\",\"data\":[{\"id\":3,\"groups\":[\"g3\",\"g4\"]}]}",
        "global set-agent-groups {\"mode\":\"override\",\"data\":[{\"id\":4,\"groups\":[\"default\",\"g5\"]}]}",
        "global set-agent-groups {\"mode\":\"empty_only\",\"data\":[{\"id\":5,\"groups\":[\"g6\"]}]}",
        "global set-agent-groups {\"mode\":\"remove\",\"data\":[{\"id\":4,\"groups\":[\"g5\"]}]}",
        "global set-agent-groups {\"mode\":\"bad\",\"data\":[]}",
        "global set-agent-groups {\"mode\":\"append\",\"data\":[{\"id\":3,\"groups\":[\"bad group!\"]}]}",
        "global set-agent-groups {\"mode\":\"append\",\"data\":[{\"id\":3,\"groups\":[\"..\"]}]}",
        "global set-agent-groups {\"mode\":\"append\",\"data\":[{\"id\":77,\"groups\":[\"gx\"]}]}",
        "global set-agent-groups {\"data\":[]}",
        "global sync-agent-groups-get {}",
        "global sync-agent-groups-get {\"condition\":\"sync_status\",\"set_synced\":true,\"get_global_hash\":true}",
        "global sync-agent-groups-get {\"condition\":\"all\",\"last_id\":2}",
        "global sync-agent-groups-get {\"condition\":\"other\"}",
        "global sync-agent-groups-get {\"last_id\":-1}",
        "global sync-agent-groups-get {\"agent_registration_delta\":10,\"condition\":\"all\"}",
        "global sync-agent-groups-get {\"set_synced\":1}",
        "global sync-agent-info-get",
        "global sync-agent-info-get last_id 2",
        "global sync-agent-info-get last_id",
        "global sync-agent-info-set [{\"id\":1,\"name\":\"agent1\",\"ip\":\"1.1.1.1\",\"version\":\"v\",\"labels\":[{\"id\":1,\"key\":\"k\",\"value\":\"v\"},{\"id\":1,\"key\":\"x\"}]}]",
        "global sync-agent-info-set [{\"id\":2,\"name\":\"agent2\",\"labels\":[]}]",
        "global sync-agent-info-set [{\"id\":3,\"name\":\"agent3\",\"ip\":\"3.3.3.3\",\"version\":\"Wazuh v4.14.7\",\"connection_status\":\"active\",\"last_keepalive\":1759658000,\"labels\":[{\"id\":3,\"key\":\"k3\",\"value\":\"v3\"}]},{\"id\":4,\"name\":\"agent4\",\"connection_status\":\"disconnected\",\"labels\":[]}]",
        "global sync-agent-info-set [{\"name\":\"x\",\"labels\":[]}]",
        "global sync-agent-info-set nope",
        "global get-groups-integrity 0123456789abcdef0123456789abcdef01234567",
        "global get-groups-integrity short",
        "global recalculate-agent-group-hashes",
        "global get-groups-integrity 0123456789abcdef0123456789abcdef01234567",
        "global disconnect-agents 0 1759658500 syncreq",
        "global disconnect-agents 0 100",
        "global disconnect-agents 0",
        "global get-all-agents last_id 0",
        "global get-all-agents last_id 3",
        "global get-all-agents context",
        "global get-all-agents nothing",
        "global get-all-agents last_id",
        "global get-distinct-groups",
        "global get-distinct-groups abc",
        "global get-agent-info 1",
        "global get-agent-info 42",
        "global get-agents-by-connection-status 0 active",
        "global get-agents-by-connection-status 0 active node01 10",
        "global get-agents-by-connection-status 0 active node01",
        "global get-agents-by-connection-status 0",
        "global reset-agents-connection syncreq",
        "global get-agents-by-connection-status 0 disconnected",
        "global sql SELECT id, name, ip, connection_status, sync_status, group_hash, \"group\" FROM agent ORDER BY id",
        "global sql SELECT * FROM labels",
        "global sql SELECT * FROM belongs",
        "global sql SELECT * FROM `group`",
        "global sql SELECT nothing FROM nowhere",
        "global sql",
        "global sleep 0",
        "global sleep",
        "global sleep 18446744073709551616",
        "global get_fragmentation",
        "global delete-group g6",
        "global delete-group nogroup",
        "global delete-agent 5",
        "global delete-agent 77",
        "global select-groups",
    ] {
        c.q(r);
    }
    c.t(ORACLE_TIME + 100);

    // ---- agent databases
    let a = "agent 001";
    for r in [
        "sql SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
        "begin",
        "commit",
        "syscheck",
        "syscheck nothing",
        "syscheck scan_info_get end_scan",
        "syscheck scan_info_update first_start 1759650000",
        "syscheck scan_info_update first_end 1759650100",
        "syscheck scan_info_update first_start",
        "syscheck scan_info_get first_start",
        "syscheck control 1759650200",
        "syscheck updatedate 1759650300",
        "syscheck cleandb ",
        "syscheck save file 1024:33188:0:0:d41d8cd98f00b204e9800998ecf8427e:da39a3ee5e6b4b0d3255bfef95601890afd80709:root:root:1600000000:12345:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855!0:1759650000 /etc/passwd",
        "syscheck save registry 0:0:S-1-5-32-544:0::::Administrators:SYSTEM:1600000000:0:sha:attr!0:1759650000 HKEY_LOCAL_MACHINE\\Software",
        "syscheck save file a\\ b:1:2:3!x /tmp/with space",
        "syscheck save dir 1:2 /x",
        "syscheck save file",
        "syscheck save file nochecksum",
        "syscheck load /etc/passwd",
        "syscheck load /nothing",
        "syscheck save2 {\"path\":\"/etc/hosts\",\"timestamp\":1759650000,\"version\":2,\"attributes\":{\"type\":\"file\",\"size\":10,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":7,\"mtime\":1600000000,\"hash_md5\":\"m\",\"hash_sha1\":\"s\",\"hash_sha256\":\"h\",\"checksum\":\"c1\"}}",
        "syscheck save2 {\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\x\",\"timestamp\":1,\"version\":2,\"arch\":\"[x64]\",\"attributes\":{\"type\":\"registry_key\",\"checksum\":\"c2\"}}",
        "syscheck save2 {\"path\":\"HKLM\\\\a:b\",\"timestamp\":1,\"version\":2,\"arch\":\"[x32]\",\"value_name\":\"v:1\",\"attributes\":{\"type\":\"registry_value\",\"value_type\":\"REG_SZ\",\"checksum\":\"c3\"}}",
        "syscheck save2 {\"index\":\"idx\",\"timestamp\":1,\"version\":3,\"attributes\":{\"type\":\"registry_value\",\"checksum\":\"c4\"}}",
        "syscheck save2 {\"path\":\"/x\",\"timestamp\":1,\"attributes\":{\"type\":\"registry_key\"}}",
        "syscheck save2 {\"path\":\"/x\",\"timestamp\":1,\"attributes\":{\"type\":\"device\"}}",
        "syscheck save2 {\"path\":\"/x\",\"timestamp\":1,\"attributes\":{\"type\":\"file\",\"bogus\":1}}",
        "syscheck save2 {\"path\":\"/x\",\"attributes\":{}}",
        "syscheck save2 {\"timestamp\":1}",
        "syscheck save2 not json",
        "syscheck integrity_check_global {\"begin\":\"/a\",\"end\":\"/z\",\"checksum\":\"abc\",\"id\":1}",
        "syscheck integrity_check_left {\"begin\":\"/a\",\"end\":\"/m\",\"checksum\":\"abc\",\"id\":1,\"tail\":\"/n\",\"checksum_left\":\"x\"}",
        "syscheck integrity_check_right {\"begin\":\"/n\",\"end\":\"/z\",\"checksum\":\"abc\",\"id\":1}",
        "syscheck integrity_check_bogus {}",
        "syscheck integrity_clear {\"id\":5}",
        "syscheck integrity_clear nope",
        "fim_file integrity_check_global {\"begin\":\"/a\",\"end\":\"/z\",\"checksum\":\"abc\",\"id\":2}",
        "fim_registry_key integrity_clear {\"id\":5}",
        "fim_registry_value integrity_check_global {\"begin\":\"a\",\"end\":\"z\",\"checksum\":\"abc\",\"id\":2}",
        "fim_registry save2 {\"path\":\"k\",\"timestamp\":1,\"version\":2,\"arch\":\"[x64]\",\"attributes\":{\"type\":\"registry_key\"}}",
        "fim_file",
        "syscheck delete /etc/hosts",
        "sql SELECT * FROM fim_entry ORDER BY full_path",
        // sca
        "sca",
        "sca query 1",
        "sca insert {\"id\":10,\"policy_id\":\"cis\",\"check\":{\"id\":1001,\"title\":\"t\",\"description\":\"d\",\"rationale\":\"r\",\"remediation\":\"rm\",\"references\":\"ref\",\"file\":\"f\",\"condition\":\"all\",\"directory\":\"dir\",\"process\":\"p\",\"registry\":\"reg\",\"command\":\"cmd\",\"result\":\"passed\",\"reason\":\"why\"}}",
        "sca insert {\"id\":10,\"policy_id\":\"cis\",\"check\":{\"id\":1002,\"title\":\"t2\"}}",
        "sca insert {\"id\":-1,\"policy_id\":\"cis\",\"check\":{\"id\":1,\"title\":\"t\"}}",
        "sca insert {\"id\":\"x\"}",
        "sca insert {\"id\":1,\"policy_id\":2}",
        "sca insert {\"id\":1,\"policy_id\":\"p\"}",
        "sca insert {\"id\":1,\"policy_id\":\"p\",\"check\":{\"id\":1,\"title\":\"t\",\"file\":3}}",
        "sca insert {\"id\":1,\"policy_id\":\"p\",\"check\":{\"title\":\"t\"}}",
        "sca insert garbage",
        "sca query 1001",
        "sca update 1001|failed|because|11",
        "sca update 1002|passed||NULL",
        "sca update 1002|passed",
        "sca insert_rules 1001|file|f:/etc/passwd",
        "sca insert_rules 1001|file",
        "sca insert_compliance 1001|cis|1.1",
        "sca insert_compliance 1001",
        "sca insert_policy name|file.yml|cis|desc|refs|hash123",
        "sca insert_policy name|file.yml|cis",
        "sca query_policy cis",
        "sca query_policy none",
        "sca query_policy_sha256 cis",
        "sca query_policies ",
        "sca insert_scan_info 1|2|11|cis|5|6|7|18|50|hash",
        "sca insert_scan_info NULL|2|11|cis|5|6|7|18|50",
        "sca query_scan cis",
        "sca query_results cis",
        "sca update_scan_info cis|x3",
        "sca update_scan_info NULL|xNULL",
        "sca update_scan_info nobar",
        "sca update_scan_info_start cis|10|20|12|1|2|3|6|33|hash2",
        "sca update_scan_info_start NULL|10|20|12|1|2|3|6|33|hash2",
        "sca update_scan_info_start cis|10",
        "sca delete_check_distinct cis|12",
        "sca delete_check_distinct cis",
        "sca delete_check cis",
        "sca delete_policy cis",
        "sca bogus x",
        // legacy inventory
        "netinfo save 1|time|eth0|ether|ethernet|up|1500|00:11:22:33:44:55|1|2|3|4|5|6|7|8",
        "netinfo save NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
        "netinfo save 1|time|eth0|ether|ethernet|up|1500|mac|1|2|3",
        "netinfo save 1|time",
        "netinfo del 2",
        "netinfo del NULL",
        "netinfo foo bar",
        "netproto save 1|eth0|0|10.0.0.1|enabled|100",
        "netproto save 1|eth0|1|NULL|NULL|NULL",
        "netproto save 1|eth0",
        "netproto save 1|eth0|0",
        "netaddr save 1|eth0|0|10.0.0.2|255.0.0.0|10.255.255.255",
        "netaddr save 1|eth0|1|NULL|NULL|NULL",
        "netaddr save 1|eth0|0",
        "osinfo get",
        "osinfo set 1|time|host|x86_64|Ubuntu|20.04|focal|20|04|b|ubuntu|Linux|5.4|#1|rel|patch|disp",
        "osinfo set NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
        "osinfo set 1|2|3",
        "osinfo set 1|time|host|x86_64|Ubuntu|20.04|focal|20|04|b|ubuntu|Linux|5.4|#1|rel|patch",
        "osinfo get",
        "osinfo bad",
        "osinfo ",
        "hardware save 1|time|serial|Intel CPU|4|2400.5|8000000|4000000|50",
        "hardware save 1|time|NULL|NULL|0|abc|0|0|200",
        "hardware save 1|time|serial|cpu|4",
        "hardware del 1",
        "port save 1|time|tcp|0.0.0.0|22|0.0.0.0|0|0|0|1234|listening|123|sshd",
        "port save 1|time|udp|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
        "port save 1|time|tcp|0.0.0.0|22",
        "port del 2",
        "port del NULL",
        "port x y",
        "package save 1|time|deb|bash|optional|shells|1024|vendor|2020|5.0|amd64|same|src|desc|loc|item1",
        "package save 1|time|deb|zsh|NULL|NULL|NULLX|NULL|NULL|1.0|amd64|NULL|NULL|NULL|NULL|item2",
        "package save 1|time|deb",
        "package del 1",
        "package del NULL",
        "package get",
        "package ",
        "package zzz",
        "hotfix save 1|time|KB123",
        "hotfix save 1|NULL|KB456",
        "hotfix save 1||KB789",
        "hotfix save 1",
        "hotfix del 2",
        "hotfix get",
        "hotfix zzz",
        "process save 1|time|100|bash|S|1|2|3|/bin/bash|-l|root|root|root|root|root|root|root|20|0|100|200|300|400|1600000000|100|100|1|100|0|2",
        "process save 1|time|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
        "process save 1|time|200|sh|R|1|2|3|cmd|argv|u|u|u|g|g|g|g|20|NULL|1|2|3|4|18446744073709551615|1|1|1|1|1|1",
        "process save 1|time|100|bash",
        "process del 2",
        "process del NULL",
        "process zz z",
        "ciscat save 1|time|bench|profile|1|2|3|4|5|6",
        "ciscat save NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
        "ciscat save 1|time|bench",
        "ciscat get x",
        "rootcheck save 1759650000 Trojaned version of file detected.",
        "rootcheck save 1759650100 Trojaned version of file detected.",
        "rootcheck save -5 bad",
        "rootcheck save 99999999999999999999 big",
        "rootcheck save 1759650000",
        "rootcheck save",
        "rootcheck delete",
        "rootcheck foo",
        "rootcheck",
        "sql SELECT * FROM pm_event",
    ] {
        c.q(format!("{a} {r}"));
    }

    // ---- syscollector deltas (save2 / dbsync / integrity) for every table
    let components = [
        ("syscollector_processes", "processes"),
        ("syscollector_packages", "packages"),
        ("syscollector_hotfixes", "hotfixes"),
        ("syscollector_ports", "ports"),
        ("syscollector_network_protocol", "network_protocol"),
        ("syscollector_network_address", "network_address"),
        ("syscollector_network_iface", "network_iface"),
        ("syscollector_hwinfo", "hwinfo"),
        ("syscollector_osinfo", "osinfo"),
        ("syscollector_users", "users"),
        ("syscollector_groups", "groups"),
        ("syscollector_browser_extensions", "browser_extensions"),
        ("syscollector_services", "services"),
    ];
    for (k, (comp, key)) in components.iter().enumerate() {
        let kv = TABLE_MAP.iter().find(|kv| kv.key == *key).unwrap();
        for i in 0..3i64 {
            let j = table_json(kv, i + k as i64 * 10, i == 2);
            c.q(format!("agent 001 dbsync {key} INSERTED {j}"));
            c.q(format!("agent 002 {comp} save2 {{\"attributes\":{j}}}"));
        }
        let j = table_json(kv, k as i64 * 10, false);
        c.q(format!("agent 001 dbsync {key} MODIFIED {j}"));
        c.q(format!("agent 001 dbsync {key} DELETED {j}"));
        c.q(format!("agent 001 dbsync {key} UPDATED {j}"));
        c.q(format!("agent 001 dbsync {key} INSERTED {j} trailing"));
        c.q(format!("agent 001 dbsync {key} INSERTED"));
        c.q(format!("agent 002 {comp} save2 {{\"noattributes\":1}}"));
        c.q(format!("agent 002 {comp} save2 nojson"));
        c.q(format!(
            "agent 002 {comp} integrity_check_global {{\"begin\":\"a\",\"end\":\"z\",\"checksum\":\"0123\",\"id\":{}}}",
            k + 1
        ));
        c.q(format!("agent 002 {comp} integrity_check_left {{\"begin\":\"a\",\"end\":\"m\",\"checksum\":\"x\",\"id\":3,\"tail\":\"n\",\"checksum_left\":\"y\"}}"));
        c.q(format!("agent 002 {comp} integrity_clear {{\"id\":9}}"));
        c.q(format!("agent 002 {comp} bogus x"));
        c.q(format!("agent 002 {comp}"));
    }
    c.q("agent 001 dbsync nosuchtable INSERTED {}");
    c.q("agent 001 dbsync packages");
    c.q("agent 002 syscollector_nope save2 {}");
    c.q("agent 002 package get");
    c.q("agent 002 hotfix get");
    c.q("agent 002 osinfo get");

    // ---- transactions, maintenance and clock
    c.q("agent 001 begin");
    c.q("agent 001 begin");
    c.q("agent 001 commit");
    c.q("agent 001 commit");
    c.q("agent 001 get_fragmentation");
    c.q("agent 001 vacuum");
    c.q("agent 001 sleep 5");
    c.q("agent 001 sleep");
    c.q("agent 003 sql SELECT 1");
    c.q("agent 003 close");
    c.q("agent 004 remove");
    c.q("agent 001 sql SELECT * FROM metadata");
    c.t(ORACLE_TIME + 3600);
    c.g();
    c.t(ORACLE_TIME + 3 * 3600);
    c.g();
    c.q("agent 001 sql SELECT * FROM sys_osinfo");
    c.q("global vacuum");
    c.q("global get_fragmentation");
    c.q("wazuhdb remove 004 003 abc");

    // ---- tasks
    for r in [
        "upgrade {\"agent\":1,\"node\":\"node01\",\"module\":\"upgrade_module\"}",
        "upgrade {\"agent\":2,\"node\":\"node01\",\"module\":\"upgrade_module\"}",
        "upgrade_custom {\"agent\":3,\"node\":\"node02\",\"module\":\"upgrade_module\"}",
        "upgrade {\"agent\":\"1\"}",
        "upgrade {\"agent\":1}",
        "upgrade {\"agent\":1,\"node\":\"n\"}",
        "upgrade notjson",
        "upgrade_get_status {\"agent\":1,\"node\":\"node01\"}",
        "upgrade_get_status {\"agent\":3,\"node\":\"node01\"}",
        "upgrade_get_status {\"agent\":9,\"node\":\"node01\"}",
        "upgrade_get_status {\"agent\":1}",
        "upgrade_update_status {\"agent\":1,\"node\":\"node01\",\"status\":\"In progress\"}",
        "upgrade_update_status {\"agent\":1,\"node\":\"node01\",\"status\":\"Failed\",\"error_msg\":\"boom\"}",
        "upgrade_update_status {\"agent\":2,\"node\":\"node01\",\"status\":\"Done\"}",
        "upgrade_update_status {\"agent\":2,\"node\":\"node01\",\"status\":\"Bogus\"}",
        "upgrade_update_status {\"agent\":2,\"node\":\"node01\"}",
        "upgrade_result {\"agent\":1}",
        "upgrade_result {\"agent\":2}",
        "upgrade_result {\"agent\":99}",
        "upgrade_result {}",
        "upgrade {\"agent\":4,\"node\":\"node01\",\"module\":\"upgrade_module\"}",
        "upgrade_update_status {\"agent\":4,\"node\":\"node01\",\"status\":\"In progress\"}",
        "set_timeout {\"now\":1759670000,\"interval\":60}",
        "set_timeout {\"now\":1759650000,\"interval\":60}",
        "set_timeout {\"now\":1}",
        "upgrade_cancel_tasks {\"node\":\"node02\"}",
        "upgrade_cancel_tasks {}",
        "delete_old {\"timestamp\":1759658450}",
        "delete_old {\"timestamp\":\"x\"}",
        "sql SELECT * FROM tasks ORDER BY task_id",
        "sql SELECT nope",
        "nothing {}",
        "upgrade",
    ] {
        c.q(format!("task {r}"));
    }

    // ---- backups
    c.q("global backup");
    c.q("global backup ");
    c.q("global backup get");
    // the snapshot names contain ':' (not valid on Windows filesystems)
    if cfg!(unix) {
        backups(&mut c);
    }
    c.q("global backup nope");
    c.q("global backup restore {\"snapshot\":\"missing.gz\"}");
    c.q("global backup restore notjson");
    c.q("{\"command\":\"getstats\"}");
    c
}

fn backups(c: &mut Corpus) {
    c.q("global backup create");
    c.q("global backup get");
    c.q("global delete-agent 1");
    c.t(ORACLE_TIME + 5 * 3600);
    c.q("global backup create");
    c.q("global backup restore");
    c.q("global sql SELECT id, name FROM agent ORDER BY id");
    c.q("global backup restore {\"save_pre_restore_state\":true}");
    c.q("global backup get");
    c.q("global sql SELECT id, name FROM agent ORDER BY id");
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

const TOKENS: [&str; 16] = ["NULL", "", "0", "-1", "2147483648", "99999999999999999999", " ", "|", "\\ ", "!", ":", "{}", "null", "\"x\"", "1.5", "\n"];

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut r = base.to_vec();
    for _ in 0..1 + rng.below(3) {
        match rng.below(6) {
            0 if !r.is_empty() => {
                let p = rng.below(r.len());
                r.truncate(p);
            }
            1 => {
                // replace one '|' or ' ' separated field
                let seps: Vec<usize> = r.iter().enumerate().filter(|(_, &b)| b == b'|' || b == b' ').map(|(i, _)| i).collect();
                if seps.len() >= 2 {
                    let i = rng.below(seps.len() - 1);
                    let (s, e) = (seps[i] + 1, seps[i + 1]);
                    let t = TOKENS[rng.below(TOKENS.len())].as_bytes();
                    r.splice(s..e, t.iter().copied());
                }
            }
            2 if !r.is_empty() => {
                let p = rng.below(r.len());
                let t = TOKENS[rng.below(TOKENS.len())].as_bytes();
                r.splice(p..p, t.iter().copied());
            }
            3 if !r.is_empty() => {
                let p = rng.below(r.len());
                r.remove(p);
            }
            4 => {
                // change the agent id
                let ids: [&[u8]; 6] = [b"001", b"002", b"000", b"010", b"-1", b"1"];
                if r.starts_with(b"agent ") && r.len() > 9 {
                    let id = ids[rng.below(ids.len())];
                    r.splice(6..9, id.iter().copied());
                }
            }
            _ if !r.is_empty() => {
                let p = rng.below(r.len());
                r[p] = b"0123456789|: {}\"aZ-"[rng.below(19)];
            }
            _ => {}
        }
    }
    r
}

/// Requests whose C answer prints uninitialized memory: a `wazuhdb remove`
/// list whose first id is invalid uses the never-written `agent[]` buffer
/// as the JSON key.
fn reads_uninitialized(r: &[u8]) -> bool {
    let r = r.split(|&b| b == 0).next().unwrap_or_default();
    let r = r.strip_suffix(b"\n").unwrap_or(r);
    let t = r.iter().position(|&b| b != b' ' && b != b'\n').unwrap_or(r.len());
    let Some(rest) = r[t..].strip_prefix(b"wazuhdb remove ") else {
        return false;
    };
    let first = rest.split(|&b| b == b' ').find(|t| !t.is_empty());
    match first {
        None => false,
        Some(tok) => {
            let s = std::str::from_utf8(tok).unwrap_or("x");
            let body = s.strip_prefix(['+', '-']).unwrap_or(s);
            !(s.trim_start() == s && !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) && s.parse::<i64>().is_ok())
        }
    }
}

// -------------------------------------------------------------------- test

#[test]
fn wdb_matches_c_oracle() {
    let Ok(cmd) = std::env::var("SIEM_WDB_ORACLE") else {
        eprintln!("SIEM_WDB_ORACLE not set; skipping");
        return;
    };
    let fuzz: usize = std::env::var("SIEM_WDB_FUZZ").ok().and_then(|v| v.parse().ok()).unwrap_or(3000);
    let seed: u64 = std::env::var("SIEM_WDB_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let mut c = corpus();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
    let base = c.reqs.clone();
    for i in 0..fuzz {
        if i % 500 == 499 {
            c.t(ORACLE_TIME + 4 * 3600 + i as i64);
            c.g();
        }
        let b = &base[rng.below(base.len())];
        let m = mutate(&mut rng, b);
        if reads_uninitialized(&m) {
            continue;
        }
        c.q(m);
    }
    c.q("global sql SELECT * FROM agent ORDER BY id");
    let input = c.lines.join("\n") + "\n";

    let home: PathBuf = std::env::temp_dir().join(format!("siem_wdb_oracle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let rust = {
        let mut sess = Session::new(&home);
        for l in input.lines() {
            sess.line(l);
        }
        sess.finish()
    };
    let oracle = run_oracle(&cmd, &input);
    let _ = std::fs::remove_dir_all(&home);

    if let Ok(keep) = std::env::var("SIEM_WDB_KEEP") {
        let k = PathBuf::from(keep);
        let _ = std::fs::create_dir_all(&k);
        std::fs::write(k.join("input.txt"), &input).unwrap();
        std::fs::write(k.join("rust.txt"), rust.join("\n")).unwrap();
        std::fs::write(k.join("oracle.txt"), oracle.join("\n")).unwrap();
    }

    let n = rust.len().max(oracle.len());
    let diffs = compare(&rust, &oracle, &c.lines);
    eprintln!("{} requests, {n} output lines, {diffs} diffs", c.reqs.len());
    assert_eq!(diffs, 0, "the Rust wazuh-db differs from the C oracle");
}
