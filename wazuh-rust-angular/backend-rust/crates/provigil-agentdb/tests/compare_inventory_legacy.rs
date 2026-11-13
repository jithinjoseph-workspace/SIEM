//! Legacy inventory commands and the package / hotfix lists: old and new must match.
mod common;

fn requests() -> Vec<String> {
    let mut r: Vec<String> = vec![r#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#.into()];
    for s in [
        // network
        "netinfo",
        "netinfo save",
        "netinfo nosuch x",
        "netinfo save 1|2023/11/01|eth0|Intel|ethernet|up|1500|aa:bb|10|20|30|40|0|0|1|2",
        "netinfo save 1|2023/11/01|eth1|NULL|ethernet|down|0|NULL|-1|NULL|30|40|0|0|1|2",
        "netinfo save 1|2023/11/01|eth0|Intel|ethernet|up|1500|aa:bb|10|20|30|40|0|0|1|2",
        "netinfo save 1",
        "netinfo save 1|t",
        "netinfo save 1|t|n",
        "netinfo save 1|t|n|a|e|up",
        "netinfo save 1|t|n|a|e|up|1500",
        "netinfo save 1|t|n|a|e|up|1500|mac",
        "netinfo save 1|t|n|a|e|up|1500|mac|5|6",
        "netproto save 1|eth0|0|10.0.0.1|enabled|5",
        "netproto save 1|eth0|1|fe80::1|disabled|NULL",
        "netproto save 1|eth0|0|10.0.0.1|weird|5",
        "netproto save 1|eth0",
        "netproto save 1|eth0|0",
        "netproto save 1|eth0|0|gw",
        "netproto other 1",
        "netaddr save 1|eth0|0|10.0.0.5|255.255.255.0|10.0.0.255",
        "netaddr save 1|eth0|1|fe80::5|ffff::|NULL",
        "netaddr save 1|eth0|0",
        "netaddr save 1|eth0|0|addr",
        "netaddr other",
        "netinfo del 2",
        "netinfo del NULL",
        // OS and hardware
        "osinfo",
        "osinfo  ",
        "osinfo nosuch",
        "osinfo get",
        "osinfo set 1|2023/11/01|pc1|x86_64|Microsoft Windows 11 Pro|10.0.22631|23H2|10|0|22631|windows|Windows_NT|10.0.22631|10.0.22631|NULL|3374|23H2",
        "osinfo get",
        "osinfo set 1|2",
        "osinfo set 1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|patch",
        "osinfo set NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
        "osinfo get",
        "hardware save 1|2023/11/01|SN1|Intel i7|8|2903.5|16000000|8000000|50",
        "hardware save 1|2023/11/01|SN1|Intel i7|0|-1|-5|0|101",
        "hardware save 1|t|s|cpu|4",
        "hardware save 1|t|s|cpu|4|2.5",
        "hardware save 1|t|s|cpu|4|2.5|-3",
        "hardware other",
        // ports and processes
        "port save 1|t|tcp|0.0.0.0|22|0.0.0.0|0|0|0|1234|listening|99|sshd",
        "port save 1|t|tcp|0.0.0.0|22|0.0.0.0|0|0|0|1234|listening|99|sshd2",
        "port save 1|t|udp|::|53|NULL|-1|NULL|5|99999999999|NULL|NULL|NULLprocess",
        "port save 1|t|tcp|ip|22|rip|0|0|0|1",
        "port save 1|t|tcp|ip|22|rip|0|0|0|1|st|5",
        "port del 2",
        "port nosuch",
        "process save 1|t|100|svchost|R|4|10|20|cmd|args|eu|ru|su|eg|rg|sg|fg|8|NULL|1000|2000|300|40|1700000000|1|2|3|100|0|1",
        "process save 1|t|101|x|S|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|-5|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
        "process save 1|t|-1|bad|S|1|1|1|c|a|e|r|s|e|r|s|f|1|1|1|1|1|1|1|1|1|1|1|1|1",
        "process save 1|t|102|x|S|1|1|1|c|a|e|r|s|e|r|s|f|1|1|1|1|1|1|-7|1|1|1|1|1|1",
        "process save 1|t|103|x",
        "process save 1|t|103|x|S|1|1|1|c|a|e|r|s|e|r|s|f|1|n",
        "process del 2",
        "process other",
        // packages and hotfixes
        "package",
        "package  ",
        "package nosuch",
        "package get",
        "hotfix get",
        "package save 1|2023/11/01|deb|openssl|optional|libs|1234|Ubuntu|2023/10/01|3.0.2|amd64|same|openssl|TLS lib|/usr|abc1",
        "package save 1|2023/11/01|NULL|curl|NULL|NULL|NULL|NULL|NULL|7.81|amd64|NULL|NULL|NULL|NULL|abc2",
        "package save 1|2023/11/01|deb|openssl|optional|libs|1234|Ubuntu|2023/10/01|3.0.2|amd64|same|openssl|TLS lib|/usr|abc1",
        "package save 1|2|3",
        "package save 1|2|3|4|5|6|NULLx|8|9|10|11|12|13|14|15|16",
        "hotfix",
        "hotfix nosuch",
        "hotfix save 1|2023/11/01|KB5031455",
        "hotfix save 1||2023/11/01||KB5031456|extra",
        "hotfix save 1|2023",
        "hotfix save 1|t|NULL",
        "hotfix save ",
        "package get",
        "package del 1",
        "package get",
        "hotfix del 1",
        "hotfix get",
        "package save 2|t2|deb|openssl|o|s|10|v|i|3.0.2|amd64|m|src|d|/usr|abc1",
        "package del 2",
        "package get",
    ] {
        r.push(format!("agent 1 {s}"));
    }
    for t in ["sys_netiface", "sys_netproto", "sys_netaddr", "sys_osinfo", "sys_hwinfo", "sys_ports", "sys_processes", "sys_programs", "sys_hotfixes", "sync_info"] {
        r.push(format!("agent 1 sql SELECT * FROM {t} ORDER BY rowid"));
    }
    r
}

#[test]
fn legacy_inventory_matches_old() {
    let p = common::Pair::new();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}
