//! Cases taken from Wazuh `src/unit_tests/shared/test_validate_op.c` and
//! `test_expression.c` (where those tests do not depend on mocks).

use siem_regex::{ip_found, ip_found_list, is_valid_ip, ExpType, Expression, IpNet};

#[test]
fn valid_ipv4() {
    for ip in ["1.1.1.1", "255.255.255.255", "100.100.100.100", "10.10.10.10", "111.111.111.111", "222.222.222.222", "127.0.0.1"] {
        let (ret, parsed) = is_valid_ip(ip);
        assert_eq!(ret, 1, "{ip}");
        assert!(!parsed.unwrap().is_ipv6, "{ip}");
    }
}

#[test]
fn invalid_ipv4() {
    for ip in [
        "12.0", "111", "01.01", "01.01.01", "10.10.10.10.10", "222.222.222.222.222", "333.333.334.334", "256.1.01.001",
        "1.1.1.256", "327.0.0.1", "4000.00.0.1", "10.10.10.10/", "10.10.10.10/33", "10.10.10.10/99", "10.10.10.10/123",
        "10.10.10.10/12345", "01.01.01.01", "001.001.001.001", "000.00.0.1", "1.1.1.10/36.255.255", "1.1.1.1/36.1.1.256",
        "1.1.1.300/36.1.1.255",
    ] {
        assert_eq!(is_valid_ip(ip).0, 0, "{ip}");
    }
}

#[test]
fn cidr_and_netmask() {
    assert_eq!(is_valid_ip("192.168.10.12/32").0, 2);
    assert_eq!(is_valid_ip("0.0.0.0/32").0, 2);
    assert_eq!(is_valid_ip("32.32.32.32/255.255.255.255").0, 2);
    assert_eq!(is_valid_ip("16.16.16.16/255.255.255.0").0, 2);
    let (_, ip) = is_valid_ip("10.0.0.0/8");
    let ip = ip.unwrap();
    assert!(ip_found("10.200.3.4", &ip));
    assert!(!ip_found("11.0.0.1", &ip));
    let (_, ip) = is_valid_ip("16.16.16.16/255.255.255.0");
    assert!(ip_found("16.16.16.200", &ip.unwrap()));
}

#[test]
fn any_matches_everything_ipv4() {
    let (ret, ip) = is_valid_ip("any");
    assert_eq!(ret, 2);
    let ip = ip.unwrap();
    assert!(!ip.is_ipv6);
    assert!(ip_found("8.8.8.8", &ip));
}

#[test]
fn valid_ipv6() {
    for ip in [
        "2001:db8:abcd:0012:0000:0000:0000:0000",
        "2001:db8:abcd:0012:ffff:ffff:ffff:ffff",
        "fe80::ceaf:9ff2:b33c:1ca7",
        "11AA:11AA:11AA:11AA:11AA:11AA:11AA:11AA",
        "11AA::11AA:11AA:11AA:11AA:11AA:11AA",
        "11AA::11AA",
        "11AA:11AA:11AA:11AA:11AA:11AA:11AA::",
        "11AA::",
        "::11AA:11AA:11AA:11AA:11AA:11AA:11AA",
        "::11AA",
        "::",
    ] {
        let (ret, parsed) = is_valid_ip(ip);
        assert_eq!(ret, 1, "{ip}");
        assert!(parsed.unwrap().is_ipv6, "{ip}");
    }
    // Embedded IPv4 is caught by the IPv4 regex first, exactly like the C code.
    let (ret, parsed) = is_valid_ip("::ffff:10.2.3.1");
    assert_eq!(ret, 1);
    let parsed = parsed.unwrap();
    assert!(!parsed.is_ipv6);
    assert_eq!(parsed.ip, "10.2.3.1");
}

#[test]
fn ipv6_prefix_and_expand() {
    let (ret, ip) = is_valid_ip("2001:db8::/32");
    assert_eq!(ret, 2);
    let ip = ip.unwrap();
    assert_eq!(ip.ip, "2001:0DB8:0000:0000:0000:0000:0000:0000/32");
    assert!(ip_found("2001:db8:1::5", &ip));
    assert!(!ip_found("2001:db9::5", &ip));
    match ip.net {
        IpNet::V6 { netmask, .. } => assert_eq!(&netmask[..5], &[0xff, 0xff, 0xff, 0xff, 0]),
        _ => panic!("expected v6"),
    }
    assert_eq!(is_valid_ip("2001::db8:abcd::0012/64").0, 0);
}

#[test]
fn ip_found_list_negation_sticks() {
    // An entry whose text starts with '!' flips the result for the rest of the
    // list (OS_IPFoundList quirk).
    let mut a = is_valid_ip("16.16.16.16").1.unwrap();
    a.ip = format!("!{}", a.ip);
    let b = is_valid_ip("16.16.16.32").1.unwrap();
    assert!(!ip_found_list("16.16.16.16", &[a.clone(), b.clone()]));
    assert!(!ip_found_list("16.16.16.32", &[a.clone(), b.clone()]));
    assert!(ip_found_list("1.2.3.4", &[a, b]));
}

#[test]
fn expression_types() {
    let e = Expression::compile(ExpType::OsMatch, "failed|denied", 0).unwrap();
    assert!(e.is_match("Access DENIED"));
    let e = Expression::compile(ExpType::OsRegex, r"^(\S+) (\d+)$", siem_regex::OS_RETURN_SUBSTRING).unwrap();
    let m = e.matches("user 42");
    assert!(m.matched);
    assert_eq!(m.sub_strings, vec!["user", "42"]);
    let e = Expression::compile(ExpType::Pcre2, r"(?i)user=(\w+)\s+uid=(\d+)", 0).unwrap();
    let m = e.matches("x USER=root uid=0 y");
    assert!(m.matched);
    assert_eq!(m.sub_strings, vec!["root", "0"]);
    assert_eq!(m.end_match, Some(16));
    let e = Expression::compile(ExpType::String, "exact", 0).unwrap();
    assert!(e.is_match("exact"));
    assert!(!e.is_match("exactly"));
    let mut ips = None;
    Expression::add_osip(&mut ips, "10.0.0.0/8").unwrap();
    Expression::add_osip(&mut ips, "192.168.1.1").unwrap();
    let mut ips = ips.unwrap();
    assert!(ips.is_match("10.1.1.1"));
    assert!(ips.is_match("192.168.1.1"));
    assert!(!ips.is_match("192.168.1.2"));
    ips.negate = true;
    assert!(ips.is_match("192.168.1.2"));
    assert!(Expression::compile(ExpType::Pcre2, "(unclosed", 0).is_err());
    assert!(Expression::compile(ExpType::OsRegex, r"\z", 0).is_err());
}
