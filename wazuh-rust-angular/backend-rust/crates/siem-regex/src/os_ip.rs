//! Port of Wazuh `os_ip` handling from `src/shared/validate_op.c`
//! (`OS_IsValidIP`, `OS_IPFound`, `OS_IPFoundList`, `OS_GetIPv4FromIPv6`,
//! `OS_ExpandIPv6`). Used by `<srcip>` / `<dstip>` in rules and by CDB/AR
//! white-lists.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

const DEFAULT_IPV6_PREFIX: i32 = 128;
const DEFAULT_IPV4_NETMASK: usize = 32;
/// `INET6_ADDRSTRLEN`
const IPSIZE: usize = 46;

const IPV4_ADDRESS: &str = r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
const IPV6_PREFIX: &str = "12[0-8]|1[0-1][0-9]|[0-9]?[0-9]";

fn ip_regexes() -> &'static [pcre2::bytes::Regex] {
    static RES: OnceLock<Vec<pcre2::bytes::Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        let p6 = IPV6_PREFIX;
        let pats = vec![
            format!(r"^(?:::[fF]{{4}}:)?({IPV4_ADDRESS})(?:/((?:3[0-2]|[1-2]?[0-9])|{IPV4_ADDRESS}))?$"),
            format!(r"^((?:[0-9a-fA-F]{{1,4}}:){{7}}[0-9a-fA-F]{{1,4}})(?:/({p6}))?$"),
            format!(r"^((?:[0-9a-fA-F]{{1,4}}:){{1,6}}(?::[0-9a-fA-F]{{1,4}}){{1}})(?:/({p6}))?$"),
            format!(r"^((?:[0-9a-fA-F]{{1,4}}:){{1,5}}(?::[0-9a-fA-F]{{1,4}}){{1,2}})(?:/({p6}))?$"),
            format!(r"^((?:[0-9a-fA-F]{{1,4}}:){{1,4}}(?::[0-9a-fA-F]{{1,4}}){{1,3}})(?:/({p6}))?$"),
            format!(r"^((?:[0-9a-fA-F]{{1,4}}:){{1,3}}(?::[0-9a-fA-F]{{1,4}}){{1,4}})(?:/({p6}))?$"),
            format!(r"^((?:[0-9a-fA-F]{{1,4}}:){{1,2}}(?::[0-9a-fA-F]{{1,4}}){{1,5}})(?:/({p6}))?$"),
            format!(r"^((?:[0-9a-fA-F]{{1,4}}:){{1}}(?::[0-9a-fA-F]{{1,4}}){{1,6}})(?:/({p6}))?$"),
            format!(r"^((?:[0-9a-fA-F]{{1,4}}:){{1,7}}:)(?:/({p6}))?$"),
            format!(r"^(:(?::[0-9a-fA-F]{{1,4}}){{1,7}})(?:/({p6}))?$"),
            r"^(::)$".to_string(),
        ];
        pats.iter().map(|p| pcre2::bytes::Regex::new(p).expect("static IP regex")).collect()
    })
}

fn ipv4_mask_ipv6() -> &'static pcre2::bytes::Regex {
    static RE: OnceLock<pcre2::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let p = format!(r"^::[fF]{{4}}:({IPV4_ADDRESS}(?:/(?:(?:3[0-2]|[1-2]?[0-9])|{IPV4_ADDRESS}))?)$");
        pcre2::bytes::Regex::new(&p).expect("static IPv4-in-IPv6 regex")
    })
}

/// Captured groups (1..) of a PCRE2 match, like `w_expression_PCRE2_fill_regex_match`.
fn captures(re: &pcre2::bytes::Regex, s: &str) -> Option<Vec<String>> {
    let caps = re.captures(s.as_bytes()).ok()??;
    let mut out = Vec::new();
    // pcre2 reports captured_groups = highest group that participated + 1.
    let mut last = 0;
    for i in 1..caps.len() {
        if caps.get(i).is_some() {
            last = i;
        }
    }
    for i in 1..=last {
        out.push(caps.get(i).map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned()).unwrap_or_default());
    }
    Some(out)
}

/// `get_ipv4_numeric` (inet_pton AF_INET) in network byte order as stored by `s_addr`.
fn ipv4_numeric(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(|a| u32::from_ne_bytes(a.octets()))
}

fn ipv6_numeric(s: &str) -> Option<[u8; 16]> {
    s.parse::<Ipv6Addr>().ok().map(|a| a.octets())
}

fn netmask_v4(cidr: usize) -> u32 {
    let host = if cidr == 0 { 0u32 } else { u32::MAX << (32 - cidr.min(32)) };
    // htonl(), stored the way s_addr is.
    u32::from_ne_bytes(host.to_be_bytes())
}

fn convert_netmask(mut netnumb: i32) -> Option<[u8; 16]> {
    if !(0..=128).contains(&netnumb) {
        return None;
    }
    let mut out = [0u8; 16];
    for byte in out.iter_mut() {
        let index = netnumb.min(8);
        netnumb -= index;
        for a in 0..index {
            *byte = byte.wrapping_add(1u8 << (8 - a - 1));
        }
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNet {
    V4 { ip_address: u32, netmask: u32 },
    V6 { ip_address: [u8; 16], netmask: [u8; 16] },
}

/// `os_ip`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsIp {
    /// Text as configured (including a leading `!`), possibly rewritten by
    /// `OS_GetIPv4FromIPv6` / `OS_ExpandIPv6` just like the C code does.
    pub ip: String,
    pub net: IpNet,
    pub is_ipv6: bool,
}

impl OsIp {
    /// `ip[0] == '!'` as tested by `OS_IPFound*`. Never true for values built
    /// by [`is_valid_ip`], which strips the `!`, but kept for parity.
    pub fn negated(&self) -> bool {
        self.ip.starts_with('!')
    }
}

/// `OS_GetIPv4FromIPv6`: "::ffff:1.2.3.4" -> "1.2.3.4".
pub fn get_ipv4_from_ipv6(ip: &str) -> Option<String> {
    captures(ipv4_mask_ipv6(), ip).and_then(|c| c.into_iter().next())
}

/// `OS_ExpandIPv6`: expand to 8 groups of 4 upper-case hex digits (+ `/cidr`).
pub fn expand_ipv6(ip: &str) -> Option<String> {
    let mut parts = ip.split('/').filter(|s| !s.is_empty());
    let addr = ipv6_numeric(parts.next()?)?;
    let mut cidr = 0i32;
    if let Some(c) = parts.next() {
        cidr = atoi(c);
        if !(0..=DEFAULT_IPV6_PREFIX).contains(&cidr) {
            return None;
        }
    }
    let mut s = String::new();
    for i in 0..8 {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{:02X}{:02X}", addr[i * 2], addr[i * 2 + 1]));
    }
    if cidr != 0 {
        s.push_str(&format!("/{cidr}"));
    }
    Some(s)
}

/// C `atoi`: leading digits, 0 on failure.
pub fn atoi(s: &str) -> i32 {
    let s = s.trim_start();
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let mut v: i64 = 0;
    for b in digits.bytes() {
        if !b.is_ascii_digit() {
            break;
        }
        v = (v * 10 + (b - b'0') as i64).min(i32::MAX as i64 + 1);
    }
    let v = if neg { -v } else { v };
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// `OS_IsValidIP`. Returns `(0|1|2, parsed)`: 0 invalid, 1 plain IP, 2 IP with
/// CIDR / netmask (or `any`).
pub fn is_valid_ip(ip_address: &str) -> (u32, Option<OsIp>) {
    let addr = ip_address.strip_prefix('!').unwrap_or(ip_address);

    // final_ip->ip = strncpy(ip_address /* without '!' */) then OS_GetIPv4FromIPv6
    let mut stored: String = addr.chars().take(IPSIZE).collect();
    if let Some(v4) = get_ipv4_from_ipv6(&stored) {
        stored = v4;
    }
    // Like the C code, the stored text never keeps the leading '!': negation
    // of <srcip>/<dstip> comes from the `negate` attribute on the rule option.
    if addr == "any" {
        return (
            2,
            Some(OsIp {
                ip: stored,
                net: IpNet::V6 { ip_address: [0; 16], netmask: [0; 16] },
                is_ipv6: false,
            }),
        );
    }

    for (i, re) in ip_regexes().iter().enumerate() {
        let Some(subs) = captures(re, addr) else { continue };
        let n = subs.len();
        let ret = if n == 2 { 2 } else { 1 };

        if i > 0 {
            if n == 0 {
                return (0, None);
            }
            let Some(net6) = ipv6_numeric(&subs[0]) else { return (0, None) };
            let nmask6 = if n == 2 {
                if subs[1].len() > 3 {
                    return (0, None);
                }
                match convert_netmask(atoi(&subs[1])) {
                    Some(m) => m,
                    None => return (0, None),
                }
            } else {
                convert_netmask(DEFAULT_IPV6_PREFIX).unwrap()
            };
            let mut ip6 = [0u8; 16];
            for k in 0..16 {
                ip6[k] = net6[k] & nmask6[k];
            }
            if let Some(exp) = expand_ipv6(&stored) {
                stored = exp;
            }
            return (
                ret,
                Some(OsIp {
                    ip: stored,
                    net: IpNet::V6 { ip_address: ip6, netmask: nmask6 },
                    is_ipv6: true,
                }),
            );
        } else {
            if n == 0 {
                return (0, None);
            }
            let net = match ipv4_numeric(&subs[0]) {
                Some(v) => v,
                None if subs[0] == "0.0.0.0" => 0,
                None => return (0, None),
            };
            let nmask = if n == 2 {
                if subs[1].len() <= 2 {
                    netmask_v4(atoi(&subs[1]).clamp(0, 32) as usize)
                } else {
                    match ipv4_numeric(&subs[1]) {
                        Some(m) => m,
                        None => return (0, None),
                    }
                }
            } else {
                netmask_v4(DEFAULT_IPV4_NETMASK)
            };
            return (
                ret,
                Some(OsIp {
                    ip: stored,
                    net: IpNet::V4 { ip_address: net & nmask, netmask: nmask },
                    is_ipv6: false,
                }),
            );
        }
    }
    (0, None)
}

enum Parsed {
    V4(u32),
    V6([u8; 16]),
}

fn parse_target(ip: &str) -> Option<Parsed> {
    if let Some(v) = ipv4_numeric(ip) {
        Some(Parsed::V4(v))
    } else {
        ipv6_numeric(ip).map(Parsed::V6)
    }
}

fn in_net(target: &Parsed, net: &IpNet) -> bool {
    match (target, net) {
        (Parsed::V4(a), IpNet::V4 { ip_address, netmask }) => (a & netmask) == *ip_address,
        (Parsed::V6(a), IpNet::V6 { ip_address, netmask }) => (0..16).all(|i| (a[i] & netmask[i]) == ip_address[i]),
        // The C code reads the union with the wrong type; for `any` (v6 zero
        // mask) an IPv4 target reads ipv4->netmask = 0 / ip = 0 and matches.
        (Parsed::V4(_), IpNet::V6 { ip_address, netmask }) => {
            let m = u32::from_ne_bytes([netmask[0], netmask[1], netmask[2], netmask[3]]);
            let ip = u32::from_ne_bytes([ip_address[0], ip_address[1], ip_address[2], ip_address[3]]);
            m == 0 && ip == 0
        }
        (Parsed::V6(_), IpNet::V4 { .. }) => false,
    }
}

/// `OS_IPFound`
pub fn ip_found(ip_address: &str, that_ip: &OsIp) -> bool {
    let Some(t) = parse_target(ip_address) else { return false };
    let truth = !that_ip.negated();
    if in_net(&t, &that_ip.net) {
        truth
    } else {
        !truth
    }
}

/// `OS_IPFoundList`. Note the C quirk: once a negated entry is seen, the
/// "true" value stays inverted for the rest of the list.
pub fn ip_found_list(ip_address: &str, list: &[OsIp]) -> bool {
    let Some(t) = parse_target(ip_address) else { return false };
    let mut truth = true;
    for l in list {
        if l.negated() {
            truth = false;
        }
        if in_net(&t, &l.net) {
            return truth;
        }
    }
    !truth
}
