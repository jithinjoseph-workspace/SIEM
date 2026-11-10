use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNet {
    V4 { ip_address: u32, netmask: u32 },
    V6 { ip_address: [u8; 16], netmask: [u8; 16] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsIp {
    pub ip: String,
    pub net: IpNet,
    pub is_ipv6: bool,
}

impl OsIp {
    /// The stored text starts with `!`; parsed entries never do, hand-built ones may.
    pub fn negated(&self) -> bool {
        self.ip.starts_with('!')
    }
}

const MAX_TEXT: usize = 46;

fn octet(text: &str) -> Option<u8> {
    let plain = !text.is_empty() && text.len() <= 3 && text.bytes().all(|b| b.is_ascii_digit());
    if plain && (text == "0" || !text.starts_with('0')) {
        text.parse().ok()
    } else {
        None
    }
}

fn dotted(text: &str) -> Option<[u8; 4]> {
    let mut parts = text.split('.');
    let mut out = [0u8; 4];
    for slot in &mut out {
        *slot = octet(parts.next()?)?;
    }
    parts.next().is_none().then_some(out)
}

/// A prefix written with no leading zero, up to `max`.
fn prefix(text: &str, max: u32) -> Option<u32> {
    let plain = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !plain || (text.len() > 1 && text.starts_with('0')) || text.len() > 3 {
        return None;
    }
    text.parse().ok().filter(|&n| n <= max)
}

fn strip_mapped(text: &str) -> Option<&str> {
    let head = text.get(..7)?;
    head.eq_ignore_ascii_case("::ffff:").then(|| &text[7..])
}

fn v4_body(text: &str) -> Option<([u8; 4], Option<[u8; 4]>)> {
    match text.split_once('/') {
        None => Some((dotted(text)?, None)),
        Some((addr, mask)) => {
            let mask = match dotted(mask) {
                Some(m) => m,
                None => {
                    let n = prefix(mask, 32)?;
                    (if n == 0 { 0 } else { u32::MAX << (32 - n) }).to_be_bytes()
                }
            };
            Some((dotted(addr)?, Some(mask)))
        }
    }
}

fn v6_net(addr: Ipv6Addr, bits: Option<u32>) -> IpNet {
    let mut netmask = [0xffu8; 16];
    if let Some(n) = bits {
        netmask = (if n == 0 { 0 } else { u128::MAX << (128 - n) }).to_be_bytes();
    }
    let mut ip_address = addr.octets();
    for (b, m) in ip_address.iter_mut().zip(netmask) {
        *b &= m;
    }
    IpNet::V6 { ip_address, netmask }
}

/// Only hexadecimal groups and colons: no zone and no embedded IPv4.
fn plain_v6(text: &str) -> Option<Ipv6Addr> {
    text.bytes().all(|b| b.is_ascii_hexdigit() || b == b':').then(|| text.parse().ok())?
}

pub fn is_valid_ip(text: &str) -> (u32, Option<OsIp>) {
    let body = text.strip_prefix('!').unwrap_or(text);
    if body == "any" {
        let net = IpNet::V6 { ip_address: [0; 16], netmask: [0; 16] };
        return (2, Some(OsIp { ip: "any".to_string(), net, is_ipv6: false }));
    }
    // One trailing newline is accepted; it stays in the stored text unless that text is rewritten.
    let core = body.strip_suffix('\n').unwrap_or(body);
    let mapped = strip_mapped(core);
    let v4_text = mapped.unwrap_or(core);
    if let Some((addr, mask)) = v4_body(v4_text) {
        let code = if mask.is_some() { 2 } else { 1 };
        let netmask = u32::from_ne_bytes(mask.unwrap_or([0xff; 4]));
        let ip_address = u32::from_ne_bytes(addr) & netmask;
        let shown = if mapped.is_some() { v4_text } else { body };
        let ip = shown.chars().take(MAX_TEXT).collect();
        return (code, Some(OsIp { ip, net: IpNet::V4 { ip_address, netmask }, is_ipv6: false }));
    }
    let (addr, bits) = match core.split_once('/') {
        // An IPv6 prefix may also be written as two digits with a leading zero (`08`).
        Some((addr, bits)) => match prefix(bits.strip_prefix('0').filter(|r| r.len() == 1).unwrap_or(bits), 128) {
            Some(n) => (addr, Some(n)),
            None => return (0, None),
        },
        None => (core, None),
    };
    // `::` alone is an address, but it takes no prefix.
    if addr == "::" && bits.is_some() {
        return (0, None);
    }
    match plain_v6(addr) {
        Some(parsed) => {
            let ip = expand_ipv6(body).unwrap_or_else(|| body.chars().take(MAX_TEXT).collect());
            let code = if bits.is_some() { 2 } else { 1 };
            (code, Some(OsIp { ip, net: v6_net(parsed, bits), is_ipv6: true }))
        }
        None => (0, None),
    }
}

fn inside_v4(target: u32, net: &IpNet) -> bool {
    match net {
        IpNet::V4 { ip_address, netmask } => target & netmask == *ip_address,
        IpNet::V6 { ip_address, netmask } => ip_address[..4] == [0; 4] && netmask[..4] == [0; 4],
    }
}

fn inside_v6(target: &[u8; 16], net: &IpNet) -> bool {
    match net {
        IpNet::V4 { .. } => false,
        IpNet::V6 { ip_address, netmask } => (0..16).all(|i| target[i] & netmask[i] == ip_address[i]),
    }
}

enum Target {
    V4(u32),
    V6([u8; 16]),
}

fn parse_target(text: &str) -> Option<Target> {
    if let Ok(v4) = text.parse::<Ipv4Addr>() {
        return Some(Target::V4(u32::from_ne_bytes(v4.octets())));
    }
    text.parse::<Ipv6Addr>().ok().map(|v6| Target::V6(v6.octets()))
}

fn contains(target: &Target, net: &IpNet) -> bool {
    match target {
        Target::V4(t) => inside_v4(*t, net),
        Target::V6(t) => inside_v6(t, net),
    }
}

pub fn ip_found(target: &str, entry: &OsIp) -> bool {
    parse_target(target).is_some_and(|t| contains(&t, &entry.net) != entry.negated())
}

pub fn ip_found_list(target: &str, list: &[OsIp]) -> bool {
    let Some(t) = parse_target(target) else {
        return false;
    };
    let mut answer = true;
    for entry in list {
        answer &= !entry.negated();
        if contains(&t, &entry.net) {
            return answer;
        }
    }
    !answer
}

pub fn get_ipv4_from_ipv6(text: &str) -> Option<String> {
    let rest = strip_mapped(text.strip_suffix('\n').unwrap_or(text))?;
    v4_body(rest).map(|_| rest.to_string())
}

pub fn expand_ipv6(text: &str) -> Option<String> {
    let mut pieces = text.split('/').filter(|p| !p.is_empty());
    let addr: Ipv6Addr = pieces.next()?.parse().ok()?;
    let bits = pieces.next().map_or(0, atoi);
    if !(0..=128).contains(&bits) {
        return None;
    }
    let groups: Vec<String> = addr.segments().iter().map(|g| format!("{g:04X}")).collect();
    let groups = groups.join(":");
    Some(if bits == 0 { groups } else { format!("{groups}/{bits}") })
}

pub fn atoi(text: &str) -> i32 {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | 0x09..=0x0d) {
        i += 1;
    }
    let negative = b.get(i) == Some(&b'-');
    if matches!(b.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let mut value: i64 = 0;
    while let Some(d) = b.get(i).filter(|c| c.is_ascii_digit()) {
        value = (value * 10 + i64::from(d - b'0')).min(1 << 32);
        i += 1;
    }
    (if negative { -value } else { value }).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

pub fn cidr_to_str(entry: &OsIp) -> Option<String> {
    let text = &entry.ip;
    match &entry.net {
        IpNet::V6 { netmask, .. } if text.contains(':') => {
            let bits: u32 = netmask.iter().map(|b| b.count_ones()).sum();
            Some(if bits < 128 { format!("{text}/{bits}") } else { text.clone() })
        }
        IpNet::V4 { netmask, .. } if !text.contains(':') && *netmask != u32::MAX && text != "any" => {
            let host_order = u32::from_be_bytes(netmask.to_ne_bytes());
            (0..32u32)
                .find(|&n| (if n == 0 { 0 } else { u32::MAX << (32 - n) }) == host_order)
                .map(|n| format!("{text}/{n}"))
        }
        _ => Some(text.clone()),
    }
}
