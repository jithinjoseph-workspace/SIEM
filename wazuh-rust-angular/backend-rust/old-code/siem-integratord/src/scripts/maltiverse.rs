//! `integrations/maltiverse.py`: enriches an alert's hashes, source IP,
//! hostname and URL from Maltiverse and sends what it finds to analysisd.

use std::net::IpAddr;

use sha2::Digest;

use super::{agent_location, args_repr, contains, fmt, get, idx, Ctx, PyErr, R};
use crate::pyjson::{dict, dumps, repr, Py};

const MAX_EVENT_SIZE: usize = 65535;

/// `urlsplit(url)` -> (scheme, netloc, path, query, fragment)
fn urlsplit(url: &str) -> R<(String, String, String, String, String)> {
    // _remove_unsafe_bytes_from_url and the leading C0/space strip
    let mut u: String = url.chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    u = u.trim_start_matches(|c: char| (c as u32) <= 0x20).to_string();
    let mut scheme = String::new();
    if let Some(i) = u.find(':') {
        let head = &u[..i];
        if i > 0 && head.starts_with(|c: char| c.is_ascii_alphabetic()) && head.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            scheme = head.to_ascii_lowercase();
            u = u[i + 1..].to_string();
        }
    }
    let mut netloc = String::new();
    if u.starts_with("//") {
        let rest = &u[2..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        netloc = rest[..end].to_string();
        u = rest[end..].to_string();
        if netloc.contains('[') != netloc.contains(']') {
            return Err(PyErr::Value("Invalid IPv6 URL".into()));
        }
    }
    let mut fragment = String::new();
    if let Some((a, b)) = u.clone().split_once('#') {
        u = a.to_string();
        fragment = b.to_string();
    }
    let mut query = String::new();
    if let Some((a, b)) = u.clone().split_once('?') {
        u = a.to_string();
        query = b.to_string();
    }
    Ok((scheme, netloc, u, query, fragment))
}

/// `is_valid_url`
pub fn is_valid_url(url: &str) -> bool {
    let Ok((scheme, netloc, path, query, fragment)) = urlsplit(url) else { return false };
    if scheme != "http" && scheme != "https" {
        return false;
    }
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if !RE.get_or_init(|| regex::Regex::new(r"^[a-zA-Z0-9.-]+(:[0-9]{1,5})?$").unwrap()).is_match(&netloc) {
        return false;
    }
    let all = format!("{path}{query}{fragment}");
    if all.chars().any(|c| "<>\"'{}|\\^`".contains(c)) {
        return false;
    }
    !scheme.is_empty() && !netloc.is_empty()
}

/// `os.path.join` (posix)
fn path_join(parts: &[&str]) -> String {
    let mut p = parts[0].to_string();
    for b in &parts[1..] {
        if b.starts_with('/') {
            p = b.to_string();
        } else if p.is_empty() || p.ends_with('/') {
            p.push_str(b);
        } else {
            p.push('/');
            p.push_str(b);
        }
    }
    p
}

/// `ipaddress.ip_address(v)`
fn ip_address(v: &Py) -> Option<IpAddr> {
    match v {
        Py::Str(s) => s.parse::<std::net::Ipv4Addr>().map(IpAddr::V4).or_else(|_| s.parse::<std::net::Ipv6Addr>().map(IpAddr::V6)).ok(),
        Py::Int(i) => {
            let n: u128 = i.parse().ok()?;
            if n < (1u128 << 32) {
                Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32)))
            } else {
                Some(IpAddr::V6(std::net::Ipv6Addr::from(n)))
            }
        }
        _ => None,
    }
}

fn in_net(ip: &IpAddr, nets: &[(&str, u8)]) -> bool {
    nets.iter().any(|(n, len)| match (ip, n.parse::<IpAddr>().unwrap()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let m = if *len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(*a) & m == u32::from(b) & m
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let m = if *len == 0 { 0 } else { u128::MAX << (128 - len) };
            u128::from(*a) & m == u128::from(b) & m
        }
        _ => false,
    })
}

/// `ip.is_private or ip.is_loopback or ip.is_reserved` (Python 3.10 tables).
pub fn private_loopback_reserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => in_net(
            ip,
            &[
                ("0.0.0.0", 8),
                ("10.0.0.0", 8),
                ("127.0.0.0", 8),
                ("169.254.0.0", 16),
                ("172.16.0.0", 12),
                ("192.0.0.0", 29),
                ("192.0.0.170", 31),
                ("192.0.2.0", 24),
                ("192.168.0.0", 16),
                ("198.18.0.0", 15),
                ("198.51.100.0", 24),
                ("203.0.113.0", 24),
                ("240.0.0.0", 4),
                ("255.255.255.255", 32),
            ],
        ),
        IpAddr::V6(_) => in_net(
            ip,
            &[
                // is_private
                ("::1", 128),
                ("::", 128),
                ("::ffff:0:0", 96),
                ("100::", 64),
                ("2001::", 23),
                ("2001:2::", 48),
                ("2001:db8::", 32),
                ("2001:10::", 28),
                ("fc00::", 7),
                ("fe80::", 10),
                // is_reserved
                ("::", 8),
                ("100::", 8),
                ("200::", 7),
                ("400::", 6),
                ("800::", 5),
                ("1000::", 4),
                ("4000::", 3),
                ("6000::", 3),
                ("8000::", 3),
                ("a000::", 3),
                ("c000::", 3),
                ("e000::", 4),
                ("f000::", 5),
                ("f800::", 6),
                ("fe00::", 9),
            ],
        ),
    }
}

struct Api {
    endpoint: String,
    token: String,
}

impl Api {
    fn get(&self, parts: &[&str]) -> R<Py> {
        let mut all = vec![self.endpoint.as_str()];
        all.extend_from_slice(parts);
        let url = path_join(&all);
        let auth = format!("Bearer {}", self.token);
        super::get_url(&url, &[], &[("Accept", "application/json"), ("Authorization", &auth)], None)?.json()
    }
}

fn str_arg<'a>(v: &'a Py) -> R<&'a str> {
    v.as_str().ok_or_else(|| PyErr::Type("expected str, bytes or os.PathLike object".into()))
}

/// `get_ioc_confidence`
fn confidence(ioc: &Py) -> R<&'static str> {
    let c = get(ioc, "classification")?;
    let Some(c) = c.filter(|c| c.truthy()) else { return Ok("Not Specified") };
    let sightings = match get(ioc, "blacklist")? {
        Some(Py::List(l)) => l.len(),
        _ => 0,
    };
    Ok(match c.as_str() {
        Some("malicious") => if sightings > 1 { "High" } else { "Medium" },
        Some("suspicious") => if sightings > 1 { "Medium" } else { "Low" },
        Some("neutral") | Some("whitelist") => if sightings > 1 { "Low" } else { "None" },
        _ => "None",
    })
}

/// `', '.join(sorted(set([b.get(k) for b in blacklist])))`
fn joined(blacklist: &[Py], k: &str) -> R<String> {
    let mut vals: Vec<Py> = Vec::new();
    for b in blacklist {
        let v = get(b, k)?.cloned().unwrap_or(Py::None);
        if !vals.contains(&v) {
            vals.push(v);
        }
    }
    if vals.iter().all(|v| v.as_str().is_some()) {
        let mut s: Vec<String> = vals.into_iter().map(|v| v.as_str().unwrap().to_string()).collect();
        s.sort();
        return Ok(s.join(", "));
    }
    if vals.len() > 1 {
        return Err(PyErr::Type("'<' not supported between instances of 'NoneType' and 'str'".into()));
    }
    Err(PyErr::Type(format!("sequence item 0: expected str instance, {} found", if vals[0] == Py::None { "NoneType" } else { "int" })))
}

/// `maltiverse_alert`
fn maltiverse_alert(alert_id: &Py, ioc: &Py, name: &Py, ioc_ref: Option<&str>) -> R<Py> {
    let blacklist = match get(ioc, "blacklist")? {
        Some(Py::List(l)) => l.clone(),
        Some(_) | None => Vec::new(),
    };
    let ty = get(ioc, "type")?.cloned().unwrap_or(Py::None);
    let r = match ioc_ref {
        Some(r) => r.to_string(),
        None => fmt(name),
    };
    let ecs = if ty.as_str() == Some("ip") && get(ioc, "ip_version")?.and_then(Py::num) == Some(6.0) {
        "ipv6".to_string()
    } else if ty.as_str() == Some("ip") {
        "ipv4".to_string()
    } else if ty.truthy() {
        fmt(&ty)
    } else {
        "unknown".into()
    };
    let ecs_type = match ecs.as_str() {
        "ip" | "ipv4" => Py::str("ipv4-addr"),
        "ipv6" => Py::str("ipv6-addr"),
        "hostname" => Py::str("domain-name"),
        "sample" => Py::str("file"),
        "url" => Py::str("url"),
        _ => Py::None,
    };
    let mut indicator = dict(vec![
        ("name", name.clone()),
        ("type", ecs_type),
        ("description", Py::Str(joined(&blacklist, "description")?)),
        ("provider", Py::Str(joined(&blacklist, "source")?)),
        ("first_seen", get(ioc, "creation_time")?.cloned().unwrap_or(Py::None)),
        ("modified_at", get(ioc, "modification_time")?.cloned().unwrap_or(Py::None)),
        ("last_seen", get(ioc, "modification_time")?.cloned().unwrap_or(Py::None)),
        ("confidence", Py::str(confidence(ioc)?)),
        ("sightings", Py::int(blacklist.len() as i64)),
        ("reference", Py::Str(if ty.truthy() { format!("https://maltiverse.com/{}/{r}", fmt(&ty)) } else { String::new() })),
    ]);
    if ty.as_str() == Some("ip") {
        indicator.set("ip", name.clone());
    }
    let mut threat = dict(vec![("indicator", indicator)]);
    // get_mitre_information: the last mitre-attack software reference
    let mut software = None;
    for ind in &blacklist {
        let refs = match get(ind, "external_references")? {
            Some(Py::List(l)) => l.clone(),
            _ => Vec::new(),
        };
        for er in &refs {
            if get(er, "source_name")?.and_then(Py::as_str) != Some("mitre-attack") {
                continue;
            }
            let ext = get(er, "external_id")?.cloned().unwrap_or(Py::str(""));
            if ext.as_str().is_some_and(|s| s.starts_with('S')) {
                software = Some(dict(vec![
                    ("id", ext.clone()),
                    ("reference", get(er, "url")?.cloned().unwrap_or(Py::None)),
                    ("name", get(er, "description")?.cloned().unwrap_or(Py::None)),
                ]));
            }
        }
    }
    if let Some(sw) = software {
        threat.set("software", sw);
    }
    Ok(dict(vec![
        ("integration", Py::str("maltiverse")),
        ("alert_id", alert_id.clone()),
        ("maltiverse", dict(vec![("source", ioc.clone())])),
        ("threat", threat),
    ]))
}

fn request_info(ctx: &Ctx, alert: &Py, api: &Api) -> R<Vec<Py>> {
    let mut out = Vec::new();
    let id = || idx(alert, "id").cloned();
    if contains(alert, "syscheck")? && contains(idx(alert, "syscheck")?, "md5_after")? {
        let md5 = idx(idx(alert, "syscheck")?, "md5_after")?;
        ctx.debug(&format!("# Maltiverse: MD5 checksum present in the alert: {}", fmt(md5)));
        let ioc = api.get(&["sample", "md5", str_arg(md5)?])?;
        if ioc.truthy() {
            out.push(maltiverse_alert(&id()?, &ioc, md5, None)?);
        }
    }
    if contains(alert, "syscheck")? && contains(idx(alert, "syscheck")?, "sha1_after")? {
        let sha1 = idx(idx(alert, "syscheck")?, "sha1_after")?;
        ctx.debug(&format!("# Maltiverse: SHA1 checksum present in the alert: {}", fmt(sha1)));
        let ioc = api.get(&["sample", "sha1", str_arg(sha1)?])?;
        if ioc.truthy() {
            out.push(maltiverse_alert(&id()?, &ioc, sha1, None)?);
        }
    }
    if contains(alert, "data")? && contains(idx(alert, "data")?, "srcip")? {
        let ip = idx(idx(alert, "data")?, "srcip")?;
        ctx.debug(&format!("# Maltiverse: Source IP Address present in the alert: {}", fmt(ip)));
        match ip_address(ip) {
            None => ctx.debug(&format!("# Maltiverse: Invalid IP address format: {}", fmt(ip))),
            Some(a) if private_loopback_reserved(&a) => ctx.debug(&format!("# Maltiverse: Skipping private/reserved IP: {}", fmt(ip))),
            Some(_) => {
                let ioc = api.get(&["ip", str_arg(ip)?])?;
                if ioc.truthy() {
                    out.push(maltiverse_alert(&id()?, &ioc, ip, None)?);
                }
            }
        }
    }
    if contains(alert, "data")? && contains(idx(alert, "data")?, "hostname")? {
        let h = idx(idx(alert, "data")?, "hostname")?;
        ctx.debug(&format!("# Maltiverse: Hostname present in the alert: {}", fmt(h)));
        let ioc = api.get(&["hostname", str_arg(h)?])?;
        if ioc.truthy() {
            out.push(maltiverse_alert(&id()?, &ioc, h, None)?);
        }
    }
    if contains(alert, "data")? && contains(idx(alert, "data")?, "url")? {
        let u = idx(idx(alert, "data")?, "url")?;
        let sum: String = sha2::Sha256::digest(str_arg(u)?.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        ctx.debug(&format!("# Maltiverse: URL present in the alert: {}", fmt(u)));
        let ioc = api.get(&["url", &sum])?;
        if ioc.truthy() {
            out.push(maltiverse_alert(&id()?, &ioc, u, Some(&sum))?);
        }
    }
    Ok(out)
}

fn send_event(ctx: &Ctx, msg: &Py, agent: &Py) -> R<()> {
    let event = match agent_location(agent, "maltiverse")? {
        None => format!("1:maltiverse:{}", dumps(msg)),
        Some(loc) => format!("1:{loc}:{}", dumps(msg)),
    };
    ctx.debug(&event);
    if event.chars().count() > MAX_EVENT_SIZE {
        ctx.debug(&format!("# WARNING: Message size exceeds the maximum allowed limit of {MAX_EVENT_SIZE} bytes."));
    }
    match super::queue_send(ctx, event.as_bytes()) {
        Err(111) => {
            println!("ERROR: Wazuh is not running.");
            Err(PyErr::Exit(6))
        }
        Err(90) => {
            println!("ERROR: Message too long to send to Wazuh.");
            Err(PyErr::Exit(7))
        }
        // other socket errors are ignored by the script
        _ => Ok(()),
    }
}

pub fn main(ctx: &mut Ctx) -> R<()> {
    let a = &ctx.args;
    let (msg, bad) = if a.len() >= 4 {
        ctx.debug_enabled = a.len() > 4 && a[4] == "debug";
        (String::new(), false)
    } else {
        ("# ERROR: Wrong arguments\n".to_string(), true)
    };
    ctx.append_log(&msg)?;
    if bad {
        ctx.debug(&format!("# ERROR: Exiting, bad arguments. Inputted: {}", args_repr(&ctx.args)));
        return Err(PyErr::Exit(2));
    }
    ctx.debug("# Starting");
    let alert_file = ctx.arg(1).to_string();
    let api_key = ctx.arg(2).to_string();
    let hook_url = ctx.arg(3).to_string();
    if !is_valid_url(&hook_url) {
        ctx.debug(&format!("# Hook URL argument seems to be invalid: {hook_url}"));
        return Err(PyErr::Exit(5));
    }
    let alert = ctx.json_alert(&alert_file, (3, 4), "# Alert file {} doesn't exist", "Failed getting json_alert: {}")?;
    ctx.debug(&format!("# File location: {alert_file}"));
    ctx.debug(&format!("# API Key: {api_key}"));
    ctx.debug(&format!("# Hook Url: {hook_url}"));
    ctx.debug(&format!("# Processing alert: {}", repr(&alert)));
    let api = Api { endpoint: hook_url, token: api_key };
    for m in request_info(ctx, &alert, &api)? {
        send_event(ctx, &m, idx(&alert, "agent")?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_ips() {
        assert!(is_valid_url("https://api.maltiverse.com"));
        assert!(is_valid_url("http://127.0.0.1:8080/x"));
        assert!(!is_valid_url("ftp://x.com"));
        assert!(!is_valid_url("https://user@x.com"));
        assert!(!is_valid_url("https://x.com/a<b"));
        assert_eq!(path_join(&["https://h/", "ip", "1.2.3.4"]), "https://h/ip/1.2.3.4");
        assert_eq!(path_join(&["https://h", "sample", "/abs"]), "/abs");
        for (ip, skip) in [("8.8.8.8", false), ("10.1.2.3", true), ("192.0.2.5", true), ("::1", true), ("2a00:1450::1", false), ("2001:db8::1", true)] {
            assert_eq!(private_loopback_reserved(&ip.parse().unwrap()), skip, "{ip}");
        }
        assert!(ip_address(&Py::str("01.2.3.4")).is_none());
    }
}
