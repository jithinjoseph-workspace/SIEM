//! Plugin decoders (spec section 2.15): PF firewall, Symantec web security, SonicWall,
//! alerts read back from another manager, and JSON.

use std::sync::OnceLock;

use provigil_json::Json;
use provigil_regex::{OsRegex, OS_RETURN_SUBSTRING};

use crate::decoders::*;
use crate::event::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plugin {
    Pf,
    SymantecWs,
    SonicWall,
    Alert,
    Json,
}

impl Plugin {
    /// By the name a decoder file gives (exact).
    pub fn named(name: &str) -> Option<Plugin> {
        Some(match name {
            "PF_Decoder" => Plugin::Pf,
            "SymantecWS_Decoder" => Plugin::SymantecWs,
            "SonicWall_Decoder" => Plugin::SonicWall,
            "OSSECAlert_Decoder" => Plugin::Alert,
            "JSON_Decoder" => Plugin::Json,
            _ => return None,
        })
    }
}

pub fn run(p: Plugin, decoders: &mut [Decoder], ev: &mut Event, groups: &mut Vec<Bytes>, cx: &Context<'_>) {
    match p {
        Plugin::Pf => pf(ev),
        Plugin::SymantecWs => symantec(ev),
        Plugin::SonicWall => sonicwall(decoders, ev, groups),
        Plugin::Alert => alert(decoders, ev, cx),
        Plugin::Json => json(decoders, ev, cx.order_size),
    }
}

fn find(s: &[u8], c: u8) -> Option<usize> {
    s.iter().position(|&x| x == c)
}

/// Stores a value by field name: the fixed fields by their names (`user` only when the
/// destination user is still empty), the rest as dynamic fields while there is room.
pub fn fill(ev: &mut Event, key: Option<&[u8]>, value: &[u8], order_size: usize) {
    let Some(key) = key else { return };
    let fixed = match key {
        b"srcip" => Some(F_SRCIP),
        b"dstip" => Some(F_DSTIP),
        b"dstport" => Some(F_DSTPORT),
        b"srcport" => Some(F_SRCPORT),
        b"protocol" => Some(F_PROTOCOL),
        b"action" => Some(F_ACTION),
        b"srcuser" => Some(F_SRCUSER),
        b"dstuser" => Some(F_DSTUSER),
        b"user" if ev.f[F_DSTUSER].as_ref().map_or(true, |d| d.is_empty()) => Some(F_DSTUSER),
        b"id" => Some(F_ID),
        b"status" => Some(F_STATUS),
        b"url" => Some(F_URL),
        b"data" => Some(F_DATA),
        b"extra_data" => Some(F_EXTRA_DATA),
        b"systemname" => Some(F_SYSTEMNAME),
        _ => None,
    };
    if let Some(i) = fixed {
        ev.f[i] = Some(value.to_vec());
    } else if ev.fields.len() < order_size {
        ev.fields.push(DynamicField { key: key.to_vec(), value: Some(value.to_vec()) });
    }
}

/// A whole number as an integer, anything else with six decimals.
fn number_text(double: f64, int: i32) -> Vec<u8> {
    if f64::from(int) == double {
        int.to_string().into_bytes()
    } else {
        provigil_json::fmt_f6(double).into_bytes()
    }
}

const MAX_TEXT: usize = 65536;

fn read_json(items: &[(Option<&[u8]>, &Json)], parent: Option<&[u8]>, ev: &mut Event, flags: u8, order_size: usize) {
    for &(name, item) in items {
        let key = name.map(|n| match parent {
            Some(p) => [p, b".", n].concat(),
            None => n.to_vec(),
        });
        let key = key.as_deref();
        match item {
            Json::String(s) => fill(ev, key, text_at(s, 0), order_size),
            Json::Number { double, int } => fill(ev, key, &number_text(*double, *int), order_size),
            Json::True => fill(ev, key, b"true", order_size),
            Json::False => fill(ev, key, b"false", order_size),
            Json::Null => {
                if flags & JSON_NULL_STRING != 0 {
                    fill(ev, key, b"null", order_size);
                }
            }
            Json::Array(a) => {
                let value = if flags & JSON_ARRAY_CSV != 0 {
                    csv(a)
                } else if flags & JSON_ARRAY_ARRAY != 0 {
                    item.print()
                } else {
                    Vec::new()
                };
                if !value.is_empty() {
                    fill(ev, key, &value, order_size);
                }
            }
            Json::Object(members) => {
                let children: Vec<(Option<&[u8]>, &Json)> = members.iter().map(|(k, v)| (Some(k.as_slice()), v)).collect();
                read_json(&children, key, ev, flags, order_size);
            }
        }
    }
}

/// The scalar members joined with commas (nested arrays and objects left out, without
/// their comma); empty when the text would not fit.
fn csv(a: &[Json]) -> Vec<u8> {
    let mut v = Vec::new();
    for (i, x) in a.iter().enumerate() {
        let piece = match x {
            Json::String(s) => text_at(s, 0).to_vec(),
            Json::Number { double, int } => number_text(*double, *int),
            Json::Null => b"null".to_vec(),
            Json::True => b"true".to_vec(),
            Json::False => b"false".to_vec(),
            _ => continue,
        };
        if v.len() + piece.len() >= MAX_TEXT {
            return Vec::new();
        }
        v.extend_from_slice(&piece);
        if v.len() + 1 >= MAX_TEXT {
            return Vec::new();
        }
        if i + 1 < a.len() {
            v.push(b',');
        }
    }
    v
}

/// JSON: every member becomes a field (`a.b` for nested ones).
pub fn json(decoders: &[Decoder], ev: &mut Event, order_size: usize) {
    let d = &decoders[ev.decoder];
    let at = match d.plugin_offset {
        0 => Some(ev.log_start as isize),
        AFTER_PARENT => ev.after_parent,
        AFTER_PREMATCH => ev.after_prematch,
        _ => None,
    };
    let Some(at) = at else { return };
    let text = text_at(&ev.buf, at.max(0) as usize).to_vec();
    if let Ok((root, _)) = provigil_json::parse_with_opts(&text, false) {
        read_json(&[(None, &root)], None, ev, d.json_flags, order_size);
    }
}

/// PF: `... ) pass|block ...: src.port > dst.port: proto...`.
fn pf(ev: &mut Event) {
    let log = ev.log().to_vec();
    let at = |i: usize| log.get(i).copied().unwrap_or(0);
    let Some(p) = find(&log, b')') else { return };
    let mut t = p + 1;
    if at(t) != b' ' {
        return;
    }
    t += 1;
    ev.f[F_ACTION] = Some(match at(t) {
        b'p' => b"pass".to_vec(),
        b'b' => b"block".to_vec(),
        _ => return,
    });
    let Some(c) = find(&log[t..], b':') else { return };
    t += c + 1;
    if at(t) != b' ' {
        return;
    }
    t += 1;
    let Some(sp) = find(&log[t..], b' ') else { return };
    let (src, mut after) = (log[t..t + sp].to_vec(), t + sp + 1);
    let (ip, port) = split_port(src);
    if let Some(port) = port {
        ev.f[F_SRCPORT] = Some(port);
    }
    ev.f[F_SRCIP] = Some(ip);
    if at(after) != b'>' || at(after + 1) != b' ' {
        return;
    }
    after += 2;
    let Some(c) = find(&log[after..], b':') else { return };
    let (ip, port) = split_port(log[after..after + c].to_vec());
    if let Some(port) = port {
        ev.f[F_DSTPORT] = Some(port);
    }
    ev.f[F_DSTIP] = Some(ip);
    let mut t = after + c + 1;
    while at(t) == b' ' {
        t += 1;
    }
    if at(t) != 0 {
        ev.f[F_PROTOCOL] = Some(match at(t) {
            b'u' => b"UDP".to_vec(),
            b'i' => b"ICMP".to_vec(),
            _ => b"TCP".to_vec(),
        });
    }
}

/// `a.b.c.d.port`: the address and the port after the fourth dot.
fn split_port(mut s: Vec<u8>) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut dots = 0;
    for i in 0..s.len() {
        dots += usize::from(s[i] == b'.');
        if dots == 4 {
            let port = s[i + 1..].to_vec();
            s.truncate(i);
            return (s, Some(port));
        }
    }
    (s, None)
}

/// Symantec web security: `n=value` pairs after the first comma; the first of each wins.
fn symantec(ev: &mut Event) {
    let log = ev.log().to_vec();
    let at = |i: usize| log.get(i).copied().unwrap_or(0);
    let take = |p: &mut usize, limit: usize, to_comma: bool| {
        let mut b = Vec::new();
        while at(*p) != 0 && b.len() < limit && !(to_comma && at(*p) == b',') {
            b.push(at(*p));
            *p += 1;
        }
        b
    };
    let Some(c) = find(&log, b',') else { return };
    let mut next = Some(c + 1);
    while let Some(mut p) = next {
        let rest = &log[p.min(log.len())..];
        let (field, limit, skip, to_comma) = if rest.starts_with(b"10=") {
            (F_DSTUSER, 128, 3, true)
        } else if rest.starts_with(b"11=") {
            (F_SRCIP, 128, 3, true)
        } else if rest.starts_with(b"60=") {
            (F_URL, 1024, 3, true)
        } else if rest.starts_with(b"3=") || rest.starts_with(b"2=") {
            (F_ID, 9, 0, false)
        } else {
            (usize::MAX, 0, 0, false)
        };
        if field != usize::MAX {
            p += skip;
            let v = take(&mut p, limit, to_comma);
            if ev.f[field].is_none() {
                ev.f[field] = Some(v);
            }
        }
        next = find(&log[p.min(log.len())..], b',').map(|c| p + c + 1);
    }
}

struct Sonic {
    head: OsRegex,
    addresses: OsRegex,
    proxy: OsRegex,
}

fn sonic() -> &'static Sonic {
    static R: OnceLock<Sonic> = OnceLock::new();
    R.get_or_init(|| Sonic {
        head: OsRegex::compile("pri=(\\d) c=(\\d+) m=(\\d+) ", OS_RETURN_SUBSTRING).expect("SonicWall head"),
        addresses: OsRegex::compile("src=(\\d+.\\d+.\\d+.\\d+):(\\d+):\\S+ dst=(\\d+.\\d+.\\d+.\\d+):(\\d+):", OS_RETURN_SUBSTRING).expect("SonicWall addresses"),
        proxy: OsRegex::compile("result=(\\d+) dstname=(\\S+) arg=(\\S+)$", OS_RETURN_SUBSTRING).expect("SonicWall proxy"),
    })
}

fn exec(r: &OsRegex, s: &[u8], groups: &mut Vec<Bytes>) -> Option<isize> {
    groups.clear();
    let m = r.execute_bytes(s)?;
    *groups = m.sub_bytes;
    Some(m.end)
}

/// SonicWall: priority, category and message id, addresses, protocol; the message id sets
/// the decoder's event type (and the action).
fn sonicwall(decoders: &mut [Decoder], ev: &mut Event, g: &mut Vec<Bytes>) {
    let rx = sonic();
    let dec = ev.decoder;
    decoders[dec].kind = SYSLOG;
    let log = ev.log().to_vec();
    let Some(end1) = exec(&rx.head, &log, g) else { return };
    if g.len() < 3 {
        g.clear();
        return;
    }
    ev.f[F_STATUS] = Some(g[0].clone());
    ev.f[F_ID] = Some(g[2].clone());
    let category: Vec<u8> = g[1].iter().take(7).copied().collect();
    g.clear();

    let t1 = end1.max(0) as usize;
    let Some(end2) = exec(&rx.addresses, text_at(&log, t1), g) else { return };
    if g.len() < 4 {
        g.clear();
        return;
    }
    for (f, v) in [F_SRCIP, F_SRCPORT, F_DSTIP, F_DSTPORT].into_iter().zip(g.drain(..4)) {
        ev.f[f] = Some(v);
    }
    g.clear();

    let at = |i: usize| log.get(i).copied().unwrap_or(0);
    let base = t1 + end2.max(0) as usize;
    let rest = find(text_at(&log, base), b' ').map(|r| {
        let mut t = base + r + 1;
        if text_at(&log, t).starts_with(b"proto=") {
            t += 6;
            let mut proto = Vec::new();
            while provigil_regex::maps::is_valid_hostname_char(at(t)) && at(t) != b'/' {
                proto.push(at(t));
                t += 1;
                if proto.len() >= 6 {
                    break;
                }
            }
            ev.f[F_PROTOCOL] = Some(proto);
        }
        t
    });

    let id = ev.f[F_ID].clone().unwrap_or_default();
    let action = |ev: &mut Event, a: &[u8]| ev.f[F_ACTION] = Some(a.to_vec());
    match &id[..] {
        _ if category == b"32" => decoders[dec].kind = IDS,
        b"98" | b"597" | b"598" => {
            decoders[dec].kind = FIREWALL;
            action(ev, b"pass");
        }
        b"38" | b"36" | b"173" | b"174" | b"37" => {
            decoders[dec].kind = FIREWALL;
            action(ev, b"drop");
        }
        b"537" => {
            decoders[dec].kind = FIREWALL;
            action(ev, b"close");
        }
        b"97" => {
            decoders[dec].kind = SQUID;
            let Some(t) = rest else { return };
            if exec(&rx.proxy, text_at(&log, t), g).is_none() {
                return;
            }
            let Some(code) = g.first() else { return };
            ev.f[F_ID] = Some(code.clone());
            if g.len() >= 3 {
                ev.f[F_URL] = Some([g[1].as_slice(), &g[2]].concat());
            }
            g.clear();
        }
        _ => {}
    }
}

/// An alert of another manager: `Alert Level: n; Rule: id - ...; Location: where; srcip: x;
/// user: y; log`. The event gets the rule, a combined location and the original log.
fn alert(decoders: &mut [Decoder], ev: &mut Event, cx: &Context<'_>) {
    decoders[ev.decoder].kind = OSSEC_ALERT;
    let log = ev.log().to_vec();
    let at = |i: usize| log.get(i).copied().unwrap_or(0);
    if !(log.starts_with(b"Alert Level:") || log.starts_with(b"ossec: Alert Level")) {
        return;
    }
    let Some(c) = find(&log, b';') else { return };
    let Some(c2) = find(&log[c + 1..], b':') else { return };
    let mut t = c + 1 + c2 + 1;
    if at(t) != b' ' {
        return;
    }
    t += 1;
    let Some(sp) = find(&log[t..], b' ') else { return };
    let id = String::from_utf8_lossy(&log[t..t + sp]).into_owned();
    t += sp;
    let Some(&rule) = cx.rules.get(&id) else { return };
    let Some(c) = find(&log[t..], b';') else { return };
    t += c + 1;
    if !log[t..].starts_with(b" Location: ") {
        return;
    }
    t += 11;
    let Some(c) = find(&log[t..], b';') else { return };
    let mut location = ev.f[F_LOCATION].clone().unwrap_or_default();
    location.push(b'|');
    location.extend_from_slice(&log[t..t + c]);
    location.truncate(254);
    ev.f[F_LOCATION] = Some(location.clone());
    ev.hostname = Some(location);
    t += c + 1;
    while at(t) == b' ' && at(t + 1) != b' ' {
        t += 1;
        let Some(c) = find(&log[t..], b';') else { return };
        let v = &log[t..t + c];
        if let Some(x) = v.strip_prefix(b"srcip: ") {
            ev.f[F_SRCIP] = Some(x.to_vec());
        }
        if let Some(x) = v.strip_prefix(b"user: ") {
            ev.f[F_DSTUSER] = Some(x.to_vec());
        }
        t += c + 1;
    }
    while at(t) == b' ' {
        t += 1;
    }
    let mut full = log[t.min(log.len())..].to_vec();
    full.truncate(4094);
    full.push(0);
    ev.buf = full;
    ev.log_start = 0;
    ev.generated_rule = Some(rule);
}
