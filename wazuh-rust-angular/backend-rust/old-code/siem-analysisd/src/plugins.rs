//! Plugin decoders (analysisd/decoders/plugins/*.c).

use std::sync::OnceLock;

use siem_cjson::Json;
use siem_regex::{OsRegex, OS_RETURN_SUBSTRING};

use crate::decoders::*;
use crate::event::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plugin {
    Pf,
    SymantecWs,
    SonicWall,
    OssecAlert,
    Json,
}

impl Plugin {
    /// `plugin_decoders[]` lookup (exact name).
    pub fn from_name(name: &str) -> Option<Plugin> {
        match name {
            "PF_Decoder" => Some(Plugin::Pf),
            "SymantecWS_Decoder" => Some(Plugin::SymantecWs),
            "SonicWall_Decoder" => Some(Plugin::SonicWall),
            "OSSECAlert_Decoder" => Some(Plugin::OssecAlert),
            "JSON_Decoder" => Some(Plugin::Json),
            _ => None,
        }
    }
}

pub fn run(p: Plugin, decs: &mut Decoders, ev: &mut Event, dm: &mut Vec<Bytes>, ctx: &DecodeCtx<'_>) {
    match p {
        Plugin::Pf => pf_decoder(ev),
        Plugin::SymantecWs => symantecws_decoder(ev),
        Plugin::SonicWall => sonicwall_decoder(decs, ev, dm),
        Plugin::OssecAlert => ossecalert_decoder(decs, ev, ctx),
        Plugin::Json => json_decoder(decs, ev, ctx.order_size),
    }
}

fn find(s: &[u8], c: u8) -> Option<usize> {
    s.iter().position(|&x| x == c)
}

/* ---------------------------------------------------------------- JSON */

/// `fillData`
pub(crate) fn fill_data(ev: &mut Event, key: Option<&[u8]>, value: &[u8], order_size: usize) {
    let Some(key) = key else {
        return;
    };
    let v = value.to_vec();
    let idx = match key {
        b"srcip" => Some(F_SRCIP),
        b"dstip" => Some(F_DSTIP),
        b"dstport" => Some(F_DSTPORT),
        b"srcport" => Some(F_SRCPORT),
        b"protocol" => Some(F_PROTOCOL),
        b"action" => Some(F_ACTION),
        b"srcuser" => Some(F_SRCUSER),
        b"dstuser" => Some(F_DSTUSER),
        _ => None,
    };
    if let Some(i) = idx {
        ev.f[i] = Some(v);
        return;
    }
    if key == b"user" && ev.f[F_DSTUSER].as_ref().map_or(true, |d| d.is_empty()) {
        ev.f[F_DSTUSER] = Some(v);
        return;
    }
    let idx = match key {
        b"id" => Some(F_ID),
        b"status" => Some(F_STATUS),
        b"url" => Some(F_URL),
        b"data" => Some(F_DATA),
        b"extra_data" => Some(F_EXTRA_DATA),
        b"systemname" => Some(F_SYSTEMNAME),
        _ => None,
    };
    if let Some(i) = idx {
        ev.f[i] = Some(v);
        return;
    }
    if ev.fields.len() >= order_size {
        // merror("Too many fields for JSON decoder.")
        return;
    }
    ev.fields.push(DynamicField { key: key.to_vec(), value: Some(v) });
}

fn json_number_text(double: f64, int: i32) -> Vec<u8> {
    if int as f64 == double {
        int.to_string().into_bytes()
    } else {
        siem_cjson::fmt_f6(double).into_bytes()
    }
}

const OS_MAXSTR: usize = 65536;

/// `readJSON`
fn read_json(items: &[(Option<&[u8]>, &Json)], parent: Option<&[u8]>, ev: &mut Event, flags: u8, order_size: usize) {
    for (name, item) in items {
        let key: Option<Vec<u8>> = name.map(|n| match parent {
            Some(p) => {
                let mut k = p.to_vec();
                k.push(b'.');
                k.extend_from_slice(n);
                k
            }
            None => n.to_vec(),
        });
        let key_ref = key.as_deref();
        match item {
            Json::String(s) => fill_data(ev, key_ref, siem_cjson_cstr(s), order_size),
            Json::Number { double, int } => fill_data(ev, key_ref, &json_number_text(*double, *int), order_size),
            Json::Array(arr) => {
                let mut value: Option<Vec<u8>> = None;
                if flags & JSON_TREAT_ARRAY_AS_CSV_STRING != 0 {
                    let mut v: Vec<u8> = Vec::new();
                    let mut ok = true;
                    for (i, a) in arr.iter().enumerate() {
                        let piece: Vec<u8> = match a {
                            Json::String(s) => siem_cjson_cstr(s).to_vec(),
                            Json::Number { double, int } => json_number_text(*double, *int),
                            Json::Null => b"null".to_vec(),
                            Json::True => b"true".to_vec(),
                            Json::False => b"false".to_vec(),
                            _ => continue,
                        };
                        if v.len() + piece.len() < OS_MAXSTR {
                            v.extend_from_slice(&piece);
                        } else {
                            ok = false;
                            break;
                        }
                        if v.len() + 1 >= OS_MAXSTR {
                            ok = false;
                            break;
                        } else if i + 1 < arr.len() {
                            v.push(b',');
                        }
                    }
                    if !ok {
                        v.clear();
                    }
                    value = Some(v);
                } else if flags & JSON_TREAT_ARRAY_AS_ARRAY != 0 {
                    value = Some(item.print());
                }
                if let Some(v) = value {
                    if !v.is_empty() {
                        fill_data(ev, key_ref, &v, order_size);
                    }
                }
            }
            Json::Null => {
                if flags & JSON_TREAT_NULL_AS_STRING != 0 {
                    fill_data(ev, key_ref, b"null", order_size);
                }
            }
            Json::True => fill_data(ev, key_ref, b"true", order_size),
            Json::False => fill_data(ev, key_ref, b"false", order_size),
            Json::Object(members) => {
                let children: Vec<(Option<&[u8]>, &Json)> = members.iter().map(|(k, v)| (Some(k.as_slice()), v)).collect();
                read_json(&children, key_ref, ev, flags, order_size);
            }
            Json::Raw(_) => {}
        }
    }
}

/// A cJSON `valuestring` is a C string: it ends at the first NUL.
fn siem_cjson_cstr(s: &[u8]) -> &[u8] {
    cstr(s, 0)
}

/// `JSON_Decoder_Exec`
pub(crate) fn json_decoder(decs: &mut Decoders, ev: &mut Event, order_size: usize) {
    let info = &decs.infos[ev.decoder];
    let input: Option<isize> = match info.plugin_offset {
        0 => Some(ev.log as isize),
        AFTER_PARENT => ev.log_after_parent,
        AFTER_PREMATCH => ev.log_after_prematch,
        _ => None,
    };
    let flags = info.flags;
    let Some(input) = input else {
        return;
    };
    let text = cstr(&ev.buf, input.max(0) as usize).to_vec();
    if let Ok((root, _)) = siem_cjson::parse_with_opts(&text, false) {
        read_json(&[(None, &root)], None, ev, flags, order_size);
    }
}

/* ------------------------------------------------------------------ PF */

/// `PF_Decoder_Exec`
fn pf_decoder(ev: &mut Event) {
    let log = ev.log().to_vec();
    let Some(mut t) = find(&log, b')') else {
        return;
    };
    let at = |i: usize| log.get(i).copied().unwrap_or(0);
    t += 1;
    if at(t) != b' ' {
        return;
    }
    t += 1;
    match at(t) {
        b'p' => ev.f[F_ACTION] = Some(b"pass".to_vec()),
        b'b' => ev.f[F_ACTION] = Some(b"block".to_vec()),
        _ => return,
    }
    let Some(c) = find(&log[t..], b':') else {
        return;
    };
    t += c + 1;
    if at(t) != b' ' {
        return;
    }
    t += 1;
    let Some(sp) = find(&log[t..], b' ') else {
        return;
    };
    let mut aux = t + sp;
    let mut srcip = log[t..aux].to_vec();
    aux += 1;
    // Source port after the 4th dot
    let mut dots = 0;
    for i in 0..srcip.len() {
        if srcip[i] == b'.' {
            dots += 1;
        }
        if dots == 4 {
            ev.f[F_SRCPORT] = Some(srcip[i + 1..].to_vec());
            srcip.truncate(i);
            break;
        }
    }
    ev.f[F_SRCIP] = Some(srcip);
    if at(aux) != b'>' {
        return;
    }
    aux += 1;
    if at(aux) != b' ' {
        return;
    }
    aux += 1;
    let Some(c) = find(&log[aux..], b':') else {
        return;
    };
    let mut t = aux + c;
    let mut dstip = log[aux..t].to_vec();
    t += 1;
    let mut dots = 0;
    for i in 0..dstip.len() {
        if dstip[i] == b'.' {
            dots += 1;
        }
        if dots == 4 {
            ev.f[F_DSTPORT] = Some(dstip[i + 1..].to_vec());
            dstip.truncate(i);
            break;
        }
    }
    ev.f[F_DSTIP] = Some(dstip);
    while at(t) != 0 {
        if at(t) == b' ' {
            t += 1;
            continue;
        } else if at(t) == b'u' {
            ev.f[F_PROTOCOL] = Some(b"UDP".to_vec());
        } else if at(t) == b'i' {
            ev.f[F_PROTOCOL] = Some(b"ICMP".to_vec());
        } else {
            ev.f[F_PROTOCOL] = Some(b"TCP".to_vec());
        }
        break;
    }
}

/* ---------------------------------------------------------- SymantecWS */

/// `SymantecWS_Decoder_Exec`
fn symantecws_decoder(ev: &mut Event) {
    let log = ev.log().to_vec();
    let at = |i: usize| log.get(i).copied().unwrap_or(0);
    // Both strchr calls find the same first comma.
    let Some(c) = find(&log, b',') else {
        return;
    };
    let mut t: Option<usize> = Some(c + 1);
    while let Some(mut p) = t {
        let rest = &log[p.min(log.len())..];
        let take = |p: &mut usize, limit: usize, stop_comma: bool| -> Vec<u8> {
            let mut buf = Vec::new();
            while at(*p) != 0 && buf.len() < limit && (!stop_comma || at(*p) != b',') {
                buf.push(at(*p));
                *p += 1;
            }
            buf
        };
        if rest.starts_with(b"10=") {
            p += 3;
            let b = take(&mut p, 128, true);
            if ev.f[F_DSTUSER].is_none() {
                ev.f[F_DSTUSER] = Some(b);
            }
        } else if rest.starts_with(b"11=") {
            p += 3;
            let b = take(&mut p, 128, true);
            if ev.f[F_SRCIP].is_none() {
                ev.f[F_SRCIP] = Some(b);
            }
        } else if rest.starts_with(b"60=") {
            p += 3;
            let b = take(&mut p, 1024, true);
            if ev.f[F_URL].is_none() {
                ev.f[F_URL] = Some(b);
            }
        } else if rest.starts_with(b"3=") || rest.starts_with(b"2=") {
            let b = take(&mut p, 9, false);
            if ev.f[F_ID].is_none() {
                ev.f[F_ID] = Some(b);
            }
        }
        t = find(&log[p.min(log.len())..], b',').map(|c| p + c + 1);
    }
}

/* ----------------------------------------------------------- SonicWall */

struct SonicRegexes {
    prid: OsRegex,
    sdip: OsRegex,
    prox: OsRegex,
}

fn sonic() -> &'static SonicRegexes {
    static R: OnceLock<SonicRegexes> = OnceLock::new();
    R.get_or_init(|| SonicRegexes {
        prid: OsRegex::compile("pri=(\\d) c=(\\d+) m=(\\d+) ", OS_RETURN_SUBSTRING).expect("sonicwall regid"),
        sdip: OsRegex::compile("src=(\\d+.\\d+.\\d+.\\d+):(\\d+):\\S+ dst=(\\d+.\\d+.\\d+.\\d+):(\\d+):", OS_RETURN_SUBSTRING)
            .expect("sonicwall regex"),
        prox: OsRegex::compile("result=(\\d+) dstname=(\\S+) arg=(\\S+)$", OS_RETURN_SUBSTRING).expect("sonicwall proxy"),
    })
}

/// `OSRegex_Execute_ex` with an external `regex_matching`.
fn osregex_ex(r: &OsRegex, s: &[u8], dm: &mut Vec<Bytes>) -> Option<isize> {
    dm.clear();
    let m = r.execute_bytes(s)?;
    *dm = m.sub_bytes;
    Some(m.end)
}

/// `SonicWall_Decoder_Exec`
fn sonicwall_decoder(decs: &mut Decoders, ev: &mut Event, dm: &mut Vec<Bytes>) {
    let rx = sonic();
    let dec = ev.decoder;
    decs.infos[dec].type_ = SYSLOG;

    let log = ev.log().to_vec();
    let Some(end1) = osregex_ex(&rx.prid, &log, dm) else {
        return;
    };
    if dm.len() < 3 {
        dm.clear();
        return;
    }
    ev.f[F_STATUS] = Some(dm[0].clone());
    ev.f[F_ID] = Some(dm[2].clone());
    let category: Vec<u8> = dm[1].iter().take(7).copied().collect();
    dm.clear();

    // Get ips and ports (the search starts at the end of the first match)
    let t1 = end1.max(0) as usize;
    let s2 = cstr(&log, t1).to_vec();
    let Some(end2) = osregex_ex(&rx.sdip, &s2, dm) else {
        return;
    };
    if dm.len() < 4 {
        dm.clear();
        return;
    }
    ev.f[F_SRCIP] = Some(dm[0].clone());
    ev.f[F_SRCPORT] = Some(dm[1].clone());
    ev.f[F_DSTIP] = Some(dm[2].clone());
    ev.f[F_DSTPORT] = Some(dm[3].clone());
    dm.clear();

    // Look for protocol (tmp_str is the end of the second match)
    let mut tmp: Option<usize> = {
        let base = t1 + end2.max(0) as usize;
        find(cstr(&log, base), b' ').map(|r| base + r)
    };
    if let Some(mut t) = tmp {
        t += 1;
        let at = |i: usize| log.get(i).copied().unwrap_or(0);
        if cstr(&log, t).starts_with(b"proto=") {
            t += 6;
            let mut proto = Vec::new();
            while siem_regex::is_valid_hostname_char(at(t)) && at(t) != b'/' {
                proto.push(at(t));
                t += 1;
                if proto.len() >= 6 {
                    break;
                }
            }
            ev.f[F_PROTOCOL] = Some(proto);
        }
        tmp = Some(t);
    }

    let id = ev.f[F_ID].clone().unwrap_or_default();
    if category == b"32" {
        decs.infos[dec].type_ = IDS;
    } else if id == b"98" || id == b"597" || id == b"598" {
        decs.infos[dec].type_ = FIREWALL;
        ev.f[F_ACTION] = Some(b"pass".to_vec());
    } else if id == b"38" || id == b"36" || id == b"173" || id == b"174" || id == b"37" {
        decs.infos[dec].type_ = FIREWALL;
        ev.f[F_ACTION] = Some(b"drop".to_vec());
    } else if id == b"537" {
        decs.infos[dec].type_ = FIREWALL;
        ev.f[F_ACTION] = Some(b"close".to_vec());
    } else if id == b"97" {
        decs.infos[dec].type_ = SQUID;
        let Some(t) = tmp else {
            return;
        };
        let s3 = cstr(&log, t).to_vec();
        if osregex_ex(&rx.prox, &s3, dm).is_none() {
            return;
        }
        match dm.first() {
            Some(code) => ev.f[F_ID] = Some(code.clone()),
            None => return,
        }
        if dm.len() >= 3 {
            let mut url = dm[1].clone();
            url.extend_from_slice(&dm[2]);
            ev.f[F_URL] = Some(url);
        }
        dm.clear();
    }
}

/* ---------------------------------------------------------- OSSECAlert */

/// `OSSECAlert_Decoder_Exec`
fn ossecalert_decoder(decs: &mut Decoders, ev: &mut Event, ctx: &DecodeCtx<'_>) {
    decs.infos[ev.decoder].type_ = OSSEC_ALERT;
    let log = ev.log().to_vec();
    if !(log.starts_with(&b"Alert Level: "[..12]) || log.starts_with(&b"ossec: Alert Level:"[..18])) {
        return;
    }
    let Some(c) = find(&log, b';') else {
        return;
    };
    let mut t = c + 1;
    let Some(c) = find(&log[t..], b':') else {
        return;
    };
    t += c + 1;
    if log.get(t) != Some(&b' ') {
        return;
    }
    t += 1;
    let id_start = t;
    let Some(c) = find(&log[t..], b' ') else {
        return;
    };
    t += c;
    let oa_id = String::from_utf8_lossy(&log[id_start..t]).into_owned();
    let Some(&rule) = ctx.rules_hash.get(&oa_id) else {
        return;
    };
    let Some(c) = find(&log[t..], b';') else {
        return;
    };
    t += c + 1;
    if !log[t..].starts_with(b" Location: ") {
        return;
    }
    t += 11;
    let loc_start = t;
    let Some(c) = find(&log[t..], b';') else {
        return;
    };
    t += c;
    let oa_location = &log[loc_start..t];

    let mut newloc = ev.f[F_LOCATION].clone().unwrap_or_default();
    newloc.push(b'|');
    newloc.extend_from_slice(oa_location);
    newloc.truncate(254);
    ev.f[F_LOCATION] = Some(newloc.clone());
    ev.hostname = Some(newloc);

    t += 1;
    let at = |i: usize| log.get(i).copied().unwrap_or(0);
    while at(t) == b' ' && at(t + 1) != b' ' {
        t += 1;
        let val_start = t;
        let Some(c) = find(&log[t..], b';') else {
            return;
        };
        t += c;
        let val = &log[val_start..t];
        if let Some(v) = val.strip_prefix(b"srcip: ") {
            ev.f[F_SRCIP] = Some(v.to_vec());
        }
        if let Some(v) = val.strip_prefix(b"user: ") {
            ev.f[F_DSTUSER] = Some(v.to_vec());
        }
        t += 1;
    }
    while at(t) == b' ' {
        t += 1;
    }
    let mut full: Vec<u8> = log[t.min(log.len())..].to_vec();
    full.truncate(4094);
    full.push(0);
    ev.buf = full;
    ev.log = 0;
    ev.generated_rule = Some(rule);
}
