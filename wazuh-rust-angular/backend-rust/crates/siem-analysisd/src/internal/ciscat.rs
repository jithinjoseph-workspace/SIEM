//! CIS-CAT decoder (analysisd/decoders/ciscat.c): the event is decoded as
//! JSON and, for a `scan_info` message, its summary is stored in the agent
//! database (`ciscat save`).

use siem_cjson::Json;

use crate::daemon::Env;
use crate::decoders::Decoders;
use crate::event::{Event, F_LOCATION};

/// `CISCAT_MOD`
pub const CISCAT_MOD: &str = "ciscat";
const OS_MAXSTR: usize = 65536;
const OS_SIZE_6144: usize = 6144;

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `->valueint` (0 for anything but a number).
fn valueint(j: &Json) -> i32 {
    match j {
        Json::Number { int, .. } => *int,
        _ => 0,
    }
}

/// `(int)strtoul(s, &end, 10)`
fn strtoul_int(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((s[i] - b'0') as u64)) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        v = u64::MAX;
    } else if neg {
        v = v.wrapping_neg();
    }
    v as u32 as i32
}

/// `DecodeCiscat`: false when the event goes no further.
pub fn decode(env: &mut dyn Env, decs: &mut Decoders, dec: usize, order_size: usize, ev: &mut Event) -> bool {
    // JSON_Decoder_Exec(lf, NULL, NULL) with the null decoder
    crate::plugins::json_decoder(decs, ev, order_size);
    ev.decoder = dec;

    let loc = ev.f[F_LOCATION].clone().unwrap_or_default();
    let loc = cstr(&loc);
    if loc.first() == Some(&b'(') {
        match loc.iter().position(|&c| c == b'>') {
            None => {
                env.log("DEBUG", b"Invalid received event.");
                return false;
            }
            Some(p) if &loc[p + 1..] != b"wodle_cis-cat" => {
                env.log("DEBUG", b"Invalid received event. Not CIS-CAT.");
                return false;
            }
            _ => {}
        }
    } else if loc != b"wodle_cis-cat" {
        env.log("DEBUG", b"Invalid received event. (Location)");
        return false;
    }

    let log = ev.log().to_vec();
    let Ok((root, _)) = siem_cjson::parse_with_opts(&log, false) else {
        env.log("DEBUG", b"Error parsing JSON event.");
        env.log("DEBUG2", &[&b"Input JSON: '"[..], &log].concat());
        return false;
    };
    // cJSON_GetStringValue
    let Some(Json::String(msg_type)) = root.get("type") else {
        env.log("DEBUG", b"Invalid message. Type not found or not a string.");
        return false;
    };
    if cstr(msg_type) != b"scan_info" {
        return true;
    }
    let agent = ev.agent_id.clone().unwrap_or_default();
    let Some(cis) = root.get("cis") else {
        env.log("DEBUG", &[&b"Unable to parse CIS-CAT event for agent '"[..], &agent, b"'"].concat());
        return false;
    };
    let mut msg = b"agent ".to_vec();
    msg.extend_from_slice(&agent);
    msg.extend_from_slice(b" ciscat save");
    msg.truncate(OS_MAXSTR - 2);
    // wm_strcat(&msg, value, sep)
    let add = |msg: &mut Vec<u8>, v: &[u8], sep: u8| {
        msg.push(sep);
        msg.extend_from_slice(cstr(v));
    };
    match root.get("scan_id") {
        Some(j) => add(&mut msg, valueint(j).to_string().as_bytes(), b' '),
        None => add(&mut msg, b"NULL", b' '),
    }
    for k in ["timestamp", "benchmark", "profile"] {
        match cis.get(k) {
            Some(Json::String(s)) => add(&mut msg, s, b'|'),
            _ => add(&mut msg, b"NULL", b'|'),
        }
    }
    for k in ["pass", "fail", "error", "notchecked", "unknown"] {
        match cis.get(k) {
            Some(j) => add(&mut msg, valueint(j).to_string().as_bytes(), b'|'),
            None => add(&mut msg, b"NULL", b'|'),
        }
    }
    match cis.get("score") {
        Some(Json::String(s)) => add(&mut msg, strtoul_int(cstr(s)).to_string().as_bytes(), b'|'),
        _ => add(&mut msg, b"NULL", b'|'),
    }
    match env.wdb_query_ex(&msg, OS_SIZE_6144) {
        Ok(r) => r.starts_with(b"ok ") || r == b"ok",
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores() {
        assert_eq!(strtoul_int(b"85"), 85);
        assert_eq!(strtoul_int(b" -1"), -1);
        assert_eq!(strtoul_int(b"99999999999999999999999"), -1);
        assert_eq!(strtoul_int(b"4294967297"), 1);
        assert_eq!(strtoul_int(b"x"), 0);
    }
}
