//! Windows eventchannel decoder (analysisd/decoders/winevtchannel.c): the
//! agent sends `{"Message": ..., "Event": "<Event>...</Event>"}`; the XML is
//! turned into `{"win":{"system":{...},"eventdata":{...}}}`, which replaces
//! the log and goes through the JSON decoder.

use siem_cjson::Json;
use siem_xml::{OsXml, RawNode};

use crate::daemon::Env;
use crate::decoders::Decoders;
use crate::event::Event;

/// `WINEVT_MOD`
pub const WINEVT_MOD: &str = "windows_eventchannel";
const OS_MAXSTR: usize = 65536;
const AUDIT_FAILURE: u64 = 0x10000000000000;
const AUDIT_SUCCESS: u64 = 0x20000000000000;

/// Process-wide state of the decoder (`first_time`).
#[derive(Debug, Default)]
pub struct Winevt {
    first_time: i32,
}

fn c_isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `wstr_unescape_json`
pub fn unescape_json(s: &[u8]) -> Vec<u8> {
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            out.push(s[i]);
            i += 1;
            continue;
        }
        i += 1;
        match s.get(i) {
            None => {
                out.push(b'\\');
            }
            Some(&c) => {
                let m = match c {
                    b'b' => Some(0x08),
                    b't' => Some(b'\t'),
                    b'n' => Some(b'\n'),
                    b'f' => Some(0x0c),
                    b'r' => Some(b'\r'),
                    b'"' => Some(b'"'),
                    b'\\' => Some(b'\\'),
                    _ => None,
                };
                match m {
                    Some(u) => out.push(u),
                    None => {
                        out.push(b'\\');
                        out.push(c);
                    }
                }
                i += 1;
            }
        }
    }
    out
}

/// `replace_win_format`
pub fn replace_win_format(s: &[u8], message: bool) -> Vec<u8> {
    let mut r = if message { unescape_json(s) } else { s.to_vec() };
    if !r.is_empty() {
        let mut e = r.len() - 1;
        let mut spaces = false;
        while e > 0 && c_isspace(r[e]) {
            e -= 1;
            spaces = true;
        }
        if spaces {
            r.truncate(e + 1);
        }
    }
    r
}

/// `wstr_replace`
fn replace(s: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    crate::output::search_and_replace(s, from, to)
}

/// `strtol(s, NULL, 10)` as an `int`.
fn strtol_int(s: &[u8]) -> i32 {
    crate::internal::rootcheck::strtol(s) as i32
}

/// `strtoull(s, NULL, 16)`
fn strtoull_hex(s: &[u8]) -> u64 {
    let mut i = 0;
    while i < s.len() && c_isspace(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    if i + 1 < s.len() && s[i] == b'0' && (s[i + 1] | 0x20) == b'x' && s.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit()) {
        i += 2;
    }
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_hexdigit() {
        let d = (s[i] as char).to_digit(16).unwrap() as u64;
        match v.checked_mul(16).and_then(|x| x.checked_add(d)) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    }
}

fn lower_first(b: &mut [u8]) {
    if let Some(c) = b.first_mut() {
        *c = c.to_ascii_lowercase();
    }
}

fn content(n: &RawNode) -> &[u8] {
    n.content.as_deref().unwrap_or(b"")
}

fn add(o: &mut Json, k: &[u8], v: &[u8]) {
    o.add(k, Json::String(v.to_vec()));
}

fn category(cat: i32, sub: i32) -> (Option<&'static str>, Option<&'static str>) {
    let (c, subs): (&str, &[(i32, &str)]) = match cat {
        8272 => (
            "System",
            &[
                (12288, "Security State Change"),
                (12289, "Security System Extension"),
                (12290, "System Integrity"),
                (12291, "IPsec Driver"),
                (12292, "Other System Events"),
            ],
        ),
        8273 => (
            "Logon/Logoff",
            &[
                (12544, "Logon"),
                (12545, "Logoff"),
                (12546, "Account Lockout"),
                (12547, "IPsec Main Mode"),
                (12548, "Special Logon"),
                (12549, "IPSec Extended Mode"),
                (12550, "IPSec Quick Mode"),
                (12551, "Other Logon/Logoff Events"),
                (12552, "Network Policy Server"),
                (12553, "User/Device Claims"),
                (12554, "Group Membership"),
            ],
        ),
        8274 => (
            "Object Access",
            &[
                (12800, "File System"),
                (12801, "Registry"),
                (12802, "Kernel Object"),
                (12803, "SAM"),
                (12804, "Other Object Access Events"),
                (12805, "Certification Services"),
                (12806, "Application Generated"),
                (12807, "Handle Manipulation"),
                (12808, "File Share"),
                (12809, "Filtering Platform Packet Drop"),
                (12810, "Filtering Platform Connection"),
                (12811, "Detailed File Share"),
                (12812, "Removable Storage"),
                (12813, "Central Policy Staging"),
            ],
        ),
        8275 => (
            "Privilege Use",
            &[(13056, "Sensitive Privilege Use"), (13057, "Non Sensitive Privilege Use"), (13058, "Other Privilege Use Events")],
        ),
        8276 => (
            "Detailed Tracking",
            &[
                (13312, "Process Creation"),
                (13313, "Process Termination"),
                (13314, "DPAPI Activity"),
                (13315, "RPC Events"),
                (13316, "Plug and Play Events"),
                (13317, "Token Right Adjusted Events"),
            ],
        ),
        8277 => (
            "Policy Change",
            &[
                (13568, "Audit Policy Change"),
                (13569, "Authentication Policy Change"),
                (13570, "Authorization Policy Change"),
                (13571, "MPSSVC Rule-Level Policy Change"),
                (13572, "Filtering Platform Policy Change"),
                (13573, "Other Policy Change Events"),
            ],
        ),
        8278 => (
            "Account Management",
            &[
                (13824, "User Account Management"),
                (13825, "Computer Account Management"),
                (13826, "Security Group Management"),
                (13827, "Distribution Group Management"),
                (13828, "Application Group Management"),
                (13829, "Other Account Management Events"),
            ],
        ),
        8279 => (
            "DS Access",
            &[
                (14080, "Directory Service Access"),
                (14081, "Directory Service Changes"),
                (14082, "Directory Service Replication"),
                (14083, "Detailed Directory Service Replication"),
            ],
        ),
        8280 => (
            "Account Logon",
            &[
                (14336, "Credential Validation"),
                (14337, "Kerberos Service Ticket Operations"),
                (14338, "Other Account Logon Events"),
                (14339, "Kerberos Authentication Service"),
            ],
        ),
        _ => return (None, None),
    };
    (Some(c), subs.iter().find(|(k, _)| *k == sub).map(|(_, v)| *v))
}

impl Winevt {
    /// `DecodeWinevt`: false when the event goes no further (the C
    /// function returns 1 for that).
    pub fn decode(&mut self, env: &mut dyn Env, decs: &mut Decoders, dec: usize, order_size: usize, ev: &mut Event) -> bool {
        ev.decoder = dec;
        ev.program_name = None;
        ev.dec_timestamp = None;
        let log = ev.log().to_vec();
        let Ok((received, _)) = siem_cjson::parse_with_opts(&log, false) else {
            env.log("ERROR", b"Malformed EventChannel JSON event.");
            return false;
        };
        let Some(json_event_in) = received.get("Event") else {
            env.log("DEBUG", b"Malformed JSON received. No 'Event' field found.");
            return false;
        };
        let mut system = Json::object();
        let mut eventdata = Json::object();
        let mut extra_in = Json::object();
        let mut extra: Option<Vec<u8>> = None;
        let mut join_data: Vec<u8> = Vec::new();
        let mut join_data2: Option<Vec<u8>> = None;
        let mut level: Option<Vec<u8>> = None;
        let mut keywords: Option<Vec<u8>> = None;
        let mut category_id: Option<Vec<u8>> = None;
        let mut subcategory_id: Option<Vec<u8>> = None;
        let mut audit_changes: Option<Vec<u8>> = None;

        let event = json_event_in.print_unformatted();
        match OsXml::read_string_bytes(&event, false) {
            Err(_) => {
                self.first_time += 1;
                let m = [&b"Could not read XML string: '"[..], &event, b"'"].concat();
                env.log(if self.first_time > 1 { "DEBUG2" } else { "WARNING" }, &m);
            }
            Ok(xml) => {
                let node = xml.get_elements_by_node_raw(None);
                let child = node.as_ref().and_then(|n| n.first()).and_then(|n0| xml.get_elements_by_node_raw(Some(n0.key)));
                for cj in child.iter().flatten() {
                    let attrs = xml.get_elements_by_node_raw(Some(cj.key));
                    for ca in attrs.into_iter().flatten() {
                        let mut ca = ca;
                        let c = content(&ca).to_vec();
                        if cj.element == b"System" {
                            let e = ca.element.clone();
                            let has_attrs = !ca.attributes.is_empty();
                            if e == b"Provider" && has_attrs {
                                for (a, v) in ca.attributes.iter().zip(&ca.values) {
                                    match &a[..] {
                                        b"Name" => add(&mut system, b"providerName", v),
                                        b"Guid" => add(&mut system, b"providerGuid", v),
                                        b"EventSourceName" => add(&mut system, b"eventSourceName", v),
                                        _ => {}
                                    }
                                }
                            } else if e == b"TimeCreated" && has_attrs {
                                if ca.attributes[0] == b"SystemTime" {
                                    add(&mut system, b"systemTime", &ca.values[0]);
                                }
                            } else if e == b"Execution" && has_attrs {
                                for (a, v) in ca.attributes.iter().zip(&ca.values) {
                                    match &a[..] {
                                        b"ProcessID" => add(&mut system, b"processID", v),
                                        b"ThreadID" => add(&mut system, b"threadID", v),
                                        _ => {}
                                    }
                                }
                            } else if e == b"Channel" {
                                add(&mut system, b"channel", &c);
                                if has_attrs && ca.values[0] == b"UserID" {
                                    add(&mut system, b"userID", &ca.values[0]);
                                }
                            } else if e == b"Security" {
                                if has_attrs && ca.values[0] == b"UserID" {
                                    add(&mut system, b"securityUserID", &ca.values[0]);
                                }
                            } else if e == b"Level" {
                                level = Some(c.clone());
                                lower_first(&mut ca.element);
                                add(&mut system, &ca.element, &c);
                            } else if e == b"Keywords" {
                                keywords = Some(c.clone());
                                lower_first(&mut ca.element);
                                add(&mut system, &ca.element, &c);
                            } else if e == b"Correlation" {
                            } else if !c.is_empty() {
                                lower_first(&mut ca.element);
                                add(&mut system, &ca.element, &c);
                            }
                        } else if cj.element == b"EventData" {
                            let valid = c != b"(NULL)" && c != b"-";
                            if ca.element == b"Data" && !ca.values.is_empty() && !c.is_empty() {
                                for l in 0..ca.attributes.len() {
                                    if ca.attributes[l] == b"Name" && valid {
                                        let fs = replace_win_format(&c, false);
                                        lower_first(&mut ca.values[l]);
                                        let name = ca.values[l].clone();
                                        if name == b"categoryId" {
                                            category_id = Some(fs.clone());
                                        } else if name == b"subcategoryId" {
                                            subcategory_id = Some(fs.clone());
                                        }
                                        if name == b"auditPolicyChanges" {
                                            audit_changes = Some(fs.clone());
                                            add(&mut eventdata, b"auditPolicyChangesId", &fs);
                                        } else {
                                            add(&mut eventdata, &name, &fs);
                                        }
                                        break;
                                    } else if valid {
                                        let fs = replace_win_format(&c, false);
                                        env.log(
                                            "DEBUG2",
                                            &[&b"Unexpected attribute at EventData ("[..], &ca.attributes[l], b")."].concat(),
                                        );
                                        lower_first(&mut ca.values[l]);
                                        let name = ca.values[l].clone();
                                        add(&mut eventdata, &name, &fs);
                                    }
                                }
                            } else if valid && !c.is_empty() {
                                let fs = replace_win_format(&c, false);
                                if !fs.is_empty() && ca.element == b"Data" {
                                    let mut j = if !join_data.is_empty() {
                                        [join_data2.as_deref().unwrap_or(b"(null)"), b", ", &fs].concat()
                                    } else {
                                        fs.clone()
                                    };
                                    j.truncate(OS_MAXSTR - 1);
                                    join_data = j;
                                    join_data2 = Some(join_data.clone());
                                } else if ca.element != b"Data" {
                                    lower_first(&mut ca.element);
                                    add(&mut eventdata, &ca.element, &fs);
                                }
                            }
                        } else {
                            env.log("DEBUG", &[&b"Unexpected element ("[..], &cj.element, b"). Decoding it."].concat());
                            for mut x in xml.get_elements_by_node_raw(Some(ca.key)).into_iter().flatten() {
                                let xc = content(&x).to_vec();
                                if xc != b"(NULL)" && xc != b"-" && !xc.is_empty() {
                                    let fs = replace_win_format(&xc, false);
                                    lower_first(&mut x.element);
                                    add(&mut extra_in, &x.element, &fs);
                                }
                            }
                            extra = Some(ca.element.clone());
                        }
                    }
                }

                if let (Some(lv), Some(kw)) = (&level, &keywords) {
                    let level_n = strtol_int(lv);
                    let keywords_n = strtoull_hex(kw);
                    let sev = match level_n {
                        1 => "CRITICAL",
                        2 => "ERROR",
                        3 => "WARNING",
                        4 => "INFORMATION",
                        5 => "VERBOSE",
                        0 if keywords_n & AUDIT_FAILURE != 0 => "AUDIT_FAILURE",
                        0 if keywords_n & AUDIT_SUCCESS != 0 => "AUDIT_SUCCESS",
                        _ => "UNKNOWN",
                    };
                    add(&mut system, b"severityValue", sev.as_bytes());
                    if let (Some(ci), Some(si)) = (&category_id, &subcategory_id) {
                        let cn = strtol_int(&replace(ci, b"%%", b""));
                        let sn = strtol_int(&replace(si, b"%%", b""));
                        let (c, s) = category(cn, sn);
                        if let Some(c) = c {
                            add(&mut eventdata, b"category", c.as_bytes());
                        }
                        if let Some(s) = s {
                            add(&mut eventdata, b"subcategory", s.as_bytes());
                        }
                    }
                }

                if let Some(ac) = &audit_changes {
                    let filtered = replace(ac, b"%%", b"");
                    let parts = siem_regex::str_break(',', &String::from_utf8_lossy(&filtered), 4).unwrap_or_default();
                    let mut pol: Option<Vec<u8>> = None;
                    for p in parts {
                        let s: &[u8] = match strtol_int(p.as_bytes()) {
                            8448 => b"Success removed",
                            8449 => b"Success added",
                            8450 => b"Failure removed",
                            8451 => b"Failure added",
                            _ => continue,
                        };
                        match &mut pol {
                            Some(v) => {
                                v.push(b',');
                                v.extend_from_slice(s);
                            }
                            None => pol = Some(s.to_vec()),
                        }
                    }
                    if let Some(p) = pol {
                        add(&mut eventdata, b"auditPolicyChanges", &replace(&p, b",", b", "));
                    }
                }
            }
        }

        if let Some(m) = received.get("Message") {
            let fs = replace_win_format(&m.print_unformatted(), true);
            add(&mut system, b"message", &fs);
        }
        let mut json_event = Json::object();
        json_event.add("system", system);
        if !join_data.is_empty() {
            add(&mut eventdata, b"data", &join_data);
        }
        if !eventdata.children().is_empty() {
            json_event.add("eventdata", eventdata);
        }
        if let Some(mut x) = extra {
            lower_first(&mut x);
            json_event.add(&x, extra_in);
        }
        let mut final_event = Json::object();
        final_event.add("win", json_event);
        let mut buf = final_event.print_unformatted();
        buf.push(0);
        ev.buf = buf;
        ev.log = 0;
        ev.decoder = dec;
        crate::plugins::json_decoder(decs, ev, order_size);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(unescape_json(br#"a\"b\\c\nd\x\"#), b"a\"b\\c\nd\\x\\");
        assert_eq!(replace_win_format(b"abc  \n", false), b"abc");
        assert_eq!(replace_win_format(b"  ", false), b" ");
        assert_eq!(replace_win_format(b" ", false), b" ");
        assert_eq!(strtoull_hex(b"0x8020000000000000"), 0x8020000000000000);
        assert_eq!(strtoull_hex(b"0x"), 0);
        assert_eq!(strtoull_hex(b"fffffffffffffffff"), u64::MAX);
    }
}
