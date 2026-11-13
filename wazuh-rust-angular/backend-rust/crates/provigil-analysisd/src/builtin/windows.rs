//! Windows event channel events (spec section 2.23): the agent sends
//! `{"Message": ..., "Event": "<Event>...</Event>"}`; the XML becomes
//! `{"win":{"system":{..},"eventdata":{..}}}`, which replaces the log and is read by the JSON
//! decoder.

use provigil_daemon::xml::RawNode;
use provigil_json::Json;

use crate::decoders::DecoderSet;
use crate::event::*;
use crate::host::Host;

pub const NAME: &str = "windows_eventchannel";
const AUDIT_FAILURE: u64 = 0x10_0000_0000_0000;
const AUDIT_SUCCESS: u64 = 0x20_0000_0000_0000;

/// Unreadable XML is a warning the first time, a debug message after.
#[derive(Debug, Default)]
pub struct Windows {
    unreadable: i32,
}

fn space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// JSON string escapes (`\b \t \n \f \r \" \\`) undone; others stay as written.
pub fn json_unescape(s: &[u8]) -> Vec<u8> {
    let s = text_at(s, 0);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            out.push(s[i]);
            i += 1;
            continue;
        }
        match s.get(i + 1) {
            None => out.push(b'\\'),
            Some(&c) => {
                match c {
                    b'b' => out.push(0x08),
                    b't' => out.push(b'\t'),
                    b'n' => out.push(b'\n'),
                    b'f' => out.push(0x0c),
                    b'r' => out.push(b'\r'),
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    _ => out.extend_from_slice(&[b'\\', c]),
                }
                i += 1;
            }
        }
        i += 1;
    }
    out
}

/// Trailing white space removed (a text of white space keeps its first byte); messages
/// are JSON-unescaped first.
pub fn tidy(s: &[u8], message: bool) -> Vec<u8> {
    let mut r = if message { json_unescape(s) } else { s.to_vec() };
    if !r.is_empty() {
        let mut e = r.len() - 1;
        let mut trailing = false;
        while e > 0 && space(r[e]) {
            e -= 1;
            trailing = true;
        }
        if trailing {
            r.truncate(e + 1);
        }
    }
    r
}

fn int(s: &[u8]) -> i32 {
    super::small::long(s) as i32
}

/// `strtoull(s, 16)`.
fn hex(s: &[u8]) -> u64 {
    let mut i = s.iter().take_while(|&&c| space(c)).count();
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    if s.get(i) == Some(&b'0') && s.get(i + 1).is_some_and(|c| c | 0x20 == b'x') && s.get(i + 2).is_some_and(u8::is_ascii_hexdigit) {
        i += 2;
    }
    let mut v: u64 = 0;
    let mut over = false;
    while let Some(d) = s.get(i).and_then(|&c| (c as char).to_digit(16)) {
        match v.checked_mul(16).and_then(|x| x.checked_add(u64::from(d))) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    if over {
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

fn add(o: &mut Json, k: &[u8], v: &[u8]) {
    o.add(k, Json::String(v.to_vec()));
}

/// The audit category and subcategory names of `%%` ids.
fn category(cat: i32, sub: i32) -> (Option<&'static str>, Option<&'static str>) {
    let (c, subs): (&str, &[(i32, &str)]) = match cat {
        8272 => ("System", &[(12288, "Security State Change"), (12289, "Security System Extension"), (12290, "System Integrity"), (12291, "IPsec Driver"), (12292, "Other System Events")]),
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
        8275 => ("Privilege Use", &[(13056, "Sensitive Privilege Use"), (13057, "Non Sensitive Privilege Use"), (13058, "Other Privilege Use Events")]),
        8276 => (
            "Detailed Tracking",
            &[(13312, "Process Creation"), (13313, "Process Termination"), (13314, "DPAPI Activity"), (13315, "RPC Events"), (13316, "Plug and Play Events"), (13317, "Token Right Adjusted Events")],
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
        8279 => ("DS Access", &[(14080, "Directory Service Access"), (14081, "Directory Service Changes"), (14082, "Directory Service Replication"), (14083, "Detailed Directory Service Replication")]),
        8280 => ("Account Logon", &[(14336, "Credential Validation"), (14337, "Kerberos Service Ticket Operations"), (14338, "Other Account Logon Events"), (14339, "Kerberos Authentication Service")]),
        _ => return (None, None),
    };
    (Some(c), subs.iter().find(|(k, _)| *k == sub).map(|(_, v)| *v))
}

/// What is read from the `<Event>` XML.
#[derive(Default)]
struct Read {
    system: Vec<(Vec<u8>, Vec<u8>)>,
    eventdata: Vec<(Vec<u8>, Vec<u8>)>,
    extra: Option<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)>,
    joined: Vec<u8>,
    level: Option<Vec<u8>>,
    keywords: Option<Vec<u8>>,
    category: Option<Vec<u8>>,
    subcategory: Option<Vec<u8>>,
    audit_changes: Option<Vec<u8>>,
}

impl Read {
    fn system_item(&mut self, mut x: RawNode) {
        let first = |x: &RawNode| x.attributes.first().map(|(_, v)| v.clone());
        let c = x.content.clone();
        let named = |x: &RawNode, names: &[(&[u8], &[u8])], out: &mut Vec<(Vec<u8>, Vec<u8>)>| {
            for (a, v) in &x.attributes {
                if let Some((_, key)) = names.iter().find(|(n, _)| *n == a.as_slice()) {
                    out.push((key.to_vec(), v.clone()));
                }
            }
        };
        let has = !x.attributes.is_empty();
        match x.name.as_slice() {
            b"Provider" if has => named(&x, &[(b"Name", b"providerName"), (b"Guid", b"providerGuid"), (b"EventSourceName", b"eventSourceName")], &mut self.system),
            b"TimeCreated" if has => {
                if x.attributes[0].0 == b"SystemTime" {
                    self.system.push((b"systemTime".to_vec(), x.attributes[0].1.clone()));
                }
            }
            b"Execution" if has => named(&x, &[(b"ProcessID", b"processID"), (b"ThreadID", b"threadID")], &mut self.system),
            b"Channel" => {
                self.system.push((b"channel".to_vec(), c));
                // only when the first attribute's value is literally "UserID"
                if has && first(&x).as_deref() == Some(b"UserID") {
                    self.system.push((b"userID".to_vec(), b"UserID".to_vec()));
                }
            }
            b"Security" => {
                if has && first(&x).as_deref() == Some(b"UserID") {
                    self.system.push((b"securityUserID".to_vec(), b"UserID".to_vec()));
                }
            }
            b"Level" | b"Keywords" => {
                if x.name == b"Level" {
                    self.level = Some(c.clone());
                } else {
                    self.keywords = Some(c.clone());
                }
                lower_first(&mut x.name);
                self.system.push((x.name, c));
            }
            b"Correlation" => {}
            _ if !c.is_empty() => {
                lower_first(&mut x.name);
                self.system.push((x.name, c));
            }
            _ => {}
        }
    }

    fn eventdata_item(&mut self, host: &mut dyn Host, mut x: RawNode) {
        let c = x.content.clone();
        let valid = c != b"(NULL)" && c != b"-";
        if x.name == b"Data" && !x.attributes.is_empty() && !c.is_empty() {
            for l in 0..x.attributes.len() {
                let named = x.attributes[l].0 == b"Name";
                if named && valid {
                    let v = tidy(&c, false);
                    lower_first(&mut x.attributes[l].1);
                    let name = x.attributes[l].1.clone();
                    match name.as_slice() {
                        b"categoryId" => self.category = Some(v.clone()),
                        b"subcategoryId" => self.subcategory = Some(v.clone()),
                        _ => {}
                    }
                    if name == b"auditPolicyChanges" {
                        self.audit_changes = Some(v.clone());
                        self.eventdata.push((b"auditPolicyChangesId".to_vec(), v));
                    } else {
                        self.eventdata.push((name, v));
                    }
                    break;
                } else if valid {
                    host.log("DEBUG2", &[&b"Unexpected attribute at EventData ("[..], &x.attributes[l].0, b")."].concat());
                    lower_first(&mut x.attributes[l].1);
                    self.eventdata.push((x.attributes[l].1.clone(), tidy(&c, false)));
                }
            }
        } else if valid && !c.is_empty() {
            let v = tidy(&c, false);
            if !v.is_empty() && x.name == b"Data" {
                // unnamed values joined with ", " (at most 65,535 bytes)
                let mut j = if self.joined.is_empty() { v } else { [self.joined.as_slice(), b", ", &v].concat() };
                j.truncate(65535);
                self.joined = j;
            } else if x.name != b"Data" {
                lower_first(&mut x.name);
                self.eventdata.push((x.name, v));
            }
        }
    }
}

impl Windows {
    /// One event channel event; false when it goes no further.
    pub fn decode(&mut self, host: &mut dyn Host, decoders: &mut DecoderSet, decoder: DecoderId, order: usize, ev: &mut Event) -> bool {
        ev.decoder = decoder;
        ev.program_name = None;
        ev.dec_timestamp = None;
        let log = ev.log().to_vec();
        let Ok((received, _)) = provigil_json::parse_with_opts(&log, false) else {
            host.log("ERROR", b"Malformed EventChannel JSON event.");
            return false;
        };
        let Some(event_in) = received.get("Event") else {
            host.log("DEBUG", b"Malformed JSON received. No 'Event' field found.");
            return false;
        };
        let mut r = Read::default();
        let event = event_in.print_unformatted();
        match provigil_daemon::xml::parse_text_raw(&event) {
            Err(_) => {
                self.unreadable += 1;
                host.log(if self.unreadable > 1 { "DEBUG2" } else { "WARNING" }, &[&b"Could not read XML string: '"[..], &event, b"'"].concat());
            }
            Ok(roots) => {
                for section in roots.into_iter().next().map(|e| e.children).unwrap_or_default() {
                    for item in section.children.clone() {
                        if section.name == b"System" {
                            r.system_item(item);
                        } else if section.name == b"EventData" {
                            r.eventdata_item(host, item);
                        } else {
                            host.log("DEBUG", &[&b"Unexpected element ("[..], &section.name, b"). Decoding it."].concat());
                            let mut values = Vec::new();
                            for mut y in item.children.clone() {
                                if y.content != b"(NULL)" && y.content != b"-" && !y.content.is_empty() {
                                    let v = tidy(&y.content, false);
                                    lower_first(&mut y.name);
                                    values.push((y.name, v));
                                }
                            }
                            // each item's values go to one object named after the last item
                            let mut all = r.extra.take().map(|(_, v)| v).unwrap_or_default();
                            all.extend(values);
                            r.extra = Some((item.name.clone(), all));
                        }
                    }
                }
                if let (Some(level), Some(keywords)) = (&r.level, &r.keywords) {
                    let k = hex(keywords);
                    let severity = match int(level) {
                        1 => "CRITICAL",
                        2 => "ERROR",
                        3 => "WARNING",
                        4 => "INFORMATION",
                        5 => "VERBOSE",
                        0 if k & AUDIT_FAILURE != 0 => "AUDIT_FAILURE",
                        0 if k & AUDIT_SUCCESS != 0 => "AUDIT_SUCCESS",
                        _ => "UNKNOWN",
                    };
                    r.system.push((b"severityValue".to_vec(), severity.as_bytes().to_vec()));
                    if let (Some(ci), Some(si)) = (&r.category, &r.subcategory) {
                        let strip = |s: &[u8]| int(&crate::text_logs::replace_all(s, b"%%", b""));
                        let (c, s) = category(strip(ci), strip(si));
                        if let Some(c) = c {
                            r.eventdata.push((b"category".to_vec(), c.as_bytes().to_vec()));
                        }
                        if let Some(s) = s {
                            r.eventdata.push((b"subcategory".to_vec(), s.as_bytes().to_vec()));
                        }
                    }
                }
                if let Some(changes) = &r.audit_changes {
                    let ids = crate::text_logs::replace_all(changes, b"%%", b"");
                    let names: Vec<&[u8]> = provigil_regex::str_break(',', &String::from_utf8_lossy(&ids), 4)
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|p| match int(p.as_bytes()) {
                            8448 => Some(&b"Success removed"[..]),
                            8449 => Some(b"Success added"),
                            8450 => Some(b"Failure removed"),
                            8451 => Some(b"Failure added"),
                            _ => None,
                        })
                        .collect();
                    if !names.is_empty() {
                        r.eventdata.push((b"auditPolicyChanges".to_vec(), names.join(&b", "[..])));
                    }
                }
            }
        }
        let mut system = Json::object();
        for (k, v) in &r.system {
            add(&mut system, k, v);
        }
        if let Some(m) = received.get("Message") {
            add(&mut system, b"message", &tidy(&m.print_unformatted(), true));
        }
        let mut win = Json::object();
        win.add("system", system);
        let mut eventdata = Json::object();
        for (k, v) in &r.eventdata {
            add(&mut eventdata, k, v);
        }
        if !r.joined.is_empty() {
            add(&mut eventdata, b"data", &r.joined);
        }
        if !eventdata.is_empty() {
            win.add("eventdata", eventdata);
        }
        if let Some((mut name, values)) = r.extra {
            lower_first(&mut name);
            let mut o = Json::object();
            for (k, v) in values {
                add(&mut o, &k, &v);
            }
            win.add(&name, o);
        }
        let mut root = Json::object();
        root.add("win", win);
        ev.buf = [root.print_unformatted().as_slice(), &[0]].concat();
        ev.log_start = 0;
        ev.decoder = decoder;
        crate::plugins::json(&decoders.decoders, ev, order);
        true
    }
}
