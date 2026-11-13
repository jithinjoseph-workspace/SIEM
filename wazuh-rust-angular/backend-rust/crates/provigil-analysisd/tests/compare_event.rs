//! Message cleaning, old against new: the same message must give the same buffer, positions,
//! header fields, location, agent and times, or the same error.

use provigil_analysisd::event::{self as new, Event as NewEvent, Instant};
use siem_analysisd::event::{self as old, Event as OldEvent, TimeSpec};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        v[self.below(v.len())]
    }
}

const STAMPS: &[&str] = &[
    "Dec 29 10:00:01",
    "Mär 29 10:00:01",
    "2007-06-14 15:48:55,123",
    "2015-03-09T06:25:46+00:00",
    "2015-03-09T06:25:46.123+00:00",
    "2015-03-09T06:25:46.123456+00:00",
    "2015-03-09T06:25:46.123456789+00:00",
    "2015-03-09T06:25:46.12+0000",
    "2007 Jun 14 15:48:55",
    "2007-06-14 15:48:55.123456+02:00",
    "Mon Jun 14 15:48:55 2007 1",
    "01/28-09:13:16.240702 ",
    "01/28/2015-09:13:16.240702 ",
    "[Mon Jun 14 15:48:55 2007]",
    "[Time 2008.07.14 07:30:17 UTC]",
    "1140702036.411    213",
    "1140702036.411     213",
    "Dec  9 10:00:01",
    "",
];

const HOSTS: &[&str] = &["myhost", "my.host-1", "host_a", "", "h@st", "10.0.0.1", "host|user:info", "host|x:y", "host|1:y", "host|ab"];
const PROGRAMS: &[&str] = &[
    "sshd[123]:",
    "sshd:",
    "sshd: ",
    "sshd[123] ",
    "sshd[12a]:",
    "sshd[]:",
    "sshd",
    "kernel:",
    "su[1]: ",
    "prog[99]:x",
    "",
    ":",
    "[ID 123 auth.info]",
];
const TAILS: &[&str] = &["Accepted password", "[ID 702911 auth.info] message", "[ID x", "", " a b", "[Sender s] [Message m] [Host h] rest", "[Sender s", "[Message m [Host h]", "x:y|z"];

fn log(r: &mut Rng) -> Vec<u8> {
    if r.below(20) == 0 {
        // raw bytes
        let n = r.below(60);
        return (0..n).map(|_| *r.pick(&["a", " ", ":", "[", "]", "1", "-", ".", "T", "/", "|", "\u{e4}"]).as_bytes().first().unwrap()).collect();
    }
    let stamp = r.pick(STAMPS);
    let mut s = String::from(stamp);
    if r.below(5) > 0 {
        s.push_str(r.pick(&[" ", "  ", ""]));
        s.push_str(r.pick(HOSTS));
        s.push_str(r.pick(&[" ", ": ", "", "  "]));
        s.push_str(r.pick(PROGRAMS));
        s.push_str(r.pick(&[" ", "", "  "]));
    }
    s.push_str(r.pick(TAILS));
    s.into_bytes()
}

fn location(r: &mut Rng) -> String {
    r.pick(&[
        "stdin",
        "[001] (agent1) 10.0.0.1->/var/log/auth.log",
        "[002] (win) any->EventChannel",
        "[003] x",
        "[004]",
        "[005]x",
        "[006] (noend",
        "[bad",
        "a|:b",
        "a||b",
        "|",
        "",
        "/var/log/syslog",
        "(no-agent)->x",
    ])
    .to_string()
}

#[derive(Debug, PartialEq)]
struct Seen {
    ok: bool,
    buf: Vec<u8>,
    log: usize,
    stamp: Option<Vec<u8>>,
    program: Option<Vec<u8>>,
    program_size: usize,
    host: Option<Vec<u8>>,
    agent: Option<Vec<u8>>,
    location: Option<Vec<u8>>,
    times: (i64, i32, i32, String, String),
}

fn old_seen(e: &OldEvent, ok: bool) -> Seen {
    Seen {
        ok,
        buf: e.buf.clone(),
        log: e.log,
        stamp: e.dec_timestamp.clone(),
        program: e.program_name.clone(),
        program_size: e.p_name_size,
        host: e.hostname.clone(),
        agent: e.agent_id.clone(),
        location: e.f[old::F_LOCATION].clone(),
        times: (e.generate_time, e.day, e.year, e.mon.clone(), e.hour.clone()),
    }
}

fn new_seen(e: &NewEvent, ok: bool) -> Seen {
    Seen {
        ok,
        buf: e.buf.clone(),
        log: e.log_start,
        stamp: e.dec_timestamp.clone(),
        program: e.program_name.clone(),
        program_size: e.program_name_size,
        host: e.hostname.clone(),
        agent: e.agent_id.clone(),
        location: e.f[new::F_LOCATION].clone(),
        times: (e.generate_time, e.day, e.year, e.mon.clone(), e.hour.clone()),
    }
}

fn both(msg: &[u8], sec: i64) -> (OldEvent, NewEvent) {
    let mut o = OldEvent::new(0);
    let ro = o.clean_msg(msg, b"manager", TimeSpec { sec, nsec: 7 });
    let mut n = NewEvent::new(0);
    let rn = n.clean(msg, b"manager", Instant { sec, nsec: 7 });
    assert_eq!(ro, rn, "{:?}", String::from_utf8_lossy(msg));
    assert_eq!(old_seen(&o, ro.is_ok()), new_seen(&n, rn.is_ok()), "{:?}", String::from_utf8_lossy(msg));
    (o, n)
}

#[test]
fn generated_messages() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    let mut seen = std::collections::BTreeMap::<&str, usize>::new();
    for round in 0..300_000 {
        // the time zone of the texts: the system one, then fixed offsets
        if round % 100_000 == 0 {
            let off = [None, Some(19_800), Some(-28_800)][round / 100_000];
            siem_analysisd::localtime::set_fixed_offset(off);
            provigil_analysisd::time::set_fixed_offset(off);
        }
        let mut m = r.pick(&["1:", "x:", "", "1", "5:"]).as_bytes().to_vec();
        m.extend_from_slice(location(&mut r).as_bytes());
        m.extend_from_slice(r.pick(&[":", ":", ":", "|:", ""]).as_bytes());
        m.extend_from_slice(&log(&mut r));
        if r.below(30) == 0 {
            let i = r.below(m.len() + 1);
            m.insert(i, 0);
        }
        let sec = [0, 1_700_000_000, 951_782_400, -1, 4_102_444_800][r.below(5)];
        let (o, _) = both(&m, sec);
        let stamp = o.dec_timestamp.as_deref().map(|t| String::from_utf8_lossy(t).into_owned()).unwrap_or_default();
        for (k, hit) in [
            ("program", o.program_name.is_some()),
            ("host", o.hostname.as_deref().is_some_and(|h| h != b"manager" && !h.is_empty())),
            ("agent", o.agent_id.as_deref().is_some_and(|a| a != b"000")),
            ("error", o.agent_id.is_none()),
            ("stamp", o.dec_timestamp.is_some()),
            ("apache", stamp.starts_with("Mon Jun")),
            ("mac", stamp.is_empty() && o.program_name.is_some()),
            ("id skipped", o.log().starts_with(b"message")),
            ("aix", o.program_name.is_some() && m.windows(5).any(|w| w == b"|user")),
        ] {
            *seen.entry(k).or_default() += hit as usize;
        }
    }
    for (k, n) in &seen {
        assert!(*n > 100, "{k}: {n} in {seen:?}");
    }
}

#[test]
fn comments() {
    let mut r = Rng(0xD1B54A32D192ED03);
    for _ in 0..100_000 {
        let (mut o, mut n) = both(b"1:[001] (a1) 1.2.3.4->x:Dec 29 10:00:01 host prog[1]: msg", 1_700_000_000);
        for (i, v) in [(old::F_SRCIP, "10.0.0.1"), (old::F_DSTUSER, "root"), (old::F_DATA, "d"), (old::F_SRCGEOIP, "geo")] {
            if r.below(2) == 0 {
                o.f[i] = Some(v.as_bytes().to_vec());
                n.f[i] = Some(v.as_bytes().to_vec());
            }
        }
        if r.below(2) == 0 {
            o.fields.push(old::DynamicField { key: b"Win.User".to_vec(), value: Some(b"bob".to_vec()) });
            n.fields.push(new::DynamicField { key: b"Win.User".to_vec(), value: Some(b"bob".to_vec()) });
        }
        let parts = ["$(srcip)", "$(dstuser)", "$(win.user)", "$(data)", "$(srcgeoip)", "$(hostname)", "$(program_name)", "$(nope)", "$(", "$(x", ")", "text ", "$", "$$(srcip)"];
        let mut c = String::new();
        for _ in 0..r.below(12) {
            c.push_str(parts[r.below(parts.len())]);
        }
        if r.below(10) == 0 {
            c.push_str(&"y".repeat(1000 + r.below(40)));
            c.push_str("$(srcip)");
        }
        assert_eq!(o.parse_rule_comment(c.as_bytes()), n.expand_comment(c.as_bytes()), "{c:?}");
    }
}

#[test]
fn escapes() {
    let mut r = Rng(0x2545F4914F6CDD1D);
    for _ in 0..300_000 {
        let n = r.below(12);
        let s: Vec<u8> = (0..n).map(|_| *[b'a', b'|', b':', b'b', 0].get(r.below(5)).unwrap()).collect();
        let room = 2 + r.below(14);
        assert_eq!(old::wstr_escape(&s, b'|', b':', room), new::escape(&s, b'|', b':', room), "escape {s:?} {room}");
        assert_eq!(old::wstr_unescape(&s, b'|', room), new::unescape(&s, b'|', room), "unescape {s:?} {room}");
        assert_eq!(old::wstr_chr_escape(&s, b':', b'|'), new::find_unescaped(&s, b':', b'|'), "find {s:?}");
    }
}
