//! Decoders, old against new: the shipped decoder files and generated ones must load to the
//! same decoders, trees, ids and messages, and every ruleset test log (in several locations,
//! and cut or changed) must decode to the same event.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use provigil_analysisd::config::Config;
use provigil_analysisd::decoders::{self as nd, DecoderSet};
use provigil_analysisd::event::{Event as NewEvent, Instant};
use provigil_analysisd::messages::Messages;
use siem_analysisd::decoders::{self as od, Decoders};
use siem_analysisd::event::{Event as OldEvent, TimeSpec};
use siem_analysisd::logmsg::LogList;

const ORDER: usize = 256;

fn manager() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager")
}

fn old_msgs(l: &LogList) -> Vec<String> {
    l.msgs.iter().map(|m| format!("{:?} {}", m.level, m.msg)).collect()
}

fn new_msgs(l: &Messages) -> Vec<String> {
    l.list.iter().map(|m| format!("{:?} {}", m.level, m.text)).collect()
}

fn old_dump(d: &Decoders) -> Vec<String> {
    let mut out: Vec<String> = d
        .infos
        .iter()
        .map(|i| {
            let order: Vec<String> = i.order.iter().flatten().map(|o| format!("{o:?}")).collect();
            format!(
                "{} {} {} {} {} {} {} {} {} {} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
                i.get_next, i.type_, i.use_own_name, i.flags, i.id, i.regex_offset, i.prematch_offset, i.plugin_offset, i.fts, i.accumulate, i.parent, i.name, i.ftscomment,
                i.fields, i.fts_fields, i.regex, i.prematch, i.program_name, i.plugin, order
            )
        })
        .collect();
    fn tree(n: &[od::DNode], depth: usize, out: &mut Vec<String>) {
        for x in n {
            out.push(format!("{}{}", " ".repeat(depth), x.dec));
            tree(&x.children, depth + 1, out);
        }
    }
    out.push("pn".into());
    tree(&d.pn, 0, &mut out);
    out.push("nopn".into());
    tree(&d.nopn, 0, &mut out);
    out.push(format!("{:?}", d.store));
    out
}

fn new_dump(d: &DecoderSet) -> Vec<String> {
    let mut out: Vec<String> = d
        .decoders
        .iter()
        .map(|i| {
            // the old crate's names for the order targets
            let order: Vec<String> = i
                .order
                .iter()
                .flatten()
                .map(|o| match o {
                    None => "None".into(),
                    Some(nd::Target::Named) => "Some(Dynamic)".into(),
                    Some(nd::Target::Fixed(f)) => format!(
                        "Some({})",
                        ["SrcIp", "Id", "DstIp", "SrcPort", "DstPort", "SrcUser", "DstUser", "Protocol", "Action", "Url", "Data", "ExtraData", "Status", "SystemName"][*f]
                    ),
                })
                .collect();
            let plugin = i.plugin.map(|p| match p {
                provigil_analysisd::plugins::Plugin::Alert => "OssecAlert".to_string(),
                p => format!("{p:?}"),
            });
            format!(
                "{} {} {} {} {} {} {} {} {} {} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {} {:?}",
                i.get_next, i.kind, i.use_own_name, i.json_flags, i.id, i.regex_offset, i.prematch_offset, i.plugin_offset, i.fts, i.accumulate, i.parent, i.name, i.fts_comment,
                i.field_names, i.fts_fields, i.regex, i.prematch, i.program_name, plugin.map_or("None".to_string(), |p| format!("Some({p})")), order
            )
        })
        .collect();
    fn tree(n: &[nd::Node], depth: usize, out: &mut Vec<String>) {
        for x in n {
            out.push(format!("{}{}", " ".repeat(depth), x.decoder));
            tree(&x.children, depth + 1, out);
        }
    }
    out.push("pn".into());
    tree(&d.with_program, 0, &mut out);
    out.push("nopn".into());
    tree(&d.without_program, 0, &mut out);
    out.push(format!("{:?}", d.names));
    out
}

/// Loads `files` in both; the results and messages must agree.
fn load(files: &[String], home: &Path) -> (Decoders, DecoderSet) {
    let (mut o, mut n) = (Decoders::default(), DecoderSet::default());
    let (mut ol, mut nl) = (LogList::default(), Messages::default());
    for f in files {
        let a = o.read_decode_xml(f, ORDER, home, &mut ol);
        let b = n.load_file(f, ORDER, home, &mut nl);
        assert_eq!(a, b, "loading {f}: {:?} / {:?}", old_msgs(&ol), new_msgs(&nl));
        assert_eq!(old_msgs(&ol), new_msgs(&nl), "messages of {f}");
        if a == 0 {
            return (o, n);
        }
    }
    assert_eq!(o.set_decode_xml(&mut ol), n.finish(&mut nl));
    assert_eq!(old_msgs(&ol), new_msgs(&nl));
    (o, n)
}

fn compare_sets(o: &Decoders, n: &DecoderSet, what: &str) {
    let (a, b) = (old_dump(o), new_dump(n));
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x, y, "{what}");
    }
    assert_eq!(a.len(), b.len(), "{what}");
}

#[derive(Debug, PartialEq)]
struct State {
    decoder: usize,
    kind: u8,
    buf: Vec<u8>,
    log: usize,
    after: (Option<isize>, Option<isize>),
    f: Vec<Option<Vec<u8>>>,
    fields: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    host: Option<Vec<u8>>,
    rule: Option<usize>,
    groups: Vec<Vec<u8>>,
}

fn decode_both(o: &mut Decoders, n: &mut DecoderSet, msg: &[u8]) -> usize {
    let mut oe = OldEvent::new(0);
    let mut ne = NewEvent::new(0);
    let a = oe.clean_msg(msg, b"manager", TimeSpec { sec: 1_700_000_000, nsec: 0 });
    let b = ne.clean(msg, b"manager", Instant { sec: 1_700_000_000, nsec: 0 });
    assert_eq!(a, b);
    if a.is_err() {
        return 0;
    }
    let rules: HashMap<String, usize> = [("5715".to_string(), 3usize), ("100".to_string(), 1)].into_iter().collect();
    let (mut og, mut ng) = (Vec::new(), Vec::new());
    let ocx = od::DecodeCtx { order_size: ORDER, rules_hash: &rules };
    let ncx = nd::Context { order_size: ORDER, rules: &rules };
    let opn = oe.program_name.is_some();
    od::decode_event(o, &mut oe, &mut og, &ocx, opn);
    let npn = ne.program_name.is_some();
    nd::decode(n, &mut ne, &mut ng, &ncx, npn);
    let os = State {
        decoder: oe.decoder,
        kind: o.infos[oe.decoder].type_,
        buf: oe.buf.clone(),
        log: oe.log,
        after: (oe.log_after_parent, oe.log_after_prematch),
        f: oe.f.to_vec(),
        fields: oe.fields.iter().map(|f| (f.key.clone(), f.value.clone())).collect(),
        host: oe.hostname.clone(),
        rule: oe.generated_rule,
        groups: og,
    };
    let ns = State {
        decoder: ne.decoder,
        kind: n.decoders[ne.decoder].kind,
        buf: ne.buf.clone(),
        log: ne.log_start,
        after: (ne.after_parent, ne.after_prematch),
        f: ne.f.to_vec(),
        fields: ne.fields.iter().map(|f| (f.key.clone(), f.value.clone())).collect(),
        host: ne.hostname.clone(),
        rule: ne.generated_rule,
        groups: ng,
    };
    assert_eq!(os, ns, "{:?}", String::from_utf8_lossy(msg));
    os.decoder
}

/// Every `log N pass|fail = ...` line of the ruleset tests.
fn test_logs() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ruleset/testing/tests");
    let mut out = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
    names.sort();
    for p in names {
        for line in std::fs::read_to_string(&p).unwrap_or_default().lines() {
            if line.starts_with("log ") {
                if let Some((_, v)) = line.split_once(" = ") {
                    out.push(v.to_string());
                }
            }
        }
    }
    out
}

#[test]
fn shipped_decoders_and_test_logs() {
    let home = manager();
    let cfg = Config::load(&home, &home.join("etc/ossec.conf"), false).unwrap();
    let (mut o, mut n) = load(&cfg.ruleset.decoders, &home);
    compare_sets(&o, &n, "shipped decoders");
    assert!(n.decoders.len() > 1000, "{} decoders", n.decoders.len());

    let logs = test_logs();
    assert!(logs.len() > 2000, "{} logs", logs.len());
    let mut decoded = 0;
    let mut r: u64 = 0x9E3779B97F4A7C15;
    for log in &logs {
        for loc in ["1:stdin:", "1:[001] (agent1) 10.0.0.1->/var/log/secure:", "f:[002] (win) any->EventChannel:", "1:/var/log/syslog:"] {
            let msg = format!("{loc}{log}");
            decoded += usize::from(decode_both(&mut o, &mut n, msg.as_bytes()) != 0);
            // cut short and one byte changed
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            let b = msg.as_bytes();
            let cut = loc.len() + (r as usize) % (b.len() - loc.len() + 1);
            decode_both(&mut o, &mut n, &b[..cut]);
            let mut m = b.to_vec();
            let i = loc.len() + (r as usize >> 8) % (b.len() - loc.len()).max(1);
            if i < m.len() {
                m[i] = b" :;[]{}\",=."[(r as usize >> 20) % 11];
            }
            decode_both(&mut o, &mut n, &m);
        }
    }
    assert!(decoded > logs.len() * 2, "decoded {decoded} of {}", logs.len() * 4);
}

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

fn decoder(r: &mut Rng, names: &[&str]) -> String {
    let name = r.pick(names);
    let attrs = r.pick(&["", "", " status=\"x\"", " other=\"x\"", " status=\"a\" more=\"b\""]);
    let mut s = format!("<{} name=\"{name}\"{attrs}>", r.pick(&["decoder", "decoder", "decoder", "Decoder", "rule"]));
    let opts: &[&dyn Fn(&mut Rng) -> String] = &[
        &|r| format!("<parent>{}</parent>", r.pick(&["p1", "p2", "nope"])),
        &|r| format!("<prematch{}{}>{}</prematch>", r.pick(&["", " offset=\"after_parent\"", " offset=\"after_regex\"", " offset=\"bad\""]), r.pick(&["", " type=\"pcre2\"", " type=\"osmatch\"", " type=\"x\""]), r.pick(&["^a", "^\\w+", "b", "(", "^"])),
        &|r| format!("<regex{}{}>{}</regex>", r.pick(&["", " offset=\"after_parent\"", " offset=\"after_prematch\"", " offset=\"after_regex\"", " offset=\"x\""]), r.pick(&["", " type=\"pcre2\"", " type=\"osmatch\""]), r.pick(&["(\\w+)", "^(\\S+) (\\d+)", "\\w+", "(", "(a)|(b)"])),
        &|r| format!("<program_name{}>{}</program_name>", r.pick(&["", " type=\"osregex\"", " type=\"pcre2\"", " type=\"x\""]), r.pick(&["^sshd", "sshd", "^su$", "("])),
        &|r| format!("<order>{}</order>", r.pick(&["srcip", "user, srcport", "a.b, c", "srcip,", " , x", "id,url,data,extra_data,status,system_name,protocol,action,dstip,dstport,srcuser"])),
        &|r| format!("<fts>{}</fts>", r.pick(&["name, srcip", "a.b", "location, data", "nope", ","])),
        &|r| format!("<plugin_decoder{}>{}</plugin_decoder>", r.pick(&["", " offset=\"after_parent\"", " offset=\"after_prematch\"", " offset=\"x\""]), r.pick(&["JSON_Decoder", "PF_Decoder", "x"])),
        &|r| format!("<type>{}</type>", r.pick(&["firewall", "ids", "web-log", "squid", "windows", "host-information", "ossec", "bad"])),
        &|r| format!("<json_null_field>{}</json_null_field>", r.pick(&["discard", "empty", "string", "x"])),
        &|r| format!("<json_array_structure>{}</json_array_structure>", r.pick(&["csv", "array", "x"])),
        &|r| format!("<use_own_name>{}</use_own_name>", r.pick(&["true", "false"])),
        &|r| format!("<ftscomment>{}</ftscomment>", r.pick(&["c", ""])),
        &|_| "<accumulate/>".to_string(),
        &|_| "<other>1</other>".to_string(),
        &|r| format!("<prematch>{}</prematch>", "x".repeat(r.pick(&["1000", "30"]).parse().unwrap())),
    ];
    for _ in 0..1 + r.below(5) {
        let cut = if r.below(8) == 0 { 0 } else { 2 };
        let i = r.below(opts.len() - cut);
        s.push_str(&opts[i](r));
    }
    s.push_str(&format!("</{}>", "decoder"));
    s
}

#[test]
fn generated_decoder_files() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir_all(home.join("d")).unwrap();
    let mut r = Rng(0xD1B54A32D192ED03);
    let logs = ["a b c", "sshd: x", "Dec 29 10:00:01 host sshd[1]: user root from 1.2.3.4 port 22", "{\"a\":1,\"b\":[1,2]}", "b 10", "hello"];
    let (mut ok, mut failed) = (0, 0);
    for round in 0..4000 {
        let mut files = Vec::new();
        for k in 0..1 + r.below(3) {
            let mut doc = String::new();
            if r.below(10) == 0 {
                doc.push_str("<var name=\"V\">^a</var>");
            }
            for _ in 0..r.below(6) {
                doc.push_str(&decoder(&mut r, &["p1", "p2", "c1", "c2", "p1"]));
            }
            let f = format!("d/{round}_{k}.xml");
            std::fs::write(home.join(&f), doc).unwrap();
            files.push(f);
        }
        if r.below(10) == 0 {
            files.push("d/missing.xml".into());
        }
        if r.below(10) == 0 {
            files.push(nd::LOCAL_FILE.into());
        }
        let (mut o, mut n) = load(&files, home);
        compare_sets(&o, &n, &files.join(" "));
        if o.store.is_empty() {
            failed += 1;
            continue;
        }
        ok += 1;
        for l in logs {
            for loc in ["1:stdin:", "1:[001] (a) 1.2.3.4->x:"] {
                decode_both(&mut o, &mut n, format!("{loc}{l}").as_bytes());
            }
        }
    }
    assert!(ok > 500 && failed > 100, "ok {ok} failed {failed}");
}
