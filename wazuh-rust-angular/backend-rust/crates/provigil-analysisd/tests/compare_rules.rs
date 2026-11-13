//! Rules, old against new: the shipped rule files and generated ones must load to the same
//! rules (every option), tree, context lists, levels, hash and messages.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use provigil_analysisd::config::{Config, Response};
use provigil_analysisd::decoders::DecoderSet;
use provigil_analysisd::lists::Lists as NewLists;
use provigil_analysisd::messages::Messages;
use provigil_analysisd::rules::{self as nr, RuleSet, RuleSettings};
use siem_analysisd::decoders::Decoders;
use siem_analysisd::lists::Lists as OldLists;
use siem_analysisd::logmsg::LogList;
use siem_analysisd::rules::{self as or, RuleConfig, Rules};

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

fn old_rule(r: &or::RuleInfo) -> String {
    let lists: Vec<String> = r.lists.iter().map(|l| format!("{} {} {:?} {:?} {} {:?}", l.field, l.lookup_type, l.matcher, l.dfield, l.filename, l.db)).collect();
    let fields: Vec<String> = r.fields.iter().map(|f| format!("{:?} {:?}", f.name, f.regex)).collect();
    let details: Vec<String> = r.info_details.iter().map(|d| format!("{} {}", d.type_, d.data)).collect();
    let check = r.compiled_rule.map(|c| format!("{c:?}"));
    format!(
        "{} {} {} {} {} {} {} {} {} {} {:?} {:?} {} {} {} {} {} {} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        r.sigid, r.level, r.maxsize, r.frequency, r.timeframe, r.context, r.firedtimes, r.time_ignored, r.ignore_time, r.ignore, r.ignore_fields, r.ckignore_fields, r.ckignore, r.alert_opts,
        r.context_opts, r.same_field, r.different_field, r.category, r.decoded_as, r.sid_prev_matched, r.sid_search, r.group_prev_matched, r.group_search, r.event_search, r.group, r.match_,
        r.regex, r.day_time, r.week_day, r.srcip, r.dstip, r.srcgeoip, r.dstgeoip, r.srcport, r.dstport, r.user, r.url, r.id, r.status, r.hostname, r.program_name, r.data, r.extra_data,
        r.location, r.system_name, r.protocol, fields, r.action, r.comment, r.info, r.cve, details, lists, r.if_matched_sid, r.if_sid, r.if_level, r.if_group, r.if_matched_regex,
        r.if_matched_group, (check, &r.ar, &r.file), (&r.same_fields, &r.not_same_fields), (&r.mitre_id, &r.mitre_tactic_id, &r.mitre_technique_id)
    )
}

fn new_rule(r: &nr::Rule) -> String {
    let lists: Vec<String> = r.lists.iter().map(|l| format!("{} {} {:?} {:?} {} {:?}", l.field, l.lookup, l.value_pattern, l.dynamic_field, l.file, l.list)).collect();
    let fields: Vec<String> = r.fields.iter().map(|f| format!("{:?} {:?}", f.name, f.regex)).collect();
    let details: Vec<String> = r.info_details.iter().map(|d| format!("{} {}", d.kind, d.data)).collect();
    // the old crate's names for the built-in checks
    let check = r.check.map(|c| {
        match c {
            nr::Check::IdSize => "CheckIdSize",
            nr::Check::SameUsers => "CompSrcuserDstuser",
            nr::Check::WindowsAccountDiffers => "CompMswinTargetuserCalleruserDiff",
            nr::Check::SimpleHttpRequest => "IsSimpleHttpRequest",
            nr::Check::Crawler => "IsValidCrawler",
        }
        .to_string()
    });
    format!(
        "{} {} {} {} {} {} {} {} {} {} {:?} {:?} {} {} {} {} {} {} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        r.sigid, r.level, r.maxsize, r.frequency, r.timeframe, r.context, r.firedtimes, r.time_ignored, r.ignore_time, r.ignore, r.ignore_fields, r.ckignore_fields, r.ckignore, r.alert_opts,
        r.context_opts, r.same_field, r.different_field, r.category, r.decoded_as, r.sid_prev_matched, r.sid_search, r.group_prev_matched, r.group_search, r.event_search, r.group, r.match_,
        r.regex, r.day_time, r.week_day, r.srcip, r.dstip, r.srcgeoip, r.dstgeoip, r.srcport, r.dstport, r.user, r.url, r.id, r.status, r.hostname, r.program_name, r.data, r.extra_data,
        r.location, r.system_name, r.protocol, fields, r.action, r.comment, r.info, r.cve, details, lists, r.if_matched_sid, r.if_sid, r.if_level, r.if_group, r.if_matched_regex,
        r.if_matched_group, (check, &r.ar, &r.file), (&r.same_fields, &r.not_same_fields), (&r.mitre_id, &r.mitre_tactic_id, &r.mitre_technique_id)
    )
}

fn old_dump(r: &Rules) -> Vec<String> {
    let mut out: Vec<String> = r.infos.iter().map(|i| old_rule(i)).collect();
    fn tree(n: &[or::RNode], d: usize, out: &mut Vec<String>) {
        for x in n {
            out.push(format!("{}{}", " ".repeat(d), x.rule));
            tree(&x.children, d + 1, out);
        }
    }
    tree(&r.tree, 0, &mut out);
    out.push(format!("lists {} max {}", r.lists.len(), r.max_freq));
    let mut h = HashMap::new();
    r.rules_hash(&mut h);
    let mut h: Vec<_> = h.into_iter().collect();
    h.sort();
    out.push(format!("{h:?}"));
    out
}

fn new_dump(r: &RuleSet) -> Vec<String> {
    let mut out: Vec<String> = r.rules.iter().map(|i| new_rule(i)).collect();
    fn tree(n: &[nr::RuleNode], d: usize, out: &mut Vec<String>) {
        for x in n {
            out.push(format!("{}{}", " ".repeat(d), x.rule));
            tree(&x.children, d + 1, out);
        }
    }
    tree(&r.tree, 0, &mut out);
    out.push(format!("lists {} max {}", r.event_lists.len(), r.max_frequency));
    let mut h = HashMap::new();
    r.hash(&mut h);
    let mut h: Vec<_> = h.into_iter().collect();
    h.sort();
    out.push(format!("{h:?}"));
    out
}

fn compare(o: &Rules, n: &RuleSet, what: &str) {
    let (a, b) = (old_dump(o), new_dump(n));
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x, y, "{what}");
    }
    assert_eq!(a.len(), b.len(), "{what}");
}

/// The shipped decoders and lists, loaded once in both.
struct Base {
    od: Decoders,
    nd: DecoderSet,
    ol: OldLists,
    nl: NewLists,
    lists: Vec<String>,
}

fn base(home: &Path, cfg: &Config) -> Base {
    let (mut od, mut nd) = (Decoders::default(), DecoderSet::default());
    let (mut a, mut b) = (LogList::default(), Messages::default());
    for f in &cfg.ruleset.decoders {
        od.read_decode_xml(f, ORDER, home, &mut a);
        nd.load_file(f, ORDER, home, &mut b);
    }
    od.set_decode_xml(&mut a);
    nd.finish(&mut b);
    let (mut ol, mut nl) = (OldLists::default(), NewLists::default());
    for l in &cfg.ruleset.lists {
        ol.load_list(l, home, &mut a);
        nl.load(l, home, &mut b);
    }
    Base { od, nd, ol, nl, lists: cfg.ruleset.lists.clone() }
}

fn responses() -> (Vec<or::ActiveResponse>, Vec<Response>) {
    let spec: [(i32, Option<&str>, Option<&str>); 4] = [(6, None, None), (0, Some("authentication_failed|sshd"), None), (3, Some("web"), Some("5712, 100,abc 5")), (0, None, Some("31151,31152"))];
    let old = spec.iter().map(|(l, g, i)| or::ActiveResponse { level: *l, rules_group: g.map(String::from), rules_id: i.map(String::from), ..Default::default() }).collect();
    let new = spec.iter().map(|(l, g, i)| Response { level: *l, rules_group: g.map(String::from), rules_id: i.map(String::from), ..Default::default() }).collect();
    (old, new)
}

/// Loads `files` in both; return codes and messages must agree after each file.
fn load(b: &Base, files: &[String], home: &Path) -> (Rules, RuleSet) {
    let oc = RuleConfig { decoder_order_size: ORDER, mailbylevel: 7, logbylevel: 1, default_timeframe: 360, rulepath: "ruleset/rules".into(), home: home.to_path_buf() };
    let nc = RuleSettings { order_size: ORDER, email_level: 7, log_level: 1, default_timeframe: 360, rule_dir: "ruleset/rules".into(), home: home.to_path_buf() };
    let (oa, na) = responses();
    let (mut o, mut n) = (Rules::default(), RuleSet::default());
    let (mut ol, mut nl) = (LogList::default(), Messages::default());
    for f in files {
        let x = o.read_rules(f, &b.ol, &b.od, &oc, Some(&oa), &mut ol);
        let y = n.load_file(f, &b.nl, &b.nd, &nc, Some(&na), &mut nl);
        assert_eq!(x, y, "{f}: {:?} / {:?}", old_msgs(&ol), new_msgs(&nl));
        assert_eq!(old_msgs(&ol), new_msgs(&nl), "{f}");
    }
    o.set_levels();
    n.set_levels();
    (o, n)
}

#[test]
fn shipped_rules() {
    let home = manager();
    let cfg = Config::load(&home, &home.join("etc/ossec.conf"), false).unwrap();
    let b = base(&home, &cfg);
    assert!(!b.lists.is_empty());
    let (o, n) = load(&b, &cfg.ruleset.rules, &home);
    compare(&o, &n, "shipped rules");
    assert!(n.rules.len() > 3000, "{} rules", n.rules.len());
}

/// `.1`: mostly valid choices.
struct Rng(u64, bool);
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
        if self.1 && self.below(10) < 8 {
            return v[0];
        }
        v[self.below(v.len())]
    }
}

type Gen = dyn Fn(&mut Rng) -> String;

fn options() -> Vec<Box<Gen>> {
    let simple = |e: &'static str, vals: &'static [&'static str]| -> Box<Gen> {
        Box::new(move |r: &mut Rng| {
            let attrs = r.pick(&["", "", " negate=\"yes\"", " negate=\"x\"", " type=\"pcre2\"", " type=\"osregex\"", " type=\"bad\""]);
            format!("<{e}{attrs}>{}</{e}>", r.pick(vals))
        })
    };
    let flag = |e: &'static str| -> Box<Gen> { Box::new(move |_: &mut Rng| format!("<{e} />")) };
    let mut v: Vec<Box<Gen>> = vec![
        simple("match", &["Failed password", "^sshd", "a|b", "("]),
        simple("regex", &["^(\\S+)", "\\d+", "(", "[a"]),
        simple("srcport", &["22", "^1"]),
        simple("dstport", &["80"]),
        simple("user", &["root", "^admin$"]),
        simple("id", &["4625"]),
        simple("status", &["failed"]),
        simple("hostname", &["web"]),
        simple("data", &["x"]),
        simple("extra_data", &["y"]),
        simple("program_name", &["sshd", "^su$"]),
        simple("action", &["block", "("]),
        simple("system_name", &["win"]),
        simple("protocol", &["tcp", "("]),
        simple("location", &["/var/log"]),
        simple("url", &["/admin"]),
        simple("srcgeoip", &["US"]),
        simple("description", &["Desc $(srcip)", "multi\nline\ntext"]),
        simple("srcip", &["10.0.0.0/8", "!1.2.3.4", "bad"]),
        simple("dstip", &["192.168.1.1"]),
        simple("decoded_as", &["sshd", "json", "nope", "windows_eventchannel"]),
        simple("cve", &["CVE-1"]),
        Box::new(|r: &mut Rng| format!("<info{}>i</info>", r.pick(&["", " type=\"link\"", " type=\"cve\"", " type=\"x\"", " other=\"1\""]))),
        simple("time", &["6 pm - 8:30 am", "9:00 - 17:00", "bad"]),
        simple("weekday", &["weekends", "monday,tue", "!monday", "funday"]),
        simple("group", &["authentication_failed,", "web,\nattack,"]),
        Box::new(|r: &mut Rng| format!("<field name=\"{}\"{}>{}</field>", r.pick(&["win.system.eventID", "srcip", "a.b"]), r.pick(&["", " type=\"osmatch\"", " negate=\"yes\""]), r.pick(&["^4625$", "("]))),
        Box::new(|_: &mut Rng| "<field>x</field>".into()),
        Box::new(|r: &mut Rng| {
            format!(
                "<list{}{}{}>{}</list>",
                r.pick(&[" field=\"srcip\"", " field=\"user\"", " field=\"win.x\"", ""]),
                r.pick(&["", " lookup=\"address_match_key\"", " lookup=\"match_key_value\"", " lookup=\"bad\""]),
                r.pick(&["", " check_value=\"^a\"", " other=\"1\""]),
                r.pick(&["etc/lists/audit-keys", "etc/lists/missing", "etc/lists/security-eventchannel"])
            )
        }),
        simple("compiled_rule", &["is_valid_crawler", "check_id_size", "nope"]),
        simple("category", &["firewall", "ids", "windows", "bad"]),
        simple("if_sid", &["5700", "5715, 5716", "1,x", "999999", "", "100,"]),
        simple("if_level", &["5", "x", "0", "16"]),
        simple("if_group", &["authentication_failed", "nogroup"]),
        simple("if_matched_sid", &["5715", "x", "999998"]),
        simple("if_matched_group", &["authentication_failed", "("]),
        simple("if_matched_regex", &["^a", "("]),
        flag("same_source_ip"),
        flag("same_user"),
        flag("SAME_ID"),
        flag("same_id"),
        flag("different_srcip"),
        flag("Different_srcip"),
        flag("same_agent"),
        flag("check_diff"),
        flag("if_fts"),
        flag("global_frequency"),
        simple("same_field", &["win.x"]),
        simple("different_field", &["win.y"]),
        simple("options", &["no_log", "no_email_alert", "alert_by_email", "no_ar", "no_full_log", "no_counter", "bad"]),
        simple("ignore", &["srcip, user", "name, win.x", ","]),
        simple("check_if_ignored", &["srcip", "a.b"]),
        Box::new(|r: &mut Rng| {
            format!(
                "<mitre>{}{}</mitre>",
                r.pick(&["<id>T1110</id>", "<tacticID>TA0006</tacticID><techniqueID>T1110</techniqueID>", "<id></id>", "<tacticID>TA1</tacticID>", "<other>x</other>", ""]),
                r.pick(&["", "<id>T1021</id>", "<techniqueID>T2</techniqueID>"])
            )
        }),
        flag("bad_option"),
    ];
    v.shrink_to_fit();
    v
}

fn rule(r: &mut Rng, opts: &[Box<Gen>]) -> String {
    let id = r.pick(&["100001", "100002", "100003", "100004", "5715", "100", "1", "abc", "1234567", "100005"]);
    let attrs = [
        format!(" id=\"{id}\""),
        format!(" level=\"{}\"", r.pick(&["0", "5", "10", "17", "x"])),
        r.pick(&["", "", " frequency=\"5\"", " frequency=\"1\"", " timeframe=\"120\"", " maxsize=\"100\"", " noalert=\"1\"", " ignore=\"60\"", " accuracy=\"0\"", " overwrite=\"yes\"", " bad=\"1\""]).to_string(),
    ];
    let attrs: String = attrs.iter().filter(|_| r.1 || r.below(12) != 0).cloned().collect();
    let mut s = format!("<rule{attrs}>");
    if r.1 || r.below(5) > 0 {
        s.push_str("<description>d</description>");
    }
    for _ in 0..r.below(5) {
        let cut = if r.below(10) == 0 { 0 } else { 1 };
        let k = r.below(opts.len() - cut);
        let o = opts[k](r);
        if r.1 && ["SAME_ID", "Different_srcip", "bad_option", "<field>x"].iter().any(|b| o.contains(b)) {
            continue;
        }
        s.push_str(&o);
    }
    s + "</rule>"
}

#[test]
fn generated_rules() {
    let home = manager();
    let cfg = Config::load(&home, &home.join("etc/ossec.conf"), false).unwrap();
    let b = base(&home, &cfg);
    // a few shipped rule files, then generated ones in a temporary folder (absolute paths)
    let dir = tempfile::tempdir().unwrap();
    let opts = options();
    let mut r = Rng(0x9E3779B97F4A7C15, false);
    let shipped: Vec<String> = cfg.ruleset.rules.iter().filter(|f| f.contains("0095-sshd") || f.contains("0020-syslog") || f.contains("0010-rules_config")).cloned().collect();
    let (mut ok, mut failed) = (0, 0);
    for round in 0..3000 {
        r.1 = round % 2 == 0;
        let mut files = shipped.clone();
        for k in 0..1 + r.below(2) {
            let mut doc = String::new();
            if r.below(15) == 0 {
                doc.push_str("<var name=\"G\">grp,</var>");
            }
            for _ in 0..1 + r.below(2) {
                let head = r.pick(&["<group name=\"local,\">", "<group name=\"$G\">", "<group>", "<group name=\"a\" x=\"1\">", "<rules name=\"x\">"]);
                doc.push_str(head);
                for _ in 0..r.below(5) {
                    doc.push_str(&rule(&mut r, &opts));
                }
                doc.push_str(if head.starts_with("<rules") { "</rules>" } else { "</group>" });
            }
            let f = dir.path().join(format!("{round}_{k}.xml"));
            std::fs::write(&f, doc).unwrap();
            files.push(f.to_string_lossy().replace('\\', "/"));
        }
        let (o, n) = load(&b, &files, &home);
        compare(&o, &n, &files.join(" "));
        // rounds where generated rules were loaded (their files are absolute paths)
        if n.rules.iter().any(|x| x.file.as_deref().is_some_and(|f| !f.starts_with("ruleset/") && !f.starts_with("etc/") && !f.contains("_rules.xml"))) {
            ok += 1;
        } else {
            failed += 1;
        }
    }
    assert!(ok > 600 && failed > 100, "ok {ok} failed {failed}");
}
