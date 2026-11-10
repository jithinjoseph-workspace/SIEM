use crate::{h, l1, Out, Rng};
use serde_json::{json, Value};
use siem_regex::expression::{OSMATCH_STR, OSREGEX_STR, PCRE2_STR, STRING_STR};
use siem_regex::os_ip::{atoi, cidr_to_str, expand_ipv6, get_ipv4_from_ipv6};
use siem_regex::*;
use std::collections::HashSet;

const RS: u32 = OS_RETURN_SUBSTRING;
const CS: u32 = OS_CASE_SENSITIVE;
const K: &str = "siem-regex";

pub fn regex_result(p: &str, flags: u32, s: &[u8]) -> Value {
    match OsRegex::compile(p, flags) {
        Err(e) => json!({"error": format!("{e:?}"), "code": e as i32}),
        Ok(r) => match r.execute_bytes(s) {
            None => json!({"has_sub_strings": r.has_sub_strings(), "match": false}),
            Some(m) => {
                let lossy: Vec<String> = m.sub_bytes.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect();
                assert_eq!(lossy, m.sub_strings);
                if let Ok(st) = std::str::from_utf8(s) {
                    assert_eq!(r.execute(st).map(|x| x.end), Some(m.end));
                    assert!(r.is_match(st));
                }
                json!({"has_sub_strings": r.has_sub_strings(), "match": true, "end": m.end,
                       "subs_hex": m.sub_bytes.iter().map(|b| h(b)).collect::<Vec<_>>()})
            }
        },
    }
}

fn match_result(p: &str, flags: u32, s: &[u8]) -> Value {
    match OsMatch::compile(p, flags) {
        Err(e) => json!({"error": format!("{e:?}"), "code": e as i32}),
        Ok(m) => {
            assert_eq!(m.raw(), p);
            if let Ok(st) = std::str::from_utf8(s) {
                assert_eq!(m.is_match(st), m.is_match_bytes(s));
            }
            json!({"negated": m.is_negated(), "patterns_hex": m.patterns().iter().map(|x| h(x)).collect::<Vec<_>>(),
                   "match": m.is_match_bytes(s)})
        }
    }
}

const ESC: [&str; 15] = [r"\w", r"\d", r"\s", r"\p", r"\W", r"\D", r"\S", r"\.", r"\t", r"\$", r"\(", r"\)", r"\\", r"\|", r"\<"];
const BAD: [&str; 7] = [r"\z", r"\a", r"\n", r"\x", r"\+", r"\^", r"\é"];
const LIT: [&str; 25] = ["a", "b", "1", " ", ":", "-", ".", "/", "=", "[", "]", "\"", "'", "x", "y", "z", "A", "B", "0", "9", "_", "é", "€", "@", "\t"];

fn fuzz_regex(r: &mut Rng, depth: u32) -> String {
    let mut p = String::new();
    let mut open = false;
    for _ in 0..1 + r.below(9) {
        let x = r.below(100);
        if x < 42 {
            p += r.pick(&ESC);
            p += r.pick(&["", "", "+", "*"]);
        } else if x < 70 {
            p += r.pick(&LIT);
            if r.chance(0.08) {
                p += r.pick(&["+", "*"]);
            }
        } else if x < 80 && !open {
            p.push('(');
            open = true;
        } else if x < 90 && open {
            p.push(')');
            open = false;
        } else if x < 92 {
            p += r.pick(&BAD);
        } else if x < 94 {
            p.push(*r.pick(&['(', ')', '|', '^', '$', '\\']));
        } else {
            p += r.pick(&LIT);
        }
    }
    if open && r.chance(0.9) {
        p.push(')');
    }
    if r.chance(0.15) {
        p.insert(0, '^');
    }
    if r.chance(0.15) {
        p.push('$');
    }
    if depth < 2 && r.chance(0.1) {
        p.push('|');
        p += &fuzz_regex(r, depth + 1);
    }
    p
}

/// A subject built from the pattern, so that many cases match.
fn sample(r: &mut Rng, p: &str) -> Vec<u8> {
    let b = p.as_bytes();
    let mut o = Vec::new();
    if r.chance(0.3) {
        o.extend(l1(r.pick(&["xx ", "1", "--", "\t", "\u{ff}"])));
    }
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' && i + 1 < b.len() {
            let k = b[i + 1];
            i += 2;
            let opts: &[&str] = match k {
                b'w' => &["a", "Z", "_", "-", "@", "7"],
                b'd' => &["0", "9"],
                b's' => &[" "],
                b'p' => &[".", "!", ":", "["],
                b'W' => &[" ", "!", "\u{80}"],
                b'D' => &["x", " ", "\u{ff}"],
                b'S' => &["q", "\u{c3}"],
                b'.' => &["Q", "\u{1}"],
                b't' => &["\t"],
                b'$' => &["$"],
                b'(' => &["("],
                b')' => &[")"],
                b'\\' => &["\\"],
                b'|' => &["|"],
                b'<' => &["<"],
                _ => &["?"],
            };
            let mut n = 1;
            if i < b.len() && (b[i] == b'+' || b[i] == b'*') {
                n = if b[i] == b'*' { r.below(3) } else { 1 + r.below(3) };
                i += 1;
            }
            for _ in 0..n {
                o.extend(l1(r.pick(opts)));
            }
            continue;
        }
        if c == b'|' && r.chance(0.5) {
            break;
        }
        if !matches!(c, b'(' | b')' | b'^' | b'$' | b'|' | b'+' | b'*') {
            o.push(if r.chance(0.5) { c.to_ascii_uppercase() } else { c });
        }
        i += 1;
    }
    if r.chance(0.3) {
        o.extend(l1(r.pick(&[" tail", "\u{0}x", "1", ""])));
    }
    o
}

fn subj_alpha() -> Vec<u8> {
    l1("ab1 2:-./=\tAB_xyz\\$|()<@[]{}~\u{0}\u{80}\u{c3}\u{a9}\u{ff}\n\r")
}

struct Tsv {
    rows: Vec<(char, String, Vec<u8>)>,
}

fn load_tsv() -> Tsv {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/siem-regex/tests/data/oracle_cases.tsv");
    let data = std::fs::read_to_string(p).expect("oracle_cases.tsv");
    let mut rows = Vec::new();
    for line in data.lines() {
        let c: Vec<&str> = line.splitn(4, '\t').collect();
        if c.len() != 4 {
            continue;
        }
        let Ok(pat) = String::from_utf8(hex::decode(c[1]).unwrap()) else { continue };
        rows.push((c[0].chars().next().unwrap(), pat, hex::decode(c[2]).unwrap()));
    }
    Tsv { rows }
}

const SPECIAL_PATTERNS: &[&str] = &[
    "", "^", "$", "^$", "|", "a|", "|a", "a||b", "()", "(", ")", "((a))", "(a|b)", "a\\", "\\", "\\(", "\\)+", "\\w+\\s*$",
    "\\S(\\s*)$", "(\\w+)*", "a+", "+", "*", "\\d*\\d+", "^(\\S+) (\\d+)$", "(\\d+)(\\d+)", "^\\d+$", "\\w+", "\\w*", "\\s+",
    "\\p+", "\\.+", "\\.*", "^\\.*$", "\\t", "\\$\\d+", "\\|", "\\<\\w+", "user (\\S+) from (\\S+)$", "(\\S+)@(\\S+)", "^$|^a",
    "é", "É", "^é", "é$", "^é$", "(é)", "\\W+", "\\D+", "\\S+", "^\\s*$", "\\w+\\.\\w+", "a\\w*b", "(a)(b)(c)(d)(e)", "x\\s+(\\d+)$",
    "\\d+\\.\\d+\\.\\d+\\.\\d+", "^(\\d+)", "(\\w+)$", "ABC", "abc", "^ABC$", "\\w+ \\w+ \\w+", "\\(\\w+\\)", "\\)", "a\\|b",
    "^\\S+\\s+\\S+", "\\w+\\p", "(\\w)+", "\\w(+)", "(\\w*)", "(\\w*)x", "\\d+$", "^\\d*$", "\\s*\\S*\\s*", "\\.+$",
];
const SPECIAL_SUBJECTS: &[&str] = &[
    "", "a", "ab", "abc", "ABC", "user 42", "  ", "\u{0}abc", "abc\u{0}def", "\u{ff}", "\u{c3}\u{a9}", "\u{c3}\u{89}", "1.2.3.4",
    "user root from 10.0.0.1", "x  123", "(word)", "a|b", "$15", "<tag>", "tab\there", "line\nnext", "a@b.c", "12345", "-_-",
    "...", "aaaa", "abcde", "x 7", "trailing ", " leading", "\r\n",
];

pub fn run(out: &Out) -> usize {
    let tsv = load_tsv();
    let mut r = Rng::new(0x5EED_0001);
    let mut n = 0;

    // ---- OSRegex
    let mut seen = HashSet::new();
    let mut cases = Vec::new();
    let mut push = |cases: &mut Vec<Value>, p: &str, f: u32, s: &[u8]| {
        if seen.insert((p.to_string(), f, s.to_vec())) {
            cases.push(json!({"pattern": p, "flags": f, "subject_hex": h(s), "result": regex_result(p, f, s)}));
        }
    };
    for p in SPECIAL_PATTERNS {
        for f in [0, RS, CS, RS | CS] {
            for s in SPECIAL_SUBJECTS {
                push(&mut cases, p, f, &l1(s));
            }
        }
    }
    for (m, p, s) in &tsv.rows {
        match m {
            'R' => push(&mut cases, p, RS, s),
            'r' => push(&mut cases, p, 0, s),
            _ => {}
        }
    }
    let alpha = subj_alpha();
    for _ in 0..16000 {
        let p = fuzz_regex(&mut r, 0);
        let f = *r.pick(&[0, RS, RS, CS, RS | CS]);
        let s1 = sample(&mut r, &p);
        let s2 = sample(&mut r, &p);
        let s3 = r.bytes(&alpha, 24);
        push(&mut cases, &p, f, &s1);
        push(&mut cases, &p, f, &s2);
        push(&mut cases, &p, f, &s3);
    }
    // size limits: bytes, not characters
    for (p, s) in [
        ("a".repeat(OS_PATTERN_MAXSIZE), "a".repeat(OS_PATTERN_MAXSIZE)),
        ("a".repeat(OS_PATTERN_MAXSIZE + 1), "a".to_string()),
        ("é".repeat(OS_PATTERN_MAXSIZE / 2), "x".to_string()),
        (format!("{}a", "é".repeat(OS_PATTERN_MAXSIZE / 2)), "x".to_string()),
        ("\\w+$".to_string(), "a".repeat(200_000)),
        ("^(\\w+) (\\d+)$".to_string(), format!("{} 1", "b".repeat(100_000))),
    ] {
        push(&mut cases, &p, RS, s.as_bytes());
    }
    n += out.write(K, "osregex", "OsRegex::compile(pattern, flags) then execute_bytes(subject). flags: 128 = return substrings, 256 = case sensitive. result: error {error,code} | {has_sub_strings, match:false} | {has_sub_strings, match:true, end (offset of the last consumed byte, may be -1), subs_hex}", cases);

    // ---- OSMatch
    let mut seen = HashSet::new();
    let mut cases = Vec::new();
    let mut push = |cases: &mut Vec<Value>, p: &str, f: u32, s: &[u8]| {
        if seen.insert((p.to_string(), f, s.to_vec())) {
            cases.push(json!({"pattern": p, "flags": f, "subject_hex": h(s), "result": match_result(p, f, s)}));
        }
    };
    let mpats = [
        "", "!", "!!", "^", "$", "^$", "|", "||", "a|", "|a", "!a", "!^a", "!a$", "^a", "a$", "^a$", "ab|cd", "^ab|cd$", "failed|denied",
        "é", "^é", "é$", "^é$", "É", "!é", "^ABC", "abc$", "A", "$a", "a^", "^^a", "a$$", "!|a", "\\", "^\\$", "a\u{0}b",
    ];
    for p in mpats {
        for f in [0, CS] {
            for s in SPECIAL_SUBJECTS.iter().chain(["failed login", "ACCESS DENIED", "cd", "xab", "$a", "a^", "!a", "|", "abc\u{0}"].iter()) {
                push(&mut cases, p, f, &l1(s));
            }
        }
    }
    for (m, p, s) in &tsv.rows {
        if *m == 'M' {
            push(&mut cases, p, 0, s);
        }
    }
    let malpha: Vec<char> = "ab1 :-.AB^$|!é\\".chars().collect();
    for _ in 0..20000 {
        let len = r.below(11);
        let p: String = (0..len).map(|_| *r.pick(&malpha)).collect();
        let f = *r.pick(&[0, 0, CS]);
        let mut s = r.bytes(&l1("ab1 :-.AB^$|!\u{c3}\u{a9}\u{e9}\u{0}xyz"), 14);
        if r.chance(0.4) {
            s = p.replace(['^', '$', '|', '!'], "").into_bytes();
            if r.chance(0.5) {
                s.extend_from_slice(b" end");
            }
        }
        push(&mut cases, &p, f, &s);
    }
    push(&mut cases, &"a".repeat(OS_PATTERN_MAXSIZE), 0, b"a");
    push(&mut cases, &"a".repeat(OS_PATTERN_MAXSIZE + 1), 0, b"a");
    push(&mut cases, &format!("!{}", "a".repeat(OS_PATTERN_MAXSIZE)), 0, b"a");
    n += out.write(K, "osmatch", "OsMatch::compile(pattern, flags) then is_match_bytes(subject). flags 256 = case sensitive. result: {error,code} | {negated, patterns_hex (compiled pieces: anchors removed, folded to lower case unless case sensitive), match}", cases);

    // ---- word match and the two one-shot helpers
    let mut seen = HashSet::new();
    let mut cases = Vec::new();
    for (m, p, s) in &tsv.rows {
        if *m == 'W' {
            let s = String::from_utf8_lossy(s).into_owned();
            if seen.insert((p.clone(), s.clone())) {
                cases.push(json!({"fn": "os_word_match", "pattern": p, "subject": s, "result": os_word_match(p, &s)}));
            }
        }
    }
    let walpha: Vec<char> = "ab1 :-.AB^$|é".chars().collect();
    for i in 0..12000 {
        let len = r.below(9);
        let p: String = (0..len).map(|_| *r.pick(&walpha)).collect();
        let s: String = if r.chance(0.5) {
            let sl = r.below(12);
            (0..sl).map(|_| *r.pick(&walpha)).chain(if i % 50 == 0 { Some('\u{0}') } else { None }).collect()
        } else {
            format!("x{}", p.replace(['^', '|'], ""))
        };
        if seen.insert((p.clone(), s.clone())) {
            cases.push(json!({"fn": "os_word_match", "pattern": p, "subject": s, "result": os_word_match(&p, &s)}));
        }
    }
    for p in SPECIAL_PATTERNS.iter().take(40) {
        for s in SPECIAL_SUBJECTS.iter().take(12) {
            cases.push(json!({"fn": "os_regex", "pattern": p, "subject": s, "result": os_regex(p, s)}));
        }
    }
    for p in mpats {
        for s in SPECIAL_SUBJECTS.iter().take(12) {
            cases.push(json!({"fn": "os_match2", "pattern": p, "subject": s, "result": os_match2(p, s)}));
        }
    }
    n += out.write(K, "word_match_and_oneshot", "os_word_match(pattern, subject) / os_regex(pattern, subject) (compile flags 0 + match, false on compile error) / os_match2(pattern, subject) (same for OsMatch)", cases);

    n += expressions(out, &mut r);
    n += ips(out, &mut r);
    n += strings(out, &mut r);
    n += tables(out);
    n
}

fn exp_err(e: &ExpressionError) -> Value {
    match e {
        ExpressionError::Regex(re) => json!({"error": "regex", "code": *re as i32, "display": e.to_string()}),
        ExpressionError::Pcre2(_) => json!({"error": "pcre2"}),
        ExpressionError::InvalidIp(_) => json!({"error": "invalid_ip", "display": e.to_string()}),
    }
}

fn exp_case(t: ExpType, p: &str, f: u32, subjects: &[Vec<u8>]) -> Value {
    let tname = format!("{t:?}");
    match Expression::compile(t, p, f) {
        Err(e) => json!({"type": tname, "pattern": p, "flags": f, "compile": exp_err(&e)}),
        Ok(e) => {
            assert_eq!(e.exp_type(), t);
            assert!(!e.negate);
            let mut res = Vec::new();
            for s in subjects {
                let mut prior = vec![b"PRIOR".to_vec()];
                let (m, end) = e.match_bytes(s, Some(&mut prior));
                let (m2, end2) = e.match_bytes(s, None);
                assert_eq!((m, end), (m2, end2));
                let mut v = json!({"subject_hex": h(s), "match_bytes": {"matched": m, "end": end, "captures_after_hex": prior.iter().map(|x| h(x)).collect::<Vec<_>>()}});
                if let Ok(st) = std::str::from_utf8(s) {
                    let mm = e.matches(st);
                    let mut neg = e.clone();
                    neg.negate = true;
                    assert_eq!(e.is_match(st), mm.matched);
                    assert_eq!(neg.is_match(st), !mm.matched);
                    v["matches_str"] = json!({"matched": mm.matched, "end_match": mm.end_match, "sub_strings": mm.sub_strings});
                }
                res.push(v);
            }
            json!({"type": tname, "pattern": p, "flags": f, "compile": "ok", "pattern_fn": e.pattern(), "type_str": e.type_str(), "subjects": res})
        }
    }
}

fn expressions(out: &Out, r: &mut Rng) -> usize {
    assert_eq!((OSMATCH_STR, OSREGEX_STR, PCRE2_STR, STRING_STR), ("osmatch", "osregex", "pcre2", "string"));
    let mut cases = Vec::new();
    let gen_subj = |r: &mut Rng, p: &str| -> Vec<Vec<u8>> {
        let mut v = vec![sample(r, p), sample(r, p), r.bytes(&subj_alpha(), 16)];
        let mut z = sample(r, p);
        z.push(0);
        z.extend_from_slice(b"after nul");
        v.push(z);
        v
    };
    for p in SPECIAL_PATTERNS {
        for f in [0, RS, CS] {
            let s = gen_subj(r, p);
            cases.push(exp_case(ExpType::OsRegex, p, f, &s));
        }
    }
    for _ in 0..1500 {
        let p = fuzz_regex(r, 0);
        let f = *r.pick(&[0, RS, RS | CS]);
        let s = gen_subj(r, &p);
        cases.push(exp_case(ExpType::OsRegex, &p, f, &s));
    }
    for p in ["", "!", "^a", "a$", "^a$", "failed|denied", "!sshd", "é", "^ABC|x$", "a\u{0}b"] {
        for f in [0, CS] {
            let s: Vec<Vec<u8>> = SPECIAL_SUBJECTS.iter().map(|x| l1(x)).chain([b"Failed".to_vec(), b"sshd: ok".to_vec()]).collect();
            cases.push(exp_case(ExpType::OsMatch, p, f, &s));
        }
    }
    let pcre: &[(&str, &[&str])] = &[
        (r"(?i)user=(\w+)\s+uid=(\d+)", &["x USER=root uid=0 y", "user=a uid=", ""]),
        (r"(a)|(b)", &["a", "b", "c", "ab"]),
        (r"(a)?(b)", &["b", "ab", "zzb"]),
        (r"(a)(b)?", &["a", "ab"]),
        (r"^$", &["", "x"]),
        (r"x*", &["", "yyy", "xx"]),
        (r"^.$", &["\u{c3}\u{a9}", "a", "\u{ff}"]),
        (r"\d+", &["abc 123 456", "none"]),
        (r"(\d+)-(\d+)", &["10-20", "1-", "a1-2b"]),
        (r"(?<name>\w+)@(?<dom>[\w.]+)", &["me@ex.com", "@"]),
        (r"\bword\b", &["a word here", "swordfish"]),
        (r"a.c", &["abc", "a\nc", "a\u{0}c"]),
        (r"(?s)a.c", &["a\nc"]),
        (r"^abc", &["abc\u{0}def", "\u{0}abc"]),
        (r"def$", &["abc\u{0}def"]),
        (r"()", &["", "x"]),
        (r"(x)()", &["x"]),
        (r"\x{e9}", &["\u{e9}", "\u{c3}\u{a9}"]),
        (r"[[:alpha:]]+", &["abc1", "123"]),
        (r"(", &[""]),
        (r"[a-", &[""]),
        (r"a{2,1}", &[""]),
        (r"(?<=a)b", &["ab", "cb"]),
        (r"\", &[""]),
        (r"*a", &[""]),
        (r"(?i)FAILED", &["failed password", "FaIlEd"]),
        (r"^(\S+) (\S+)$", &["one two", "one  two"]),
        (r"(((a)))", &["a"]),
        (r"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)", &["abcdefghijk"]),
    ];
    for (p, subs) in pcre {
        let s: Vec<Vec<u8>> = subs.iter().map(|x| l1(x)).collect();
        cases.push(exp_case(ExpType::Pcre2, p, 0, &s));
        cases.push(exp_case(ExpType::Pcre2, p, RS | CS, &s));
    }
    for p in ["exact", "", "Exact", "a\u{0}b", "é"] {
        let s: Vec<Vec<u8>> = ["exact", "exactly", "", "Exact", "a", "a\u{0}b", "\u{c3}\u{a9}", "exact\u{0}tail"].iter().map(|x| l1(x)).collect();
        cases.push(exp_case(ExpType::String, p, 0, &s));
    }
    let ipsubj: Vec<Vec<u8>> = ["10.1.1.1", "192.168.1.1", "192.168.1.2", "::1", "2001:db8::5", "x", "", "10.1.1.1\u{0}junk", " 10.1.1.1"].iter().map(|x| l1(x)).collect();
    for p in ["10.0.0.0/8", "192.168.1.1", "any", "!10.0.0.0/8", "2001:db8::/32", "bad", "", "::ffff:10.0.0.1"] {
        cases.push(exp_case(ExpType::OsIpArray, p, 0, &ipsubj));
    }
    // add_osip sequences
    let seqs: &[&[&str]] = &[
        &["10.0.0.0/8", "192.168.1.1"],
        &["10.0.0.0/8", "bad", "192.168.1.1"],
        &["bad", "192.168.1.1"],
        &["any"],
        &["!1.2.3.4", "5.6.7.8"],
        &["2001:db8::/32", "10.0.0.1"],
        &[],
    ];
    for start in ["none", "osmatch"] {
        for seq in seqs {
            let mut e = if start == "none" { None } else { Some(Expression::compile(ExpType::OsMatch, "abc", 0).unwrap()) };
            let mut steps = Vec::new();
            for ip in *seq {
                let res = Expression::add_osip(&mut e, ip);
                steps.push(json!({"add": ip, "ok": res.is_ok(), "now_none": e.is_none(),
                    "now_type": e.as_ref().map(|x| format!("{:?}", x.exp_type())),
                    "now_ips": e.as_ref().and_then(|x| if let ExpressionKind::OsIpArray(v) = &x.kind { Some(v.iter().map(|o| o.ip.clone()).collect::<Vec<_>>()) } else { None })}));
            }
            let m: Vec<Value> = ipsubj.iter().map(|s| {
                let st = String::from_utf8_lossy(s).into_owned();
                json!({"subject": st, "matched": e.as_ref().map(|x| x.matches(&st).matched)})
            }).collect();
            cases.push(json!({"add_osip_start": start, "steps": steps, "pattern_fn": e.as_ref().map(|x| x.pattern().map(str::to_string)), "subjects": m}));
        }
    }
    out.write(K, "expression", "Expression::compile(type, pattern, flags), then match_bytes(subject, Some(captures pre-filled with [\"PRIOR\"])) and matches(subject as text). Also add_osip sequences.", cases)
}

fn net_json(n: &IpNet) -> Value {
    match n {
        IpNet::V4 { ip_address, netmask } => json!({"v4_addr": h(&ip_address.to_ne_bytes()), "v4_mask": h(&netmask.to_ne_bytes())}),
        IpNet::V6 { ip_address, netmask } => json!({"v6_addr": h(ip_address), "v6_mask": h(netmask)}),
    }
}

fn osip_json(o: &OsIp) -> Value {
    json!({"ip": o.ip, "is_ipv6": o.is_ipv6, "negated": o.negated(), "net": net_json(&o.net), "cidr_to_str": cidr_to_str(o)})
}

const IP_LIST: &[&str] = &[
    "1.1.1.1", "255.255.255.255", "0.0.0.0", "127.0.0.1", "10.10.10.10", "192.168.10.12/32", "0.0.0.0/32", "0.0.0.0/0", "10.0.0.0/8",
    "10.1.2.3/8", "1.2.3.4/0", "1.2.3.4/1", "1.2.3.4/31", "1.2.3.4/32", "1.2.3.4/33", "1.2.3.4/", "1.2.3.4/255.255.255.0",
    "1.2.3.4/255.0.255.0", "1.2.3.4/0.0.0.0", "1.2.3.4/255.255.255.255", "1.2.3.4/255.255.255.256", "1.2.3.4/01", "1.2.3.4/001",
    "16.16.16.16/255.255.255.0", "32.32.32.32/255.255.255.255", "12.0", "111", "01.01", "10.10.10.10.10", "256.1.1.1", "1.1.1.256",
    "01.01.01.01", "001.001.001.001", "000.00.0.1", "1.1.1.10/36.255.255", "1.1.1.1/36.1.1.256", " 1.2.3.4", "1.2.3.4 ", "!1.2.3.4",
    "!10.0.0.0/8", "!any", "any", "ANY", "any/8", "::ffff:10.2.3.1", "::FFFF:10.2.3.1", "::ffff:10.2.3.1/24", "::ffff:10.2.3.1/255.0.0.0",
    "::ffff:1.2.3.4/33", "::fffe:1.2.3.4", "::1.2.3.4", "2001:db8:abcd:0012:0000:0000:0000:0000", "2001:db8:abcd:0012:ffff:ffff:ffff:ffff",
    "fe80::ceaf:9ff2:b33c:1ca7", "11AA:11AA:11AA:11AA:11AA:11AA:11AA:11AA", "11AA::11AA:11AA:11AA:11AA:11AA:11AA", "11AA::11AA",
    "11AA:11AA:11AA:11AA:11AA:11AA:11AA::", "11AA::", "::11AA:11AA:11AA:11AA:11AA:11AA:11AA", "::11AA", "::", "::/0", "::1", "::1/128",
    "2001:db8::/32", "2001:db8::/0", "2001:db8::/128", "2001:db8::/129", "2001:db8::/064", "2001:db8::/0064", "2001:db8::1/64",
    "2001::db8:abcd::0012/64", "fe80::1%eth0", "12345::1", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "1::2::3", ":::", ":1", "1:",
    "", "!", "/", "/8", "1.2.3.4/8/8", "a.b.c.d", "1.2.3.4\u{0}", "x::1", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF/127",
    "0000:0000:0000:0000:0000:0000:0000:0001/127", "1234:5678:9abc:def0:1234:5678:9abc:def0/56",
    "1234:5678:9abc:def0:1234:5678:9abc:def0:extra-long-text-beyond-46-chars", "::ffff:255.255.255.255", "::ffff:256.1.1.1",
];

fn ips(out: &Out, r: &mut Rng) -> usize {
    let mut list: Vec<String> = IP_LIST.iter().map(|s| s.to_string()).collect();
    let alpha: Vec<char> = "0123456789abcdefABCDEF:./!anyf".chars().collect();
    for _ in 0..4000 {
        let n = 1 + r.below(22);
        list.push((0..n).map(|_| *r.pick(&alpha)).collect());
    }
    for _ in 0..1500 {
        let mut s = format!("{}.{}.{}.{}", r.below(300), r.below(300), r.below(260), r.below(260));
        if r.chance(0.5) {
            s += &format!("/{}", r.below(40));
        }
        list.push(s);
        let g: Vec<String> = (0..8).map(|_| format!("{:x}", r.below(0x10000))).collect();
        let k = r.below(8);
        let mut s = if r.chance(0.5) { g.join(":") } else { format!("{}::{}", g[..k].join(":"), g[k + 1..].join(":")) };
        if r.chance(0.5) {
            s += &format!("/{}", r.below(140));
        }
        list.push(s);
    }
    let mut seen = HashSet::new();
    list.retain(|s| seen.insert(s.clone()));

    let mut cases = Vec::new();
    let mut parsed: Vec<OsIp> = Vec::new();
    for s in &list {
        let (code, ip) = is_valid_ip(s);
        cases.push(json!({"fn": "is_valid_ip", "input": s, "code": code, "parsed": ip.as_ref().map(osip_json)}));
        if let Some(ip) = ip {
            if parsed.len() < 160 && !parsed.contains(&ip) {
                parsed.push(ip);
            }
        }
        cases.push(json!({"fn": "get_ipv4_from_ipv6", "input": s, "result": get_ipv4_from_ipv6(s)}));
        cases.push(json!({"fn": "expand_ipv6", "input": s, "result": expand_ipv6(s)}));
    }
    for s in ["0", "12", "-5", "+7", "  42x", "\t9", "abc", "", "2147483647", "2147483648", "-2147483648", "-2147483649", "99999999999", "007", "1e3", " -0", "+-1", "\n3"] {
        cases.push(json!({"fn": "atoi", "input": s, "result": atoi(s)}));
    }
    // negated entries (text starting with '!') can only be made by hand
    let mut entries = parsed.clone();
    for p in parsed.iter().take(12) {
        let mut q = p.clone();
        q.ip = format!("!{}", q.ip);
        entries.push(q);
    }
    let targets = [
        "10.1.2.3", "10.0.0.0", "11.0.0.1", "1.2.3.4", "1.2.3.5", "16.16.16.200", "192.168.10.12", "0.0.0.0", "255.255.255.255",
        "127.0.0.1", "::1", "::", "2001:db8::5", "2001:db8:1::5", "2001:db9::5", "fe80::ceaf:9ff2:b33c:1ca7", "11aa::11aa",
        "::ffff:10.2.3.1", "10.2.3.1", "abc", "", " 1.2.3.4", "1.2.3.4/32", "any", "8.8.8.8", "2001:0db8:0000:0000:0000:0000:0000:0005",
    ];
    for e in &entries {
        for t in targets {
            cases.push(json!({"fn": "ip_found", "target": t, "entry": osip_json(e), "result": ip_found(t, e)}));
        }
    }
    for _ in 0..3000 {
        let n = r.below(5);
        let l: Vec<OsIp> = (0..n).map(|_| r.pick(&entries).clone()).collect();
        let t = *r.pick(&targets);
        cases.push(json!({"fn": "ip_found_list", "target": t, "list": l.iter().map(osip_json).collect::<Vec<_>>(), "result": ip_found_list(t, &l)}));
    }
    out.write(K, "ip", "is_valid_ip (code 0 invalid, 1 address, 2 network/any; parsed entry), get_ipv4_from_ipv6, expand_ipv6, atoi, ip_found(target, entry), ip_found_list(target, list). v4 bytes are in network order.", cases)
}

fn strings(out: &Out, r: &mut Rng) -> usize {
    let mut cases = Vec::new();
    let words = ["", "0", "123", "12a", " 1", "1 ", "-1", "+1", "٣", "00000", "1.5", "\u{0}", "9\u{0}x", "abc"];
    for w in words {
        cases.push(json!({"fn": "str_is_num", "input": w, "result": str_is_num(w)}));
    }
    let pairs = [("", ""), ("abc", ""), ("", "abc"), ("abc", "abc"), ("abc", "abd"), ("abcd", "abxy"), ("a", "a"), ("Ab", "ab"), ("ab\u{0}c", "ab\u{0}d"), ("é", "è"), ("x", "xyz"), ("xyz", "x")];
    for (a, b) in pairs {
        cases.push(json!({"fn": "str_starts_with", "s": a, "pattern": b, "result": str_starts_with(a, b)}));
        cases.push(json!({"fn": "str_how_closed_match", "a": a, "b": b, "result": str_how_closed_match(a, b)}));
    }
    let seps = [',', ':', ' ', '\\', 'é', '\u{12c}', '\u{0}'];
    let mut inputs: Vec<String> = [
        "a,b,c", "", ",", ",,", "a\\,b,c", "a\\\\,b", "\\", "a,", ",a", "a\\:b:c", "x y  z", "a,b\u{0},c", "é,è", "a\\,b\\,c\\,d",
        "one two three four five", "\\,", "a,,b", "a\u{12c}b",
    ].iter().map(|s| s.to_string()).collect();
    let alpha: Vec<char> = "ab,:\\ é".chars().collect();
    for _ in 0..1500 {
        let n = r.below(12);
        inputs.push((0..n).map(|_| *r.pick(&alpha)).collect());
    }
    for s in &inputs {
        for sep in seps {
            for size in [0usize, 1, 2, 3, 4, 64] {
                if sep != ',' && sep != ':' && sep != ' ' && size != 3 {
                    continue;
                }
                cases.push(json!({"fn": "str_break", "sep": sep.to_string(), "input": s, "size": size, "result": str_break(sep, s, size)}));
            }
        }
    }
    for s in [&b"a\xff,b"[..], b"\x80,\x81,\x82", b"a,b\x00c,d", b"\\\xff,x"] {
        for size in [0usize, 2, 5] {
            let res = siem_regex::strings::str_break_bytes(b',', s, size).map(|v| v.iter().map(|x| h(x)).collect::<Vec<_>>());
            cases.push(json!({"fn": "str_break_bytes", "sep_hex": "2c", "input_hex": h(s), "size": size, "result_hex": res}));
        }
    }
    for c in 0..=255u8 {
        cases.push(json!({"fn": "is_valid_hostname_char", "byte": c, "result": is_valid_hostname_char(c), "hostname_map_is_1": siem_regex::maps::HOSTNAME_MAP[c as usize] == 1}));
    }
    out.write(K, "strings", "str_is_num, str_starts_with, str_how_closed_match, str_break(sep, s, size) (None when size 0), str_break_bytes, is_valid_hostname_char / hostname-table value 1", cases)
}

fn tables(out: &Out) -> usize {
    use siem_regex::maps::{CHARMAP, HOSTNAME_MAP, REGEXMAP};
    let mut cases = Vec::new();
    let names = ["(unused 0)", "\\d", "\\w", "\\s", "\\p", "\\(", "\\)", "\\\\", "\\D", "\\W", "\\S", "\\.", "\\t", "\\$", "\\|", "\\<"];
    for (code, row) in REGEXMAP.iter().enumerate() {
        let members: Vec<u8> = (0..=255u8).filter(|&c| row[c as usize] == 1).collect();
        cases.push(json!({"table": "osregex_class", "escape": names[code], "code": code, "member_bytes": members}));
    }
    let folded: Vec<Value> = (0..=255u8).filter(|&c| CHARMAP[c as usize] != c).map(|c| json!([c, CHARMAP[c as usize]])).collect();
    cases.push(json!({"table": "case_fold", "changed": folded}));
    cases.push(json!({"table": "hostname_value", "values": HOSTNAME_MAP.to_vec()}));
    out.write(K, "tables", "Character classes of every OSRegex escape (bytes that belong), case folding (bytes that change), hostname table values", cases)
}
