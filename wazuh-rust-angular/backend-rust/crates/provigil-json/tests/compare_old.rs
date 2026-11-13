//! Old JSON code against new: the same inputs must give the same values, the same error offsets
//! and the same printed bytes.

use provigil_json::Json;
use siem_cjson::Json as Old;

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
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

fn from_old(o: &Old) -> Json {
    match o {
        Old::False => Json::False,
        Old::True => Json::True,
        Old::Null => Json::Null,
        Old::Number { double, int } => Json::Number { double: *double, int: *int },
        Old::String(s) => Json::String(s.clone()),
        Old::Array(a) => Json::Array(a.iter().map(from_old).collect()),
        Old::Object(m) => Json::Object(m.iter().map(|(k, v)| (k.clone(), from_old(v))).collect()),
        Old::Raw(_) => panic!("the parser never makes raw values"),
    }
}

fn to_old(j: &Json) -> Old {
    match j {
        Json::False => Old::False,
        Json::True => Old::True,
        Json::Null => Old::Null,
        Json::Number { double, int } => Old::Number { double: *double, int: *int },
        Json::String(s) => Old::String(s.clone()),
        Json::Array(a) => Old::Array(a.iter().map(to_old).collect()),
        Json::Object(m) => Old::Object(m.iter().map(|(k, v)| (k.clone(), to_old(v))).collect()),
    }
}

/// NaN != NaN: compare through the bits.
fn same(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Number { double: x, int: i }, Json::Number { double: y, int: j }) => x.to_bits() == y.to_bits() && i == j,
        (Json::Array(x), Json::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b)),
        (Json::Object(x), Json::Object(y)) => x.len() == y.len() && x.iter().zip(y).all(|((k, a), (l, b))| k == l && same(a, b)),
        _ => a == b,
    }
}

fn check(input: &[u8]) {
    for whole in [false, true] {
        let old = siem_cjson::parse_with_opts(input, whole).map(|(v, at)| (from_old(&v), at));
        let new = provigil_json::parse_with_opts(input, whole);
        let ok = match (&old, &new) {
            (Ok((a, x)), Ok((b, y))) => x == y && same(a, b),
            (Err(x), Err(y)) => x == y,
            _ => false,
        };
        assert!(ok, "input {:?} whole={whole}\n old: {old:?}\n new: {new:?}", String::from_utf8_lossy(input));
        if let Ok((v, _)) = new {
            printed_same(&v);
        }
    }
}

fn printed_same(v: &Json) {
    let o = to_old(v);
    assert_eq!(v.print_unformatted(), o.print_unformatted(), "{v:?}");
    assert_eq!(v.print(), o.print(), "{v:?}");
}

/// Short random byte strings over the bytes that matter to the reader.
#[test]
fn random_text() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    let alphabet: Vec<&[u8]> = vec![
        b"{", b"}", b"[", b"]", b",", b":", b"\"", b"\\", b"u", b"0", b"1", b"9", b"-", b"+", b".", b"e", b"E", b"a", b"f", b"D", b"8", b"C", b" ", b"\t", b"\n", b"\x01", b"\0",
        b"\xEF\xBB\xBF", b"\xC3\xA9", b"\xFF", b"null", b"true", b"false", b"nul", b"\\u", b"\\ud83d", b"\\ude00", b"\\n", b"\"k\":", b"1e400", b"0.1", b"x", b"/",
    ];
    for _ in 0..300_000 {
        let n = r.below(14);
        let s: Vec<u8> = (0..n).flat_map(|_| r.pick(&alphabet).to_vec()).collect();
        check(&s);
    }
}

fn number(r: &mut Rng) -> String {
    match r.below(7) {
        0 => f64::from_bits(r.next()).to_string(),
        1 => format!("{}", r.next() as i64 >> r.below(64)),
        2 => format!("{}.{}e{}{}", r.below(1_000_000), r.below(1_000_000_000), r.pick(&["", "+", "-"]), r.below(330)),
        // halfway between two 15- or 17-digit decimals
        3 => format!("{}{}.5", r.below(9) + 1, r.next() % 100_000_000_000_000),
        4 => format!("-0.{}{}", "0".repeat(r.below(8)), r.next()),
        5 => format!("{}", (r.next() >> 11) as f64 / (1u64 << r.below(60)) as f64),
        _ => format!("{}", r.below(2_000_000_000) as i64 * if r.below(2) == 0 { 1 } else { -1 } * (1 + r.below(3) as i64)),
    }
}

fn string(r: &mut Rng) -> String {
    let parts = ["a", "Z", " ", "\\n", "\\t", "\\\"", "\\\\", "\\/", "\\b", "\\f", "\\r", "\\u00e9", "\\u0001", "\\u001f", "\\ud83d\\ude00", "\\u20AC", "é", "€", "\\u0000", "\\uZZZZ", "\u{1}", "\u{7f}"];
    let n = r.below(6);
    format!("\"{}\"", (0..n).map(|_| *r.pick(&parts)).collect::<String>())
}

fn doc(r: &mut Rng, depth: usize) -> String {
    let ws = |r: &mut Rng| r.pick(&["", "", " ", "\n\t", "\r\n  "]).to_string();
    match if depth > 4 { r.below(4) } else { r.below(7) } {
        0 => number(r),
        1 => string(r),
        2 => r.pick(&["true", "false", "null"]).to_string(),
        3 => number(r),
        4 | 5 => {
            let n = r.below(5);
            let items: Vec<String> = (0..n).map(|_| format!("{}{}{}", ws(r), doc(r, depth + 1), ws(r))).collect();
            format!("[{}{}]", items.join(","), ws(r))
        }
        _ => {
            let n = r.below(5);
            let items: Vec<String> = (0..n).map(|_| format!("{}{}{}:{}{}", ws(r), string(r), ws(r), ws(r), doc(r, depth + 1))).collect();
            format!("{{{}{}}}", items.join(","), ws(r))
        }
    }
}

/// Structured documents, also cut short or with one byte changed.
#[test]
fn random_documents() {
    let mut r = Rng(0xD1B54A32D192ED03);
    for _ in 0..100_000 {
        let d = doc(&mut r, 0).into_bytes();
        check(&d);
        if !d.is_empty() {
            check(&d[..r.below(d.len())]);
            let mut m = d.clone();
            let i = r.below(m.len());
            m[i] = *r.pick(&[b'"', b',', b':', b'}', b']', b'\\', b' ', b'x', 0]);
            check(&m);
        }
    }
}

/// Numbers alone, from random bits too; printed values built in code as well.
#[test]
fn random_numbers() {
    let mut r = Rng(0x2545F4914F6CDD1D);
    for _ in 0..300_000 {
        let t = number(&mut r);
        check(t.as_bytes());
        let d = f64::from_bits(r.next());
        printed_same(&Json::number(d));
        assert_eq!(provigil_json::fmt_f6(d), siem_cjson::fmt_f6(d));
    }
    for d in [0.0, -0.0, f64::NAN, -f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MIN_POSITIVE, 5e-324, f64::MAX, 2147483647.5, -2147483648.5, 1e15, 1e16, 1e17] {
        printed_same(&Json::number(d));
        assert_eq!(provigil_json::fmt_f6(d), siem_cjson::fmt_f6(d));
        assert_eq!(provigil_json::clamp_i32(d), siem_cjson::saturate(d));
    }
}

#[test]
fn nesting_and_mark() {
    for n in [999, 1000, 1001] {
        for (o, c) in [("[", "]"), ("{\"a\":", "}")] {
            check(format!("{}1{}", o.repeat(n), c.repeat(n)).as_bytes());
        }
    }
    for s in [&b"\xEF\xBB\xBF1"[..], b"\xEF\xBB\xBF", b"\xEF\xBB\xBF ", b"\xEF\xBB\xBF{}", b"\xEF\xBB"] {
        check(s);
    }
}

/// Lookups, edits and printing of documents built in code.
#[test]
fn building_and_lookup() {
    let mut r = Rng(0xA0761D6478BD642F);
    for _ in 0..20_000 {
        let d = doc(&mut r, 0);
        let (Some(v), Some(o)) = (provigil_json::parse(d.as_bytes()), siem_cjson::parse(d.as_bytes())) else { continue };
        for key in ["", "a", "A", "Z", "aZ"] {
            assert_eq!(v.get(key).map(|x| x.print_unformatted()), o.get(key).map(|x| x.print_unformatted()));
            let (mut v2, mut o2) = (v.clone(), o.clone());
            assert_eq!(v2.remove(key).map(|x| x.print_unformatted()), o2.remove(key).map(|x| x.print_unformatted()));
            assert_eq!(v2.print_unformatted(), o2.print_unformatted());
        }
        assert_eq!(v.len(), o.len());
        assert_eq!(v.children().len(), o.children().len());
        assert_eq!(v.as_i32(), o.as_i32());
        assert_eq!(v.as_bytes(), o.as_bytes());
    }
    let mut v = Json::object();
    v.add("k", Json::bool(true)).add("k", Json::array());
    *v.get_mut("K").unwrap() = Json::string("x\0y");
    let mut o = Old::object();
    o.add("k", Old::bool(true)).add("k", Old::array());
    *o.get_mut("K").unwrap() = Old::string("x\0y");
    assert_eq!(v.print_unformatted(), o.print_unformatted());
    assert_eq!(v.print(), o.print());
}
