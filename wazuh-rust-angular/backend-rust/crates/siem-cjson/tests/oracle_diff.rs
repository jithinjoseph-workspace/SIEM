//! Differential test against the real cJSON 1.7.18 (`tools/cjson_harness.c`).
//! Enabled with `SIEM_CJSON_ORACLE=<harness>`; `SIEM_CJSON_FUZZ=<n>` sets the
//! number of generated documents (default 50000).

use siem_cjson::{fmt_f6, parse_with_opts, Json};
use std::io::Write;
use std::process::{Command, Stdio};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        v[(self.next() % v.len() as u64) as usize]
    }
    fn n(&mut self, m: u64) -> u64 {
        self.next() % m
    }
}

const NUMS: &[&str] = &[
    "0", "-0", "1", "-1", "2.5", "0.1", "1e400", "-1e400", "1e-400", "123456789012345678", "2147483647", "2147483648",
    "-2147483648", "-2147483649", "3.141592653589793", "1.", "1.e5", "1e", "1e+", "12.5e-3", "-0.0", "1E10", "9007199254740993",
    "1000000000000005", "0.30000000000000004", "4.35", "1.0000000000000002", "5e-324", "1.7976931348623157e308",
    "123.456", "0.000001", "100", "1e15", "1e16", "1e21", "0.5", "-12", "7.0", "1e-5", "1e-4", "99999999999999999999",
];
const STRS: &[&str] = &[
    "\"\"", "\"abc\"", "\"a\\nb\"", "\"\\u00e9\"", "\"\\ud83d\\ude00\"", "\"\\udc00\"", "\"\\ud83d\"", "\"\\u0000x\"",
    "\"tab\there\"", "\"\\/\"", "\"\\x\"", "\"é\"", "\"\\\"q\\\"\"", "\"\\u001f\"", "\"\x01\"", "\"unterminated",
    "\"\\uZZZZ\"", "\"\\u12\"", "\"a\\\\\"",
];

fn value(r: &mut Rng, depth: u32) -> String {
    let k = if depth > 4 { r.n(5) } else { r.n(9) };
    match k {
        0 => {
            // Random finite double from raw bits, written so strtod round-trips it.
            let f = loop {
                let f = f64::from_bits(r.next());
                if f.is_finite() {
                    break f;
                }
            };
            let scale = r.n(4);
            let f = match scale {
                0 => f,
                1 => (f.fract() * 1e6).trunc() / 1e3,
                2 => f.fract() * 1e17,
                _ => (r.next() % 100000) as f64 / 7.0,
            };
            if f.is_finite() { format!("{f:e}") } else { "1".into() }
        }
        1 => r.pick(STRS).to_string(),
        2 => r.pick(&["true", "false", "null", "tru", "nul"]).to_string(),
        3 | 4 => r.pick(NUMS).to_string(),
        5 | 6 => {
            let n = r.n(4);
            let items: Vec<String> = (0..n).map(|_| value(r, depth + 1)).collect();
            let sep = r.pick(&[",", ", ", " ,\n", ","]);
            let mut s = format!("[{}]", items.join(sep));
            if r.n(20) == 0 {
                s.pop();
            }
            if r.n(25) == 0 {
                s = s.replace(']', ",]");
            }
            s
        }
        _ => {
            let n = r.n(4);
            let items: Vec<String> = (0..n)
                .map(|_| {
                    let key = r.pick(&["\"a\"", "\"A\"", "\"key\"", "\"k\\u00e9y\"", "\"\"", "\"dup\"", "\"dup\"", "bad"]);
                    format!("{key}{}{}", r.pick(&[":", " : ", ":\t", ""]), value(r, depth + 1))
                })
                .collect();
            let mut s = format!("{{{}}}", items.join(r.pick(&[",", " , ", ",\n"])));
            if r.n(20) == 0 {
                s.pop();
            }
            s
        }
    }
}

fn doc(r: &mut Rng) -> String {
    let mut s = String::new();
    if r.n(30) == 0 {
        s.push('\u{feff}');
    }
    s.push_str(r.pick(&["", " ", "\n\t ", "\r\n"]));
    s.push_str(&value(r, 0));
    s.push_str(r.pick(&["", " ", " trailing", "]", ",1", "\n"]));
    s
}

fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rust_dump(input: &str) -> String {
    let mut out = String::new();
    match parse_with_opts(input.as_bytes(), false) {
        Err(pos) => {
            // `return_parse_end` on failure: `value + global_error.position`.
            out.push_str(&format!("P 0 {pos}\nEND\n"));
        }
        Ok((j, end)) => {
            out.push_str(&format!("P 1 {end}\nU {}\nF {}\n", hex(&j.print_unformatted()), hex(&j.print())));
            fn nums(j: &Json, out: &mut String) {
                match j {
                    Json::Number { double, int } => out.push_str(&format!("N {int} {}\n", hex(fmt_f6(*double).as_bytes()))),
                    Json::Array(a) => a.iter().for_each(|x| nums(x, out)),
                    Json::Object(m) => m.iter().for_each(|(_, x)| nums(x, out)),
                    _ => {}
                }
            }
            nums(&j, &mut out);
            out.push_str("END\n");
        }
    }
    out
}

#[test]
fn matches_c_cjson() {
    let Ok(h) = std::env::var("SIEM_CJSON_ORACLE") else {
        eprintln!("SIEM_CJSON_ORACLE not set; skipping");
        return;
    };
    let n: usize = std::env::var("SIEM_CJSON_FUZZ").ok().and_then(|v| v.parse().ok()).unwrap_or(50000);
    let mut r = Rng(0x2545F4914F6CDD1D);
    let docs: Vec<String> = (0..n).map(|_| doc(&mut r)).collect();
    let mut child = Command::new(h).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let feed: String = docs.iter().map(|d| hex(d.as_bytes()).replace('-', "") + "\n").collect();
    let t = std::thread::spawn(move || stdin.write_all(feed.as_bytes()).unwrap());
    let out = child.wait_with_output().unwrap();
    t.join().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    let parts: Vec<&str> = text.split_inclusive("END\n").collect();
    assert_eq!(parts.len(), docs.len());
    let mut bad = 0;
    for (d, c) in docs.iter().zip(parts) {
        let c = c.to_string();
        let ours = rust_dump(d);
        if ours != c {
            bad += 1;
            if bad <= 8 {
                eprintln!("INPUT {d:?}\n--- rust\n{ours}--- c\n{c}");
            }
        }
    }
    assert_eq!(bad, 0, "{bad} / {} documents differ from cJSON", docs.len());
    eprintln!("{} documents identical to cJSON", docs.len());
}
