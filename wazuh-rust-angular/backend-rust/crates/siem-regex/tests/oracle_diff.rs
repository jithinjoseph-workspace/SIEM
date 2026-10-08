//! Differential test against Wazuh's C `os_regex` (see `tools/gen_oracle.py`).
//!
//! Each row: `mode \t hex(pattern) \t hex(log) \t expected`, where `expected`
//! is what the compiled C harness (`tools/harness.c`) printed:
//!   `E<code>` compile error, `N` no match, `Y` match (OSMatch / WordMatch), or
//!   `Y <end-offset> [hex(substring)|-]...` for OSRegex.
//! Set `SIEM_REGEX_ORACLE=<path>` to run a larger, freshly generated corpus.

use siem_regex::{os_word_match, OsMatch, OsRegex, OS_RETURN_SUBSTRING};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn error_code(e: siem_regex::RegexError) -> i32 {
    e as i32
}

fn run(mode: &str, pat: &[u8], log: &[u8]) -> String {
    // The C harness works on raw bytes; patterns in the corpus are valid UTF-8.
    let pat = String::from_utf8(pat.to_vec()).expect("utf8 pattern");
    match mode {
        "R" | "r" => {
            let flags = if mode == "R" { OS_RETURN_SUBSTRING } else { 0 };
            match OsRegex::compile(&pat, flags) {
                Err(e) => format!("E{}", error_code(e)),
                Ok(re) => match re.execute_bytes(log) {
                    None => "N".to_string(),
                    Some(m) => {
                        let mut s = format!("Y {}", m.end);
                        for sub in &m.sub_strings {
                            s.push(' ');
                            if sub.is_empty() {
                                s.push('-');
                            } else {
                                s.push_str(&hex(sub.as_bytes()));
                            }
                        }
                        s
                    }
                },
            }
        }
        "M" => match OsMatch::compile(&pat, 0) {
            Err(e) => format!("E{}", error_code(e)),
            Ok(m) => if m.is_match_bytes(log) { "Y" } else { "N" }.to_string(),
        },
        "W" => {
            let log = String::from_utf8_lossy(log);
            if os_word_match(&pat, &log) { "Y" } else { "N" }.to_string()
        }
        other => panic!("unknown mode {other}"),
    }
}

#[test]
fn matches_c_oracle() {
    let path = std::env::var("SIEM_REGEX_ORACLE")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/oracle_cases.tsv").to_string());
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut total = 0usize;
    let mut failures = Vec::new();
    for line in data.lines() {
        let cols: Vec<&str> = line.splitn(4, '\t').collect();
        if cols.len() != 4 {
            continue;
        }
        total += 1;
        let (pat, log) = (unhex(cols[1]), unhex(cols[2]));
        let got = run(cols[0], &pat, &log);
        // The C implementation crashed on this input (memory-safety bug in
        // Wazuh); we only require the port to return without panicking.
        if cols[3] == "CRASH" {
            continue;
        }
        if got != cols[3] {
            failures.push(format!(
                "mode={} pattern={:?} log={:?}\n   expected: {}\n   got:      {}",
                cols[0],
                String::from_utf8_lossy(&pat),
                String::from_utf8_lossy(&log),
                cols[3],
                got
            ));
        }
    }
    assert!(total > 0, "empty oracle corpus");
    if !failures.is_empty() {
        let shown: Vec<_> = failures.iter().take(25).cloned().collect();
        panic!("{} / {} cases differ from C os_regex:\n{}", failures.len(), total, shown.join("\n"));
    }
    eprintln!("{total} oracle cases match the C implementation");
}
