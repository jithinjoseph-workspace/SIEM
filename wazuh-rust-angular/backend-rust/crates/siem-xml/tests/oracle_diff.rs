//! Differential test against Wazuh's C `os_xml` (`tools/xml_harness.c`).
//!
//! `SIEM_XML_ORACLE=<harness>` enables it; `SIEM_XML_CORPUS=<dir>` adds every
//! `*.xml` / `*.conf` file under that directory (e.g. a Wazuh source tree).
//! Without the variables the test is skipped.

use siem_xml::{dump::dump, OsXml};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::io::Write;

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect(&p, out);
        } else if matches!(p.extension().and_then(|e| e.to_str()), Some("xml" | "conf" | "template")) {
            out.push(p);
        }
    }
}

/// Deterministic generator of XML-like fragments exercising comments, escapes,
/// attributes, variables, self-closing tags and malformed input.
fn fuzz_cases(n: usize) -> Vec<String> {
    let pieces = [
        "<a>", "</a>", "<b x=\"1\">", "</b>", "<c/>", "<d y='2' z=\"3\"/>", "text", " ", "\n", "<!-- c -->", "<! c !>",
        r"\<", r"\", "$V", "$W.", "$(x)", "<var name=\"V\">vv</var>", "<var name=\"W\">w,w</var>", "<var name='V'/>",
        "&lt;", "=", "\"", "'", "<", ">", "/", "<e a=b>", "<f a = \"q\" >", "<g a=\"1\" a=\"2\">", "<var x=\"1\">v</var>",
        "<!--", "-->", "$", "|", "<h>$V|$W</h>", "<i k=\"$V\">", "</i>", r"<j>a\<b</j>",
    ];
    let mut out = Vec::new();
    let mut x: u64 = 0x9e3779b97f4a7c15;
    for _ in 0..n {
        let mut s = String::new();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let len = (x % 12) as usize + 1;
        for _ in 0..len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.push_str(pieces[(x % pieces.len() as u64) as usize]);
        }
        out.push(s);
    }
    out
}

#[test]
fn matches_c_os_xml() {
    let Ok(harness) = std::env::var("SIEM_XML_ORACLE") else {
        eprintln!("SIEM_XML_ORACLE not set; skipping");
        return;
    };
    let mut failures = Vec::new();
    let mut total = 0;

    // 1. Files
    let mut files = Vec::new();
    if let Ok(c) = std::env::var("SIEM_XML_CORPUS") {
        collect(Path::new(&c), &mut files);
    }
    for chunk in files.chunks(200) {
        let out = Command::new(&harness).args(chunk).output().expect("run harness");
        // Windows text-mode stdout turns "\n" into "\r\n".
        let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
        let c_parts: Vec<&str> = text.split_inclusive("END\n").collect();
        assert_eq!(c_parts.len(), chunk.len(), "harness output count");
        for (f, c) in chunk.iter().zip(c_parts) {
            total += 1;
            let ours = dump(OsXml::read_file(f, false));
            if ours != c {
                failures.push(format!("file {}", f.display()));
                if failures.len() == 1 {
                    let (a, b): (Vec<_>, Vec<_>) = (ours.lines().collect(), c.lines().collect());
                    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                        if x != y {
                            eprintln!("first diff at line {i}:\n  rust: {x}\n  c:    {y}");
                            break;
                        }
                    }
                }
            }
        }
    }

    // 2. Fuzzed strings
    let n: usize = std::env::var("SIEM_XML_FUZZ").ok().and_then(|v| v.parse().ok()).unwrap_or(20000);
    let cases = fuzz_cases(n);
    let mut child = Command::new(&harness).arg("-s").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        let feed: String = cases.iter().map(|c| {
            let h: String = c.bytes().map(|b| format!("{b:02x}")).collect();
            h + "\n"
        }).collect();
        std::thread::spawn(move || {
            stdin.write_all(feed.as_bytes()).unwrap();
        });
    }
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    let c_parts: Vec<&str> = text.split_inclusive("END\n").collect();
    assert_eq!(c_parts.len(), cases.len());
    for (s, c) in cases.iter().zip(c_parts) {
        total += 1;
        let ours = dump(OsXml::read_string(s, false));
        if ours != c {
            if failures.len() < 10 {
                eprintln!("STRING {s:?}\n--- rust\n{ours}--- c\n{c}");
            }
            failures.push(format!("string {s:?}"));
        }
    }

    assert!(failures.is_empty(), "{} / {} cases differ from C os_xml; first: {:?}", failures.len(), total, &failures[..failures.len().min(10)]);
    eprintln!("{total} XML documents parse identically to C os_xml");
}

#[test]
fn writer_matches_c() {
    let Ok(harness) = std::env::var("SIEM_XML_ORACLE") else {
        eprintln!("SIEM_XML_ORACLE not set; skipping");
        return;
    };
    let mut files = Vec::new();
    if let Ok(c) = std::env::var("SIEM_XML_CORPUS") {
        collect(Path::new(&c), &mut files);
    }
    files.retain(|f| f.extension().and_then(|e| e.to_str()) != Some("xml") || f.to_string_lossy().contains("etc"));
    let tmp = std::env::temp_dir().join(format!("siem-xml-writer-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let paths: &[&[&str]] = &[
        &["ossec_config", "client", "server", "address"],
        &["ossec_config", "global", "email_notification"],
        &["ossec_config", "syscheck", "frequency"],
        &["ossec_config", "client", "enrollment", "enabled"],
        &["agent_config", "localfile", "location"],
        &["nonexistent"],
    ];
    let mut checked = 0;
    for f in files.iter().take(400) {
        for nodes in paths {
            for oldval in [Some("x"), None] {
                let c_out = tmp.join("c.out");
                let r_out = tmp.join("r.out");
                let _ = std::fs::remove_file(&c_out);
                let _ = std::fs::remove_file(&r_out);
                let mut cmd = Command::new(&harness);
                cmd.arg("-w").arg(f).arg(&c_out).arg(oldval.unwrap_or("~")).arg("NEW-VALUE");
                cmd.args(*nodes);
                let out = cmd.output().unwrap();
                let c_rc: i32 = String::from_utf8_lossy(&out.stdout).trim().trim_start_matches("W ").parse().unwrap();
                let r_rc = match siem_xml::write_xml(f, &r_out, nodes, oldval, "NEW-VALUE") {
                    Ok(()) => 0,
                    Err(e) => e as i32,
                };
                assert_eq!(r_rc, c_rc, "rc for {} {:?} {:?}", f.display(), nodes, oldval);
                if c_rc == 0 {
                    let a = std::fs::read(&c_out).unwrap();
                    let b = std::fs::read(&r_out).unwrap();
                    assert!(a == b, "output differs for {} {:?} {:?}", f.display(), nodes, oldval);
                }
                checked += 1;
            }
        }
    }
    eprintln!("{checked} OS_WriteXML cases match C");
}
