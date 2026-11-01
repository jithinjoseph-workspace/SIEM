//! YARA scanning of one file (EDR, not in Wazuh), with the rules the manager sends every
//! agent (`shared/siem-yara.rules`: YARA Forge core and the SIEM's test rule). Used by the
//! `yara-scan` program on the agent and by the manager to check a rule set before sending it.
//!
//! The rules travel and rest compressed and base64-encoded (`encode_rules`): as plain text
//! their malware strings are malware signatures to antivirus, and Windows Defender removed
//! the manager's `merged.mg` (which also carries every agent's agent.conf) when it held them.

use std::io::{Read, Write};

use base64::Engine;

/// Where the agent keeps the manager's rules (its shared folder, filled by remoted).
pub const RULES_FILE: &str = "shared/siem-yara.rules";
const MAGIC: &str = "SIEM-YARA-RULES-1\n";

/// The rules as they are stored and sent: a header line, then deflate + base64.
pub fn encode_rules(text: &str) -> String {
    let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    let _ = z.write_all(text.as_bytes());
    let packed = z.finish().unwrap_or_default();
    let b64 = base64::engine::general_purpose::STANDARD.encode(packed);
    let mut out = String::with_capacity(MAGIC.len() + b64.len() + b64.len() / 76 + 1);
    out.push_str(MAGIC);
    for line in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out
}

/// The rules' text from `encode_rules`' form (at most 256 MB, against a hostile file).
pub fn decode_rules(stored: &str) -> Result<String, String> {
    // the Windows agent writes shared files with CRLF line ends
    let body = stored.strip_prefix(MAGIC.trim_end()).and_then(|r| r.strip_prefix("\r\n").or_else(|| r.strip_prefix('\n'))).ok_or("not a SIEM YARA rules file")?;
    let packed = base64::engine::general_purpose::STANDARD.decode(body.split_whitespace().collect::<String>()).map_err(|e| format!("rules file: {e}"))?;
    let mut text = String::new();
    flate2::read::DeflateDecoder::new(&packed[..]).take(256 * 1024 * 1024).read_to_string(&mut text).map_err(|e| format!("rules file: {e}"))?;
    Ok(text)
}
/// Larger files are not scanned (installers, disk images): memory and time stay bounded.
pub const MAX_FILE: u64 = 64 * 1024 * 1024;

/// A harmless rule that matches a file holding its marker, so the whole path (trigger,
/// scan, alert) can be tried on a real endpoint without any malware.
pub const TEST_RULE: &str = r#"
rule SIEM_EDR_YARA_Test_File
{
    meta:
        description = "Harmless test file for the SIEM's YARA scanning (not malware)"
        author = "SIEM"
    strings:
        $marker = "SIEM-EDR-YARA-TEST-FILE-7c1e5b2a"
    condition:
        $marker
}
"#;

/// The rules compiled; the error names the first problem.
pub fn compile(source: &str) -> Result<boreal::Scanner, String> {
    let mut c = boreal::Compiler::new();
    c.add_rules_str(source).map_err(|e| e.to_diagnostic().message)?;
    Ok(c.finalize())
}

/// The rules (`namespace:name` when namespaced) that match the file.
pub fn scan_file(scanner: &boreal::Scanner, path: &std::path::Path) -> Result<Vec<String>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    if meta.len() > MAX_FILE {
        return Err(format!("{} is larger than {} MB: not scanned", path.display(), MAX_FILE / 1024 / 1024));
    }
    let data = std::fs::read(path).map_err(|e| format!("{} cannot be read: {e}", path.display()))?;
    scan_bytes(scanner, &data)
}

pub fn scan_bytes(scanner: &boreal::Scanner, data: &[u8]) -> Result<Vec<String>, String> {
    // a scan error (a timeout) still returns what matched until then
    let r = match scanner.scan_mem(data) {
        Ok(r) => r,
        Err((e, r)) if !r.rules.is_empty() => {
            let _ = e;
            r
        }
        Err((e, _)) => return Err(format!("scan failed: {e:?}")),
    };
    let mut names: Vec<String> = r.rules.iter().map(|m| if m.namespace.is_empty() || m.namespace == "default" { m.name.to_string() } else { format!("{}:{}", m.namespace, m.name) }).collect();
    names.sort();
    names.dedup();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_matches_its_marker_only() {
        let s = compile(TEST_RULE).unwrap();
        assert_eq!(scan_bytes(&s, b"xx SIEM-EDR-YARA-TEST-FILE-7c1e5b2a xx").unwrap(), ["SIEM_EDR_YARA_Test_File"]);
        assert!(scan_bytes(&s, b"an ordinary file").unwrap().is_empty());
        assert!(compile("rule broken { condition: }").is_err(), "a broken rule set is refused");
    }

    #[test]
    fn rules_round_trip_encoded() {
        let text = format!("{TEST_RULE}\nrule x {{ strings: $a = \"import socket,subprocess,os\" condition: $a }}\n");
        let stored = encode_rules(&text);
        assert!(!stored.contains("socket"), "no rule text in the stored form");
        assert_eq!(decode_rules(&stored).unwrap(), text);
        assert_eq!(decode_rules(&stored.replace('\n', "\r\n")).unwrap(), text, "as the Windows agent stores it");
        assert!(decode_rules("rule plain { condition: true }").is_err());
        assert!(decode_rules(&format!("{MAGIC}!!!")).is_err());
    }

    #[test]
    fn files_too_large_or_missing_are_not_scanned() {
        let s = compile(TEST_RULE).unwrap();
        let dir = std::env::temp_dir().join(format!("siem-yara-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("t.bin");
        std::fs::write(&f, "SIEM-EDR-YARA-TEST-FILE-7c1e5b2a").unwrap();
        assert_eq!(scan_file(&s, &f).unwrap().len(), 1);
        assert!(scan_file(&s, &dir).is_err(), "a directory");
        assert!(scan_file(&s, &dir.join("missing")).is_err());
        let big = std::fs::File::create(dir.join("big.bin")).unwrap();
        big.set_len(MAX_FILE + 1).unwrap();
        assert!(scan_file(&s, &dir.join("big.bin")).unwrap_err().contains("larger"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
