//! Live response (EDR, not in Wazuh): what `live-response` sends back for one request.
//! The result travels as active-responses.log lines, the agent's own encrypted channel
//! to the manager (so an isolated host still answers): the payload gzip-compressed and
//! base64-encoded in chunks of [`CHUNK`] characters, one line each, then one "done" line
//! with the chunk count and the SHA-256 of the compressed payload. siem-api
//! (live_response.rs) puts the chunks back together.

use std::io::Write;
use std::path::Path;

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::edr::json_str;

pub const SCRIPT: &str = "live-response";
/// base64 characters per line: well under the agent's 64 KB line limit (OS_MAXSTR)
pub const CHUNK: usize = 32 * 1024;
/// largest file collected
pub const MAX_FILE: u64 = 25 * 1024 * 1024;
/// entries listed per folder
pub const MAX_DIR_ENTRIES: usize = 5000;

/// A request id: the manager's 32 hex characters.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The log lines that carry `payload`: the chunks, then the "done" line. `extra` holds
/// more members for the "done" line, each starting with a comma.
pub fn result_lines(id: &str, kind: &str, payload: &[u8], extra: &str) -> Vec<String> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = gz.write_all(payload);
    let gz = gz.finish().unwrap_or_default();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&gz);
    // base64 is ASCII: byte slices are character slices
    let mut lines: Vec<String> = b64
        .as_bytes()
        .chunks(CHUNK)
        .enumerate()
        .map(|(seq, c)| format!("{{\"script\":\"{SCRIPT}\",\"id\":\"{id}\",\"kind\":{},\"seq\":{seq},\"data\":\"{}\"}}", json_str(kind), String::from_utf8_lossy(c)))
        .collect();
    lines.push(format!(
        "{{\"script\":\"{SCRIPT}\",\"id\":\"{id}\",\"kind\":{},\"status\":\"done\",\"chunks\":{},\"bytes\":{},\"sha256\":\"{}\"{extra}}}",
        json_str(kind),
        lines.len(),
        payload.len(),
        hex(&Sha256::digest(&gz))
    ));
    lines
}

/// The line reporting why the request could not be answered.
pub fn failed_line(id: &str, kind: &str, message: &str) -> String {
    format!("{{\"script\":\"{SCRIPT}\",\"id\":\"{id}\",\"kind\":{},\"status\":\"failed\",\"message\":{}}}", json_str(kind), json_str(message))
}

/// Why `path` is not a usable full Windows path; None when it is.
pub fn path_refusal(path: &str) -> Option<String> {
    let p = path.trim().replace('/', "\\");
    let b = p.as_bytes();
    if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
        return Some("a full path (C:\\...) is required".into());
    }
    if p.split('\\').any(|c| c == ".." || c == ".") {
        return Some("the path has relative parts".into());
    }
    None
}

/// A folder's entries as JSON (folders first, then by name; at most [`MAX_DIR_ENTRIES`]):
/// `{"path":..,"entries":[{"name","dir","size","modified"}],"truncated":bool}`.
pub fn dir_listing(dir: &Path) -> Result<Vec<u8>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut entries: Vec<(bool, String, u64, i64)> = Vec::new();
    let mut truncated = false;
    for e in rd.flatten() {
        if entries.len() >= MAX_DIR_ENTRIES {
            truncated = true;
            break;
        }
        // a link is listed as itself, never followed
        let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
        let modified = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64);
        entries.push((m.is_dir(), e.file_name().to_string_lossy().into_owned(), if m.is_dir() { 0 } else { m.len() }, modified));
    }
    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase())));
    let items: Vec<String> = entries
        .iter()
        .map(|(d, n, s, m)| format!("{{\"name\":{},\"dir\":{d},\"size\":{s},\"modified\":{m}}}", json_str(n)))
        .collect();
    Ok(format!("{{\"path\":{},\"entries\":[{}],\"truncated\":{truncated}}}", json_str(&dir.to_string_lossy()), items.join(",")).into_bytes())
}

/// A file's bytes and SHA-256 (regular files up to [`MAX_FILE`]).
pub fn read_file(path: &Path) -> Result<(Vec<u8>, String), String> {
    let m = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    if m.len() > MAX_FILE {
        return Err(format!("{} is {} bytes: files up to {} MB are collected", path.display(), m.len(), MAX_FILE / 1024 / 1024));
    }
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let sha = hex(&Sha256::digest(&data));
    Ok((data, sha))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn chunks_put_back_together() {
        let payload: Vec<u8> = (0..200_000u32).flat_map(|i| (i * 2654435761).to_le_bytes()).collect();
        let lines = result_lines("ab12", "file", &payload, ",\"path\":\"C:\\\\x\"");
        assert!(lines.len() > 2 && lines.iter().all(|l| l.len() < CHUNK + 200), "short lines");
        let done = lines.last().unwrap();
        assert!(done.contains("\"status\":\"done\"") && done.contains(&format!("\"chunks\":{}", lines.len() - 1)) && done.contains("\"path\":\"C:\\\\x\""));
        let b64: String = lines[..lines.len() - 1].iter().map(|l| l.split("\"data\":\"").nth(1).unwrap().trim_end_matches("\"}").to_string()).collect();
        let gz = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        assert!(done.contains(&hex(&Sha256::digest(&gz))));
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&gz[..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
        assert!(failed_line("ab12", "dir", "no \"such\" folder").contains("\\\"such\\\""));
    }

    #[test]
    fn paths_and_listing() {
        assert!(path_refusal("C:\\Users\\a\\Downloads").is_none());
        assert!(path_refusal("Downloads").is_some());
        assert!(path_refusal("C:\\Users\\..\\Windows").is_some());
        assert!(valid_id("0123abcd") && !valid_id("x;y") && !valid_id(""));

        let dir = std::env::temp_dir().join(format!("live-resp-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("b.txt"), b"hello").unwrap();
        std::fs::write(dir.join("A.exe"), b"MZ").unwrap();
        let j = String::from_utf8(dir_listing(&dir).unwrap()).unwrap();
        let (sub, a, b) = (j.find("\"sub\"").unwrap(), j.find("\"A.exe\"").unwrap(), j.find("\"b.txt\"").unwrap());
        assert!(sub < a && a < b, "folders first, then by name: {j}");
        assert!(j.contains("\"size\":5") && j.contains("\"truncated\":false"));
        let (data, sha) = read_file(&dir.join("b.txt")).unwrap();
        assert_eq!((data.as_slice(), sha.as_str()), (&b"hello"[..], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"));
        assert!(read_file(&dir.join("sub")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
