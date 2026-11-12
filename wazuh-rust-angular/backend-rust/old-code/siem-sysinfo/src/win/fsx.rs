//! The `std::filesystem` (libstdc++, Windows) and `std::ifstream` behaviour
//! the package scanners rely on, and `Utils::expandAbsolutePath`.

use std::collections::VecDeque;
use std::path::Path;

use crate::strings;

/// `path / rhs` (libstdc++ on Windows: '\\' unless lhs is empty or ends
/// with a separator).
pub fn join(lhs: &str, rhs: &str) -> String {
    if lhs.is_empty() {
        return rhs.to_string();
    }
    if lhs.ends_with('\\') || lhs.ends_with('/') {
        format!("{lhs}{rhs}")
    } else {
        format!("{lhs}\\{rhs}")
    }
}

/// `std::filesystem::exists` (Err for errors other than "not found").
pub fn exists(p: &str) -> Result<bool, String> {
    if p.is_empty() {
        return Ok(false);
    }
    match std::fs::metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) if e.raw_os_error() == Some(3) => Ok(false), // ERROR_PATH_NOT_FOUND
        Err(e) if e.raw_os_error() == Some(123) => Ok(false), // ERROR_INVALID_NAME
        Err(e) => Err(e.to_string()),
    }
}

pub fn is_directory(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

pub fn is_regular_file(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// `directory_iterator(dir)`: the entries' full paths and file names, in
/// FindFirstFile order; Err when it cannot be opened or iterated.
pub fn dir_entries(dir: &str) -> Result<Vec<(String, String)>, String> {
    let rd = std::fs::read_dir(Path::new(dir)).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for e in rd {
        let e = e.map_err(|e| e.to_string())?;
        let name = e.file_name().to_string_lossy().into_owned();
        out.push((join(dir, &name), name));
    }
    Ok(out)
}

/// `Utils::expandAbsolutePath` (Err for the exceptions it lets out)
pub fn expand_absolute_path(path: &str, out: &mut VecDeque<String>) -> Result<(), String> {
    let wildcard = path.find(['*', '?']);
    let Some(wp) = wildcard else {
        out.push_back(path.to_string());
        return Ok(());
    };
    let parent = path[..=wp].rfind('\\');
    let next = if wp == 0 { Some(0) } else { path[wp..].find('\\').map(|p| p + wp) };
    let Some(parent) = parent else {
        return Err(format!("Invalid path: {path}"));
    };
    let base_dir = if wp == 0 { String::new() } else { path[..parent].to_string() };
    let pstart = if parent == 0 { 0 } else { parent + 1 };
    let pattern = match next {
        None => &path[pstart..],
        Some(n) => &path[pstart..n.max(pstart)],
    };
    if exists(&base_dir)? {
        for (_, name) in dir_entries(&base_dir)? {
            if strings::pattern_match(&name, pattern) {
                let mut next_path = base_dir.clone();
                next_path.push('\\');
                next_path.push_str(&name);
                if let Some(n) = next {
                    next_path.push_str(&path[n..]);
                }
                expand_absolute_path(&next_path, out)?;
            }
        }
    }
    Ok(())
}

/// The contents of a file read through a text-mode `std::ifstream` (CR LF
/// read as LF, Ctrl-Z ends the file); None when it cannot be opened.
pub fn read_text(p: &str) -> Option<Vec<u8>> {
    if p.is_empty() {
        return None;
    }
    let raw = std::fs::read(p).ok()?;
    let end = raw.iter().position(|&c| c == 0x1A).unwrap_or(raw.len());
    let mut out = Vec::with_capacity(end);
    let mut i = 0;
    while i < end {
        if raw[i] == b'\r' && i + 1 < end && raw[i + 1] == b'\n' {
            i += 1;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
    Some(out)
}

/// `std::getline` over text: the lines (no trailing empty line).
pub fn lines(text: &[u8]) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = text.split(|&c| c == b'\n').collect();
    if v.last().is_some_and(|l| l.is_empty()) {
        v.pop();
    }
    v
}
