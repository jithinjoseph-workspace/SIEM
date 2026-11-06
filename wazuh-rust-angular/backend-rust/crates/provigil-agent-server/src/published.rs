//! The published agent package: which files, where they are, the agent's version.

use std::path::{Path, PathBuf};

/// The files of the Windows agent package (`/downloads/windows/<file>`).
pub const WINDOWS_AGENT_FILES: &[&str] = &[
    "provigil-agent.exe",
    "netsh.exe",
    "restart-agent.exe",
    "route-null.exe",
    "kill-process.exe",
    "quarantine-file.exe",
    "isolate-host.exe",
    "yara-scan.exe",
    "live-response.exe",
    "tamper-protect.exe",
];

pub const AGENT_EXE: &str = "provigil-agent.exe";

/// Where a build puts the package's programs.
const BUILD_OUTPUTS: [&str; 6] = ["target/x86_64-pc-windows-gnu/release", "target/release", "backend-rust/target/release", "backend-rust/target/x86_64-pc-windows-gnu/release", "target/debug", "backend-rust/target/debug"];

fn modified(p: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).ok().filter(|m| m.is_file()).and_then(|m| m.modified().ok())
}

/// A file of the package: `<dist>/windows/<name>`, or for a program the build output when newer.
pub fn windows_agent_file(dist: &Path, name: &str) -> Option<PathBuf> {
    if !WINDOWS_AGENT_FILES.contains(&name) {
        return None;
    }
    let mut cands = vec![dist.join("windows").join(name)];
    if name.ends_with(".exe") {
        cands.extend(BUILD_OUTPUTS.iter().map(|o| PathBuf::from(o).join(name)));
    }
    cands.into_iter().filter_map(|p| modified(&p).map(|t| (t, p))).max_by_key(|(t, _)| *t).map(|(_, p)| p)
}

/// The version the agent build writes into its exe (`provigil-agent-version:<x.y.z>`).
pub fn exe_version(exe: &[u8]) -> Option<String> {
    const MARK: &[u8] = b"provigil-agent-version:";
    let at = exe.windows(MARK.len()).position(|w| w == MARK)? + MARK.len();
    let v: String = exe[at..].iter().take(32).take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')).map(|&b| b as char).collect();
    (!v.is_empty()).then_some(v)
}

/// The published agent's version (read again only when the file changes).
pub fn published_version(dist: &Path) -> Option<String> {
    static CACHE: std::sync::Mutex<Option<(PathBuf, Option<std::time::SystemTime>, String)>> = std::sync::Mutex::new(None);
    let path = windows_agent_file(dist, AGENT_EXE)?;
    let mtime = modified(&path);
    if let Some((p, t, v)) = CACHE.lock().unwrap().as_ref() {
        if *p == path && *t == mtime {
            return Some(v.clone());
        }
    }
    let v = exe_version(&std::fs::read(&path).ok()?)?;
    *CACHE.lock().unwrap() = Some((path, mtime, v.clone()));
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_package_files() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("windows")).unwrap();
        std::fs::write(d.path().join("windows").join("yara-scan.exe"), b"x").unwrap();
        assert!(windows_agent_file(d.path(), "yara-scan.exe").is_some());
        assert!(windows_agent_file(d.path(), "..\\secret.txt").is_none());
        assert_eq!(exe_version(b"MZ provigil-agent-version:9.9.9 x").as_deref(), Some("9.9.9"));
        assert_eq!(exe_version(b"MZ"), None);
    }
}
