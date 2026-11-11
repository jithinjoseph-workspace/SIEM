//! EDR response (not in upstream): scans one file with the YARA rules the manager sends every
//! agent (`shared\siem-yara.yar`) and logs the outcome (match / clean / failed) with the
//! file's SHA-256 and the rule set's version, for the manager to alert on and cache.
//! extra_args: `path=<full path>`. Runs at below-normal priority; files over 64 MB are skipped.

use siem_active_response::{edr::*, yara, *};

fn main() {
    #[cfg(windows)]
    {
        // This must be always the first instruction
        dll_guard::enable();
        // a scan is background work: the user's programs come first
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS};
        unsafe { SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) };
    }
    std::process::exit(run_main());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn skip_reason(path: &std::path::Path) -> Option<String> {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !path.as_os_str().is_empty() => Some("the file no longer exists: not scanned".into()),
        Ok(m) if m.is_file() && m.len() > yara::MAX_FILE => Some(format!("larger than {} MB: not scanned", yara::MAX_FILE / 1024 / 1024)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn gone_or_big_files_are_skipped_not_failed() {
        let dir = std::env::temp_dir().join(format!("pv-yara-skip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(super::skip_reason(&dir.join("gone.exe")).unwrap().contains("no longer exists"));
        let small = dir.join("small.bin");
        std::fs::write(&small, b"x").unwrap();
        assert_eq!(super::skip_reason(&small), None);
        assert_eq!(super::skip_reason(std::path::Path::new("")), None, "an empty path stays an error");
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn run_main() -> i32 {
    use sha2::{Digest, Sha256};

    let argv0 = argv0();
    let Some((action, input)) = setup_and_check_message(&argv0) else { return -1 };
    if action != Action::Add {
        write_debug_file(&argv0, b"Ended");
        return 0;
    }
    let path = extra_arg(&input, "path").map(|p| p.trim().to_string()).unwrap_or_default();
    // nothing to scan is not a failure: a file already gone (temporary files) or over the size limit
    if let Some(why) = skip_reason(std::path::Path::new(&path)) {
        let m = format!("{{\"message\":{},\"path\":{},\"status\":\"skipped\",\"script\":\"yara-scan\"}}", json_str(&why), json_str(&path));
        write_debug_file(&argv0, m.as_bytes());
        write_debug_file(&argv0, b"Ended");
        return 0;
    }
    let r = (|| -> Result<(String, String, Vec<String>), String> {
        if path.is_empty() {
            return Err("A file (path=<full path>) is required".into());
        }
        let stored = std::fs::read_to_string(yara::RULES_FILE).map_err(|e| format!("no YARA rules from the manager yet ({}: {e})", yara::RULES_FILE))?;
        // decoded in memory only: the plain rules never touch the endpoint's disk
        let rules = yara::decode_rules(&stored)?;
        let version = hex(&Sha256::digest(rules.as_bytes())[..8]);
        let scanner = yara::compile(&rules).map_err(|e| format!("the YARA rules do not compile: {e}"))?;
        let file = std::path::Path::new(&path);
        let matched = yara::scan_file(&scanner, file)?;
        let sha = std::fs::read(file).map(|d| hex(&Sha256::digest(&d))).unwrap_or_default();
        Ok((version, sha, matched))
    })();
    let m = match &r {
        Ok((version, sha, matched)) => {
            let rules = matched.iter().map(|n| json_str(n)).collect::<Vec<_>>().join(",");
            let (status, what) = if matched.is_empty() { ("clean", "YARA scan: no rule matched") } else { ("match", "YARA rule matched") };
            format!("{{\"message\":\"{what}\",\"path\":{},\"sha256\":\"{sha}\",\"rules\":[{rules}],\"rules_version\":\"{version}\",\"status\":\"{status}\",\"script\":\"yara-scan\"}}", json_str(&path))
        }
        Err(e) => format!("{{\"message\":{},\"path\":{},\"status\":\"failed\",\"script\":\"yara-scan\"}}", json_str(e), json_str(&path)),
    };
    write_debug_file(&argv0, m.as_bytes());
    write_debug_file(&argv0, b"Ended");
    if r.is_ok() { 0 } else { -1 }
}
