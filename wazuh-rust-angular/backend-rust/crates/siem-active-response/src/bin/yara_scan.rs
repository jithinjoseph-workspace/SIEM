//! EDR response (not in Wazuh): scans one file with the YARA rules the manager sends every
//! agent (`shared\siem-yara.yar`) and logs the outcome (match / clean / failed) with the
//! file's SHA-256 and the rule set's version, for the manager to alert on and cache.
//! extra_args: `path=<full path>`. Runs at below-normal priority; files over 64 MB are skipped.

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

use siem_active_response::{edr::*, yara, *};

fn main() {
    #[cfg(windows)]
    {
        // This must be always the first instruction
        dll_verify::enable_dll_verification(&std::sync::Arc::new(siem_log::WLog::new("unset", std::path::Path::new("."))));
        // a scan is background work: the user's programs come first
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS};
        unsafe { SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) };
    }
    std::process::exit(run_main());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
