//! EDR response (not in Wazuh): moves a file into the agent's `quarantine\`
//! folder (renamed `<id>.bin`, so it cannot be run by a double click) with a
//! `<id>.json` record of where it came from and its SHA-256, or puts it back.
//! extra_args: `path=<full path>`, or `restore=<id>`. Windows files and the
//! agent's own are never moved (`edr::quarantine_refusal`).

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

#[cfg(windows)]
use siem_active_response::{edr::*, *};

#[cfg(windows)]
const QUARANTINE_DIR: &str = "quarantine";

fn main() {
    #[cfg(windows)]
    std::process::exit(win_main());
    #[cfg(not(windows))]
    std::process::exit(-1);
}

#[cfg(windows)]
fn win_main() -> i32 {
    // This must be always the first instruction
    dll_verify::enable_dll_verification(&std::sync::Arc::new(siem_log::WLog::new("unset", std::path::Path::new("."))));
    let argv0 = argv0();
    let Some((action, input)) = setup_and_check_message(&argv0) else { return -1 };
    if action != Action::Add {
        write_debug_file(&argv0, b"Ended");
        return 0;
    }
    let r = match extra_arg(&input, "restore") {
        Some(id) => restore(&id).map(|p| ("File restored", format!("\"id\":{},\"path\":{}", json_str(&id), json_str(&p)))),
        None => quarantine(&input).map(|m| ("File quarantined", m)),
    };
    let m = match &r {
        Ok((what, m)) => format!("{{\"message\":\"{what}\",{m},\"status\":\"success\",\"script\":\"quarantine-file\"}}"),
        Err(e) => format!("{{\"message\":{},\"status\":\"failed\",\"script\":\"quarantine-file\"}}", json_str(e)),
    };
    write_debug_file(&argv0, m.as_bytes());
    write_debug_file(&argv0, b"Ended");
    if r.is_ok() { 0 } else { -1 }
}

/// A move, else a copy and delete (the quarantine folder may be on another volume).
#[cfg(windows)]
fn move_file(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to)?;
    std::fs::remove_file(from).inspect_err(|_| {
        let _ = std::fs::remove_file(to);
    })
}

#[cfg(windows)]
fn quarantine(input: &siem_cjson::Json) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    let path = extra_arg(input, "path").map(|p| p.trim().to_string()).ok_or("A file (path=<full path>) is required")?;
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let home = std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default();
    if let Some(why) = quarantine_refusal(&path, &root, &home) {
        return Err(format!("{path} not quarantined: {why}"));
    }
    let src = std::path::Path::new(&path);
    let meta = std::fs::metadata(src).map_err(|e| format!("{path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} is not a file"));
    }
    let data = std::fs::read(src).map_err(|e| format!("{path} cannot be read (in use? kill its process first): {e}"))?;
    let sha256: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    drop(data);
    std::fs::create_dir_all(QUARANTINE_DIR).map_err(|e| format!("{QUARANTINE_DIR}: {e}"))?;
    let id = format!("{}-{}", chrono::Local::now().format("%Y%m%d%H%M%S%3f"), std::process::id());
    let dst = std::path::Path::new(QUARANTINE_DIR).join(format!("{id}.bin"));
    move_file(src, &dst).map_err(|e| format!("{path} cannot be moved (in use? kill its process first): {e}"))?;
    let at = chrono::Local::now().to_rfc3339();
    let record = quarantine_record(&id, &path, &sha256, meta.len(), &at);
    if let Err(e) = std::fs::write(std::path::Path::new(QUARANTINE_DIR).join(format!("{id}.json")), &record) {
        // without its record the file could not be put back: undo
        let _ = move_file(&dst, src);
        return Err(format!("{path} not quarantined: the record cannot be written: {e}"));
    }
    Ok(format!("\"id\":{},\"path\":{},\"sha256\":{},\"size\":{}", json_str(&id), json_str(&path), json_str(&sha256), meta.len()))
}

/// Puts a quarantined file back where it was; its original path.
#[cfg(windows)]
fn restore(id: &str) -> Result<String, String> {
    if !valid_quarantine_id(id) {
        return Err(format!("Invalid quarantine id {id}"));
    }
    let rec_path = std::path::Path::new(QUARANTINE_DIR).join(format!("{id}.json"));
    let rec = std::fs::read(&rec_path).map_err(|_| format!("No quarantined file {id}"))?;
    let (j, _) = siem_cjson::parse_with_opts(&rec, false).map_err(|_| format!("The record of {id} is damaged"))?;
    let path = j.get("path").and_then(|p| p.as_str()).map(|p| p.to_string()).ok_or(format!("The record of {id} has no path"))?;
    let dst = std::path::Path::new(&path);
    if dst.exists() {
        return Err(format!("{path} exists again; not overwritten"));
    }
    move_file(&std::path::Path::new(QUARANTINE_DIR).join(format!("{id}.bin")), dst).map_err(|e| format!("{path} cannot be restored: {e}"))?;
    let _ = std::fs::remove_file(&rec_path);
    Ok(path)
}
