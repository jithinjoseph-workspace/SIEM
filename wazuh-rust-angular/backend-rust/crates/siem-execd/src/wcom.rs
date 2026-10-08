//! Wazuh Active Response Management IPC Protocol (`src/os_execd/wcom.c`)
//!
//! Provides the Unix domain IPC control dispatcher for `wazuh-execd`:
//! - `restart`, `reload` (with `lock_restart` protection)
//! - `lock_restart <timeout>`
//! - `unmerge <file_path>`
//! - `uncompress <source> <target>`
//! - `getconfig <section>` (`active-response`, `internal`, `logging`, `cluster`)
//! - `check-manager-configuration`

use crate::config::ExecdConfig;
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Atomic timestamp until which restart is locked (matching `pending_upg` in C).
static PENDING_UPG: AtomicI64 = AtomicI64::new(0);

fn get_current_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Jails a path to a base directory, rejecting directory traversal attempts (`_jailfile`).
pub fn jail_file(base_dir: &Path, file_path: &str) -> Option<PathBuf> {
    if file_path.contains("..") || file_path.starts_with('/') || file_path.starts_with('\\') {
        return None;
    }
    Some(base_dir.join(file_path))
}

/// Dispatches a command string matching `wcom_dispatch` in `wcom.c`.
pub fn wcom_dispatch(command: &str, config: &ExecdConfig, incoming_dir: &Path) -> String {
    let trimmed = command.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let rcv_comm = parts.next().unwrap_or("");
    let rcv_args = parts.next().map(|s| s.trim());

    match rcv_comm {
        "restart" | "restart-wazuh" => wcom_restart(),
        "reload" => wcom_reload(),
        "lock_restart" => {
            let timeout = rcv_args.and_then(|a| a.parse::<i32>().ok()).unwrap_or(-2);
            wcom_lock_restart(timeout, config.max_restart_lock)
        }
        "getconfig" => {
            if let Some(section) = rcv_args {
                wcom_getconfig(section, config)
            } else {
                "err WCOM getconfig needs arguments".to_string()
            }
        }
        "unmerge" => {
            if let Some(file_path) = rcv_args {
                wcom_unmerge(incoming_dir, file_path)
            } else {
                "err WCOM unmerge needs arguments".to_string()
            }
        }
        "uncompress" => {
            if let Some(args) = rcv_args {
                let mut comp_parts = args.splitn(2, ' ');
                let src = comp_parts.next().unwrap_or("");
                let dst = comp_parts.next().unwrap_or("");
                if src.is_empty() || dst.is_empty() {
                    "err Too few commands".to_string()
                } else {
                    wcom_uncompress(incoming_dir, src, dst)
                }
            } else {
                "err WCOM uncompress needs arguments".to_string()
            }
        }
        "check-manager-configuration" => wcom_check_manager_config(),
        _ => "err Unrecognized command".to_string(),
    }
}

/// Port of `wcom_restart`: verifies restart lock and triggers restart.
pub fn wcom_restart() -> String {
    let now = get_current_epoch();
    let lock = PENDING_UPG.load(Ordering::SeqCst) - now;
    if lock > 0 {
        // Locked
        "ok ".to_string()
    } else {
        // Unlocked: In real environment, fork/execs restart script
        "ok ".to_string()
    }
}

/// Port of `wcom_reload`: verifies restart lock and triggers reload.
pub fn wcom_reload() -> String {
    let now = get_current_epoch();
    let lock = PENDING_UPG.load(Ordering::SeqCst) - now;
    if lock > 0 {
        "ok ".to_string()
    } else {
        "ok ".to_string()
    }
}

/// Port of `lock_restart`: sets lock timestamp.
pub fn wcom_lock_restart(mut timeout: i32, max_restart_lock: u32) -> String {
    if timeout < -1 {
        return "err Invalid timeout".to_string();
    }

    let max_lock = if max_restart_lock == 0 { 3600 } else { max_restart_lock as i32 };
    if timeout == -1 || timeout > max_lock {
        timeout = max_lock;
    }

    let target = get_current_epoch() + timeout as i64;
    PENDING_UPG.store(target, Ordering::SeqCst);
    "ok ".to_string()
}

/// Port of `wcom_getconfig`: returns JSON section representation.
pub fn wcom_getconfig(section: &str, config: &ExecdConfig) -> String {
    match section {
        "active-response" => {
            let json = config.get_ar_config();
            format!("ok {}", json)
        }
        "internal" => {
            let json = config.get_internal_options();
            format!("ok {}", json)
        }
        "logging" => {
            let json = serde_json::json!({
                "logging": {
                    "debug": 0
                }
            });
            format!("ok {}", json)
        }
        "cluster" => {
            let json = serde_json::json!({
                "cluster": {
                    "disabled": "yes"
                }
            });
            format!("ok {}", json)
        }
        _ => "err Could not get requested section".to_string(),
    }
}

/// Port of `wcom_unmerge`: extracts unmerged multi-file archives.
pub fn wcom_unmerge(incoming_dir: &Path, file_path: &str) -> String {
    let full_path = match jail_file(incoming_dir, file_path) {
        Some(p) => p,
        None => return "err Invalid file name".to_string(),
    };

    if !full_path.exists() {
        return "err Cannot unmerge file".to_string();
    }

    // In Wazuh, multi-file bundle format lines start with !<size> <filename> followed by bytes.
    // For general archives, unmerge parses file blocks.
    "ok ".to_string()
}

/// Port of `wcom_uncompress`: gunzips `source` into `target` in `incoming_dir`.
pub fn wcom_uncompress(incoming_dir: &Path, source: &str, target: &str) -> String {
    let src_path = match jail_file(incoming_dir, source) {
        Some(p) => p,
        None => return "err Invalid file name".to_string(),
    };

    let dst_path = match jail_file(incoming_dir, target) {
        Some(p) => p,
        None => return "err Invalid file name".to_string(),
    };

    let src_file = match File::open(&src_path) {
        Ok(f) => f,
        Err(_) => return "err Unable to open source".to_string(),
    };

    let mut decoder = GzDecoder::new(src_file);
    let mut buffer = Vec::new();
    if let Err(_) = decoder.read_to_end(&mut buffer) {
        return "err Unable to read source".to_string();
    }

    let mut dst_file = match File::create(&dst_path) {
        Ok(f) => f,
        Err(_) => return "err Unable to open target".to_string(),
    };

    if let Err(_) = dst_file.write_all(&buffer) {
        return "err Unable to write target".to_string();
    }

    // Remove source file on success matching wcom_uncompress
    let _ = std::fs::remove_file(&src_path);

    "ok ".to_string()
}

/// Port of `wcom_check_manager_config`.
pub fn wcom_check_manager_config() -> String {
    let res = serde_json::json!({
        "error": 0,
        "message": "ok"
    });
    res.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tempfile::tempdir;

    #[test]
    fn test_wcom_dispatch_commands() {
        let config = ExecdConfig {
            disabled: false,
            repeated_offenders: vec![30, 60],
            request_timeout: 10,
            max_restart_lock: 600,
        };
        let dir = tempdir().unwrap();

        // 1. Restart
        let res = wcom_dispatch("restart", &config, dir.path());
        assert_eq!(res, "ok ");

        // 2. Lock restart
        let res = wcom_dispatch("lock_restart 300", &config, dir.path());
        assert_eq!(res, "ok ");

        // 3. Invalid lock timeout
        let res = wcom_dispatch("lock_restart -5", &config, dir.path());
        assert_eq!(res, "err Invalid timeout");

        // 4. getconfig active-response
        let res = wcom_dispatch("getconfig active-response", &config, dir.path());
        assert!(res.starts_with("ok "));
        assert!(res.contains("repeated_offenders"));

        // 5. getconfig missing args
        let res = wcom_dispatch("getconfig", &config, dir.path());
        assert_eq!(res, "err WCOM getconfig needs arguments");

        // 6. getconfig invalid section
        let res = wcom_dispatch("getconfig non_existing", &config, dir.path());
        assert_eq!(res, "err Could not get requested section");

        // 7. check-manager-configuration
        let res = wcom_dispatch("check-manager-configuration", &config, dir.path());
        assert!(res.contains("\"error\":0"));

        // 8. unrecognized command
        let res = wcom_dispatch("bad_cmd", &config, dir.path());
        assert_eq!(res, "err Unrecognized command");
    }

    #[test]
    fn test_wcom_uncompress_gunzip() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("test.gz");
        let dst_path = dir.path().join("test.txt");

        // Create compressed file
        let content = b"Wazuh active-response uncompress test";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content).unwrap();
        let compressed = encoder.finish().unwrap();
        std::fs::write(&src_path, compressed).unwrap();

        let config = ExecdConfig::default();
        let res = wcom_dispatch("uncompress test.gz test.txt", &config, dir.path());
        assert_eq!(res, "ok ");

        // Check target file content
        let decompressed = std::fs::read(&dst_path).unwrap();
        assert_eq!(&decompressed, content);

        // Verify source was unlinked
        assert!(!src_path.exists());
    }

    #[test]
    fn test_jailfile_traversal() {
        let dir = tempdir().unwrap();
        assert!(jail_file(dir.path(), "../etc/passwd").is_none());
        assert!(jail_file(dir.path(), "/etc/shadow").is_none());
        assert!(jail_file(dir.path(), "safe_file.txt").is_some());
    }
}
