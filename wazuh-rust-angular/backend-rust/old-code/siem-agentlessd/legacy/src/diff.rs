//! Agentless State Diff & Alert Generator (`src/agentlessd/agentlessd.c`)
//!
//! Tracks state changes for network devices and agentless hosts,
//! computes unified line diffs, and formats security change alerts.

use md5::{Digest, Md5};
use similar::{ChangeTag, TextDiff};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DIFF_NEW_FILE: &str = "new";
pub const DIFF_LAST_FILE: &str = "last";
pub const STR_MORE_CHANGES: &str = "More changes...";

/// Produces platform-safe directory name for host and script pair.
pub fn safe_host_script_dir(host: &str, script: &str) -> String {
    if cfg!(windows) {
        format!("{}_to_{}", host, script)
    } else {
        format!("{}->{}", host, script)
    }
}

/// Computes MD5 hash of a file.
pub fn md5_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Md5::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Evaluates if an agentless output file changed and generates unified diff matching `check_diff_file`.
pub fn check_diff_file<P: AsRef<Path>>(
    diff_dir: P,
    host: &str,
    script: &str,
) -> io::Result<Option<String>> {
    let host_dir = diff_dir.as_ref().join(safe_host_script_dir(host, script));
    fs::create_dir_all(&host_dir)?;

    let new_path = host_dir.join(DIFF_NEW_FILE);
    let last_path = host_dir.join(DIFF_LAST_FILE);

    if !new_path.exists() {
        return Ok(None);
    }

    if !last_path.exists() {
        fs::rename(&new_path, &last_path)?;
        return Ok(None);
    }

    let md5_new = md5_file(&new_path)?;
    let md5_last = md5_file(&last_path)?;

    if md5_new == md5_last {
        let _ = fs::remove_file(&new_path);
        return Ok(None);
    }

    // Changed: archive old last state
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let state_path = host_dir.join(format!("state.{}", now));
    fs::rename(&last_path, &state_path)?;
    fs::rename(&new_path, &last_path)?;

    // Compute diff
    let old_text = fs::read_to_string(&state_path).unwrap_or_default();
    let new_text = fs::read_to_string(&last_path).unwrap_or_default();

    let diff = TextDiff::from_lines(&old_text, &new_text);
    let mut diff_output = String::new();

    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        diff_output.push_str(sign);
        diff_output.push_str(change.value());
    }

    let diff_file_path = host_dir.join(format!("diff.{}", now));
    fs::write(&diff_file_path, &diff_output)?;

    // Format alert
    let mut alert_content = diff_output;
    if alert_content.len() > 4096 {
        alert_content.truncate(4096);
        alert_content.push_str(STR_MORE_CHANGES);
    }

    let alert_msg = format!("ossec: agentless: Change detected:\n{}", alert_content);
    Ok(Some(alert_msg))
}

/// Helper to prepare `new` diff file for streaming execution output matching `open_diff_file`.
pub fn open_diff_file<P: AsRef<Path>>(
    diff_dir: P,
    host: &str,
    script: &str,
) -> io::Result<(PathBuf, File)> {
    let host_dir = diff_dir.as_ref().join(safe_host_script_dir(host, script));
    fs::create_dir_all(&host_dir)?;

    let new_path = host_dir.join(DIFF_NEW_FILE);
    let file = File::create(&new_path)?;
    Ok((new_path, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_diff_lifecycle() {
        let dir = tempdir().unwrap();
        let host = "router-cisco-1";
        let script = "ssh_pixconfig_diff";

        // First run: establishes baseline
        let (_, mut f1) = open_diff_file(dir.path(), host, script).unwrap();
        writeln!(f1, "hostname router-cisco-1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0").unwrap();
        drop(f1);

        let res1 = check_diff_file(dir.path(), host, script).unwrap();
        assert!(res1.is_none()); // Baseline stored

        // Second run with identical content: no diff
        let (_, mut f2) = open_diff_file(dir.path(), host, script).unwrap();
        writeln!(f2, "hostname router-cisco-1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0").unwrap();
        drop(f2);

        let res2 = check_diff_file(dir.path(), host, script).unwrap();
        assert!(res2.is_none());

        // Third run with modification: diff detected!
        let (_, mut f3) = open_diff_file(dir.path(), host, script).unwrap();
        writeln!(f3, "hostname router-cisco-1\ninterface GigabitEthernet0/0\n ip address 10.0.0.254 255.255.255.0\n shutdown").unwrap();
        drop(f3);

        let res3 = check_diff_file(dir.path(), host, script).unwrap();
        assert!(res3.is_some());
        let alert = res3.unwrap();
        assert!(alert.contains("Change detected:"));
        assert!(alert.contains("+ shutdown"));
    }
}
