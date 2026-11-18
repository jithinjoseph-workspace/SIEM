use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::info;

pub const DIR: &str = "upgrade";
const RESULT_FILE: &str = "upgrade_result.json";
const HELPER_FILE: &str = "upgrade.sh";
const AGENT_BIN: &str = "siem-agent-linux";
const MAX_BYTES: u64 = 200 * 1024 * 1024;
pub const DOWNLOAD_LIMIT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpgradeResult {
    pub status: String,
    pub version: String,
    #[serde(default)]
    pub from_version: String,
    pub timestamp: String,
    #[serde(default)]
    pub command_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub struct UpgradeSupervisor {
    dir: PathBuf,
    busy: AtomicBool,
}

impl Default for UpgradeSupervisor {
    fn default() -> Self {
        let candidate = Path::new("/opt/provigil-agent/upgrade");
        let dir = if candidate.parent().map(|p| p.exists()).unwrap_or(false) {
            candidate.to_path_buf()
        } else {
            PathBuf::from("data").join("upgrade")
        };
        Self {
            dir,
            busy: AtomicBool::new(false),
        }
    }
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

pub fn linux_helper_script(files: &[(PathBuf, PathBuf)], result: &Path, r: &UpgradeResult, pid: u32) -> String {
    let mut pairs = String::new();
    for (target, new) in files {
        pairs.push_str(&format!("    swap_one {} {}\n", sh_quote(&target.display().to_string()), sh_quote(&new.display().to_string())));
    }
    let mut restore = String::new();
    for (target, _) in files {
        restore.push_str(&format!("    restore_one {}\n", sh_quote(&target.display().to_string())));
    }
    format!(
        r#"#!/bin/sh
# ProVigil Linux agent upgrade {from} -> {version}
set -u
SVC='provigil-agent'
RESULT={result}

write_result() {{
    st="$1"
    why="$2"
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
    if [ -n "$why" ]; then
        esc=$(printf '%s' "$why" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ')
        reason_json="\"$esc\""
    else
        reason_json="null"
    fi
    printf '{{"status":"%s","version":"{ver_j}","from_version":"{from_j}","command_id":"{id_j}","timestamp":"%s","reason":%s}}\n' "$st" "$ts" "$reason_json" > "$RESULT"
}}

restore_one() {{
    t="$1"
    if [ -e "${{t}}.bak" ]; then
        mv -f "${{t}}.bak" "$t" 2>/dev/null || true
    elif [ -e "$t" ]; then
        rm -f "$t" 2>/dev/null || true
    fi
}}

restore_all() {{
{restore}}}

swap_one() {{
    t="$1"
    n="$2"
    parent=$(dirname "$t")
    mkdir -p "$parent" 2>/dev/null || true
    rm -f "${{t}}.bak" 2>/dev/null || true
    if [ -e "$t" ]; then
        mv -f "$t" "${{t}}.bak" || return 1
    fi
    chmod 0755 "$n" 2>/dev/null || true
    mv -f "$n" "$t" || return 1
    chmod 0755 "$t" 2>/dev/null || true
}}

# 1. Wait for parent agent PID {pid} to exit cleanly
i=0
while [ "$i" -lt 300 ] && kill -0 {pid} 2>/dev/null; do
    sleep 1
    i=$((i + 1))
done

# 2. Swap binary files
if ! (
{pairs}
); then
    restore_all
    write_result 'failed' 'Failed to swap agent binaries'
    systemctl restart "$SVC" 2>/dev/null || true
    exit 1
fi

# 3. Start updated agent service
if ! systemctl restart "$SVC" 2>/dev/null; then
    restore_all
    write_result 'rolled_back' 'Failed to restart agent service with new binary'
    systemctl restart "$SVC" 2>/dev/null || true
    exit 1
fi

# 4. Verify running health
sleep 5
if ! systemctl is-active --quiet "$SVC" 2>/dev/null; then
    restore_all
    write_result 'rolled_back' 'New agent binary failed health check after restart'
    systemctl restart "$SVC" 2>/dev/null || true
    exit 1
fi

write_result 'done' ''
exit 0
"#,
        from = r.from_version,
        version = r.version,
        result = sh_quote(&result.display().to_string()),
        ver_j = r.version,
        from_j = r.from_version,
        id_j = r.command_id,
        restore = restore,
        pairs = pairs,
        pid = pid,
    )
}

impl UpgradeSupervisor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check and return any prior upgrade result from a previous supervisor execution
    pub fn check_prior_result(&self) -> Option<UpgradeResult> {
        let result_path = self.dir.join(RESULT_FILE);
        if result_path.exists() {
            if let Ok(content) = fs::read_to_string(&result_path) {
                if let Ok(r) = serde_json::from_str::<UpgradeResult>(&content) {
                    let _ = fs::remove_file(&result_path);
                    return Some(r);
                }
            }
            let _ = fs::remove_file(&result_path);
        }
        None
    }

    /// Execute upgrade workflow: download release binary, verify SHA-256, write helper script, and launch detached
    pub async fn execute_upgrade(&self, cmd: &Value, current_version: &str) -> Result<String, String> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err("An upgrade is already in progress".into());
        }

        let target_version = cmd["version"].as_str().unwrap_or("unknown").trim();
        let command_id = cmd["command_id"].as_str().unwrap_or("").to_string();

        info!("provigil-upgrade: Initiating in-band upgrade to version '{}'", target_version);

        let target_dir = self.dir.join(target_version);
        fs::create_dir_all(&target_dir).map_err(|e| format!("Failed to create upgrade dir: {e}"))?;

        let url = cmd["url"].as_str().or_else(|| {
            cmd["files"].as_array().and_then(|a| a.first()).and_then(|f| f["url"].as_str())
        }).unwrap_or("").trim();

        let sha256 = cmd["sha256"].as_str().or_else(|| {
            cmd["files"].as_array().and_then(|a| a.first()).and_then(|f| f["sha256"].as_str())
        }).unwrap_or("").trim();

        if url.is_empty() {
            self.busy.store(false, Ordering::SeqCst);
            return Err("Upgrade URL is missing".into());
        }

        let downloaded_file = target_dir.join(AGENT_BIN);
        self.download_and_verify(url, sha256, &downloaded_file).await?;

        let current_bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/opt/provigil-agent/bin/siem-agent-linux"));
        let pairs = vec![(current_bin, downloaded_file)];

        let result_file = self.dir.join(RESULT_FILE);
        let upgrade_result = UpgradeResult {
            status: "pending".into(),
            version: target_version.to_string(),
            from_version: current_version.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            command_id,
            reason: None,
        };

        let helper_script = linux_helper_script(&pairs, &result_file, &upgrade_result, std::process::id());
        let helper_path = target_dir.join(HELPER_FILE);
        fs::write(&helper_path, helper_script).map_err(|e| format!("Failed to write helper: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o750));
        }

        info!("provigil-upgrade: Spawning detached helper '{}' to complete upgrade.", helper_path.display());

        #[cfg(unix)]
        {
            let _ = std::process::Command::new("/bin/sh")
                .arg(&helper_path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }

        Ok(format!("Upgrade to {} scheduled; agent will restart via supervisor", target_version))
    }

    async fn download_and_verify(&self, url: &str, expected_sha256: &str, dest: &Path) -> Result<(), String> {
        let client = crate::enroll::http_builder().timeout(DOWNLOAD_LIMIT).build().map_err(|e| e.to_string())?;
        let res = client.get(url).send().await.map_err(|e| format!("Download error: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("Download failed with HTTP {}", res.status()));
        }

        let mut file = tokio::fs::File::create(dest).await.map_err(|e| format!("{}: {e}", dest.display()))?;
        let mut hasher = Sha256::new();
        let mut stream = res;

        let mut total = 0u64;
        while let Some(chunk) = stream.chunk().await.map_err(|e| e.to_string())? {
            total += chunk.len() as u64;
            if total > MAX_BYTES {
                return Err("Download exceeds 200 MB limit".into());
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        file.flush().await.map_err(|e| e.to_string())?;
        drop(file);

        let calculated_hash = format!("{:x}", hasher.finalize());
        if !expected_sha256.is_empty() && !calculated_hash.eq_ignore_ascii_case(expected_sha256) {
            let _ = fs::remove_file(dest);
            return Err(format!("SHA-256 mismatch! Expected {}, got {}", expected_sha256, calculated_hash));
        }

        info!("provigil-upgrade: Download verified. SHA-256: {}", calculated_hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_helper_script_generation() {
        let pairs = vec![(
            PathBuf::from("/opt/provigil-agent/bin/siem-agent-linux"),
            PathBuf::from("/opt/provigil-agent/upgrade/2.0.0/siem-agent-linux"),
        )];
        let res_file = PathBuf::from("/opt/provigil-agent/upgrade/upgrade_result.json");
        let r = UpgradeResult {
            status: "pending".into(),
            version: "2.0.0".into(),
            from_version: "1.0.0".into(),
            timestamp: "2026-11-17T00:00:00Z".into(),
            command_id: "upg-42".into(),
            reason: None,
        };

        let script = linux_helper_script(&pairs, &res_file, &r, 1234);
        assert!(script.contains("ProVigil Linux agent upgrade 1.0.0 -> 2.0.0"));
        assert!(script.contains("swap_one '/opt/provigil-agent/bin/siem-agent-linux'"));
        assert!(script.contains("kill -0 1234"));
        assert!(script.contains("write_result 'done'"));
    }
}
