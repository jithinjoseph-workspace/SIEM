//! Remote upgrade: the manager's `upgrade` command (`{"command_id", "type": "upgrade", "version",
//! "files": [{"name", "url", "sha256"}]}`, or one `url` and `sha256` for the agent alone) downloads
//! the new `provigil-agent.exe` and response programs to `upgrade\<version>\`, checks each SHA-256
//! and, when the running agent is signed, that each is signed by the same subject. A generated
//! PowerShell helper then swaps every file while the service is stopped, and puts them all back
//! when the new agent does not keep running.
//! The helper's outcome (`upgrade\upgrade_result.json`) is reported at the next start.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::transport::{Download, Link};

pub const DIR: &str = "upgrade";
const RESULT_FILE: &str = "upgrade_result.json";
#[cfg(windows)]
const HELPER_FILE: &str = "upgrade.ps1";
#[cfg(not(windows))]
const HELPER_FILE: &str = "upgrade.sh";
#[cfg(windows)]
const AGENT_EXE: &str = "provigil-agent.exe";
#[cfg(not(windows))]
const AGENT_EXE: &str = "provigil-agent-linux";

fn is_agent_binary(name: &str) -> bool {
    #[cfg(windows)]
    {
        name == AGENT_EXE
    }
    #[cfg(not(windows))]
    {
        matches!(name, "provigil-agent-linux" | "provigil-agent")
    }
}
const MAX_BYTES: u64 = 200 * 1024 * 1024;
pub(crate) const DOWNLOAD_LIMIT: Duration = Duration::from_secs(600);

/// `upgrade\upgrade_result.json`: `pending` until the helper writes `done`, `rolled_back` or
/// `failed`.
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
    enabled: bool,
    busy: AtomicBool,
    /// The subject that validly signed a file, `None` when it is not (see [`signed_by`]).
    signer: fn(&Path) -> Option<String>,
}

/// Only letters, digits, `.`, `-` and `_`, not starting with a dot: safe in a file name (no `..`)
/// and in the helper script.
fn plain(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('.') && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// (name, url, SHA-256) of the files of an `upgrade` command: `files`, or its `url` and `sha256`
/// for the agent alone (a manager from before `files`).
fn files_of(cmd: &Value) -> Vec<(String, String, String)> {
    let s = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
    match cmd["files"].as_array() {
        Some(list) => list.iter().map(|f| (s(f, "name"), s(f, "url"), s(f, "sha256"))).collect(),
        None => vec![(AGENT_EXE.to_string(), s(cmd, "url"), s(cmd, "sha256"))],
    }
}

/// The subject of a file's valid signature (empty when it cannot be read), `None` when unsigned.
#[cfg(windows)]
fn signed_by(path: &Path) -> Option<String> {
    use std::os::windows::process::CommandExt;
    siem_active_response::dll_guard::verify(path).ok()?;
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"])
        .arg("(Get-AuthenticodeSignature -LiteralPath $env:PROVIGIL_SIGNED_FILE).SignerCertificate.Subject")
        .env("PROVIGIL_SIGNED_FILE", path)
        .stdin(std::process::Stdio::null())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output();
    Some(out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default())
}

#[cfg(not(windows))]
fn signed_by(_: &Path) -> Option<String> {
    None
}

impl UpgradeSupervisor {
    pub fn new(dir: impl Into<PathBuf>, enabled: bool) -> Self {
        Self { dir: dir.into(), enabled, busy: AtomicBool::new(false), signer: signed_by }
    }

    /// The upgrade result left by the helper. A final one (`done`, `rolled_back`, `failed`) is
    /// returned once: the file is removed. `pending` stays: the helper is still checking.
    pub fn check_previous_upgrade_result(&self) -> Option<UpgradeResult> {
        let path = self.dir.join(RESULT_FILE);
        let text = fs::read_to_string(&path).ok()?;
        let result = serde_json::from_str::<UpgradeResult>(&text).ok();
        if result.as_ref().is_none_or(|r| r.status != "pending") {
            let _ = fs::remove_file(&path);
        }
        result
    }

    /// Runs an `upgrade` command up to the hand-over to the helper: the result to report, and
    /// whether the agent must now stop (the helper is waiting for it). The package comes over `link`.
    pub async fn handle(&self, cmd: &Value, link: &dyn Link) -> (Value, bool) {
        let id = cmd["command_id"].as_str().unwrap_or_default();
        let version = cmd["version"].as_str().unwrap_or_default();
        let failed = |reason: &str| (json!({ "command_id": id, "status": "failed", "version": version, "reason": reason }), false);
        if !self.enabled {
            return failed("upgrades are disabled on this agent (upgrade_enabled)");
        }
        if self.busy.swap(true, Ordering::SeqCst) {
            return failed("upgrade in progress");
        }
        match self.prepare(cmd, id, version, link).await {
            Ok(()) => {
                info!(version = %version, "Upgrade helper started; the agent stops for the upgrade");
                (json!({ "command_id": id, "status": "in_progress", "version": version }), true)
            }
            Err(e) => {
                warn!(version = %version, error = %e, "Upgrade failed");
                self.busy.store(false, Ordering::SeqCst);
                failed(&e)
            }
        }
    }

    async fn prepare(&self, cmd: &Value, id: &str, version: &str, link: &dyn Link) -> Result<(), String> {
        let files = files_of(cmd);
        let complete = files.iter().all(|(name, url, sha)| plain(name) && !url.is_empty() && sha.len() == 64)
            && files.iter().any(|f| is_agent_binary(&f.0));
        if !complete || !plain(version) || !plain(id) {
            return Err("upgrade command incomplete or not valid".into());
        }
        // the helper runs from elsewhere: absolute paths
        let here = std::env::current_dir().map_err(|e| e.to_string())?;
        let dir = here.join(&self.dir);
        let staged = dir.join(version);
        fs::create_dir_all(&staged).map_err(|e| format!("{}: {e}", staged.display()))?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let bin = here.join("active-response").join("bin");
        let fetched = self.fetch(&files, version, &exe, &bin, &staged, link).await;
        let drop_staged = || {
            let _ = fs::remove_dir_all(&staged);
        };
        let swaps = fetched.inspect_err(|_| drop_staged())?;

        let pending = UpgradeResult {
            status: "pending".into(),
            version: version.into(),
            from_version: env!("CARGO_PKG_VERSION").into(),
            timestamp: Utc::now().to_rfc3339(),
            command_id: id.into(),
            reason: None,
        };
        let result = dir.join(RESULT_FILE);
        fs::write(&result, serde_json::to_string(&pending).unwrap_or_default()).map_err(|e| format!("{}: {e}", result.display()))?;
        let script = dir.join(HELPER_FILE);
        #[cfg(windows)]
        let script_body = "\u{feff}".to_string() + &helper_script(&swaps, &result, &pending, std::process::id());
        #[cfg(not(windows))]
        let script_body = helper_script(&swaps, &result, &pending, std::process::id());
        fs::write(&script, script_body).map_err(|e| format!("{}: {e}", script.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&script, fs::Permissions::from_mode(0o700));
        }
        launch(&script).inspect_err(|_| {
            let _ = fs::remove_file(&result);
            drop_staged();
        })
    }

    /// Downloads and checks every file into `staged`: (where it goes, where it is now).
    async fn fetch(&self, files: &[(String, String, String)], version: &str, exe: &Path, bin: &Path, staged: &Path, link: &dyn Link) -> Result<Vec<(PathBuf, PathBuf)>, String> {
        let running = self.signer_of(exe).await;
        let mut swaps = Vec::new();
        for (name, url, sha) in files {
            let new = staged.join(name);
            info!(url = %url, version = %version, "Downloading the agent upgrade");
            tokio::time::timeout(DOWNLOAD_LIMIT, async { download(link.download(url, version).await.map_err(|e| format!("download: {e}"))?, &new, sha).await })
                .await
                .unwrap_or_else(|_| Err("download: timed out".into()))?;
            if let Some(subject) = &running {
                // an unreadable subject proves nothing: refused rather than skipped
                if subject.is_empty() || self.signer_of(&new).await.as_ref() != Some(subject) {
                    return Err(format!("{name} is not signed by '{subject}', the running agent's signer"));
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&new, fs::Permissions::from_mode(0o755));
            }
            swaps.push((if is_agent_binary(name) { exe.to_path_buf() } else { bin.join(name) }, new));
        }
        Ok(swaps)
    }

    async fn signer_of(&self, file: &Path) -> Option<String> {
        let (signer, file) = (self.signer, file.to_path_buf());
        tokio::task::spawn_blocking(move || signer(&file)).await.ok().flatten()
    }
}

/// Downloads to `to` (at most `MAX_BYTES`, within `DOWNLOAD_LIMIT`) and checks the SHA-256;
/// on any failure the file is removed.
async fn download(mut resp: Download, to: &Path, sha256: &str) -> Result<(), String> {
    if resp.size().is_some_and(|n| n > MAX_BYTES) {
        return Err("download larger than 200 MB".into());
    }
    let mut file = tokio::fs::File::create(to).await.map_err(|e| format!("{}: {e}", to.display()))?;
    let mut hash = Sha256::new();
    let r = async {
        let mut total = 0u64;
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("download: {e}"))? {
            total += chunk.len() as u64;
            if total > MAX_BYTES {
                return Err("download larger than 200 MB".to_string());
            }
            hash.update(&chunk);
            file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        file.flush().await.map_err(|e| e.to_string())?;
        let got = format!("{:x}", hash.finalize());
        if got.eq_ignore_ascii_case(sha256) { Ok(()) } else { Err(format!("SHA-256 mismatch: expected {sha256}, got {got}")) }
    }
    .await;
    drop(file);
    if r.is_err() {
        let _ = fs::remove_file(to);
    }
    r
}

/// A path in a single-quoted PowerShell string.
#[cfg_attr(not(windows), allow(dead_code))]
fn ps(p: &Path) -> String {
    p.display().to_string().replace('\'', "''")
}

/// A string safely wrapped for single-quoted POSIX `sh`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Renders the POSIX `sh` upgrade helper used on Linux agents (exposed for cross-platform tests).
pub fn linux_helper_script(files: &[(PathBuf, PathBuf)], result: &Path, r: &UpgradeResult, pid: u32) -> String {
    let mut pairs = String::new();
    for (target, new) in files {
        pairs.push_str(&format!("    swap_one {} {}\n", sh_quote(&target.display().to_string()), sh_quote(&new.display().to_string())));
    }
    let mut restore = String::new();
    for (target, _) in files {
        restore.push_str(&format!("    restore_one {}\n", sh_quote(&target.display().to_string())));
    }
    let esc_json = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
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

# Wait up to 300 s for agent PID {pid} to exit
i=0
while [ "$i" -lt 300 ] && kill -0 {pid} 2>/dev/null; do
    sleep 1
    i=$((i + 1))
done

do_swaps() {{
{pairs}    return 0
}}

if ! do_swaps; then
    restore_all
    write_result "failed" "file swap failed during upgrade"
    systemctl restart "$SVC" 2>/dev/null || true
    exit 1
fi

systemctl restart "$SVC" 2>/dev/null || systemctl start "$SVC" 2>/dev/null || true
sleep 60
if systemctl is-active --quiet "$SVC"; then
    write_result "done" ""
else
    systemctl stop "$SVC" 2>/dev/null || true
    restore_all
    write_result "rolled_back" "the new version was not running 60 s after its start"
    systemctl start "$SVC" 2>/dev/null || true
fi
"#,
        from = r.from_version,
        version = r.version,
        result = sh_quote(&result.display().to_string()),
        ver_j = esc_json(&r.version),
        from_j = esc_json(&r.from_version),
        id_j = esc_json(&r.command_id),
    )
}

/// The helper: waits for the agent to exit, swaps every (target, new) file, starts the service
/// and after 60 s puts all the old files back when the service is not running. A file with no
/// old version is removed by that. A swap that fails half-way restores what it swapped.
#[cfg(windows)]
fn helper_script(files: &[(PathBuf, PathBuf)], result: &Path, r: &UpgradeResult, pid: u32) -> String {
    let list: String = files.iter().map(|(target, new)| format!("    @{{ target = '{}'; new = '{}' }}\n", ps(target), ps(new))).collect();
    format!(
        r#"# ProVigil agent upgrade {from} -> {version}
$svc = '{svc}'
$files = @(
{list})
function Write-Result($status, $reason) {{
    $r = [ordered]@{{ status = $status; version = '{version}'; from_version = '{from}'; command_id = '{id}'; timestamp = (Get-Date).ToUniversalTime().ToString('o'); reason = $reason }}
    [IO.File]::WriteAllText('{result}', ($r | ConvertTo-Json -Compress))
}}
function Restore($list) {{
    foreach ($f in $list) {{
        $bak = $f.target + '.bak'
        if (Test-Path -LiteralPath $bak) {{
            Move-Item -LiteralPath $bak -Destination $f.target -Force
        }} else {{
            Remove-Item -LiteralPath $f.target -Force -ErrorAction SilentlyContinue
        }}
    }}
}}
Wait-Process -Id {pid} -Timeout 300 -ErrorAction SilentlyContinue
$done = @()
try {{
    foreach ($f in $files) {{
        $bak = $f.target + '.bak'
        if (Test-Path -LiteralPath $bak) {{ Remove-Item -LiteralPath $bak -Force -ErrorAction Stop }}
        if (Test-Path -LiteralPath $f.target) {{ Move-Item -LiteralPath $f.target -Destination $bak -ErrorAction Stop }}
        $done += $f
        Move-Item -LiteralPath $f.new -Destination $f.target -Force -ErrorAction Stop
    }}
}} catch {{
    $why = "$_"
    Restore $done
    Write-Result 'failed' $why
    Start-Service $svc
    exit 1
}}
Start-Service $svc -ErrorAction SilentlyContinue
Start-Sleep -Seconds 60
if ((Get-Service $svc).Status -eq 'Running') {{
    Write-Result 'done' $null
}} else {{
    Stop-Service $svc -Force -ErrorAction SilentlyContinue
    Restore $files
    Write-Result 'rolled_back' 'the new version was not running 60 s after its start'
    Start-Service $svc
}}
"#,
        svc = crate::service::SERVICE_NAME,
        result = ps(result),
        version = r.version,
        from = r.from_version,
        id = r.command_id,
    )
}

#[cfg(not(windows))]
fn helper_script(files: &[(PathBuf, PathBuf)], result: &Path, r: &UpgradeResult, pid: u32) -> String {
    linux_helper_script(files, result, r, pid)
}

#[cfg(windows)]
fn launch(script: &Path) -> Result<(), String> {
    let mut c = std::process::Command::new("powershell.exe");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File"])
        .arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP: outlives the service. Not DETACHED_PROCESS:
        // PowerShell without any console exits at once (the upgrade then never ran, seen live)
        c.creation_flags(0x0800_0000 | 0x0000_0200);
    }
    c.spawn().map(drop).map_err(|e| format!("upgrade helper not started: {e}"))
}

#[cfg(not(windows))]
fn launch(script: &Path) -> Result<(), String> {
    let mut c = std::process::Command::new("sh");
    c.arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    c.spawn().map(drop).map_err(|e| format!("upgrade helper not started: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Creds, HttpsLink};
    use std::io::{Read, Write};

    /// The helper is really started the way an upgrade starts it, and it runs (a PowerShell
    /// started without a console exits before running anything).
    #[cfg(windows)]
    #[test]
    fn helper_really_runs() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("ran.txt");
        let script = dir.path().join("helper.ps1");
        std::fs::write(&script, format!("[IO.File]::WriteAllText('{}', 'ran')", out.display())).unwrap();
        launch(&script).unwrap();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !out.exists() && std::time::Instant::now() < end {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(out.exists(), "the upgrade helper did not run");
    }

    /// Answers one HTTP request with `body`; the manager's address.
    fn serve_once(body: &'static [u8]) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let _ = s.read(&mut [0u8; 4096]);
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = s.write_all(body);
        });
        format!("http://{addr}")
    }

    fn cmd(sha: &str) -> Value {
        json!({ "command_id": "c-1", "type": "upgrade", "url": "/downloads/provigil-agent.exe", "sha256": sha, "version": "9.9.9" })
    }

    #[tokio::test]
    async fn sha_mismatch_fails_and_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let sup = UpgradeSupervisor::new(dir.path(), true);
        let base = serve_once(b"NOT THE PUBLISHED PROGRAM");
        let link = HttpsLink::new(&base, Creds::default(), reqwest::Client::new());
        let (r, stop) = sup.handle(&cmd(&"0".repeat(64)), &link).await;
        assert!(!stop);
        assert_eq!((r["status"].as_str(), r["command_id"].as_str()), (Some("failed"), Some("c-1")));
        assert!(r["reason"].as_str().unwrap().contains("SHA-256"));
        assert!(!dir.path().join("9.9.9").exists(), "nothing staged is left");
        assert!(!sup.busy.load(Ordering::SeqCst), "a failed upgrade frees the way for the next");
    }

    #[tokio::test]
    async fn second_upgrade_refused_while_one_runs() {
        let dir = tempfile::tempdir().unwrap();
        let sup = UpgradeSupervisor::new(dir.path(), true);
        sup.busy.store(true, Ordering::SeqCst);
        let link = HttpsLink::new("http://127.0.0.1:9", Creds::default(), reqwest::Client::new());
        let (r, stop) = sup.handle(&cmd(&"0".repeat(64)), &link).await;
        assert!(!stop);
        assert_eq!((r["status"].as_str(), r["reason"].as_str()), (Some("failed"), Some("upgrade in progress")));
        let (r, _) = UpgradeSupervisor::new(dir.path(), false).handle(&cmd(&"0".repeat(64)), &link).await;
        assert_eq!(r["status"], "failed", "upgrade_enabled off");
    }

    fn pending() -> UpgradeResult {
        UpgradeResult { status: "pending".into(), version: "9.9.9".into(), from_version: "0.1.0".into(), timestamp: String::new(), command_id: "c-1".into(), reason: None }
    }

    #[test]
    fn helper_swaps_all_files_starts_then_rolls_all_back() {
        let files = [
            (PathBuf::from(r"C:\Program Files\ProVigil Agent\provigil-agent.exe"), PathBuf::from(r"C:\x\upgrade\9.9.9\provigil-agent.exe")),
            (PathBuf::from(r"C:\Program Files\ProVigil Agent\active-response\bin\kill-process.exe"), PathBuf::from(r"C:\x\upgrade\9.9.9\kill-process.exe")),
        ];
        let s = helper_script(&files, Path::new(r"C:\x\upgrade\upgrade_result.json"), &pending(), 42);
        let at = |t: &str| s.find(t).unwrap_or_else(|| panic!("{t} missing"));
        let steps = [
            r"@{ target = 'C:\Program Files\ProVigil Agent\provigil-agent.exe'; new = 'C:\x\upgrade\9.9.9\provigil-agent.exe' }",
            r"@{ target = 'C:\Program Files\ProVigil Agent\active-response\bin\kill-process.exe'; new = 'C:\x\upgrade\9.9.9\kill-process.exe' }",
            "Wait-Process -Id 42",
            "foreach ($f in $files)",
            "Move-Item -LiteralPath $f.target -Destination $bak",
            "$done += $f",
            "Move-Item -LiteralPath $f.new -Destination $f.target",
            "Restore $done\n    Write-Result 'failed'",
            "Start-Service $svc -ErrorAction SilentlyContinue\nStart-Sleep -Seconds 60",
            "Restore $files\n    Write-Result 'rolled_back'",
        ];
        assert!(steps.windows(2).all(|w| at(w[0]) < at(w[1])), "{s}");
        assert!(s.contains("Write-Result 'done'") && s.contains("$svc = 'ProVigilSvc'"));
    }

    /// The real script on real files. The service commands are stand-ins and the service name is
    /// not a real one, so no service is touched.
    #[cfg(windows)]
    #[test]
    fn helper_swaps_and_restores_every_file_on_disk() {
        let mut gone = std::process::Command::new("cmd").args(["/c", "exit"]).spawn().unwrap();
        let pid = gone.id();
        gone.wait().unwrap();
        for (service, outcome, new_prog_missing) in [("Running", "done", false), ("Stopped", "rolled_back", false), ("Running", "failed", true)] {
            let d = tempfile::tempdir().unwrap();
            let p = |n: &str| d.path().join(n);
            let text = |n: &str| fs::read_to_string(p(n)).ok();
            for (n, t) in [("agent.exe", "old agent"), ("prog.exe", "old prog"), ("new-agent", "new agent"), ("new-prog", "new prog"), ("new-extra", "new extra")] {
                fs::write(p(n), t).unwrap();
            }
            if new_prog_missing {
                fs::remove_file(p("new-prog")).unwrap();
            }
            let files = [(p("agent.exe"), p("new-agent")), (p("extra.exe"), p("new-extra")), (p("prog.exe"), p("new-prog"))];
            let script = helper_script(&files, &p("result.json"), &pending(), pid).replace("$svc = 'ProVigilSvc'", "$svc = 'ProVigilNoSuchTestService'");
            let stand_ins = format!("function Start-Service {{ }}\nfunction Stop-Service {{ }}\nfunction Start-Sleep {{ }}\nfunction Get-Service {{ [pscustomobject]@{{ Status = '{service}' }} }}\n");
            fs::write(p("run.ps1"), stand_ins + &script).unwrap();
            let run = std::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]).arg(p("run.ps1")).output().unwrap();
            let log = String::from_utf8_lossy(&run.stdout).into_owned() + &String::from_utf8_lossy(&run.stderr);
            let result: UpgradeResult = serde_json::from_str(&text("result.json").unwrap_or_else(|| panic!("no result: {log}"))).unwrap();
            assert_eq!(result.status, outcome, "{log}");
            let after: Vec<Option<String>> = ["agent.exe", "extra.exe", "prog.exe"].map(text).into();
            let want: [Option<&str>; 3] = if outcome == "done" { [Some("new agent"), Some("new extra"), Some("new prog")] } else { [Some("old agent"), None, Some("old prog")] };
            assert_eq!(after.iter().map(Option::as_deref).collect::<Vec<_>>(), want, "{outcome}: every file swapped, or every file back: {log}");
        }
    }

    fn sha(body: &[u8]) -> String {
        format!("{:x}", Sha256::digest(body))
    }

    #[tokio::test]
    async fn unsigned_new_exe_refused_when_the_running_one_is_signed() {
        let dir = tempfile::tempdir().unwrap();
        let mut sup = UpgradeSupervisor::new(dir.path(), true);
        // the running test program is "signed"; what lands in the temp folder is not
        sup.signer = |p| (!p.starts_with(std::env::temp_dir())).then(|| "CN=ProVigil".to_string());
        let body = b"UNSIGNED PROGRAM";
        let link = HttpsLink::new(&serve_once(body), Creds::default(), reqwest::Client::new());
        let (r, stop) = sup.handle(&cmd(&sha(body)), &link).await;
        assert!(!stop);
        assert_eq!(r["status"], "failed");
        assert!(r["reason"].as_str().unwrap().contains("not signed by 'CN=ProVigil'"), "{r}");
        assert!(!dir.path().join("9.9.9").exists() && !dir.path().join(RESULT_FILE).exists(), "nothing staged, no helper");
    }

    async fn fetch_one(sup: &UpgradeSupervisor, staged: &Path) -> Result<Vec<(PathBuf, PathBuf)>, String> {
        let link = HttpsLink::new(&serve_once(b"x"), Creds::default(), reqwest::Client::new());
        let files = [(AGENT_EXE.to_string(), "/downloads/provigil-agent.exe".to_string(), sha(b"x"))];
        sup.fetch(&files, "9.9.9", Path::new("running.exe"), Path::new("bin"), staged, &link).await
    }

    #[tokio::test]
    async fn signer_must_be_the_same_subject_and_readable() {
        let dir = tempfile::tempdir().unwrap();
        let mut sup = UpgradeSupervisor::new(dir.path(), true);
        sup.signer = |p| Some(if p == Path::new("running.exe") { "CN=A".into() } else { "CN=B".into() });
        assert!(fetch_one(&sup, dir.path()).await.unwrap_err().contains("not signed by 'CN=A'"), "another subject");
        sup.signer = |_| Some("CN=A".into());
        assert_eq!(fetch_one(&sup, dir.path()).await.unwrap(), [(PathBuf::from("running.exe"), dir.path().join(AGENT_EXE))], "the same subject");
        sup.signer = |_| Some(String::new());
        assert!(fetch_one(&sup, dir.path()).await.is_err(), "a subject that cannot be read refuses");
        sup.signer = |p| (p != Path::new("running.exe")).then(String::new);
        assert!(fetch_one(&sup, dir.path()).await.is_ok(), "an unsigned running agent checks nothing");
    }

    #[tokio::test]
    async fn every_file_downloaded_and_a_failure_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let sup = UpgradeSupervisor::new(dir.path(), true);
        let link = HttpsLink::new("http://127.0.0.1:9", Creds::default(), reqwest::Client::new());
        let good = serve_once(b"PROGRAM");
        let bad = serve_once(b"NOT THE AGENT");
        let c = json!({ "command_id": "c-1", "type": "upgrade", "version": "9.9.9", "files": [
            { "name": "kill-process.exe", "url": format!("{good}/p"), "sha256": sha(b"PROGRAM") },
            { "name": AGENT_EXE, "url": format!("{bad}/a"), "sha256": sha(b"THE AGENT") },
        ] });
        let (r, _) = sup.handle(&c, &link).await;
        assert!(r["reason"].as_str().unwrap().contains("SHA-256"), "{r}");
        assert!(!dir.path().join("9.9.9").exists(), "the file already fetched goes too");
    }

    #[tokio::test]
    async fn file_lists_refused_when_unsafe_or_without_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let sup = UpgradeSupervisor::new(dir.path(), true);
        let link = HttpsLink::new("http://127.0.0.1:9", Creds::default(), reqwest::Client::new());
        let file = |n: &str| json!({ "name": n, "url": "/u", "sha256": "0".repeat(64) });
        for files in [vec![file("kill-process.exe")], vec![file(AGENT_EXE), file("..")], vec![file(AGENT_EXE), file(r"..\evil.exe")], vec![file(AGENT_EXE), file("a/b")], vec![]] {
            let (r, _) = sup.handle(&json!({ "command_id": "c-1", "version": "9.9.9", "files": files }), &link).await;
            assert_eq!(r["reason"], "upgrade command incomplete or not valid", "{files:?}");
        }
        let (r, _) = sup.handle(&json!({ "command_id": "c-1", "version": "..", "files": [file(AGENT_EXE)] }), &link).await;
        assert_eq!(r["reason"], "upgrade command incomplete or not valid");
    }

    #[cfg(windows)]
    #[test]
    fn subject_read_from_a_signed_file_and_none_for_an_unsigned_one() {
        let system = std::env::var("SystemRoot").unwrap();
        let subject = signed_by(&Path::new(&system).join("System32").join("kernel32.dll")).unwrap();
        assert!(subject.contains("Microsoft"), "{subject}");
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), b"MZ not a program").unwrap();
        assert_eq!(signed_by(f.path()), None);
    }

    #[test]
    fn result_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        let sup = UpgradeSupervisor::new(dir.path(), true);
        let file = dir.path().join(RESULT_FILE);
        fs::write(&file, r#"{"status":"pending","version":"9.9.9","from_version":"0.1.0","timestamp":"t","command_id":"c-1"}"#).unwrap();
        assert_eq!(sup.check_previous_upgrade_result().unwrap().status, "pending");
        assert!(file.exists(), "the helper is still checking");
        // as the helper writes it (reason null)
        fs::write(&file, r#"{"status":"done","version":"9.9.9","from_version":"0.1.0","command_id":"c-1","timestamp":"t","reason":null}"#).unwrap();
        let r = sup.check_previous_upgrade_result().unwrap();
        assert_eq!((r.status.as_str(), r.command_id.as_str()), ("done", "c-1"));
        assert_eq!(sup.check_previous_upgrade_result(), None);
    }
}
