//! `provigil-deploy.exe`, in the deployment kit next to `deploy-provigil.ps1`, which runs it for what
//! PowerShell cannot do well (specs/provigil-mass-deploy.md):
//!
//! - `push-linux --host H [--port 22] --user U [--key FILE] --kit DIR`: installs the Linux agent over
//!   SSH with the kit's `linux/install.sh` and token; the password (login and sudo) comes in the
//!   environment variable `PROVIGIL_SSH_PASSWORD`, never on the command line. Prints one JSON result.
//! - `report --kit DIR [--file results.json] [--from PC]`: sends result rows to the console through
//!   the gateway, TLS checked with the kit's CA. Without `--file` it only checks the cloud and token.
//!
//! Exit code 0 when the work was done (the outcome is in the JSON), 2 on bad arguments.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{client, ChannelMsg, Disconnect};
use serde_json::{json, Value};

const SSH_TIMEOUT: Duration = Duration::from_secs(15);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);
const REPORT_CHUNK: usize = 100;
const RESULT_MARK: &str = "PROVIGIL_RESULT ";

fn args() -> (String, HashMap<String, String>) {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_default();
    let mut m = HashMap::new();
    while let Some(k) = it.next() {
        if let Some(k) = k.strip_prefix("--") {
            m.insert(k.to_string(), it.next().unwrap_or_default());
        }
    }
    (cmd, m)
}

/// The kit's `deploy.json`.
fn kit(dir: &Path) -> Result<Value, String> {
    let s = std::fs::read_to_string(dir.join("deploy.json")).map_err(|e| format!("deploy.json: {e}"))?;
    // Windows PowerShell 5.1 writes a BOM when an admin edits the file
    serde_json::from_str(s.trim_start_matches('\u{feff}')).map_err(|e| format!("deploy.json: {e}"))
}

#[tokio::main]
async fn main() {
    let (cmd, a) = args();
    let dir = PathBuf::from(a.get("kit").cloned().unwrap_or_else(|| ".".into()));
    let code = match cmd.as_str() {
        "push-linux" => {
            let (Some(host), Some(user)) = (a.get("host"), a.get("user")) else {
                eprintln!("push-linux needs --host and --user");
                std::process::exit(2);
            };
            let port = a.get("port").and_then(|p| p.parse().ok()).unwrap_or(22);
            let password = std::env::var("PROVIGIL_SSH_PASSWORD").ok().filter(|p| !p.is_empty());
            let row = push_linux(&dir, host, port, user, a.get("key").map(PathBuf::from), password).await;
            println!("{row}");
            0
        }
        "report" => match report(&dir, a.get("file").map(PathBuf::from), a.get("from").cloned().unwrap_or_default()).await {
            Ok(n) => {
                println!("{}", json!({ "status": "ok", "sent": n }));
                0
            }
            Err(e) => {
                println!("{}", json!({ "status": "error", "message": e }));
                1
            }
        },
        _ => {
            eprintln!("usage: provigil-deploy push-linux|report ... (see deploy-provigil.ps1)");
            2
        }
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------- Linux over SSH

struct Accept;

impl client::Handler for Accept {
    type Error = russh::Error;
    // shortcut: any host key is accepted (the client's own LAN, the hosts they listed or we found);
    // pin known_hosts when a client asks for it
    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// One result row, the same fields as the Windows push (section 7 of the plan).
fn row(host: &str, computer: &str, os: &str, outcome: &str, reason: &str, agent_id: &str) -> Value {
    json!({ "computer": computer, "address": host, "os": os, "method": "ssh", "outcome": outcome, "reason": reason, "agent_id": agent_id })
}

async fn push_linux(dir: &Path, host: &str, port: u16, user: &str, key: Option<PathBuf>, password: Option<String>) -> Value {
    match tokio::time::timeout(INSTALL_TIMEOUT, push_linux_inner(dir, host, port, user, key, password)).await {
        Ok(Ok(v)) => v,
        Ok(Err((outcome, reason))) => row(host, "", "linux", outcome, &reason, ""),
        Err(_) => row(host, "", "linux", "failed", "timed out after 10 minutes", ""),
    }
}

/// The output and exit status of a command; `stdin` is written first, then closed.
async fn run(s: &client::Handle<Accept>, cmd: &str, stdin: Option<&[u8]>) -> Result<(String, u32), String> {
    let mut ch = s.channel_open_session().await.map_err(|e| e.to_string())?;
    ch.exec(true, cmd).await.map_err(|e| e.to_string())?;
    if let Some(data) = stdin {
        ch.data(data).await.map_err(|e| e.to_string())?;
    }
    ch.eof().await.map_err(|e| e.to_string())?;
    let (mut out, mut code) = (Vec::new(), 255);
    while let Some(m) = ch.wait().await {
        match m {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => out.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => code = exit_status,
            _ => {}
        }
    }
    Ok((String::from_utf8_lossy(&out).into_owned(), code))
}

/// `PRETTY_NAME` and whether the system is supported (systemd running).
fn os_of(release: &str) -> String {
    release.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| v.trim_matches('"').to_string()).unwrap_or_else(|| "Linux".into())
}

/// Single-quoted for sh.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

type Fail = (&'static str, String);

async fn push_linux_inner(dir: &Path, host: &str, port: u16, user: &str, key: Option<PathBuf>, password: Option<String>) -> Result<Value, Fail> {
    let deploy = kit(dir).map_err(|e| ("failed", e))?;
    let files = ["siem-agent-linux", "install.sh"].map(|f| (f, std::fs::read(dir.join("linux").join(f))));
    let ca = std::fs::read(dir.join("ca.pem")).map_err(|e| ("failed", format!("ca.pem: {e}")))?;

    let config = Arc::new(client::Config { inactivity_timeout: Some(Duration::from_secs(120)), ..Default::default() });
    let mut s = tokio::time::timeout(SSH_TIMEOUT, client::connect(config, (host, port), Accept))
        .await
        .map_err(|_| ("unreachable", "SSH did not answer within 15 s".to_string()))?
        .map_err(|e| ("unreachable", format!("SSH: {e}")))?;
    let ok = match &key {
        Some(k) => {
            let kp = load_secret_key(k, password.as_deref()).map_err(|e| ("failed", format!("key file: {e}")))?;
            let hash = s.best_supported_rsa_hash().await.ok().flatten().flatten();
            s.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(kp), hash)).await.map_err(|e| ("failed", e.to_string()))?.success()
        }
        None => {
            let Some(p) = &password else { return Err(("failed", "no SSH password or key given".into())) };
            s.authenticate_password(user, p).await.map_err(|e| ("failed", e.to_string()))?.success()
        }
    };
    if !ok {
        return Err(("access denied", format!("SSH login refused for {user}")));
    }

    let (info, _) = run(&s, "cat /etc/os-release 2>/dev/null; echo; echo HOST=$(hostname -s 2>/dev/null || hostname); echo UID=$(id -u); test -d /run/systemd/system && echo SYSTEMD=1", None).await.map_err(|e| ("failed", e))?;
    let os = os_of(&info);
    let computer = info.lines().find_map(|l| l.strip_prefix("HOST=")).unwrap_or_default().trim().to_string();
    let root = info.lines().any(|l| l.trim() == "UID=0");
    if !info.lines().any(|l| l.trim() == "SYSTEMD=1") {
        return Ok(row(host, &computer, &os, "not supported", "systemd is not running (the agent runs as a systemd service)", ""));
    }
    let fail = |o: &'static str, r: String| Ok(row(host, &computer, &os, o, &r, ""));

    let tmp = format!("/tmp/provigil-{}", uuid::Uuid::new_v4().simple());
    let (out, code) = run(&s, &format!("umask 077 && mkdir -m 700 {tmp}"), None).await.map_err(|e| ("failed", e))?;
    if code != 0 {
        return fail("failed", format!("could not create {tmp}: {}", out.trim()));
    }
    // the settings install.sh reads, in a file only this user can read (not on a command line)
    let env = format!(
        "SIEM_MANAGER_URL={}\nSIEM_CA_FILE={tmp}/ca.pem\nSIEM_AGENT_GROUP={}\nSIEM_TENANT_KEY={}\n",
        sq(deploy["manager_url"].as_str().unwrap_or_default()),
        sq(deploy["groups"].as_str().filter(|g| !g.is_empty()).unwrap_or("default")),
        sq(deploy["token"].as_str().unwrap_or_default()),
    );
    let mut uploads: Vec<(&str, Vec<u8>)> = vec![("env", env.into_bytes()), ("ca.pem", ca)];
    for (name, data) in files {
        uploads.push((name, data.map_err(|e| ("failed", format!("linux/{name}: {e}")))?));
    }
    for (name, data) in &uploads {
        let (out, code) = run(&s, &format!("cat > {tmp}/{name}"), Some(data)).await.map_err(|e| ("failed", e))?;
        if code != 0 {
            let _ = run(&s, &format!("rm -rf {tmp}"), None).await;
            return fail("failed", format!("copying {name}: {}", out.trim()));
        }
    }
    let inner = sq(&format!("set -a; . {tmp}/env; set +a; chmod 755 {tmp}/siem-agent-linux; bash {tmp}/install.sh"));
    let (cmd, stdin) = match (root, &password) {
        (true, _) => (format!("bash -c {inner}"), None),
        (false, Some(p)) => (format!("sudo -S -p '' bash -c {inner}"), Some(format!("{p}\n"))),
        (false, None) => (format!("sudo -n bash -c {inner}"), None),
    };
    let result = run(&s, &cmd, stdin.as_deref().map(str::as_bytes)).await;
    // root's files in it (the agent copied them away), so with sudo when not root
    let rm = if root { format!("rm -rf {tmp}") } else { format!("rm -rf {tmp} 2>/dev/null || sudo -n rm -rf {tmp}") };
    let _ = run(&s, &rm, None).await;
    let _ = s.disconnect(Disconnect::ByApplication, "", "en").await;
    let (out, code) = result.map_err(|e| ("failed", e))?;
    Ok(parse_install(&out, code, host, &computer, &os))
}

/// The row from install.sh's `PROVIGIL_RESULT {json}` line, or why there is none.
fn parse_install(out: &str, code: u32, host: &str, computer: &str, os: &str) -> Value {
    if let Some(mut v) = out.lines().rev().find_map(|l| l.trim().strip_prefix(RESULT_MARK)).and_then(|j| serde_json::from_str::<Value>(j).ok()) {
        v["address"] = json!(host);
        v["method"] = json!("ssh");
        if v["os"].as_str().is_none_or(str::is_empty) {
            v["os"] = json!(os);
        }
        if v["computer"].as_str().is_none_or(str::is_empty) {
            v["computer"] = json!(computer);
        }
        return v;
    }
    let low = out.to_ascii_lowercase();
    let reason = if low.contains("a password is required") || low.contains("incorrect password") || low.contains("not in the sudoers") || low.contains("is not allowed to run sudo") {
        "sudo refused for this user".to_string()
    } else {
        let tail: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        format!("install.sh exited with {code}: {}", tail[tail.len().saturating_sub(3)..].join(" / "))
    };
    row(host, computer, os, if reason.starts_with("sudo") { "access denied" } else { "failed" }, &reason, "")
}

// ---------------------------------------------------------------- results to the console

async fn report(dir: &Path, file: Option<PathBuf>, from: String) -> Result<usize, String> {
    let deploy = kit(dir)?;
    let ca = std::fs::read(dir.join("ca.pem")).map_err(|e| format!("ca.pem: {e}"))?;
    let cert = reqwest::Certificate::from_pem(&ca).map_err(|e| format!("ca.pem: {e}"))?;
    let http = reqwest::Client::builder().tls_built_in_root_certs(false).add_root_certificate(cert).timeout(Duration::from_secs(30)).build().map_err(|e| e.to_string())?;
    let url = format!("{}/api/v1/deploy/report", deploy["manager_url"].as_str().unwrap_or_default().trim_end_matches('/'));
    let token = deploy["token"].as_str().unwrap_or_default();
    let rows: Vec<Value> = match file {
        Some(f) => {
            let s = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            // PowerShell writes a BOM and a lone object for one row
            match serde_json::from_str(s.trim_start_matches('\u{feff}')).map_err(|e| format!("{}: {e}", f.display()))? {
                Value::Array(a) => a,
                v => vec![v],
            }
        }
        None => Vec::new(),
    };
    let chunks: Vec<&[Value]> = if rows.is_empty() { vec![&[]] } else { rows.chunks(REPORT_CHUNK).collect() };
    for c in chunks {
        let r = http.post(&url).header("x-tenant-key", token).json(&json!({ "from": from, "rows": c })).send().await.map_err(|e| format!("{url}: {e}"))?;
        if !r.status().is_success() {
            let code = r.status();
            return Err(format!("{url}: {code} {}", r.text().await.unwrap_or_default()));
        }
    }
    Ok(rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_install_result_line_is_read_and_failures_explained() {
        let out = "[+] stuff\nPROVIGIL_RESULT {\"computer\":\"web1\",\"os\":\"Ubuntu 22.04\",\"outcome\":\"installed\",\"reason\":\"\",\"agent_id\":\"042\"}\n";
        let v = parse_install(out, 0, "10.0.0.5", "web1", "Ubuntu");
        assert_eq!((v["outcome"].as_str(), v["agent_id"].as_str(), v["address"].as_str(), v["method"].as_str()), (Some("installed"), Some("042"), Some("10.0.0.5"), Some("ssh")));

        let v = parse_install("sudo: a password is required\n", 1, "h", "c", "o");
        assert_eq!((v["outcome"].as_str(), v["reason"].as_str()), (Some("access denied"), Some("sudo refused for this user")));

        let v = parse_install("a\nb\nc\nd\n", 3, "h", "c", "o");
        assert_eq!(v["reason"].as_str(), Some("install.sh exited with 3: b / c / d"));
    }

    #[test]
    fn os_name_and_quoting() {
        assert_eq!(os_of("NAME=x\nPRETTY_NAME=\"Rocky Linux 9.4\"\n"), "Rocky Linux 9.4");
        assert_eq!(os_of(""), "Linux");
        assert_eq!(sq("a'b"), r"'a'\''b'");
    }
}
