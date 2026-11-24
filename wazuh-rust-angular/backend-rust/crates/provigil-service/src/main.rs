//! provigil-service: ProVigil's server programs as Windows services (the Windows MSI,
//! specs/provigil-packages.md).
//!
//!   provigil-service run <program> [--console]   the service of one program (the MSI registers it);
//!                                                --console runs it in this window (testing)
//!   provigil-service configure [options]         the settings, written by the MSI at install
//!
//! Layout: programs in `<install>\bin` (this file's folder), the console in `<install>\console`,
//! the default ruleset in `<install>\ruleset`; everything that changes in `%ProgramData%\ProVigil`
//! (`provigil.env` with the settings and secrets, `data\`, `logs\`), which is also every
//! program's working folder (siem-api finds `data\` there).
//!
//! A program that ends without a stop request is started again after 5 s, doubling to 60 s.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A supervised program: its name on the command line, its Windows service, its file and arguments.
struct Program {
    name: &'static str,
    service: &'static str,
    exe: &'static str,
    args: &'static [&'static str],
}

const PROGRAMS: [Program; 4] = [
    Program { name: "auth-service", service: "ProVigilAuth", exe: "auth-service.exe", args: &[] },
    Program { name: "siem-api", service: "ProVigilSiemApi", exe: "siem-api.exe", args: &[] },
    Program { name: "gateway", service: "ProVigilGateway", exe: "provigil-gateway.exe", args: &[] },
    Program { name: "console", service: "ProVigilConsole", exe: "caddy.exe", args: &["run", "--adapter", "caddyfile", "--config", "{install}\\Caddyfile"] },
];

static STOP: AtomicBool = AtomicBool::new(false);

fn program(name: &str) -> Option<&'static Program> {
    PROGRAMS.iter().find(|p| p.name == name)
}

fn install_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    // <install>\bin\provigil-service.exe
    exe.parent().and_then(Path::parent).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
}

fn data_dir() -> PathBuf {
    std::env::var_os("PROVIGIL_DATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join("ProVigil"))
}

// ── settings file: KEY=VALUE lines ──────────────────────────────────────────────────────────

fn read_env(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn write_env(path: &Path, env: &BTreeMap<String, String>) -> std::io::Result<()> {
    let mut s = String::from("# ProVigil settings (written by the installer; secrets: keep this file private)\r\n");
    for (k, v) in env {
        s.push_str(&format!("{k}={v}\r\n"));
    }
    std::fs::write(path, s)
}

/// Everything a program gets besides the settings file: its folders and its neighbours' addresses.
fn program_env(install: &Path, data: &Path) -> Vec<(String, String)> {
    let i = install.display().to_string();
    let d = data.display().to_string();
    vec![
        ("PROVIGIL_SOURCE_DIR".into(), format!("{i}\\ruleset")),
        ("PROVIGIL_MANAGER_HOME".into(), format!("{d}\\data\\manager")),
        ("LISTEN_ADDR".into(), "127.0.0.1:3011".into()),
        ("SIEM_PORT".into(), "8088".into()),
        // the console's web server (Caddyfile): the programs behind it, the built console, its certificates
        ("AUTH_UPSTREAM".into(), "127.0.0.1:3011".into()),
        ("SIEM_UPSTREAM".into(), "127.0.0.1:8088".into()),
        ("NDR_UPSTREAM".into(), "127.0.0.1:13000".into()),
        ("CONSOLE_ROOT".into(), format!("{i}\\console")),
        ("XDG_DATA_HOME".into(), format!("{d}\\caddy")),
        ("XDG_CONFIG_HOME".into(), format!("{d}\\caddy")),
    ]
}

// ── run: one program, started again when it ends ───────────────────────────────────────────

fn start(p: &Program, install: &Path, data: &Path) -> std::io::Result<Child> {
    let logs = data.join("logs");
    std::fs::create_dir_all(&logs)?;
    let log_path = logs.join(format!("{}.log", p.name));
    // one old log is kept: <name>.log.1
    if std::fs::metadata(&log_path).map(|m| m.len() > 50 << 20).unwrap_or(false) {
        let _ = std::fs::rename(&log_path, logs.join(format!("{}.log.1", p.name)));
    }
    let log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)?;
    let args: Vec<String> = p.args.iter().map(|a| a.replace("{install}", &install.display().to_string())).collect();
    let mut cmd = Command::new(install.join("bin").join(p.exe));
    cmd.args(&args).current_dir(data).stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
    for (k, v) in program_env(install, data) {
        cmd.env(k, v);
    }
    // the settings file wins over the defaults above
    for (k, v) in read_env(&data.join("provigil.env")) {
        cmd.env(k, v);
    }
    cmd.spawn()
}

/// Runs `p` until STOP is set, starting it again when it ends on its own.
fn supervise(p: &Program) {
    let (install, data) = (install_dir(), data_dir());
    let mut wait = Duration::from_secs(5);
    while !STOP.load(Ordering::SeqCst) {
        let began = Instant::now();
        match start(p, &install, &data) {
            Ok(mut child) => {
                while !STOP.load(Ordering::SeqCst) {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            note(&data, p, &format!("ended ({status}); starting again in {}s", wait.as_secs()));
                            break;
                        }
                        Ok(None) => std::thread::sleep(Duration::from_millis(500)),
                        Err(e) => {
                            note(&data, p, &format!("cannot watch: {e}"));
                            break;
                        }
                    }
                }
                if STOP.load(Ordering::SeqCst) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
            Err(e) => note(&data, p, &format!("cannot start {}: {e}; trying again in {}s", p.exe, wait.as_secs())),
        }
        // a program that ran a while is restarted quickly again
        if began.elapsed() > Duration::from_secs(300) {
            wait = Duration::from_secs(5);
        }
        let until = Instant::now() + wait;
        while Instant::now() < until && !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(250));
        }
        wait = (wait * 2).min(Duration::from_secs(60));
    }
}

fn note(data: &Path, p: &Program, m: &str) {
    use std::io::Write;
    let _ = std::fs::create_dir_all(data.join("logs"));
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(data.join("logs").join("provigil-service.log")) {
        let _ = writeln!(f, "{} {}: {m}", unix_now(), p.name);
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(windows)]
mod winsvc {
    use super::*;
    use std::ffi::OsString;
    use std::sync::OnceLock;
    use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    static PROGRAM: OnceLock<&'static Program> = OnceLock::new();

    define_windows_service!(ffi_main, service_main);

    pub fn dispatch(p: &'static Program) -> Result<(), windows_service::Error> {
        let _ = PROGRAM.set(p);
        service_dispatcher::start(p.service, ffi_main)
    }

    fn status(state: ServiceState) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(if state == ServiceState::StopPending { 20 } else { 0 }),
            process_id: None,
        }
    }

    fn service_main(_args: Vec<OsString>) {
        let Some(p) = PROGRAM.get().copied() else { return };
        let handler = |c| match c {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                STOP.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(h) = service_control_handler::register(p.service, handler) else { return };
        let _ = h.set_service_status(status(ServiceState::Running));
        supervise(p);
        let _ = h.set_service_status(status(ServiceState::Stopped));
    }
}

// ── configure: the settings the MSI collected ───────────────────────────────────────────────

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system random");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// ProVigil's licence key: built in at release (PROVIGIL_LICENSE_PUBLIC_KEY), as base64 of PEM.
fn built_in_key() -> Option<String> {
    use base64::Engine as _;
    let k = provigil_license::BUILT_IN_KEY?;
    let pem = provigil_license::pem(k).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(pem))
}

struct Config {
    data: PathBuf,
    licence: Option<PathBuf>,
    msi: Option<PathBuf>,
    settings: BTreeMap<String, String>,
}

/// Writes provigil.env (new secrets only the first time: a reinstall or upgrade keeps them, so
/// sessions, stored credentials and the gateway keep working) and the licence. Errors stop the
/// install (the MSI then rolls back) with the message in its log.
fn configure(c: &Config, key: Option<&str>) -> Result<String, String> {
    std::fs::create_dir_all(c.data.join("data")).map_err(|e| format!("{}: {e}", c.data.display()))?;
    std::fs::create_dir_all(c.data.join("logs")).map_err(|e| e.to_string())?;
    let file = c.data.join("provigil.env");
    let mut env = read_env(&file);
    for (k, v) in &c.settings {
        if !v.trim().is_empty() {
            env.insert(k.clone(), v.trim().to_string());
        }
    }
    env.entry("CLICKHOUSE_DB".into()).or_insert_with(|| "ndr".into());
    env.entry("CLICKHOUSE_USER".into()).or_insert_with(|| "provigil".into());
    env.entry("JWT_SECRET".into()).or_insert_with(|| random_hex(48));
    env.entry("AGENT_KEYS_SECRET".into()).or_insert_with(|| random_hex(32));
    env.entry("GATEWAY_INTERNAL_TOKEN".into()).or_insert_with(|| random_hex(32));
    if let Some(k) = key {
        env.insert("LICENSE_PUBLIC_KEY".into(), k.to_string());
    }
    for need in ["CLICKHOUSE_URL", "VALKEY_URL"] {
        if env.get(need).is_none_or(|v| v.is_empty()) {
            return Err(format!("{need} is required: the data lake's address (and its Valkey) from install-datalake.sh"));
        }
    }
    // the licence: the given file, else licence.jwt next to the MSI, else the one already installed
    let candidates = c.licence.iter().cloned().chain(c.msi.as_ref().and_then(|m| m.parent().map(|d| d.join("licence.jwt"))));
    let installed = c.data.join("data").join("license.jwt");
    let mut summary = String::from("no new licence (the installed one is kept)");
    if let Some(path) = candidates.into_iter().find(|p| p.is_file()) {
        let token = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?.trim().to_string();
        let claims = match key {
            Some(k) => provigil_license::verify(&token, k).map_err(|e| format!("{}: {e}", path.display()))?,
            None => return Err("this build has no ProVigil key: it cannot check a licence (use a release build)".into()),
        };
        std::fs::write(&installed, format!("{token}\n")).map_err(|e| e.to_string())?;
        summary = format!("licence for {} ({})", claims.tenant_name, if claims.features.is_empty() { "all modules".into() } else { claims.features.join(", ") });
    } else if !installed.is_file() && key.is_some() {
        return Err("no licence: put licence.jwt next to the MSI, or give LICENCE_FILE".into());
    }
    write_env(&file, &env).map_err(|e| format!("{}: {e}", file.display()))?;
    restrict(&file);
    Ok(summary)
}

/// Only SYSTEM and administrators may read the settings file (it holds the secrets).
fn restrict(file: &Path) {
    // tests run as an ordinary user, who could then no longer read the file back
    if cfg!(windows) && !cfg!(test) {
        // drop any entry the file already had, then only these two
        let _ = Command::new("icacls").arg(file).arg("/reset").stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = Command::new("icacls").arg(file).args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

fn parse_configure(args: &[String]) -> Result<Config, String> {
    let mut c = Config { data: data_dir(), licence: None, msi: None, settings: BTreeMap::new() };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--data" => c.data = PathBuf::from(val()?),
            "--licence" => c.licence = Some(PathBuf::from(val()?)).filter(|p| !p.as_os_str().is_empty()),
            "--msi" => c.msi = Some(PathBuf::from(val()?)).filter(|p| !p.as_os_str().is_empty()),
            "--datalake" => {
                let mut u = val()?;
                if !u.is_empty() && !u.contains("://") {
                    u = format!("http://{u}:8123");
                }
                c.settings.insert("CLICKHOUSE_URL".into(), u);
            }
            "--datalake-user" => { c.settings.insert("CLICKHOUSE_USER".into(), val()?); }
            "--datalake-password" => { c.settings.insert("CLICKHOUSE_PASSWORD".into(), val()?); }
            "--valkey" => { c.settings.insert("VALKEY_URL".into(), val()?); }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(c)
}

/// The MSI passes the settings as one CustomActionData text: `key=value` parts separated by `;`.
fn args_from_msi(data: &str) -> Vec<String> {
    data.split(';').filter_map(|kv| kv.split_once('=')).flat_map(|(k, v)| [format!("--{}", k.trim()), v.to_string()]).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("run") => {
            let Some(p) = args.get(1).and_then(|n| program(n)) else {
                eprintln!("run: one of {}", PROGRAMS.iter().map(|p| p.name).collect::<Vec<_>>().join(", "));
                std::process::exit(2)
            };
            if args.iter().any(|a| a == "--console") {
                supervise(p);
                0
            } else {
                #[cfg(windows)]
                {
                    match winsvc::dispatch(p) {
                        Ok(()) => 0,
                        Err(e) => {
                            eprintln!("not started by Windows ({e}); use --console to run it here");
                            1
                        }
                    }
                }
                #[cfg(not(windows))]
                {
                    supervise(p);
                    0
                }
            }
        }
        Some("configure") => {
            let rest = if args.get(1).map(String::as_str) == Some("--msi-data") { args_from_msi(args.get(2).map(String::as_str).unwrap_or("")) } else { args[1..].to_vec() };
            match parse_configure(&rest).and_then(|c| configure(&c, built_in_key().as_deref())) {
                Ok(s) => {
                    println!("ProVigil configured: {s}");
                    0
                }
                Err(e) => {
                    eprintln!("ProVigil configuration failed: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("usage: provigil-service run <{}> [--console] | configure [--datalake URL --datalake-user U --datalake-password P --valkey URL --licence FILE --msi PATH --data DIR]", PROGRAMS.iter().map(|p| p.name).collect::<Vec<_>>().join("|"));
            2
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIV: &str = include_str!("../../provigil-license/testdata/TEST-ONLY-private.pem");
    const PUB: &str = include_str!("../../provigil-license/testdata/TEST-ONLY-public.pem");

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("provigil-service-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn licence(features: &[&str]) -> String {
        let c = provigil_license::Claims { tenant_id: "acme".into(), tenant_name: "Acme Ltd".into(), features: features.iter().map(|f| f.to_string()).collect(), exp: 4_000_000_000, ..Default::default() };
        provigil_license::issue(&c, PRIV).unwrap()
    }

    #[test]
    fn configure_writes_settings_keeps_secrets_and_checks_the_licence() {
        let d = tmp("cfg");
        let msi_dir = d.join("download");
        std::fs::create_dir_all(&msi_dir).unwrap();
        std::fs::write(msi_dir.join("licence.jwt"), licence(&["siem", "soar"])).unwrap();
        let args = args_from_msi("data=ignored;datalake=192.168.1.20;datalake-password=pw;valkey=redis://:vk@192.168.1.20:6379");
        let mut c = parse_configure(&args).unwrap();
        c.data = d.join("pd");
        c.msi = Some(msi_dir.join("ProVigil-Setup.msi"));
        let out = configure(&c, Some(PUB)).unwrap();
        assert!(out.contains("Acme Ltd (siem, soar)"), "{out}");
        let env = read_env(&c.data.join("provigil.env"));
        assert_eq!(env["CLICKHOUSE_URL"], "http://192.168.1.20:8123");
        assert_eq!(env["CLICKHOUSE_USER"], "provigil");
        assert_eq!(env["VALKEY_URL"], "redis://:vk@192.168.1.20:6379");
        assert_eq!(env["JWT_SECRET"].len(), 96);
        assert!(c.data.join("data").join("license.jwt").is_file());
        // an upgrade: same secrets, the settings it was not given kept, the licence kept
        let first = env["JWT_SECRET"].clone();
        let again = Config { data: c.data.clone(), licence: None, msi: None, settings: BTreeMap::new() };
        assert!(configure(&again, Some(PUB)).unwrap().contains("kept"));
        let env2 = read_env(&c.data.join("provigil.env"));
        assert_eq!(env2["JWT_SECRET"], first);
        assert_eq!(env2["CLICKHOUSE_PASSWORD"], "pw");
        // a changed licence is refused, and nothing is replaced
        let bad = licence(&["siem"]).replace('.', "x.");
        std::fs::write(msi_dir.join("licence.jwt"), bad).unwrap();
        assert!(configure(&c, Some(PUB)).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_data_lake_and_a_licence_are_required() {
        let d = tmp("req");
        let c = Config { data: d.clone(), licence: None, msi: None, settings: BTreeMap::new() };
        assert!(configure(&c, Some(PUB)).unwrap_err().contains("CLICKHOUSE_URL"));
        let c = Config { data: d.clone(), licence: None, msi: None, settings: [("CLICKHOUSE_URL", "http://x:8123"), ("VALKEY_URL", "redis://x")].map(|(k, v)| (k.to_string(), v.to_string())).into() };
        assert!(configure(&c, Some(PUB)).unwrap_err().contains("no licence"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn every_program_is_known_and_the_console_gets_its_folders() {
        assert!(program("siem-api").is_some() && program("console").is_some() && program("x").is_none());
        let env: BTreeMap<_, _> = program_env(Path::new("C:\\PV"), Path::new("D:\\PD")).into_iter().collect();
        assert_eq!(env["CONSOLE_ROOT"], "C:\\PV\\console");
        assert_eq!(env["PROVIGIL_MANAGER_HOME"], "D:\\PD\\data\\manager");
        assert_eq!(env["PROVIGIL_SOURCE_DIR"], "C:\\PV\\ruleset");
    }
}
