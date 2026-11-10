//! `os_integrator/integrator.c` (`OS_IntegratorD`): every alert from
//! `alerts.json` that matches an `<integration>` is written to a temp file
//! and handed to `integrations/<name>`.

use std::io::{BufRead, BufReader, Read, Write};

use siem_cjson::Json;
use siem_maild::alert::JQueue;
use siem_maild::log;

use crate::config::Integration;

/// `INTEGRATORDIR`
pub const INTEGRATORDIR: &str = "integrations";

/// `os_random()`: `random()` seeded like integratord's `srandom`.
pub struct Random(u64);

impl Random {
    pub fn new() -> Random {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1);
        Random(t ^ ((std::process::id() as u64) << 32) | 1)
    }

    pub fn next(&mut self) -> i64 {
        // xorshift64*; only the 31-bit range of random() matters
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        ((self.0.wrapping_mul(0x2545F4914F6CDD1D)) >> 33) as i64
    }
}

impl Default for Random {
    fn default() -> Self {
        Self::new()
    }
}

fn tmp_dir() -> String {
    if cfg!(unix) {
        "/tmp".into()
    } else {
        std::env::temp_dir().display().to_string().trim_end_matches(['\\', '/']).to_string()
    }
}

/// The script for an integration, when it exists.
fn script_path(name: &str) -> Option<String> {
    let p = format!("{INTEGRATORDIR}/{name}");
    if std::path::Path::new(&p).exists() {
        return Some(p);
    }
    // a Rust build of the scripts on Windows carries the .exe suffix
    let exe = format!("{p}.exe");
    (cfg!(windows) && std::path::Path::new(&exe).exists()).then_some(exe)
}

/// The integrations that can run, as `OS_IntegratorD` decides at start.
pub fn enable(list: &mut [Integration]) {
    for it in list.iter_mut() {
        it.enabled = true;
        let name = it.name.clone().unwrap_or_default();
        match script_path(&name) {
            Some(p) => it.path = Some(p),
            None => {
                it.enabled = false;
                log().error(format!("Unable to enable integration for: '{name}'. File not found inside '{INTEGRATORDIR}'."));
                continue;
            }
        }
        let missing = match name.as_str() {
            "slack" | "shuffle" => it.hookurl.is_none().then_some("Missing hook URL."),
            "pagerduty" | "virustotal" => it.apikey.is_none().then_some("Missing API Key."),
            "maltiverse" => {
                if it.hookurl.is_none() {
                    Some("Missing hook URL.")
                } else if it.apikey.is_none() {
                    Some("Missing API Key.")
                } else {
                    None
                }
            }
            n if n.starts_with("custom-") => None,
            _ => {
                it.enabled = false;
                log().error(format!("Invalid integration: '{name}'. Not currently supported."));
                None
            }
        };
        if let Some(m) = missing {
            it.enabled = false;
            log().error(format!("Unable to enable integration for: '{name}'. {m}"));
            continue;
        }
        if it.enabled {
            log().info(format!("Enabling integration for: '{name}'."));
        }
    }
}

fn cstr(j: Option<&Json>) -> Option<Vec<u8>> {
    match j {
        Some(Json::String(s)) => Some(s.clone()),
        Some(_) => Some(b"(null)".to_vec()),
        None => None,
    }
}

/// Whether integration `it` takes this alert (location, level, group, rule).
fn matches(it: &Integration, al: &Json, rule: &Json) -> bool {
    if let Some(loc) = &it.location {
        let Some(l) = al.get("location") else { return false };
        if !loc.is_match_bytes(l.as_bytes().unwrap_or_default()) {
            log().debug2("Skipping: Location doesn't match");
            return false;
        }
    }
    if it.level != 0 {
        let Some(l) = rule.get("level") else { return false };
        if (l.as_i32().unwrap_or(0) as u32) < it.level {
            log().debug2("Skipping: Alert level is too low");
            return false;
        }
    }
    if let Some(g) = &it.group {
        // C walks the comma list until the text ends: a trailing comma adds no empty name
        let mut names: Vec<&str> = g.split(',').collect();
        if names.last() == Some(&"") {
            names.pop();
        }
        let found = rule.get("groups").is_some_and(|groups| names.iter().any(|t| groups.children().iter().any(|x| x.as_bytes() == Some(t.as_bytes()))));
        if !found {
            log().debug2("Skipping: Group doesn't match.");
            return false;
        }
    }
    if let Some(ids) = &it.rule_id {
        let Some(id) = rule.get("id") else {
            log().debug2("Skipping: Alert does not containg rule id.");
            return false;
        };
        let id = siem_maild::alert::atoi(id.as_bytes().unwrap_or_default()) as u32;
        if !ids.iter().take_while(|&&x| x != 0).any(|&x| x == id) {
            log().debug2("Skipping: Rule doesn't match.");
            return false;
        }
    }
    true
}

/// The legacy (non-JSON) alert file. Like C it rewrites `full_log` and
/// `data.srcip` inside the alert itself, so later integrations see the result.
fn legacy_text(al: &mut Json, max_log: u32) -> Vec<u8> {
    if let Some(Json::String(s)) = al.get_mut("full_log") {
        let mut n = 0usize;
        let mut cut = None;
        for i in 0..s.len() {
            let c = s[i];
            s[i] = match c {
                b'\'' | b'`' | b'"' | b'!' | b'$' => b' ',
                b'\\' => b'/',
                b';' => b',',
                c if !(32..=122).contains(&c) => b' ',
                c => c,
            };
            n += 1;
            if n >= max_log as usize {
                cut = Some(i + 1);
                break;
            }
        }
        if let Some(end) = cut {
            s.truncate(end);
            for k in 1..=3 {
                if end >= k {
                    s[end - k] = b'.';
                }
            }
        }
    }
    if let Some(data) = al.get_mut("data") {
        if let Some(Json::String(s)) = data.get_mut("srcip") {
            for c in s.iter_mut() {
                *c = match *c {
                    b'\'' | b'\\' | b'`' => b' ',
                    b' ' => b' ',
                    x if !(46..=122).contains(&x) => b' ',
                    x => x,
                };
            }
        }
    }
    let rule = al.get("rule").cloned().unwrap_or(Json::object());
    let date = cstr(al.get("timestamp")).unwrap_or_default();
    let location = cstr(al.get("location")).unwrap_or_default();
    let rule_id = cstr(rule.get("id")).unwrap_or_default();
    let level = rule.get("level").and_then(Json::as_i32).unwrap_or(0);
    let desc = cstr(rule.get("description")).unwrap_or_default();
    let full_log = cstr(al.get("full_log")).unwrap_or_default();
    let srcip = al.get("data").and_then(|d| cstr(d.get("srcip"))).unwrap_or_default();
    let mut out = Vec::new();
    out.extend_from_slice(b"alertdate='");
    out.extend_from_slice(&date);
    out.extend_from_slice(b"'\nalertlocation='");
    out.extend_from_slice(&location);
    out.extend_from_slice(b"'\nruleid='");
    out.extend_from_slice(&rule_id);
    out.extend_from_slice(format!("'\nalertlevel='{level}'\nruledescription='").as_bytes());
    out.extend_from_slice(&desc);
    out.extend_from_slice(b"'\nalertlog='");
    out.extend_from_slice(&full_log);
    out.extend_from_slice(b"'\nsrcip='");
    out.extend_from_slice(&srcip);
    out.push(b'\'');
    out
}

/// `OS_StrBreak(' ', cmd, 9)`
fn split9(cmd: &str) -> Vec<String> {
    siem_regex::str_break(' ', cmd, 9).unwrap_or_default()
}

/// Runs one integration on one alert (the body of the per-integration loop).
pub fn run_integration(it: &Integration, al: &mut Json, rng: &mut Random) {
    let name = it.name.clone().unwrap_or_default();
    let now = chrono::Utc::now().timestamp();
    let mut exec_tmp_file = format!("{}/{name}-{now}-{}.alert", tmp_dir(), rng.next());
    let mut temp_created = false;
    match std::fs::File::create(&exec_tmp_file) {
        Err(_) => {
            log().debug2(format!("File {exec_tmp_file} couldn't be created."));
            exec_tmp_file.clear();
        }
        Ok(mut f) => {
            let body = if it.alert_format.as_deref().is_some_and(|f| f.starts_with("json")) {
                let mut b = al.print_unformatted();
                b.push(b'\n');
                b
            } else {
                legacy_text(al, it.max_log)
            };
            let _ = f.write_all(&body);
            temp_created = true;
            log().debug2(format!("File {exec_tmp_file} was written."));
        }
    }
    let mut opt_tmp_file = String::new();
    let mut opt_created = false;
    if let Some(o) = &it.options {
        opt_tmp_file = format!("{}/{name}-{now}-{}.options", tmp_dir(), rng.next());
        match std::fs::write(&opt_tmp_file, format!("{o}\n")) {
            Ok(()) => {
                opt_created = true;
                log().debug2(format!("File {opt_tmp_file} was written."));
            }
            Err(_) => {
                log().debug2(format!("File {opt_tmp_file} couldn't be created."));
                opt_tmp_file.clear();
            }
        }
    }
    let dbg = log().is_debug();
    let mut cmd = format!(
        "{INTEGRATORDIR} {exec_tmp_file} {} {} {} {} {} {}",
        it.apikey.as_deref().unwrap_or(""),
        it.hookurl.as_deref().unwrap_or(""),
        if dbg <= 0 { "" } else { "debug" },
        if opt_created { opt_tmp_file.as_str() } else { "" },
        it.timeout as i32,
        it.retries as i32
    );
    if cmd.len() >= 4095 {
        log().warn("String may be truncated because it is too long.");
        cmd.truncate(4094);
    }
    if dbg <= 0 {
        cmd.push_str(" > /dev/null 2>&1");
    }
    let argv = split9(&cmd);
    if !argv.is_empty() {
        let path = it.path.clone().unwrap_or_default();
        run(&path, &argv, &cmd, &name);
    }
    if temp_created {
        let _ = std::fs::remove_file(&exec_tmp_file);
    }
    if opt_created {
        let _ = std::fs::remove_file(&opt_tmp_file);
    }
}

/// `access(path, W_OK) == 0`
#[cfg(unix)]
fn writable(path: &str) -> bool {
    let c = std::ffi::CString::new(path).unwrap_or_default();
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// `wpopenv(path, argv, W_BIND_STDOUT | W_BIND_STDERR | W_CHECK_WRITE)` + `wpclose`.
fn run(path: &str, argv: &[String], full: &str, name: &str) {
    #[cfg(unix)]
    if writable(path) {
        log().error(format!("At wpopenv(): file '{path}' has write permissions."));
        log().error(format!("Couldn't execute command ({full}). Check file and permissions."));
        return;
    }
    let (reader, writer) = match std::io::pipe() {
        Ok(p) => p,
        Err(e) => {
            log().error(format!("Could not launch command {} ({})", crate::strerror(&e), e.raw_os_error().unwrap_or(0)));
            return;
        }
    };
    let mut c = std::process::Command::new(path);
    c.args(&argv[1..]).stdin(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.arg0(&argv[0]);
    }
    let Ok(w2) = writer.try_clone() else { return };
    c.stdout(writer).stderr(w2);
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(_) => {
            // the forked child's execv failed: exit status 127
            drop(c);
            log().error(format!("Couldn't execute command ({full}). Check file and permissions."));
            return;
        }
    };
    drop(c);
    let mut last = Vec::new();
    let mut r = BufReader::new(reader);
    loop {
        // fgets(buffer, 4096)
        let mut line = Vec::new();
        let n = r.by_ref().take(4095).read_until(b'\n', &mut line).unwrap_or(0);
        if n == 0 {
            break;
        }
        log().debug2(&line);
        last = line;
    }
    let st = child.wait();
    match st.ok().and_then(|s| s.code()) {
        Some(0) => log().debug1("Command ran successfully."),
        Some(127) => log().error(format!("Couldn't execute command ({full}). Check file and permissions.")),
        Some(code) => {
            log().error(format!("Unable to run integration for {name} -> {INTEGRATORDIR}"));
            let mut m = format!("While running {name} -> {INTEGRATORDIR}. Output: ").into_bytes();
            m.extend_from_slice(&last);
            m.push(b' ');
            log().error(m);
            log().error(format!("Exit status was: {code}"));
        }
        None => log().error(format!("Command ({full}) execution exited abnormally.")),
    }
}

/// `OS_IntegratorD`
pub fn os_integratord(mut list: Vec<Integration>) -> ! {
    let sleep = |s: u64| std::thread::sleep(std::time::Duration::from_secs(s));
    let mut jq = JQueue::default();
    let mut tries = 1;
    while tries < 100 && jq.open(true) < 0 {
        sleep(1);
        tries += 1;
    }
    if tries == 100 {
        log().error(format!("Could not open JSON queue after {tries} tries."));
    } else {
        log().debug1("JSON file queue connected.");
    }
    enable(&mut list);
    let mut rng = Random::new();
    loop {
        log().debug2("jqueue_next()");
        let Some(mut al) = jq.next(&sleep) else {
            sleep(1);
            continue;
        };
        process_alert(&list, &mut al, &mut rng);
    }
}

/// One alert through every integration.
pub fn process_alert(list: &[Integration], al: &mut Json, rng: &mut Random) {
    log().debug1("Sending new alert.");
    let Some(rule) = al.get("rule").cloned() else {
        log().debug2("Skipping: Alert does not contain a rule block.");
        return;
    };
    for it in list {
        if !it.enabled {
            log().debug2("Skipping: Integration disabled");
            continue;
        }
        if !matches(it, al, &rule) {
            continue;
        }
        run_integration(it, al, rng);
    }
}
