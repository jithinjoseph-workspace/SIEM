//! Throughput benchmark of the event path (decode + rules + output), with a
//! small sampling profiler (Linux: SIGPROF + glibc `backtrace`).
//!
//! bench_events <manager home> <count> [winevt|syslog] [profile | live <wazuh-db home>]
//! "live" uses the daemon's own environment (labels from the running wazuh-db).
//! The home needs etc/ (ossec.conf, internal options), ruleset/ and a writable logs/.
//! With "profile", the hottest functions (self and inclusive) are printed via addr2line;
//! build with CARGO_PROFILE_RELEASE_DEBUG=1 for names.

use std::path::Path;
use std::time::Instant;

use siem_analysisd::ar::{AgentVersion, ArBackend};
use siem_analysisd::daemon::{Analysis, Env};
use siem_analysisd::daemon_config::AnalysisdConfig;
use siem_analysisd::labels::Label;

struct BenchEnv;

impl ArBackend for BenchEnv {
    fn agent_version(&mut self, _agent_id: i32) -> AgentVersion {
        AgentVersion::NoInfo
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        Some(vec![])
    }
    fn node_name(&mut self) -> String {
        "node01".into()
    }
    fn send_exec(&mut self, _msg: &[u8]) {}
    fn send_ar(&mut self, _msg: &[u8]) {}
}

impl Env for BenchEnv {
    fn labels(&mut self, _agent_id: &[u8]) -> Vec<Label> {
        Vec::new()
    }
    fn log(&self, _level: &str, _msg: &[u8]) {}
    fn ar(&mut self) -> &mut dyn ArBackend {
        self
    }
    fn agents_of_node(&mut self, _last_id: i32, _limit: i32) -> Option<Vec<i32>> {
        Some(vec![])
    }
}

/// A remoted-format message as the Windows agent sends it (1 in 20 is an error event).
fn winevt(n: usize) -> Vec<u8> {
    let (id, level, msg) = if n % 20 == 0 { (1000, 2, "Faulting application name: bench.exe") } else { (1001, 4, "Bench informational event") };
    format!(
        "f:[{a:03}] (bench-{a}) any->EventChannel:{{\"Message\":\"{msg} #{n}\",\"Event\":\"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='LoadTest'/><EventID Qualifiers='0'>{id}</EventID><Version>0</Version><Level>{level}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-10-16T00:00:00.0000000Z'/><EventRecordID>{n}</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='0'/><Channel>Application</Channel><Computer>bench-{a}</Computer><Security/></System><EventData><Data>{msg} #{n}</Data></EventData></Event>\"}}",
        a = agent(n)
    )
    .into_bytes()
}

/// The agent of event n: BENCH_AGENTS ids from BENCH_FIRST (default 50 from 100).
fn agent(n: usize) -> usize {
    let get = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    get("BENCH_FIRST", 100) + n % get("BENCH_AGENTS", 50)
}

fn syslog(n: usize) -> Vec<u8> {
    format!("1:[{a:03}] (bench-{a}) any->/var/log/auth.log:Oct 16 00:00:00 host sshd[{n}]: Failed password for invalid user u{n} from 10.0.0.{b} port 22 ssh2", a = 100 + n % 50, b = n % 250)
        .into_bytes()
}

#[cfg(target_os = "linux")]
mod prof {
    use std::sync::atomic::{AtomicUsize, Ordering};
    pub const DEPTH: usize = 48;
    pub const CAP: usize = 200_000;
    pub static mut SAMPLES: [[usize; DEPTH]; CAP] = [[0; DEPTH]; CAP];
    pub static N: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn on_prof(_: libc::c_int) {
        let i = N.fetch_add(1, Ordering::Relaxed);
        if i < CAP {
            // SAFETY: each slot is written by one signal only; read after the timer is stopped.
            unsafe {
                let p = std::ptr::addr_of_mut!(SAMPLES[i]) as *mut *mut libc::c_void;
                libc::backtrace(p, DEPTH as i32);
            }
        }
    }

    pub fn start(hz: i64) {
        // SAFETY: a plain signal handler and a profiling timer for this process.
        unsafe {
            let mut warm = [std::ptr::null_mut(); 4];
            libc::backtrace(warm.as_mut_ptr(), 4); // load libgcc before the first signal
            libc::signal(libc::SIGPROF, on_prof as usize);
            let us = 1_000_000 / hz;
            let t = libc::itimerval { it_interval: libc::timeval { tv_sec: 0, tv_usec: us }, it_value: libc::timeval { tv_sec: 0, tv_usec: us } };
            libc::setitimer(libc::ITIMER_PROF, &t, std::ptr::null_mut());
        }
    }

    pub fn stop() {
        // SAFETY: as above.
        unsafe {
            let t: libc::itimerval = std::mem::zeroed();
            libc::setitimer(libc::ITIMER_PROF, &t, std::ptr::null_mut());
        }
    }

    /// Symbolizes the samples and prints the top functions.
    pub fn report() {
        use std::collections::HashMap;
        let n = N.load(Ordering::Relaxed).min(CAP);
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let base = maps
            .lines()
            .find(|l| l.ends_with(exe.to_str().unwrap()))
            .and_then(|l| usize::from_str_radix(l.split('-').next().unwrap(), 16).ok())
            .unwrap();
        let mut addrs: Vec<usize> = Vec::new();
        // SAFETY: the timer is stopped.
        let samples = unsafe { &*std::ptr::addr_of!(SAMPLES) };
        for s in &samples[..n] {
            for &a in s.iter().take_while(|&&a| a != 0) {
                addrs.push(a.wrapping_sub(base).wrapping_sub(1));
            }
        }
        addrs.sort_unstable();
        addrs.dedup();
        let out = std::process::Command::new("addr2line")
            .args(["-f", "-C", "-e", exe.to_str().unwrap()])
            .args(addrs.iter().map(|a| format!("{a:#x}")))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let names: Vec<&str> = text.lines().step_by(2).collect();
        let name_of: HashMap<usize, String> = addrs
            .iter()
            .zip(names)
            .map(|(a, n)| {
                // drop the generic hash suffix and argument lists for grouping
                let n = n.split("::h").next().unwrap_or(n);
                (*a, n.to_string())
            })
            .collect();
        let mut selfc: HashMap<String, usize> = HashMap::new();
        let mut incl: HashMap<String, usize> = HashMap::new();
        for s in &samples[..n] {
            let frames: Vec<String> = s.iter().take_while(|&&a| a != 0).filter_map(|&a| name_of.get(&a.wrapping_sub(base).wrapping_sub(1)).cloned()).collect();
            // frame 0-1 are the handler and the signal trampoline
            if let Some(f) = frames.iter().find(|f| !f.contains("on_prof") && !f.contains("??") && !f.contains("__restore_rt")) {
                *selfc.entry(f.clone()).or_default() += 1;
            }
            let mut seen = std::collections::HashSet::new();
            for f in frames {
                if seen.insert(f.clone()) {
                    *incl.entry(f).or_default() += 1;
                }
            }
        }
        for (title, m) in [("SELF", selfc), ("INCLUSIVE", incl)] {
            let mut v: Vec<_> = m.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            println!("--- {title} ({n} samples)");
            for (f, c) in v.iter().filter(|(f, _)| !f.contains("on_prof") && !f.starts_with("std::") && !f.contains("??")).take(40) {
                println!("{:5.1}%  {}", 100.0 * *c as f64 / n as f64, f);
            }
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let home = Path::new(&a[1]);
    let count: usize = a[2].parse().unwrap();
    let kind = a.get(3).map(String::as_str).unwrap_or("winevt");
    let profile = a.get(4).map(|s| s == "profile").unwrap_or(false);
    let live = a.get(4).map(|s| s == "live").unwrap_or(false);
    let mut cfg = AnalysisdConfig::load(home, &home.join("etc/ossec.conf"), false).expect("config");
    cfg.global.stats = 0;
    cfg.global.forwarders_list.clear();
    let t0 = Instant::now();
    let mut analysis = Analysis::new(cfg, &siem_analysisd::daemon::StderrLogger, true).unwrap_or_else(|e| panic!("ruleset: {e}"));
    analysis.start().expect("log files");
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let mut env: Box<dyn Env> = if live {
        let wdb_home = Path::new(&a[5]);
        let wdb: std::sync::Arc<dyn siem_ipc::wdbc::WdbQuery> =
            std::sync::Arc::new(siem_ipc::wdbc::WdbcSocket::new(wdb_home.join(siem_ipc::wdbc::WDB_LOCAL_SOCK)));
        let log: std::sync::Arc<dyn siem_analysisd::daemon::Logger> = std::sync::Arc::new(siem_analysisd::daemon::StderrLogger);
        let ctx = siem_analysisd::daemon::Ctx { home: home.to_path_buf(), rt: rt.handle().clone(), wdb, log };
        Box::new(analysis.live_env(ctx))
    } else {
        Box::new(BenchEnv)
    };
    let env = &mut *env;
    analysis.init_decoders(env);
    eprintln!("ruleset loaded in {:.1} s", t0.elapsed().as_secs_f64());
    let gen: fn(usize) -> Vec<u8> = if kind == "syslog" { syslog } else { winevt };
    let msgs: Vec<Vec<u8>> = (0..count + 500).map(gen).collect();
    for m in &msgs[..500] {
        analysis.handle_message(env, m);
    }
    #[cfg(target_os = "linux")]
    if profile {
        prof::start(2000);
    }
    let t = Instant::now();
    for m in &msgs[500..] {
        analysis.handle_message(env, m);
    }
    let el = t.elapsed();
    #[cfg(target_os = "linux")]
    if profile {
        prof::stop();
    }
    analysis.files.flush();
    println!("{count} {kind} events in {:.2} s: {:.0} events/s, {:.1} us/event", el.as_secs_f64(), count as f64 / el.as_secs_f64(), el.as_micros() as f64 / count as f64);
    #[cfg(target_os = "linux")]
    if profile {
        prof::report();
    }
    let _ = profile;
}
