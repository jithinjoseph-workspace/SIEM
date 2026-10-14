//! `syscollector-run <seconds> <dbpath>`: the counterpart of the C
//! `syscollector_start` test harness (scan on start, every category, a long
//! interval). Prints `D <delta>`, `S <sync>`, `L <level> <log>` lines, then
//! stops the module.

#[cfg(not(windows))]
fn main() {
    eprintln!("syscollector-run: the Windows provider only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use siem_syscollector::port::syscollector::{LogLevel, Options, Syscollector};

    let args: Vec<String> = std::env::args().collect();
    let secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(30);
    let db = args.get(2).cloned().unwrap_or_else(|| ".\\local.db".into());
    // The agent starts Winsock before the modules run.
    unsafe {
        let mut d: windows_sys_wsadata::WSADATA = std::mem::zeroed();
        windows_sys_wsadata::WSAStartup(0x0202, &mut d);
    }
    let out = Arc::new(Mutex::new(()));
    let line = move |tag: &str, b: &[u8]| {
        let _g = out.lock().unwrap();
        let mut o = std::io::stdout().lock();
        let _ = o.write_all(tag.as_bytes());
        let _ = o.write_all(b);
        let _ = o.write_all(b"\n");
        let _ = o.flush();
    };
    let l = Arc::new(line);
    let (l1, l2, l3) = (l.clone(), l.clone(), l.clone());
    let level = |lv: LogLevel| match lv {
        LogLevel::Debug => 0,
        LogLevel::Info => 1,
        LogLevel::Warning => 2,
        LogLevel::Error => 3,
        LogLevel::ErrorExit => 4,
        LogLevel::DebugVerbose => 5,
    };
    let log: siem_syscollector::port::syscollector::LogFn = Arc::new(move |lv, m: &str| l3(&format!("L {} ", level(lv)), m.as_bytes()));
    let l4 = log.clone();
    siem_dbsync::initialize(move |m: &[u8]| l4(LogLevel::Error, &String::from_utf8_lossy(m)));
    let o = Options {
        interval: 3600,
        scan_on_start: true,
        hardware: true,
        os: true,
        network: true,
        packages: true,
        ports: true,
        ports_all: false,
        processes: true,
        hotfixes: true,
        groups: true,
        users: true,
        services: true,
        browser_extensions: true,
        notify_on_first_scan: false,
    };
    let t = std::thread::spawn(move || {
        let _ = Syscollector::instance().init(
            Arc::new(siem_sysinfo::SysInfo),
            Arc::new(move |d| l1("D ", d)),
            Arc::new(move |d| l2("S ", d)),
            log,
            &db,
            ".\\norm_config.json",
            "windows",
            o,
        );
    });
    std::thread::sleep(std::time::Duration::from_secs(secs));
    Syscollector::instance().destroy();
    let _ = t.join();
}

#[cfg(windows)]
mod windows_sys_wsadata {
    #[repr(C)]
    pub struct WSADATA {
        _b: [u8; 512],
    }
    extern "system" {
        pub fn WSAStartup(v: u16, d: *mut WSADATA) -> i32;
    }
    #[link(name = "ws2_32")]
    extern "C" {}
}
