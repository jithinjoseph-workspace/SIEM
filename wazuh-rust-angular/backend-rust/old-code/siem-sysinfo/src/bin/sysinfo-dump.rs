//! `sysinfo-dump <category>`: one category's JSON (nlohmann `dump()`), the
//! counterpart of the C `sysinfo_<category>` test harness.

#[cfg(not(windows))]
fn main() {
    eprintln!("sysinfo-dump: the Windows provider only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::io::Write;
    let cat = std::env::args().nth(1).unwrap_or_default();
    // The agent starts Winsock before the modules run.
    unsafe {
        let mut d: windows_sys::Win32::Networking::WinSock::WSADATA = std::mem::zeroed();
        windows_sys::Win32::Networking::WinSock::WSAStartup(0x0202, &mut d);
    }
    let si = siem_sysinfo::SysInfo;
    let r = match cat.as_str() {
        "hardware" => si.hardware(),
        "os" => si.os(),
        "processes" => si.processes(),
        "hotfixes" => si.hotfixes(),
        "networks" => si.networks(),
        "ports" => si.ports(),
        "services" => si.services(),
        "groups" => si.groups(),
        "users" => si.users(),
        "packages" => si.packages(),
        "browser_extension" => si.browser_extensions(),
        _ => {
            println!("usage");
            std::process::exit(2);
        }
    };
    match r.map(|v| v.dump()) {
        Ok(Ok(d)) => {
            let mut o = std::io::stdout();
            let _ = o.write_all(&d);
            let _ = o.write_all(b"\n");
        }
        Ok(Err(e)) => {
            eprintln!("dump: {}", String::from_utf8_lossy(&e));
            std::process::exit(1);
        }
        Err(e) => {
            println!("rc -1 ({e})");
            std::process::exit(1);
        }
    }
}
