//! Port of `wazuh-csyslogd` (`src/os_csyslogd`, Wazuh 4.14.7): forwards
//! alerts to remote syslog servers over UDP in the default, CEF, JSON or
//! Splunk format, filtered by level, rule, group and location.

pub mod alert;
pub mod config;

use std::net::UdpSocket;

use siem_maild::log;

pub use config::Syslog;

/// `OS_GetHost(host, attempts)`: the first IPv4 or IPv6 address.
pub fn get_host(host: &str, attempts: u32) -> Option<String> {
    use std::net::ToSocketAddrs;
    for i in 0..=attempts {
        match (host, 0).to_socket_addrs() {
            Ok(mut a) => return a.next().map(|s| s.ip().to_string()),
            Err(_) => {
                if i < attempts {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }
    None
}

/// `resolve_hostname`: an IP stays as is, a name becomes "name/ip" (or "name/").
pub fn resolve_hostname(server: &mut String, attempts: u32) {
    if siem_regex::is_valid_ip(server).0 == 1 {
        return;
    }
    let name = server.split('/').next().unwrap_or("").to_string();
    *server = match get_host(&name, attempts) {
        Some(ip) => format!("{name}/{ip}"),
        None => format!("{name}/"),
    };
    server.truncate(126);
}

/// `get_ip_from_resolved_hostname`
pub fn ip_of(server: &str) -> &str {
    server.split_once('/').map(|(_, ip)| ip).unwrap_or(server)
}

/// `OS_ConnectUDP(port, ip, ipv6 = 0, 0)`: IPv4 only, as csyslogd asks.
pub fn connect_udp(port: u32, ip: &str) -> std::io::Result<UdpSocket> {
    let addr: std::net::Ipv4Addr = ip.parse().map_err(|_| std::io::Error::from_raw_os_error(22))?;
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect((addr, port as u16))?;
    Ok(s)
}

/// `OS_SendUDPbySize`: retries only while the kernel is out of buffers.
pub fn send_udp(s: &UdpSocket, msg: &[u8]) -> bool {
    let mut i = 0;
    loop {
        match s.send(msg) {
            Ok(_) => return true,
            Err(e) if e.raw_os_error() == Some(105) && i < 5 => {
                i += 1;
                log().info(format!("Remote socket busy, waiting {i} s."));
                std::thread::sleep(std::time::Duration::from_secs(i));
            }
            Err(_) => return false,
        }
    }
}

/// `strerror(errno)` text of an I/O error.
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.split(" (os error").next().unwrap_or(&s).to_string()
}

/// The host names put in the messages (`__shost`, `__shost_long`).
pub struct Hostnames {
    pub short: String,
    pub long: String,
}

impl Hostnames {
    pub fn get() -> Hostnames {
        let long = siem_ipc::os_net::gethostname(511).map(|h| String::from_utf8_lossy(&h).into_owned()).unwrap_or_default();
        let short = long.split('.').next().unwrap_or("").to_string();
        Hostnames { short, long }
    }
}

/// `OS_CSyslogD`
pub fn os_csyslogd(shared: std::sync::Arc<std::sync::Mutex<Vec<Syslog>>>, hosts: &Hostnames) -> ! {
    use siem_maild::alert::{FileQueue, JQueue};
    let sleep = |s: u64| std::thread::sleep(std::time::Duration::from_secs(s));
    let mut guard = shared.lock().unwrap();
    let list = &mut *guard;
    let mut want_log = list.iter().any(|c| c.format != config::JSON_CSYSLOG);
    let mut want_json = list.iter().any(|c| c.format == config::JSON_CSYSLOG);
    let mut fq = None;
    if want_log {
        // Init_FileQueue only fails on seek/stat errors: never in practice
        fq = Some(FileQueue::init(None, 0));
        log().debug1("File queue connected.");
    }
    let mut jq = JQueue::default();
    if want_json {
        let mut tries = 1;
        while tries < 10 && jq.open(true) < 0 {
            sleep(1);
            tries += 1;
        }
        if tries == 10 {
            log().error(format!("Could not open JSON queue after {tries} tries."));
            want_json = false;
        } else {
            log().debug1("JSON file queue connected.");
        }
    }
    if !want_log && !want_json {
        log().error("No configurations available. Exiting.");
        std::process::exit(1);
    }
    if fq.is_none() {
        want_log = false;
    }
    for c in list.iter_mut() {
        log().debug2(format!("Resolving server hostname: {}", c.server));
        resolve_hostname(&mut c.server, 5);
        match connect_udp(c.port, ip_of(&c.server)) {
            Ok(s) => {
                c.socket = Some(s);
                log().info(format!("Forwarding alerts via syslog to: '{}:{}'.", c.server, c.port));
            }
            Err(e) => log().error(format!("(1216): Unable to connect to '[{}]:{}/udp': '{}'.", c.server, c.port, strerror(&e))),
        }
    }
    loop {
        let mut al = None;
        let mut js = None;
        if want_log {
            log().debug2("Read_FileMon()");
            al = fq.as_mut().and_then(|q| q.read_filemon(1, &sleep));
        }
        if want_json {
            log().debug2("jqueue_next()");
            js = jq.next(&sleep);
        }
        if al.is_none() && js.is_none() {
            drop(guard);
            sleep(1);
            guard = shared.lock().unwrap();
            continue;
        }
        let mut al = al;
        for c in guard.iter_mut() {
            if c.format == config::JSON_CSYSLOG {
                if let Some(j) = js.as_mut() {
                    alert::send_json(j, c, hosts);
                }
            } else if let Some(a) = al.as_mut() {
                alert::send_log(a, c, hosts);
            }
        }
    }
}
