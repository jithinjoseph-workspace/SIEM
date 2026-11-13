//! Linux runtime process, listening port, and systemd/SysV service collection via `/proc` and
//! `systemctl`, matching the Windows schemas returned by `provigil_collect::win`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg_attr(not(unix), allow(unused_imports))]
use crate::{nonempty, tcp_state, PortInfo, ProcessInfo, ServiceInfo};

/// Parse `/etc/passwd` contents into a `uid -> username` map.
pub(crate) fn parse_passwd_uids(content: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(':');
        let Some(name) = parts.next() else { continue };
        let _pw = parts.next();
        let Some(uid_str) = parts.next() else { continue };
        if let Ok(uid) = uid_str.parse::<u32>() {
            map.entry(uid).or_insert_with(|| name.to_string());
        }
    }
    map
}

/// Extract `Uid` (real UID) and `VmSize` (kB) and `VmRSS` (kB) from `/proc/<pid>/status`.
pub(crate) fn parse_proc_status(content: &str) -> (Option<u32>, Option<u64>, Option<u64>, Option<u32>) {
    let mut uid = None;
    let mut vm_size_kb = None;
    let mut vm_rss_kb = None;
    let mut tgid = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().and_then(|s| s.parse::<u32>().ok());
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            vm_size_kb = rest.split_whitespace().next().and_then(|s| s.parse::<u64>().ok());
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            vm_rss_kb = rest.split_whitespace().next().and_then(|s| s.parse::<u64>().ok());
        } else if let Some(rest) = line.strip_prefix("Tgid:") {
            tgid = rest.split_whitespace().next().and_then(|s| s.parse::<u32>().ok());
        }
    }
    (uid, vm_size_kb, vm_rss_kb, tgid)
}

pub(crate) struct ProcStatFields {
    pub pid: u32,
    pub comm: String,
    pub parent_pid: u32,
    pub session_id: u32,
    pub priority: i32,
    pub threads: u32,
    pub cpu_time_ms: u64,
    pub start_time: u64,
    pub virtual_kb: u64,
    pub rss_kb: u64,
}

/// Parse `/proc/<pid>/stat`, safely handling process names that contain spaces or `)`.
pub(crate) fn parse_proc_stat(
    content: &str,
    ticks_per_sec: u64,
    boot_time: u64,
    page_size_kb: u64,
) -> Option<ProcStatFields> {
    let lparen = content.find('(')?;
    let rparen = content.rfind(')')?;
    if rparen <= lparen {
        return None;
    }
    let pid: u32 = content[..lparen].trim().parse().ok()?;
    let comm = content[lparen + 1..rparen].to_string();
    let after: Vec<&str> = content[rparen + 1..].split_whitespace().collect();
    // Index mapping after `comm)` (field 2):
    // 0:state(3), 1:ppid(4), 2:pgrp(5), 3:session(6), 4:tty_nr(7), 5:tpgid(8), 6:flags(9),
    // 7:minflt(10), 8:cminflt(11), 9:majflt(12), 10:cmajflt(13), 11:utime(14), 12:stime(15),
    // 13:cutime(16), 14:cstime(17), 15:priority(18), 16:nice(19), 17:num_threads(20),
    // 18:itrealvalue(21), 19:starttime(22), 20:vsize(23), 21:rss(24)
    if after.len() < 22 {
        return None;
    }
    let parent_pid = after[1].parse::<u32>().unwrap_or(0);
    let session_id = after[3].parse::<u32>().unwrap_or(0);
    let utime = after[11].parse::<u64>().unwrap_or(0);
    let stime = after[12].parse::<u64>().unwrap_or(0);
    let priority = after[15].parse::<i32>().unwrap_or(0);
    let threads = after[17].parse::<u32>().unwrap_or(1);
    let starttime_ticks = after[19].parse::<u64>().unwrap_or(0);
    let vsize_bytes = after[20].parse::<u64>().unwrap_or(0);
    let rss_pages = after[21].parse::<u64>().unwrap_or(0);

    let tps = ticks_per_sec.max(1);
    let cpu_time_ms = ((utime + stime) * 1000) / tps;
    let start_time = boot_time + (starttime_ticks / tps);
    Some(ProcStatFields {
        pid,
        comm,
        parent_pid,
        session_id,
        priority,
        threads,
        cpu_time_ms,
        start_time,
        virtual_kb: vsize_bytes / 1024,
        rss_kb: rss_pages * page_size_kb,
    })
}

/// Decode a kernel `/proc/net/{tcp,udp}` IPv4 or IPv6 hex address into dotted-quad or canonical IPv6.
pub(crate) fn decode_proc_net_addr(addr_port: &str, v6: bool) -> Option<(String, u16)> {
    let (hex_ip, hex_port) = addr_port.split_once(':')?;
    let port = u16::from_str_radix(hex_port, 16).ok()?;
    if !v6 {
        if hex_ip.len() != 8 {
            return None;
        }
        let word = u32::from_str_radix(hex_ip, 16).ok()?;
        let ip = Ipv4Addr::from(word.to_ne_bytes());
        return Some((ip.to_string(), port));
    }
    if hex_ip.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (idx, dst) in bytes.chunks_exact_mut(4).enumerate() {
        let word = u32::from_str_radix(&hex_ip[idx * 8..(idx + 1) * 8], 16).ok()?;
        dst.copy_from_slice(&word.to_ne_bytes());
    }
    Some((Ipv6Addr::from(bytes).to_string(), port))
}

/// Map Linux `/proc/net/tcp*` state hex (`"0A"`, `"01"`, ...) to Win32-aligned state string.
pub(crate) fn proc_tcp_state(hex_state: &str) -> Option<&'static str> {
    match u8::from_str_radix(hex_state.trim(), 16).ok()? {
        // Linux TCP_ESTABLISHED..TCP_CLOSING map to the same canonical states as MIB_TCP_STATE_*
        1 => Some("established"),
        2 => Some("syn_sent"),
        3 => Some("syn_recv"),
        4 => Some("fin_wait1"),
        5 => Some("fin_wait2"),
        6 => Some("time_wait"),
        7 => Some("closed"),
        8 => Some("close_wait"),
        9 => Some("last_ack"),
        10 => Some("listening"),
        11 => Some("closing"),
        n => Some(tcp_state(n as u32)),
    }
}

/// Parse `/proc/net/{tcp,tcp6,udp,udp6}` table lines into `PortInfo` entries.
pub(crate) fn parse_proc_net(
    content: &str,
    protocol: &str,
    v6: bool,
    inode_pid: &HashMap<u64, (u32, String)>,
) -> Vec<PortInfo> {
    let is_udp = protocol.starts_with("udp");
    let mut ports = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((local_ip, local_port)) = decode_proc_net_addr(cols[1], v6) else { continue };
        let remote = decode_proc_net_addr(cols[2], v6);
        let state = if is_udp {
            None
        } else {
            proc_tcp_state(cols[3]).map(str::to_string)
        };
        let (remote_ip, remote_port) = match remote {
            Some((rip, rport)) if rport > 0 => (Some(rip), Some(rport)),
            _ => (None, None),
        };
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let (pid, process) = if inode > 0 {
            inode_pid
                .get(&inode)
                .map(|(p, n)| (*p, Some(n.clone())))
                .unwrap_or((0, None))
        } else {
            (0, None)
        };
        ports.push(PortInfo {
            protocol: protocol.to_string(),
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state,
            pid,
            process,
        });
    }
    ports
}

/// Parse `systemctl list-units --type=service --all --no-pager --no-legend --plain` rows.
pub(crate) fn parse_systemctl_units(content: &str) -> Vec<(String, String, String, String)> {
    let mut rows = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let unit = parts[0].to_string();
        if !unit.ends_with(".service") {
            continue;
        }
        let active = parts[2];
        let sub = parts[3];
        let state = match (active, sub) {
            (_, "running") => "running",
            ("activating", _) => "starting",
            ("deactivating", _) => "stopping",
            (_, "paused") => "paused",
            _ => "stopped",
        };
        let desc = parts[4..].join(" ");
        rows.push((unit, state.to_string(), sub.to_string(), desc));
    }
    rows
}

/// Parse `systemctl list-unit-files --type=service --no-pager --no-legend --plain` rows.
pub(crate) fn parse_systemctl_unit_files(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(unit) = parts.next() else { continue };
        let Some(state) = parts.next() else { continue };
        if unit.ends_with(".service") {
            let startup = match state {
                "enabled" | "enabled-runtime" | "alias" => "auto",
                "disabled" => "disabled",
                "static" | "indirect" => "manual",
                "masked" | "masked-runtime" => "disabled",
                other => other,
            };
            map.entry(unit.to_string()).or_insert_with(|| startup.to_string());
        }
    }
    map
}

/// Parse `systemctl show <units...> -p Id,Description,MainPID,ExecStart,User,UnitFileState` stanzas.
pub(crate) fn parse_systemctl_show(content: &str) -> HashMap<String, (Option<u32>, Option<String>, Option<String>, Option<String>)> {
    let mut map = HashMap::new();
    for stanza in content.split("\n\n") {
        let mut id = None;
        let mut pid = None;
        let mut path = None;
        let mut account = None;
        let mut desc = None;
        for line in stanza.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            match k {
                "Id" => id = nonempty(v),
                "MainPID" => {
                    if let Ok(p) = v.trim().parse::<u32>() {
                        if p > 0 {
                            pid = Some(p);
                        }
                    }
                }
                "ExecStart" => {
                    // Format: `{ path=/usr/sbin/sshd ; argv[]=... }`
                    if let Some(p) = v
                        .split("path=")
                        .nth(1)
                        .and_then(|s| s.split(';').next())
                        .and_then(nonempty)
                    {
                        path = Some(p);
                    }
                }
                "User" => account = nonempty(v),
                "Description" => desc = nonempty(v),
                _ => {}
            }
        }
        if let Some(unit) = id {
            map.insert(unit, (pid, path, account, desc));
        }
    }
    map
}

/// Extract clean `startup_type` for a unit from `unit_files` map with a sensible fallback.
pub(crate) fn normalize_unit_startup(unit: &str, unit_files: &HashMap<String, String>) -> String {
    unit_files
        .get(unit)
        .cloned()
        .unwrap_or_else(|| "manual".to_string())
}

#[cfg(unix)]
fn read_boot_time() -> u64 {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("btime "))
                .and_then(|v| v.trim().parse::<u64>().ok())
        })
        .unwrap_or(0)
}

#[cfg(unix)]
fn clock_ticks_per_sec() -> u64 {
    // 100 Hz (USER_HZ) is invariant across x86_64/aarch64 Linux user ABI.
    100
}

#[cfg(unix)]
fn page_size_kb() -> u64 {
    // Standard 4 KiB page fallback; read `/proc/self/smaps` or default to 4 KiB.
    4
}

#[cfg(unix)]
fn socket_inode_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return map };
    for entry in rd.flatten() {
        let fname = entry.file_name();
        let Some(pid_str) = fname.to_str() else { continue };
        let Ok(pid) = pid_str.parse::<u32>() else { continue };
        let pdir = entry.path();
        let comm = std::fs::read_to_string(pdir.join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if comm.is_empty() {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(pdir.join("fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else { continue };
            let s = target.to_string_lossy();
            if let Some(inode) = s.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                if let Ok(ino) = inode.parse::<u64>() {
                    map.entry(ino).or_insert_with(|| (pid, comm.clone()));
                }
            }
        }
    }
    map
}

#[cfg(unix)]
pub fn processes() -> Result<Vec<ProcessInfo>, String> {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let uids = parse_passwd_uids(&passwd);
    let tps = clock_ticks_per_sec();
    let btime = read_boot_time();
    let pskb = page_size_kb();

    let rd = std::fs::read_dir("/proc").map_err(|e| format!("/proc: {e}"))?;
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let pdir = entry.path();
        let Ok(stat_text) = std::fs::read_to_string(pdir.join("stat")) else { continue };
        let Some(fields) = parse_proc_stat(&stat_text, tps, btime, pskb) else { continue };
        let status_text = std::fs::read_to_string(pdir.join("status")).unwrap_or_default();
        let (uid, vm_size_kb, vm_rss_kb, tgid) = parse_proc_status(&status_text);
        // Skip kernel threads that aren't standalone processes if tgid mismatches
        if let Some(t) = tgid {
            if t != pid {
                continue;
            }
        }
        let raw_cmd = std::fs::read(pdir.join("cmdline")).unwrap_or_default();
        let cmdline = if raw_cmd.is_empty() {
            None
        } else {
            let s = raw_cmd
                .split(|&b| b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            nonempty(&s)
        };
        let owner = uid.map(|u| uids.get(&u).cloned().unwrap_or_else(|| u.to_string()));
        let mem_kb = vm_rss_kb.unwrap_or(fields.rss_kb);
        out.push(ProcessInfo {
            pid: fields.pid,
            name: fields.comm,
            command_line: cmdline,
            owner,
            parent_pid: fields.parent_pid,
            memory_mb: mem_kb / 1024,
            cpu_time_ms: fields.cpu_time_ms,
            start_time: fields.start_time,
            priority: fields.priority,
            threads: fields.threads,
            virtual_kb: vm_size_kb.or(Some(fields.virtual_kb)),
            session_id: Some(fields.session_id),
        });
    }
    Ok(out)
}

#[cfg(unix)]
pub fn ports() -> Result<Vec<PortInfo>, String> {
    let inodes = socket_inode_map();
    let mut out = Vec::new();
    let mut any_ok = false;
    let mut last_err = String::new();
    for (file, proto, v6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp6", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp6", true),
    ] {
        match std::fs::read_to_string(file) {
            Ok(text) => {
                any_ok = true;
                out.extend(parse_proc_net(&text, proto, v6, &inodes));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => last_err = format!("{file}: {e}"),
        }
    }
    if !any_ok && !last_err.is_empty() {
        return Err(last_err);
    }
    Ok(out)
}

#[cfg(unix)]
pub fn services() -> Result<Vec<ServiceInfo>, String> {
    use std::process::Command;

    let unit_files = Command::new("systemctl")
        .args(["list-unit-files", "--type=service", "--no-pager", "--no-legend", "--plain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_systemctl_unit_files(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();

    let units_out = Command::new("systemctl")
        .args(["list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"])
        .output();

    if let Ok(out) = units_out {
        if out.status.success() {
            let parsed = parse_systemctl_units(&String::from_utf8_lossy(&out.stdout));
            if !parsed.is_empty() {
                let names: Vec<String> = parsed.iter().map(|(u, _, _, _)| u.clone()).collect();
                let mut details = HashMap::new();
                for chunk in names.chunks(64) {
                    let mut cmd = Command::new("systemctl");
                    cmd.args(["show", "--no-pager", "-p", "Id,Description,MainPID,ExecStart,User"]);
                    cmd.args(chunk);
                    if let Ok(show_out) = cmd.output() {
                        if show_out.status.success() {
                            details.extend(parse_systemctl_show(&String::from_utf8_lossy(&show_out.stdout)));
                        }
                    }
                }
                let mut services = Vec::with_capacity(parsed.len());
                for (unit, state, _sub, list_desc) in parsed {
                    let (pid, path, account, show_desc) = details.remove(&unit).unwrap_or((None, None, None, None));
                    let desc = show_desc.or_else(|| nonempty(&list_desc));
                    let startup_type = normalize_unit_startup(&unit, &unit_files);
                    services.push(ServiceInfo {
                        display_name: desc.clone().unwrap_or_else(|| unit.clone()),
                        name: unit,
                        state,
                        startup_type,
                        account: account.or_else(|| Some("root".to_string())),
                        path,
                        pid,
                        description: desc,
                    });
                }
                return Ok(services);
            }
        }
    }

    // Fallback for non-systemd Linux containers / init systems: /etc/init.d scripts.
    let mut initd = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/etc/init.d") {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "README" || name == "rc" || name == "rcS" {
                continue;
            }
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            initd.push(ServiceInfo {
                display_name: name.clone(),
                name,
                state: "unknown".to_string(),
                startup_type: "manual".to_string(),
                account: Some("root".to_string()),
                path: Some(p.display().to_string()),
                pid: None,
                description: None,
            });
        }
    }
    Ok(initd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_passwd_uids() {
        let text = "root:x:0:0:root:/root:/bin/bash\n#comment\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
        let m = parse_passwd_uids(text);
        assert_eq!(m.get(&0).map(String::as_str), Some("root"));
        assert_eq!(m.get(&33).map(String::as_str), Some("www-data"));
    }

    #[test]
    fn parses_proc_stat_with_spaces_in_comm() {
        let line = "4210 (Web Content) S 100 4210 100 0 -1 4194304 100 0 0 0 250 50 0 0 20 0 8 0 12345 104857600 4096";
        let p = parse_proc_stat(line, 100, 1_700_000_000, 4).unwrap();
        assert_eq!(p.pid, 4210);
        assert_eq!(p.comm, "Web Content");
        assert_eq!(p.parent_pid, 100);
        assert_eq!(p.threads, 8);
        assert_eq!(p.cpu_time_ms, 3000);
        assert_eq!(p.start_time, 1_700_000_123);
        assert_eq!(p.virtual_kb, 102400);
        assert_eq!(p.rss_kb, 16384);
    }

    #[test]
    fn parses_proc_net_tcp_and_udp6() {
        let tcp = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18442 1 00000000 100 0 0 10 0
   1: 0100007F:1538 0200000A:C350 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 00000000 20 4 30 10 -1
";
        let mut inodes = HashMap::new();
        inodes.insert(18442, (901, "sshd".to_string()));
        let parsed = parse_proc_net(tcp, "tcp", false, &inodes);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].local_ip, "0.0.0.0");
        assert_eq!(parsed[0].local_port, 22);
        assert_eq!(parsed[0].state.as_deref(), Some("listening"));
        assert_eq!(parsed[0].pid, 901);
        assert_eq!(parsed[0].process.as_deref(), Some("sshd"));
        assert_eq!(parsed[1].local_ip, "127.0.0.1");
        assert_eq!(parsed[1].local_port, 5432);
        assert_eq!(parsed[1].remote_ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(parsed[1].remote_port, Some(50000));
        assert_eq!(parsed[1].state.as_deref(), Some("established"));

        let udp6 = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000000000000000000001000000:0143 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 555 2 00000000 0
";
        let uparsed = parse_proc_net(udp6, "udp6", true, &HashMap::new());
        assert_eq!(uparsed.len(), 1);
        assert_eq!(uparsed[0].local_ip, "::1");
        assert_eq!(uparsed[0].local_port, 323);
        assert_eq!(uparsed[0].state, None);
    }

    #[test]
    fn parses_systemctl_outputs() {
        let units = "\
ssh.service                 loaded active   running OpenBSD Secure Shell server
systemd-journald.service    loaded active   running Journal Service
apt-daily.service           loaded inactive dead    Daily apt download activities
";
        let uf = "\
ssh.service enabled
apt-daily.service static
";
        let show = "\
Id=ssh.service
Description=OpenBSD Secure Shell server
MainPID=901
ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no }
User=

Id=apt-daily.service
Description=Daily apt download activities
MainPID=0
ExecStart={ path=/usr/lib/apt/apt.systemd.daily ; argv[]=/usr/lib/apt/apt.systemd.daily }
";
        let parsed = parse_systemctl_units(units);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].1, "running");
        assert_eq!(parsed[2].1, "stopped");
        let files = parse_systemctl_unit_files(uf);
        assert_eq!(normalize_unit_startup("ssh.service", &files), "auto");
        assert_eq!(normalize_unit_startup("apt-daily.service", &files), "manual");
        let shown = parse_systemctl_show(show);
        assert_eq!(shown["ssh.service"].0, Some(901));
        assert_eq!(shown["ssh.service"].1.as_deref(), Some("/usr/sbin/sshd"));
        assert_eq!(shown["ssh.service"].2, None);
    }
}
