//! Linux Ports provider (`sysInfoLinux.cpp` / `ports/`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use super::Error;
use crate::json::{i, s, Obj, Value};
use crate::UNKNOWN_VALUE;

fn parse_hex_ipv4(hex_str: &str) -> Option<String> {
    let num = u32::from_str_radix(hex_str, 16).ok()?;
    let ip = Ipv4Addr::from(num.to_be());
    Some(ip.to_string())
}

fn parse_hex_ipv6(hex_str: &str) -> Option<String> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex_str[i * 8..(i + 1) * 8];
        let val = u32::from_str_radix(chunk, 16).ok()?;
        let be_bytes = val.to_be_bytes();
        octets[i * 4..(i + 1) * 4].copy_from_slice(&be_bytes);
    }
    Some(Ipv6Addr::from(octets).to_string())
}

fn tcp_state_name(state_hex: &str) -> &'static str {
    match state_hex {
        "01" => "listening",
        "02" => "syn_sent",
        "03" => "syn_recv",
        "04" => "fin_wait1",
        "05" => "fin_wait2",
        "06" => "time_wait",
        "07" => "close",
        "08" => "close_wait",
        "09" => "last_ack",
        "0A" => "listening",
        "0B" => "closing",
        _ => UNKNOWN_VALUE,
    }
}

/// Build inode -> (pid, process_name) map by inspecting /proc/[pid]/fd
fn build_socket_inode_map() -> HashMap<String, (u32, String)> {
    let mut map = HashMap::new();
    if let Ok(proc_entries) = std::fs::read_dir("/proc") {
        for p_entry in proc_entries.flatten() {
            let pid_str = p_entry.file_name().to_string_lossy().to_string();
            if let Ok(pid) = pid_str.parse::<u32>() {
                let comm = std::fs::read_to_string(p_entry.path().join("comm"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| UNKNOWN_VALUE.into());

                let fd_dir = p_entry.path().join("fd");
                if let Ok(fds) = std::fs::read_dir(fd_dir) {
                    for fd in fds.flatten() {
                        if let Ok(target) = std::fs::read_link(fd.path()) {
                            let t = target.to_string_lossy();
                            if t.starts_with("socket:[") && t.ends_with(']') {
                                let inode = &t["socket:[".len()..t.len() - 1];
                                map.insert(inode.to_string(), (pid, comm.clone()));
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

pub fn get_ports() -> Result<Value, Error> {
    let mut ports: Vec<Value> = Vec::new();
    let inode_map = build_socket_inode_map();

    let files = [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp6", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp6", true),
    ];

    for (file_path, proto, is_v6) in files {
        if let Ok(file) = File::open(file_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1).flatten() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }

                let local = parts[1];
                let remote = parts[2];
                let state_hex = parts[3];
                let inode = parts[9];

                let (local_ip, local_port) = match local.split_once(':') {
                    Some((ip_hex, port_hex)) => {
                        let ip = if is_v6 {
                            parse_hex_ipv6(ip_hex).unwrap_or_else(|| "::".into())
                        } else {
                            parse_hex_ipv4(ip_hex).unwrap_or_else(|| "0.0.0.0".into())
                        };
                        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
                        (ip, port)
                    }
                    None => continue,
                };

                let (remote_ip, remote_port) = match remote.split_once(':') {
                    Some((ip_hex, port_hex)) => {
                        let ip = if is_v6 {
                            parse_hex_ipv6(ip_hex).unwrap_or_else(|| "::".into())
                        } else {
                            parse_hex_ipv4(ip_hex).unwrap_or_else(|| "0.0.0.0".into())
                        };
                        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
                        (ip, port)
                    }
                    None => (String::new(), 0),
                };

                let (pid, process_name) = inode_map.get(inode)
                    .cloned()
                    .unwrap_or((0, UNKNOWN_VALUE.into()));

                let mut o = Obj::new();
                o.set("protocol", s(proto));
                o.set("local_ip", s(&local_ip));
                o.set("local_port", i(local_port as i64));
                o.set("remote_ip", s(&remote_ip));
                o.set("remote_port", i(remote_port as i64));
                o.set("tx_queue", i(0));
                o.set("rx_queue", i(0));
                o.set("inode", i(inode.parse::<i64>().unwrap_or(0)));
                o.set("state", s(tcp_state_name(state_hex)));
                o.set("pid", i(pid as i64));
                o.set("process", s(&process_name));

                ports.push(o.into_value());
            }
        }
    }

    Ok(if ports.is_empty() { Value::Null } else { Value::Array(ports) })
}
