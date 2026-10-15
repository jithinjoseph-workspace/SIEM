//! Linux Network provider (`sysInfoLinux.cpp` / `network/`).

use std::fs::File;
use std::io::{BufRead, BufReader};
use super::Error;
use crate::json::{i, s, u, Obj, Value};
use crate::UNKNOWN_VALUE;

pub fn get_networks() -> Result<Value, Error> {
    let mut ifaces: Vec<Value> = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let base_path = entry.path();

            let mac = std::fs::read_to_string(base_path.join("address"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| UNKNOWN_VALUE.into());

            let mtu = std::fs::read_to_string(base_path.join("mtu"))
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or(1500);

            let operstate = std::fs::read_to_string(base_path.join("operstate"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".into());

            let mut o = Obj::new();
            o.set("name", s(&name));
            o.set("mac", s(&mac));
            o.set("mtu", i(mtu));
            o.set("state", s(&operstate));
            o.set("type", s(if name.starts_with("wl") { "wireless" } else if name == "lo" { "loopback" } else { "ethernet" }));

            // Read stats from /proc/net/dev
            let mut rx_bytes = 0u64;
            let mut tx_bytes = 0u64;
            let mut rx_packets = 0u64;
            let mut tx_packets = 0u64;

            if let Ok(dev_file) = File::open("/proc/net/dev") {
                let reader = BufReader::new(dev_file);
                for line in reader.lines().flatten() {
                    let trimmed = line.trim();
                    if trimmed.starts_with(&format!("{}:", name)) {
                        let fields: Vec<&str> = trimmed.split_whitespace().collect();
                        if fields.len() >= 10 {
                            rx_bytes = fields[1].parse::<u64>().unwrap_or(0);
                            rx_packets = fields[2].parse::<u64>().unwrap_or(0);
                            tx_bytes = fields[9].parse::<u64>().unwrap_or(0);
                            if fields.len() >= 11 {
                                tx_packets = fields[10].parse::<u64>().unwrap_or(0);
                            }
                        }
                    }
                }
            }

            o.set("rx_bytes", u(rx_bytes));
            o.set("tx_bytes", u(tx_bytes));
            o.set("rx_packets", u(rx_packets));
            o.set("tx_packets", u(tx_packets));

            ifaces.push(o.into_value());
        }
    }

    Ok(if ifaces.is_empty() { Value::Null } else { Value::Array(ifaces) })
}
