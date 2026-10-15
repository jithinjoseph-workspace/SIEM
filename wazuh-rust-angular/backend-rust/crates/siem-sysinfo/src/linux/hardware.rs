//! Linux Hardware provider (`sysInfoLinux.cpp` / `hardware/`).

use std::fs::File;
use std::io::{BufRead, BufReader};
use super::Error;
use crate::json::{f, i, s, u, Obj, Value};
use crate::UNKNOWN_VALUE;

pub fn get_hardware() -> Result<Value, Error> {
    let mut o = Obj::new();

    // Serial number from DMI/SMBIOS
    let board_serial = std::fs::read_to_string("/sys/class/dmi/id/product_serial")
        .or_else(|_| std::fs::read_to_string("/sys/class/dmi/id/board_serial"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| UNKNOWN_VALUE.into());
    o.set("board_serial", s(board_serial));

    // CPU info from /proc/cpuinfo
    let mut cpu_name = UNKNOWN_VALUE.to_string();
    let mut cpu_mhz = 2400.0f64;
    let mut cpu_cores = 1usize;

    if let Ok(file) = File::open("/proc/cpuinfo") {
        let reader = BufReader::new(file);
        let mut count = 0;
        for line in reader.lines().flatten() {
            if line.starts_with("model name") {
                if let Some(val) = line.split(':').nth(1) {
                    cpu_name = val.trim().to_string();
                }
            } else if line.starts_with("cpu MHz") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(mhz) = val.trim().parse::<f64>() {
                        cpu_mhz = mhz;
                    }
                }
            } else if line.starts_with("processor") {
                count += 1;
            }
        }
        if count > 0 {
            cpu_cores = count;
        }
    }

    o.set("cpu_name", s(cpu_name));
    o.set("cpu_cores", i(cpu_cores as i64));
    o.set("cpu_mhz", f(cpu_mhz));

    // RAM info from /proc/meminfo (in KB)
    let mut ram_total = 0u64;
    let mut ram_free = 0u64;
    let mut ram_available = 0u64;

    if let Ok(file) = File::open("/proc/meminfo") {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if line.starts_with("MemTotal:") {
                    ram_total = parts[1].parse::<u64>().unwrap_or(0);
                } else if line.starts_with("MemFree:") {
                    ram_free = parts[1].parse::<u64>().unwrap_or(0);
                } else if line.starts_with("MemAvailable:") {
                    ram_available = parts[1].parse::<u64>().unwrap_or(0);
                }
            }
        }
    }

    let effective_free = if ram_available > 0 { ram_available } else { ram_free };
    let ram_usage = if ram_total > 0 {
        ((ram_total.saturating_sub(effective_free)) * 100) / ram_total
    } else {
        0
    };

    o.set("ram_total", u(ram_total));
    o.set("ram_free", u(effective_free));
    o.set("ram_usage", u(ram_usage));

    Ok(o.into_value())
}
