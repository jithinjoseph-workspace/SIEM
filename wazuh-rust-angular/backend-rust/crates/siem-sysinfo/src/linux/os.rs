//! Linux OS provider (`sysInfoLinux.cpp` / `osinfo/sysOsInfoLinux.cpp`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use super::Error;
use crate::json::{s, Obj, Value};
use crate::UNKNOWN_VALUE;

pub fn get_os_info() -> Result<Value, Error> {
    let mut os_data: HashMap<String, String> = HashMap::new();

    // Parse /etc/os-release or /usr/lib/os-release
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || !trimmed.contains('=') {
                    continue;
                }
                let mut parts = trimmed.splitn(2, '=');
                if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                    let clean_v = v.trim_matches('"').trim_matches('\'').trim();
                    os_data.insert(k.trim().to_string(), clean_v.to_string());
                }
            }
            break;
        }
    }

    let os_name = os_data.get("NAME")
        .cloned()
        .unwrap_or_else(|| "Linux".into());

    let os_version = os_data.get("VERSION_ID")
        .or_else(|| os_data.get("VERSION"))
        .cloned()
        .unwrap_or_else(|| UNKNOWN_VALUE.into());

    let (os_major, os_minor) = if os_version != UNKNOWN_VALUE {
        let parts: Vec<&str> = os_version.split('.').collect();
        let maj = parts.first().unwrap_or(&UNKNOWN_VALUE).to_string();
        let min = parts.get(1).unwrap_or(&"0").to_string();
        (maj, min)
    } else {
        (UNKNOWN_VALUE.into(), UNKNOWN_VALUE.into())
    };

    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| UNKNOWN_VALUE.into());

    let kernel_version = std::fs::read_to_string("/proc/sys/kernel/version")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| UNKNOWN_VALUE.into());

    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into());

    let architecture = std::env::consts::ARCH.to_string();

    let mut o = Obj::new();
    o.set("os_name", s(&os_name));
    o.set("os_major", s(&os_major));
    o.set("os_minor", s(&os_minor));
    o.set("os_build", s(&kernel_version));
    o.set("os_version", s(&os_version));
    o.set("hostname", s(&hostname));
    o.set("os_release", s(&kernel_release));
    o.set("os_display_version", s(os_data.get("PRETTY_NAME").unwrap_or(&os_name)));
    o.set("release", s(&kernel_release));
    o.set("architecture", s(&architecture));
    o.set("os_platform", s("linux"));

    Ok(o.into_value())
}
