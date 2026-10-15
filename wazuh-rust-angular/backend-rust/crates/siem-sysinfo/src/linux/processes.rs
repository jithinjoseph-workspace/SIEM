//! Linux Processes provider (`sysInfoLinux.cpp` / `readproc.h`).

use std::fs::File;
use std::io::{BufRead, BufReader};
use super::Error;
use crate::json::{i, s, u, Obj, Value};
use crate::UNKNOWN_VALUE;

pub fn get_processes_info(mut cb: impl FnMut(Value) -> Result<(), Error>) -> Result<(), Error> {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };

            let proc_path = entry.path();

            // 1. comm (executable name)
            let name = std::fs::read_to_string(proc_path.join("comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| UNKNOWN_VALUE.into());

            // 2. cmdline
            let cmdline_raw = std::fs::read(proc_path.join("cmdline")).unwrap_or_default();
            let (cmd, argvs) = if !cmdline_raw.is_empty() {
                let parts: Vec<&[u8]> = cmdline_raw.split(|&b| b == 0).filter(|p| !p.is_empty()).collect();
                let c = parts.first().map(|p| String::from_utf8_lossy(p).to_string()).unwrap_or_else(|| name.clone());
                let args = if parts.len() > 1 {
                    parts[1..].iter().map(|p| String::from_utf8_lossy(p)).collect::<Vec<_>>().join(" ")
                } else {
                    String::new()
                };
                (c, args)
            } else {
                (name.clone(), String::new())
            };

            // 3. status
            let mut ppid = 0u32;
            let mut state = "S".to_string();
            let mut vm_size = 0u64;
            let mut rss_size = 0u64;
            let mut ruser = "root".to_string();

            if let Ok(status_file) = File::open(proc_path.join("status")) {
                let reader = BufReader::new(status_file);
                for line in reader.lines().flatten() {
                    if line.starts_with("PPid:") {
                        ppid = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    } else if line.starts_with("State:") {
                        state = line.split_whitespace().nth(1).unwrap_or("S").to_string();
                    } else if line.starts_with("VmSize:") {
                        vm_size = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    } else if line.starts_with("VmRSS:") {
                        rss_size = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    } else if line.starts_with("Uid:") {
                        if let Some(uid_str) = line.split_whitespace().nth(1) {
                            if let Ok(uid) = uid_str.parse::<u32>() {
                                ruser = if uid == 0 { "root".into() } else { format!("uid-{}", uid) };
                            }
                        }
                    }
                }
            }

            let mut o = Obj::new();
            o.set("pid", s(&pid.to_string()));
            o.set("name", s(&name));
            o.set("state", s(&state));
            o.set("ppid", i(ppid as i64));
            o.set("utime", u(0));
            o.set("stime", u(0));
            o.set("cmd", s(&cmd));
            o.set("argvs", s(&argvs));
            o.set("euser", s(&ruser));
            o.set("ruser", s(&ruser));
            o.set("suser", s(&ruser));
            o.set("egroup", s("root"));
            o.set("rgroup", s("root"));
            o.set("sgroup", s("root"));
            o.set("vm_size", u(vm_size));
            o.set("size", u(rss_size));
            o.set("session", i(0));
            o.set("priority", i(20));

            cb(o.into_value())?;
        }
    }
    Ok(())
}
