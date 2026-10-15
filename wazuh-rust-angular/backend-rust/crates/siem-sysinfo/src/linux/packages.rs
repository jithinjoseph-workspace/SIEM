//! Linux Packages provider (`sysInfoLinux.cpp` / `packages/`).

use std::fs::File;
use std::io::{BufRead, BufReader};
use super::Error;
use crate::json::{i, s, Obj, Value};
use crate::UNKNOWN_VALUE;

pub fn get_packages() -> Result<Value, Error> {
    let mut packages: Vec<Value> = Vec::new();

    // 1. Check Debian/Ubuntu package database (/var/lib/dpkg/status)
    if let Ok(file) = File::open("/var/lib/dpkg/status") {
        let reader = BufReader::new(file);
        let mut cur_name = String::new();
        let mut cur_version = String::new();
        let mut cur_arch = String::new();
        let mut cur_desc = String::new();
        let mut cur_vendor = String::new();
        let mut cur_section = String::new();
        let mut cur_priority = String::new();
        let mut cur_size = 0i64;
        let mut is_installed = false;

        let flush_package = |packages: &mut Vec<Value>,
                             cur_name: &str,
                             cur_version: &str,
                             cur_arch: &str,
                             cur_desc: &str,
                             cur_vendor: &str,
                             cur_section: &str,
                             cur_priority: &str,
                             cur_size: i64,
                             is_installed: bool| {
            if !cur_name.is_empty() && is_installed {
                let mut o = Obj::new();
                o.set("name", s(cur_name));
                o.set("description", s(if cur_desc.is_empty() { UNKNOWN_VALUE } else { cur_desc }));
                o.set("version", s(if cur_version.is_empty() { UNKNOWN_VALUE } else { cur_version }));
                o.set("groups", s(if cur_section.is_empty() { UNKNOWN_VALUE } else { cur_section }));
                o.set("priority", s(if cur_priority.is_empty() { UNKNOWN_VALUE } else { cur_priority }));
                o.set("size", i(cur_size));
                o.set("vendor", s(if cur_vendor.is_empty() { UNKNOWN_VALUE } else { cur_vendor }));
                o.set("install_time", s(UNKNOWN_VALUE));
                o.set("location", s(UNKNOWN_VALUE));
                o.set("architecture", s(if cur_arch.is_empty() { UNKNOWN_VALUE } else { cur_arch }));
                o.set("format", s("deb"));
                packages.push(o.into_value());
            }
        };

        for line in reader.lines().flatten() {
            if line.is_empty() {
                flush_package(
                    &mut packages,
                    &cur_name,
                    &cur_version,
                    &cur_arch,
                    &cur_desc,
                    &cur_vendor,
                    &cur_section,
                    &cur_priority,
                    cur_size,
                    is_installed,
                );
                cur_name.clear();
                cur_version.clear();
                cur_arch.clear();
                cur_desc.clear();
                cur_vendor.clear();
                cur_section.clear();
                cur_priority.clear();
                cur_size = 0;
                is_installed = false;
                continue;
            }

            if line.starts_with("Package: ") {
                cur_name = line["Package: ".len()..].trim().to_string();
            } else if line.starts_with("Status: ") {
                if line.contains("installed") && !line.contains("not-installed") {
                    is_installed = true;
                }
            } else if line.starts_with("Version: ") {
                cur_version = line["Version: ".len()..].trim().to_string();
            } else if line.starts_with("Architecture: ") {
                cur_arch = line["Architecture: ".len()..].trim().to_string();
            } else if line.starts_with("Description: ") {
                cur_desc = line["Description: ".len()..].trim().to_string();
            } else if line.starts_with("Maintainer: ") {
                cur_vendor = line["Maintainer: ".len()..].trim().to_string();
            } else if line.starts_with("Section: ") {
                cur_section = line["Section: ".len()..].trim().to_string();
            } else if line.starts_with("Priority: ") {
                cur_priority = line["Priority: ".len()..].trim().to_string();
            } else if line.starts_with("Installed-Size: ") {
                if let Ok(sz_kb) = line["Installed-Size: ".len()..].trim().parse::<i64>() {
                    cur_size = sz_kb * 1024;
                }
            }
        }

        flush_package(
            &mut packages,
            &cur_name,
            &cur_version,
            &cur_arch,
            &cur_desc,
            &cur_vendor,
            &cur_section,
            &cur_priority,
            cur_size,
            is_installed,
        );
    }

    Ok(if packages.is_empty() { Value::Null } else { Value::Array(packages) })
}
