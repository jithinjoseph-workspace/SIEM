//! Linux Accounts provider (`sysInfoLinux.cpp` / `users_linux.hpp` / `groups_linux.hpp`).

use std::fs::File;
use std::io::{BufRead, BufReader};
use super::Error;
use crate::json::{i, s, Obj, Value};

pub fn get_users() -> Result<Value, Error> {
    let mut users: Vec<Value> = Vec::new();

    if let Ok(file) = File::open("/etc/passwd") {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                let username = parts[0];
                let uid = parts[2].parse::<i64>().unwrap_or(0);
                let gid = parts[3].parse::<i64>().unwrap_or(0);
                let home = parts[5];
                let shell = parts[6];

                let mut o = Obj::new();
                o.set("user_name", s(username));
                o.set("uid", i(uid));
                o.set("gid", i(gid));
                o.set("home", s(home));
                o.set("shell", s(shell));
                users.push(o.into_value());
            }
        }
    }

    Ok(if users.is_empty() { Value::Null } else { Value::Array(users) })
}

pub fn get_groups() -> Result<Value, Error> {
    let mut groups: Vec<Value> = Vec::new();

    if let Ok(file) = File::open("/etc/group") {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let group_name = parts[0];
                let gid = parts[2].parse::<i64>().unwrap_or(0);

                let mut o = Obj::new();
                o.set("group_name", s(group_name));
                o.set("gid", i(gid));
                groups.push(o.into_value());
            }
        }
    }

    Ok(if groups.is_empty() { Value::Null } else { Value::Array(groups) })
}
