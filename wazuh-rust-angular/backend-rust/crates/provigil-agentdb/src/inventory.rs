//! Legacy inventory commands (spec § 2.4, § 2.5): network interfaces, protocols and addresses,
//! OS, hardware, ports, packages, hotfixes and processes in the old `|` format, and the
//! package / hotfix lists read by the vulnerability scanner.

use std::sync::Arc;

use provigil_json::Json;
use provigil_sqlite::{Stmt, SQLITE_CONSTRAINT, SQLITE_DONE, SQLITE_ROW};

use crate::integrity::{self, HOTFIXES, PACKAGES};
use crate::legacy::{Kind, Val, Words};
use crate::rows::SEND_FAILED;
use crate::text::{answer, near, read_long, until_nul};
use crate::{Answer, Engine, Handle, INVALID, OK};

/// The checksum value of rows written by the old protocol.
pub const LEGACY: &[u8] = b"legacy";

fn nul_text(f: &[u8]) -> Option<Vec<u8>> {
    if f == b"NULL" {
        None
    } else {
        Some(f.to_vec())
    }
}

fn i32_or_null(st: &Stmt, i: i32, v: i64, keep: bool) {
    if keep {
        st.bind_int(i, v as i32);
    } else {
        st.bind_null(i);
    }
}
fn i64_or_null(st: &Stmt, i: i32, v: i64, keep: bool) {
    if keep {
        st.bind_int64(i, v);
    } else {
        st.bind_null(i);
    }
}

impl Engine {
    fn inv_begin(&self, h: &mut Handle, func: &str) -> bool {
        if !h.transaction && !self.begin(h) {
            self.debug(cat!("at ", func, "(): cannot begin transaction"));
            return false;
        }
        true
    }

    fn inv_stmt(&self, h: &mut Handle, sql: &str, func: &str) -> Option<Arc<Stmt>> {
        let st = self.stmt_plain(h, sql);
        if st.is_none() {
            self.error(cat!("DB(", h.id.clone(), ") sqlite3_prepare_v2() stmt(", sql, "): ", h.errmsg()));
            self.debug(cat!("at ", func, "(): cannot cache statement"));
        }
        st
    }

    /// DONE, or a UNIQUE constraint (logged at debug level), counts as written.
    pub(crate) fn written_unique(&self, h: &Handle, st: &Stmt) -> bool {
        match self.step(st) {
            SQLITE_DONE => true,
            SQLITE_CONSTRAINT => {
                let e = h.errmsg();
                if e.starts_with(b"UNIQUE") {
                    self.debug(cat!("SQLite: ", e));
                    true
                } else {
                    self.error(cat!("SQLite: ", e));
                    false
                }
            }
            _ => {
                self.error(cat!("SQLite: ", h.errmsg()));
                false
            }
        }
    }

    pub(crate) fn written_done(&self, h: &Handle, st: &Stmt) -> bool {
        if self.step(st) == SQLITE_DONE {
            true
        } else {
            self.error(cat!("SQLite: ", h.errmsg()));
            false
        }
    }

    /// Deletes the rows of other scans from `table`.
    fn delete_other_scans(&self, h: &mut Handle, table: &str, func: &str, scan: Option<&[u8]>) -> bool {
        let Some(st) = self.inv_stmt(h, &format!("DELETE FROM {table} WHERE scan_id != ?;"), func) else { return false };
        st.bind_text(1, scan);
        if self.step(&st) != SQLITE_DONE {
            self.error(cat!("Deleting old information from '", table, "' table: ", h.errmsg()));
            return false;
        }
        true
    }

    fn save_or(&self, ok_: bool, m1: &str, err: &str) -> Answer {
        if ok_ {
            (OK, b"ok".to_vec())
        } else {
            self.debug(m1.as_bytes().to_vec());
            (INVALID, err.as_bytes().to_vec())
        }
    }

    pub(crate) fn inventory_command(&self, h: &mut Handle, cmd: &[u8], args: &[u8]) -> Option<Answer> {
        Some(match cmd {
            b"netinfo" => self.cmd_netinfo(h, args),
            b"netproto" => self.cmd_netproto(h, args),
            b"netaddr" => self.cmd_netaddr(h, args),
            b"osinfo" => self.cmd_osinfo(h, args),
            b"hardware" => self.cmd_hardware(h, args),
            b"port" => self.cmd_port(h, args),
            b"package" => self.cmd_package(h, args),
            b"hotfix" => self.cmd_hotfix(h, args),
            b"process" => self.cmd_process(h, args),
            _ => return None,
        })
    }

    // ------------------------------------------------------------------ network

    fn cmd_netinfo(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let w = Words { m1: "Invalid Network query syntax.", p: "Network query: ", err: "err Invalid Network query syntax" };
        let (action, rest) = match self.legacy_action(input, &w) {
            Ok(x) => x,
            Err(r) => return r,
        };
        match action {
            b"save" => {
                use Kind::*;
                let f = match self.split_fields(rest, &[Text, Text, Text, Text, Text, Text, Int, Text, Long, Long, Long, Long, Long, Long, Long, Long], &w, &|_| None) {
                    Ok(f) => f,
                    Err(r) => return r,
                };
                let ok_ = self.inv_begin(h, "wdb_netinfo_save") && {
                    let r = self.inv_stmt(
                        h,
                        "INSERT INTO sys_netiface (scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                        "wdb_netinfo_insert",
                    );
                    match r {
                        None => false,
                        Some(st) => {
                            for i in 0..6 {
                                st.bind_text(i as i32 + 1, f[i].text());
                            }
                            i64_or_null(&st, 7, f[6].int(), f[6].int() > 0);
                            st.bind_text(8, f[7].text());
                            for i in 8..16 {
                                i64_or_null(&st, i as i32 + 1, f[i].int(), f[i].int() >= 0);
                            }
                            st.bind_text(17, Some(LEGACY));
                            self.written_unique(h, &st)
                        }
                    }
                };
                self.save_or(ok_, "Cannot save Network information.", "err Cannot save Network information.")
            }
            b"del" => {
                let scan = nul_text(rest);
                let ok_ = self.inv_begin(h, "wdb_netinfo_delete")
                    && self.delete_other_scans(h, "sys_netiface", "wdb_netinfo_delete", scan.as_deref())
                    && self.delete_other_scans(h, "sys_netproto", "wdb_netinfo_delete", scan.as_deref())
                    && self.delete_other_scans(h, "sys_netaddr", "wdb_netinfo_delete", scan.as_deref());
                self.save_or(ok_, "Cannot delete old network information.", "err Cannot delete old network information.")
            }
            _ => self.legacy_bad("Invalid netinfo query syntax.", "err Invalid netinfo query syntax", action),
        }
    }

    /// netproto and netaddr share their layout: scan|iface|kind|text|text|last.
    fn cmd_net_pair(&self, h: &mut Handle, input: &[u8], proto: bool) -> Answer {
        let (name, p, e) = if proto {
            ("netproto", "netproto query: ", "err Invalid netproto query syntax")
        } else {
            ("netaddr", "netaddr query: ", "err Invalid netaddr query syntax")
        };
        let m1 = format!("Invalid {name} query syntax.");
        let w = Words { m1: &m1, p, err: e };
        let (action, rest) = match self.legacy_action(input, &w) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if action != b"save" {
            return self.legacy_bad(&m1, e, action);
        }
        use Kind::*;
        let last = if proto { Int } else { Text };
        // the field after the type uses the general network wording
        let network = |i: usize| (i == 3).then_some(Words { m1: "Invalid Network query syntax.", p: "Network query: ", err: "err Invalid Network query syntax" });
        let f = match self.split_fields(rest, &[Text, Text, Plain, Text, Text, last], &w, &network) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let family: &[u8] = if f[2].int() == 0 { b"ipv4" } else { b"ipv6" };
        let (func, sql) = if proto {
            ("wdb_netproto", "INSERT INTO sys_netproto (scan_id, iface, type, gateway, dhcp, metric, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);")
        } else {
            ("wdb_netaddr", "INSERT INTO sys_netaddr (scan_id, iface, proto, address, netmask, broadcast, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);")
        };
        let ok_ = self.inv_begin(h, &format!("{func}_save")) && {
            match self.inv_stmt(h, sql, &format!("{func}_insert")) {
                None => false,
                Some(st) => {
                    st.bind_text(1, f[0].text());
                    st.bind_text(2, f[1].text());
                    st.bind_text(3, Some(family));
                    st.bind_text(4, f[3].text());
                    st.bind_text(5, f[4].text());
                    if proto {
                        i64_or_null(&st, 6, f[5].int(), f[5].int() >= 0);
                    } else {
                        st.bind_text(6, f[5].text());
                    }
                    st.bind_text(7, Some(LEGACY));
                    if proto {
                        self.written_unique(h, &st)
                    } else {
                        self.written_done(h, &st)
                    }
                }
            }
        };
        self.save_or(ok_, &format!("Cannot save {name} information."), &format!("err Cannot save {name} information."))
    }

    fn cmd_netproto(&self, h: &mut Handle, input: &[u8]) -> Answer {
        self.cmd_net_pair(h, input, true)
    }

    fn cmd_netaddr(&self, h: &mut Handle, input: &[u8]) -> Answer {
        self.cmd_net_pair(h, input, false)
    }

    // ------------------------------------------------------------------ OS and hardware

    fn cmd_osinfo(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let input = until_nul(input);
        let start = input.iter().position(|&c| c != b' ');
        let Some(start) = start else { return (INVALID, b"err Missing osinfo action".to_vec()) };
        let t = &input[start..];
        let (action, rest) = match t.iter().position(|&c| c == b' ') {
            Some(p) => (&t[..p], &t[p + 1..]),
            None => (t, &b""[..]),
        };
        match action {
            b"get" => {
                let r = self.prepare(h, "SELECT * FROM sys_osinfo;").and_then(|st| {
                    let r = self.rows(&st);
                    if r.is_none() {
                        self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
                    }
                    r
                });
                match r {
                    None => (INVALID, answer(cat!("err Cannot get sys_osinfo database table information; SQL err: ", h.errmsg()))),
                    Some(j) => (OK, answer(cat!("ok ", j.print_unformatted()))),
                }
            }
            b"set" => self.osinfo_set(h, rest),
            _ => (INVALID, answer(cat!("err Invalid osinfo action: ", action))),
        }
    }

    fn osinfo_set(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let mut f: Vec<Option<Vec<u8>>> = Vec::new();
        let mut rest = input;
        for _ in 0..15 {
            let Some(p) = rest.iter().position(|&c| c == b'|') else {
                self.debug(b"Invalid OS info query syntax.".to_vec());
                return (INVALID, b"err Invalid OS info query syntax".to_vec());
            };
            f.push(nul_text(&rest[..p]));
            rest = &rest[p + 1..];
        }
        let Some(p) = rest.iter().position(|&c| c == b'|') else {
            self.debug(b"Invalid OS info query syntax.".to_vec());
            self.debug2(cat!("OS info query: ", rest));
            return (INVALID, near("err Invalid OS info query syntax", rest));
        };
        let patch = nul_text(&rest[..p]);
        let display = nul_text(&rest[p + 1..]);
        // order: scan_id scan_time hostname architecture os_name os_version os_codename os_major
        // os_minor os_build os_platform sysname release version os_release
        let g = |i: usize| f[i].as_deref();
        let ok_ = self.inv_begin(h, "wdb_osinfo_save") && {
            match self.stmt_plain(h, "DELETE FROM sys_osinfo;") {
                None => {
                    self.debug(b"at wdb_osinfo_save(): cannot cache statement (12)".to_vec());
                    false
                }
                Some(del) if self.step(&del) != SQLITE_DONE => {
                    self.error(cat!("Deleting old information from 'sys_osinfo' table: ", h.errmsg()));
                    false
                }
                Some(_) => {
                    let e = |v: Option<&[u8]>| v.unwrap_or_default().to_vec();
                    let reference = {
                        use sha1::{Digest, Sha1};
                        let mut c = Sha1::new();
                        for v in [g(3), g(4), g(5), g(6), g(7), g(8), patch.as_deref(), g(9), g(10), g(11), g(12), g(13), g(14)] {
                            c.update(until_nul(&e(v)));
                        }
                        integrity::hex(&c.finalize())
                    };
                    match self.inv_stmt(
                        h,
                        "INSERT INTO sys_osinfo (scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor,  os_patch, os_build, os_platform, sysname, release, version, os_release, os_display_version, checksum, reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                        "wdb_osinfo_insert",
                    ) {
                        None => false,
                        Some(st) => {
                            let vals = [g(0), g(1), g(2), g(3), g(4), g(5), g(6), g(7), g(8), patch.as_deref(), g(9), g(10), g(11), g(12), g(13), g(14), display.as_deref(), Some(LEGACY)];
                            for (i, v) in vals.iter().enumerate() {
                                st.bind_text(i as i32 + 1, *v);
                            }
                            st.bind_text(19, Some(&reference));
                            self.written_done(h, &st)
                        }
                    }
                }
            }
        };
        self.save_or(ok_, "Cannot save OS information.", "err Cannot save OS information.")
    }

    fn cmd_hardware(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let w = Words { m1: "Invalid HW info query syntax.", p: "HW info query: ", err: "err Invalid HW info query syntax" };
        let (action, rest) = match self.legacy_action(input, &w) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if action != b"save" {
            return self.legacy_bad(w.m1, w.err, action);
        }
        use Kind::*;
        let f = match self.split_fields(rest, &[Text, Text, Text, Text, Plain, Real, Unsigned, Unsigned, Plain], &w, &|_| None) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let mhz = match f[5] {
            Val::Real(r) => r,
            _ => 0.0,
        };
        let ok_ = self.inv_begin(h, "wdb_hardware_save") && {
            match self.inv_stmt(h, "DELETE FROM sys_hwinfo;", "wdb_hardware_save") {
                None => false,
                Some(del) if self.step(&del) != SQLITE_DONE => {
                    self.error(cat!("Deleting old information from 'sys_hwinfo' table: ", h.errmsg()));
                    false
                }
                Some(_) => match self.inv_stmt(
                    h,
                    "INSERT INTO sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                    "wdb_hardware_insert",
                ) {
                    None => false,
                    Some(st) => {
                        for i in 0..4 {
                            st.bind_text(i as i32 + 1, f[i].text());
                        }
                        i32_or_null(&st, 5, f[4].int(), f[4].int() > 0);
                        if mhz > 0.0 {
                            st.bind_double(6, mhz);
                        } else {
                            st.bind_null(6);
                        }
                        // the RAM values are unsigned: anything but 0 is stored
                        let (total, free) = (f[6].int() as u64, f[7].int() as u64);
                        i64_or_null(&st, 7, total as i64, total > 0);
                        i64_or_null(&st, 8, free as i64, free > 0);
                        let usage = f[8].int();
                        i32_or_null(&st, 9, usage, usage > 0 && usage <= 100);
                        st.bind_text(10, Some(LEGACY));
                        self.written_done(h, &st)
                    }
                },
            }
        };
        self.save_or(ok_, "wdb_parse_hardware(): Cannot save HW information.", "err Cannot save HW information.")
    }

    // ------------------------------------------------------------------ ports and processes

    fn cmd_port(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let w = Words { m1: "Invalid Port query syntax.", p: "Port query: ", err: "err Invalid Port query syntax" };
        let (action, rest) = match self.legacy_action(input, &w) {
            Ok(x) => x,
            Err(r) => return r,
        };
        match action {
            b"save" => {
                use Kind::*;
                let f = match self.split_fields(rest, &[Text, Text, Text, Text, Int, Text, Int, Int, Int, Long, Text, Int, Text], &w, &|_| None) {
                    Ok(f) => f,
                    Err(r) => return r,
                };
                // a process starting with NULL is none
                let process = f[12].text().filter(|p| !p.starts_with(b"NULL")).map(|p| p.to_vec());
                let ok_ = self.inv_begin(h, "wdb_port_save") && {
                    match self.inv_stmt(
                        h,
                        "INSERT OR REPLACE INTO sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                        "wdb_port_insert",
                    ) {
                        None => false,
                        Some(st) => {
                            for i in 0..4 {
                                st.bind_text(i as i32 + 1, f[i].text());
                            }
                            i32_or_null(&st, 5, f[4].int(), f[4].int() >= 0);
                            st.bind_text(6, f[5].text());
                            for (i, k) in [(7, 6), (8, 7), (9, 8)] {
                                i32_or_null(&st, i, f[k].int(), f[k].int() >= 0);
                            }
                            i64_or_null(&st, 10, f[9].int(), f[9].int() >= 0);
                            st.bind_text(11, f[10].text());
                            i32_or_null(&st, 12, f[11].int(), f[11].int() >= 0);
                            st.bind_text(13, process.as_deref());
                            st.bind_text(14, Some(LEGACY));
                            self.written_done(h, &st)
                        }
                    }
                };
                self.save_or(ok_, "Cannot save Port information.", "err Cannot save Port information.")
            }
            b"del" => {
                let ok_ = self.inv_begin(h, "wdb_port_delete") && self.delete_other_scans(h, "sys_ports", "wdb_port_delete", nul_text(rest).as_deref());
                self.save_or(ok_, "Cannot delete old Port information.", "err Cannot delete old Port information.")
            }
            _ => self.legacy_bad(w.m1, w.err, action),
        }
    }

    fn cmd_process(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let w = Words { m1: "Invalid Process query syntax.", p: "Process query: ", err: "err Invalid Process query syntax" };
        let (action, rest) = match self.legacy_action(input, &w) {
            Ok(x) => x,
            Err(r) => return r,
        };
        match action {
            b"save" => {
                use Kind::*;
                let kinds = [
                    Text, Text, Int, Text, Text, Int, Int, Int, Text, Text, Text, Text, Text, Text, Text, Text, Text, Int, Nice, Int, Int, Int, Int,
                    StartTime, Int, Int, Int, Int, Int, Int,
                ];
                let f = match self.split_fields(rest, &kinds, &w, &|_| None) {
                    Ok(f) => f,
                    Err(r) => return r,
                };
                let pid = f[2].int();
                let ok_ = self.inv_begin(h, "wdb_process_save") && pid >= 0 && {
                    match self.inv_stmt(
                        h,
                        "INSERT INTO sys_processes (scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        "wdb_process_insert",
                    ) {
                        None => false,
                        Some(st) => {
                            st.bind_text(1, f[0].text());
                            st.bind_text(2, f[1].text());
                            i32_or_null(&st, 3, pid, pid >= 0);
                            st.bind_text(4, f[3].text());
                            st.bind_text(5, f[4].text());
                            for i in 5..8 {
                                i32_or_null(&st, i as i32 + 1, f[i].int(), f[i].int() >= 0);
                            }
                            for i in 8..17 {
                                st.bind_text(i as i32 + 1, f[i].text());
                            }
                            i32_or_null(&st, 18, f[17].int(), f[17].int() >= 0);
                            st.bind_int(19, f[18].int() as i32);
                            for i in 19..23 {
                                i32_or_null(&st, i as i32 + 1, f[i].int(), f[i].int() >= 0);
                            }
                            i64_or_null(&st, 24, f[23].int(), f[23].int() >= 0);
                            for i in 24..30 {
                                i32_or_null(&st, i as i32 + 1, f[i].int(), f[i].int() >= 0);
                            }
                            st.bind_text(31, Some(LEGACY));
                            self.written_done(h, &st)
                        }
                    }
                };
                self.save_or(ok_, "Cannot save Process information.", "err Cannot save Process information.")
            }
            b"del" => {
                let ok_ = self.inv_begin(h, "wdb_process_delete") && self.delete_other_scans(h, "sys_processes", "wdb_process_delete", nul_text(rest).as_deref());
                self.save_or(ok_, "Cannot delete old Process information.", "err Cannot delete old Process information.")
            }
            _ => self.legacy_bad(w.m1, w.err, action),
        }
    }

    // ------------------------------------------------------------------ packages and hotfixes

    /// The first space-separated word (leading spaces skipped) and the text after its space.
    fn first_token(input: &[u8]) -> Option<(&[u8], &[u8])> {
        let input = until_nul(input);
        let s = input.iter().position(|&c| c != b' ')?;
        let t = &input[s..];
        Some(match t.iter().position(|&c| c == b' ') {
            Some(p) => (&t[..p], &t[p + 1..]),
            None => (t, &b""[..]),
        })
    }

    fn cmd_package(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let Some((action, rest)) = Self::first_token(input) else {
            self.debug(b"Invalid package info query syntax. Missing action".to_vec());
            self.debug2(b"DB query error. Missing action".to_vec());
            return (INVALID, b"err Invalid package info query syntax. Missing action".to_vec());
        };
        match action {
            b"save" => {
                let mut f: Vec<Option<Vec<u8>>> = Vec::with_capacity(16);
                let mut r = rest;
                for i in 0..16 {
                    let field = if i < 15 {
                        let Some(p) = r.iter().position(|&c| c == b'|') else {
                            self.debug(b"Invalid package info query syntax.".to_vec());
                            self.debug2(cat!("Package info query: ", r));
                            return (INVALID, near("err Invalid package info query syntax", r));
                        };
                        let x = &r[..p];
                        r = &r[p + 1..];
                        x
                    } else {
                        r
                    };
                    f.push(nul_text(field));
                }
                let size = match &f[6] {
                    Some(s) if !s.starts_with(b"NULL") => read_long(s).0,
                    _ => -1,
                };
                let g = |i: usize| f[i].as_deref();
                let ok_ = self.inv_begin(h, "wdb_package_save") && {
                    match self.inv_stmt(
                        h,
                        "INSERT INTO sys_programs (scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                        "wdb_package_insert",
                    ) {
                        None => false,
                        Some(st) => {
                            st.bind_text(1, g(0));
                            st.bind_text(2, g(1));
                            st.bind_text(3, Some(g(2).unwrap_or(b"")));
                            st.bind_text(4, g(3));
                            st.bind_text(5, g(4));
                            st.bind_text(6, g(5));
                            i64_or_null(&st, 7, size, size >= 0);
                            for (i, k) in [(8, 7), (9, 8), (10, 9), (11, 10), (12, 11), (13, 12), (14, 13)] {
                                st.bind_text(i, g(k));
                            }
                            st.bind_text(15, Some(g(14).unwrap_or(b"")));
                            st.bind_text(16, Some(LEGACY));
                            st.bind_text(17, g(15));
                            self.written_unique(h, &st)
                        }
                    }
                };
                if !ok_ {
                    self.debug(b"Cannot save package information.".to_vec());
                    return (INVALID, b"err Cannot save package information.".to_vec());
                }
                let t = self.time() as u32 as i64;
                self.sync_attempt(h, PACKAGES, t, b"", b"", true);
                (OK, b"ok".to_vec())
            }
            b"del" => {
                let scan = nul_text(until_nul(rest));
                if !self.package_update(h, scan.as_deref()) {
                    self.debug(b"Cannot update scanned packages.".to_vec());
                }
                let ok_ = self.inv_begin(h, "wdb_package_delete") && self.delete_other_scans(h, "sys_programs", "wdb_package_delete", scan.as_deref());
                if !ok_ {
                    self.debug(b"Cannot delete old package information.".to_vec());
                    return (INVALID, b"err Cannot delete old package information.".to_vec());
                }
                let t = self.time() as u32 as i64;
                self.sync_completion(h, PACKAGES, t, b"", b"");
                (OK, b"ok".to_vec())
            }
            b"get" => self.inventory_get(
                h,
                PACKAGES,
                "SELECT DISTINCT NAME, VERSION, ARCHITECTURE, VENDOR, FORMAT, SOURCE, CPE, MSU_NAME, ITEM_ID, DESCRIPTION, LOCATION, SIZE, INSTALL_TIME FROM SYS_PROGRAMS;",
            ),
            _ => {
                self.debug(b"Invalid package info query syntax.".to_vec());
                self.debug2(cat!("DB query error near: ", action));
                (INVALID, near("err Invalid package info query syntax", action))
            }
        }
    }

    /// Carries CPE and MSU name of the previous scan's packages over to the new scan's rows.
    fn package_update(&self, h: &mut Handle, scan: Option<&[u8]>) -> bool {
        if !h.transaction && !self.begin(h) {
            self.debug(b"at wdb_package_update(): cannot begin transaction".to_vec());
            return false;
        }
        let Some(get) = self.stmt_plain(h, "SELECT CPE, MSU_NAME, FORMAT, NAME, VENDOR, VERSION, ARCHITECTURE FROM SYS_PROGRAMS WHERE SCAN_ID != ?;") else {
            self.debug(b"at wdb_package_update(): cannot cache get statement".to_vec());
            return false;
        };
        get.bind_text(1, scan);
        let mut result;
        loop {
            result = self.step(&get);
            if result != SQLITE_ROW {
                break;
            }
            let v: Vec<Option<Vec<u8>>> = (0..7).map(|i| get.column_text(i)).collect();
            let Some(upd) = self.stmt_plain(
                h,
                "UPDATE SYS_PROGRAMS SET CPE = ?, MSU_NAME = ? WHERE SCAN_ID = ? AND FORMAT IS ? AND NAME IS ? AND VENDOR IS ? AND VERSION IS ? AND ARCHITECTURE IS ?;",
            ) else {
                self.debug(b"at wdb_package_update(): cannot cache update statement".to_vec());
                return false;
            };
            upd.bind_text(1, v[0].as_deref());
            upd.bind_text(2, v[1].as_deref());
            upd.bind_text(3, scan);
            for i in 2..7 {
                upd.bind_text(i as i32 + 2, v[i].as_deref());
            }
            if self.step(&upd) != SQLITE_DONE {
                self.error(cat!("Unable to update the 'sys_programs' table: ", h.errmsg()));
                return false;
            }
        }
        if result != SQLITE_DONE {
            self.error(cat!("Unable to update the 'sys_programs' table: ", h.errmsg()));
            return false;
        }
        true
    }

    fn cmd_hotfix(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let Some((action, rest)) = Self::first_token(input) else {
            self.debug(b"Invalid hotfix info query syntax. Missing action".to_vec());
            self.debug2(b"DB query error. Missing action".to_vec());
            return (INVALID, b"err Invalid hotfix info query syntax. Missing action".to_vec());
        };
        match action {
            b"save" => {
                // three `|` tokens, empty ones skipped
                let mut toks = rest.split(|&c| c == b'|').filter(|t| !t.is_empty());
                let mut last: &[u8] = rest;
                let mut f: Vec<Option<Vec<u8>>> = Vec::new();
                for _ in 0..3 {
                    let Some(t) = toks.next() else {
                        self.debug(b"Invalid hotfix info query syntax.".to_vec());
                        self.debug2(cat!("Hotfix info query: ", last));
                        return (INVALID, near("err Invalid hotfix info query syntax", last));
                    };
                    last = t;
                    f.push(nul_text(t));
                }
                let ok_ = self.inv_begin(h, "wdb_hotfix_save")
                    && f[2].is_some()
                    && match self.inv_stmt(h, "INSERT INTO sys_hotfixes (scan_id, scan_time, hotfix, checksum) VALUES (?, ?, ?, ?);", "wdb_hotfix_insert") {
                        None => false,
                        Some(st) => {
                            st.bind_text(1, f[0].as_deref());
                            st.bind_text(2, f[1].as_deref());
                            st.bind_text(3, f[2].as_deref());
                            st.bind_text(4, Some(LEGACY));
                            self.written_done(h, &st)
                        }
                    };
                if !ok_ {
                    self.debug(b"Cannot save hotfix information.".to_vec());
                    return (INVALID, b"err Cannot save hotfix information.".to_vec());
                }
                let t = self.time() as u32 as i64;
                self.sync_attempt(h, HOTFIXES, t, b"", b"", true);
                (OK, b"ok".to_vec())
            }
            b"del" => {
                let scan = nul_text(until_nul(rest));
                let ok_ = self.inv_begin(h, "wdb_hotfix_delete") && self.delete_other_scans(h, "sys_hotfixes", "wdb_hotfix_delete", scan.as_deref());
                if !ok_ {
                    self.debug(b"Cannot delete old hotfix information.".to_vec());
                    return (INVALID, b"err Cannot delete old hotfix information.".to_vec());
                }
                let t = self.time() as u32 as i64;
                self.sync_completion(h, HOTFIXES, t, b"", b"");
                (OK, b"ok".to_vec())
            }
            b"get" => self.inventory_get(h, HOTFIXES, "SELECT HOTFIX FROM SYS_HOTFIXES;"),
            _ => {
                self.debug(b"Invalid hotfix info query syntax.".to_vec());
                self.debug2(cat!("DB query error near: ", action));
                (INVALID, near("err Invalid hotfix info query syntax", action))
            }
        }
    }

    /// The package or hotfix list: rows sent to the caller as `due` messages, then a status.
    fn inventory_get(&self, h: &mut Handle, component: i32, sql: &str) -> Answer {
        let mut response = Json::object();
        let mut status = OK;
        match self.component_sync_status(h, component) {
            1 => {
                status = match self.prepare(h, sql) {
                    Some(st) => self.rows_send(&st, h.peer),
                    None => INVALID,
                };
                response.add("status", Json::string(if status == OK { "SUCCESS" } else { "ERROR" }));
            }
            0 => {
                response.add("status", Json::string("NOT_SYNCED"));
            }
            _ => {
                response.add("status", Json::string("ERROR"));
                status = INVALID;
            }
        }
        let p = response.print_unformatted();
        if status == SEND_FAILED {
            // the connection is closed and nothing more is sent
            self.env.close_peer(h.peer);
            return (status, Vec::new());
        }
        if status == OK {
            (status, answer(cat!("ok ", p)))
        } else {
            (status, answer(cat!("err ", p)))
        }
    }
}
