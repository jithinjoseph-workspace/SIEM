//! The agent database commands of wazuh_db/wdb_parser.c: syscheck, the
//! syscollector deltas and legacy inventory, SCA, CIS-CAT, rootcheck and
//! dbsync. Each function mirrors the C pointer by pointer on a [`CBuf`].

use super::agentdb::RkEvent;
use super::fim::{WDB_FILE_TYPE_FILE, WDB_FILE_TYPE_REGISTRY};
use super::integrity::*;
use super::parser::{near, CBuf};
use super::syscollector::*;
use super::*;

type R = (i32, B);

/// `if (next = strchr(curr, '|'), !next) { mdebug1; mdebug2; near }`
macro_rules! cut {
    ($s:ident, $buf:ident, $curr:expr, $m1:expr, $err:expr; $($dbg:expr),+; $near:expr) => {
        match $buf.chr($curr, b'|') {
            Some(p) => p,
            None => {
                $s.mdebug1($m1.as_bytes());
                $s.mdebug2(&msg!($($dbg),+));
                return (OS_INVALID, near($err, $near));
            }
        }
    };
}


/// `!strcmp(at(i), "NULL") ? NULL : at(i)`
fn nul_or(buf: &CBuf, i: usize) -> Option<B> {
    if buf.eq(i, "NULL") {
        None
    } else {
        Some(buf.owned(i))
    }
}

/// `!strncmp(at(i), "NULL", 4) ? OS_INVALID : strtol(at(i))` (as an int)
fn num_or(buf: &CBuf, i: usize) -> i32 {
    if buf.starts(i, "NULL") {
        OS_INVALID
    } else {
        buf.strtol(i) as i32
    }
}

/// The same as a `long`.
fn long_or(buf: &CBuf, i: usize) -> i64 {
    if buf.starts(i, "NULL") {
        OS_INVALID as i64
    } else {
        buf.strtol(i)
    }
}

fn legacy() -> Option<B> {
    Some(SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE.as_bytes().to_vec())
}

impl Wdbd {
    /// `wdb_parse_syscheck`
    pub fn parse_syscheck(&self, wdb: &mut Wdb, component: i32, buf: &mut CBuf, input: usize) -> R {
        let Some(sp) = buf.wchr(input, b' ') else {
            self.mdebug2(&msg!("DB(", wdb.id, ") Invalid FIM query syntax: ", buf.at(input)));
            return (OS_INVALID, near("err Invalid FIM query syntax", buf.at(input)));
        };
        let curr = input;
        buf.nul(sp);
        let next = sp + 1;
        let cmd = buf.owned(curr);
        match &cmd[..] {
            b"scan_info_get" => {
                let (result, ts) = self.scan_info_get(wdb, b"fim", buf.at(next));
                if result < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot get FIM scan info."));
                    (result, out(b"err Cannot get fim scan info.".to_vec()))
                } else {
                    (result, out(msg!("ok ", ts)))
                }
            }
            b"updatedate" => {
                let result = self.fim_update_date_entry(wdb, buf.at(next));
                if result < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot update fim date field."));
                    (result, out(b"err Cannot update fim date field.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"cleandb" => {
                let result = self.fim_clean_old_entries(wdb);
                if result < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot clean fim database."));
                    (result, out(b"err Cannot clean fim database.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"scan_info_update" => {
                let curr = next;
                let Some(sp) = buf.wchr(curr, b' ') else {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Invalid scan_info fim query syntax."));
                    return (OS_INVALID, near("err Invalid Syscheck query syntax", buf.at(curr)));
                };
                buf.nul(sp);
                let ts = strtol(buf.at(sp + 1));
                let field = buf.owned(curr);
                let result = self.scan_info_update(wdb, b"fim", &field, ts);
                if result < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot save fim control message."));
                    (result, out(b"err Cannot save fim control message".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"control" => {
                let v = buf.owned(next);
                let result = self.scan_info_fim_checks_control(wdb, &v);
                if result < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot save fim check_control message."));
                    (result, out(b"err Cannot save fim control message".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"load" => {
                let file = buf.owned(next);
                let (result, s) = self.syscheck_load(wdb, &file, OS_MAXSTR - 16);
                if result < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot load FIM."));
                    (result, out(b"err Cannot load Syscheck".to_vec()))
                } else {
                    (result, out(msg!("ok ", s)))
                }
            }
            b"delete" => {
                let path = buf.owned(next);
                let result = self.fim_delete(wdb, &path);
                if result < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot delete FIM entry."));
                    (result, out(b"err Cannot delete Syscheck".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"save" => {
                let curr = next;
                let Some(sp) = buf.wchr(curr, b' ') else {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Invalid FIM query syntax."));
                    self.mdebug2(&msg!("DB(", wdb.id, ") FIM query: ", buf.at(curr)));
                    return (OS_INVALID, near("err Invalid Syscheck query syntax", buf.at(curr)));
                };
                buf.nul(sp);
                let ftype = if buf.eq(curr, "file") {
                    WDB_FILE_TYPE_FILE
                } else if buf.eq(curr, "registry") {
                    WDB_FILE_TYPE_REGISTRY
                } else {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Invalid FIM query syntax."));
                    self.mdebug2(&msg!("DB(", wdb.id, ") FIM query: ", buf.at(curr)));
                    return (OS_INVALID, near("err Invalid Syscheck query syntax", buf.at(curr)));
                };
                let checksum = sp + 1;
                let Some(sp2) = buf.wchr(checksum, b' ') else {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Invalid FIM query syntax."));
                    self.mdebug2(&msg!("FIM query: ", buf.at(checksum)));
                    return (OS_INVALID, near("err Invalid Syscheck query syntax", buf.at(checksum)));
                };
                buf.nul(sp2);
                let file = buf.owned(sp2 + 1);
                // Only the part before '!' has been escaped
                let c = buf.owned(checksum);
                let unsc = match c.iter().position(|&x| x == b'!') {
                    Some(m) => {
                        let mut u = sk::replace(&c[..m], b"\\ ", b" ");
                        u.extend_from_slice(&c[m..]);
                        u
                    }
                    None => sk::replace(&c, b"\\ ", b" "),
                };
                let result = self.syscheck_save(wdb, ftype, &unsc, &file);
                if result < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot save FIM."));
                    (result, out(b"err Cannot save Syscheck".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"save2" => {
                let p = buf.owned(next);
                if self.syscheck_save2(wdb, &p) == OS_INVALID {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot save FIM."));
                    return (OS_INVALID, out(b"err Cannot save Syscheck".to_vec()));
                }
                (0, out(b"ok".to_vec()))
            }
            _ if cmd.starts_with(b"integrity_check_") => {
                let action = integrity_action(&cmd);
                let payload = buf.owned(next);
                match self.wdbi_query_checksum(wdb, component, action, &payload) {
                    INTEGRITY_SYNC_ERR => {
                        self.mdebug1(&msg!("DB(", wdb.id, ") Cannot query FIM range checksum."));
                        (OS_INVALID, out(b"err Cannot perform range checksum".to_vec()))
                    }
                    INTEGRITY_SYNC_NO_DATA => (0, out(b"ok no_data".to_vec())),
                    INTEGRITY_SYNC_CKS_FAIL => (0, out(b"ok checksum_fail".to_vec())),
                    _ => (0, out(b"ok ".to_vec())),
                }
            }
            b"integrity_clear" => {
                let payload = buf.owned(next);
                match self.wdbi_query_clear(wdb, component, &payload) {
                    OS_INVALID => {
                        self.mdebug1(&msg!("DB(", wdb.id, ") Cannot query FIM range checksum."));
                        (OS_INVALID, out(b"err Cannot perform range checksum".to_vec()))
                    }
                    _ => (0, out(b"ok ".to_vec())),
                }
            }
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") Invalid FIM query syntax."));
                self.mdebug2(&msg!("DB query error near: ", cmd));
                (OS_INVALID, near("err Invalid Syscheck query syntax", &cmd))
            }
        }
    }

    /// `wdb_parse_syscollector`: the component on success.
    pub fn parse_syscollector(&self, wdb: &mut Wdb, query: &[u8], buf: &mut CBuf, input: usize) -> R {
        let component = match query {
            b"syscollector_processes" => {
                self.state.w_inc_agent_syscollector_processes();
                WDB_SYSCOLLECTOR_PROCESSES
            }
            b"syscollector_packages" => {
                self.state.w_inc_agent_syscollector_packages();
                WDB_SYSCOLLECTOR_PACKAGES
            }
            b"syscollector_hotfixes" => {
                self.state.w_inc_agent_syscollector_hotfixes();
                WDB_SYSCOLLECTOR_HOTFIXES
            }
            b"syscollector_ports" => {
                self.state.w_inc_agent_syscollector_ports();
                WDB_SYSCOLLECTOR_PORTS
            }
            b"syscollector_network_protocol" => {
                self.state.w_inc_agent_syscollector_network_protocol();
                WDB_SYSCOLLECTOR_NETPROTO
            }
            b"syscollector_network_address" => {
                self.state.w_inc_agent_syscollector_network_address();
                WDB_SYSCOLLECTOR_NETADDRESS
            }
            b"syscollector_network_iface" => {
                self.state.w_inc_agent_syscollector_network_iface();
                WDB_SYSCOLLECTOR_NETINFO
            }
            b"syscollector_hwinfo" => {
                self.state.w_inc_agent_syscollector_hwinfo();
                WDB_SYSCOLLECTOR_HWINFO
            }
            b"syscollector_osinfo" => {
                self.state.w_inc_agent_syscollector_osinfo();
                WDB_SYSCOLLECTOR_OSINFO
            }
            b"syscollector_users" => {
                self.state.w_inc_agent_syscollector_users();
                WDB_SYSCOLLECTOR_USERS
            }
            b"syscollector_groups" => {
                self.state.w_inc_agent_syscollector_groups();
                WDB_SYSCOLLECTOR_GROUPS
            }
            b"syscollector_browser_extensions" => {
                self.state.w_inc_agent_syscollector_browser_extensions();
                WDB_SYSCOLLECTOR_BROWSER_EXTENSIONS
            }
            b"syscollector_services" => {
                self.state.w_inc_agent_syscollector_services();
                WDB_SYSCOLLECTOR_SERVICES
            }
            _ => {
                self.mdebug2(&msg!("DB(", wdb.id, ") Invalid Syscollector query : ", query));
                return (OS_INVALID, near("err Invalid Syscollector query syntax", query));
            }
        };
        self.mdebug2(&msg!("DB(", wdb.id, ") ", query, " Syscollector query. "));
        let Some(sp) = buf.wchr(input, b' ') else {
            self.mdebug2(&msg!("DB(", wdb.id, ") Invalid Syscollector query syntax: ", buf.at(input)));
            return (OS_INVALID, near("err Invalid Syscollector query syntax", buf.at(input)));
        };
        buf.nul(sp);
        let curr = buf.owned(input);
        let next = sp + 1;
        if curr == b"save2" {
            let p = buf.owned(next);
            if self.syscollector_save2(wdb, component, &p) == OS_INVALID {
                self.mdebug1(&msg!("DB(", wdb.id, ") Cannot save Syscollector."));
                return (OS_INVALID, out(b"err Cannot save Syscollector".to_vec()));
            }
            return (component, out(b"ok".to_vec()));
        }
        if curr.starts_with(b"integrity_check_") {
            let action = integrity_action(&curr);
            let payload = buf.owned(next);
            match self.wdbi_query_checksum(wdb, component, action, &payload) {
                INTEGRITY_SYNC_ERR => {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot query Syscollector range checksum."));
                    (OS_INVALID, out(b"err Cannot perform range checksum".to_vec()))
                }
                INTEGRITY_SYNC_NO_DATA => (component, out(b"ok no_data".to_vec())),
                INTEGRITY_SYNC_CKS_FAIL => (component, out(b"ok checksum_fail".to_vec())),
                _ => (component, out(b"ok ".to_vec())),
            }
        } else if curr.starts_with(b"integrity_clear") {
            let payload = buf.owned(next);
            match self.wdbi_query_clear(wdb, component, &payload) {
                OS_INVALID => {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Cannot query Syscollector range checksum."));
                    (OS_INVALID, out(b"err Cannot perform range checksum".to_vec()))
                }
                _ => (component, out(b"ok ".to_vec())),
            }
        } else {
            self.mdebug1(&msg!("DB(", wdb.id, ") Invalid Syscollector query syntax."));
            self.mdebug2(&msg!("DB query error near: ", curr));
            (OS_INVALID, near("err Invalid Syscollector query syntax", &curr))
        }
    }

    /// `wdb_parse_sca`
    pub fn parse_sca(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        const BAD: &str = "err Invalid Security Configuration Assessment query syntax";
        const BAD2: &str = "err Invalid configuration assessment query syntax";
        let Some(sp) = buf.chr(input, b' ') else {
            self.mdebug1(b"Invalid Security Configuration Assessment query syntax.");
            self.mdebug2(&msg!("Security Configuration Assessment query: ", buf.at(input)));
            return (OS_INVALID, near(BAD, buf.at(input)));
        };
        buf.nul(sp);
        let cmd = buf.owned(input);
        let mut next = sp + 1;
        // `if (next = strchr(curr, '|'), !next) { ... near curr }`
        const SCA: (&str, &str) = ("Invalid Security Configuration Assessment query syntax.", "Security Configuration Assessment query: ");
        const CA: (&str, &str) = ("Invalid configuration assessment query syntax.", "configuration assessment query: ");
        macro_rules! bar {
            ($curr:expr, $log:expr, $msg:expr) => {
                match buf.chr($curr, b'|') {
                    Some(p) => p,
                    None => {
                        self.mdebug1($log.0.as_bytes());
                        self.mdebug2(&msg!($log.1, buf.at($curr)));
                        return (OS_INVALID, near($msg, buf.at($curr)));
                    }
                }
            };
        }
        let found = |r: i32, v: B, err: &str| -> R {
            match r {
                0 => (r, out(b"ok not found".to_vec())),
                1 => (r, out(msg!("ok found ", v))),
                _ => {
                    self.mdebug1(b"Cannot query Security Configuration Assessment.");
                    (r, out(err.as_bytes().to_vec()))
                }
            }
        };
        match &cmd[..] {
            b"query" => {
                let pm_id = buf.strtol(next) as i32;
                let (r, v) = self.sca_find(wdb, pm_id);
                found(r, v, "err Cannot query Security Configuration Assessment")
            }
            b"update" => {
                let curr = next;
                let pm_id = buf.strtol(curr) as i32;
                let p = bar!(curr, SCA, BAD);
                buf.nul(p);
                let result_check = p + 1;
                let p = bar!(result_check, SCA, BAD);
                buf.nul(p);
                let reason_check = p + 1;
                let p = bar!(reason_check, SCA, BAD);
                buf.nul(p);
                next = p + 1;
                let scan_id = if buf.starts(next, "NULL") { OS_INVALID } else { buf.strtol(next) as i32 };
                let rc = buf.owned(result_check);
                let reason = buf.owned(reason_check);
                let result = self.sca_update(wdb, &rc, pm_id, scan_id, &reason);
                if result < 0 {
                    self.mdebug1(b"Cannot update Security Configuration Assessment information.");
                    (result, out(b"err Cannot update Security Configuration Assessment information.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"insert" => self.parse_sca_insert(wdb, buf, next),
            b"delete_policy" => {
                let policy_id = buf.owned(next);
                let result = self.sca_policy_delete(wdb, &policy_id);
                if result < 0 {
                    self.mdebug1(b"Cannot delete Security Configuration Assessment information.");
                    (result, out(b"err Cannot delete Security Configuration Assessment information.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"delete_check_distinct" => {
                let curr = next;
                let p = bar!(curr, SCA, BAD);
                buf.nul(p);
                let policy_id = buf.owned(curr);
                let n = p + 1;
                let scan_id = if buf.starts(n, "NULL") { OS_INVALID } else { buf.strtol(n) as i32 };
                let result = self.sca_check_delete_distinct(wdb, &policy_id, scan_id);
                if result < 0 {
                    self.mdebug1(b"Cannot delete Security Configuration Assessment checks.");
                    (result, out(b"err Cannot delete Security Configuration Assessment checks.".to_vec()))
                } else {
                    self.sca_check_compliances_delete(wdb);
                    self.sca_check_rules_delete(wdb);
                    (result, out(b"ok".to_vec()))
                }
            }
            b"delete_check" => {
                let policy_id = buf.owned(next);
                let result = self.sca_check_delete(wdb, &policy_id);
                if result < 0 {
                    self.mdebug1(b"Cannot delete Security Configuration Assessment information.");
                    (result, out(b"err Cannot delete Security Configuration Assessment check information.".to_vec()))
                } else {
                    self.sca_check_compliances_delete(wdb);
                    self.sca_check_rules_delete(wdb);
                    (result, out(b"ok".to_vec()))
                }
            }
            b"query_results" => {
                let policy_id = buf.owned(next);
                let (r, v) = self.sca_checks_get_result(wdb, &policy_id);
                found(r, v, "err Cannot query Security Configuration Assessment global")
            }
            b"query_scan" => {
                let policy_id = buf.owned(next);
                let (r, v) = self.sca_scan_find(wdb, &policy_id);
                found(r, v, "err Cannot query Security Configuration Assessment scan")
            }
            b"query_policies" => {
                let (r, v) = self.sca_policy_get_id(wdb);
                found(r, v, "err Cannot query Security Configuration Assessment scan")
            }
            b"query_policy" => {
                let policy = buf.owned(next);
                let (r, v) = self.sca_policy_find(wdb, &policy);
                found(r, v, "err Cannot query policy scan")
            }
            b"query_policy_sha256" => {
                let policy = buf.owned(next);
                let (r, v) = self.sca_policy_sha256(wdb, &policy);
                found(r, v, "err Cannot query policy scan")
            }
            b"insert_policy" => {
                let mut f: Vec<B> = Vec::new();
                let mut curr = next;
                for _ in 0..5 {
                    let p = bar!(curr, SCA, BAD);
                    buf.nul(p);
                    f.push(buf.owned(curr));
                    curr = p + 1;
                }
                f.push(buf.owned(curr));
                let arr = [&f[0][..], &f[1][..], &f[2][..], &f[3][..], &f[4][..], &f[5][..]];
                let result = self.sca_policy_info_save(wdb, &arr);
                if result < 0 {
                    self.mdebug1(b"Cannot save Security Configuration Assessment information.");
                    (result, out(b"err Cannot save Security Configuration Assessment global information.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"insert_rules" | b"insert_compliance" => {
                let curr = next;
                let p = bar!(curr, SCA, BAD);
                let id_check = buf.strtol(curr) as i32;
                buf.nul(p);
                let curr = p + 1;
                let p = bar!(curr, SCA, BAD2);
                buf.nul(p);
                let a = buf.owned(curr);
                let b = buf.owned(p + 1);
                let result = if cmd == b"insert_rules" {
                    self.sca_rules_save(wdb, id_check, &a, &b)
                } else {
                    self.sca_compliance_save(wdb, id_check, &a, &b)
                };
                if result < 0 {
                    self.mdebug1(b"Cannot save configuration assessment information.");
                    (result, out(b"err Cannot save configuration assessment global information.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"insert_scan_info" => {
                let mut curr = next;
                let mut v = [0i32; 3];
                for item in v.iter_mut() {
                    let p = bar!(curr, CA, BAD2);
                    *item = num_or(buf, curr);
                    buf.nul(p);
                    curr = p + 1;
                }
                let p = bar!(curr, CA, BAD2);
                let policy_id = curr;
                buf.nul(p);
                curr = p + 1;
                let mut n = [0i32; 5];
                for item in n.iter_mut() {
                    let p = bar!(curr, CA, BAD2);
                    *item = num_or(buf, curr);
                    buf.nul(p);
                    curr = p + 1;
                }
                let pid = buf.owned(policy_id);
                let hash = buf.owned(curr);
                let result = self.sca_scan_info_save(wdb, v[0], v[1], v[2], &pid, n, &hash);
                if result < 0 {
                    self.mdebug1(b"Cannot save configuration assessment information.");
                    (result, out(b"err Cannot save configuration assessment information.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"update_scan_info" => {
                let curr = next;
                let p = bar!(curr, CA, BAD2);
                buf.nul(p);
                let module = nul_or(buf, curr);
                // the C writes a second NUL, skipping one character
                buf.nul(p + 1);
                let n = p + 2;
                let end_scan = num_or(buf, n);
                let result = self.sca_scan_info_update(wdb, module.as_deref(), end_scan);
                if result < 0 {
                    self.mdebug1(b"Cannot save configuration assessment information.");
                    (result, out(b"err Cannot save configuration assessment information.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            b"update_scan_info_start" => {
                let curr = next;
                let p = bar!(curr, CA, BAD2);
                let policy_id_i = curr;
                buf.nul(p);
                let curr = p + 1;
                let p = bar!(curr, CA, BAD2);
                let policy_id = nul_or(buf, policy_id_i);
                buf.nul(p);
                let curr = p + 1;
                // pm_start_scan and pm_end_scan are both read from this field
                let start = num_or(buf, curr);
                let p = bar!(curr, CA, BAD2);
                let end = num_or(buf, curr);
                buf.nul(p);
                let mut curr = p + 1;
                let p = bar!(curr, CA, BAD2);
                let scan_id = num_or(buf, curr);
                buf.nul(p);
                curr = p + 1;
                let mut n = [0i32; 5];
                for item in n.iter_mut() {
                    let p = bar!(curr, CA, BAD2);
                    *item = num_or(buf, curr);
                    buf.nul(p);
                    curr = p + 1;
                }
                let hash = buf.owned(curr);
                let result = self.sca_scan_info_update_start(wdb, policy_id.as_deref(), start, end, scan_id, n, &hash);
                if result < 0 {
                    self.mdebug1(b"Cannot save configuration assessment information.");
                    (result, out(b"err Cannot save configuration assessment information.".to_vec()))
                } else {
                    (result, out(b"ok".to_vec()))
                }
            }
            _ => {
                self.mdebug1(b"Invalid configuration assessment query syntax.");
                self.mdebug2(&msg!("DB query error near: ", cmd));
                (OS_INVALID, near("err Invalid Rootcheck query syntax", &cmd))
            }
        }
    }

    /// The `sca insert` command.
    fn parse_sca_insert(&self, wdb: &mut Wdb, buf: &mut CBuf, curr: usize) -> R {
        use siem_cjson::Json;
        const BAD: &str = "err Invalid Security Configuration Assessment query syntax";
        let text = buf.owned(curr);
        let Ok((event, _)) = siem_cjson::parse_with_opts(&text, false) else {
            self.mdebug1(b"Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");
            return (OS_INVALID, near(BAD, &text));
        };
        let Some(scan_id) = event.get("id") else {
            self.mdebug1(b"Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");
            return (OS_INVALID, near(BAD, &text));
        };
        let Json::Number { int: scan_id, .. } = scan_id else {
            self.mdebug1(b"Malformed JSON: field 'id' must be a number");
            return (OS_INVALID, near(BAD, &text));
        };
        if *scan_id < 0 {
            self.mdebug1(b"Malformed JSON: field 'id' cannot be negative");
            return (OS_INVALID, near(BAD, &text));
        }
        let Some(policy_id) = event.get("policy_id") else {
            self.mdebug1(b"Malformed JSON: field 'policy_id' not found");
            return (OS_INVALID, near(BAD, &text));
        };
        let Some(policy_id) = policy_id.as_bytes() else {
            self.mdebug1(b"Malformed JSON: field 'policy_id' must be a string");
            return (OS_INVALID, near(BAD, &text));
        };
        // the output keeps whatever it had (empty) for the check errors
        let Some(check) = event.get("check") else {
            self.mdebug1(b"Malformed JSON: field 'check' not found");
            return (OS_INVALID, Vec::new());
        };
        let Some(id) = check.get("id") else {
            self.mdebug1(b"Malformed JSON: field 'id' not found");
            return (OS_INVALID, Vec::new());
        };
        let Json::Number { int: id, .. } = id else {
            self.mdebug1(b"Malformed JSON: field 'id' must be a number");
            return (OS_INVALID, Vec::new());
        };
        let Some(title) = check.get("title") else {
            self.mdebug1(b"Malformed JSON: field 'title' not found");
            return (OS_INVALID, Vec::new());
        };
        let Some(title) = title.as_bytes() else {
            self.mdebug1(b"Malformed JSON: field 'title' must be a string");
            return (OS_INVALID, Vec::new());
        };
        // optional strings: present but not a string is an error
        let mut vals: Vec<Option<B>> = Vec::new();
        for (k, name) in [
            ("description", "description"),
            ("rationale", "rationale"),
            ("remediation", "remediation"),
            ("references", "reference"),
            ("file", "file"),
            ("condition", "condition"),
            ("directory", "directory"),
            ("process", "process"),
            ("registry", "registry"),
            ("command", "command"),
            ("result", "result"),
            ("reason", "reason"),
        ] {
            match check.get(k) {
                None => vals.push(None),
                Some(v) => match v.as_bytes() {
                    Some(s) => vals.push(Some(cstr(s).to_vec())),
                    None => {
                        self.mdebug1(&msg!("Malformed JSON: field '", name, "' must be a string"));
                        return (OS_INVALID, Vec::new());
                    }
                },
            }
        }
        let [description, rationale, remediation, reference, file, condition, directory, process, registry, command, result_check, reason] =
            <[Option<B>; 12]>::try_from(vals).expect("12 fields");
        let result_s = result_check.unwrap_or_else(|| b"not applicable".to_vec());
        let texts: [Option<&[u8]>; 14] = [
            Some(cstr(title)),
            description.as_deref(),
            rationale.as_deref(),
            remediation.as_deref(),
            condition.as_deref(),
            file.as_deref(),
            directory.as_deref(),
            process.as_deref(),
            registry.as_deref(),
            reference.as_deref(),
            Some(&result_s),
            Some(cstr(policy_id)),
            command.as_deref(),
            reason.as_deref(),
        ];
        let result = self.sca_save(wdb, *id, *scan_id, &texts);
        if result < 0 {
            self.mdebug1(b"Cannot save Security Configuration Assessment information.");
            (result, out(b"err Cannot save Security Configuration Assessment information.".to_vec()))
        } else {
            (result, out(b"ok".to_vec()))
        }
    }

    /// The unknown-command branch shared by the legacy parsers.
    fn bad_cmd(&self, m1: &str, err: &str, curr: &[u8]) -> R {
        self.mdebug1(m1.as_bytes());
        self.mdebug2(&msg!("DB query error near: ", curr));
        (OS_INVALID, near(err, curr))
    }

    /// The first `strchr(input, ' ')` of the legacy parsers.
    fn first_space(&self, buf: &mut CBuf, input: usize, m1: &str, m2: &str, err: &str) -> Result<usize, R> {
        match buf.chr(input, b' ') {
            Some(sp) => {
                buf.nul(sp);
                Ok(sp + 1)
            }
            None => {
                self.mdebug1(m1.as_bytes());
                self.mdebug2(&msg!(m2, buf.at(input)));
                Err((OS_INVALID, near(err, buf.at(input))))
            }
        }
    }

    /// `wdb_parse_netinfo`
    pub fn parse_netinfo(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        const M1: &str = "Invalid Network query syntax.";
        const P: &str = "Network query: ";
        const E: &str = "err Invalid Network query syntax";
        let next = match self.first_space(buf, input, M1, P, E) {
            Ok(n) => n,
            Err(r) => return r,
        };
        if buf.eq(input, "save") {
            let mut curr = next;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
            let scan_id = curr;
            buf.nul(p);
            curr = p + 1;
            let scan_id = nul_or(buf, scan_id);
            let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
            let scan_time = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(scan_time); buf.at(scan_time));
            let scan_time = nul_or(buf, scan_time);
            let name = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(name); buf.at(name));
            let name = nul_or(buf, name);
            let adapter = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(adapter); buf.at(adapter));
            let adapter = nul_or(buf, adapter);
            let type_ = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(type_); buf.at(type_));
            let type_ = nul_or(buf, type_);
            let state = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(state); buf.at(state));
            let state = nul_or(buf, state);
            let mtu = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, mtu; buf.at(curr));
            let mac = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(mac); buf.at(mac));
            let mac = nul_or(buf, mac);
            // tx_packets .. tx_dropped: each checked with the previous value
            let mut nums = [0i64; 8];
            let mut p = p;
            for k in 0..7 {
                if k > 0 {
                    let prev = nums[k - 1];
                    p = cut!(self, buf, curr, M1, E; P, prev; buf.at(curr));
                }
                nums[k] = long_or(buf, curr);
                buf.nul(p);
                curr = p + 1;
            }
            nums[7] = long_or(buf, curr);
            let r = Netinfo {
                scan_id,
                scan_time,
                name,
                adapter,
                type_,
                state,
                mtu: mtu as i64,
                mac,
                tx_packets: nums[0],
                rx_packets: nums[1],
                tx_bytes: nums[2],
                rx_bytes: nums[3],
                tx_errors: nums[4],
                rx_errors: nums[5],
                tx_dropped: nums[6],
                rx_dropped: nums[7],
                checksum: legacy(),
                item_id: None,
            };
            let result = self.netinfo_save(wdb, &r, false);
            if result < 0 {
                self.mdebug1(b"Cannot save Network information.");
                (result, out(b"err Cannot save Network information.".to_vec()))
            } else {
                (result, out(b"ok".to_vec()))
            }
        } else if buf.eq(input, "del") {
            let scan_id = nul_or(buf, next);
            let result = self.netinfo_delete(wdb, scan_id.as_deref());
            if result < 0 {
                self.mdebug1(b"Cannot delete old network information.");
                (result, out(b"err Cannot delete old network information.".to_vec()))
            } else {
                (result, out(b"ok".to_vec()))
            }
        } else {
            self.bad_cmd("Invalid netinfo query syntax.", "err Invalid netinfo query syntax", buf.at(input))
        }
    }

    /// `wdb_parse_netproto`
    pub fn parse_netproto(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        const M1: &str = "Invalid netproto query syntax.";
        const P: &str = "netproto query: ";
        const E: &str = "err Invalid netproto query syntax";
        let next = match self.first_space(buf, input, M1, P, E) {
            Ok(n) => n,
            Err(r) => return r,
        };
        if !buf.eq(input, "save") {
            return self.bad_cmd(M1, E, buf.at(input));
        }
        let mut curr = next;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
        let scan_id = curr;
        buf.nul(p);
        curr = p + 1;
        let scan_id = nul_or(buf, scan_id);
        let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
        let iface = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(iface); buf.at(iface));
        let iface = nul_or(buf, iface);
        let type_ = buf.strtol(curr) as i32;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, "Invalid Network query syntax.", "err Invalid Network query syntax"; "Network query: ", type_; buf.at(curr));
        let gateway = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(gateway); buf.at(gateway));
        let gateway = nul_or(buf, gateway);
        let dhcp = curr;
        buf.nul(p);
        let dhcp = nul_or(buf, dhcp);
        let metric = num_or(buf, p + 1);
        let r = Netproto { scan_id, iface, type_, gateway, dhcp, metric, checksum: legacy(), item_id: None };
        let result = self.netproto_save(wdb, &r, false);
        if result < 0 {
            self.mdebug1(b"Cannot save netproto information.");
            (result, out(b"err Cannot save netproto information.".to_vec()))
        } else {
            (result, out(b"ok".to_vec()))
        }
    }

    /// `wdb_parse_netaddr`
    pub fn parse_netaddr(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        const M1: &str = "Invalid netaddr query syntax.";
        const P: &str = "netaddr query: ";
        const E: &str = "err Invalid netaddr query syntax";
        let next = match self.first_space(buf, input, M1, P, E) {
            Ok(n) => n,
            Err(r) => return r,
        };
        if !buf.eq(input, "save") {
            return self.bad_cmd(M1, E, buf.at(input));
        }
        let mut curr = next;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
        let scan_id = curr;
        buf.nul(p);
        curr = p + 1;
        let scan_id = nul_or(buf, scan_id);
        let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
        let iface = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(iface); buf.at(iface));
        let iface = nul_or(buf, iface);
        let proto = buf.strtol(curr) as i32;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, "Invalid Network query syntax.", "err Invalid Network query syntax"; "Network query: ", proto; buf.at(curr));
        let address = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(address); buf.at(address));
        let address = nul_or(buf, address);
        let netmask = curr;
        buf.nul(p);
        let netmask = nul_or(buf, netmask);
        let broadcast = nul_or(buf, p + 1);
        let r = Netaddr { scan_id, iface, proto, address, netmask, broadcast, checksum: legacy(), item_id: None };
        let result = self.netaddr_save(wdb, &r, false);
        if result < 0 {
            self.mdebug1(b"Cannot save netaddr information.");
            (result, out(b"err Cannot save netaddr information.".to_vec()))
        } else {
            (result, out(b"ok".to_vec()))
        }
    }

    /// `wdb_parse_osinfo`
    pub fn parse_osinfo(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut tail = 0;
        let Some(tok) = buf.strtok(Some(input), &mut tail, b" ") else {
            return (OS_INVALID, out(b"err Missing osinfo action".to_vec()));
        };
        if buf.eq(tok, "get") {
            match self.agents_get_sys_osinfo(wdb) {
                None => (OS_INVALID, out(msg!("err Cannot get sys_osinfo database table information; SQL err: ", wdb.errmsg()))),
                Some(r) => (OS_SUCCESS, out(msg!("ok ", r.print_unformatted()))),
            }
        } else if buf.eq(tok, "set") {
            self.parse_agents_set_sys_osinfo(wdb, buf, tail)
        } else {
            (OS_INVALID, out(msg!("err Invalid osinfo action: ", buf.at(tok))))
        }
    }

    /// `wdb_parse_agents_set_sys_osinfo`
    fn parse_agents_set_sys_osinfo(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut curr = input;
        let mut f: Vec<Option<B>> = Vec::new();
        // scan_id .. os_release
        for _ in 0..15 {
            let Some(p) = buf.chr(curr, b'|') else {
                self.mdebug1(b"Invalid OS info query syntax.");
                return (OS_INVALID, out(b"err Invalid OS info query syntax".to_vec()));
            };
            let field = curr;
            buf.nul(p);
            curr = p + 1;
            f.push(nul_or(buf, field));
        }
        let p = cut!(self, buf, curr, "Invalid OS info query syntax.", "err Invalid OS info query syntax"; "OS info query: ", buf.at(curr); buf.at(curr));
        let os_patch = curr;
        buf.nul(p);
        let os_patch = nul_or(buf, os_patch);
        let os_display_version = nul_or(buf, p + 1);
        let mut f = f.into_iter();
        let mut n = || f.next().expect("15 fields");
        let r = Osinfo {
            scan_id: n(),
            scan_time: n(),
            hostname: n(),
            architecture: n(),
            os_name: n(),
            os_version: n(),
            os_codename: n(),
            os_major: n(),
            os_minor: n(),
            os_build: n(),
            os_platform: n(),
            sysname: n(),
            release: n(),
            version: n(),
            os_release: n(),
            os_patch,
            os_display_version,
            checksum: legacy(),
        };
        let result = self.osinfo_save(wdb, &r, false);
        if result < 0 {
            self.mdebug1(b"Cannot save OS information.");
            (result, out(b"err Cannot save OS information.".to_vec()))
        } else {
            (result, out(b"ok".to_vec()))
        }
    }

    /// `wdb_parse_hardware`
    pub fn parse_hardware(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        const M1: &str = "Invalid HW info query syntax.";
        const P: &str = "HW info query: ";
        const E: &str = "err Invalid HW info query syntax";
        let next = match self.first_space(buf, input, M1, P, E) {
            Ok(n) => n,
            Err(r) => return r,
        };
        if !buf.eq(input, "save") {
            return self.bad_cmd(M1, E, buf.at(input));
        }
        let mut curr = next;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
        let scan_id = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
        let scan_id = nul_or(buf, scan_id);
        let scan_time = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(scan_time); buf.at(scan_time));
        let scan_time = nul_or(buf, scan_time);
        let serial = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(serial); buf.at(serial));
        let serial = nul_or(buf, serial);
        let cpu_name = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(cpu_name); buf.at(cpu_name));
        let cpu_name = nul_or(buf, cpu_name);
        let cpu_cores = buf.strtol(curr) as i32;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, cpu_cores; buf.at(curr));
        let cpu_mhz = super::delta::c_strtod(buf.at(curr)).0;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, fmt_f(cpu_mhz); buf.at(curr));
        let ram_total = buf.strtol(curr) as u64;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, ram_total; buf.at(curr));
        let ram_free = buf.strtol(curr) as u64;
        buf.nul(p);
        let ram_usage = buf.strtol(p + 1) as i32;
        let r = Hardware { scan_id, scan_time, serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum: legacy() };
        let result = self.hardware_save(wdb, &r, false);
        if result < 0 {
            self.mdebug1(b"wdb_parse_hardware(): Cannot save HW information.");
            (result, out(b"err Cannot save HW information.".to_vec()))
        } else {
            (result, out(b"ok".to_vec()))
        }
    }

    /// `wdb_parse_ports`
    pub fn parse_ports(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        const M1: &str = "Invalid Port query syntax.";
        const P: &str = "Port query: ";
        const E: &str = "err Invalid Port query syntax";
        let next = match self.first_space(buf, input, M1, P, E) {
            Ok(n) => n,
            Err(r) => return r,
        };
        if buf.eq(input, "save") {
            let mut curr = next;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
            let scan_id = curr;
            buf.nul(p);
            curr = p + 1;
            let scan_id = nul_or(buf, scan_id);
            let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
            let scan_time = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(scan_time); buf.at(scan_time));
            let scan_time = nul_or(buf, scan_time);
            let protocol = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(protocol); buf.at(protocol));
            let protocol = nul_or(buf, protocol);
            let local_ip = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(local_ip); buf.at(local_ip));
            let local_ip = nul_or(buf, local_ip);
            let local_port = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, local_port; buf.at(curr));
            let remote_ip = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(remote_ip); buf.at(remote_ip));
            let remote_ip = nul_or(buf, remote_ip);
            let remote_port = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, remote_port; buf.at(curr));
            let tx_queue = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, tx_queue; buf.at(curr));
            let rx_queue = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, rx_queue; buf.at(curr));
            // strtoll
            let inode = long_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, inode; buf.at(curr));
            let state = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(state); buf.at(state));
            let state = nul_or(buf, state);
            let pid = num_or(buf, curr);
            buf.nul(p);
            let n = p + 1;
            let process = if buf.starts(n, "NULL") { None } else { Some(buf.owned(n)) };
            let r = Port {
                scan_id,
                scan_time,
                protocol,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                tx_queue,
                rx_queue,
                inode,
                state,
                pid,
                process,
                checksum: legacy(),
                item_id: None,
            };
            let result = self.port_save(wdb, &r, true);
            if result < 0 {
                self.mdebug1(b"Cannot save Port information.");
                (result, out(b"err Cannot save Port information.".to_vec()))
            } else {
                (result, out(b"ok".to_vec()))
            }
        } else if buf.eq(input, "del") {
            let scan_id = nul_or(buf, next);
            let result = self.port_delete(wdb, scan_id.as_deref());
            if result < 0 {
                self.mdebug1(b"Cannot delete old Port information.");
                (result, out(b"err Cannot delete old Port information.".to_vec()))
            } else {
                (result, out(b"ok".to_vec()))
            }
        } else {
            self.bad_cmd(M1, E, buf.at(input))
        }
    }

    /// The `get` action of packages and hotfixes.
    fn inventory_get(&self, wdb: &mut Wdb, component: i32, stmt: usize) -> R {
        let (result, response) = self.agents_get_inventory(wdb, component, stmt);
        let p = response.print_unformatted();
        let mut o = if result == OS_SUCCESS { out(msg!("ok ", p)) } else { out(msg!("err ", p)) };
        if result == OS_SOCKTERR {
            // Close the socket and send nothing as a response
            self.env.close_peer(wdb.peer);
            o.clear();
        }
        (result, o)
    }

    /// `wdb_parse_packages`
    pub fn parse_packages(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut tail = 0;
        let Some(action) = buf.strtok(Some(input), &mut tail, b" ") else {
            self.mdebug1(b"Invalid package info query syntax. Missing action");
            self.mdebug2(b"DB query error. Missing action");
            return (OS_INVALID, out(b"err Invalid package info query syntax. Missing action".to_vec()));
        };
        if buf.eq(action, "save") {
            let mut fields: Vec<Option<B>> = vec![None; 16];
            for (i, field) in fields.iter_mut().enumerate() {
                let last = tail;
                if i < 15 {
                    let Some(p) = buf.chr(tail, b'|') else {
                        self.mdebug1(b"Invalid package info query syntax.");
                        self.mdebug2(&msg!("Package info query: ", buf.at(last)));
                        return (OS_INVALID, near("err Invalid package info query syntax", buf.at(last)));
                    };
                    buf.nul(p);
                    tail = p + 1;
                }
                if !buf.eq(last, "NULL") {
                    *field = Some(buf.owned(last));
                }
            }
            // size must be converted and can be NULL with a longer string
            let size = match &fields[6] {
                Some(s) if !s.starts_with(b"NULL") => strtol(s),
                _ => OS_INVALID as i64,
            };
            let mut f = fields.into_iter();
            let mut n = || f.next().expect("16 fields");
            let r = Package {
                scan_id: n(),
                scan_time: n(),
                format: n(),
                name: n(),
                priority: n(),
                section: {
                    let s = n();
                    n();
                    s
                },
                size,
                vendor: n(),
                install_time: n(),
                version: n(),
                architecture: n(),
                multiarch: n(),
                source: n(),
                description: n(),
                location: n(),
                checksum: legacy(),
                item_id: n(),
            };
            let result = self.package_save(wdb, &r, false);
            if result < 0 {
                self.mdebug1(b"Cannot save package information.");
                (result, out(b"err Cannot save package information.".to_vec()))
            } else {
                let t = self.time() as u32 as i64;
                self.wdbi_update_attempt(wdb, WDB_SYSCOLLECTOR_PACKAGES, t, b"", b"", true);
                (result, out(b"ok".to_vec()))
            }
        } else if buf.eq(action, "del") {
            let scan_id = nul_or(buf, tail);
            if self.package_update(wdb, scan_id.as_deref()) < 0 {
                self.mdebug1(b"Cannot update scanned packages.");
            }
            let result = self.package_delete(wdb, scan_id.as_deref());
            if result < 0 {
                self.mdebug1(b"Cannot delete old package information.");
                (result, out(b"err Cannot delete old package information.".to_vec()))
            } else {
                let t = self.time() as u32 as i64;
                self.wdbi_update_completion(wdb, WDB_SYSCOLLECTOR_PACKAGES, t, b"", b"");
                (result, out(b"ok".to_vec()))
            }
        } else if buf.eq(action, "get") {
            self.inventory_get(wdb, WDB_SYSCOLLECTOR_PACKAGES, WDB_STMT_SYS_PROGRAMS_GET)
        } else {
            self.mdebug1(b"Invalid package info query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(input)));
            (OS_INVALID, near("err Invalid package info query syntax", buf.at(input)))
        }
    }

    /// `wdb_parse_hotfixes`
    pub fn parse_hotfixes(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut tail = 0;
        let Some(action) = buf.strtok(Some(input), &mut tail, b" ") else {
            self.mdebug1(b"Invalid hotfix info query syntax. Missing action");
            self.mdebug2(b"DB query error. Missing action");
            return (OS_INVALID, out(b"err Invalid hotfix info query syntax. Missing action".to_vec()));
        };
        if buf.eq(action, "save") {
            let mut fields: Vec<Option<B>> = vec![None; 3];
            let mut last = tail;
            for field in fields.iter_mut() {
                let Some(tok) = buf.strtok(None, &mut tail, b"|") else {
                    self.mdebug1(b"Invalid hotfix info query syntax.");
                    self.mdebug2(&msg!("Hotfix info query: ", buf.at(last)));
                    return (OS_INVALID, near("err Invalid hotfix info query syntax", buf.at(last)));
                };
                last = tok;
                if !buf.eq(tok, "NULL") {
                    *field = Some(buf.owned(tok));
                }
            }
            let result = self.hotfix_save(wdb, &fields[0], &fields[1], &fields[2], &legacy(), false);
            if result < 0 {
                self.mdebug1(b"Cannot save hotfix information.");
                (result, out(b"err Cannot save hotfix information.".to_vec()))
            } else {
                let t = self.time() as u32 as i64;
                self.wdbi_update_attempt(wdb, WDB_SYSCOLLECTOR_HOTFIXES, t, b"", b"", true);
                (result, out(b"ok".to_vec()))
            }
        } else if buf.eq(action, "del") {
            let scan_id = nul_or(buf, tail);
            let result = self.hotfix_delete(wdb, scan_id.as_deref());
            if result < 0 {
                self.mdebug1(b"Cannot delete old hotfix information.");
                (result, out(b"err Cannot delete old hotfix information.".to_vec()))
            } else {
                let t = self.time() as u32 as i64;
                self.wdbi_update_completion(wdb, WDB_SYSCOLLECTOR_HOTFIXES, t, b"", b"");
                (result, out(b"ok".to_vec()))
            }
        } else if buf.eq(action, "get") {
            self.inventory_get(wdb, WDB_SYSCOLLECTOR_HOTFIXES, WDB_STMT_SYS_HOTFIXES_GET)
        } else {
            self.mdebug1(b"Invalid hotfix info query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(input)));
            (OS_INVALID, near("err Invalid hotfix info query syntax", buf.at(input)))
        }
    }

    /// `wdb_parse_processes`
    pub fn parse_processes(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        const M1: &str = "Invalid Process query syntax.";
        const P: &str = "Process query: ";
        const E: &str = "err Invalid Process query syntax";
        let next = match self.first_space(buf, input, M1, P, E) {
            Ok(n) => n,
            Err(r) => return r,
        };
        if buf.eq(input, "save") {
            let mut curr = next;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
            let scan_id = curr;
            buf.nul(p);
            curr = p + 1;
            let scan_id = nul_or(buf, scan_id);
            let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
            let scan_time = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(scan_time); buf.at(scan_time));
            let scan_time = nul_or(buf, scan_time);
            let pid = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, pid; buf.at(curr));
            let name = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(name); buf.at(name));
            let name = nul_or(buf, name);
            let state = curr;
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, buf.at(state); buf.at(state));
            let state = nul_or(buf, state);
            let ppid = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, ppid; buf.at(curr));
            let utime = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, utime; buf.at(curr));
            let stime = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let mut p = cut!(self, buf, curr, M1, E; P, stime; buf.at(curr));
            // cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup
            let mut texts: Vec<Option<B>> = Vec::new();
            for _ in 0..9 {
                let s = curr;
                buf.nul(p);
                curr = p + 1;
                p = cut!(self, buf, curr, M1, E; P, buf.at(s); buf.at(s));
                texts.push(nul_or(buf, s));
            }
            let priority = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, priority; buf.at(curr));
            let nice = if buf.starts(curr, "NULL") { 0 } else { buf.strtol(curr) as i32 };
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, nice; buf.at(curr));
            let size = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, size; buf.at(curr));
            let vm_size = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, vm_size; buf.at(curr));
            let resident = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, resident; buf.at(curr));
            let share = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, share; buf.at(curr));
            let start_time = if buf.starts(curr, "NULL") { OS_INVALID as i64 } else { super::parser::strtoul(buf.at(curr)) as i64 };
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, start_time; buf.at(curr));
            let pgrp = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, pgrp; buf.at(curr));
            let session = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, session; buf.at(curr));
            let nlwp = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, nlwp; buf.at(curr));
            let tgid = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
            let p = cut!(self, buf, curr, M1, E; P, tgid; buf.at(curr));
            let tty = num_or(buf, curr);
            buf.nul(p);
            let processor = num_or(buf, p + 1);
            let mut t = texts.into_iter();
            let mut n = || t.next().expect("9 fields");
            let r = Process {
                scan_id,
                scan_time,
                pid,
                name,
                state,
                ppid,
                utime,
                stime,
                cmd: n(),
                argvs: n(),
                euser: n(),
                ruser: n(),
                suser: n(),
                egroup: n(),
                rgroup: n(),
                sgroup: n(),
                fgroup: n(),
                priority,
                nice,
                size,
                vm_size,
                resident,
                share,
                start_time,
                pgrp,
                session,
                nlwp,
                tgid,
                tty,
                processor,
                checksum: legacy(),
            };
            let result = self.process_save(wdb, &r, false);
            if result < 0 {
                self.mdebug1(b"Cannot save Process information.");
                (result, out(b"err Cannot save Process information.".to_vec()))
            } else {
                (result, out(b"ok".to_vec()))
            }
        } else if buf.eq(input, "del") {
            let scan_id = nul_or(buf, next);
            let result = self.process_delete(wdb, scan_id.as_deref());
            if result < 0 {
                self.mdebug1(b"Cannot delete old Process information.");
                (result, out(b"err Cannot delete old Process information.".to_vec()))
            } else {
                (result, out(b"ok".to_vec()))
            }
        } else {
            self.bad_cmd(M1, E, buf.at(input))
        }
    }

    /// `wdb_parse_ciscat`
    pub fn parse_ciscat(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        const M1: &str = "Invalid CISCAT query syntax.";
        const P: &str = "CISCAT query: ";
        const E: &str = "err Invalid CISCAT query syntax";
        let next = match self.first_space(buf, input, M1, P, E) {
            Ok(n) => n,
            Err(r) => return r,
        };
        if !buf.eq(input, "save") {
            return self.bad_cmd(M1, E, buf.at(input));
        }
        let mut curr = next;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
        let scan_id = curr;
        buf.nul(p);
        curr = p + 1;
        let scan_id = nul_or(buf, scan_id);
        let p = cut!(self, buf, curr, M1, E; P, buf.at(curr); buf.at(curr));
        let scan_time = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(scan_time); buf.at(scan_time));
        let scan_time = nul_or(buf, scan_time);
        let benchmark = curr;
        buf.nul(p);
        curr = p + 1;
        let p = cut!(self, buf, curr, M1, E; P, buf.at(benchmark); buf.at(benchmark));
        let benchmark = nul_or(buf, benchmark);
        let profile = curr;
        buf.nul(p);
        curr = p + 1;
        let mut p = cut!(self, buf, curr, M1, E; P, buf.at(profile); buf.at(profile));
        let profile = nul_or(buf, profile);
        // pass, fail, error, notchecked, unknown; score is the rest
        let mut n = [0i32; 6];
        for k in 0..5 {
            if k > 0 {
                let prev = n[k - 1];
                p = cut!(self, buf, curr, M1, E; P, prev; buf.at(curr));
            }
            n[k] = num_or(buf, curr);
            buf.nul(p);
            curr = p + 1;
        }
        n[5] = num_or(buf, curr);
        let result = self.ciscat_save(wdb, scan_id.as_deref(), scan_time.as_deref(), benchmark.as_deref(), profile.as_deref(), n);
        if result < 0 {
            self.mdebug1(b"Cannot save CISCAT information.");
            (result, out(b"err Cannot save CISCAT information.".to_vec()))
        } else {
            (result, out(b"ok".to_vec()))
        }
    }

    /// `wdb_parse_rootcheck`
    pub fn parse_rootcheck(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let next = match buf.wchr(input, b' ') {
            Some(p) => {
                buf.nul(p);
                Some(p + 1)
            }
            None => None,
        };
        let id = wdb.id.clone();
        let bad = |s: &Self, b: &CBuf| {
            s.mdebug2(&msg!("DB(", id, ") Invalid rootcheck query syntax: ", b.at(input)));
            (OS_INVALID, near("err Invalid rootcheck query syntax", b.at(input)))
        };
        if buf.eq(input, "delete") {
            if self.rootcheck_delete(wdb) >= 0 {
                (0, out(b"ok 0".to_vec()))
            } else {
                (OS_INVALID, out(b"err Error deleting rootcheck PM tuple".to_vec()))
            }
        } else if buf.eq(input, "save") {
            let Some(next) = next else {
                return bad(self, buf);
            };
            let Some(ptr) = buf.wchr(next, b' ') else {
                return bad(self, buf);
            };
            buf.nul(ptr);
            let date_last = buf.strtol(next);
            let event = RkEvent { date_first: date_last, date_last, log: buf.owned(ptr + 1) };
            if date_last == i64::MAX || date_last < 0 {
                self.mdebug2(&msg!("DB(", wdb.id, ") Invalid rootcheck date timestamp: ", date_last));
                return (OS_INVALID, near("err Invalid rootcheck query syntax", buf.at(input)));
            }
            match self.rootcheck_update(wdb, &event) {
                OS_INVALID => {
                    self.merror(&msg!("DB(", wdb.id, ") Error updating rootcheck PM tuple on SQLite database"));
                    (OS_INVALID, out(b"err Error updating rootcheck PM tuple".to_vec()))
                }
                OS_SUCCESS => {
                    if self.rootcheck_insert(wdb, &event) < 0 {
                        self.merror(&msg!("DB(", wdb.id, ") Error inserting rootcheck PM tuple on SQLite database for agent"));
                        (OS_INVALID, out(b"err Error updating rootcheck PM tuple".to_vec()))
                    } else {
                        (0, out(b"ok 2".to_vec()))
                    }
                }
                _ => (0, out(b"ok 1".to_vec())),
            }
        } else {
            bad(self, buf)
        }
    }

    /// `wdb_parse_dbsync`
    pub fn parse_dbsync(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let bad = |s: &Self, b: &CBuf| {
            s.mdebug2(&msg!("DBSYNC query: ", b.at(input)));
            (OS_INVALID, near("err Invalid dbsync query syntax", b.at(input)))
        };
        let Some(p) = buf.chr(input, b' ') else {
            return bad(self, buf);
        };
        buf.nul(p);
        let curr = p + 1;
        let Some(p2) = buf.chr(curr, b' ') else {
            return bad(self, buf);
        };
        buf.nul(p2);
        let data = p2 + 1;
        if buf.at(data).is_empty() {
            return bad(self, buf);
        }
        let table_key = buf.owned(input);
        let operation = buf.owned(curr);
        let data = buf.owned(data);
        // strncmp(key, table_key, OS_SIZE_256 - 1) == 0
        let n = OS_SIZE_256 - 1;
        let tk = &table_key[..table_key.len().min(n)];
        let mut ret = OS_INVALID;
        if let Some(kv) = super::tables::TABLE_MAP.iter().find(|kv| &kv.key.as_bytes()[..kv.key.len().min(n)] == tk) {
            ret = if self.process_dbsync_data(wdb, kv, &operation, &data) { OS_SUCCESS } else { OS_INVALID };
        }
        if ret == OS_SUCCESS {
            (ret, b"ok ".to_vec())
        } else {
            (ret, b"err".to_vec())
        }
    }

    /// `process_dbsync_data`
    fn process_dbsync_data(&self, wdb: &mut Wdb, kv: &super::tables::Kv, operation: &[u8], raw: &[u8]) -> bool {
        match siem_cjson::parse_with_opts(raw, true) {
            Ok((data, _)) => match operation {
                b"INSERTED" | b"MODIFIED" => self.upsert_dbsync(wdb, kv, &data),
                b"DELETED" => {
                    self.delete_dbsync(wdb, kv, &data);
                    true
                }
                _ => {
                    self.mdebug1(&msg!("Invalid operation type: ", operation));
                    false
                }
            },
            Err(off) => {
                self.mdebug1(b"(5217): Could not parse syscollector delta information as JSON.");
                self.mdebug2(&msg!("JSON error near: ", cstr(&raw[off.min(raw.len())..])));
                false
            }
        }
    }
}

/// `printf("%f", v)`
fn fmt_f(v: f64) -> String {
    if v.is_nan() {
        if v.is_sign_negative() { "-nan".into() } else { "nan".into() }
    } else if v.is_infinite() {
        if v < 0.0 { "-inf".into() } else { "inf".into() }
    } else {
        format!("{v:.6}")
    }
}

/// The `integrity_check_*` action (INTEGRITY_CLEAR for an unknown suffix).
fn integrity_action(cmd: &[u8]) -> i32 {
    if cmd == INTEGRITY_COMMANDS[INTEGRITY_CHECK_GLOBAL as usize].as_bytes() {
        INTEGRITY_CHECK_GLOBAL
    } else if cmd == INTEGRITY_COMMANDS[INTEGRITY_CHECK_LEFT as usize].as_bytes() {
        INTEGRITY_CHECK_LEFT
    } else if cmd == INTEGRITY_COMMANDS[INTEGRITY_CHECK_RIGHT as usize].as_bytes() {
        INTEGRITY_CHECK_RIGHT
    } else {
        INTEGRITY_CLEAR
    }
}
