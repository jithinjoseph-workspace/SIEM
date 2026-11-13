//! FIM entries (wazuh_db/wdb_fim.c) and the scan_info table
//! (wazuh_db/wdb_scan_info.c).

use siem_cjson::Json;
use siem_sqlite::Stmt;

use super::sk::{self, Sum};
use super::*;

pub const WDB_FILE_TYPE_FILE: i32 = 0;
pub const WDB_FILE_TYPE_REGISTRY: i32 = 1;

impl Wdbd {
    /// `wdb_scan_info_update`: the changed rows or -1.
    pub fn scan_info_update(&self, wdb: &mut Wdb, module: &[u8], field: &[u8], value: i64) -> i32 {
        let field = cstr(field);
        let mut st: Option<std::sync::Arc<Stmt>> = None;
        let cases: [(&[u8], usize, bool); 7] = [
            (b"first_start", WDB_STMT_SCAN_INFO_UPDATEFS, true),
            (b"first_end", WDB_STMT_SCAN_INFO_UPDATEFE, true),
            (b"start_scan", WDB_STMT_SCAN_INFO_UPDATESS, false),
            (b"end_scan", WDB_STMT_SCAN_INFO_UPDATEES, false),
            (b"fim_first_check", WDB_STMT_SCAN_INFO_UPDATE1C, false),
            (b"fim_second_check", WDB_STMT_SCAN_INFO_UPDATE2C, false),
            (b"fim_third_check", WDB_STMT_SCAN_INFO_UPDATE3C, false),
        ];
        for (name, idx, three) in cases {
            if field == name {
                if self.stmt_cache(wdb, idx) < 0 {
                    self.merror(&msg!("DB(", wdb.id, ") Cannot cache statement"));
                    return -1;
                }
                let s = wdb.st(idx);
                if three {
                    s.bind_int64(2, value);
                    s.bind_text(3, Some(module));
                } else {
                    s.bind_text(2, Some(module));
                }
                st = Some(s);
            }
        }
        // an unknown field leaves a NULL statement: binding and stepping it
        // are SQLITE_MISUSE
        let r = match &st {
            Some(s) => {
                s.bind_int64(1, value);
                self.step(s)
            }
            None => SQLITE_MISUSE,
        };
        if r == SQLITE_DONE {
            wdb.db().changes()
        } else {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
            -1
        }
    }

    /// `wdb_scan_info_get`: (1 found | 0 not found | -1, value).
    pub fn scan_info_get(&self, wdb: &mut Wdb, module: &[u8], field: &[u8]) -> (i32, i64) {
        let field = cstr(field);
        let cases: [(&[u8], usize); 7] = [
            (b"first_start", WDB_STMT_SCAN_INFO_GETFS),
            (b"first_end", WDB_STMT_SCAN_INFO_GETFE),
            (b"start_scan", WDB_STMT_SCAN_INFO_GETSS),
            (b"end_scan", WDB_STMT_SCAN_INFO_GETES),
            (b"fim_first_check", WDB_STMT_SCAN_INFO_GET1C),
            (b"fim_second_check", WDB_STMT_SCAN_INFO_GET2C),
            (b"fim_third_check", WDB_STMT_SCAN_INFO_GET3C),
        ];
        let mut st = None;
        for (name, idx) in cases {
            if field == name {
                if self.stmt_cache(wdb, idx) < 0 {
                    self.merror(&msg!("DB(", wdb.id, ") Cannot cache statement"));
                    return (-1, 0);
                }
                st = Some(wdb.st(idx));
            }
        }
        let r = match &st {
            Some(s) => {
                s.bind_text(1, Some(module));
                self.step(s)
            }
            None => SQLITE_MISUSE,
        };
        match r {
            SQLITE_ROW => (1, st.expect("statement").column_int64(0)),
            SQLITE_DONE => (0, 0),
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                (-1, 0)
            }
        }
    }

    /// `wdb_scan_info_fim_checks_control`
    pub fn scan_info_fim_checks_control(&self, wdb: &mut Wdb, last_check: &[u8]) -> i32 {
        let last = strtol(last_check);
        let mut value = 0i64;
        let (r, v) = self.scan_info_get(wdb, b"fim", b"fim_second_check");
        if r < 0 {
            self.mdebug1(&msg!("DB(", wdb.id, ") Cannot get scan_info entry"));
        } else {
            value = v;
        }
        if self.scan_info_update(wdb, b"fim", b"fim_third_check", value) < 0 {
            self.mdebug1(&msg!("DB(", wdb.id, ") Cannot update scan_info entry"));
        }
        let (r, v) = self.scan_info_get(wdb, b"fim", b"fim_first_check");
        if r < 0 {
            self.mdebug1(&msg!("DB(", wdb.id, ") Cannot get scan_info entry"));
        } else {
            value = v;
        }
        if self.scan_info_update(wdb, b"fim", b"fim_second_check", value) < 0 {
            self.mdebug1(&msg!("DB(", wdb.id, ") Cannot update scan_info entry"));
        }
        if self.scan_info_update(wdb, b"fim", b"fim_first_check", last) < 0 {
            self.mdebug1(&msg!("DB(", wdb.id, ") Cannot update scan_info entry"));
        }
        0
    }

    /// `wdb_syscheck_load`: (result, the checksum string).
    pub fn syscheck_load(&self, wdb: &mut Wdb, file: &[u8], size: usize) -> (i32, B) {
        if self.stmt_cache(wdb, WDB_STMT_FIM_LOAD) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement"));
            return (-1, Vec::new());
        }
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't begin transaction"));
            return (-1, Vec::new());
        }
        let st = wdb.st(WDB_STMT_FIM_LOAD);
        if st.bind_text(1, Some(file)) != SQLITE_OK {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_text(): ", wdb.errmsg()));
            return (-1, Vec::new());
        }
        match self.step(&st) {
            SQLITE_ROW => {
                let mut sum = Sum {
                    changes: st.column_int64(0) as i32,
                    size: st.column_text(1),
                    uid: st.column_text(3),
                    gid: st.column_text(4),
                    md5: st.column_text(5),
                    sha1: st.column_text(6),
                    uname: st.column_text(7),
                    gname: st.column_text(8),
                    mtime: st.column_int64(9),
                    inode: st.column_int64(10),
                    sha256: st.column_text(11),
                    date_alert: st.column_int64(12),
                    attributes: st.column_text(13),
                    symbolic_path: st.column_text(14),
                    ..Default::default()
                };
                let str_perm = st.column_text(2);
                match &str_perm {
                    Some(p) if p.first().is_some_and(|c| c.is_ascii_digit()) => sum.perm = strtol_base8(p) as i32,
                    _ => sum.win_perm = str_perm,
                }
                match sk::sk_build_sum(&sum, size) {
                    Some(o) => (0, o),
                    None => (-1, Vec::new()),
                }
            }
            SQLITE_DONE => (0, Vec::new()),
            _ => {
                self.merror(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                (-1, Vec::new())
            }
        }
    }

    /// `wdb_syscheck_save`
    pub fn syscheck_save(&self, wdb: &mut Wdb, ftype: i32, checksum: &[u8], file: &[u8]) -> i32 {
        let mut sum = Sum::default();
        // sk_decode_extradata cuts the checksum at '!'
        let (head, _) = sk::sk_decode_extradata(&mut sum, checksum);
        if sk::sk_decode_sum(&mut sum, &head, None) < 0 {
            self.mdebug1(&msg!("Checksum: ", head));
            return -1;
        }
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't begin transaction"));
            return -1;
        }
        match self.fim_find_entry(wdb, file) {
            -1 => {
                self.mdebug1(&msg!("DB(", wdb.id, ") Can't find file by name"));
                -1
            }
            0 => {
                if self.fim_insert_entry(wdb, file, ftype, &sum) < 0 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Can't insert file entry"));
                    return -1;
                }
                0
            }
            _ => {
                if self.fim_update_entry(wdb, file, &sum) < 1 {
                    self.mdebug1(&msg!("DB(", wdb.id, ") Can't update file entry"));
                    return -1;
                }
                0
            }
        }
    }

    /// `wdb_syscheck_save2`
    pub fn syscheck_save2(&self, wdb: &mut Wdb, payload: &[u8]) -> i32 {
        let Some(data) = siem_cjson::parse(cstr(payload)) else {
            self.mdebug1(&msg!("DB(", wdb.id, "): cannot parse FIM payload: '", cstr(payload), "'"));
            return -1;
        };
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't begin transaction."));
            return -1;
        }
        if self.fim_insert_entry2(wdb, &data) == -1 {
            self.mdebug1(&msg!("DB(", wdb.id, ") Can't insert file entry."));
            return -1;
        }
        0
    }

    /// `wdb_fim_find_entry`: 1 found, 0 not, -1 error.
    pub fn fim_find_entry(&self, wdb: &mut Wdb, path: &[u8]) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_FIM_FIND_ENTRY) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement"));
            return -1;
        }
        let st = wdb.st(WDB_STMT_FIM_FIND_ENTRY);
        st.bind_text(1, Some(path));
        match self.step(&st) {
            SQLITE_ROW => 1,
            SQLITE_DONE => 0,
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                -1
            }
        }
    }

    /// `wdb_fim_insert_entry`
    pub fn fim_insert_entry(&self, wdb: &mut Wdb, file: &[u8], ftype: i32, sum: &Sum) -> i32 {
        let s_ftype: &[u8] = match ftype {
            WDB_FILE_TYPE_FILE => b"file",
            WDB_FILE_TYPE_REGISTRY => b"registry_key",
            _ => {
                self.merror(&msg!("DB(", wdb.id, ") Invalid file type '", ftype, "'"));
                return -1;
            }
        };
        if self.stmt_cache(wdb, WDB_STMT_FIM_INSERT_ENTRY) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement"));
            return -1;
        }
        let s_perm = format!("{:06o}", sum.perm as u32).into_bytes();
        let st = wdb.st(WDB_STMT_FIM_INSERT_ENTRY);
        let unescaped = sum.win_perm.as_ref().map(|w| sk::replace(w, b"\\:", b":"));
        st.bind_text(1, Some(file));
        st.bind_text(2, Some(s_ftype));
        st.bind_text(3, sum.size.as_deref());
        st.bind_text(4, Some(unescaped.as_deref().unwrap_or(&s_perm)));
        st.bind_text(5, sum.uid.as_deref());
        st.bind_text(6, sum.gid.as_deref());
        st.bind_text(7, sum.md5.as_deref());
        st.bind_text(8, sum.sha1.as_deref());
        st.bind_text(9, sum.uname.as_deref());
        st.bind_text(10, sum.gname.as_deref());
        st.bind_int64(11, sum.mtime);
        st.bind_int64(12, sum.inode);
        st.bind_text(13, sum.sha256.as_deref());
        st.bind_text(14, sum.attributes.as_deref());
        st.bind_text(15, sum.symbolic_path.as_deref());
        st.bind_text(16, Some(file));
        if self.step(&st) == SQLITE_DONE {
            0
        } else {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
            -1
        }
    }

    /// `wdb_fim_insert_entry2`
    pub fn fim_insert_entry2(&self, wdb: &mut Wdb, data: &Json) -> i32 {
        let json_path = data.get("path").or_else(|| data.get("index"));
        let Some(json_path) = json_path else {
            self.merror(&msg!("DB(", wdb.id, ") fim/save request with no file path argument."));
            return -1;
        };
        let path: Option<B> = json_path.as_bytes().map(|p| cstr(p).to_vec());
        let timestamp = match data.get("timestamp") {
            Some(Json::Number { double, .. }) => *double,
            _ => {
                self.merror(&msg!("DB(", wdb.id, ") fim/save request with no timestamp path argument."));
                return -1;
            }
        };
        let version = data.get("version");
        let attributes = match data.get("attributes") {
            Some(a @ Json::Object(_)) => a,
            _ => {
                self.merror(&msg!("DB(", wdb.id, ") fim/save request with no valid attributes."));
                return -1;
            }
        };
        let Some(item_type0) = attributes.get("type").and_then(|t| t.as_bytes()).map(|t| cstr(t).to_vec()) else {
            self.merror(&msg!("DB(", wdb.id, ") fim/save request with no type attribute."));
            return -1;
        };
        let mut item_type = item_type0.clone();
        let mut arch: Option<B> = None;
        let mut value_name: Option<B> = None;
        let full_path: Option<B>;
        if item_type == b"file" {
            full_path = path.clone();
        } else if item_type == b"registry" {
            full_path = path.clone();
            item_type = b"registry_key".to_vec();
        } else if item_type.starts_with(b"registry_") {
            let Some(Json::Number { double: ver, .. }) = version else {
                // Synchronization messages without the "version" attribute are ignored
                return 0;
            };
            arch = data.get("arch").and_then(|a| a.as_bytes()).map(|a| cstr(a).to_vec());
            value_name = data.get("value_name").and_then(|a| a.as_bytes()).map(|a| cstr(a).to_vec());
            if *ver == 2.0 {
                // wstr_replace(NULL) is NULL, printed as "(null)"
                let path_escaped = match &path {
                    Some(p) => sk::replace(&sk::replace(p, b"\\", b"\\\\"), b":", b"\\:"),
                    None => b"(null)".to_vec(),
                };
                let Some(a) = &arch else {
                    self.merror(&msg!("DB(", wdb.id, ") fim/save registry request with no arch argument."));
                    return -1;
                };
                if &item_type[9..] == b"key" {
                    value_name = None;
                    full_path = Some(msg!(a, " ", path_escaped));
                } else if &item_type[9..] == b"value" {
                    let Some(vn) = &value_name else {
                        self.merror(&msg!("DB(", wdb.id, ") fim/save registry value request with no value name argument."));
                        return -1;
                    };
                    let vne = sk::replace(&sk::replace(vn, b"\\", b"\\\\"), b":", b"\\:");
                    full_path = Some(msg!(a, " ", path_escaped, ":", vne));
                } else {
                    self.merror(&msg!("DB(", wdb.id, ") fim/save request with invalid '", item_type, "' type argument."));
                    return -1;
                }
            } else if *ver == 3.0 {
                let Some(json_index) = data.get("index") else {
                    self.merror(&msg!("DB(", wdb.id, ") version 3.0 fim/save request with no index argument."));
                    return -1;
                };
                full_path = json_index.as_bytes().map(|i| cstr(i).to_vec());
            } else {
                full_path = None;
            }
        } else {
            self.merror(&msg!("DB(", wdb.id, ") fim/save request with invalid '", item_type, "' type argument."));
            return -1;
        }
        if self.stmt_cache(wdb, WDB_STMT_FIM_INSERT_ENTRY2) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement"));
            return -1;
        }
        let st = wdb.st(WDB_STMT_FIM_INSERT_ENTRY2);
        st.bind_text(1, path.as_deref());
        st.bind_text(2, Some(&item_type));
        st.bind_int64(3, super::integrity::d2long(timestamp));
        st.bind_text(18, arch.as_deref());
        st.bind_text(19, value_name.as_deref());
        st.bind_text(21, full_path.as_deref());
        if let Json::Object(members) = attributes {
            for (key, element) in members {
                let key = cstr(key);
                let invalid = |s: &Self| {
                    s.merror(&msg!("DB(", wdb.id, ") Invalid attribute name: ", key));
                    -1
                };
                match element {
                    Json::Number { double, int } => match key {
                        b"size" => {
                            st.bind_int64(4, super::integrity::d2long(*double));
                        }
                        b"mtime" => {
                            st.bind_int(12, *int);
                        }
                        b"inode" => {
                            st.bind_int64(13, super::integrity::d2long(*double));
                        }
                        _ => return invalid(self),
                    },
                    Json::String(v) => match key {
                        b"type" => {}
                        b"perm" => {
                            st.bind_text(5, Some(v));
                        }
                        b"uid" => {
                            st.bind_text(6, Some(v));
                        }
                        b"gid" => {
                            st.bind_text(7, Some(v));
                        }
                        b"hash_md5" => {
                            st.bind_text(8, Some(v));
                        }
                        b"hash_sha1" => {
                            st.bind_text(9, Some(v));
                        }
                        b"user_name" => {
                            st.bind_text(10, Some(v));
                        }
                        b"group_name" => {
                            st.bind_text(11, Some(v));
                        }
                        b"hash_sha256" => {
                            st.bind_text(14, Some(v));
                        }
                        b"symbolic_path" => {
                            st.bind_text(16, Some(v));
                        }
                        b"checksum" => {
                            st.bind_text(17, Some(v));
                        }
                        b"attributes" => {
                            st.bind_text(15, Some(v));
                        }
                        b"value_type" => {
                            st.bind_text(20, Some(v));
                        }
                        b"inode" => {
                            let v = cstr(v);
                            match strtoll_strict(v) {
                                Some(n) => {
                                    st.bind_int64(13, n);
                                }
                                None => {
                                    self.merror(&msg!("DB(", wdb.id, ") Invalid inode value: ", v));
                                    st.bind_int64(13, 0);
                                }
                            }
                        }
                        _ => return invalid(self),
                    },
                    Json::Object(_) => {
                        if key == b"perm" {
                            let perm = element.print_unformatted();
                            st.bind_text(5, Some(&perm));
                        } else {
                            return invalid(self);
                        }
                    }
                    _ => {}
                }
            }
        }
        if self.step(&st) != SQLITE_DONE {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
            return -1;
        }
        0
    }

    /// `wdb_fim_update_entry`: the changed rows or -1.
    pub fn fim_update_entry(&self, wdb: &mut Wdb, file: &[u8], sum: &Sum) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_FIM_UPDATE_ENTRY) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement"));
            return -1;
        }
        let s_perm = format!("{:06o}", sum.perm as u32).into_bytes();
        let st = wdb.st(WDB_STMT_FIM_UPDATE_ENTRY);
        let unescaped = sum.win_perm.as_ref().map(|w| sk::replace(w, b"\\:", b":"));
        st.bind_int64(1, sum.changes as i64);
        st.bind_text(2, sum.size.as_deref());
        st.bind_text(3, Some(unescaped.as_deref().unwrap_or(&s_perm)));
        st.bind_text(4, sum.uid.as_deref());
        st.bind_text(5, sum.gid.as_deref());
        st.bind_text(6, sum.md5.as_deref());
        st.bind_text(7, sum.sha1.as_deref());
        st.bind_text(8, sum.uname.as_deref());
        st.bind_text(9, sum.gname.as_deref());
        st.bind_int64(10, sum.mtime);
        st.bind_int64(11, sum.inode);
        st.bind_text(12, sum.sha256.as_deref());
        st.bind_text(13, sum.attributes.as_deref());
        st.bind_text(14, sum.symbolic_path.as_deref());
        st.bind_text(15, Some(file));
        if self.step(&st) == SQLITE_DONE {
            wdb.db().changes()
        } else {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
            -1
        }
    }

    /// `wdb_fim_delete`
    pub fn fim_delete(&self, wdb: &mut Wdb, path: &[u8]) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_FIM_DELETE) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement"));
            return -1;
        }
        let st = wdb.st(WDB_STMT_FIM_DELETE);
        st.bind_text(1, Some(path));
        match self.step(&st) {
            SQLITE_ROW | SQLITE_DONE => 0,
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                -1
            }
        }
    }

    /// `wdb_fim_update_date_entry`
    pub fn fim_update_date_entry(&self, wdb: &mut Wdb, path: &[u8]) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_FIM_UPDATE_DATE) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement"));
            return -1;
        }
        let st = wdb.st(WDB_STMT_FIM_UPDATE_DATE);
        st.bind_text(1, Some(path));
        match self.step(&st) {
            SQLITE_DONE => {
                self.mdebug2(&msg!("DB(", wdb.id, ") Updated date field for file '", cstr(path), "' to '", self.time(), "'"));
                0
            }
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                -1
            }
        }
    }

    /// `wdb_fim_clean_old_entries`
    pub fn fim_clean_old_entries(&self, wdb: &mut Wdb) -> i32 {
        let (r, tscheck3) = self.scan_info_get(wdb, b"fim", b"fim_third_check");
        if r < 0 {
            self.mdebug1(&msg!("DB(", wdb.id, ") Can't get scan_info entry"));
        }
        if self.stmt_cache(wdb, WDB_STMT_FIM_FIND_DATE_ENTRIES) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement"));
            return -1;
        }
        let st = wdb.st(WDB_STMT_FIM_FIND_DATE_ENTRIES);
        st.bind_int64(1, tscheck3);
        loop {
            let r = self.step(&st);
            if r == SQLITE_DONE {
                break;
            }
            if r != SQLITE_ROW {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                return -1;
            }
            let file = st.column_text(0).unwrap_or_default();
            let date = st.column_int64(13);
            self.mdebug2(&msg!(
                "DB(",
                wdb.id,
                ") Cleaning FIM DDBB. Deleting entry '",
                file,
                "' date<tscheck3 '",
                date,
                "'<'",
                tscheck3,
                "'."
            ));
            if file != b"internal_options.conf" && file != b"ossec.conf" && self.fim_delete(wdb, &file) < 0 {
                self.mdebug1(&msg!("DB(", wdb.id, ") Can't delete FIM entry '", file, "'."));
            }
        }
        0
    }
}

/// `strtol(s, NULL, 8)` (saturating).
pub fn strtol_base8(s: &[u8]) -> i64 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: i128 = 0;
    while i < s.len() && (b'0'..=b'7').contains(&s[i]) {
        v = (v * 8 + (s[i] - b'0') as i128).min(i64::MAX as i128 + 1);
        i += 1;
    }
    let v = if neg { -v } else { v };
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// `strtoll(s, &end, 10)` requiring the whole string and no ERANGE.
fn strtoll_strict(s: &[u8]) -> Option<i64> {
    let (v, end) = strtol_end(s);
    if end == 0 || end != s.len() || strtol_overflows(s) {
        None
    } else {
        Some(v)
    }
}
