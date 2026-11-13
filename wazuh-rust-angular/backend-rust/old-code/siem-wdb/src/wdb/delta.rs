//! Syscollector dbsync deltas (wazuh_db/wdb_delta_event.c): generic upsert
//! and delete statements built from the column tables.

use siem_cjson::Json;
use siem_sqlite::Stmt;

use super::tables::{Default, Field, FieldType, Kv};
use super::*;

/// `QUERY_MAX_SIZE`
const QUERY_MAX_SIZE: usize = OS_SIZE_2048;

/// `IS_VALID_VALUE(table, field, value)`
fn is_valid_value(table: &str, field: &[u8], v: f64) -> bool {
    match table {
        "sys_hwinfo" => match field {
            b"cpu_cores" | b"cpu_mhz" | b"ram_total" | b"ram_free" => v > 0.0,
            b"ram_usage" => v > 0.0 && v <= 100.0,
            _ => true,
        },
        "sys_users" => match field {
            b"user_id" | b"user_group_id" | b"user_auth_failed_count" | b"user_password_inactive_days"
            | b"user_password_max_days_between_changes" | b"user_password_min_days_between_changes"
            | b"user_password_warning_days_before_expiration" | b"process_pid" => v >= 0.0,
            b"user_created" | b"user_last_login" | b"user_auth_failed_timestamp" | b"user_password_last_change"
            | b"user_password_expiration_date" => v > 0.0,
            _ => true,
        },
        "sys_groups" => match field {
            b"group_id" => v >= 0.0,
            _ => true,
        },
        "sys_services" => match field {
            b"service_frequency" | b"service_process_pid" | b"service_target_ephemeral_id" | b"service_exit_code"
            | b"service_win32_exit_code" => v >= 0.0,
            _ => true,
        },
        _ => true,
    }
}

/// `wdb_dbsync_translate_field`
fn translate(f: &Field) -> &'static str {
    f.source_name.unwrap_or(f.target_name)
}

/// `wdb_dbsync_get_field_default`
fn field_default(f: &Field) -> Json {
    match f.default_value {
        Default::Int(i) => Json::number(i as f64),
        Default::Long(l) => Json::number(l as f64),
        Default::Real(r) => Json::number(r),
        Default::Text(t) => Json::string(t),
    }
}

/// `wdb_dbsync_stmt_bind_from_json`
fn bind_from_json(st: &Stmt, index: i32, type_: FieldType, value: &Json, field_name: &str, table: &str, convert_empty: bool) -> bool {
    let fname = field_name.as_bytes();
    if let Json::Null = value {
        return st.bind_null(index) == SQLITE_OK;
    }
    match type_ {
        FieldType::Text => match value {
            Json::String(s) => {
                let s = cstr(s);
                if s.is_empty() && convert_empty {
                    st.bind_null(index) == SQLITE_OK
                } else {
                    st.bind_text(index, Some(s)) == SQLITE_OK
                }
            }
            Json::Number { double, int } => {
                let text = if *int as f64 == *double { int.to_string().into_bytes() } else { siem_cjson::fmt_f6(*double).into_bytes() };
                st.bind_text(index, Some(&trunc(text, OS_SIZE_1024))) == SQLITE_OK
            }
            _ => false,
        },
        FieldType::Integer => match value {
            Json::String(s) => {
                let s = cstr(s);
                let (v, end) = strtol_end(s);
                // an empty string or one with only a sign/spaces leaves endptr
                // at the start: the whole string must be consumed
                let consumed = if end == 0 { s.is_empty() } else { end == s.len() };
                if !consumed {
                    return false;
                }
                let n = v as i32;
                if is_valid_value(table, fname, n as f64) {
                    st.bind_int(index, n) == SQLITE_OK
                } else {
                    st.bind_null(index) == SQLITE_OK
                }
            }
            Json::Number { int, .. } => {
                if is_valid_value(table, fname, *int as f64) {
                    st.bind_int(index, *int) == SQLITE_OK
                } else {
                    st.bind_null(index) == SQLITE_OK
                }
            }
            _ => false,
        },
        FieldType::Real => match value {
            Json::String(s) => {
                let s = cstr(s);
                let (v, end) = c_strtod(s);
                let consumed = if end == 0 { s.is_empty() } else { end == s.len() };
                if !consumed {
                    return false;
                }
                if is_valid_value(table, fname, v) {
                    st.bind_double(index, v) == SQLITE_OK
                } else {
                    st.bind_null(index) == SQLITE_OK
                }
            }
            Json::Number { double, .. } => {
                if is_valid_value(table, fname, *double) {
                    st.bind_double(index, *double) == SQLITE_OK
                } else {
                    st.bind_null(index) == SQLITE_OK
                }
            }
            _ => false,
        },
        FieldType::IntegerLong => match value {
            Json::String(s) => {
                let s = cstr(s);
                let (v, end) = strtol_end(s);
                let consumed = if end == 0 { s.is_empty() } else { end == s.len() };
                if !consumed {
                    return false;
                }
                if is_valid_value(table, fname, v as f64) {
                    st.bind_int64(index, v) == SQLITE_OK
                } else {
                    st.bind_null(index) == SQLITE_OK
                }
            }
            Json::Number { double, .. } => {
                if is_valid_value(table, fname, *double) {
                    st.bind_int64(index, super::integrity::d2long(*double)) == SQLITE_OK
                } else {
                    st.bind_null(index) == SQLITE_OK
                }
            }
            _ => false,
        },
    }
}

impl Wdbd {
    /// `wdb_upsert_dbsync`
    pub fn upsert_dbsync(&self, wdb: &mut Wdb, kv: &Kv, data: &Json) -> bool {
        let mut query = format!("INSERT INTO {} VALUES( ", kv.value);
        let cols = kv.column_list;
        for (i, _) in cols.iter().enumerate() {
            if 3 + query.len() > QUERY_MAX_SIZE {
                self.merror(&msg!("Exceeding maximum query size of ", QUERY_MAX_SIZE, " bytes adding values placeholders."));
                return false;
            }
            query.push('?');
            if i + 1 < cols.len() {
                query.push(',');
            }
        }
        if 29 + query.len() > QUERY_MAX_SIZE {
            self.merror(&msg!("Exceeding maximum query size of ", QUERY_MAX_SIZE, " bytes adding conflict clause."));
            return false;
        }
        query.push_str(") ON CONFLICT DO UPDATE SET ");
        let mut first = true;
        for c in cols {
            if !c.is_aux_field && !c.is_pk {
                if first {
                    if c.target_name.len() + query.len() + 3 > QUERY_MAX_SIZE {
                        self.merror(&msg!("Exceeding maximum query size of ", QUERY_MAX_SIZE, " bytes adding first field."));
                        return false;
                    }
                    query.push_str(&format!("{}=?", c.target_name));
                    first = false;
                } else {
                    if c.target_name.len() + query.len() + 4 > QUERY_MAX_SIZE {
                        self.merror(&msg!("Exceeding maximum query size of ", QUERY_MAX_SIZE, " bytes adding subsequent fields."));
                        return false;
                    }
                    query.push_str(&format!(",{}=?", c.target_name));
                }
            }
        }
        let Some(st) = self.get_cache_stmt(wdb, query.as_bytes()) else {
            self.merror(b"(5214): Null statement on internal cache.");
            return false;
        };
        let mut has_error = false;
        let mut index = 1;
        for c in cols {
            if has_error {
                break;
            }
            let field_name = translate(c);
            let field_value = if c.is_aux_field {
                field_default(c)
            } else {
                match data.get(field_name) {
                    None | Some(Json::Null) => field_default(c),
                    Some(v) => v.clone(),
                }
            };
            if !bind_from_json(&st, index, c.type_, &field_value, field_name, kv.value, c.convert_empty_string_as_null) {
                self.merror(&msg!("(5216): DB(", wdb.id, ") Could not bind delta field '", field_name, "' from '", kv.key, "' scan."));
                has_error = true;
            }
            index += 1;
        }
        for c in cols {
            if has_error {
                break;
            }
            if !c.is_aux_field && !c.is_pk {
                let field_name = translate(c);
                if let Some(v) = data.get(field_name) {
                    if !bind_from_json(&st, index, c.type_, v, field_name, kv.value, c.convert_empty_string_as_null) {
                        self.merror(&msg!("(5216): DB(", wdb.id, ") Could not bind delta field '", field_name, "' from '", kv.key, "' scan."));
                        has_error = true;
                    }
                }
                index += 1;
            }
        }
        !has_error && self.step(&st) == SQLITE_DONE
    }

    /// `wdb_delete_dbsync`
    pub fn delete_dbsync(&self, wdb: &mut Wdb, kv: &Kv, data: &Json) -> bool {
        let mut query = format!("DELETE FROM {} WHERE ", kv.value);
        let mut first = true;
        for c in kv.column_list {
            if c.is_pk {
                if first {
                    if c.target_name.len() + query.len() + 3 > QUERY_MAX_SIZE {
                        self.merror(&msg!("Exceeding maximum query size of ", QUERY_MAX_SIZE, " bytes adding first pk."));
                        return false;
                    }
                    query.push_str(&format!("{}=?", c.target_name));
                    first = false;
                } else {
                    if c.target_name.len() + query.len() + 8 > QUERY_MAX_SIZE {
                        self.merror(&msg!("Exceeding maximum query size of ", QUERY_MAX_SIZE, " bytes adding subsequent pks."));
                        return false;
                    }
                    query.push_str(&format!(" AND {}=?", c.target_name));
                }
            }
        }
        let Some(st) = self.get_cache_stmt(wdb, query.as_bytes()) else {
            self.merror(b"(5214): Null statement on internal cache.");
            return false;
        };
        let mut has_error = false;
        let mut index = 1;
        for c in kv.column_list {
            if has_error {
                break;
            }
            if c.is_pk {
                let field_name = translate(c);
                let field_value = match data.get(field_name) {
                    None | Some(Json::Null) => field_default(c),
                    Some(v) => v.clone(),
                };
                if !bind_from_json(&st, index, c.type_, &field_value, field_name, kv.value, c.convert_empty_string_as_null) {
                    self.merror(&msg!("(5216): DB(", wdb.id, ") Could not bind delta field '", field_name, "' from '", kv.key, "' scan."));
                    has_error = true;
                }
                index += 1;
            }
        }
        !has_error && self.step(&st) == SQLITE_DONE
    }
}

/// `strtod(s, &end)` (glibc): the value and the bytes consumed (0 when no
/// conversion was performed).
pub fn c_strtod(s: &[u8]) -> (f64, usize) {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let ws = i;
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let rest = &s[i..];
    let lower: Vec<u8> = rest.iter().take(8).map(|c| c.to_ascii_lowercase()).collect();
    let sign = |v: f64| if neg { -v } else { v };
    if lower.starts_with(b"infinity") {
        return (sign(f64::INFINITY), i + 8);
    }
    if lower.starts_with(b"inf") {
        return (sign(f64::INFINITY), i + 3);
    }
    if lower.starts_with(b"nan") {
        let mut j = i + 3;
        if j < s.len() && s[j] == b'(' {
            let mut k = j + 1;
            while k < s.len() && (s[k].is_ascii_alphanumeric() || s[k] == b'_') {
                k += 1;
            }
            if k < s.len() && s[k] == b')' {
                j = k + 1;
            }
        }
        return (sign(f64::NAN), j);
    }
    if rest.len() >= 2 && rest[0] == b'0' && (rest[1] == b'x' || rest[1] == b'X') {
        // hexadecimal floating point: 0x<hex>[.<hex>][p[+-]<dec>]
        let mut j = i + 2;
        let mut mant: f64 = 0.0;
        let mut digits = 0;
        while j < s.len() && s[j].is_ascii_hexdigit() {
            mant = mant * 16.0 + (s[j] as char).to_digit(16).unwrap_or(0) as f64;
            j += 1;
            digits += 1;
        }
        let mut scale = 0i32;
        if j < s.len() && s[j] == b'.' {
            let mut k = j + 1;
            let mut fd = 0;
            while k < s.len() && s[k].is_ascii_hexdigit() {
                mant = mant * 16.0 + (s[k] as char).to_digit(16).unwrap_or(0) as f64;
                scale -= 4;
                k += 1;
                fd += 1;
            }
            if digits + fd > 0 {
                j = k;
                digits += fd;
            }
        }
        if digits == 0 {
            // "0x" alone: the "0" is the number
            return (sign(0.0), i + 1);
        }
        if j < s.len() && (s[j] == b'p' || s[j] == b'P') {
            let (e, n) = strtol_end(&s[j + 1..]);
            let sign_or_digit = s.get(j + 1).is_some_and(|c| c.is_ascii_digit() || *c == b'+' || *c == b'-');
            if n > 0 && sign_or_digit {
                scale = scale.saturating_add(e.clamp(-100000, 100000) as i32);
                j = j + 1 + n;
            }
        }
        return (sign(mant * 2f64.powi(scale)), j);
    }
    match siem_cjson::strtod_prefix(&s[ws..]) {
        Some((v, n)) => (v, ws + n),
        None => (0.0, 0),
    }
}
