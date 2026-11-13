//! `wazuh_modules/wm_task_general.c` and the small C helpers the task and
//! upgrade modules share.

use siem_cjson::Json;

/// `task_manager_commands_list`
pub const UPGRADE: &str = "upgrade";
pub const UPGRADE_CUSTOM: &str = "upgrade_custom";
pub const UPGRADE_GET_STATUS: &str = "upgrade_get_status";
pub const UPGRADE_UPDATE_STATUS: &str = "upgrade_update_status";
pub const UPGRADE_RESULT: &str = "upgrade_result";
pub const UPGRADE_CANCEL_TASKS: &str = "upgrade_cancel_tasks";
pub const SET_TIMEOUT: &str = "set_timeout";
pub const DELETE_OLD: &str = "delete_old";

/// `task_manager_modules_list[WM_TASK_UPGRADE_MODULE]`
pub const UPGRADE_MODULE: &str = "upgrade_module";

/// `task_statuses`
pub const STATUS_PENDING: &str = "Pending";
pub const STATUS_IN_PROGRESS: &str = "In progress";
pub const STATUS_DONE: &str = "Done";
pub const STATUS_FAILED: &str = "Failed";
pub const STATUS_CANCELLED: &str = "Cancelled";
pub const STATUS_TIMEOUT: &str = "Timeout";
pub const STATUS_LEGACY: &str = "Legacy";

/// `OS_MAXSTR`
pub const OS_MAXSTR: usize = 65536;
pub const OS_INVALID: i32 = -1;

/// The C string view of a buffer (up to its first NUL).
pub fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// Concatenation of byte pieces (C `%s` formatting keeps bytes as they are).
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `cJSON_Parse` of a C string.
pub fn parse(b: &[u8]) -> Option<Json> {
    siem_cjson::parse(cstr(b))
}

/// `strtol(s, &end, 0)` with a 64-bit `long`: (value, the byte at `end`).
pub fn strtol0(s: &str) -> (i64, u8) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let neg = b.get(i) == Some(&b'-');
    if matches!(b.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let mut base = 10;
    if b.get(i) == Some(&b'0') {
        if matches!(b.get(i + 1), Some(b'x' | b'X')) && b.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit()) {
            base = 16;
            i += 2;
        } else {
            base = 8;
        }
    }
    let start = i;
    let mut v: i128 = 0;
    while let Some(d) = b.get(i).and_then(|&c| (c as char).to_digit(base)) {
        v = (v * base as i128 + d as i128).min(i64::MAX as i128 + 1);
        i += 1;
    }
    if i == start {
        return (0, b.first().copied().unwrap_or(0));
    }
    let v = if neg { (-v).max(i64::MIN as i128) } else { v.min(i64::MAX as i128) };
    (v as i64, b.get(i).copied().unwrap_or(0))
}

/// `w_get_timestamp`: local time as "YYYY/MM/DD hh:mm:ss".
pub fn timestamp(t: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(t, 0).single() {
        Some(d) => d.format("%Y/%m/%d %H:%M:%S").to_string(),
        None => String::new(),
    }
}

/// `w_is_worker() != 0`: an unreadable `ossec.conf` counts as a worker, as in C.
pub fn is_worker() -> bool {
    !matches!(siem_config::cluster::is_worker(std::path::Path::new("etc/ossec.conf")), Some(false))
}

/// `OS_ReadXML(OSSECCONF)` + `OS_GetOneContentforElement(ossec_config/cluster/node_name)`
pub fn node_name() -> Option<String> {
    let mut x = siem_xml::OsXml::read_file("etc/ossec.conf", false).ok()?;
    x.get_one_content_for_element(&["ossec_config", "cluster", "node_name"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtol_base0() {
        assert_eq!(strtol0("10d"), (10, b'd'));
        assert_eq!(strtol0("0x10"), (16, 0));
        assert_eq!(strtol0("010m"), (8, b'm'));
        assert_eq!(strtol0("x"), (0, b'x'));
        assert_eq!(strtol0("99999999999"), (99999999999, 0));
    }
}

/// A logger with its own manager home (WLog needs an `ossec.conf`).
#[cfg(test)]
pub fn test_log() -> std::sync::Arc<siem_log::WLog> {
    let home = tempfile::tempdir().unwrap().keep();
    std::fs::create_dir_all(home.join("etc")).unwrap();
    std::fs::create_dir_all(home.join("logs")).unwrap();
    std::fs::write(home.join("etc/ossec.conf"), "<ossec_config></ossec_config>\n").unwrap();
    let l = siem_log::WLog::new_server("test", &home);
    let _ = l.init();
    std::sync::Arc::new(l)
}
