//! Wazuh Syslog IPC Control Interface (`src/os_csyslogd/csyscom.c`)
//!
//! Provides the IPC control dispatcher for wazuh-csyslogd:
//! - Command: `getconfig csyslog`
//! - Dispatches responses formatted as `ok <json_data>` or `err <msg>`

use crate::config::SyslogConfigHolder;

/// Port of `csyscom.c: csyscom_dispatch`:
/// Handles incoming management command string and produces response.
pub fn csyscom_dispatch(command: &str, holder: &SyslogConfigHolder) -> String {
    let trimmed = command.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let rcv_comm = parts.next().unwrap_or("");
    let rcv_args = parts.next();

    if rcv_comm.is_empty() {
        return "err Unrecognized command".to_string();
    }

    if rcv_comm == "getconfig" {
        match rcv_args {
            Some(section) => csyscom_getconfig(section.trim(), holder),
            None => "err CSYSCOM getconfig needs arguments".to_string(),
        }
    } else {
        "err Unrecognized command".to_string()
    }
}

/// Port of `csyscom.c: csyscom_getconfig`:
/// Returns JSON configuration for the requested section.
pub fn csyscom_getconfig(section: &str, holder: &SyslogConfigHolder) -> String {
    if section == "csyslog" {
        let json_val = holder.to_json_config();
        format!("ok {}", json_val)
    } else {
        "err Could not get requested section".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SyslogConfig, SyslogFormat};

    #[test]
    fn test_csyscom_dispatch() {
        let mut holder = SyslogConfigHolder::default();
        holder.configs.push(SyslogConfig {
            server: "10.0.0.5".to_string(),
            port: 514,
            level: 5,
            format: SyslogFormat::Default,
            ..Default::default()
        });

        // 1. Valid getconfig csyslog
        let resp = csyscom_dispatch("getconfig csyslog", &holder);
        assert!(resp.starts_with("ok "));
        assert!(resp.contains("\"server\":\"10.0.0.5\""));
        assert!(resp.contains("\"port\":514"));

        // 2. getconfig missing args
        let resp_no_arg = csyscom_dispatch("getconfig", &holder);
        assert_eq!(resp_no_arg, "err CSYSCOM getconfig needs arguments");

        // 3. getconfig invalid section
        let resp_inv_sec = csyscom_dispatch("getconfig non_existent", &holder);
        assert_eq!(resp_inv_sec, "err Could not get requested section");

        // 4. unrecognized command
        let resp_unrec = csyscom_dispatch("unknown_cmd", &holder);
        assert_eq!(resp_unrec, "err Unrecognized command");
    }
}
