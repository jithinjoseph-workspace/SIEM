//! Wazuh Shared Foundation Library (src/shared)
//!
//! Provides the core SIEM runtime primitives ported directly from Wazuh's C code:
//! - `validate`: Input and path validation (`validate_op.c`).
//! - `keys`: Agent fleet registry and `client.keys` manager (`agent_op.c`, `read-agents.c`).
//! - `version`: Wazuh version comparing and SemVer engine (`version_op.c`).
//! - `schedule`: Recurring scan scheduling with intervals and jitter (`schedule_scan.c`).
//! - `expression`: Condition matching for rules and decoders (`expression.c`, `rules_op.c`).
//! - `formatter`: Custom alert template variable replacement (`custom_output_search_replace.c`).
//! - `labels`: Agent custom labels parser and JSON injector (`labels_op.c`).
//! - `queue`: Disk-backed rotating queues and memory IPC queues (`file-queue.c`, `mq_op.c`).
//! - `audit`: Linux auditd netlink record decoder (`audit_op.c`).

pub mod audit;
pub mod expression;
pub mod formatter;
pub mod keys;
pub mod labels;
pub mod net;
pub mod queue;
pub mod regex;
pub mod schedule;
pub mod validate;
pub mod version;
pub mod xml;
pub mod zlib;

pub use net::{
    bind_port_tcp, bind_port_udp, connect_tcp, connect_udp, decode_cluster_message,
    encode_cluster_message, encode_secure_tcp, get_ip_from_resolved_hostname, is_valid_ip,
    os_get_host, recv_secure_tcp, resolve_hostname, send_secure_tcp, wnet_order, wnet_order_big,
    ClusterFrame, IpcListener, IpcSocket, IpcStream, NetError, CLUSTER_COMMAND_SIZE,
    MAX_CLUSTER_PAYLOAD_SIZE, WAZUH_IPC_TIMEOUT,
};
pub use regex::{
    is_valid_hostname_char, os_match, os_match2, os_regex, os_str_break,
    os_str_how_closed_match, os_str_is_num, os_str_starts_with, os_word_match, OSMatch, OSRegex,
    RegexError, OS_CASE_SENSITIVE, OS_RETURN_SUBSTRING,
};
pub use xml::{w_get_attr_val_by_name, OsXml, XmlNode};
pub use zlib::{os_zlib_compress, os_zlib_compress_into, os_zlib_uncompress, os_zlib_uncompress_into, ZlibError};
pub use os_zlib_compress as compress;
pub use os_zlib_uncompress as uncompress;

#[cfg(test)]
mod tests {
    use super::*;
    use audit::AuditRecord;
    use expression::{NumericOp, RuleExpression};
    use formatter::format_custom_output;
    use keys::{AgentStatus, ClientKeys};
    use labels::LabelSet;
    use queue::DiskQueue;
    use schedule::ScanSchedule;
    use serde_json::json;
    use validate::*;
    use version::WazuhVersion;

    #[test]
    fn test_validation() {
        assert!(is_valid_agent_id("001"));
        assert!(is_valid_agent_id("12345678"));
        assert!(!is_valid_agent_id("agent001"));

        assert!(is_valid_agent_name("ubuntu-agent-01"));
        assert!(!is_valid_agent_name("invalid name with spaces"));

        assert!(is_valid_agent_ip("192.168.1.50"));
        assert!(is_valid_agent_ip("10.0.0.0/24"));
        assert!(is_valid_agent_ip("any"));
        assert!(!is_valid_agent_ip("999.999.999.999"));

        assert!(is_safe_path("var/ossec/etc/ossec.conf"));
        assert!(!is_safe_path("../../../etc/shadow"));
    }

    #[test]
    fn test_client_keys_and_status() {
        let keys_text = "001 agent-one 192.168.1.100 key1234567890abcdef\n002 agent-two any keyabcdef1234567890\n";
        let keys = ClientKeys::parse_str(keys_text).unwrap();
        assert_eq!(keys.count(), 2);

        let agent1 = keys.get_by_id("001").unwrap();
        assert_eq!(agent1.name, "agent-one");
        assert_eq!(agent1.ip, "192.168.1.100");

        let agent2 = keys.get_by_name("agent-two").unwrap();
        assert_eq!(agent2.id, "002");

        // Status calculation
        let now = 1700000000;
        let active_status = ClientKeys::resolve_agent_status(Some(now - 30), now, 120);
        assert_eq!(active_status, AgentStatus::Active);

        let disconnected_status = ClientKeys::resolve_agent_status(Some(now - 600), now, 120);
        assert_eq!(disconnected_status, AgentStatus::Disconnected);

        let never_status = ClientKeys::resolve_agent_status(None, now, 120);
        assert_eq!(never_status, AgentStatus::NeverConnected);
    }

    #[test]
    fn test_wazuh_version_comparison() {
        let v_mgr = WazuhVersion::parse("Wazuh v4.14.7").unwrap();
        let v_agt = WazuhVersion::parse("v4.9.0").unwrap();
        let v_future = WazuhVersion::parse("v5.0.0").unwrap();

        assert_eq!(v_mgr.major, 4);
        assert_eq!(v_mgr.minor, 14);
        assert_eq!(v_mgr.patch, 7);

        assert!(v_agt < v_mgr);
        assert!(v_agt.is_compatible_with_manager(&v_mgr));
        assert!(!v_future.is_compatible_with_manager(&v_mgr));
    }

    #[test]
    fn test_scan_schedule() {
        let sched = ScanSchedule {
            interval_secs: 3600,
            max_jitter_secs: 0,
            ..Default::default()
        };

        let now = 10000;
        assert!(sched.is_due(None, now));
        assert!(!sched.is_due(Some(now - 1000), now));
        assert!(sched.is_due(Some(now - 3601), now));
    }

    #[test]
    fn test_expression_engine() {
        let exp_exact = RuleExpression::exact("apache2", false);
        assert!(exp_exact.matches("apache2"));
        assert!(!exp_exact.matches("nginx"));

        let exp_cidr = RuleExpression::cidr("10.0.0.0/8", false);
        assert!(exp_cidr.matches("10.1.2.3"));
        assert!(!exp_cidr.matches("192.168.1.1"));

        let exp_num = RuleExpression::numeric(NumericOp::GreaterOrEqual, 10.0, false);
        assert!(exp_num.matches("12"));
        assert!(exp_num.matches("10.0"));
        assert!(!exp_num.matches("5.5"));
    }

    #[test]
    fn test_formatter_custom_output() {
        let event = json!({
            "rule": { "id": "5710", "level": 10 },
            "agent": { "id": "001", "name": "web-server" },
            "srcip": "192.168.1.10"
        });

        let template = "Alert [$(rule.id)] on Agent $(agent.name) from $(srcip)";
        let formatted = format_custom_output(template, &event);
        assert_eq!(formatted, "Alert [5710] on Agent web-server from 192.168.1.10");
    }

    #[test]
    fn test_labels_manager() {
        let mut labels = LabelSet::new();
        labels.add("environment", "production", false);
        labels.add("secret_tag", "internal_only", true);

        let mut event = json!({
            "rule": { "id": "1001" },
            "agent": { "id": "001" }
        });

        labels.merge_into_json(&mut event, false); // don't include hidden
        assert_eq!(event["agent"]["labels"]["environment"], "production");
        assert!(event["agent"]["labels"].get("secret_tag").is_none());
    }

    #[test]
    fn test_disk_queue() {
        let temp_dir = tempfile::tempdir().unwrap();
        let queue = DiskQueue::open(temp_dir.path(), "test_events", 1024 * 1024).unwrap();

        queue.push_line("event 1: agent connected").unwrap();
        queue.push_line("event 2: rule fired").unwrap();

        let lines = queue.read_index_lines(0).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "event 1: agent connected");
        assert_eq!(lines[1], "event 2: rule fired");
    }

    #[test]
    fn test_audit_log_parsing() {
        let line = r#"type=SYSCALL msg=audit(1633072800.123:456): arch=c000003e syscall=59 success=yes exe="/bin/bash" a0="62617368""#;
        let record = AuditRecord::parse_line(line).unwrap();

        assert_eq!(record.record_type, "SYSCALL");
        assert_eq!(record.event_id, 456);
        assert_eq!(record.fields.get("syscall").unwrap(), "59");
        assert_eq!(record.fields.get("exe").unwrap(), "/bin/bash");
        assert_eq!(record.fields.get("a0").unwrap(), "bash"); // hex-decoded "62617368"
    }
}
