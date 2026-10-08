pub mod ar_forward;
pub mod authd;
pub mod config;
pub mod crypto;
pub mod keys;
pub mod protocol;
pub mod remcom;
pub mod server;
pub mod shared_download;
pub mod state;
pub mod syslog;

pub use ar_forward::{ActiveResponseCommand, ArForwarder, ArLocation, ArQueueMessage};
pub use authd::{AuthdConfig, AuthdError, AuthdService};
pub use config::{ConnectionType, NetProtocol, RemoteSection};
pub use crypto::{decrypt_aes256_cbc, encrypt_aes256_cbc, CryptoError};
pub use keys::{AgentKey, KeyError, KeysDatabase};
pub use protocol::{ProtocolError, RemotedMessage, WazuhSubsystem};
pub use remcom::{RemcomHandler, RemcomRequest, RemcomResponse};
pub use server::{RemotedConfig, RemotedServer, ServerError};
pub use shared_download::{SharedConfigManager, SharedFile};
pub use state::{RemotedMetricsSnapshot, RemotedState};
pub use syslog::SyslogMessage;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use siem_engine::AnalysisEngine;

    #[test]
    fn test_full_enrollment_to_message_lifecycle() {
        let keys_db = Arc::new(KeysDatabase::new());
        let engine = Arc::new(AnalysisEngine::new());
        let authd = AuthdService::new(keys_db.clone(), AuthdConfig::default());
        let remoted = RemotedServer::new(keys_db.clone(), engine, RemotedConfig::default());

        // 1. New agent arrives and enrolls via authd (Port 1515)
        let enroll_req = "OSSEC A:'db-prod-mysql'";
        let enroll_resp = authd
            .handle_enrollment_request("10.0.1.55", enroll_req)
            .expect("Enrollment must succeed");

        assert!(enroll_resp.starts_with("OSSEC K:'001 db-prod-mysql any "));
        assert_eq!(keys_db.total_agents(), 1);

        let enrolled_agent = keys_db.get_by_name("db-prod-mysql").expect("Agent must exist");
        assert_eq!(enrolled_agent.id, "001");

        // 2. Agent uses generated key to encrypt first FIM event (Port 1514)
        let fim_payload = "/etc/mysql/my.cnf modified md5=c4ca4238a0b923820dcc509a6f75849b";
        let wire = RemotedMessage::format_wire(1, 1, fim_payload);
        let ciphertext = encrypt_aes256_cbc(&enrolled_agent.key_bytes, wire.as_bytes());

        let mut packet = b"!001:".to_vec();
        packet.extend(ciphertext);

        // 3. Remoted receives, decrypts, and dispatches
        let (msg, _maybe_alert) = remoted
            .process_agent_packet("10.0.1.55", &packet)
            .expect("Packet must decrypt and parse");

        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.counter, 1);
        assert_eq!(msg.subsystem, WazuhSubsystem::Fim);
        assert_eq!(msg.payload, fim_payload);

        // 4. Replay attack verification: attacker tries to replay exact same packet
        let replay_result = remoted.process_agent_packet("10.0.1.55", &packet);
        assert!(replay_result.is_err(), "Replay of counter 1 must be blocked!");

        // 5. Subsequent valid packet with higher counter succeeds
        let wire2 = RemotedMessage::format_wire(2, 5, "#ping");
        let ciphertext2 = encrypt_aes256_cbc(&enrolled_agent.key_bytes, wire2.as_bytes());
        let mut packet2 = b"!001:".to_vec();
        packet2.extend(ciphertext2);

        let (msg2, _) = remoted
            .process_agent_packet("10.0.1.55", &packet2)
            .expect("New packet with higher counter must succeed");
        assert_eq!(msg2.counter, 2);
        assert_eq!(msg2.subsystem, WazuhSubsystem::Keepalive);
    }

    #[test]
    fn test_client_keys_export_and_import() {
        let keys_db = KeysDatabase::new();

        let (key1, key1_bytes) = KeysDatabase::generate_key();
        let (key2, key2_bytes) = KeysDatabase::generate_key();

        keys_db
            .add_agent(AgentKey {
                id: "001".to_string(),
                name: "srv1".to_string(),
                ip: "any".to_string(),
                raw_key: key1,
                key_bytes: key1_bytes,
                last_counter: 0,
            })
            .unwrap();

        keys_db
            .add_agent(AgentKey {
                id: "002".to_string(),
                name: "srv2".to_string(),
                ip: "192.168.1.20".to_string(),
                raw_key: key2,
                key_bytes: key2_bytes,
                last_counter: 0,
            })
            .unwrap();

        let exported = keys_db.export_client_keys();
        assert!(exported.contains("001 srv1 any"));
        assert!(exported.contains("002 srv2 192.168.1.20"));

        // Import into clean database
        let keys_db2 = KeysDatabase::new();
        let loaded_count = keys_db2.load_from_str(&exported);
        assert_eq!(loaded_count, 2);
        assert_eq!(keys_db2.total_agents(), 2);
        assert_eq!(keys_db2.get_by_id("001").unwrap().name, "srv1");
        assert_eq!(keys_db2.get_by_id("002").unwrap().name, "srv2");
    }

    #[test]
    fn test_ar_forward_packet_generation() {
        let forwarder = ArForwarder::new();
        let (_raw_key, key_bytes) = KeysDatabase::generate_key();

        let agent = AgentKey {
            id: "005".to_string(),
            name: "web-srv".to_string(),
            ip: "10.0.0.5".to_string(),
            raw_key: "dummy".to_string(),
            key_bytes,
            last_counter: 10,
        };

        let cmd = ActiveResponseCommand {
            message_id: 1,
            command: "firewall-drop".to_string(),
            target_ip: Some("192.168.1.200".to_string()),
            extra_args: Some("-".to_string()),
        };

        let cmd_text = format!("{} {} {}", cmd.command, cmd.target_ip.unwrap(), cmd.extra_args.unwrap());
        let packet = forwarder.build_encrypted_ar_packet(&agent, 11, &cmd_text, false);
        assert!(packet.starts_with(b"!005:"));

        // Verify decryptability
        let ciphertext = &packet[5..];
        let decrypted = decrypt_aes256_cbc(&agent.key_bytes, ciphertext).unwrap();
        let dec_str = String::from_utf8(decrypted).unwrap();
        assert!(dec_str.contains("#!-execd firewall-drop 192.168.1.200 -"));
    }

    #[test]
    fn test_shared_download_merged_mg() {
        let mut mgr = SharedConfigManager::new();
        let conf_content = b"<agent_config><syscheck><frequency>3600</frequency></syscheck></agent_config>".to_vec();

        mgr.set_group_file("default", "agent.conf", conf_content.clone());

        let bundle = mgr.generate_merged_mg("default");
        assert!(!bundle.is_empty());

        let checksum = mgr.compute_merged_checksum("default");
        assert!(!checksum.is_empty());

        // Parse back on agent side
        let parsed = SharedConfigManager::parse_merged_mg(&bundle).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "agent.conf");
        assert_eq!(parsed[0].content, conf_content);
    }

    #[test]
    fn test_remoted_state_metrics() {
        let state = RemotedState::new();
        state.inc_received(500);
        state.inc_sent();
        state.inc_dropped();
        state.inc_replay();
        state.set_active_agents(12);

        let snap = state.snapshot();
        assert_eq!(snap.total_messages_received, 1);
        assert_eq!(snap.total_bytes_received, 500);
        assert_eq!(snap.total_messages_sent, 1);
        assert_eq!(snap.dropped_messages, 1);
        assert_eq!(snap.discarded_replays, 1);
        assert_eq!(snap.active_agents, 12);
    }

    #[test]
    fn test_syslog_parsing() {
        // 1. RFC 3164 (BSD syslog)
        let bsd_raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick";
        let bsd_msg = SyslogMessage::parse(bsd_raw);
        assert_eq!(bsd_msg.priority, 34);
        assert_eq!(bsd_msg.facility, 4); // auth
        assert_eq!(bsd_msg.severity, 2); // crit
        assert_eq!(bsd_msg.hostname.as_deref(), Some("mymachine"));
        assert!(bsd_msg.message.contains("'su root' failed"));

        // 2. RFC 5424
        let rfc5424_raw = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] An application event log entry";
        let rfc5424_msg = SyslogMessage::parse(rfc5424_raw);
        assert_eq!(rfc5424_msg.priority, 165);
        assert_eq!(rfc5424_msg.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(rfc5424_msg.app_name.as_deref(), Some("evntslog"));
        assert!(rfc5424_msg.message.contains("An application event log entry"));
    }

    #[test]
    fn test_ar_queue_message_parsing() {
        let line = "(5710) [192.168.1.100] -S- 001 firewall-drop 192.168.1.100 -";
        let parsed = ArQueueMessage::parse_queue_line(line).unwrap();

        assert_eq!(parsed.rule_id, "5710");
        assert_eq!(parsed.srcip.as_deref(), Some("192.168.1.100"));
        assert_eq!(parsed.location, ArLocation::SpecificAgent);
        assert_eq!(parsed.agent_id, "001");
        assert_eq!(parsed.command, "firewall-drop 192.168.1.100 -");
    }

    #[test]
    fn test_remote_config_xml() {
        let xml = r#"
        <remote>
            <connection>syslog</connection>
            <port>514</port>
            <protocol>udp</protocol>
            <allowed-ips>192.168.1.0/24</allowed-ips>
            <queue_size>65536</queue_size>
        </remote>
        "#;

        let cfg = RemoteSection::parse_xml(xml).unwrap();
        assert_eq!(cfg.connection, ConnectionType::Syslog);
        assert_eq!(cfg.port, 514);
        assert_eq!(cfg.protocol, NetProtocol::Udp);
        assert_eq!(cfg.queue_size, 65536);
        assert_eq!(cfg.allow_ips[0], "192.168.1.0/24");
    }

    #[test]
    fn test_multigroup_merged_mg() {
        let mut mgr = SharedConfigManager::new();
        mgr.set_group_file("default", "agent.conf", b"<syscheck></syscheck>".to_vec());
        mgr.set_group_file("web", "agent.conf", b"<rootcheck></rootcheck>".to_vec());

        let multigroup_bundle = mgr.generate_multigroup_merged_mg("default,web");
        assert!(!multigroup_bundle.is_empty());

        let checksum = mgr.compute_multigroup_checksum("default,web");
        assert!(!checksum.is_empty());
    }

    #[test]
    fn test_remcom_ipc_handler() {
        let keys_db = Arc::new(KeysDatabase::new());
        let (k, k_bytes) = KeysDatabase::generate_key();
        keys_db.add_agent(AgentKey {
            id: "001".to_string(),
            name: "srv1".to_string(),
            ip: "any".to_string(),
            raw_key: k,
            key_bytes: k_bytes,
            last_counter: 0,
        }).unwrap();

        let handler = RemcomHandler::new(keys_db, RemoteSection::default());

        let resp_str = handler.process_command(r#"{"command": "getagentsstate"}"#);
        assert!(resp_str.contains("\"error\":0"));
        assert!(resp_str.contains("srv1"));

        let resp_cfg = handler.process_command(r#"{"command": "getconfig", "parameters": {"section": "remote"}}"#);
        assert!(resp_cfg.contains("\"error\":0"));
        assert!(resp_cfg.contains("1514"));
    }
}
