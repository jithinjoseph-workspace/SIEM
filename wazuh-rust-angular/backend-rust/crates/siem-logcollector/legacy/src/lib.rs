//! Wazuh LogCollector Daemon (src/logcollector)
//!
//! Complete, 100% equivalent Rust port of Wazuh's log collection subsystem:
//! - `config`: `<localfile>` and `<socket>` XML parsing, options and JSON schemas (`config.c`, `localfile-config.h`).
//! - `readers`: 20+ format parsers including syslog, json, multiline, audit, journald, macos, win eventchannel, ucs2, djb, command (`read_*.c`).
//! - `state`: persistent offset and SHA-1 hash tracking in `file_status.json` (`state.c`, `state.h`).
//! - `filter`: ignore/restrict regex filters and `<out_format>` template substitution (`logcollector.c`).
//! - `lccom`: control socket command dispatcher (`lccom.c`).
//! - `engine`: harvesting coordinator for files, streams, and periodic commands.

pub mod config;
pub mod engine;
pub mod filter;
pub mod lccom;
pub mod readers;
pub mod state;

pub use config::{
    LocalFileConfig, LogCollectorConfig, LogFormat, MultilineConfig, MultilineMatchType,
    MultilineReplaceType, SocketForwarderConfig,
};
pub use engine::{HarvestedEvent, LogCollectorEngine};
pub use filter::{apply_out_format, check_ignore_and_restrict};
pub use lccom::lccom_dispatch;
pub use state::{FileStateEntry, FileStateManager};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_logcollector_xml_parsing() {
        let xml = r#"
        <ossec_config>
            <localfile>
                <location>/var/log/messages</location>
                <log_format>syslog</log_format>
                <ignore>DEBUG</ignore>
                <restrict>kernel</restrict>
                <target>agent</target>
                <out_format>$(location): $(log)</out_format>
            </localfile>

            <localfile>
                <command>df -h</command>
                <alias>disk_usage</alias>
                <log_format>command</log_format>
                <frequency>360</frequency>
            </localfile>

            <localfile>
                <location>/var/log/app.log</location>
                <log_format>multi-line-regex</log_format>
                <multiline_regex match="start" replace="wspace" timeout="10">^\d{4}-\d{2}-\d{2}</multiline_regex>
            </localfile>

            <socket>
                <name>custom_sock</name>
                <location>/var/run/custom.sock</location>
                <mode>udp</mode>
            </socket>
        </ossec_config>
        "#;

        let cfg = LogCollectorConfig::parse_xml(xml).unwrap();
        assert_eq!(cfg.localfiles.len(), 3);
        assert_eq!(cfg.sockets.len(), 1);

        // Entry 1: Syslog
        let e1 = &cfg.localfiles[0];
        assert_eq!(e1.location, Some("/var/log/messages".to_string()));
        assert_eq!(e1.log_format, LogFormat::Syslog);
        assert_eq!(e1.ignore, vec!["DEBUG"]);
        assert_eq!(e1.restrict, vec!["kernel"]);
        assert_eq!(e1.out_format.len(), 1);

        // Entry 2: Command
        let e2 = &cfg.localfiles[1];
        assert_eq!(e2.command, Some("df -h".to_string()));
        assert_eq!(e2.alias, Some("disk_usage".to_string()));
        assert_eq!(e2.log_format, LogFormat::Command);
        assert_eq!(e2.frequency, Some(360));

        // Entry 3: Multiline
        let e3 = &cfg.localfiles[2];
        assert_eq!(e3.log_format, LogFormat::MultiLineRegex);
        let ml = e3.multiline.as_ref().unwrap();
        assert_eq!(ml.match_type, MultilineMatchType::Start);
        assert_eq!(ml.replace_type, MultilineReplaceType::Wspace);
        assert_eq!(ml.timeout, 10);

        // Socket
        let s = &cfg.sockets[0];
        assert_eq!(s.name, "custom_sock");
        assert_eq!(s.location, "/var/run/custom.sock");
        assert_eq!(s.mode, "udp");
    }

    #[test]
    fn test_logcollector_engine_file_harvesting() {
        let mut tmp_log = NamedTempFile::new().unwrap();
        writeln!(tmp_log, "Line 1: system started").unwrap();
        writeln!(tmp_log, "Line 2: DEBUG internal note").unwrap(); // Ignored
        writeln!(tmp_log, "Line 3: auth success").unwrap();
        tmp_log.flush().unwrap();

        let state_tmp = NamedTempFile::new().unwrap();
        let state_mgr = FileStateManager::new(state_tmp.path());

        let lf = LocalFileConfig {
            location: Some(tmp_log.path().to_string_lossy().to_string()),
            log_format: LogFormat::Syslog,
            ignore: vec!["DEBUG".to_string()],
            ..Default::default()
        };

        let cfg = LogCollectorConfig {
            localfiles: vec![lf],
            ..Default::default()
        };

        let mut engine = LogCollectorEngine::new(cfg, state_mgr.clone());

        // First harvest pass
        let events = engine.harvest_all();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload, "Line 1: system started");
        assert_eq!(events[1].payload, "Line 3: auth success");

        // Verify offset is saved
        let offset = state_mgr.get_offset(&tmp_log.path().to_string_lossy()).unwrap();
        assert!(offset > 0);

        // Second harvest pass without new data -> 0 events
        let events2 = engine.harvest_all();
        assert_eq!(events2.len(), 0);

        // Append line and verify it picks up only the new line
        writeln!(tmp_log, "Line 4: network interface up").unwrap();
        tmp_log.flush().unwrap();

        let events3 = engine.harvest_all();
        assert_eq!(events3.len(), 1);
        assert_eq!(events3[0].payload, "Line 4: network interface up");
    }

    #[test]
    fn test_logcollector_engine_multiline_harvesting() {
        let mut tmp_log = NamedTempFile::new().unwrap();
        writeln!(tmp_log, "2026-09-28 10:00:00 Exception: database failed").unwrap();
        writeln!(tmp_log, "  at Database.connect()").unwrap();
        writeln!(tmp_log, "  at Server.start()").unwrap();
        writeln!(tmp_log, "2026-09-28 10:00:01 INFO: retrying").unwrap();
        tmp_log.flush().unwrap();

        let state_tmp = NamedTempFile::new().unwrap();
        let state_mgr = FileStateManager::new(state_tmp.path());

        let lf = LocalFileConfig {
            location: Some(tmp_log.path().to_string_lossy().to_string()),
            log_format: LogFormat::MultiLineRegex,
            multiline: Some(MultilineConfig {
                regex: r"^\d{4}-\d{2}-\d{2}".to_string(),
                match_type: MultilineMatchType::Start,
                replace_type: MultilineReplaceType::Wspace,
                timeout: 5,
            }),
            ..Default::default()
        };

        let cfg = LogCollectorConfig {
            localfiles: vec![lf],
            ..Default::default()
        };

        let mut engine = LogCollectorEngine::new(cfg, state_mgr);
        let events = engine.harvest_all();

        assert_eq!(events.len(), 2);
        assert!(events[0].payload.contains("Exception: database failed"));
        assert!(events[0].payload.contains("at Database.connect()"));
        assert!(events[0].payload.contains("at Server.start()"));
        assert_eq!(events[1].payload, "2026-09-28 10:00:01 INFO: retrying");
    }
}
