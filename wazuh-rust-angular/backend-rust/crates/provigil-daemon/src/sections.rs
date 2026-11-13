//! The sections the manager accepts inside `<ossec_config>` and `<agent_config>`, and which of
//! them must have child elements. Every service rejects a document with another section.

/// (name, must have child elements)
pub const SECTIONS: &[(&str, bool)] = &[
    ("global", true),
    ("email_alerts", true),
    ("database_output", true),
    ("syslog_output", true),
    ("integration", true),
    ("agentless", true),
    ("ruleset", true),
    ("syscheck", false),
    ("rootcheck", false),
    ("alerts", true),
    ("localfile", true),
    ("remote", true),
    ("client", true),
    ("anti_tampering", true),
    ("client_buffer", false),
    ("command", true),
    ("active-response", true),
    ("reports", true),
    ("wodle", false),
    ("sca", false),
    ("vulnerability-detection", false),
    ("vulnerability-detector", false),
    ("indexer", false),
    ("gcp-pubsub", false),
    ("gcp-bucket", false),
    ("fluent-forward", false),
    ("auth", false),
    ("labels", true),
    ("logging", false),
    ("cluster", true),
    ("socket", true),
    ("rule_test", true),
    ("agent-upgrade", true),
    ("task-manager", true),
    ("wdb", true),
    ("github", true),
    ("office365", true),
    ("ms-graph", true),
];


/// Whether a section is accepted: a known name, with child elements when it needs them.
pub fn known(name: &str, has_children: bool) -> bool {
    SECTIONS.iter().any(|(n, needs)| *n == name && (has_children || !needs))
}
