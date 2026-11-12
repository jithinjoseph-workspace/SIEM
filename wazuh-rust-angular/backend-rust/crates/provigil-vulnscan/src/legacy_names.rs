//! Literals that something outside this crate reads or that are already on disk. They keep their
//! exact values until the owner renames them together with their readers.

/// Feed consumer name; the content server sees it in the `User-Agent` header.
pub const CONSUMER_NAME: &str = "Wazuh VulnerabilityDetector";
/// Content version: `User-Agent` suffix (content server) and the prebuilt-feed check (state store).
pub const CONTENT_VERSION: &str = "v4.14.7";
/// Default feed URL when no `cti-url` is configured; read by the content server routing.
pub const DEFAULT_CTI_URL: &str =
    "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";
/// `vulnerability.scanner.reference` base in documents and alerts; shown to users by siem-api.
pub const CVE_REFERENCE_BASE: &str = "https://cti.wazuh.com/vulnerabilities/cves/";
/// Index name prefix: names the `queue/indexer/db|sent/<index>` directories already on disk.
pub const INDEX_PREFIX: &str = "wazuh-states-vulnerabilities-";
/// `agent.type` and `vulnerability.scanner.vendor`; stored in siem-api rows.
pub const VENDOR_NAME: &str = "Wazuh";
/// Top-level document object holding `cluster.name` and `schema.version`; stored in siem-api rows.
pub const DOC_ROOT_KEY: &str = "wazuh";
/// Characters stripped from the start of agent versions of the agent list (`agent.version`).
pub const AGENT_VERSION_STRIP: &str = "Wazuh ";
/// Prebuilt feed path printed by the start check; nobody reads it.
pub const PREBUILT_FEED_PATH: &str = "tmp/vd_1.0.0_vd_4.13.0.tar.xz";
/// Manager configuration file; the host and the installer read it.
pub const CONFIG_FILE: &str = "etc/ossec.conf";
/// Directory of the updater metadata store under `queue/vd_updater`; holds the stored offset.
pub const UPDATER_DB_DIR: &str = "rocksdb";
/// Internal option giving the reports-per-second limit (ProVigil name; set in etc/internal_options.conf).
pub const MAX_EPS_OPTION: &str = "provigil_modules.max_eps";
