//! Wazuh Authd & Agent Enrollment Subsystem (`src/os_auth`)
//!
//! Provides agent registration, key exchange, mutual TLS verification,
//! duplicate agent replacement rules, group validation, and local control IPC.

pub mod authcom;
pub mod cert;
pub mod config;
pub mod enrollment;
pub mod groups;
pub mod local_server;
pub mod server;

pub use authcom::{authcom_dispatch, authcom_getconfig};
pub use cert::{match_dns_hostname, match_ip_address, verify_peer_identity};
pub use config::{AuthdConfig, ForceOptions, KeyRequestConfig, DEFAULT_PORT};
pub use enrollment::{
    add_agent_to_keystore, can_replace_agent, compare_wazuh_versions, format_success_response,
    is_valid_name, parse_enrollment_data, validate_and_prepare, EnrollmentError, EnrollmentRequest,
};
pub use groups::{delete_repeated_groups, validate_groups, MAX_GROUPS_PER_MULTIGROUP};
pub use local_server::{local_dispatch, LocalErrorCode};
pub use server::AuthDaemon;
