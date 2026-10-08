//! What this engine process is for (`ENGINE_ROLE`).
//!
//! Every engine used to do everything: receive sensor data, read Kafka, run the
//! detection jobs and serve the UI. At thousands of sensors a burst of ingest
//! competes with the UI for the same CPU. The same binary can now be started in
//! different roles and put behind different nginx upstreams:
//!
//! | role      | receives ingest | Kafka consumer | leader jobs | rest of the platform |
//! |-----------|-----------------|----------------|-------------|----------------------|
//! | `all`     | yes             | yes            | yes         | yes  (the default)   |
//! | `ingest`  | yes             | no             | no          | no                   |
//! | `process` | yes             | yes            | yes         | yes                  |
//! | `ui`      | yes             | no             | no          | yes                  |
//!
//! "receives ingest" is always on (the HTTP routes are the same in every role);
//! which engines actually get sensor traffic is decided by nginx. An unset or
//! unrecognised value means `all`, i.e. exactly the behaviour before this existed.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineRole {
    All,
    Ingest,
    Process,
    Ui,
}

impl EngineRole {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "all" => Some(Self::All),
            "ingest"   => Some(Self::Ingest),
            "process"  => Some(Self::Process),
            "ui"       => Some(Self::Ui),
            _          => None,
        }
    }

    pub fn from_env() -> Self {
        match std::env::var("ENGINE_ROLE") {
            Err(_) => Self::All,
            Ok(v) => Self::parse(&v).unwrap_or_else(|| {
                tracing::error!(
                    "ENGINE_ROLE='{}' is not one of all|ingest|process|ui - running as 'all'", v
                );
                Self::All
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::All     => "all",
            Self::Ingest  => "ingest",
            Self::Process => "process",
            Self::Ui      => "ui",
        }
    }

    /// Reads events from Kafka and writes them to ClickHouse.
    pub fn consumer(self) -> bool {
        matches!(self, Self::All | Self::Process)
    }

    /// Takes part in the leader election and runs the elected-leader jobs
    /// (threat analysis, triage, multiflow, Arkime sync, pcap cleanup).
    pub fn leader_jobs(self) -> bool {
        matches!(self, Self::All | Self::Process)
    }

    /// Runs the platform's shared in-process machinery: enrichment caches, threat-intel
    /// refresh, OUI and vendor updates, rule updater, agent-status and version checks.
    /// An ingest engine only needs to check keys, accept batches and publish to Kafka.
    pub fn full_platform(self) -> bool {
        !matches!(self, Self::Ingest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_values_case_and_space_insensitively() {
        assert_eq!(EngineRole::parse("all"), Some(EngineRole::All));
        assert_eq!(EngineRole::parse(""), Some(EngineRole::All), "empty means all");
        assert_eq!(EngineRole::parse("  INGEST "), Some(EngineRole::Ingest));
        assert_eq!(EngineRole::parse("Process"), Some(EngineRole::Process));
        assert_eq!(EngineRole::parse("ui"), Some(EngineRole::Ui));
        assert_eq!(EngineRole::parse("ingset"), None, "typos are not silently accepted here");
    }

    #[test]
    fn capability_matrix_is_exactly_the_documented_one() {
        // (role, consumer, leader_jobs, full_platform)
        let expected = [
            (EngineRole::All,     true,  true,  true),
            (EngineRole::Ingest,  false, false, false),
            (EngineRole::Process, true,  true,  true),
            (EngineRole::Ui,      false, false, true),
        ];
        for (role, consumer, jobs, full) in expected {
            assert_eq!(role.consumer(), consumer, "{role:?} consumer");
            assert_eq!(role.leader_jobs(), jobs, "{role:?} leader_jobs");
            assert_eq!(role.full_platform(), full, "{role:?} full_platform");
        }
    }

    #[test]
    fn default_and_unknown_env_run_everything() {
        // one test for the env var: it is process-wide state
        std::env::remove_var("ENGINE_ROLE");
        assert_eq!(EngineRole::from_env(), EngineRole::All);
        std::env::set_var("ENGINE_ROLE", "nonsense");
        assert_eq!(EngineRole::from_env(), EngineRole::All, "an unknown value falls back to all");
        std::env::set_var("ENGINE_ROLE", "ingest");
        assert_eq!(EngineRole::from_env(), EngineRole::Ingest);
        std::env::remove_var("ENGINE_ROLE");
    }

    #[test]
    fn as_str_round_trips() {
        for r in [EngineRole::All, EngineRole::Ingest, EngineRole::Process, EngineRole::Ui] {
            assert_eq!(EngineRole::parse(r.as_str()), Some(r));
        }
    }
}
