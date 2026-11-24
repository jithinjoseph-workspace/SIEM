// NDR-specific detection wiring: sigma updater and multiflow correlator stay here.
// DetectionEngine, SigmaRule, and the full Sigma parser live in provigil-common.
// License: Apache-2.0

pub mod updater;
pub mod multiflow;
pub use updater::{spawn_sigma_updater, sync_now};
pub use provigil_common::detection::{DetectionEngine, SigmaRule, DetectionMatch, parse_rule_content};
