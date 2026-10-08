// ThreatIntel lives in provigil-common so ndr-engine and siem-engine share the same
// in-memory IOC cache, feed refreshers, and CIDR matching logic.
pub use provigil_common::threat_intel::ThreatIntel;
