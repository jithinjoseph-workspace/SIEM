// CEF forwarder lives in provigil-common so ndr-engine and siem-engine
// both forward alerts to 3rd-party SIEMs (Splunk, QRadar, etc.) with
// the same CEF formatting logic.
pub use provigil_common::siem::forwarder::*;
