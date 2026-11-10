//! In-memory high-throughput Threat Intelligence Manager:
//! Evaluates incoming events against malicious IP subnets (CIDR), cryptographic
//! file hashes (MD5/SHA1/SHA256), and C2/malware domains with zero external C dependencies.

mod matcher;
mod threat_intel;

pub use threat_intel::*;
