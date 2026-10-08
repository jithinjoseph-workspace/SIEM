use regex::Regex;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::OnceLock;

static RE_TIMESTAMP_ISO: OnceLock<Regex> = OnceLock::new();
static RE_TIMESTAMP_SYSLOG: OnceLock<Regex> = OnceLock::new();
static RE_IPV4: OnceLock<Regex> = OnceLock::new();
static RE_IPV6: OnceLock<Regex> = OnceLock::new();
static RE_MAC: OnceLock<Regex> = OnceLock::new();
static RE_UUID: OnceLock<Regex> = OnceLock::new();
static RE_HEX: OnceLock<Regex> = OnceLock::new();
static RE_KV: OnceLock<Regex> = OnceLock::new();
static RE_QUOTED: OnceLock<Regex> = OnceLock::new();
static RE_NUMBERS: OnceLock<Regex> = OnceLock::new();
static RE_MULTI_SPACE: OnceLock<Regex> = OnceLock::new();

pub struct FingerprintEngine;

impl FingerprintEngine {
    fn get_re_iso() -> &'static Regex {
        RE_TIMESTAMP_ISO.get_or_init(|| {
            Regex::new(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b").unwrap()
        })
    }

    fn get_re_syslog() -> &'static Regex {
        RE_TIMESTAMP_SYSLOG.get_or_init(|| {
            Regex::new(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b").unwrap()
        })
    }

    fn get_re_ipv4() -> &'static Regex {
        RE_IPV4.get_or_init(|| {
            Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()
        })
    }

    fn get_re_ipv6() -> &'static Regex {
        RE_IPV6.get_or_init(|| {
            Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b").unwrap()
        })
    }

    fn get_re_mac() -> &'static Regex {
        RE_MAC.get_or_init(|| {
            Regex::new(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b").unwrap()
        })
    }

    fn get_re_uuid() -> &'static Regex {
        RE_UUID.get_or_init(|| {
            Regex::new(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b").unwrap()
        })
    }

    fn get_re_hex() -> &'static Regex {
        RE_HEX.get_or_init(|| {
            Regex::new(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{32,64}\b").unwrap()
        })
    }

    fn get_re_kv() -> &'static Regex {
        RE_KV.get_or_init(|| {
            Regex::new(r"([\w\.\-]+)=([^\s,]+)").unwrap()
        })
    }

    fn get_re_quoted() -> &'static Regex {
        RE_QUOTED.get_or_init(|| {
            Regex::new(r#""[^"]*"|'[^']*'"#).unwrap()
        })
    }

    fn get_re_num() -> &'static Regex {
        RE_NUMBERS.get_or_init(|| {
            Regex::new(r"\b\d+\b").unwrap()
        })
    }

    fn get_re_space() -> &'static Regex {
        RE_MULTI_SPACE.get_or_init(|| {
            Regex::new(r"\s+").unwrap()
        })
    }

    /// Produce a normalized structural signature and 64-bit deterministic hash
    /// Combines Method A (Structural Masking) & Method B (Token Classification)
    pub fn compute(raw_log: &str) -> (u64, String) {
        let trimmed = raw_log.trim();

        // 1. Mask Timestamps (ISO and Syslog)
        let s = Self::get_re_iso().replace_all(trimmed, "<TIMESTAMP>");
        let s = Self::get_re_syslog().replace_all(&s, "<TIMESTAMP>");

        // 2. Mask Network Identifiers (IP, MAC, UUID)
        let s = Self::get_re_ipv4().replace_all(&s, "<IP>");
        let s = Self::get_re_ipv6().replace_all(&s, "<IP>");
        let s = Self::get_re_mac().replace_all(&s, "<MAC>");
        let s = Self::get_re_uuid().replace_all(&s, "<UUID>");
        let s = Self::get_re_hex().replace_all(&s, "<HEX>");

        // 3. Mask Key-Value pairs with tokenized values
        let s = Self::get_re_kv().replace_all(&s, "$1=<VAL>");

        // 4. Mask Quoted strings
        let s = Self::get_re_quoted().replace_all(&s, "<STR>");

        // 5. Mask numbers / ports / PIDs
        let s = Self::get_re_num().replace_all(&s, "<NUM>");

        // 6. Mask Syslog header hostnames: "<TIMESTAMP> <HOSTNAME> <PROG>[<NUM>]:" -> "<TIMESTAMP> <HOST> <PROG>[<NUM>]:"
        let syslog_host_re = Regex::new(r"(<TIMESTAMP>)\s+([^\s:]+)\s+([\w\.\-]+)(?:\[<NUM>\])?:\s*").unwrap();
        let s = syslog_host_re.replace_all(&s, "$1 <HOST> $3[<NUM>]: ");

        // 7. Mask user phrases: "for invalid user root" -> "for invalid user <VAL>"
        let user_re = Regex::new(r"\b(for invalid user|for user|user)\s+([a-zA-Z0-9_\-\.]+)\b").unwrap();
        let s = user_re.replace_all(&s, "$1 <VAL>");

        // 8. Normalize multiple whitespaces
        let signature = Self::get_re_space().replace_all(&s, " ").trim().to_string();

        // Compute fast 64-bit hash
        let mut hasher = DefaultHasher::new();
        signature.hash(&mut hasher);
        let hash = hasher.finish();

        (hash, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_matching() {
        let log1 = "2026-10-03 14:22:11 LOGIN FAILED user=john src=192.168.1.50 reason=wrong_password";
        let log2 = "2026-10-03 14:25:30 LOGIN FAILED user=alice src=10.0.0.99 reason=account_expired";

        let (hash1, sig1) = FingerprintEngine::compute(log1);
        let (hash2, sig2) = FingerprintEngine::compute(log2);

        assert_eq!(hash1, hash2, "Structural hashes should match for same format!");
        assert_eq!(sig1, sig2, "Signatures should be identical!");
        assert!(sig1.contains("<TIMESTAMP>"));
        assert!(sig1.contains("user=<VAL>"));
        assert!(sig1.contains("src=<VAL>"));
    }

    #[test]
    fn test_syslog_fingerprint() {
        let l1 = "Oct 03 14:22:11 host01 sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 54321 ssh2";
        let l2 = "Oct 03 14:23:45 host02 sshd[5678]: Failed password for invalid user root from 10.0.0.1 port 43210 ssh2";

        let (h1, s1) = FingerprintEngine::compute(l1);
        let (h2, s2) = FingerprintEngine::compute(l2);

        assert_eq!(h1, h2);
        assert_eq!(s1, s2);
    }
}
