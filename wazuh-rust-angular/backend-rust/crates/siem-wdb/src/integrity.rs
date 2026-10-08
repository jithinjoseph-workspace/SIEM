use sha1::{Digest, Sha1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeChecksum {
    pub begin: String,
    pub end: String,
    pub count: usize,
    pub checksum: String,
}

pub struct IntegrityChecker;

impl IntegrityChecker {
    /// Computes collective SHA-1 checksum over a sorted slice of key-value items
    pub fn compute_range_checksum(items: &[(&str, &str)]) -> Option<RangeChecksum> {
        if items.is_empty() {
            return None;
        }

        let begin = items.first().unwrap().0.to_string();
        let end = items.last().unwrap().0.to_string();
        let count = items.len();

        let mut hasher = Sha1::new();
        for (key, val) in items {
            hasher.update(key.as_bytes());
            hasher.update(b":");
            hasher.update(val.as_bytes());
            hasher.update(b"\n");
        }

        let digest = hasher.finalize();
        let checksum = format!("{:02x}", digest);

        Some(RangeChecksum {
            begin,
            end,
            count,
            checksum,
        })
    }

    /// Verifies if a range on manager matches the reported checksum from the agent
    pub fn verify_range(items: &[(&str, &str)], expected_checksum: &str) -> bool {
        if let Some(range) = Self::compute_range_checksum(items) {
            range.checksum.eq_ignore_ascii_case(expected_checksum.trim())
        } else {
            expected_checksum.is_empty()
        }
    }
}
