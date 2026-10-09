//! Superseded: the faithful port of Wazuh's rsync is the `siem-dbsync`
//! crate. This simplified in-memory version is kept for its current users.
//!
//! Wazuh differential table synchronization protocol (rsync)
//!
//! Provides range-based checksum partitioning and binary search differential synchronization
//! to reconcile databases between endpoints with minimal network bandwidth.

use crate::common::{ReturnType, Result, SharedModuleError};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SyncMessageType {
    Start,
    RangeChecksum,
    RowData,
    SyncComplete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RangeChecksumMessage {
    pub table: String,
    pub start_id: String,
    pub end_id: String,
    pub count: usize,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RowDataMessage {
    pub table: String,
    pub item_id: String,
    pub checksum: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RsyncMessage {
    pub msg_type: SyncMessageType,
    pub table: String,
    pub range: Option<RangeChecksumMessage>,
    pub row: Option<RowDataMessage>,
}

/// Computes range checksum for a slice of (item_id, row_checksum) pairs.
pub fn compute_range_checksum(items: &[(&str, &str)]) -> String {
    let mut hasher = Sha1::new();
    for (id, cksum) in items {
        hasher.update(id.as_bytes());
        hasher.update(b"=");
        hasher.update(cksum.as_bytes());
        hasher.update(b";");
    }
    format!("{:x}", hasher.finalize())
}

/// Binary search range differential partitioner.
/// Compares local range items with remote range checksum.
/// If checksum matches, range is synchronized.
/// If checksum mismatches and count > 1, divides into two sub-ranges.
/// If checksum mismatches and count == 1, outputs the differing row.
#[derive(Debug, Clone, Default)]
pub struct RsyncSynchronizer;

impl RsyncSynchronizer {
    pub fn new() -> Self {
        Self
    }

    /// Build a range checksum message for a collection of (item_id, row_checksum) items.
    pub fn build_range_checksum(
        &self,
        table: &str,
        items: &[(&str, &str)],
    ) -> Result<RangeChecksumMessage> {
        if items.is_empty() {
            return Err(SharedModuleError::Failure(
                ReturnType::InvalidParam,
                "Cannot build range checksum on empty item list".into(),
            ));
        }

        let start_id = items.first().unwrap().0.to_string();
        let end_id = items.last().unwrap().0.to_string();
        let count = items.len();
        let checksum = compute_range_checksum(items);

        Ok(RangeChecksumMessage {
            table: table.to_string(),
            start_id,
            end_id,
            count,
            checksum,
        })
    }

    /// Check if remote range matches local items, and if not, partition into subranges or return mismatch.
    pub fn reconcile_range<'a>(
        &self,
        remote_range: &RangeChecksumMessage,
        local_items: &'a [(&'a str, &'a str)],
    ) -> Result<RangeReconciliation<'a>> {
        let local_checksum = compute_range_checksum(local_items);
        if local_checksum == remote_range.checksum {
            return Ok(RangeReconciliation::Synchronized);
        }

        if local_items.len() <= 1 {
            // Found specific row difference
            return Ok(RangeReconciliation::Differences(local_items.to_vec()));
        }

        // Split in half
        let mid = local_items.len() / 2;
        let left = &local_items[..mid];
        let right = &local_items[mid..];

        Ok(RangeReconciliation::Split {
            left: left.to_vec(),
            right: right.to_vec(),
        })
    }
}

pub enum RangeReconciliation<'a> {
    Synchronized,
    Split {
        left: Vec<(&'a str, &'a str)>,
        right: Vec<(&'a str, &'a str)>,
    },
    Differences(Vec<(&'a str, &'a str)>),
}
