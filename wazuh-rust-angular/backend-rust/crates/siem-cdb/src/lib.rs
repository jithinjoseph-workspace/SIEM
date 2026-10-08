pub mod cdb;
pub mod threat_intel;

pub use cdb::{cdb_hash, CdbTable};
pub use threat_intel::ThreatIntelManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdb_integration() {
        let manager = ThreatIntelManager::new_with_builtin_feeds();

        // Custom list addition
        let mut custom = CdbTable::new("custom_blocklist");
        custom.insert("10.99.0.0/16", "Internal Compromised Segment");
        manager.add_list(custom);

        let res = manager.check_ip("10.99.5.42");
        assert!(res.is_some());
        let (list_name, desc) = res.unwrap();
        assert_eq!(list_name, "custom_blocklist");
        assert_eq!(desc, "Internal Compromised Segment");
    }
}
