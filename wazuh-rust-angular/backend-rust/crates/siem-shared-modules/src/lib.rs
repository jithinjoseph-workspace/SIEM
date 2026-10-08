//! Wazuh Shared Modules Rust Implementation
//!
//! Provides direct, production-grade 1-to-1 ports of Wazuh's C++ shared modules:
//! - `common`: Error codes, common results, and definitions.
//! - `dbsync`: Database synchronization, row hashing, composite checksums, and delta generation.
//! - `rsync`: Differential table reconciliation with binary search range checksums.
//! - `router`: In-process topic-based pub-sub broker (RouterProvider / RouterSubscriber).
//! - `indexer_connector`: OpenSearch / Elasticsearch bulk NDJSON ingestion client and queue.
//! - `keystore`: Column-family key-value store abstraction with prefix scans and atomic batches.
//! - `content_manager`: Security content updater and feed coordinator with socket control.
//! - `http_request`: Asynchronous HTTP client wrapper.
//! - `utils`: LRU cache, thread-safe queue, pipeline pattern, round-robin selector, and crypto digests.

pub mod common;
pub mod content_manager;
pub mod dbsync;
pub mod http_request;
pub mod indexer_connector;
pub mod keystore;
pub mod router;
pub mod rsync;
pub mod utils;

#[cfg(test)]
mod tests {
    use super::*;
    use common::ReturnType;
    use dbsync::{DbSyncEngine, SyncOperation};
    use indexer_connector::{IndexDocument, IndexerConfig, IndexerConnector};
    use keystore::{KeyStore, KeyStoreOptions};
    use router::RouterProvider;
    use rsync::{RangeReconciliation, RsyncSynchronizer};
    use serde_json::json;
    use utils::{CryptoHelper, LruCache, Pipeline, RoundRobinSelector, ThreadSafeQueue};

    #[test]
    fn test_common_types() {
        let ret = ReturnType::Success;
        assert_eq!(ret as u32, 0);
        assert_eq!(ret.to_string(), "SUCCESS");
    }

    #[test]
    fn test_dbsync_engine_lifecycle() {
        let engine = DbSyncEngine::new();
        engine.register_table("sys_programs", vec!["name", "architecture"]).unwrap();

        // 1. Initial snapshot (2 rows inserted)
        let row1 = json!({
            "name": "curl",
            "version": "7.68.0",
            "architecture": "x86_64"
        }).as_object().unwrap().clone();

        let row2 = json!({
            "name": "openssl",
            "version": "1.1.1f",
            "architecture": "x86_64"
        }).as_object().unwrap().clone();

        let deltas1 = engine.sync_snapshot("sys_programs", vec![row1.clone(), row2.clone()]).unwrap();
        assert_eq!(deltas1.len(), 2);
        assert_eq!(deltas1[0].operation, SyncOperation::Inserted);
        assert_eq!(deltas1[1].operation, SyncOperation::Inserted);
        assert_eq!(engine.get_row_count("sys_programs").unwrap(), 2);

        let initial_checksum = engine.get_table_checksum("sys_programs").unwrap();
        assert!(!initial_checksum.is_empty());

        // 2. Second snapshot (row1 modified, row2 removed/deleted, row3 added)
        let mut row1_modified = row1.clone();
        row1_modified.insert("version".to_string(), json!("8.0.0"));

        let row3 = json!({
            "name": "nginx",
            "version": "1.18.0",
            "architecture": "x86_64"
        }).as_object().unwrap().clone();

        let deltas2 = engine.sync_snapshot("sys_programs", vec![row1_modified, row3]).unwrap();
        assert_eq!(deltas2.len(), 3);

        let modified_event = deltas2.iter().find(|d| d.operation == SyncOperation::Modified).unwrap();
        assert_eq!(modified_event.primary_keys.get("name").unwrap(), &json!("curl"));

        let deleted_event = deltas2.iter().find(|d| d.operation == SyncOperation::Deleted).unwrap();
        assert_eq!(deleted_event.primary_keys.get("name").unwrap(), &json!("openssl"));

        let inserted_event = deltas2.iter().find(|d| d.operation == SyncOperation::Inserted).unwrap();
        assert_eq!(inserted_event.primary_keys.get("name").unwrap(), &json!("nginx"));

        assert_eq!(engine.get_row_count("sys_programs").unwrap(), 2);
    }

    #[test]
    fn test_rsync_reconciliation() {
        let synchronizer = RsyncSynchronizer::new();
        let items = vec![
            ("id_001", "hash_aaa"),
            ("id_002", "hash_bbb"),
            ("id_003", "hash_ccc"),
            ("id_004", "hash_ddd"),
        ];

        let range_msg = synchronizer.build_range_checksum("test_tbl", &items).unwrap();
        assert_eq!(range_msg.count, 4);

        // Matching range
        let res = synchronizer.reconcile_range(&range_msg, &items).unwrap();
        match res {
            RangeReconciliation::Synchronized => (),
            _ => panic!("Expected range to match!"),
        }

        // Differing range -> triggers split
        let mut diff_items = items.clone();
        diff_items[1] = ("id_002", "hash_modified");

        let res_diff = synchronizer.reconcile_range(&range_msg, &diff_items).unwrap();
        match res_diff {
            RangeReconciliation::Split { left, right } => {
                assert_eq!(left.len(), 2);
                assert_eq!(right.len(), 2);
            }
            _ => panic!("Expected range split!"),
        }
    }

    #[tokio::test]
    async fn test_router_pub_sub() {
        let provider = RouterProvider::new(64);
        let mut sub = provider.subscribe("fim_events").await;

        let sent_count = provider.publish(
            "fim_events",
            "syscheckd",
            json!({ "path": "/etc/shadow", "action": "modified" }),
        ).await.unwrap();

        assert_eq!(sent_count, 1);

        let received = sub.recv().await.unwrap();
        assert_eq!(received.topic, "fim_events");
        assert_eq!(received.sender, "syscheckd");
        assert_eq!(received.payload["path"], "/etc/shadow");
    }

    #[test]
    fn test_indexer_connector_ndjson() {
        let (connector, _rx) = IndexerConnector::new(IndexerConfig::default());
        let docs = vec![
            IndexDocument {
                index: Some("alerts".to_string()),
                doc_id: Some("doc-1".to_string()),
                document: json!({ "agent": "001", "level": 10 }),
            },
            IndexDocument {
                index: None,
                doc_id: None,
                document: json!({ "agent": "002", "level": 3 }),
            },
        ];

        let ndjson = connector.serialize_bulk_ndjson(&docs).unwrap();
        assert!(ndjson.contains("{\"index\":{\"_id\":\"doc-1\",\"_index\":\"alerts\"}}"));
        assert!(ndjson.contains("{\"index\":{\"_index\":\"wazuh-alerts-4.x\"}}"));
    }

    #[test]
    fn test_keystore_column_families() {
        let store = KeyStore::new(KeyStoreOptions::default()).unwrap();
        store.create_column_family("vulns").unwrap();

        store.put("vulns", b"CVE-2024-0001", b"Critical Linux Kernel flaw").unwrap();
        assert_eq!(
            store.get("vulns", b"CVE-2024-0001").unwrap(),
            Some(b"Critical Linux Kernel flaw".to_vec())
        );

        // Prefix scan
        store.put("vulns", b"CVE-2024-0002", b"OpenSSL flaw").unwrap();
        store.put("vulns", b"CVE-2023-9999", b"Old flaw").unwrap();

        let cve2024 = store.prefix_scan("vulns", b"CVE-2024").unwrap();
        assert_eq!(cve2024.len(), 2);
    }

    #[tokio::test]
    async fn test_content_manager_commands() {
        let cm = content_manager::ContentManager::new();
        cm.register_feed("nvd_cve", "https://nvd.nist.gov/feed.json", "/var/ossec/queue/cve.json").await.unwrap();

        let resp = cm.process_command(content_manager::ContentCommand {
            command: "update".to_string(),
            target: Some("nvd_cve".to_string()),
        }).await;

        assert_eq!(resp.error, 0);

        let status_resp = cm.process_command(content_manager::ContentCommand {
            command: "status".to_string(),
            target: None,
        }).await;
        assert_eq!(status_resp.error, 0);
    }

    #[test]
    fn test_utils_components() {
        // 1. ThreadSafeQueue
        let q = ThreadSafeQueue::new(2);
        assert!(q.push(10));
        assert!(q.push(20));
        assert!(!q.push(30)); // full
        assert_eq!(q.pop(), Some(10));
        assert_eq!(q.pop(), Some(20));
        assert_eq!(q.pop(), None);

        // 2. LruCache
        let mut lru = LruCache::new(2);
        lru.insert("k1", 100);
        lru.insert("k2", 200);
        assert_eq!(lru.get(&"k1"), Some(&100)); // access k1
        lru.insert("k3", 300); // evicts k2
        assert_eq!(lru.get(&"k2"), None);
        assert_eq!(lru.get(&"k1"), Some(&100));
        assert_eq!(lru.get(&"k3"), Some(&300));

        // 3. Pipeline
        let pipeline = Pipeline::new()
            .add_stage(|n: i32| if n > 0 { Some(n * 2) } else { None })
            .add_stage(|n: i32| Some(n + 5));

        assert_eq!(pipeline.process(10), Some(25));
        assert_eq!(pipeline.process(-5), None);

        // 4. RoundRobinSelector
        let rr = RoundRobinSelector::new(vec!["server1", "server2"]);
        assert_eq!(rr.next(), Some("server1"));
        assert_eq!(rr.next(), Some("server2"));
        assert_eq!(rr.next(), Some("server1"));

        // 5. CryptoHelper
        assert_eq!(
            CryptoHelper::sha1(b"hello world"),
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        );
    }
}
