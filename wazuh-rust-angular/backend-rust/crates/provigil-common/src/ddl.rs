//! Table definitions for a ClickHouse cluster (specs/provigil-nodes.md, N4a).
//!
//! The programs create most of their tables themselves at start (`CREATE TABLE IF NOT EXISTS`). On
//! a cluster (`CLICKHOUSE_CLUSTER` set, for example `ndr_cluster`) every data lake node must get the
//! table, and its data must be copied: [`on_cluster`] adds `ON CLUSTER` to statements that change
//! the schema and turns a `…MergeTree` engine into `Replicated…MergeTree` (ClickHouse then copies
//! inserts, deletes and updates by itself). Without a cluster the statement is unchanged. Queries,
//! inserts and data mutations (`DELETE`, `ALTER … DELETE/UPDATE`) are never changed: on replicated
//! tables they reach every copy already.

use std::sync::OnceLock;

/// The cluster name from `CLICKHOUSE_CLUSTER` (empty: a single server).
pub fn cluster() -> Option<&'static str> {
    static C: OnceLock<Option<String>> = OnceLock::new();
    C.get_or_init(|| std::env::var("CLICKHOUSE_CLUSTER").ok().map(|c| c.trim().to_string()).filter(|c| !c.is_empty())).as_deref()
}

/// `sql` for this deployment's ClickHouse (see the module notes).
pub fn on_cluster(sql: impl AsRef<str>) -> String {
    on_cluster_with(sql.as_ref(), cluster())
}

/// The statement kinds that change the schema, and how many words precede the object's name.
const KINDS: &[&[&str]] = &[
    &["CREATE", "TABLE", "IF", "NOT", "EXISTS"],
    &["CREATE", "TABLE"],
    &["CREATE", "DATABASE", "IF", "NOT", "EXISTS"],
    &["CREATE", "DATABASE"],
    &["CREATE", "MATERIALIZED", "VIEW", "IF", "NOT", "EXISTS"],
    &["CREATE", "MATERIALIZED", "VIEW"],
    &["CREATE", "VIEW", "IF", "NOT", "EXISTS"],
    &["CREATE", "VIEW"],
    &["CREATE", "OR", "REPLACE", "VIEW"],
    &["DROP", "TABLE", "IF", "EXISTS"],
    &["DROP", "TABLE"],
    &["DROP", "VIEW", "IF", "EXISTS"],
    &["DROP", "VIEW"],
    &["DROP", "DATABASE", "IF", "EXISTS"],
    &["DROP", "DATABASE"],
    &["ALTER", "TABLE"],
];

/// ALTER actions that change the schema (data mutations are left alone).
const ALTER_SCHEMA: &[&str] = &["ADD", "DROP", "MODIFY", "RENAME", "COMMENT", "CLEAR", "MATERIALIZE"];

pub fn on_cluster_with(sql: &str, cluster: Option<&str>) -> String {
    let Some(cluster) = cluster else { return sql.to_string() };
    let upper = sql.to_ascii_uppercase();
    if upper.contains(" ON CLUSTER ") {
        return sql.to_string();
    }
    // the leading words and where each ends
    let mut words: Vec<(&str, usize, usize)> = Vec::new();
    let mut i = 0;
    let b = sql.as_bytes();
    while words.len() < 8 && i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'(' {
            i += 1;
        }
        if i > start {
            words.push((&sql[start..i], start, i));
        } else {
            break;
        }
    }
    let Some(kind) = KINDS.iter().find(|k| k.len() < words.len() && k.iter().zip(&words).all(|(kw, (w, _, _))| w.eq_ignore_ascii_case(kw))) else {
        return sql.to_string();
    };
    let (_, _, name_end) = words[kind.len()];
    if kind[0] == "ALTER" && !words.get(kind.len() + 1).is_some_and(|(w, _, _)| ALTER_SCHEMA.iter().any(|a| w.eq_ignore_ascii_case(a))) {
        return sql.to_string();
    }
    let mut out = format!("{} ON CLUSTER `{}`{}", &sql[..name_end], cluster.replace('`', ""), &sql[name_end..]);
    if kind[0] == "CREATE" {
        out = replicated_engine(&out);
    }
    out
}

/// `ENGINE = XMergeTree` → `ENGINE = ReplicatedXMergeTree` (arguments kept: ClickHouse uses its default
/// copy path and replica name when the path is left out).
fn replicated_engine(sql: &str) -> String {
    let upper = sql.to_ascii_uppercase();
    let b = sql.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    // the ENGINE clause: a whole word followed by '=' (not "ENGINE" inside a name like siem_engine_docs)
    let Some(mut j) = upper.match_indices("ENGINE").map(|(e, _)| e).find_map(|e| {
        let end = e + "ENGINE".len();
        if e > 0 && word(b[e - 1]) || b.get(end).is_some_and(|c| word(*c)) {
            return None;
        }
        let mut k = end;
        while k < b.len() && b[k].is_ascii_whitespace() {
            k += 1;
        }
        (b.get(k) == Some(&b'=')).then_some(k + 1)
    }) else {
        return sql.to_string();
    };
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    let start = j;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
        j += 1;
    }
    let engine = &sql[start..j];
    if engine.ends_with("MergeTree") && !engine.starts_with("Replicated") {
        format!("{}Replicated{}", &sql[..start], &sql[start..])
    } else {
        sql.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: Option<&str> = Some("ndr_cluster");

    #[test]
    fn a_single_server_is_unchanged() {
        let s = "CREATE TABLE IF NOT EXISTS t (id String) ENGINE = ReplacingMergeTree(v) ORDER BY id";
        assert_eq!(on_cluster_with(s, None), s);
    }

    #[test]
    fn tables_get_the_cluster_and_a_replicated_engine() {
        assert_eq!(
            on_cluster_with("CREATE TABLE IF NOT EXISTS siem_x (id String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id", C),
            "CREATE TABLE IF NOT EXISTS siem_x ON CLUSTER `ndr_cluster` (id String, version UInt64) ENGINE = ReplicatedReplacingMergeTree(version) ORDER BY id"
        );
        assert_eq!(
            on_cluster_with("create table if not exists `ndr_acme`.soar(id String) ENGINE=MergeTree ORDER BY id", C),
            "create table if not exists `ndr_acme`.soar ON CLUSTER `ndr_cluster`(id String) ENGINE=ReplicatedMergeTree ORDER BY id"
        );
        assert_eq!(on_cluster_with("\n  CREATE TABLE IF NOT EXISTS m (x UInt8) ENGINE = Memory", C), "\n  CREATE TABLE IF NOT EXISTS m ON CLUSTER `ndr_cluster` (x UInt8) ENGINE = Memory");
        // "engine" inside a name or a column is not the ENGINE clause (found in the cluster test)
        assert_eq!(
            on_cluster_with("CREATE TABLE IF NOT EXISTS siem_engine_docs (id String, engine_name String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id", C),
            "CREATE TABLE IF NOT EXISTS siem_engine_docs ON CLUSTER `ndr_cluster` (id String, engine_name String, version UInt64) ENGINE = ReplicatedReplacingMergeTree(version) ORDER BY id"
        );
    }

    #[test]
    fn databases_views_drops_and_schema_alters_get_the_cluster() {
        assert_eq!(on_cluster_with("CREATE DATABASE IF NOT EXISTS `ndr_acme`", C), "CREATE DATABASE IF NOT EXISTS `ndr_acme` ON CLUSTER `ndr_cluster`");
        assert_eq!(on_cluster_with("ALTER TABLE t ADD COLUMN IF NOT EXISTS z UInt8", C), "ALTER TABLE t ON CLUSTER `ndr_cluster` ADD COLUMN IF NOT EXISTS z UInt8");
        assert_eq!(on_cluster_with("DROP TABLE IF EXISTS t", C), "DROP TABLE IF EXISTS t ON CLUSTER `ndr_cluster`");
        assert_eq!(
            on_cluster_with("CREATE MATERIALIZED VIEW IF NOT EXISTS mv TO t AS SELECT 1", C),
            "CREATE MATERIALIZED VIEW IF NOT EXISTS mv ON CLUSTER `ndr_cluster` TO t AS SELECT 1"
        );
    }

    #[test]
    fn data_and_queries_are_never_changed() {
        for s in [
            "SELECT * FROM t WHERE id = ?",
            "INSERT INTO t (id) VALUES (?)",
            "DELETE FROM t WHERE id = ?",
            "ALTER TABLE t DELETE WHERE id = ?",
            "ALTER TABLE t UPDATE x = 1 WHERE id = ?",
            "OPTIMIZE TABLE t FINAL",
            "CREATE TABLE IF NOT EXISTS t ON CLUSTER ndr_cluster (id String) ENGINE = ReplicatedMergeTree('/p', '{replica}') ORDER BY id",
        ] {
            assert_eq!(on_cluster_with(s, C), s);
        }
    }
}
