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
const ALTER_SCHEMA: &[&str] = &["ADD", "DROP", "MODIFY", "REMOVE", "RENAME", "COMMENT", "CLEAR", "MATERIALIZE"];

/// The copy path of a table that every data lake server holds in full: without the shard, so all
/// servers of every shard are copies of each other (the default path has the shard in it).
const ALL_PATH: &str = "/clickhouse/tables/{uuid}/all";

pub fn on_cluster_with(sql: &str, cluster: Option<&str>) -> String {
    on_cluster_path(sql, cluster, Some(ALL_PATH))
}

/// As [`on_cluster_with`]; `path` None keeps ClickHouse's default copy path (per shard: a split
/// table's local part).
fn on_cluster_path(sql: &str, cluster: Option<&str>, path: Option<&str>) -> String {
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
        out = replicated_engine(&out, path);
    }
    out
}

/// `ENGINE = XMergeTree(args)` → `ENGINE = ReplicatedXMergeTree('path', '{replica}', args)`, or without
/// `path` ClickHouse's default copy path and replica name (`ReplicatedXMergeTree(args)`).
fn replicated_engine(sql: &str, path: Option<&str>) -> String {
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
    if !engine.ends_with("MergeTree") || engine.starts_with("Replicated") {
        return sql.to_string();
    }
    let Some(path) = path else { return format!("{}Replicated{}", &sql[..start], &sql[start..]) };
    let args = format!("'{path}', '{{replica}}'");
    let mut k = j;
    while k < b.len() && b[k].is_ascii_whitespace() {
        k += 1;
    }
    let tail = if b.get(k) == Some(&b'(') {
        let mut m = k + 1;
        while m < b.len() && b[m].is_ascii_whitespace() {
            m += 1;
        }
        let sep = if b.get(m) == Some(&b')') { "" } else { ", " };
        format!("{}({args}{sep}{}", &sql[j..k], &sql[k + 1..])
    } else {
        format!("({args}){}", &sql[j..])
    };
    format!("{}Replicated{engine}{tail}", &sql[..start])
}

// ---- split tables (N4b) ----
//
// The large tables (`CLICKHOUSE_SHARD_TABLES`, for example `siem_events,siem_alerts`) are split over
// the cluster's shards: each server keeps its share in `<table>_local` (copied within its shard),
// and `<table>` becomes a Distributed table over them, so the programs read and insert as before.
// Schema changes go to the right table: retention (TTL) to the local one, column changes to both.

/// NDR tables init.sql always creates split (`_local` + Distributed), with the key that keeps one
/// row's versions on one shard (ReplacingMergeTree) or `rand()` for an insert-only table.
pub const NDR_SPLIT: [(&str, &str); 2] = [("ndr_events", "rand()"), ("ndr_hits", "cityHash64(tenant_id, community_id)")];

/// The split tables (only on a cluster): `CLICKHOUSE_SHARD_TABLES` and [`NDR_SPLIT`].
pub fn shard_tables() -> &'static [String] {
    static T: OnceLock<Vec<String>> = OnceLock::new();
    T.get_or_init(|| {
        if cluster().is_none() {
            return Vec::new();
        }
        let mut v: Vec<String> = std::env::var("CLICKHOUSE_SHARD_TABLES").unwrap_or_default().split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
        v.extend(NDR_SPLIT.iter().map(|(t, _)| t.to_string()));
        v
    })
}

/// How a split table's rows are spread over the shards.
pub fn shard_key(table: &str) -> &'static str {
    NDR_SPLIT.iter().find(|(t, _)| *t == table).map(|(_, k)| *k).unwrap_or("rand()")
}

/// The statements to run for `sql` on this deployment (one, or several for a split table).
pub fn statements(sql: impl AsRef<str>) -> Vec<String> {
    statements_with(sql.as_ref(), cluster(), shard_tables())
}

/// (database part with its dot, table name, whether the name was quoted) of `db.t`, `` `db`.`t` `` or `t`.
fn split_name(name: &str) -> (String, String, bool) {
    let (db, t) = match name.rfind('.') {
        Some(i) => (name[..=i].to_string(), &name[i + 1..]),
        None => (String::new(), name),
    };
    let quoted = t.starts_with('`');
    (db, t.trim_matches('`').to_string(), quoted)
}

fn named(db: &str, t: &str, quoted: bool) -> String {
    if quoted {
        format!("{db}`{t}`")
    } else {
        format!("{db}{t}")
    }
}

pub fn statements_with(sql: &str, cluster: Option<&str>, split: &[String]) -> Vec<String> {
    let Some(c) = cluster else { return vec![sql.to_string()] };
    let words: Vec<&str> = sql.split_whitespace().take(8).collect();
    let up: Vec<String> = words.iter().map(|w| w.to_ascii_uppercase()).collect();
    let is = |i: usize, w: &str| up.get(i).is_some_and(|u| u == w);
    // the object's name position for CREATE TABLE [IF NOT EXISTS] and ALTER TABLE
    let at = if is(0, "CREATE") && is(1, "TABLE") {
        if is(2, "IF") { 5 } else { 2 }
    } else if is(0, "ALTER") && is(1, "TABLE") {
        2
    } else {
        return vec![on_cluster_with(sql, Some(c))];
    };
    let Some(raw) = words.get(at) else { return vec![on_cluster_with(sql, Some(c))] };
    let name = raw.split('(').next().unwrap_or(raw);
    let (db, t, quoted) = split_name(name);
    if !split.iter().any(|s| *s == t) {
        return vec![on_cluster_with(sql, Some(c))];
    }
    let local = named(&db, &format!("{t}_local"), quoted);
    let full = named(&db, &t, quoted);
    let db_arg = if db.is_empty() { "currentDatabase()".to_string() } else { format!("'{}'", db.trim_end_matches('.').trim_matches('`')) };
    let key = shard_key(&t);
    let distributed = |source: &str| format!("CREATE TABLE IF NOT EXISTS {full} ON CLUSTER `{c}` AS {source} ENGINE = Distributed(`{c}`, {db_arg}, '{t}_local', {key})");
    // the name in the statement, swapped for the local table's
    let pos = sql.find(name).unwrap_or(0);
    let to_local = format!("{}{local}{}", &sql[..pos], &sql[pos + name.len()..]);
    if up[0] == "CREATE" {
        // a copy of another split table (a tenant's tables: CREATE TABLE db.t AS ndr.t)
        if let Some(i) = up.iter().position(|w| w == "AS") {
            if let Some(src) = words.get(i + 1) {
                let (sdb, st, sq) = split_name(src);
                if st == t {
                    let src_local = named(&sdb, &format!("{t}_local"), sq);
                    let clone = to_local.replacen(src, &src_local, 1);
                    return vec![on_cluster_with(&clone, Some(c)), distributed(&local)];
                }
            }
        }
        return vec![on_cluster_path(&to_local, Some(c), None), distributed(&local)];
    }
    // ALTER: retention, indexes and projections only on the local table; columns on both
    let action = up.get(at + 1).map(String::as_str).unwrap_or("");
    let what = up.get(at + 2).map(String::as_str).unwrap_or("");
    let ttl = what == "TTL";
    let storage_only = ["INDEX", "PROJECTION", "CONSTRAINT", "SETTING", "ORDER", "SAMPLE"].contains(&what) || action == "MATERIALIZE";
    if (action == "MODIFY" || action == "REMOVE") && (ttl || action == "REMOVE") || storage_only {
        vec![on_cluster_with(&to_local, Some(c))]
    } else if ["ADD", "DROP", "MODIFY", "RENAME", "COMMENT", "CLEAR"].contains(&action) {
        vec![on_cluster_with(&to_local, Some(c)), on_cluster_with(sql, Some(c))]
    } else {
        // a data mutation on the Distributed table is refused by ClickHouse: it goes to the local tables
        vec![format!("{} ON CLUSTER `{c}`{}", &to_local[..pos + local.len()], &to_local[pos + local.len()..])]
    }
}

/// One init.sql statement for a client's own database (`ndr_<client>`): the database name, the copy
/// paths in ZooKeeper / Keeper (per shard and on all servers: a copy path shared with `ndr`'s table
/// is refused as "replica already exists"), a split table's Distributed database, and the client as
/// the default tenant. The NDR engine and the sign-in service both make client databases this way.
pub fn for_tenant(stmt: &str, db: &str, tenant_id: &str) -> String {
    stmt.replace("ndr.", &format!("{db}."))
        .replace("/clickhouse/tables/{shard}/ndr/", &format!("/clickhouse/tables/{{shard}}/{db}/"))
        .replace("/clickhouse/tables/all/ndr/", &format!("/clickhouse/tables/all/{db}/"))
        .replace("Distributed(ndr_cluster, ndr, ", &format!("Distributed(ndr_cluster, {db}, "))
        .replace("DEFAULT 'default'", &format!("DEFAULT '{tenant_id}'"))
}

#[cfg(test)]
mod tenant_tests {
    use super::for_tenant;

    #[test]
    fn a_clients_tables_have_their_own_copy_paths_and_names() {
        let s = for_tenant(
            "CREATE TABLE IF NOT EXISTS ndr.settings ON CLUSTER ndr_cluster (key String, tenant_id String DEFAULT 'default') ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/all/ndr/settings', '{replica}') ORDER BY key",
            "ndr_acme",
            "acme",
        );
        assert!(s.contains("ndr_acme.settings") && s.contains("'/clickhouse/tables/all/ndr_acme/settings'") && s.contains("DEFAULT 'acme'"), "{s}");
        let s = for_tenant("CREATE TABLE IF NOT EXISTS ndr.ndr_hits ON CLUSTER ndr_cluster AS ndr.ndr_hits_local ENGINE = Distributed(ndr_cluster, ndr, ndr_hits_local, rand())", "ndr_acme", "acme");
        assert_eq!(s, "CREATE TABLE IF NOT EXISTS ndr_acme.ndr_hits ON CLUSTER ndr_cluster AS ndr_acme.ndr_hits_local ENGINE = Distributed(ndr_cluster, ndr_acme, ndr_hits_local, rand())");
        let s = for_tenant("ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/ndr/ndr_events_local', '{replica}')", "ndr_acme", "acme");
        assert!(s.contains("'/clickhouse/tables/{shard}/ndr_acme/ndr_events_local'"));
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;

    fn s(sql: &str) -> Vec<String> {
        statements_with(sql, Some("lake"), &["siem_alerts".to_string(), "siem_events".to_string()])
    }

    #[test]
    fn a_split_table_is_a_local_copied_table_and_a_distributed_one_under_the_old_name() {
        assert_eq!(
            s("CREATE TABLE IF NOT EXISTS siem_alerts (id String, timestamp UInt64) ENGINE = MergeTree() ORDER BY timestamp"),
            [
                "CREATE TABLE IF NOT EXISTS siem_alerts_local ON CLUSTER `lake` (id String, timestamp UInt64) ENGINE = ReplicatedMergeTree() ORDER BY timestamp",
                "CREATE TABLE IF NOT EXISTS siem_alerts ON CLUSTER `lake` AS siem_alerts_local ENGINE = Distributed(`lake`, currentDatabase(), 'siem_alerts_local', rand())",
            ]
        );
    }

    #[test]
    fn a_tenant_copy_clones_the_local_table() {
        assert_eq!(
            s("CREATE TABLE IF NOT EXISTS `ndr_acme`.`siem_events` AS `ndr`.`siem_events`"),
            [
                "CREATE TABLE IF NOT EXISTS `ndr_acme`.`siem_events_local` ON CLUSTER `lake` AS `ndr`.`siem_events_local`",
                "CREATE TABLE IF NOT EXISTS `ndr_acme`.`siem_events` ON CLUSTER `lake` AS `ndr_acme`.`siem_events_local` ENGINE = Distributed(`lake`, 'ndr_acme', 'siem_events_local', rand())",
            ]
        );
    }

    #[test]
    fn retention_goes_to_the_local_table_and_columns_to_both() {
        assert_eq!(
            s("ALTER TABLE `ndr`.`siem_events` MODIFY TTL toDateTime(intDiv(timestamp, 1000)) + toIntervalDay(90)"),
            ["ALTER TABLE `ndr`.`siem_events_local` ON CLUSTER `lake` MODIFY TTL toDateTime(intDiv(timestamp, 1000)) + toIntervalDay(90)"]
        );
        assert_eq!(s("ALTER TABLE `ndr`.`siem_events` REMOVE TTL"), ["ALTER TABLE `ndr`.`siem_events_local` ON CLUSTER `lake` REMOVE TTL"]);
        assert_eq!(
            s("ALTER TABLE siem_alerts ADD COLUMN IF NOT EXISTS alert_json String DEFAULT ''"),
            [
                "ALTER TABLE siem_alerts_local ON CLUSTER `lake` ADD COLUMN IF NOT EXISTS alert_json String DEFAULT ''",
                "ALTER TABLE siem_alerts ON CLUSTER `lake` ADD COLUMN IF NOT EXISTS alert_json String DEFAULT ''",
            ]
        );
    }

    #[test]
    fn ndr_hits_keeps_one_hits_versions_on_one_shard_and_indexes_go_to_the_local_table() {
        let v = statements_with("CREATE TABLE IF NOT EXISTS `ndr_acme`.`ndr_hits` AS `ndr`.`ndr_hits`", Some("lake"), &["ndr_hits".to_string()]);
        assert!(v[1].ends_with("Distributed(`lake`, 'ndr_acme', 'ndr_hits_local', cityHash64(tenant_id, community_id))"), "{}", v[1]);
        let v = statements_with("ALTER TABLE ndr.ndr_events ADD INDEX IF NOT EXISTS idx_sensor_id sensor_id TYPE bloom_filter GRANULARITY 1", Some("lake"), &["ndr_events".to_string()]);
        assert_eq!(v, ["ALTER TABLE ndr.ndr_events_local ON CLUSTER `lake` ADD INDEX IF NOT EXISTS idx_sensor_id sensor_id TYPE bloom_filter GRANULARITY 1"]);
        let v = statements_with("ALTER TABLE ndr.ndr_events ADD PROJECTION IF NOT EXISTS p (SELECT * ORDER BY sensor_id)", Some("lake"), &["ndr_events".to_string()]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn other_tables_and_no_cluster_are_as_before() {
        assert_eq!(s("CREATE TABLE IF NOT EXISTS soar_cases (id String) ENGINE = MergeTree ORDER BY id"), ["CREATE TABLE IF NOT EXISTS soar_cases ON CLUSTER `lake` (id String) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{uuid}/all', '{replica}') ORDER BY id"]);
        assert_eq!(statements_with("CREATE TABLE IF NOT EXISTS siem_alerts (id String) ENGINE = MergeTree ORDER BY id", None, &["siem_alerts".into()]).len(), 1);
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
            "CREATE TABLE IF NOT EXISTS siem_x ON CLUSTER `ndr_cluster` (id String, version UInt64) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{uuid}/all', '{replica}', version) ORDER BY id"
        );
        assert_eq!(
            on_cluster_with("create table if not exists `ndr_acme`.soar(id String) ENGINE=MergeTree ORDER BY id", C),
            "create table if not exists `ndr_acme`.soar ON CLUSTER `ndr_cluster`(id String) ENGINE=ReplicatedMergeTree('/clickhouse/tables/{uuid}/all', '{replica}') ORDER BY id"
        );
        assert_eq!(on_cluster_with("\n  CREATE TABLE IF NOT EXISTS m (x UInt8) ENGINE = Memory", C), "\n  CREATE TABLE IF NOT EXISTS m ON CLUSTER `ndr_cluster` (x UInt8) ENGINE = Memory");
        // "engine" inside a name or a column is not the ENGINE clause (found in the cluster test)
        assert_eq!(
            on_cluster_with("CREATE TABLE IF NOT EXISTS siem_engine_docs (id String, engine_name String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id", C),
            "CREATE TABLE IF NOT EXISTS siem_engine_docs ON CLUSTER `ndr_cluster` (id String, engine_name String, version UInt64) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{uuid}/all', '{replica}', version) ORDER BY id"
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
