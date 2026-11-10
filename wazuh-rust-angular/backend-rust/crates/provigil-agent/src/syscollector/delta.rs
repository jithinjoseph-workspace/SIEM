//! The inventory as tables of items, each with a hash, and what changed since the last send.
//!
//! Every item carries its hash in `_h` (40 hex): the manager keeps it as the row's checksum, and
//! compares each table's count and [`table_hash`] with what its rows give. A `system_inventory_delta`
//! event has per table `count` and `hash`, and the `added`, `changed` (`_was`: the hash it replaces)
//! and `removed` (hashes) that are not empty. A table that could not be read is left out, so its
//! rows at the manager stay. Figures that change all the time are not in the hash: an item goes
//! out for a real change, and the manager shows those figures as they last came.

use std::collections::{BTreeMap, HashMap};

use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// (table, its list in the inventory, the fields that tell its items apart, what the hash leaves
/// out). The fields are no finer than what keeps two rows of the manager's table apart.
const LISTS: [(&str, &str, &[&str], &[&str]); 8] = [
    ("packages", "packages", &["name", "version", "architecture", "format", "location"], &[]),
    ("ports", "ports", &["protocol", "local_ip", "local_port", "pid"], &[]),
    ("processes", "processes", &["pid"], &["memory_mb", "cpu_time_ms", "virtual_kb", "threads"]),
    ("services", "services", &["name"], &[]),
    ("users", "users", &["name"], &[]),
    ("groups", "groups", &["name"], &[]),
    ("network", "network_interfaces", &["name"], &["rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"]),
    ("browser_extensions", "browser_extensions", &["browser", "user", "profile", "id"], &[]),
];
const HARDWARE_VOLATILE: [&str; 2] = ["ram_free_kb", "ram_usage_percent"];

/// One table's items: key -> (hash, the item with its `_h`).
pub struct Table {
    pub name: &'static str,
    pub items: BTreeMap<String, (String, Value)>,
}

impl Table {
    pub fn hash(&self) -> String {
        table_hash(self.items.values().map(|(h, _)| h.clone()).collect())
    }
}

/// SHA-256 of the text, the first 20 bytes in hex (what the manager's `checksum` gives).
pub fn short_hash(text: &str) -> String {
    Sha256::digest(text.as_bytes())[..20].iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash of a table: of its items' hashes in sorted order.
pub fn table_hash(mut hashes: Vec<String>) -> String {
    hashes.sort();
    short_hash(&hashes.join("\u{1}"))
}

fn with_hash(mut item: Value, volatile: &[&str]) -> (String, Value) {
    let mut stable = item.clone();
    if let Some(o) = stable.as_object_mut() {
        volatile.iter().for_each(|k| {
            o.remove(*k);
        });
    }
    let hash = short_hash(&stable.to_string());
    item["_h"] = json!(hash);
    (hash, item)
}

/// The tables of one scan; `inv` is the inventory as JSON. Items with the same key count once.
pub fn tables(inv: &Value, os_info: &Value, hotfixes: &[String]) -> Vec<Table> {
    let failed = |part: &str| inv["errors"].as_array().is_some_and(|e| e.iter().filter_map(Value::as_str).any(|e| e.starts_with(&format!("{part}: "))));
    let one = |name: &'static str, item: (String, Value)| Table { name, items: BTreeMap::from([(name.to_string(), item)]) };
    let mut out = Vec::new();
    for (name, list, keys, volatile) in LISTS {
        if failed(list) {
            continue;
        }
        let items = inv[list].as_array().into_iter().flatten().filter(|v| !v[keys[0]].is_null() && v[keys[0]] != "");
        let items = items.map(|v| (keys.iter().map(|k| v[*k].to_string()).collect::<Vec<_>>().join("|"), with_hash(v.clone(), volatile)));
        out.push(Table { name, items: items.collect() });
    }
    if inv["hardware"].is_object() && !failed("hardware") {
        out.push(one("hardware", with_hash(inv["hardware"].clone(), &HARDWARE_VOLATILE)));
    }
    // without the OS name the update list is not known either, and no updates would mean false findings
    if os_info["os_name"].as_str().is_some_and(|n| !n.is_empty()) {
        out.push(one("os", with_hash(os_info.clone(), &[])));
        let items = hotfixes.iter().map(|h| (h.clone(), (short_hash(h), json!({ "hotfix": h, "_h": short_hash(h) }))));
        out.push(Table { name: "hotfixes", items: items.collect() });
    }
    out
}

/// A full send's lists: each item once, with its `_h` (the update list stays plain: the manager
/// gets to the same hash from the text).
pub fn mark_full(tables: &[Table], inv: &mut Value, os_info: &mut Value) {
    for t in tables {
        let first = t.items.values().next().map(|(_, v)| v.clone());
        match t.name {
            "hardware" => inv["hardware"] = first.unwrap_or_default(),
            "os" => *os_info = first.unwrap_or_default(),
            "hotfixes" => {}
            name => {
                let (_, list, ..) = LISTS.iter().find(|l| l.0 == name).expect("a list table");
                inv[*list] = t.items.values().map(|(_, v)| v.clone()).collect();
            }
        }
    }
}

/// The `tables` of a delta event, and how many items changed.
pub fn changes(tables: &[Table], saved: &HashMap<String, HashMap<String, String>>) -> (Value, usize) {
    let (mut out, mut n, none) = (json!({}), 0, HashMap::new());
    for t in tables {
        let last = saved.get(t.name).unwrap_or(&none);
        let (mut added, mut changed) = (Vec::new(), Vec::new());
        for (key, (hash, item)) in &t.items {
            match last.get(key) {
                None => added.push(item.clone()),
                Some(old) if old != hash => {
                    let mut item = item.clone();
                    item["_was"] = json!(old);
                    changed.push(item);
                }
                Some(_) => {}
            }
        }
        let removed: Vec<&String> = last.iter().filter(|(k, _)| !t.items.contains_key(*k)).map(|(_, h)| h).collect();
        n += added.len() + changed.len() + removed.len();
        let mut part = json!({ "count": t.items.len(), "hash": t.hash() });
        for (k, v) in [("added", json!(added)), ("changed", json!(changed)), ("removed", json!(removed))] {
            if v.as_array().is_some_and(|a| !a.is_empty()) {
                part[k] = v;
            }
        }
        out[t.name] = part;
    }
    (out, n)
}

/// The `system_inventory_delta` event.
pub fn event(agent: (&str, &str), tables: Value, changed: usize) -> Value {
    json!({
        "event_type": "system_inventory_delta",
        "timestamp": Utc::now().to_rfc3339(),
        "agent": { "id": agent.0, "name": agent.1 },
        "location": "syscollector/inventory",
        "message": format!("syscollector: System inventory changes: {changed} item(s)."),
        "tables": tables,
    })
}
