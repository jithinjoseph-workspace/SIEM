//! Inventory bookkeeping (`queue/vd/inventory`): what was reported per agent, so later scans can
//! report solved CVEs and delete documents.

use crate::event::{Component, Ctx};
use crate::json::{compact, Error, Res};
use crate::kvstore::KvStore;
use crate::scan::Core;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const COL_PACKAGE: &str = "package";
pub const COL_OS: &str = "os";
pub const COL_INITIAL: &str = "os_initial_scan";

pub fn open(dir: &std::path::Path) -> Result<KvStore, String> {
    let s = KvStore::open(dir)?;
    for c in [COL_OS, COL_PACKAGE, COL_INITIAL] {
        if !s.has_column(c) {
            s.create_column(c)?;
        }
    }
    Ok(s)
}

/// Comma-separated list; a trailing empty piece is dropped, inner empty pieces are kept.
pub fn split_list(s: &str) -> Vec<String> {
    let mut v: Vec<String> = s.split(',').map(str::to_string).collect();
    if v.last().is_some_and(String::is_empty) {
        v.pop();
    }
    v
}

fn now_ms() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn element(op: &str, id: String) -> Value {
    json!({"operation": op, "id": id})
}

impl Core {
    fn node_prefix(&self, agent: &str) -> String {
        if self.settings.cluster_enabled && agent == "000" {
            format!("{}_", self.settings.node_name)
        } else {
            String::new()
        }
    }

    fn package_key(&self, ctx: &Ctx) -> Res<String> {
        match ctx.component {
            Component::Package => Ok(format!("{}{}_{}", self.node_prefix(&ctx.agent.id), ctx.agent.id, ctx.field("item_id")?)),
            _ => Err("Invalid affected component type for inventory key.".into()),
        }
    }

    fn get_list(&self, col: &str, key: &str) -> Res<Option<Vec<String>>> {
        Ok(self.inventory.get_text(col, key)?.map(|v| split_list(&v)))
    }

    /// Publishes one deletion through the document sink.
    /// Publishes one deletion through the element publisher (one key line each).
    fn publish_deletion(&mut self, id: String, op: &str, no_index: bool) {
        vs!(self.log, Debug2, "Processing and publish key: {id}");
        self.sink.publish(&compact(&json!({"id": id, "no-index": no_index, "operation": op})));
    }

    /// 12.1: new CVEs are prepended; CVEs no longer found are not removed.
    pub(crate) fn inventory_insert(&mut self, ctx: &mut Ctx) -> Res<()> {
        let key = self.package_key(ctx)?;
        let found: Vec<String> = ctx.elements.keys().cloned().collect();
        for c in &found {
            ctx.elements.insert(c.clone(), element("INSERTED", format!("{key}_{c}")));
        }
        match self.inventory.get_text(COL_PACKAGE, &key)? {
            Some(old) => {
                let known: BTreeSet<String> = split_list(&old).into_iter().collect();
                let new: Vec<&String> = found.iter().filter(|c| !known.contains(*c)).collect();
                if !new.is_empty() {
                    let list = format!("{},{old}", new.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","));
                    vs!(self.log, Debug2, "Updating agent package key: {key} -> {list}");
                    self.inventory.put_text(COL_PACKAGE, &key, &list)?;
                }
            }
            None => {
                let list = found.join(",");
                vs!(self.log, Debug2, "Inserting agent package key: {key} -> {list}");
                self.inventory.put_text(COL_PACKAGE, &key, &list)?;
            }
        }
        Ok(())
    }

    /// 12.2
    pub(crate) fn inventory_delete(&mut self, ctx: &mut Ctx) -> Res<()> {
        let key = self.package_key(ctx)?;
        if let Some(list) = self.get_list(COL_PACKAGE, &key)? {
            for c in list {
                let id = format!("{key}_{c}");
                ctx.elements.entry(c).or_insert_with(|| element("DELETED", id));
            }
            vs!(self.log, Debug2, "Deleting package agent key: {key}");
            self.inventory.delete(COL_PACKAGE, key.as_bytes())?;
        }
        Ok(())
    }

    /// 12.3: false ("stop") when nothing changed.
    pub(crate) fn inventory_os_sync(&mut self, ctx: &mut Ctx) -> Res<bool> {
        if ctx.component != Component::Os {
            return Err("Invalid affected type for inventory sync.".into());
        }
        let agent = ctx.agent.id.clone();
        let key = format!("{}{agent}_{}_{}", self.node_prefix(&agent), ctx.os.name, ctx.os.version);
        for (k, v) in self.inventory.prefix(COL_OS, format!("{agent}_").as_bytes())? {
            let k = String::from_utf8_lossy(&k).into_owned();
            if k == key {
                continue;
            }
            vs!(self.log, Debug2, "Deleting agent element key: {k}");
            for c in split_list(&String::from_utf8_lossy(&v)) {
                self.publish_deletion(format!("{k}_{c}"), "DELETED", ctx.no_index);
            }
            self.inventory.delete(COL_OS, k.as_bytes())?;
        }
        // An existing but empty stored value counts as no list.
        let old = self.get_list(COL_OS, &key)?.filter(|l| !l.is_empty());
        let mut list = old.clone().unwrap_or_default();
        let found: BTreeSet<String> = ctx.elements.keys().cloned().collect();
        for c in &found {
            if list.contains(c) {
                ctx.elements.remove(c);
            } else {
                ctx.elements.insert(c.clone(), element("INSERTED", format!("{key}_{c}")));
                list.push(c.clone());
            }
        }
        list.retain(|c| {
            if found.contains(c) {
                return true;
            }
            let id = format!("{key}_{c}");
            vs!(self.log, Debug2, "Removing element from inventory: {id}");
            ctx.elements.insert(c.clone(), element("DELETED", id));
            false
        });
        ctx.first_os_scan = self.inventory.get_text(COL_INITIAL, &agent)?.is_none();
        if ctx.first_os_scan {
            self.inventory.put_text(COL_INITIAL, &agent, &now_ms())?;
        }
        if list.is_empty() {
            if old.is_some() {
                vs!(self.log, Debug2, "Deleting agent element key: {key}");
                self.inventory.delete(COL_OS, key.as_bytes())?;
            }
            return Ok(true);
        }
        list.sort();
        let mut before = old.unwrap_or_default();
        before.sort();
        if list != before {
            let text = list.join(",");
            self.inventory.put_text(COL_OS, &key, &text)?;
            vs!(self.log, Debug2, "Updating/Inserting agent element key: {key} -> {text}");
            Ok(true)
        } else {
            vs!(self.log, Debug2, "No changes in agent element key: {key}");
            Ok(false)
        }
    }

    /// 12.4: CVEs solved by a hotfix leave the package lists of the agent (not the OS lists).
    pub(crate) fn inventory_hotfix_solved(&mut self, ctx: &mut Ctx) -> Res<()> {
        let agent = ctx.agent.id.clone();
        for (k, v) in self.inventory.prefix(COL_PACKAGE, format!("{agent}_").as_bytes())? {
            let k = String::from_utf8_lossy(&k).into_owned();
            let mut list = split_list(&String::from_utf8_lossy(&v));
            let before = list.len();
            // The hotfix's CVEs in sorted order, one line per removed occurrence.
            let cves: Vec<String> = ctx.elements.keys().cloned().collect();
            for c in cves {
                while let Some(pos) = list.iter().position(|x| *x == c) {
                    list.remove(pos);
                    let id = format!("{k}_{c}");
                    vs!(self.log, Debug2, "CVE '{c}' was remediated by hotfix '{}' for '{id}'.", ctx.hotfix);
                    if let Some(Value::Array(dels)) = ctx.elements.get_mut(&c) {
                        dels.push(element("DELETED", id));
                    }
                }
            }
            if list.is_empty() {
                vs!(self.log, Debug2, "Deleting agent element key: {k}");
                self.inventory.delete(COL_PACKAGE, k.as_bytes())?;
            } else if list.len() != before {
                let text = list.join(",");
                self.inventory.put_text(COL_PACKAGE, &k, &text)?;
                vs!(self.log, Debug2, "Updating agent element key: {k} -> {text}");
            }
        }
        Ok(())
    }

    /// 12.5
    pub(crate) fn cleanup_all(&mut self, ctx: &Ctx) -> Res<()> {
        for col in [COL_OS, COL_PACKAGE] {
            let rows = self.inventory.prefix(col, b"")?;
            for (k, v) in &rows {
                let k = String::from_utf8_lossy(k).into_owned();
                for c in split_list(&String::from_utf8_lossy(v)) {
                    self.publish_deletion(format!("{k}_{c}"), "DELETED", ctx.no_index);
                }
                vs!(self.log, Debug2, "Deleting all entries for key prefix: {k}");
            }
            for (k, _) in rows {
                self.inventory.delete(col, &k)?;
            }
        }
        for k in self.inventory.keys_text(COL_INITIAL, "")? {
            self.inventory.delete(COL_INITIAL, k.as_bytes())?;
        }
        Ok(())
    }


    /// Integrity clear of one component: only that component's keys and documents go, then the
    /// clear alert is sent once (no delete-by-query).
    pub(crate) fn integrity_clear(&mut self, ctx: &Ctx) -> Res<()> {
        let agent = ctx.agent.id.clone();
        let prefix = format!("{}{agent}_", self.node_prefix(&agent));
        let col = match ctx.component {
            Component::Package => COL_PACKAGE,
            Component::Os => COL_OS,
            _ => return Err(Error::Other("Unknown inventory column".into())),
        };
        for (k, v) in self.inventory.prefix(col, prefix.as_bytes())? {
            let k = String::from_utf8_lossy(&k).into_owned();
            for c in split_list(&String::from_utf8_lossy(&v)) {
                self.publish_deletion(format!("{k}_{c}"), "DELETED", ctx.no_index);
            }
            vs!(self.log, Debug2, "Deleting {col} agent vulnerabilities key: {k}");
            self.inventory.delete(col, k.as_bytes())?;
        }
        if ctx.component == Component::Os {
            self.inventory.delete(COL_INITIAL, agent.as_bytes())?;
        }
        self.send_clear_alert(ctx);
        Ok(())
    }
    /// 12.6
    pub(crate) fn cleanup_agent(&mut self, ctx: &Ctx, component: Component) -> Res<()> {
        self.cleanup_agent_id(&ctx.agent.id, component, ctx.no_index)
    }

    pub(crate) fn cleanup_agent_id(&mut self, agent: &str, component: Component, no_index: bool) -> Res<()> {
        let prefix = format!("{}{agent}_", self.node_prefix(agent));
        let cols: &[&str] = match component {
            Component::Agent => &[COL_OS, COL_PACKAGE],
            Component::Package => &[COL_PACKAGE],
            Component::Os => &[COL_OS],
            _ => return Err(Error::Other("Unknown inventory column".into())),
        };
        for col in cols {
            for k in self.inventory.keys_text(col, &prefix)? {
                vs!(self.log, Debug2, "Deleting {col} agent vulnerabilities key: {k}");
                self.inventory.delete(col, k.as_bytes())?;
            }
        }
        self.publish_deletion(agent.to_string(), "DELETED_BY_QUERY", no_index);
        if matches!(component, Component::Os | Component::Agent) {
            self.inventory.delete(COL_INITIAL, agent.as_bytes())?;
        }
        Ok(())
    }

    /// The agent's reported (column, inventory key, CVE) triples.
    pub(crate) fn agent_pairs(&self, agent: &str) -> Res<BTreeSet<(String, String, String)>> {
        let prefix = format!("{}{agent}_", self.node_prefix(agent));
        let mut out = BTreeSet::new();
        for col in [COL_PACKAGE, COL_OS] {
            for (k, v) in self.inventory.prefix(col, prefix.as_bytes())? {
                let k = String::from_utf8_lossy(&k).into_owned();
                for c in split_list(&String::from_utf8_lossy(&v)) {
                    out.insert((col.to_string(), k.clone(), c));
                }
            }
        }
        Ok(out)
    }

    /// Agent ids that have anything in the inventory.
    pub(crate) fn inventory_agents(&self) -> Res<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        for col in [COL_PACKAGE, COL_OS] {
            for k in self.inventory.keys_text(col, "")? {
                out.insert(k.split('_').next().unwrap_or("").to_string());
            }
        }
        out.extend(self.inventory.keys_text(COL_INITIAL, "")?);
        Ok(out)
    }

    pub(crate) fn os_key(&self, ctx: &Ctx) -> String {
        format!("{}{}_{}_{}", self.node_prefix(&ctx.agent.id), ctx.agent.id, ctx.os.name, ctx.os.version)
    }

    pub(crate) fn package_key_of(&self, ctx: &Ctx) -> Res<String> {
        self.package_key(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_split() {
        assert_eq!(split_list("a,b,"), vec!["a", "b"]);
        assert!(split_list("").is_empty());
        assert_eq!(split_list("a,,b"), vec!["a", "", "b"]);
    }
}
