//! Event processing and the scan procedures. Everything here runs under the feed lock (the
//! `Core` mutex), so events never run in parallel with each other or with a feed update.

use crate::agentdb::{self, AgentDb, DbError};
use crate::cpe::{is_cpe, Cpe};
use crate::event::{Agent, Component, Cond, Ctx, Event, EventType, OsData, Origin, OS_FIELDS};
use crate::feed::FeedDb;
use crate::json::{key_missing, opt_text, req_text, s, wrong_type, Error, Res};
use crate::kvstore::KvStore;
use crate::legacy_names::AGENT_VERSION_STRIP;
use crate::log::Log;
use crate::lru::Lru;
use crate::queue::DurableQueue;
use crate::report::ReportSink;
use crate::sink::DocSink;
use crate::version::{compare_installed, parse_installed, Kind};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const L1_SIZE: usize = 2048;

/// Translated packages: (product, vendor, version).
pub type Translated = Vec<(String, String, String)>;

/// Which first-level translation cache a scan uses.
#[derive(Clone, Copy)]
pub enum L1 {
    Events = 0,
    RescanAll = 1,
    RescanOne = 2,
}

pub struct Settings {
    pub manager_name: String,
    pub cluster_enabled: bool,
    pub cluster_name: String,
    pub node_name: String,
    pub manager_disabled_scan: bool,
    pub translation_cap: usize,
}

pub struct Core {
    pub log: Log,
    pub feed: FeedDb,
    pub inventory: KvStore,
    pub agent_db: Arc<dyn AgentDb>,
    pub os_cache: Lru<String, OsData>,
    pub hotfix_cache: Lru<String, BTreeSet<String>>,
    pub l1: [Lru<String, Translated>; 3],
    pub sink: DocSink,
    pub reports: Arc<dyn ReportSink>,
    pub delayed: Arc<DurableQueue>,
    /// The background re-scan job of all agents: one entry per agent (`queue/vd/rescan`).
    pub job: Arc<DurableQueue>,
    /// Alerts a re-scan would send, by (inventory key, CVE); set only while re-scanning an agent.
    pub collect: Option<BTreeMap<(String, String), Value>>,
    pub settings: Settings,
}

/// Agent versions of the agent list lose their leading characters found in the strip set.
fn strip_version(v: &str) -> String {
    v.trim_start_matches(|c| AGENT_VERSION_STRIP.contains(c)).to_string()
}

fn not_ready(agent: &str) -> impl Fn(DbError) -> Error + '_ {
    move |e| match e {
        DbError::NotSynced => Error::NotReady { agent: agent.to_string(), text: agentdb::NOT_SYNCED_TEXT.into() },
        DbError::Failed(t) => Error::Other(t),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Subject {
    Package,
    Os,
}

impl Core {
    // ---- context ----------------------------------------------------------------------------

    /// Builds the scan context, with the side effects of 7.2 (OS data, hotfix cache).
    pub fn build_ctx(&mut self, ev: &Event) -> Res<Ctx> {
        let (ty, comp) = crate::event::classify(ev)?;
        let mut ctx = Ctx::new(ev, ty, comp)?;
        if ctx.agent.id == "000" {
            ctx.agent.name = self.settings.manager_name.clone();
        }
        let os_event = ty == EventType::Os && ev.origin != Origin::Json;
        let loads_os = ev.origin != Origin::Json
            && matches!(comp, Component::Package | Component::Hotfix)
            && !(ev.origin == Origin::Rsync && ty == EventType::IntegrityClear);
        if os_event {
            let mut os = OsData::from_row(ctx.row(), false)?;
            os.build_cpe(&self.feed.maps.oscpe);
            self.os_cache.insert(ctx.agent.id.clone(), os.clone());
            ctx.os = os;
        }
        if ty == EventType::HotfixInsert {
            // Only a text hotfix id goes into the cache.
            if let Some(kb) = ctx.row().get("hotfix").and_then(Value::as_str).filter(|k| !k.is_empty()).map(str::to_string) {
                let mut set = self.hotfix_cache.get(&ctx.agent.id).unwrap_or_default();
                set.insert(kb);
                self.hotfix_cache.insert(ctx.agent.id.clone(), set);
            }
        }
        if loads_os {
            ctx.os = self.load_os(&ctx.agent.id)?;
        }
        Ok(ctx)
    }

    fn load_os(&mut self, agent: &str) -> Res<OsData> {
        if let Some(os) = self.os_cache.get(&agent.to_string()) {
            return Ok(os);
        }
        let q = agentdb::q_osinfo(agent).map_err(not_ready(agent))?;
        let rows = self.agent_db.query(&q).map_err(|e| match e {
            DbError::NotSynced => Error::NotReady { agent: agent.into(), text: agentdb::NOT_SYNCED_TEXT.into() },
            DbError::Failed(t) => Error::Other(format!("Unable to retrieve OS data from provigil-db (agent {agent}). Reason: {t}")),
        })?;
        let Some(row) = rows.first() else {
            return Err(Error::NotReady { agent: agent.into(), text: "Empty OS data from provigil-db.".into() });
        };
        let mut os = OsData::from_row(row, true)?;
        os.build_cpe(&self.feed.maps.oscpe);
        self.os_cache.insert(agent.to_string(), os.clone());
        Ok(os)
    }

    // ---- one event (7.7) --------------------------------------------------------------------

    /// Processes one event. `delayed` is true when it comes from the delayed queue.
    pub fn process(&mut self, ev: &Event, delayed: bool) -> Res<()> {
        let mut ctx = self.build_ctx(ev)?;
        use EventType as T;
        let id = ctx.agent.id.clone();
        if !delayed && !matches!(ctx.ty, T::CleanupAll | T::RescanAll | T::CleanupOne) && self.delayed.count(&id) > 0 {
            vs!(self.log, Debug2, "Postponing event '{}' for agent '{id}'", ctx.ty as u8);
            self.delayed.push(&id, &ev.encode());
            vs!(self.log, Debug2, "Event type: {} processed", ctx.ty as u8);
            return Ok(());
        }
        match ctx.ty {
            T::HotfixInsert => {
                vs!(self.log, Debug2, "Processing 'HotfixInsert' event for agent '{id}'");
                self.hotfix_chain(&mut ctx)?;
            }
            T::PackageInsert => {
                vs!(self.log, Debug2, "Processing 'PackageInsert' event for agent '{id}'");
                self.package_insert(&mut ctx, L1::Events)?;
            }
            T::PackageDelete => {
                vs!(self.log, Debug2, "Processing 'PackageDelete' event for agent '{id}'");
                self.package_delete(&mut ctx)?;
            }
            T::Os => {
                vs!(self.log, Debug2, "Processing 'OS scan' event for agent '{id}'");
                self.os_chain(&mut ctx)?;
            }
            T::IntegrityClear => {
                vs!(self.log, Debug2, "Processing 'IntegrityClear' event for agent '{id}'");
                self.integrity_clear(&ctx)?;
            }
            T::RescanAll => {
                vs!(self.log, Debug2, "Re-scan all agents event received. Initiating re-scan for all agents");
                self.start_rescan_job(&ctx)?;
                self.delayed.clear(None);
            }
            T::RescanOne => {
                vs!(self.log, Debug2, "Processing 'ReScanSingleAgent' event for agent '{id}'");
                self.sink.begin_rescan(ctx.full);
                let r = self.rescan_one(&mut ctx);
                self.sink.end_rescan();
                r?;
                self.delayed.clear(Some(&id));
            }
            T::CleanupAll => {
                vs!(self.log, Debug2, "Clean-up all data event received. Cleaning up data for all agents");
                self.cleanup_all(&ctx)?;
                self.delayed.clear(None);
            }
            T::CleanupOne => {
                vs!(self.log, Debug2, "Processing 'CleanupSingleAgentData' event for agent '{id}'");
                self.cleanup_agent(&ctx, Component::Agent)?;
                self.delayed.clear(Some(&id));
            }
            T::GlobalSync => {
                vs!(self.log, Debug2, "Processing 'GlobalSyncInventory' event to synchronize inventory across nodes");
            }
            T::Unknown | T::HotfixDelete => return Ok(()),
        }
        vs!(self.log, Debug2, "Event type: {} processed", ctx.ty as u8);
        Ok(())
    }

    // ---- package insert / delete (9.2-9.7) --------------------------------------------------

    pub fn package_insert(&mut self, ctx: &mut Ctx, l1: L1) -> Res<()> {
        if !self.package_scan(ctx, l1)? {
            return Ok(());
        }
        self.inventory_insert(ctx)?;
        self.document_details(ctx)?;
        if self.collect.is_some() {
            self.collect_alerts(ctx, false)?;
        } else if ctx.origin == Origin::Delta {
            self.vuln_alerts(ctx, false)?;
        }
        self.send_alerts(ctx);
        self.publish_elements(ctx);
        Ok(())
    }

    fn package_delete(&mut self, ctx: &mut Ctx) -> Res<()> {
        self.inventory_delete(ctx)?;
        if ctx.origin == Origin::Delta {
            self.vuln_alerts(ctx, false)?;
        }
        self.send_alerts(ctx);
        self.publish_elements(ctx);
        Ok(())
    }

    /// The vendor map's CNA list: `None` when absent; a value that is not a list is an empty
    /// list. Elements are checked as they are used.
    fn vendor_list(&self, key: &str) -> Option<Vec<Value>> {
        self.feed.maps.vendor.get(key).map(|v| v.as_array().cloned().unwrap_or_default())
    }

    /// Chooses the CNA and scans the package; false ("stop") when no CVE was found.
    fn package_scan(&mut self, ctx: &mut Ctx, l1: L1) -> Res<bool> {
        let format = ctx.field("format").unwrap_or_default();
        let source = ctx.field("source").unwrap_or_default();
        let vendor = ctx.field("vendor").unwrap_or_default();
        let platform = ctx.os.platform.clone();
        let mut cna = self.feed.cna_by_format(&format);
        if cna.is_empty() {
            cna = self.feed.cna_by_source(&source);
        }
        if cna.is_empty() {
            cna = self.feed.cna_by_prefix(&vendor, &platform);
        }
        if cna.is_empty() {
            cna = self.feed.cna_by_contains(&vendor, &platform);
        }
        ctx.vuln_source = if cna.is_empty() { ("nvd".into(), "nvd".into()) } else { self.expand_cna(&cna, ctx)? };
        let expanded = ctx.vuln_source.1.clone();
        if expanded != "nvd" {
            self.scan_with(ctx, &expanded, l1);
        } else {
            match self.vendor_list("adp_default_array") {
                Some(list) => {
                    for x in list {
                        let c = x.as_str().ok_or_else(|| wrong_type("string", &x))?;
                        vs!(self.log, Debug2, "Using CNA '{c}' from CNA array.");
                        self.scan_with(ctx, c, l1);
                    }
                }
                None => {
                    vs!(self.log, Debug2, "No CNA array found, using default CNA 'nvd'.");
                    self.scan_with(ctx, "nvd", l1);
                }
            }
        }
        let name = ctx.field("name").unwrap_or_default();
        vs!(self.log, Debug, "Vulnerability scan for package '{name}' on Agent '{}' has completed.", ctx.agent.id);
        Ok(!ctx.elements.is_empty())
    }

    fn expand_cna(&self, cna: &str, ctx: &Ctx) -> Res<(String, String)> {
        let m = &self.feed.maps.cna_mapping;
        let mapping = m.get("cnaMapping").ok_or_else(|| key_missing("cnaMapping"))?;
        let Some(t) = mapping.get(cna) else { return Ok((cna.into(), cna.into())) };
        let t = t.as_str().ok_or_else(|| wrong_type("string", t))?;
        let pe = m.get("platformEquivalence").ok_or_else(|| key_missing("platformEquivalence"))?;
        let me = m.get("majorVersionEquivalence").ok_or_else(|| key_missing("majorVersionEquivalence"))?;
        let text = |v: &Value| -> Res<String> {
            v.as_str().map(str::to_string).ok_or_else(|| Error::Json { id: 303, text: format!("JSON value is not a text, actual type is {}", crate::json::type_name(v)) })
        };
        let platform = &ctx.os.platform;
        let p = match pe.get(platform) {
            Some(v) => text(v)?,
            None => platform.clone(),
        };
        let major = match me.get(platform).and_then(|x| x.get(&ctx.os.major)) {
            Some(v) => text(v)?,
            None => ctx.os.major.clone(),
        };
        Ok((cna.into(), t.replace("$(PLATFORM)", &p).replace("$(MAJOR_VERSION)", &major)))
    }

    /// Scans the package with one CNA (translations first). Errors end this CNA only.
    fn scan_with(&mut self, ctx: &mut Ctx, cna: &str, l1: L1) {
        let r = (|| -> Res<()> {
            let name = ctx.field("name")?;
            let vendor = ctx.field("vendor")?;
            let format = ctx.field("format")?;
            let version = ctx.field("version")?;
            let platform = ctx.os.platform.clone();
            let key = format!("{platform}_{vendor}_{name}");
            let cache = &mut self.l1[l1 as usize];
            let pkgs: Vec<(String, String, String)> = if let Some(list) = cache.get(&key) {
                vs!(self.log, Debug2, "Translation for package '{name}' in platform '{platform}' found in Level 1 cache.");
                list
            } else {
                let l2 = self.feed.translate(&name, &vendor, &platform);
                if !l2.is_empty() {
                    vs!(self.log, Debug2, "Translation for package '{name}' in platform '{platform}' found in Level 2 cache.");
                    self.l1[l1 as usize].insert(key, l2.clone());
                    l2
                } else {
                    vs!(self.log, Debug2, "Translation for package '{name}' in platform '{platform}' not found. Using provided packageName.");
                    vec![(name.to_ascii_lowercase(), vendor.to_ascii_lowercase(), String::new())]
                }
            };
            for (p, v, ver) in pkgs {
                let pick = |t: String, orig: &str| if t.is_empty() { orig.to_string() } else { t };
                let (p, v, ver) = (pick(p, &name), pick(v, &vendor), pick(ver, &version));
                self.scan_one(ctx, cna, &p, &v, &ver, &format)?;
            }
            Ok(())
        })();
        if let Err(e) = r {
            let name = ctx.field("name").unwrap_or_default();
            vs!(self.log, Warning, "Failed to scan package: '{name}', CVE Numbering Authorities (CNA): '{cna}', Error: '{e}'.");
        }
    }

    fn agent_text(ctx: &Ctx) -> String {
        format!("Agent '{}' (ID: '{}', Version: '{}')", ctx.agent.name, ctx.agent.id, ctx.agent.version)
    }

    fn scan_one(&mut self, ctx: &mut Ctx, cna: &str, name: &str, vendor: &str, version: &str, format: &str) -> Res<()> {
        vs!(
            self.log,
            Debug,
            "Initiating a vulnerability scan for package '{name}' ({format}) ({vendor}) with CVE Numbering Authorities (CNA) '{cna}' on Agent '{}' (ID: '{}', Version: '{}').",
            ctx.agent.name,
            ctx.agent.id,
            ctx.agent.version
        );
        let lists = self.feed.candidate_lists(cna, name)?;
        let os_cpe = Cpe::parse(&ctx.os.cpe_name);
        let kind = Kind::for_format(format);
        for list in lists {
            for cand in &list {
                let cve = s(cand, "cveId").to_string();
                if ctx.elements.contains_key(&cve) {
                    vs!(self.log, Debug, "CVE '{cve}' already found by a higher priority CNA. Skipping.");
                    break;
                }
                if let Some(platforms) = cand.get("platforms").and_then(Value::as_array) {
                    if !self.platform_ok(ctx, platforms, &os_cpe, name, version, &cve) {
                        continue;
                    }
                }
                if let Some(cv) = cand.get("vendor") {
                    let cv = cv.as_str().unwrap_or("");
                    if vendor.is_empty() || vendor == " " {
                        vs!(self.log, Debug2, "The vendor information is not available for Package: {name}, Version: {version}, CVE: {cve}, Content vendor: {cv}");
                        continue;
                    }
                    if cv != vendor {
                        vs!(self.log, Debug2, "The vendor is not the same for Package: {name}, Version: {version}, CVE: {cve}, Content vendor: {cv}, Package vendor: {vendor}");
                        continue;
                    }
                    vs!(self.log, Debug2, "Vendor match for Package: {name}, Version: {version}, CVE: {cve}, Vendor: {cv}");
                }
                let counted = (|| -> Res<bool> {
                    if !self.match_versions(ctx, Subject::Package, name, version, cand, kind)? {
                        return Ok(false);
                    }
                    ctx.detection.insert(cve.clone(), cna.to_string());
                    if ctx.os.platform == "windows" && self.remediated(ctx, &cve, name)? {
                        return Ok(false);
                    }
                    Ok(true)
                })();
                match counted {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(e) => vs!(self.log, Debug, "Failed to scan package: '{name}', CVE Numbering Authorities (CNA): '{cna}', Error: '{e}'"),
                }
            }
        }
        Ok(())
    }

    fn platform_ok(&self, ctx: &Ctx, platforms: &[Value], os_cpe: &Cpe, name: &str, version: &str, cve: &str) -> bool {
        // Non-text platforms count as ""; a CPE platform is never compared with the code name.
        for p in platforms.iter().map(|x| x.as_str().unwrap_or("")) {
            if is_cpe(p) {
                let c = Cpe::parse(p);
                if c.part() == "o" && c.matches(os_cpe) {
                    vs!(self.log, Debug2, "The platform is in the list based on CPE comparison for Package: {name}, Version: {version}, CVE: {cve}, Content platform CPE: {p} OS CPE: {}", ctx.os.cpe_name);
                    return true;
                }
                continue;
            }
            if p == ctx.os.codename {
                vs!(self.log, Debug2, "The platform is in the list based on OS code name comparison for Package: {name}, Version: {version}, CVE: {cve}, Content OS code name: {p}, OS code name: {}", ctx.os.codename);
                return true;
            }
        }
        vs!(self.log, Debug2, "The platform is not in the list for Package: {name}, Version: {version}, CVE: {cve}, OS CPE: {}, OS code name: {}", ctx.os.cpe_name, ctx.os.codename);
        false
    }

    /// Version ranges (9.5.1). Records the CVE and its condition on a match.
    fn match_versions(&self, ctx: &mut Ctx, subject: Subject, name: &str, installed: &str, cand: &Value, kind: Kind) -> Res<bool> {
        let cve = s(cand, "cveId").to_string();
        let (word, cap) = match subject {
            Subject::Package => ("package", "Package"),
            Subject::Os => ("OS", "OS"),
        };
        // The installed version is parsed once, before any range or default status; a parse
        // error ends this candidate, a text that simply does not parse is not an error here.
        let parsed = parse_installed(installed, kind, &self.log).map_err(Error::Other)?;
        let cmp = |b: &str| compare_installed(&parsed, installed, b, kind, &self.log).map_err(Error::Other);
        let agent = Self::agent_text(ctx);
        let mut found: Option<Cond> = None;
        for v in cand.get("versions").and_then(Value::as_array).into_iter().flatten() {
            let (ver, lt, lte, status) = (s(v, "version"), s(v, "lessThan"), s(v, "lessThanOrEqual"), s(v, "status"));
            vs!(self.log, Debug2, "Scanning {word} - '{name}' (Installed Version: {installed}, Security Vulnerability: {cve}). Identified vulnerability: Version: {ver}. Required Version Threshold: {lt}. Required Version Threshold (or Equal): {lte}.");
            if lt.is_empty() && lte.is_empty() {
                if cmp(ver)? == Ordering::Equal {
                    if status != "affected" {
                        return Ok(false);
                    }
                    vs!(self.log, Debug, "Match found, the {word} '{name}', is vulnerable to '{cve}'. Current version: '{installed}' is equal to '{ver}'. - {agent}.");
                    found = Some(Cond::Equal(ver.into()));
                    break;
                }
                continue;
            }
            let lower = ver == "0" || cmp(ver)? != Ordering::Less;
            let upper = lower
                && if !lt.is_empty() && lt != "*" {
                    cmp(lt)? == Ordering::Less
                } else if !lte.is_empty() {
                    cmp(lte)? != Ordering::Greater
                } else {
                    false
                };
            if lower && upper {
                if status != "affected" {
                    vs!(self.log, Debug2, "No match due to default status for {cap}: {name}, Version: {installed} while scanning for Vulnerability: {cve}, Installed Version: {ver}, Required Version Threshold: {lt}, Required Version Threshold (or Equal): {lte}");
                    return Ok(false);
                }
                vs!(self.log, Debug, "Match found, the {word} '{name}', is vulnerable to '{cve}'. Current version: '{installed}' (less than '{lt}' or equal to '{lte}'). - {agent}.");
                found = Some(if !lte.is_empty() { Cond::LessOrEqual(lte.into()) } else { Cond::LessThan(lt.into()) });
                break;
            }
        }
        let cond = match found {
            Some(c) => c,
            None if s(cand, "defaultStatus") == "affected" => {
                match subject {
                    Subject::Package => vs!(self.log, Debug, "Match found, the package '{name}' is vulnerable to '{cve}' due to default status. - {agent}."),
                    Subject::Os => vs!(self.log, Debug, "Match found for OS: {name} for vulnerability: {cve} due to default status."),
                }
                Cond::Default
            }
            None => {
                vs!(self.log, Debug2, "No match due to default status for {cap}: {name}, Version: {installed} while scanning for Vulnerability: {cve}");
                return Ok(false);
            }
        };
        ctx.elements.insert(cve.clone(), Value::Object(Map::new()));
        ctx.conditions.insert(cve, cond);
        Ok(true)
    }

    /// Windows hotfix remediation of a matched package CVE (9.6).
    fn remediated(&mut self, ctx: &mut Ctx, cve: &str, name: &str) -> Res<bool> {
        let updates = self.feed.remediation(cve)?.unwrap_or_default();
        if updates.is_empty() {
            return Ok(false);
        }
        let id = ctx.agent.id.clone();
        let hotfixes = match self.hotfix_cache.get(&id) {
            Some(h) => h,
            None => {
                let q = agentdb::q_hotfixes(&id).map_err(|e| Error::Other(e.text()))?;
                let rows = self.agent_db.query(&q).map_err(|e| match e {
                    DbError::NotSynced => Error::Other(agentdb::NOT_SYNCED_TEXT.into()),
                    DbError::Failed(t) => Error::Other(format!("Unable to retrieve remediation data from provigil-db (agent {id}). Reason: {t}")),
                })?;
                // Rows without a text hotfix are skipped.
                let set: BTreeSet<String> = rows.iter().filter_map(|r| r.get("hotfix").and_then(Value::as_str)).map(str::to_string).collect();
                if !set.is_empty() {
                    self.hotfix_cache.insert(id.clone(), set.clone());
                }
                set
            }
        };
        if hotfixes.is_empty() {
            vs!(self.log, Debug2, "No remediations for agent '{id}' have been found.");
            return Ok(false);
        }
        match updates.iter().find(|u| hotfixes.contains(*u)) {
            Some(kb) => {
                vs!(self.log, Debug2, "Remediation '{kb}' for package '{name}' on agent '{id}' that solves CVE '{cve}' has been found.");
                ctx.elements.remove(cve);
                ctx.conditions.remove(cve);
                Ok(true)
            }
            None => {
                vs!(self.log, Debug2, "No remediation for package '{name}' on agent '{id}' that solves CVE '{cve}' has been found.");
                Ok(false)
            }
        }
    }

    // ---- OS scan (9.8) ----------------------------------------------------------------------

    pub fn os_chain(&mut self, ctx: &mut Ctx) -> Res<()> {
        if !self.os_scan(ctx)? {
            return Ok(());
        }
        if !self.inventory_os_sync(ctx)? {
            return Ok(());
        }
        self.document_details(ctx)?;
        if self.collect.is_some() {
            self.collect_alerts(ctx, true)?;
        } else if !ctx.first_os_scan {
            self.vuln_alerts(ctx, true)?;
        }
        self.send_alerts(ctx);
        self.publish_elements(ctx);
        Ok(())
    }

    fn os_scan(&mut self, ctx: &mut Ctx) -> Res<bool> {
        let id = ctx.agent.id.clone();
        let mut hotfixes: Vec<String> = Vec::new();
        if ctx.os.platform == "windows" {
            let q = agentdb::q_hotfixes(&id).map_err(|e| Error::Other(e.text()))?;
            match self.agent_db.query(&q) {
                Ok(rows) => hotfixes = rows.iter().filter_map(|r| r.get("hotfix").and_then(Value::as_str)).map(str::to_string).collect(),
                Err(DbError::NotSynced) => return Err(Error::NotReady { agent: id, text: agentdb::NOT_SYNCED_TEXT.into() }),
                Err(DbError::Failed(t)) => {
                    vs!(self.log, Error, "Unable to retrieve hotfixes for agent {id}. Reason: {t}.");
                    return Ok(false);
                }
            }
        }
        let product = Cpe::parse(&ctx.os.cpe_name).product().to_string();
        let platform = ctx.os.platform.clone();
        if platform != "windows" && platform != "darwin" {
            vs!(self.log, Debug, "OS scan for platform '{platform}' on Agent '{id}' is not supported.");
            return Ok(false);
        }
        let shown = if product.is_empty() { ctx.os.name.clone() } else { product.clone() };
        if product.is_empty() {
            vs!(self.log, Debug, "No CPE product found for OS '{}' on Agent '{id}'.", ctx.os.name);
        } else {
            ctx.vuln_source = ("nvd".into(), "nvd".into());
            let r = (|| -> Res<()> {
                // A list that is not an array is empty; non-text entries read as empty names.
                let cnas: Vec<(String, bool)> = match self.vendor_list("adp_default_array") {
                    Some(a) => a.iter().map(|x| (x.as_str().unwrap_or("").to_string(), true)).collect(),
                    None => vec![("nvd".into(), false)],
                };
                let installed = ctx.os.version.clone();
                for (cna, from_list) in cnas {
                    // The CNA line comes right before the scan with that CNA.
                    if from_list {
                        vs!(self.log, Debug2, "Using CNA '{cna}' from CNA array for OS.");
                    } else {
                        vs!(self.log, Debug2, "No CNA array found for OS, using default CNA 'nvd'.");
                    }
                    for list in self.feed.candidate_lists(&cna, &product)? {
                        for cand in &list {
                            let cve = s(cand, "cveId").to_string();
                            if ctx.elements.contains_key(&cve) {
                                vs!(self.log, Debug, "CVE '{cve}' already found by a higher priority CNA. Skipping.");
                                break;
                            }
                            match self.match_versions(ctx, Subject::Os, &product, &installed, cand, Kind::Debian) {
                                Ok(true) => {
                                    ctx.detection.insert(cve, cna.clone());
                                    break;
                                }
                                Ok(false) => {}
                                Err(e) => vs!(self.log, Debug, "Failed to scan OS: '{product}', CVE Numbering Authorities (CNA): '{cna}', Error: '{e}'"),
                            }
                        }
                    }
                }
                if platform == "windows" {
                    let found: Vec<String> = ctx.elements.keys().cloned().collect();
                    for cve in found {
                        let updates = self.feed.remediation(&cve)?.unwrap_or_default();
                        if updates.is_empty() {
                            vs!(self.log, Debug2, "No remediation available for OS '{product}' on Agent '{id}' for CVE: '{cve}', discarding.");
                            ctx.elements.remove(&cve);
                        } else if let Some(kb) = updates.iter().find(|u| hotfixes.contains(u)) {
                            vs!(self.log, Debug2, "Remediation for OS '{product}' on Agent '{id}' has been found. CVE: '{cve}', Remediation: '{kb}'.");
                            ctx.elements.remove(&cve);
                            ctx.conditions.remove(&cve);
                            ctx.detection.remove(&cve);
                        }
                    }
                }
                Ok(())
            })();
            if let Err(e) = r {
                vs!(self.log, Warning, "Failed to scan OS: '{shown}', CVE Numbering Authorities (CNA): 'nvd', Error: '{e}'.");
            }
        }
        vs!(self.log, Debug, "Vulnerability scan for OS '{shown}' on Agent '{id}' has completed.");
        Ok(true)
    }

    // ---- hotfix insert (9.9) ----------------------------------------------------------------

    fn hotfix_chain(&mut self, ctx: &mut Ctx) -> Res<()> {
        let kb = ctx.field("hotfix")?;
        if kb.is_empty() {
            vs!(self.log, Debug2, "No hotfix installed");
            return Ok(());
        }
        vs!(self.log, Debug2, "Getting associated vulnerabilities for hotfix '{kb}'");
        let keys = self.feed.hotfix_keys_for(&kb)?;
        if keys.is_empty() {
            vs!(self.log, Debug2, "No vulnerabilities associated to hotfix '{kb}'");
            return Ok(());
        }
        for k in keys {
            // The CVE is the text after the hotfix id and its separator (prefix search, kept).
            let cve = k.get(kb.len() + 1..).unwrap_or("").to_string();
            ctx.elements.insert(cve, Value::Array(Vec::new()));
        }
        ctx.hotfix = kb;
        self.inventory_hotfix_solved(ctx)?;
        if ctx.origin == Origin::Delta {
            self.hotfix_alerts(ctx)?;
        }
        self.send_alerts(ctx);
        self.publish_arrays(ctx)
    }

    // ---- re-scans (9.12, with the background job and change alerts) ---------------------------

    /// The all-agents list; `None` when it could not be read (logged).
    fn all_agents(&mut self) -> Res<Option<Vec<Agent>>> {
        let rows = match self.agent_db.query(&agentdb::q_all_agents()) {
            Ok(r) => r,
            Err(DbError::NotSynced) => return Err(Error::NotReady { agent: "all".into(), text: agentdb::NOT_SYNCED_TEXT.into() }),
            Err(DbError::Failed(t)) => {
                vs!(self.log, Error, "Unable to retrieve global agents data. Reason: {t}.");
                return Ok(None);
            }
        };
        let mut agents = Vec::new();
        for row in &rows {
            let r = (|| -> Res<Option<Agent>> {
                let id = match row.get("id") {
                    None => return Err(key_missing("id")),
                    // Any JSON number; decimals are truncated.
                    Some(v) => v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)).ok_or_else(|| wrong_type("number", v))?,
                };
                if id == 0 && self.settings.manager_disabled_scan {
                    vs!(self.log, Debug2, "Skipping manager agent with id 0.");
                    return Ok(None);
                }
                let name = req_text(row, "name")?;
                let version = strip_version(&opt_text(row, "version")?);
                let ip = req_text(row, "ip")?;
                Ok(Some(Agent { id: format!("{id:03}"), ip, name, version }))
            })();
            match r {
                Ok(Some(a)) => agents.push(a),
                Ok(None) => {}
                Err(e) => vs!(self.log, Debug2, "Error reading global agent data: {e}"),
            }
        }
        vs!(self.log, Debug2, "Fetched {} agents from provigil-db.", agents.len());
        Ok(Some(agents))
    }

    /// Re-scan of all agents: (re)starts the low-priority background job, one entry per agent.
    /// A running job is replaced, so there is never more than one.
    fn start_rescan_job(&mut self, ctx: &Ctx) -> Res<()> {
        let Some(agents) = self.all_agents()? else { return Ok(()) };
        self.job.clear(None);
        // Agents no longer in the list lose their inventory and documents now.
        let listed: BTreeSet<String> = agents.iter().map(|a| a.id.clone()).collect();
        for stale in self.inventory_agents()? {
            if !listed.contains(&stale) {
                self.cleanup_agent_id(&stale, Component::Agent, ctx.no_index)?;
            }
        }
        let total = agents.len();
        for (i, a) in agents.iter().enumerate() {
            let item = json!({
                "agent": {"id": a.id, "ip": a.ip, "name": a.name, "version": a.version},
                "no-index": ctx.no_index, "full": ctx.full, "done": i + 1, "total": total,
            });
            self.job.push("", crate::json::compact(&item).as_bytes());
        }
        Ok(())
    }

    /// Re-scans the next agent of the background job; false when the job is empty.
    pub fn job_step(&mut self) -> bool {
        let Some((seq, _, item)) = self.job.front(|_| true) else { return false };
        let Ok(v) = serde_json::from_slice::<Value>(&item) else {
            self.job.remove(seq);
            return true;
        };
        let ai = &v["agent"];
        let a = Agent { id: s(ai, "id").into(), ip: s(ai, "ip").into(), name: s(ai, "name").into(), version: s(ai, "version").into() };
        let no_index = v["no-index"].as_bool().unwrap_or(false);
        let full = v["full"].as_bool().unwrap_or(false);
        self.sink.begin_rescan(full);
        let r = self.agent_pairs(&a.id).and_then(|before| {
            self.cleanup_agent_id(&a.id, Component::Agent, no_index)?;
            self.rescan_agent_data(&a, &before, L1::RescanAll, no_index)
        });
        self.sink.end_rescan();
        match r {
            Ok(()) => {}
            Err(Error::NotReady { text, .. }) => {
                vs!(self.log, Debug2, "Error executing query to fetch agent data for agents. Reason: {text}.");
                let ev = Event::json(json!({"action":"scanAgent","agent_info":{"agent_id":a.id},"no-index":no_index}));
                self.delayed.push(&a.id, &ev.encode());
            }
            Err(e) => vs!(self.log, Error, "Error handling request: {e}."),
        }
        let (done, total) = (v["done"].as_u64().unwrap_or(0), v["total"].as_u64().unwrap_or(0));
        if done % 50 == 0 || done == total {
            vs!(self.log, Info, "Re-scan after feed update: {done}/{total} agents.");
        }
        self.job.remove(seq);
        true
    }

    fn rescan_one(&mut self, ctx: &mut Ctx) -> Res<()> {
        let id = ctx.agent.id.clone();
        let before = self.agent_pairs(&id)?;
        self.cleanup_agent(ctx, Component::Agent)?;
        let rows = self.agent_db.query(&agentdb::q_agent_info(&id)).map_err(|e| match e {
            DbError::NotSynced => Error::NotReady { agent: id.clone(), text: agentdb::NOT_SYNCED_TEXT.into() },
            DbError::Failed(t) => Error::Other(format!("Unable to retrieve agent-info (agent {id}). Reason: {t}.")),
        })?;
        if rows.len() != 1 {
            return Ok(());
        }
        let r = &rows[0];
        let t = |k: &str| r.get(k).and_then(Value::as_str).map(str::to_string).ok_or_else(|| Error::Other("Invalid agent-info response format".into()));
        let (node, status, name, ip) = (t("node_name")?, t("connection_status")?, t("name")?, t("ip")?);
        // Missing or not a text = empty; stripped like the all-agents list.
        let version = strip_version(r.get("version").and_then(Value::as_str).unwrap_or(""));
        if !self.settings.cluster_enabled || (node == self.settings.node_name && status == "active") {
            vs!(self.log, Debug2, "Agent {id} added to the list of agents to be re-scanned");
        } else {
            vs!(
                self.log,
                Debug2,
                "Agent {id} not added to the list of agents to be re-scanned (cluster status: {}) (cluster node_name: {}) (connection_status: {status}) (agent node_name: {node})",
                self.settings.cluster_enabled,
                self.settings.node_name
            );
            return Ok(());
        }
        let a = Agent { id: id.clone(), ip, name, version };
        match self.rescan_agent_data(&a, &before, L1::RescanOne, ctx.no_index) {
            Err(Error::NotReady { text, .. }) => {
                vs!(self.log, Debug2, "Error executing query to fetch agent data for agents. Reason: {text}.");
                Err(Error::Incomplete { agents: vec![id], no_index: ctx.no_index })
            }
            Err(e) => {
                vs!(self.log, Error, "Error handling request: {e}.");
                Ok(())
            }
            Ok(()) => Ok(()),
        }
    }

    /// Scans one agent's data (after its clean-up) and alerts the changes against `before`.
    /// A scan that failed part-way sends no alerts.
    fn rescan_agent_data(&mut self, a: &Agent, before: &BTreeSet<(String, String, String)>, l1: L1, no_index: bool) -> Res<()> {
        self.collect = Some(BTreeMap::new());
        let r = self.scan_agent_data(a, l1, no_index);
        let collected = self.collect.take().unwrap_or_default();
        if r? && !before.is_empty() {
            self.change_alerts(a, before, &collected)?;
        }
        Ok(())
    }

    fn state_message(a: &Agent, attrs: Map<String, Value>, ty: &str) -> Event {
        Event {
            origin: Origin::Rsync,
            body: json!({
                "agent_info": {"agent_id": a.id, "agent_ip": a.ip, "agent_name": a.name, "agent_version": a.version},
                "data": {"attributes": attrs, "attributes_type": ty},
                "data_type": "state",
            }),
        }
    }

    /// OS rows and package rows of one agent turned into state messages and scanned. Returns
    /// false when a query failed (logged), so the scan is incomplete.
    fn scan_agent_data(&mut self, a: &Agent, l1: L1, no_index: bool) -> Res<bool> {
        let mut complete = true;
        // An invalid agent id is a failed query (no query is sent).
        match agentdb::q_osinfo(&a.id).and_then(|q| self.agent_db.query(&q)) {
            Err(DbError::NotSynced) => return Err(Error::NotReady { agent: a.id.clone(), text: agentdb::NOT_SYNCED_TEXT.into() }),
            Err(DbError::Failed(t)) => {
                vs!(self.log, Error, "Unable to retrieve OS agent data (agent {}). Reason: {t}.", a.id);
                complete = false;
            }
            Ok(rows) => {
                if rows.is_empty() {
                    vs!(self.log, Debug2, "Empty response for agent '{}' in provigil-db 'sys_' query", a.id);
                }
                for row in &rows {
                    let mut attrs = Map::new();
                    for k in OS_FIELDS.iter().chain(["checksum", "scan_time"].iter()) {
                        attrs.insert(k.to_string(), opt_text(row, k)?.into());
                    }
                    let mut ctx = self.build_ctx(&Self::state_message(a, attrs, "syscollector_osinfo"))?;
                    ctx.no_index = no_index;
                    self.os_chain(&mut ctx)?;
                }
            }
        }
        match agentdb::q_packages(&a.id).and_then(|q| self.agent_db.query(&q)) {
            Err(DbError::NotSynced) => return Err(Error::NotReady { agent: a.id.clone(), text: agentdb::NOT_SYNCED_TEXT.into() }),
            Err(DbError::Failed(t)) => {
                vs!(self.log, Error, "Unable to retrieve packages agent data (agent {}). Reason: {t}.", a.id);
                complete = false;
            }
            Ok(rows) => {
                if rows.is_empty() {
                    vs!(self.log, Debug2, "Empty response for agent '{}' in provigil-db 'sys_programs' query", a.id);
                }
                for row in &rows {
                    let mut attrs = Map::new();
                    for k in [
                        "architecture", "checksum", "description", "format", "groups", "install_time", "item_id", "location",
                        "multiarch", "name", "priority", "scan_time", "source", "vendor", "version",
                    ] {
                        attrs.insert(k.to_string(), opt_text(row, k)?.into());
                    }
                    let size = row.get("size").and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0) as i32;
                    attrs.insert("size".into(), size.into());
                    let mut ctx = self.build_ctx(&Self::state_message(a, attrs, "syscollector_packages"))?;
                    ctx.no_index = no_index;
                    self.package_insert(&mut ctx, l1)?;
                }
            }
        }
        Ok(complete)
    }
}
