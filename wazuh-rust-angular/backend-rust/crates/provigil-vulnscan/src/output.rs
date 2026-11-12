//! Outputs: description merge, state documents, alerts, report lines and element publishing.

use crate::event::{Agent, Component, Ctx, EventType};
use std::collections::{BTreeMap, BTreeSet};
use crate::json::{compact, key_missing, type_name, Error, Res};
use crate::legacy_names::{CVE_REFERENCE_BASE, DOC_ROOT_KEY, VENDOR_NAME};
use crate::scan::Core;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use serde_json::{json, Map, Value};

const NO_DATE: &str = "0000-01-01T00:00:00Z";
/// Most alerts one agent re-scan sends.
pub const RESCAN_ALERT_CAP: usize = 500;

pub fn sentence_case(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_ascii_uppercase().to_string() + &c.as_str().to_ascii_lowercase(),
        None => String::new(),
    }
}

/// The 32-bit score printed with 2 decimals and read back.
pub fn round2(score: f32) -> f64 {
    format!("{score:.2}").parse().unwrap_or(0.0)
}

/// Magnitudes below 1e-9 become -1.
pub fn fill(v: f64) -> f64 {
    if v.abs() < 1e-9 {
        -1.0
    } else {
        v
    }
}

/// Character-class check of fixed-width date texts (`D` = digit, other characters literal).
fn shape(t: &str, pattern: &str) -> bool {
    t.len() == pattern.len() && t.bytes().zip(pattern.bytes()).all(|(c, p)| if p == b'D' { c.is_ascii_digit() } else { c == p })
}

/// Install time conversion (13.1.1); `None` when there is nothing to write.
pub fn install_time(t: &str) -> Option<String> {
    const OUT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        let secs: i64 = t.parse().ok()?;
        return DateTime::<Utc>::from_timestamp(secs, 0).map(|d| d.format(OUT).to_string());
    }
    if let Ok(n) = NaiveDateTime::parse_from_str(t, "%Y/%m/%d %H:%M:%S") {
        return Local.from_local_datetime(&n).earliest().map(|d| d.with_timezone(&Utc).format(OUT).to_string());
    }
    if shape(t, "DDDD-DD-DDTDD:DD:DDZ") {
        return Some(format!("{}.000Z", &t[..19]));
    }
    if shape(t, "DDDD-DD-DDTDD:DD:DD.DDDZ") {
        return Some(t.to_string());
    }
    None
}

/// Merged description of one CVE (13.2).
pub struct Desc {
    pub f: Map<String, Value>,
    pub score: f32,
}

impl Desc {
    pub fn t(&self, k: &str) -> &str {
        self.f.get(k).and_then(Value::as_str).unwrap_or("")
    }
}

const FROM_CVSS: [&str; 13] = [
    "accessComplexity", "attackVector", "authentication", "availabilityImpact", "classification", "confidentialityImpact",
    "integrityImpact", "privilegesRequired", "scope", "scoreVersion", "severity", "userInteraction", "offset",
];
const FROM_DESC: [&str; 7] = ["assignerShortName", "cweId", "datePublished", "dateUpdated", "description", "reference", "offset"];

/// Description sources of an event: (first name, cvss source, description source).
pub struct Sources {
    a: String,
    cvss: String,
    desc: String,
}

fn set(doc: &mut Value, path: &str, v: Value) {
    let mut cur = doc;
    let parts: Vec<&str> = path.split('.').collect();
    for p in &parts[..parts.len() - 1] {
        if !cur.get(*p).is_some_and(Value::is_object) {
            cur[*p] = json!({});
        }
        cur = &mut cur[*p];
    }
    cur[parts[parts.len() - 1]] = v;
}

fn set_if(doc: &mut Value, path: &str, v: &str) {
    if v.chars().any(|c| c != ' ') {
        set(doc, path, v.into());
    }
}

fn dash(s: &str) -> Value {
    if s.is_empty() { "-".into() } else { s.into() }
}

fn get_text(entry: &Value, k: &str) -> Res<String> {
    match entry.get(k) {
        None => Err(key_missing(k)),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(o) => Err(Error::Json { id: 303, text: format!("JSON value is not a text, actual type is {}", type_name(o)) }),
    }
}

impl Core {
    fn adp_descriptions(&self) -> Res<&Value> {
        self.feed.maps.vendor.get("adp_descriptions").ok_or_else(|| key_missing("adp_descriptions"))
    }

    pub(crate) fn sources(&self, ctx: &Ctx) -> Res<Sources> {
        self.sources_for(&ctx.vuln_source.0, &ctx.vuln_source.1)
    }

    pub(crate) fn sources_for(&self, a: &str, x: &str) -> Res<Sources> {
        let (a, x) = (a.to_string(), x.to_string());
        let adp = self.adp_descriptions()?;
        let entry = match adp.get(&a) {
            Some(e) => e,
            None => adp.get("nvd").ok_or_else(|| key_missing("nvd"))?,
        };
        let pick = |v: String| if v == a { x.clone() } else { v };
        let cvss = pick(get_text(entry, "cvss")?);
        let desc = pick(get_text(entry, "description")?);
        Ok(Sources { a, cvss, desc })
    }

    pub(crate) fn merge(&self, cve: &str, src: &Sources) -> Res<Desc> {
        let log = &self.log;
        let mut d = self.feed.description(cve, &src.desc, log)?;
        if d.is_none() {
            vs!(log, Debug2, "Description information could not be obtained for '{cve}' from '{}' source.", src.desc);
        }
        let mut default_failed = false;
        if d.as_ref().is_none_or(|x| x["description"] == "not defined") {
            vs!(log, Debug2, "Unreliable description information for '{cve}' from '{}' source.", src.desc);
            if src.desc != "nvd" {
                d = self.feed.description(cve, "nvd", log)?;
                if d.is_none() {
                    vs!(log, Debug2, "Description information could not be obtained for '{cve}' from 'nvd' source.");
                    default_failed = true;
                }
            }
        }
        let mut c = if src.cvss != src.desc {
            let c = self.feed.description(cve, &src.cvss, log)?;
            if c.is_none() {
                vs!(log, Debug2, "CVSS information could not be obtained for '{cve}' from '{}' source.", src.cvss);
            }
            c
        } else {
            d.clone()
        };
        let reliable = c.as_ref().is_some_and(|x| x["scoreBase"].as_f64().unwrap_or(0.0) >= 0.01 && !x["severity"].as_str().unwrap_or("").is_empty());
        if !reliable {
            vs!(log, Debug2, "Unreliable information for '{cve}' from {} source.", src.cvss);
            if src.cvss != "nvd" && !default_failed {
                c = self.feed.description(cve, "nvd", log)?;
                if c.is_none() {
                    vs!(log, Debug2, "CVSS information could not be obtained for '{cve}' from 'nvd' source.");
                }
            }
        }
        let mut out = Desc { f: Map::new(), score: 0.0 };
        for k in FROM_CVSS.iter().chain(FROM_DESC.iter()) {
            out.f.insert(k.to_string(), "".into());
        }
        out.f.insert("datePublished".into(), NO_DATE.into());
        out.f.insert("dateUpdated".into(), NO_DATE.into());
        let copy = |out: &mut Desc, from: &Value, keys: &[&str]| {
            for k in keys {
                if let Some(v) = from.get(*k).and_then(Value::as_str).filter(|v| !v.is_empty()) {
                    out.f.insert(k.to_string(), v.into());
                }
            }
        };
        if let Some(c) = &c {
            copy(&mut out, c, &FROM_CVSS);
            out.score = c["scoreBase"].as_f64().unwrap_or(0.0) as f32;
        }
        if let Some(d) = &d {
            copy(&mut out, d, &FROM_DESC);
        }
        Ok(out)
    }

    fn detection_source(&self, ctx: &Ctx, cve: &str, src: &Sources) -> String {
        if src.a == "nvd" {
            ctx.detection.get(cve).cloned().unwrap_or_default()
        } else {
            src.a.clone()
        }
    }

    // ---- documents (13.1) -------------------------------------------------------------------

    pub(crate) fn document_details(&mut self, ctx: &mut Ctx) -> Res<()> {
        vs!(self.log, Debug2, "Building event details for component type: {}", ctx.component as u8);
        let os = &ctx.os;
        let os_full = if os.platform == "darwin" { format!("{} {}", os.name, os.codename) } else { format!("{} {}", os.name, os.version) };
        let mut os_version = os.major.clone();
        for p in [&os.minor, &os.patch, &os.build] {
            if !p.is_empty() {
                os_version.push('.');
                os_version.push_str(p);
            }
        }
        let os_type = if os.platform == "darwin" { "macos".to_string() } else { os.platform.to_ascii_lowercase() };
        let src = self.sources(ctx)?;
        let cves: Vec<String> = ctx.elements.keys().cloned().collect();
        for cve in cves {
            if ctx.elements[&cve].get("operation").and_then(Value::as_str) == Some("DELETED") {
                continue;
            }
            let fail = |log: &crate::log::Log, e: &dyn std::fmt::Display| {
                vs!(log, Error, "Error building event details for CVE: {cve}");
                vs!(log, Error, "Error message: {e}");
            };
            let d = match self.merge(&cve, &src) {
                Ok(d) => d,
                Err(e) => {
                    fail(&self.log, &e);
                    continue;
                }
            };
            // The offset suffix is appended right after the merge; later errors keep it.
            let el = ctx.elements.get_mut(&cve).expect("element");
            match el.get("id") {
                Some(Value::String(id)) => {
                    let id = format!("{id}_{}", d.t("offset"));
                    el["id"] = id.into();
                }
                other => {
                    fail(&self.log, &format!("JSON value must be string, but is {}", type_name(other.unwrap_or(&Value::Null))));
                    continue;
                }
            }
            match self.document(ctx, &cve, &src, &d, &os_full, &os_version, &os_type) {
                Ok(doc) => {
                    ctx.elements.get_mut(&cve).expect("element")["data"] = doc;
                }
                Err(e) => fail(&self.log, &e),
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn document(&self, ctx: &Ctx, cve: &str, src: &Sources, d: &Desc, os_full: &str, os_version: &str, os_type: &str) -> Res<Value> {
        let det = self.detection_source(ctx, cve, src);
        let scanner_source = self.adp_descriptions()?.get(&det).ok_or_else(|| key_missing(&det))?.get("adp").cloned().ok_or_else(|| key_missing("adp"))?;
        let mut doc = json!({});
        if self.settings.cluster_enabled && ctx.agent.id == "000" {
            set_if(&mut doc, "agent.ephemeral_id", &self.settings.node_name);
        }
        set_if(&mut doc, "agent.id", &ctx.agent.id);
        set_if(&mut doc, "agent.name", &ctx.agent.name);
        set(&mut doc, "agent.type", VENDOR_NAME.into());
        set_if(&mut doc, "agent.version", &ctx.agent.version);
        set_if(&mut doc, "host.os.full", os_full);
        set_if(&mut doc, "host.os.kernel", &ctx.os.kernel_release);
        set_if(&mut doc, "host.os.name", &ctx.os.name);
        set_if(&mut doc, "host.os.platform", &ctx.os.platform.to_ascii_lowercase());
        set_if(&mut doc, "host.os.type", os_type);
        set_if(&mut doc, "host.os.version", os_version);
        match ctx.component {
            Component::Package => {
                let r = ctx.row();
                let f = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                set_if(&mut doc, "package.architecture", &f("architecture"));
                set_if(&mut doc, "package.description", &f("description"));
                if let Some(t) = install_time(&f("install_time")) {
                    set(&mut doc, "package.installed", t.into());
                }
                set_if(&mut doc, "package.name", &f("name"));
                set_if(&mut doc, "package.path", &f("location"));
                set(&mut doc, "package.size", r.get("size").filter(|v| v.is_number()).cloned().unwrap_or(0.into()));
                set_if(&mut doc, "package.type", &f("format"));
                set_if(&mut doc, "package.version", &f("version"));
            }
            Component::Os => {
                set_if(&mut doc, "package.architecture", &ctx.os.architecture);
                set_if(&mut doc, "package.name", os_full);
                set_if(&mut doc, "package.type", os_type);
                set_if(&mut doc, "package.version", os_version);
            }
            _ => {}
        }
        let rounded = round2(d.score);
        set(&mut doc, "vulnerability.category", if ctx.component == Component::Os { "OS" } else { "Packages" }.into());
        set(&mut doc, "vulnerability.classification", dash(d.t("classification")));
        set(&mut doc, "vulnerability.description", d.t("description").into());
        set(&mut doc, "vulnerability.detected_at", Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string().into());
        set(&mut doc, "vulnerability.enumeration", "CVE".into());
        set(&mut doc, "vulnerability.id", cve.into());
        set(&mut doc, "vulnerability.published_at", d.t("datePublished").into());
        set(&mut doc, "vulnerability.reference", d.t("reference").into());
        set(&mut doc, "vulnerability.scanner.vendor", VENDOR_NAME.into());
        set(&mut doc, "vulnerability.scanner.source", scanner_source);
        set(&mut doc, "vulnerability.scanner.reference", format!("{CVE_REFERENCE_BASE}{cve}").into());
        if let Some(c) = ctx.conditions.get(cve) {
            set(&mut doc, "vulnerability.scanner.condition", c.text().into());
        }
        set(&mut doc, "vulnerability.score.base", json!(fill(rounded)));
        set(&mut doc, "vulnerability.score.version", dash(d.t("scoreVersion")));
        set(&mut doc, "vulnerability.severity", dash(&sentence_case(d.t("severity"))));
        set(&mut doc, "vulnerability.under_evaluation", (rounded == 0.0 || d.t("scoreVersion").is_empty() || d.t("severity").is_empty()).into());
        set(&mut doc, &format!("{DOC_ROOT_KEY}.cluster.name"), self.settings.cluster_name.clone().into());
        set(&mut doc, &format!("{DOC_ROOT_KEY}.schema.version"), "1.0.0".into());
        Ok(doc)
    }

    // ---- alerts (13.3) ----------------------------------------------------------------------

    fn cvss_key(version: &str) -> String {
        format!("cvss{}", version.chars().next().map(String::from).unwrap_or_default())
    }

    /// Package or OS alerts for every element.
    pub(crate) fn vuln_alerts(&mut self, ctx: &mut Ctx, os: bool) -> Res<()> {
        let src = self.sources(ctx)?;
        let (name, arch, version, source) = if os {
            (ctx.os.name.clone(), ctx.os.architecture.clone(), ctx.os.version.clone(), "OS".to_string())
        } else {
            let r = ctx.row();
            let f = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            (f("name"), f("architecture"), f("version"), f("source"))
        };
        let cves: Vec<String> = ctx.elements.keys().cloned().collect();
        for cve in cves {
            let op = match ctx.elements[&cve].get("operation") {
                Some(Value::String(o)) => o.clone(),
                other if os => return Err(Error::Json { id: 302, text: format!("JSON value must be string, but is {}", type_name(other.unwrap_or(&Value::Null))) }),
                _ => String::new(),
            };
            let r = (|| -> Res<Value> {
                let inserted = match op.as_str() {
                    "INSERTED" => true,
                    "DELETED" => false,
                    _ => return Err(if os { "Unknown operation" } else { "Unknown element operation" }.into()),
                };
                let d = self.merge(&cve, &src)?;
                let rounded = round2(d.score);
                let sv = d.t("scoreVersion");
                let mut a = json!({});
                let p = |k: &str| format!("vulnerability.{k}");
                if inserted {
                    set(&mut a, &p("assigner"), d.t("assignerShortName").into());
                    set(&mut a, &p("cwe_reference"), d.t("cweId").into());
                    set(&mut a, &p("package.source"), source.clone().into());
                    set(&mut a, &p("rationale"), d.t("description").into());
                }
                set(&mut a, &p("classification"), dash(d.t("classification")));
                set(&mut a, &p("cve"), cve.clone().into());
                if !sv.is_empty() {
                    let ck = Self::cvss_key(sv);
                    set(&mut a, &p(&format!("cvss.{ck}.base_score")), json!(rounded));
                    if inserted {
                        let vk = |k: &str| p(&format!("cvss.{ck}.vector.{k}"));
                        if ck == "cvss2" {
                            set(&mut a, &vk("access_complexity"), d.t("accessComplexity").into());
                            set(&mut a, &vk("authentication"), d.t("authentication").into());
                        }
                        if ck == "cvss3" {
                            set(&mut a, &vk("attack_vector"), d.t("attackVector").into());
                            set(&mut a, &vk("privileges_required"), d.t("privilegesRequired").into());
                            set(&mut a, &vk("scope"), d.t("scope").into());
                            set(&mut a, &vk("user_interaction"), d.t("userInteraction").into());
                        }
                        set(&mut a, &vk("availability"), d.t("availabilityImpact").into());
                        set(&mut a, &vk("confidentiality_impact"), d.t("confidentialityImpact").into());
                        set(&mut a, &vk("integrity_impact"), d.t("integrityImpact").into());
                    }
                }
                set(&mut a, &p("enumeration"), "CVE".into());
                set(&mut a, &p("package.architecture"), arch.clone().into());
                if let Some(c) = ctx.conditions.get(&cve) {
                    set(&mut a, &p("package.condition"), c.text().into());
                }
                set(&mut a, &p("package.name"), name.clone().into());
                set(&mut a, &p("package.version"), version.clone().into());
                set(&mut a, &p("published"), d.t("datePublished").into());
                set(&mut a, &p("reference"), d.t("reference").into());
                set(&mut a, &p("scanner.reference"), format!("{CVE_REFERENCE_BASE}{cve}").into());
                set(&mut a, &p("score.base"), json!(fill(rounded)));
                set(&mut a, &p("score.version"), dash(sv));
                set(&mut a, &p("severity"), dash(&sentence_case(d.t("severity"))));
                set(&mut a, &p("status"), if inserted { "Active" } else { "Solved" }.into());
                let title = if inserted { format!("{cve} affects {name}") } else { format!("{cve} affecting {name} was solved") };
                set(&mut a, &p("title"), title.into());
                set(&mut a, &p("type"), "Packages".into());
                set(&mut a, &p("updated"), d.t("dateUpdated").into());
                Ok(a)
            })();
            match r {
                Ok(a) => {
                    ctx.alerts.insert(cve, a);
                }
                Err(e) => {
                    vs!(self.log, Error, "Error building event details for CVE: {cve}");
                    vs!(self.log, Error, "Error message: {e}");
                }
            }
        }
        Ok(())
    }

    pub(crate) fn hotfix_alerts(&mut self, ctx: &mut Ctx) -> Res<()> {
        let src = self.sources(ctx)?;
        let cves: Vec<String> = ctx.elements.iter().filter(|(_, v)| v.as_array().is_some_and(|a| !a.is_empty())).map(|(k, _)| k.clone()).collect();
        for cve in cves {
            let d = match self.merge(&cve, &src) {
                Ok(d) => d,
                Err(e) => {
                    vs!(self.log, Error, "Error building event details for CVE: {cve}");
                    vs!(self.log, Error, "Error message: {e}");
                    continue;
                }
            };
            let rounded = round2(d.score);
            let sv = d.t("scoreVersion");
            let mut a = json!({});
            let p = |k: &str| format!("vulnerability.{k}");
            set(&mut a, &p("title"), format!("{cve} affecting one or many packages was solved by {}", ctx.hotfix).into());
            set(&mut a, &p("package.name"), "one or many packages".into());
            set(&mut a, &p("status"), "Solved".into());
            set(&mut a, &p("cve"), cve.clone().into());
            set(&mut a, &p("scanner.reference"), format!("{CVE_REFERENCE_BASE}{cve}").into());
            if !sv.is_empty() {
                set(&mut a, &p(&format!("cvss.{}.base_score", Self::cvss_key(sv))), json!(rounded));
            }
            set(&mut a, &p("enumeration"), "CVE".into());
            set(&mut a, &p("published"), d.t("datePublished").into());
            set(&mut a, &p("reference"), d.t("reference").into());
            set(&mut a, &p("severity"), dash(&sentence_case(d.t("severity"))));
            set(&mut a, &p("classification"), dash(d.t("classification")));
            set(&mut a, &p("score.base"), json!(fill(rounded)));
            set(&mut a, &p("score.version"), dash(sv));
            set(&mut a, &p("type"), "Packages".into());
            set(&mut a, &p("updated"), d.t("dateUpdated").into());
            ctx.alerts.insert(cve, a);
        }
        Ok(())
    }

    /// The clear alert of an integrity clear; its title names the component.
    pub fn clear_alert(component: Component) -> Value {
        let title = if component == Component::Os {
            "There is no information of the operating system. Vulnerabilities cleared."
        } else {
            "There is no information of installed packages. Vulnerabilities cleared."
        };
        json!({"vulnerability":{"status":"Clear","title":title,"type":"Packages"}})
    }

    /// Sends the clear alert once for the agent.
    pub(crate) fn send_clear_alert(&mut self, ctx: &Ctx) {
        self.reports.push(Self::report_line(ctx, &Self::clear_alert(ctx.component)));
        let what = if ctx.component == Component::Os { "OS" } else { "packages" };
        vs!(self.log, Warning, "Vulnerability report for agent ID {}, clean all {what} alert.", ctx.agent.id);
    }

    pub fn report_line(ctx: &Ctx, alert: &Value) -> String {
        Self::report_line_for(&ctx.agent, alert)
    }

    pub fn report_line_for(a: &Agent, alert: &Value) -> String {
        format!("1:[{}] ({}) {}->vulnerability-detector:{}", a.id, a.name, a.ip, compact(alert))
    }

    /// While re-scanning an agent: the alerts a real-time detection would send are kept, by
    /// (inventory key, CVE), instead of being sent.
    pub(crate) fn collect_alerts(&mut self, ctx: &mut Ctx, os: bool) -> Res<()> {
        let key = if os { self.os_key(ctx) } else { self.package_key_of(ctx)? };
        self.vuln_alerts(ctx, os)?;
        let alerts = std::mem::take(&mut ctx.alerts);
        if let Some(c) = self.collect.as_mut() {
            for (cve, a) in alerts {
                c.insert((key.clone(), cve), a);
            }
        }
        Ok(())
    }

    /// The `Solved` alert of a pair that a re-scan no longer finds.
    fn solved_alert(&self, cve: &str) -> Res<Value> {
        let d = self.merge(cve, &self.sources_for("nvd", "nvd")?)?;
        let rounded = round2(d.score);
        let sv = d.t("scoreVersion");
        let mut a = json!({});
        let p = |k: &str| format!("vulnerability.{k}");
        set(&mut a, &p("title"), format!("{cve} affecting one or many packages was solved").into());
        set(&mut a, &p("package.name"), "one or many packages".into());
        set(&mut a, &p("status"), "Solved".into());
        set(&mut a, &p("cve"), cve.into());
        set(&mut a, &p("scanner.reference"), format!("{CVE_REFERENCE_BASE}{cve}").into());
        if !sv.is_empty() {
            set(&mut a, &p(&format!("cvss.{}.base_score", Self::cvss_key(sv))), json!(rounded));
        }
        set(&mut a, &p("enumeration"), "CVE".into());
        set(&mut a, &p("published"), d.t("datePublished").into());
        set(&mut a, &p("reference"), d.t("reference").into());
        set(&mut a, &p("severity"), dash(&sentence_case(d.t("severity"))));
        set(&mut a, &p("classification"), dash(d.t("classification")));
        set(&mut a, &p("score.base"), json!(fill(rounded)));
        set(&mut a, &p("score.version"), dash(sv));
        set(&mut a, &p("type"), "Packages".into());
        set(&mut a, &p("updated"), d.t("dateUpdated").into());
        Ok(a)
    }

    /// Alerts for the changes a re-scan found: new pairs (`Active`) first, then pairs no longer
    /// found (`Solved`), each in CVE order, at most `RESCAN_ALERT_CAP` per agent.
    pub(crate) fn change_alerts(&mut self, a: &Agent, before: &BTreeSet<(String, String, String)>, collected: &BTreeMap<(String, String), Value>) -> Res<()> {
        let after = self.agent_pairs(&a.id)?;
        let by_cve = |s: &BTreeSet<(String, String, String)>, o: &BTreeSet<(String, String, String)>| {
            let mut v: Vec<(String, String)> = s.difference(o).map(|(_, k, c)| (c.clone(), k.clone())).collect();
            v.sort();
            v
        };
        let mut alerts: Vec<(String, Value)> = Vec::new();
        for (cve, key) in by_cve(&after, before) {
            if let Some(al) = collected.get(&(key, cve.clone())) {
                alerts.push((cve, al.clone()));
            }
        }
        for (cve, _) in by_cve(before, &after) {
            match self.solved_alert(&cve) {
                Ok(al) => alerts.push((cve, al)),
                Err(e) => {
                    vs!(self.log, Error, "Error building event details for CVE: {cve}");
                    vs!(self.log, Error, "Error message: {e}");
                }
            }
        }
        let extra = alerts.len().saturating_sub(RESCAN_ALERT_CAP);
        for (cve, al) in alerts.into_iter().take(RESCAN_ALERT_CAP) {
            self.reports.push(Self::report_line_for(a, &al));
            let status = al.pointer("/vulnerability/status").and_then(Value::as_str).unwrap_or("");
            let word = if status == "Active" { "detected" } else { "solved" };
            let name = al.pointer("/vulnerability/package/name").and_then(Value::as_str).unwrap_or("");
            vs!(self.log, Debug2, "Vulnerability {word} report for agent ID {}, package: {name}, cve: {cve}", a.id);
        }
        if extra > 0 {
            vs!(self.log, Warning, "Re-scan of agent {}: {extra} more vulnerability changes were not alerted.", a.id);
        }
        Ok(())
    }

    pub(crate) fn send_alerts(&mut self, ctx: &Ctx) {
        let id = &ctx.agent.id;
        for (cve, a) in &ctx.alerts {
            self.reports.push(Self::report_line(ctx, a));
            match ctx.component {
                Component::Package => {
                    let word = if ctx.ty == EventType::PackageInsert { "detected" } else { "solved" };
                    let name = ctx.row().get("name").and_then(Value::as_str).unwrap_or("");
                    vs!(self.log, Debug2, "Vulnerability {word} report for agent ID {id}, package: {name}, cve: {cve}");
                }
                Component::Os => vs!(self.log, Debug2, "Vulnerability report for agent ID {id}, OS: {}, cve: {cve}", ctx.os.name),
                Component::Hotfix => vs!(self.log, Debug2, "Vulnerability report for agent ID {id}, hotfix: {}, cve: {cve}", ctx.hotfix),
                _ => vs!(self.log, Warning, "Vulnerability report for agent ID {id}, cve: {cve}."),
            }
        }
    }

    /// Element publisher (13.5.2).
    pub(crate) fn publish_elements(&mut self, ctx: &mut Ctx) {
        for (cve, el) in ctx.elements.iter_mut() {
            if let Some(o) = el.as_object_mut() {
                o.insert("no-index".into(), ctx.no_index.into());
            }
            vs!(self.log, Debug2, "Processing and publish key: {cve}");
            if el.get("operation").is_some() && el.get("id").is_some() {
                self.sink.publish(&compact(el));
            } else {
                vs!(self.log, Error, "Invalid element to publish: {}.", compact(el));
            }
        }
    }

    /// Array publisher of the hotfix chain.
    pub(crate) fn publish_arrays(&mut self, ctx: &Ctx) -> Res<()> {
        for (cve, el) in &ctx.elements {
            let Some(items) = el.as_array() else {
                return Err(format!("Invalid element to publish (not an array): {}", compact(el)).into());
            };
            for it in items {
                vs!(self.log, Debug2, "Processing and publish key: {cve}");
                if it.get("operation").is_some() && it.get("id").is_some() {
                    self.sink.publish(&compact(it));
                } else {
                    vs!(self.log, Error, "Invalid element to publish (no operation or id fields): {}.", compact(it));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(sentence_case("HIGH"), "High");
        assert_eq!(round2(7.25), 7.25);
        assert_eq!(round2(6.1), 6.1);
        assert_eq!(fill(0.0), -1.0);
        assert_eq!(install_time("1700000000").unwrap(), "2023-11-14T22:13:20.000Z");
        assert_eq!(install_time("2024-11-14T18:32:28Z").unwrap(), "2024-11-14T18:32:28.000Z");
        assert_eq!(install_time("2024-11-14T18:32:28.123Z").unwrap(), "2024-11-14T18:32:28.123Z");
        assert_eq!(install_time("garbage"), None);
        assert_eq!(install_time(""), None);
        assert_eq!(install_time("20231212").unwrap(), "1970-08-23T03:46:52.000Z");
        assert!(install_time("2024/01/02 03:04:05").is_some());
        // D36: character-class check only.
        assert_eq!(install_time("2024-13-45T99:99:99Z").unwrap(), "2024-13-45T99:99:99.000Z");
    }
}
