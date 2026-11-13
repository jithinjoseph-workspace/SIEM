//! The MITRE ATT&CK table (spec section 2.19): technique id -> name and tactics, read from
//! provigil-db's `mitre` database at start.

use std::collections::HashMap;

use provigil_json::Json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tactic {
    /// e.g. "TA0006"
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Technique {
    /// e.g. "T1110"
    pub id: String,
    pub name: String,
    pub tactics: Vec<Tactic>,
}

#[derive(Debug, Clone, Default)]
pub struct Mitre {
    pub techniques: HashMap<String, Technique>,
}

const PAGE: i32 = 100;
const UNREADABLE: &str = "Response from the Mitre database cannot be parsed.";
const EMPTY: &str = "Response from the Mitre database has 0 elements.";

fn techniques_page(offset: i32) -> String {
    format!(
        "mitre sql SELECT technique.id, technique.name, reference.external_id FROM technique LEFT JOIN reference ON technique.id = reference.id WHERE technique.revoked_by IS NULL AND NOT technique.deprecated AND reference.source = 'mitre-attack' LIMIT {PAGE} OFFSET {offset};"
    )
}

/// A member's text (a missing member: None; not a string: empty).
fn text(j: Option<&Json>) -> Option<String> {
    j.map(|v| v.as_bytes().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default())
}

impl Mitre {
    pub fn technique(&self, id: &str) -> Option<&Technique> {
        self.techniques.get(id)
    }

    /// The first technique stored under an id stays.
    pub fn add(&mut self, t: Technique) {
        self.techniques.entry(t.id.clone()).or_insert(t);
    }

    /// Reads the table with `query` (provigil-db answers as JSON; None on failure). On an
    /// error the techniques read so far stay; None only when nothing could be read.
    pub fn load(query: &mut dyn FnMut(&str) -> Option<Json>, errors: &mut Vec<String>) -> Option<Mitre> {
        let mut table = None;
        if let Err(e) = Self::read(query, &mut table) {
            errors.push(e.into());
            errors.push("Mitre matrix information could not be loaded.".into());
        }
        table
    }

    fn read(query: &mut dyn FnMut(&str) -> Option<Json>, table: &mut Option<Mitre>) -> Result<(), &'static str> {
        let mut offset = 0;
        let mut page = query(&techniques_page(offset)).ok_or(UNREADABLE)?;
        if page.children().is_empty() {
            return Err(EMPTY);
        }
        let t = table.insert(Mitre::default());
        loop {
            for x in page.children() {
                let id = text(x.get("id")).ok_or("It was not possible to get Mitre technique ID.")?;
                let name = text(x.get("name")).ok_or("It was not possible to get Mitre technique name.")?;
                let external = text(x.get("external_id")).ok_or("It was not possible to get Mitre technique external ID.")?;
                let phases = query(&format!("mitre sql SELECT tactic_id FROM phase WHERE tech_id = '{id}';")).ok_or(UNREADABLE)?;
                if phases.children().is_empty() {
                    return Err(EMPTY);
                }
                let mut tactics = Vec::new();
                for p in phases.children() {
                    let tactic = text(p.get("tactic_id")).ok_or("It was not possible to get MITRE tactic ID.")?;
                    let tj = query(&format!(
                        "mitre sql SELECT tactic.name, reference.external_id FROM tactic LEFT JOIN reference ON tactic.id = reference.id WHERE reference.source = 'mitre-attack' AND tactic.id = '{tactic}';"
                    ))
                    .ok_or(UNREADABLE)?;
                    let first = tj.children().into_iter().next();
                    let name = text(first.and_then(|f| f.get("name"))).ok_or("It was not possible to get Mitre tactic name.")?;
                    let ext = text(first.and_then(|f| f.get("external_id"))).ok_or("It was not possible to get Mitre tactic external ID.")?;
                    tactics.push(Tactic { id: ext, name });
                }
                t.add(Technique { id: external, name, tactics });
            }
            offset += PAGE;
            match query(&techniques_page(offset)) {
                Some(j) if !j.children().is_empty() => page = j,
                _ => return Ok(()),
            }
        }
    }
}
