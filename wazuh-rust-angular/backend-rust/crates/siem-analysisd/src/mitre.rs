//! MITRE ATT&CK lookup (`mitre.c`): technique external id -> name and the
//! ordered list of its tactics, loaded from wazuh-db's `mitre` database.

use std::collections::HashMap;

use siem_cjson::Json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tactic {
    /// External id (e.g. "TA0006").
    pub tactic_id: String,
    pub tactic_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Technique {
    /// External id (e.g. "T1110").
    pub technique_id: String,
    pub technique_name: String,
    pub tactics: Vec<Tactic>,
}

#[derive(Debug, Clone, Default)]
pub struct MitreDb {
    pub techniques: HashMap<String, Technique>,
}

impl MitreDb {
    /// `mitre_get_attack`
    pub fn get_attack(&self, id: &str) -> Option<&Technique> {
        self.techniques.get(id)
    }

    /// `OSHash_Add` keeps the first technique stored under an id.
    pub fn add(&mut self, t: Technique) {
        self.techniques.entry(t.technique_id.clone()).or_insert(t);
    }

    /// `mitre_load`. `query` is `wdbc_query_parse_json` (None when the
    /// query failed or the reply is not "ok <json>"; it logs its own errors).
    /// Errors go to `log`. Like the C code, a failure part way leaves the
    /// techniques stored so far in the table (None only when the table was
    /// never created).
    pub fn load(query: &mut dyn FnMut(&str) -> Option<Json>, log: &mut Vec<String>) -> Option<MitreDb> {
        let mut db: Option<MitreDb> = None;
        if let Err(e) = Self::load_into(query, &mut db) {
            log.push(e.into());
            log.push("Mitre matrix information could not be loaded.".into());
        }
        db
    }

    fn load_into(query: &mut dyn FnMut(&str) -> Option<Json>, db: &mut Option<MitreDb>) -> Result<(), &'static str> {
        const PARSE: &str = "Response from the Mitre database cannot be parsed.";
        const EMPTY: &str = "Response from the Mitre database has 0 elements.";
        let vs = |j: Option<&Json>| -> Option<String> {
            // ->valuestring
            j.map(|v| v.as_bytes().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default())
        };
        let mut offset = 0;
        let mut techniques = query(&sql_all_techniques(offset)).ok_or(PARSE)?;
        if techniques.children().is_empty() {
            return Err(EMPTY);
        }
        let table = db.insert(MitreDb::default());
        loop {
            for t in techniques.children() {
                let tech_id = vs(t.get("id")).ok_or("It was not possible to get Mitre technique ID.")?;
                let tech_name = vs(t.get("name")).ok_or("It was not possible to get Mitre technique name.")?;
                let tech_ext = vs(t.get("external_id")).ok_or("It was not possible to get Mitre technique external ID.")?;
                let phases = query(&format!("mitre sql SELECT tactic_id FROM phase WHERE tech_id = '{tech_id}';")).ok_or(PARSE)?;
                let phases = phases.children();
                if phases.is_empty() {
                    return Err(EMPTY);
                }
                let mut tactics = Vec::new();
                for p in phases {
                    let tactic_id = vs(p.get("tactic_id")).ok_or("It was not possible to get MITRE tactic ID.")?;
                    let tj = query(&format!(
                        "mitre sql SELECT tactic.name, reference.external_id FROM tactic LEFT JOIN reference ON tactic.id = reference.id WHERE reference.source = 'mitre-attack' AND tactic.id = '{tactic_id}';"
                    ))
                    .ok_or(PARSE)?;
                    let first = tj.children().into_iter().next();
                    let name = vs(first.and_then(|f| f.get("name"))).ok_or("It was not possible to get Mitre tactic name.")?;
                    let ext = vs(first.and_then(|f| f.get("external_id"))).ok_or("It was not possible to get Mitre tactic external ID.")?;
                    tactics.push(Tactic { tactic_id: ext, tactic_name: name });
                }
                table.add(Technique { technique_id: tech_ext, technique_name: tech_name, tactics });
            }
            offset += MAX_TECHNIQUES_REQUEST;
            match query(&sql_all_techniques(offset)) {
                Some(j) if !j.children().is_empty() => techniques = j,
                _ => return Ok(()),
            }
        }
    }
}

const MAX_TECHNIQUES_REQUEST: i32 = 100;

/// `SQL_GET_ALL_TECHNIQUES`
fn sql_all_techniques(offset: i32) -> String {
    format!(
        "mitre sql SELECT technique.id, technique.name, reference.external_id FROM technique LEFT JOIN reference ON technique.id = reference.id WHERE technique.revoked_by IS NULL AND NOT technique.deprecated AND reference.source = 'mitre-attack' LIMIT {MAX_TECHNIQUES_REQUEST} OFFSET {offset};"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(q: &str) -> Option<Json> {
        let r = if q.contains("OFFSET 0;") {
            r#"[{"id":"attack-pattern--1","name":"Brute Force","external_id":"T1110"},{"id":"attack-pattern--2","name":"Bad","external_id":"T9999"}]"#
        } else if q.contains("OFFSET") {
            "[]"
        } else if q.contains("tech_id = 'attack-pattern--1'") {
            r#"[{"tactic_id":"x-mitre-tactic--1"}]"#
        } else if q.contains("tech_id = 'attack-pattern--2'") {
            "[]"
        } else {
            r#"[{"name":"Credential Access","external_id":"TA0006"}]"#
        };
        siem_cjson::parse(r.as_bytes())
    }

    #[test]
    fn partial_table_survives_an_error() {
        let mut log = Vec::new();
        let db = MitreDb::load(&mut fake, &mut log).unwrap();
        assert_eq!(db.get_attack("T1110").unwrap().tactics[0].tactic_id, "TA0006");
        assert!(db.get_attack("T9999").is_none());
        assert_eq!(log, ["Response from the Mitre database has 0 elements.", "Mitre matrix information could not be loaded."]);
    }
}
