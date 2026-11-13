//! Builds `var/db/mitre.db` (served as the `mitre` actor) from MITRE ATT&CK's
//! `enterprise-attack.json` (spec § 8): `provigil-mitredb -d <mitre.db> -j <enterprise-attack.json>`.
//! Exit 0 when built; otherwise a message on stdout/stderr, the half-built file removed, exit 1.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::Value;
use provigil_sqlite::{Db, SQLITE_DONE, SQLITE_OK, SQLITE_OPEN_CREATE, SQLITE_OPEN_READWRITE};

/// The tables: name, then `column:kind` with kind `t` text (NULL when absent), `b` boolean
/// (0 when absent), `t!` required text; keys and links as written in `LAYOUT`.
const TABLES: [(&str, &str); 19] = [
    ("metadata", "key:t! value:t!"),
    ("technique", "id:t! name:t! description:t created_time:t modified_time:t mitre_version:t mitre_detection:t network_requirements:b remote_support:b revoked_by:t deprecated:b subtechnique_of:t"),
    ("group", "id:t! name:t! description:t created_time:t modified_time:t mitre_version:t revoked_by:t deprecated:b"),
    ("software", "id:t! name:t! description:t created_time:t modified_time:t mitre_version:t revoked_by:t deprecated:b"),
    ("mitigation", "id:t! name:t! description:t created_time:t modified_time:t mitre_version:t revoked_by:t deprecated:b"),
    ("alias", "id:t! alias:t! type:t!"),
    ("contributor", "id:t! contributor:t! type:t!"),
    ("platform", "id:t! platform:t! type:t!"),
    ("reference", "id:t! source:t! external_id:t url:t! description:t type:t!"),
    ("use", "id:t! source_id:t! source_type:t! target_id:t! target_type:t! description:t created_time:t modified_time:t"),
    ("tactic", "id:t! name:t! description:t created_time:t modified_time:t short_name:t"),
    ("data_source", "id:t! source:t!"),
    ("defense_bypassed", "id:t! defense:t!"),
    ("effective_permission", "id:t! permission:t!"),
    ("impact", "id:t! impact:t!"),
    ("permission", "id:t! permission:t!"),
    ("system_requirement", "id:t! requirement:t!"),
    ("mitigate", "id:t! source_id:t! target_id:t! description:t created_time:t modified_time:t"),
    ("phase", "tactic_id:t! tech_id:t!"),
];

/// Keys and links of each table.
fn constraints(table: &str) -> &'static str {
    match table {
        "metadata" => "PRIMARY KEY (\"key\")",
        "alias" => "PRIMARY KEY (id, alias)",
        "contributor" => "PRIMARY KEY (id, contributor)",
        "platform" => "PRIMARY KEY (id, platform)",
        "reference" => "PRIMARY KEY (id, source, url)",
        "data_source" => "PRIMARY KEY (id, source), FOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE",
        "defense_bypassed" => "PRIMARY KEY (id, defense), FOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE",
        "effective_permission" | "permission" => "PRIMARY KEY (id, permission), FOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE",
        "impact" => "PRIMARY KEY (id, impact), FOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE",
        "system_requirement" => "PRIMARY KEY (id, requirement), FOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE",
        "mitigate" => "PRIMARY KEY (id), FOREIGN KEY(source_id) REFERENCES mitigation (id), FOREIGN KEY(target_id) REFERENCES technique (id)",
        "phase" => "PRIMARY KEY (tactic_id, tech_id), FOREIGN KEY(tactic_id) REFERENCES tactic (id) ON DELETE CASCADE, FOREIGN KEY(tech_id) REFERENCES technique (id) ON DELETE CASCADE",
        _ => "PRIMARY KEY (id)",
    }
}

fn quoted(name: &str) -> String {
    format!("\"{name}\"")
}

/// (name, kind, required) of each column.
fn columns(table: &str) -> Vec<(&'static str, char, bool)> {
    let spec = TABLES.iter().find(|(t, _)| *t == table).map(|(_, c)| *c).unwrap_or("");
    spec.split(' ')
        .map(|c| {
            let (name, kind) = c.split_once(':').unwrap_or((c, "t"));
            (name, kind.chars().next().unwrap_or('t'), kind.ends_with('!'))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq)]
enum V {
    Null,
    Text(String),
    Bool(bool),
}

type Row = HashMap<&'static str, V>;

/// A failure: the message and the half-built file removed.
struct Fail(String);

fn present(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
    }
}

/// A stored value: text as is, booleans as booleans, anything else as its JSON text.
fn value(v: &Value) -> V {
    match v {
        Value::Null => V::Null,
        Value::Bool(b) => V::Bool(*b),
        Value::String(s) => V::Text(s.clone()),
        other => V::Text(other.to_string()),
    }
}

fn field<'a>(o: &'a Value, k: &str) -> Result<&'a Value, Fail> {
    o.get(k).ok_or_else(|| Fail(format!("missing field '{k}'")))
}

fn text(o: &Value, k: &str) -> Result<String, Fail> {
    Ok(match field(o, k)? {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

/// `2017-05-31T21:30:19.735Z` → `2017-05-31 21:30:19.735000`.
fn time(s: &str) -> Result<V, Fail> {
    match chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ") {
        Ok(d) if s.contains('.') => Ok(V::Text(d.format("%Y-%m-%d %H:%M:%S%.6f").to_string())),
        _ => Err(Fail(format!("bad time '{s}' (expected YYYY-MM-DDTHH:MM:SS.fffZ)"))),
    }
}

/// The object kind of an id.
fn kind(id: &str) -> &'static str {
    [("malware", "software"), ("tool", "software"), ("intrusion-set", "group"), ("x-mitre-tactic", "tactic"), ("course-of-action", "mitigation"), ("attack-pattern", "technique")]
        .iter()
        .find(|(p, _)| id.starts_with(p))
        .map(|(_, k)| *k)
        .unwrap_or("")
}

#[derive(Default)]
struct Build {
    rows: HashMap<&'static str, Vec<Row>>,
    phases: Vec<(String, String)>,
    revoked: Vec<(String, String)>,
    parents: Vec<(String, String)>,
}

impl Build {
    fn push(&mut self, table: &'static str, row: Row) {
        self.rows.entry(table).or_default().push(row);
    }

    /// Aliases, contributors, platforms and references of any object.
    fn shared(&mut self, id: &str, o: &Value) {
        let t = V::Text(kind(id).into());
        let mut lists = vec![];
        for (key, table, col) in [("aliases", "alias", "alias"), ("x_mitre_aliases", "alias", "alias"), ("x_mitre_contributors", "contributor", "contributor"), ("x_mitre_platforms", "platform", "platform")] {
            if present(o.get(key)) {
                for v in o[key].as_array().into_iter().flatten() {
                    lists.push((table, Row::from([("id", V::Text(id.into())), (col, value(v)), ("type", t.clone())])));
                }
            }
        }
        for (table, row) in lists {
            self.push(table, row);
        }
        if present(o.get("external_references")) {
            for r in o["external_references"].as_array().into_iter().flatten().filter(|r| present(r.get("url"))) {
                let mut row = Row::from([("id", V::Text(id.into())), ("url", value(&r["url"])), ("type", t.clone())]);
                for (k, col) in [("source_name", "source"), ("external_id", "external_id"), ("description", "description")] {
                    if present(r.get(k)) {
                        row.insert(col, value(&r[k]));
                    }
                }
                self.push("reference", row);
            }
        }
    }

    /// Groups, software, mitigations and tactics: fields taken when the key is there at all.
    fn object(&mut self, table: &'static str, o: &Value) -> Result<(), Fail> {
        let id = text(o, "id")?;
        let mut row = Row::from([("id", V::Text(id.clone())), ("name", value(field(o, "name")?))]);
        if let Some(d) = o.get("description") {
            row.insert("description", value(d));
        }
        for (k, col) in [("created", "created_time"), ("modified", "modified_time")] {
            if let Some(v) = o.get(k) {
                row.insert(col, time(v.as_str().unwrap_or_default())?);
            }
        }
        let extra: &[(&str, &'static str)] = if table == "tactic" { &[("x_mitre_shortname", "short_name")] } else { &[("x_mitre_version", "mitre_version"), ("x_mitre_deprecated", "deprecated")] };
        for (k, col) in extra {
            if let Some(v) = o.get(*k) {
                row.insert(col, value(v));
            }
        }
        self.shared(&id, o);
        self.push(table, row);
        Ok(())
    }

    /// Techniques: fields taken when they have a value; the list fields go to their own tables.
    fn technique(&mut self, o: &Value) -> Result<(), Fail> {
        let id = text(o, "id")?;
        let mut row = Row::from([("id", V::Text(id.clone())), ("name", value(field(o, "name")?))]);
        for (k, col) in [
            ("description", "description"),
            ("x_mitre_version", "mitre_version"),
            ("x_mitre_detection", "mitre_detection"),
            ("x_mitre_network_requirements", "network_requirements"),
            ("x_mitre_remote_support", "remote_support"),
            ("x_mitre_deprecated", "deprecated"),
        ] {
            if present(o.get(k)) {
                row.insert(col, value(&o[k]));
            }
        }
        for (k, col) in [("created", "created_time"), ("modified", "modified_time")] {
            if present(o.get(k)) {
                row.insert(col, time(o[k].as_str().unwrap_or_default())?);
            }
        }
        for (k, table, col) in [
            ("x_mitre_data_sources", "data_source", "source"),
            ("x_mitre_defense_bypassed", "defense_bypassed", "defense"),
            ("x_mitre_effective_permissions", "effective_permission", "permission"),
            ("x_mitre_impact_type", "impact", "impact"),
            ("x_mitre_permissions_required", "permission", "permission"),
            ("x_mitre_system_requirements", "system_requirement", "requirement"),
        ] {
            if present(o.get(k)) {
                // each value once, in sorted order
                let set: BTreeSet<String> = o[k].as_array().into_iter().flatten().map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).collect();
                for v in set {
                    self.push(table, Row::from([("id", V::Text(id.clone())), (col, V::Text(v))]));
                }
            }
        }
        if present(o.get("kill_chain_phases")) {
            for p in o["kill_chain_phases"].as_array().into_iter().flatten() {
                self.phases.push((id.clone(), text(p, "phase_name")?));
            }
        }
        self.shared(&id, o);
        self.push("technique", row);
        Ok(())
    }

    /// `uses` and `mitigates` links.
    fn link(&mut self, table: &'static str, o: &Value) -> Result<(), Fail> {
        let (src, dst) = (text(o, "source_ref")?, text(o, "target_ref")?);
        let mut row = Row::from([
            ("id", value(field(o, "id")?)),
            ("source_type", V::Text(kind(&src).into())),
            ("target_type", V::Text(kind(&dst).into())),
            ("source_id", V::Text(src)),
            ("target_id", V::Text(dst)),
        ]);
        if present(o.get("description")) {
            row.insert("description", value(&o["description"]));
        }
        for (k, col) in [("created", "created_time"), ("modified", "modified_time")] {
            if present(o.get(k)) {
                row.insert(col, time(o[k].as_str().unwrap_or_default())?);
            }
        }
        self.push(table, row);
        Ok(())
    }
}

fn exec(db: &Db, sql: &str) -> Result<(), Fail> {
    match db.exec(sql.as_bytes()) {
        (SQLITE_OK, _) => Ok(()),
        (_, e) => Err(Fail(format!("{}: {sql}", e.map(|e| String::from_utf8_lossy(&e).into_owned()).unwrap_or_default()))),
    }
}

fn insert(db: &Db, table: &str, rows: &[Row]) -> Result<(), Fail> {
    if rows.is_empty() {
        return Ok(());
    }
    let cols = columns(table);
    let names: Vec<&str> = cols.iter().map(|c| c.0).collect();
    let sql = format!("INSERT INTO {} ({}) VALUES ({})", quoted(table), names.join(", "), vec!["?"; names.len()].join(", "));
    let (rc, st, _) = db.prepare_v2(sql.as_bytes());
    let st = st.filter(|_| rc == SQLITE_OK).ok_or_else(|| Fail(format!("{}: {sql}", db.errmsg_str())))?;
    for row in rows {
        st.reset();
        st.clear_bindings();
        for (i, (name, k, _)) in cols.iter().enumerate() {
            let i = i as i32 + 1;
            let absent = if *k == 'b' { V::Bool(false) } else { V::Null };
            match row.get(name).cloned().unwrap_or(absent) {
                V::Null => st.bind_null(i),
                V::Text(s) => st.bind_text(i, Some(s.as_bytes())),
                V::Bool(b) => st.bind_int(i, b as i32),
            };
        }
        if st.step() != SQLITE_DONE {
            return Err(Fail(format!("{table}: {}", db.errmsg_str())));
        }
    }
    Ok(())
}

fn set_link(db: &Db, sql: &str, value: &str, id: &str) -> Result<(), Fail> {
    let (rc, st, _) = db.prepare_v2(sql.as_bytes());
    let st = st.filter(|_| rc == SQLITE_OK).ok_or_else(|| Fail(format!("{}: {sql}", db.errmsg_str())))?;
    st.bind_text(1, Some(value.as_bytes()));
    st.bind_text(2, Some(id.as_bytes()));
    if st.step() != SQLITE_DONE {
        return Err(Fail(db.errmsg_str()));
    }
    if db.changes() == 0 {
        return Err(Fail(format!("{id}: no such object for the relationship")));
    }
    Ok(())
}

fn build(database: &Path, json: &Path) -> Result<(), Fail> {
    let raw = std::fs::read(json).map_err(|e| Fail(format!("{}: {e}", json.display())))?;
    let data: Value = serde_json::from_slice(&raw).map_err(|e| Fail(format!("{}: {e}", json.display())))?;
    let mut b = Build::default();
    b.push("metadata", Row::from([("key", V::Text("db_version".into())), ("value", V::Text("1".into()))]));
    b.push("metadata", Row::from([("key", V::Text("mitre_version".into())), ("value", value(field(&data, "spec_version")?))]));
    for o in field(&data, "objects")?.as_array().into_iter().flatten() {
        match text(o, "type")?.as_str() {
            "intrusion-set" => b.object("group", o)?,
            "course-of-action" => b.object("mitigation", o)?,
            "malware" | "tool" => b.object("software", o)?,
            "x-mitre-tactic" => b.object("tactic", o)?,
            "attack-pattern" => b.technique(o)?,
            "relationship" => match o.get("relationship_type").and_then(Value::as_str) {
                Some("revoked-by") => b.revoked.push((text(o, "source_ref")?, text(o, "target_ref")?)),
                Some("subtechnique-of") => b.parents.push((text(o, "source_ref")?, text(o, "target_ref")?)),
                Some("mitigates") => b.link("mitigate", o)?,
                Some("uses") => b.link("use", o)?,
                _ => {}
            },
            _ => {}
        }
    }
    // each phase name belongs to the first tactic with that short name
    let mut tactic_of: HashMap<String, String> = HashMap::new();
    for t in b.rows.get("tactic").into_iter().flatten() {
        if let (Some(V::Text(short)), Some(V::Text(id))) = (t.get("short_name"), t.get("id")) {
            tactic_of.entry(short.clone()).or_insert_with(|| id.clone());
        }
    }
    let mut phases = Vec::new();
    for (tech, short) in &b.phases {
        let tactic = tactic_of.get(short).ok_or_else(|| Fail(format!("no tactic named '{short}'")))?;
        phases.push(Row::from([("tech_id", V::Text(tech.clone())), ("tactic_id", V::Text(tactic.clone()))]));
    }

    let mut path = database.to_string_lossy().into_owned().into_bytes();
    path.push(0);
    let (rc, db) = Db::open_v2(&path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    let db = db.filter(|_| rc == SQLITE_OK).ok_or_else(|| Fail("unable to open database file".into()))?;
    for (t, _) in TABLES.iter().rev() {
        exec(&db, &format!("DROP TABLE IF EXISTS {}", quoted(t)))?;
    }
    for (t, _) in TABLES {
        let cols: Vec<String> = columns(t)
            .iter()
            .map(|(n, k, required)| {
                let ty = if *k == 'b' { "BOOLEAN" } else if n.ends_with("_time") { "DATETIME" } else { "VARCHAR" };
                format!("{} {ty}{}", quoted(n), if *required { " NOT NULL" } else { "" })
            })
            .collect();
        exec(&db, &format!("CREATE TABLE {} ({}, {})", quoted(t), cols.join(", "), constraints(t)))?;
    }
    let none = Vec::new();
    let rows = |t: &str| b.rows.get(t).unwrap_or(&none);
    exec(&db, "BEGIN")?;
    for t in ["metadata", "technique", "data_source", "defense_bypassed", "effective_permission", "impact", "permission", "system_requirement", "group", "mitigation", "software", "tactic"] {
        insert(&db, t, rows(t))?;
    }
    insert(&db, "phase", &phases)?;
    for (src, dst) in &b.revoked {
        let table = match kind(src) {
            k @ ("group" | "mitigation" | "software" | "technique") => k,
            _ => continue,
        };
        set_link(&db, &format!("UPDATE {} SET revoked_by=? WHERE id = ?", quoted(table)), dst, src)?;
    }
    for (src, dst) in &b.parents {
        set_link(&db, "UPDATE technique SET subtechnique_of=? WHERE id = ?", dst, src)?;
    }
    for t in ["mitigate", "use", "alias", "contributor", "platform", "reference"] {
        insert(&db, t, rows(t))?;
    }
    exec(&db, "COMMIT")?;
    Ok(())
}

fn main() {
    let (mut database, mut json): (Option<PathBuf>, Option<PathBuf>) = (None, None);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-d" | "--database" => database = args.next().map(PathBuf::from),
            "-j" | "--json" => json = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!("usage: provigil-mitredb -d <mitre.db> -j <enterprise-attack.json>");
                return;
            }
            other => {
                eprintln!("provigil-mitredb: unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let (Some(database), Some(json)) = (database, json) else {
        eprintln!("provigil-mitredb: -d <mitre.db> and -j <enterprise-attack.json> are both needed");
        std::process::exit(2);
    };
    if let Some(dir) = database.parent().filter(|d| !d.as_os_str().is_empty() && !d.is_dir()) {
        eprintln!("provigil-mitredb: folder not found: {}", dir.display());
        std::process::exit(1);
    }
    if let Err(Fail(msg)) = build(&database, &json) {
        println!("{msg}");
        println!("Deleting {}", database.display());
        let _ = std::fs::remove_file(&database);
        std::process::exit(1);
    }
}
