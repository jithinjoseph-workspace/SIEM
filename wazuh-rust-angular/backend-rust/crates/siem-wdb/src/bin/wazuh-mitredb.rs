//! `tools/mitre/mitredb.py`: builds `var/db/mitre.db` (the database
//! wazuh-db serves as "mitre") from MITRE ATT&CK's `enterprise-attack.json`.
//!
//! `wazuh-mitredb [-d <mitre.db>] [-j <enterprise-attack.json>]`
//!
//! The schema is what SQLAlchemy's `create_all` emits for the script's
//! models on SQLite (VARCHAR / DATETIME / BOOLEAN), the rows what its
//! `bulk_insert_mappings` stores: the Python-side column defaults (NULL,
//! or 0 for the booleans) and DATETIME as "YYYY-MM-DD HH:MM:SS.ffffff".

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::Value;
use siem_sqlite::{Db, SQLITE_DONE, SQLITE_OK, SQLITE_OPEN_CREATE, SQLITE_OPEN_READWRITE};

/// `Base.metadata.drop_all` + `create_all`
const SCHEMA: &[&str] = &[
    "DROP TABLE IF EXISTS phase",
    "DROP TABLE IF EXISTS mitigate",
    "DROP TABLE IF EXISTS data_source",
    "DROP TABLE IF EXISTS defense_bypassed",
    "DROP TABLE IF EXISTS effective_permission",
    "DROP TABLE IF EXISTS impact",
    "DROP TABLE IF EXISTS permission",
    "DROP TABLE IF EXISTS system_requirement",
    "DROP TABLE IF EXISTS metadata",
    "DROP TABLE IF EXISTS technique",
    "DROP TABLE IF EXISTS \"group\"",
    "DROP TABLE IF EXISTS software",
    "DROP TABLE IF EXISTS mitigation",
    "DROP TABLE IF EXISTS alias",
    "DROP TABLE IF EXISTS contributor",
    "DROP TABLE IF EXISTS platform",
    "DROP TABLE IF EXISTS reference",
    "DROP TABLE IF EXISTS use",
    "DROP TABLE IF EXISTS tactic",
    "CREATE TABLE metadata (\n\t\"key\" VARCHAR NOT NULL, \n\tvalue VARCHAR NOT NULL, \n\tPRIMARY KEY (\"key\")\n)",
    "CREATE TABLE technique (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tmitre_version VARCHAR, \n\tmitre_detection VARCHAR, \n\tnetwork_requirements BOOLEAN, \n\tremote_support BOOLEAN, \n\trevoked_by VARCHAR, \n\tdeprecated BOOLEAN, \n\tsubtechnique_of VARCHAR, \n\tPRIMARY KEY (id)\n)",
    "CREATE TABLE \"group\" (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tmitre_version VARCHAR, \n\trevoked_by VARCHAR, \n\tdeprecated BOOLEAN, \n\tPRIMARY KEY (id)\n)",
    "CREATE TABLE software (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tmitre_version VARCHAR, \n\trevoked_by VARCHAR, \n\tdeprecated BOOLEAN, \n\tPRIMARY KEY (id)\n)",
    "CREATE TABLE mitigation (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tmitre_version VARCHAR, \n\trevoked_by VARCHAR, \n\tdeprecated BOOLEAN, \n\tPRIMARY KEY (id)\n)",
    "CREATE TABLE alias (\n\tid VARCHAR NOT NULL, \n\talias VARCHAR NOT NULL, \n\ttype VARCHAR NOT NULL, \n\tPRIMARY KEY (id, alias)\n)",
    "CREATE TABLE contributor (\n\tid VARCHAR NOT NULL, \n\tcontributor VARCHAR NOT NULL, \n\ttype VARCHAR NOT NULL, \n\tPRIMARY KEY (id, contributor)\n)",
    "CREATE TABLE platform (\n\tid VARCHAR NOT NULL, \n\tplatform VARCHAR NOT NULL, \n\ttype VARCHAR NOT NULL, \n\tPRIMARY KEY (id, platform)\n)",
    "CREATE TABLE reference (\n\tid VARCHAR NOT NULL, \n\tsource VARCHAR NOT NULL, \n\texternal_id VARCHAR, \n\turl VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\ttype VARCHAR NOT NULL, \n\tPRIMARY KEY (id, source, url)\n)",
    "CREATE TABLE use (\n\tid VARCHAR NOT NULL, \n\tsource_id VARCHAR NOT NULL, \n\tsource_type VARCHAR NOT NULL, \n\ttarget_id VARCHAR NOT NULL, \n\ttarget_type VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tPRIMARY KEY (id)\n)",
    "CREATE TABLE tactic (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tshort_name VARCHAR, \n\tPRIMARY KEY (id)\n)",
    "CREATE TABLE data_source (\n\tid VARCHAR NOT NULL, \n\tsource VARCHAR NOT NULL, \n\tPRIMARY KEY (id, source), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)",
    "CREATE TABLE defense_bypassed (\n\tid VARCHAR NOT NULL, \n\tdefense VARCHAR NOT NULL, \n\tPRIMARY KEY (id, defense), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)",
    "CREATE TABLE effective_permission (\n\tid VARCHAR NOT NULL, \n\tpermission VARCHAR NOT NULL, \n\tPRIMARY KEY (id, permission), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)",
    "CREATE TABLE impact (\n\tid VARCHAR NOT NULL, \n\timpact VARCHAR NOT NULL, \n\tPRIMARY KEY (id, impact), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)",
    "CREATE TABLE permission (\n\tid VARCHAR NOT NULL, \n\tpermission VARCHAR NOT NULL, \n\tPRIMARY KEY (id, permission), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)",
    "CREATE TABLE system_requirement (\n\tid VARCHAR NOT NULL, \n\trequirement VARCHAR NOT NULL, \n\tPRIMARY KEY (id, requirement), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)",
    "CREATE TABLE mitigate (\n\tid VARCHAR NOT NULL, \n\tsource_id VARCHAR NOT NULL, \n\ttarget_id VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(source_id) REFERENCES mitigation (id), \n\tFOREIGN KEY(target_id) REFERENCES technique (id)\n)",
    "CREATE TABLE phase (\n\ttactic_id VARCHAR NOT NULL, \n\ttech_id VARCHAR NOT NULL, \n\tPRIMARY KEY (tactic_id, tech_id), \n\tFOREIGN KEY(tactic_id) REFERENCES tactic (id) ON DELETE CASCADE, \n\tFOREIGN KEY(tech_id) REFERENCES technique (id) ON DELETE CASCADE\n)",
];

/// A column value as SQLAlchemy binds it.
#[derive(Debug, Clone)]
enum V {
    Null,
    Text(String),
    Bool(bool),
}

/// `bulk_insert_mappings`: one table, its columns and their defaults.
struct Table {
    name: &'static str,
    cols: &'static [(&'static str, Default)],
    rows: Vec<HashMap<&'static str, V>>,
}

#[derive(Clone, Copy)]
enum Default {
    /// `default=None` (or no default: the key is always set)
    Null,
    /// `default=False`
    False,
}

impl Table {
    fn new(name: &'static str, cols: &'static [(&'static str, Default)]) -> Self {
        Table { name, cols, rows: Vec::new() }
    }
}

const COMMON: &[(&str, Default)] = &[
    ("id", Default::Null),
    ("name", Default::Null),
    ("description", Default::Null),
    ("created_time", Default::Null),
    ("modified_time", Default::Null),
    ("mitre_version", Default::Null),
    ("revoked_by", Default::Null),
    ("deprecated", Default::False),
];

fn die(database: &Path, msg: &str) -> ! {
    // except TypeError / KeyError / NameError: print, delete, exit(1)
    println!("{msg}");
    println!("Deleting {}", database.display());
    let _ = std::fs::remove_file(database);
    std::process::exit(1);
}

/// `core_utils.get_utc_strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ')`, stored the
/// way SQLAlchemy's SQLite DATETIME stores it.
fn utc_strptime(database: &Path, s: &str) -> String {
    match chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ") {
        Ok(d) if s.contains('.') => d.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
        _ => die(database, &format!("time data '{s}' does not match format '%Y-%m-%dT%H:%M:%S.%fZ'")),
    }
}

/// `get_type`
fn get_type(object_id: &str) -> &'static str {
    if object_id.starts_with("malware") || object_id.starts_with("tool") {
        "software"
    } else if object_id.starts_with("intrusion-set") {
        "group"
    } else if object_id.starts_with("x-mitre-tactic") {
        "tactic"
    } else if object_id.starts_with("course-of-action") {
        "mitigation"
    } else if object_id.starts_with("attack-pattern") {
        "technique"
    } else {
        ""
    }
}

/// Python truthiness of `dict.get(key)`.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
    }
}

/// A stored value: strings as they are, booleans as booleans, anything
/// else as its JSON text (SQLAlchemy would reject it; the data has none).
fn val(v: &Value) -> V {
    match v {
        Value::Null => V::Null,
        Value::Bool(b) => V::Bool(*b),
        Value::String(s) => V::Text(s.clone()),
        other => V::Text(other.to_string()),
    }
}

fn get<'a>(database: &Path, o: &'a Value, k: &str) -> &'a Value {
    o.get(k).unwrap_or_else(|| die(database, &format!("'{k}'")))
}

fn text(database: &Path, o: &Value, k: &str) -> String {
    match get(database, o, k) {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

struct Lists {
    data_source: Table,
    defense_bypassed: Table,
    effective_permission: Table,
    impact: Table,
    permission: Table,
    system_requirement: Table,
    mitigate: Table,
    use_: Table,
    alias: Table,
    contributor: Table,
    platform: Table,
    reference: Table,
}

/// `parse_common_tables`
fn parse_common_tables(l: &mut Lists, parent_id: &str, o: &Value) {
    for key in ["aliases", "x_mitre_aliases"] {
        if truthy(o.get(key)) {
            for a in o[key].as_array().into_iter().flatten() {
                l.alias.rows.push(HashMap::from([("id", V::Text(parent_id.into())), ("alias", val(a)), ("type", V::Text(get_type(parent_id).into()))]));
            }
        }
    }
    if truthy(o.get("x_mitre_contributors")) {
        for c in o["x_mitre_contributors"].as_array().into_iter().flatten() {
            l.contributor.rows.push(HashMap::from([("id", V::Text(parent_id.into())), ("contributor", val(c)), ("type", V::Text(get_type(parent_id).into()))]));
        }
    }
    if truthy(o.get("x_mitre_platforms")) {
        for p in o["x_mitre_platforms"].as_array().into_iter().flatten() {
            l.platform.rows.push(HashMap::from([("id", V::Text(parent_id.into())), ("platform", val(p)), ("type", V::Text(get_type(parent_id).into()))]));
        }
    }
    if truthy(o.get("external_references")) {
        for r in o["external_references"].as_array().into_iter().flatten() {
            if truthy(r.get("url")) {
                // parse_json_ext_references
                let mut row = HashMap::new();
                if truthy(r.get("source_name")) {
                    row.insert("source", val(&r["source_name"]));
                }
                if truthy(r.get("external_id")) {
                    row.insert("external_id", val(&r["external_id"]));
                }
                row.insert("url", val(&r["url"]));
                if truthy(r.get("description")) {
                    row.insert("description", val(&r["description"]));
                }
                row.insert("id", V::Text(parent_id.into()));
                row.insert("type", V::Text(get_type(parent_id).into()));
                l.reference.rows.push(row);
            }
        }
    }
}

/// `parse_table` (Group, Software, Mitigation, Tactic)
fn parse_table(database: &Path, l: &mut Lists, kind: &str, o: &Value) -> HashMap<&'static str, V> {
    let mut row = HashMap::new();
    let id = text(database, o, "id");
    row.insert("id", V::Text(id.clone()));
    row.insert("name", val(get(database, o, "name")));
    if let Some(d) = o.get("description") {
        row.insert("description", val(d));
    }
    if let Some(c) = o.get("created") {
        row.insert("created_time", V::Text(utc_strptime(database, c.as_str().unwrap_or_default())));
    }
    if let Some(m) = o.get("modified") {
        row.insert("modified_time", V::Text(utc_strptime(database, m.as_str().unwrap_or_default())));
    }
    if kind == "Tactic" {
        if let Some(s) = o.get("x_mitre_shortname") {
            row.insert("short_name", val(s));
        }
    } else {
        if let Some(v) = o.get("x_mitre_version") {
            row.insert("mitre_version", val(v));
        }
        if let Some(d) = o.get("x_mitre_deprecated") {
            row.insert("deprecated", val(d));
        }
    }
    parse_common_tables(l, &id, o);
    row
}

/// `parse_json_techniques`
fn parse_json_techniques(database: &Path, l: &mut Lists, o: &Value, phases: &mut Vec<(String, String)>) -> HashMap<&'static str, V> {
    let mut row = HashMap::new();
    let id = text(database, o, "id");
    row.insert("id", V::Text(id.clone()));
    row.insert("name", val(get(database, o, "name")));
    let opt = |row: &mut HashMap<&'static str, V>, j: &str, t: &'static str| {
        if truthy(o.get(j)) {
            row.insert(t, val(&o[j]));
        }
    };
    opt(&mut row, "description", "description");
    if truthy(o.get("created")) {
        row.insert("created_time", V::Text(utc_strptime(database, o["created"].as_str().unwrap_or_default())));
    }
    if truthy(o.get("modified")) {
        row.insert("modified_time", V::Text(utc_strptime(database, o["modified"].as_str().unwrap_or_default())));
    }
    opt(&mut row, "x_mitre_version", "mitre_version");
    opt(&mut row, "x_mitre_detection", "mitre_detection");
    opt(&mut row, "x_mitre_network_requirements", "network_requirements");
    opt(&mut row, "x_mitre_remote_support", "remote_support");
    opt(&mut row, "x_mitre_deprecated", "deprecated");
    let multi = |j: &str, table: &mut Table, col: &'static str| {
        if truthy(o.get(j)) {
            // list(set(...)): each value once
            let set: BTreeSet<String> = o[j].as_array().into_iter().flatten().map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).collect();
            for v in set {
                table.rows.push(HashMap::from([("id", V::Text(id.clone())), (col, V::Text(v))]));
            }
        }
    };
    multi("x_mitre_data_sources", &mut l.data_source, "source");
    multi("x_mitre_defense_bypassed", &mut l.defense_bypassed, "defense");
    multi("x_mitre_effective_permissions", &mut l.effective_permission, "permission");
    multi("x_mitre_impact_type", &mut l.impact, "impact");
    multi("x_mitre_permissions_required", &mut l.permission, "permission");
    multi("x_mitre_system_requirements", &mut l.system_requirement, "requirement");
    if truthy(o.get("kill_chain_phases")) {
        for p in o["kill_chain_phases"].as_array().into_iter().flatten() {
            phases.push((id.clone(), text(database, p, "phase_name")));
        }
    }
    parse_common_tables(l, &id, o);
    row
}

/// `parse_json_mitigate_use`
fn parse_json_mitigate_use(database: &Path, o: &Value) -> HashMap<&'static str, V> {
    let mut row = HashMap::new();
    let src = text(database, o, "source_ref");
    let dst = text(database, o, "target_ref");
    row.insert("id", val(get(database, o, "id")));
    row.insert("source_type", V::Text(get_type(&src).into()));
    row.insert("target_type", V::Text(get_type(&dst).into()));
    row.insert("source_id", V::Text(src));
    row.insert("target_id", V::Text(dst));
    if truthy(o.get("description")) {
        row.insert("description", val(&o["description"]));
    }
    if truthy(o.get("created")) {
        row.insert("created_time", V::Text(utc_strptime(database, o["created"].as_str().unwrap_or_default())));
    }
    if truthy(o.get("modified")) {
        row.insert("modified_time", V::Text(utc_strptime(database, o["modified"].as_str().unwrap_or_default())));
    }
    row
}

fn exec(db: &Db, database: &Path, sql: &str) {
    let (rc, err) = db.exec(sql.as_bytes());
    if rc != SQLITE_OK {
        let e = err.map(|e| String::from_utf8_lossy(&e).into_owned()).unwrap_or_default();
        die(database, &format!("{e}: {sql}"));
    }
}

/// `session.bulk_insert_mappings(Model, rows)`: unknown keys are ignored,
/// missing columns take the model default.
fn insert(db: &Db, database: &Path, t: &Table) {
    if t.rows.is_empty() {
        return;
    }
    let cols: Vec<&str> = t.cols.iter().map(|(c, _)| *c).collect();
    let quoted = if t.name == "group" { "\"group\"".to_string() } else { t.name.to_string() };
    let sql = format!("INSERT INTO {quoted} ({}) VALUES ({})", cols.join(", "), vec!["?"; cols.len()].join(", "));
    let (rc, stmt, _) = db.prepare_v2(sql.as_bytes());
    let Some(stmt) = stmt.filter(|_| rc == SQLITE_OK) else {
        die(database, &format!("{}: {sql}", db.errmsg_str()));
    };
    for row in &t.rows {
        stmt.reset();
        stmt.clear_bindings();
        for (i, (c, d)) in t.cols.iter().enumerate() {
            let idx = i as i32 + 1;
            match row.get(c).cloned().unwrap_or(match d {
                Default::Null => V::Null,
                Default::False => V::Bool(false),
            }) {
                V::Null => stmt.bind_null(idx),
                V::Text(s) => stmt.bind_text(idx, Some(s.as_bytes())),
                V::Bool(b) => stmt.bind_int(idx, b as i32),
            };
        }
        if stmt.step() != SQLITE_DONE {
            // sqlalchemy.exc.IntegrityError and the like are not caught by the script
            eprintln!("(sqlite3.IntegrityError) {}", db.errmsg_str());
            std::process::exit(1);
        }
    }
}

/// `find('enterprise-attack.json', '../..')`
fn find(name: &str, path: &Path) -> Option<PathBuf> {
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut subdirs = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                subdirs.push(p);
            } else if e.file_name() == name {
                return Some(p);
            }
        }
        subdirs.reverse();
        stack.extend(subdirs);
    }
    None
}

fn main() {
    let mut database: Option<PathBuf> = None;
    let mut json: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-d" | "--database" => database = args.next().map(PathBuf::from),
            "-j" | "--json" => json = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!("usage: wazuh-mitredb [-h] [--database DATABASE] [--json JSON]");
                println!();
                println!("This script installs mitre.db in a directory.");
                return;
            }
            other => {
                eprintln!("wazuh-mitredb: error: unrecognized arguments: {other}");
                std::process::exit(2);
            }
        }
    }
    let database = match database {
        None => PathBuf::from("/var/ossec/var/db/mitre.db"),
        Some(d) => {
            let parent = d.parent().map(Path::to_path_buf).unwrap_or_default();
            if !parent.as_os_str().is_empty() && !parent.is_dir() {
                eprintln!("Exception: Error: Directory not found.");
                std::process::exit(1);
            }
            d
        }
    };
    let pathfile = json.or_else(|| find("enterprise-attack.json", Path::new("../.."))).unwrap_or_else(|| {
        eprintln!("TypeError: expected str, bytes or os.PathLike object, not NoneType");
        std::process::exit(1);
    });

    let mut path_c = database.to_string_lossy().into_owned().into_bytes();
    path_c.push(0);
    let (rc, db) = Db::open_v2(&path_c, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    let Some(db) = db.filter(|_| rc == SQLITE_OK) else {
        eprintln!("(sqlite3.OperationalError) unable to open database file");
        std::process::exit(1);
    };
    for s in SCHEMA {
        exec(&db, &database, s);
    }

    // parse_json
    let raw = std::fs::read(&pathfile).unwrap_or_else(|e| {
        eprintln!("FileNotFoundError: {e}: '{}'", pathfile.display());
        std::process::exit(1);
    });
    let datajson: Value = serde_json::from_slice(&raw).unwrap_or_else(|e| {
        eprintln!("json.decoder.JSONDecodeError: {e}");
        std::process::exit(1);
    });

    let mut l = Lists {
        data_source: Table::new("data_source", &[("id", Default::Null), ("source", Default::Null)]),
        defense_bypassed: Table::new("defense_bypassed", &[("id", Default::Null), ("defense", Default::Null)]),
        effective_permission: Table::new("effective_permission", &[("id", Default::Null), ("permission", Default::Null)]),
        impact: Table::new("impact", &[("id", Default::Null), ("impact", Default::Null)]),
        permission: Table::new("permission", &[("id", Default::Null), ("permission", Default::Null)]),
        system_requirement: Table::new("system_requirement", &[("id", Default::Null), ("requirement", Default::Null)]),
        mitigate: Table::new(
            "mitigate",
            &[("id", Default::Null), ("source_id", Default::Null), ("target_id", Default::Null), ("description", Default::Null), ("created_time", Default::Null), ("modified_time", Default::Null)],
        ),
        use_: Table::new(
            "use",
            &[
                ("id", Default::Null),
                ("source_id", Default::Null),
                ("source_type", Default::Null),
                ("target_id", Default::Null),
                ("target_type", Default::Null),
                ("description", Default::Null),
                ("created_time", Default::Null),
                ("modified_time", Default::Null),
            ],
        ),
        alias: Table::new("alias", &[("id", Default::Null), ("alias", Default::Null), ("type", Default::Null)]),
        contributor: Table::new("contributor", &[("id", Default::Null), ("contributor", Default::Null), ("type", Default::Null)]),
        platform: Table::new("platform", &[("id", Default::Null), ("platform", Default::Null), ("type", Default::Null)]),
        reference: Table::new(
            "reference",
            &[("id", Default::Null), ("source", Default::Null), ("external_id", Default::Null), ("url", Default::Null), ("description", Default::Null), ("type", Default::Null)],
        ),
    };
    let mut techniques = Table::new(
        "technique",
        &[
            ("id", Default::Null),
            ("name", Default::Null),
            ("description", Default::Null),
            ("created_time", Default::Null),
            ("modified_time", Default::Null),
            ("mitre_version", Default::Null),
            ("mitre_detection", Default::Null),
            ("network_requirements", Default::False),
            ("remote_support", Default::False),
            ("revoked_by", Default::Null),
            ("deprecated", Default::False),
            ("subtechnique_of", Default::Null),
        ],
    );
    let mut groups = Table::new("group", COMMON);
    let mut mitigations = Table::new("mitigation", COMMON);
    let mut softwares = Table::new("software", COMMON);
    let mut tactics = Table::new(
        "tactic",
        &[("id", Default::Null), ("name", Default::Null), ("description", Default::Null), ("created_time", Default::Null), ("modified_time", Default::Null), ("short_name", Default::Null)],
    );
    let mut phases: Vec<(String, String)> = Vec::new();
    let mut revoked_by: Vec<(String, String)> = Vec::new();
    let mut subtechnique_of: Vec<(String, String)> = Vec::new();

    let mut metadata = Table::new("metadata", &[("key", Default::Null), ("value", Default::Null)]);
    metadata.rows.push(HashMap::from([("key", V::Text("db_version".into())), ("value", V::Text("1".into()))]));
    metadata.rows.push(HashMap::from([("key", V::Text("mitre_version".into())), ("value", val(get(&database, &datajson, "spec_version")))]));

    let objects = get(&database, &datajson, "objects").as_array().cloned().unwrap_or_default();
    for o in &objects {
        let ty = text(&database, o, "type");
        match ty.as_str() {
            "intrusion-set" => groups.rows.push(parse_table(&database, &mut l, "Group", o)),
            "course-of-action" => mitigations.rows.push(parse_table(&database, &mut l, "Mitigation", o)),
            "malware" | "tool" => softwares.rows.push(parse_table(&database, &mut l, "Software", o)),
            "x-mitre-tactic" => tactics.rows.push(parse_table(&database, &mut l, "Tactic", o)),
            "attack-pattern" => techniques.rows.push(parse_json_techniques(&database, &mut l, o, &mut phases)),
            "relationship" => {
                // parse_json_relationships
                match o.get("relationship_type").and_then(|v| v.as_str()) {
                    Some("revoked-by") => revoked_by.push((text(&database, o, "source_ref"), text(&database, o, "target_ref"))),
                    Some("subtechnique-of") => subtechnique_of.push((text(&database, o, "source_ref"), text(&database, o, "target_ref"))),
                    Some("mitigates") => l.mitigate.rows.push(parse_json_mitigate_use(&database, o)),
                    Some("uses") => l.use_.rows.push(parse_json_mitigate_use(&database, o)),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    exec(&db, &database, "BEGIN");
    insert(&db, &database, &metadata);
    insert(&db, &database, &techniques);
    insert(&db, &database, &l.data_source);
    insert(&db, &database, &l.defense_bypassed);
    insert(&db, &database, &l.effective_permission);
    insert(&db, &database, &l.impact);
    insert(&db, &database, &l.permission);
    insert(&db, &database, &l.system_requirement);
    insert(&db, &database, &groups);
    insert(&db, &database, &mitigations);
    insert(&db, &database, &softwares);
    insert(&db, &database, &tactics);
    exec(&db, &database, "COMMIT");

    // parse_list_phases: the first tactic with that short name
    let mut tactic_by_short: HashMap<String, String> = HashMap::new();
    for t in &tactics.rows {
        if let (Some(V::Text(short)), Some(V::Text(id))) = (t.get("short_name"), t.get("id")) {
            tactic_by_short.entry(short.clone()).or_insert_with(|| id.clone());
        }
    }
    let mut phase = Table::new("phase", &[("tactic_id", Default::Null), ("tech_id", Default::Null)]);
    for (tech, short) in &phases {
        let Some(tactic) = tactic_by_short.get(short) else {
            eprintln!("AttributeError: 'NoneType' object has no attribute 'id'");
            std::process::exit(1);
        };
        phase.rows.push(HashMap::from([("tech_id", V::Text(tech.clone())), ("tactic_id", V::Text(tactic.clone()))]));
    }
    exec(&db, &database, "BEGIN");
    insert(&db, &database, &phase);
    exec(&db, &database, "COMMIT");

    exec(&db, &database, "BEGIN");
    for (src, dst) in &revoked_by {
        let table = if src.starts_with("intrusion-set") {
            "\"group\""
        } else if src.starts_with("course-of-action") {
            "mitigation"
        } else if src.starts_with("malware") || src.starts_with("tool") {
            "software"
        } else if src.starts_with("attack-pattern") {
            "technique"
        } else {
            continue;
        };
        update(&db, &database, &format!("UPDATE {table} SET revoked_by=? WHERE {table}.id = ?"), dst, src);
    }
    for (src, dst) in &subtechnique_of {
        update(&db, &database, "UPDATE technique SET subtechnique_of=? WHERE technique.id = ?", dst, src);
    }
    insert(&db, &database, &l.mitigate);
    insert(&db, &database, &l.use_);
    insert(&db, &database, &l.alias);
    insert(&db, &database, &l.contributor);
    insert(&db, &database, &l.platform);
    insert(&db, &database, &l.reference);
    exec(&db, &database, "COMMIT");
    drop(db);

    // User and group permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o660));
    }
}

/// `session.get(Model, id).column = value` (flushed at commit).
fn update(db: &Db, database: &Path, sql: &str, value: &str, id: &str) {
    let (rc, stmt, _) = db.prepare_v2(sql.as_bytes());
    let Some(stmt) = stmt.filter(|_| rc == SQLITE_OK) else {
        die(database, &format!("{}: {sql}", db.errmsg_str()));
    };
    stmt.bind_text(1, Some(value.as_bytes()));
    stmt.bind_text(2, Some(id.as_bytes()));
    if stmt.step() != SQLITE_DONE {
        eprintln!("{}", db.errmsg_str());
        std::process::exit(1);
    }
    if db.changes() == 0 {
        // session.get() returned None
        eprintln!("AttributeError: 'NoneType' object has no attribute 'revoked_by'");
        std::process::exit(1);
    }
}
