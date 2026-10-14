//! `sca-yaml2json FILE...`: each policy as `yaml2json(document, 1)` prints
//! it (cJSON_PrintUnformatted), one per line, or `ERROR` (oracle compare).

fn main() {
    for path in std::env::args().skip(1) {
        let mut warn = |m: String| eprintln!("{m}");
        let out = siem_sca::yaml::parse_file(&path, &mut warn).and_then(|mut d| d.to_json(true, &mut warn));
        match out {
            Some(j) => println!("{}", j.to_string_unformatted()),
            None => println!("ERROR"),
        }
    }
}
