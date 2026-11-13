//! `dbsync` deltas on all 13 inventory kinds: old and new must match.
mod common;

/// (kind, table, [(json name, type)]) read from the column lists in src/delta.rs.
fn kinds() -> Vec<(String, String, Vec<(String, char)>)> {
    let src = include_str!("../src/delta.rs");
    let mut out = Vec::new();
    for line in src.lines().filter(|l| l.trim_start().starts_with("(\"") && !l.trim_start().starts_with("(\"sys_") && l.contains(", \"sys_")) {
        let parts: Vec<&str> = line.split('"').collect();
        let cols = parts[5]
            .split(' ')
            .map(|t| {
                let (name, ty) = t.split_once(':').unwrap();
                let json = name.split_once('<').map(|x| x.1).unwrap_or(name);
                (json.to_string(), ty.chars().next().unwrap())
            })
            .collect();
        out.push((parts[1].to_string(), parts[3].to_string(), cols));
    }
    assert_eq!(out.len(), 13);
    out
}

fn row(cols: &[(String, char)], n: i64, skip_odd: bool) -> String {
    let vals: Vec<String> = cols
        .iter()
        .enumerate()
        .filter(|(i, _)| !skip_odd || i % 2 == 0)
        .map(|(_, (k, t))| {
            let v = match t {
                'i' => format!("{}", n),
                'l' => format!("{}", n * 1_000_000_000),
                'r' => format!("{}.25", n),
                _ => format!("\"{k}_{n}\""),
            };
            format!("\"{k}\":{v}")
        })
        .collect();
    format!("{{{}}}", vals.join(","))
}

fn requests() -> Vec<String> {
    let mut r: Vec<String> = vec![r#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#.into()];
    let mut s: Vec<String> = vec![
        "dbsync".into(),
        "dbsync ".into(),
        "dbsync packages".into(),
        "dbsync packages INSERTED".into(),
        "dbsync packages INSERTED ".into(),
        "dbsync nosuch INSERTED {}".into(),
        "dbsync packages UPSERT {}".into(),
        "dbsync packages INSERTED {bad".into(),
        "dbsync packages INSERTED {} trailing".into(),
        "dbsync packages INSERTED []".into(),
    ];
    for (kind, table, cols) in kinds() {
        s.push(format!("dbsync {kind} INSERTED {}", row(&cols, 1, false)));
        s.push(format!("dbsync {kind} INSERTED {}", row(&cols, 2, false)));
        s.push(format!("dbsync {kind} MODIFIED {}", row(&cols, 1, true)));
        s.push(format!("dbsync {kind} INSERTED {{}}"));
        s.push(format!("dbsync {kind} MODIFIED {}", row(&cols, -3, false)));
        s.push(format!("sql SELECT * FROM {table} ORDER BY rowid"));
        s.push(format!("dbsync {kind} DELETED {}", row(&cols, 2, false)));
        s.push(format!("dbsync {kind} DELETED {{}}"));
        s.push(format!("sql SELECT * FROM {table} ORDER BY rowid"));
    }
    // value types against column types
    for v in [
        r#""cpu_cores":"8""#, r#""cpu_cores":"8x""#, r#""cpu_cores":"""#, r#""cpu_cores":" ""#, r#""cpu_cores":true"#, r#""cpu_cores":{}"#,
        r#""cpu_cores":null"#, r#""cpu_cores":-1"#, r#""ram_usage":101"#, r#""ram_usage":"50""#, r#""cpu_mhz":"2.5e3""#, r#""cpu_mhz":"0x1p4""#,
        r#""cpu_mhz":"abc""#, r#""cpu_mhz":-2"#, r#""cpu_name":5"#, r#""cpu_name":5.5"#, r#""cpu_name":"""#, r#""cpu_name":[1]"#, r#""checksum":"""#,
    ] {
        s.push(format!(r#"dbsync hwinfo INSERTED {{"board_serial":"SN","scan_time":"t",{v},"checksum":"c"}}"#));
    }
    for v in [
        r#""user_id":"123456789012""#, r#""user_id":"-5""#, r#""user_id":1e30"#, r#""user_id":"x""#, r#""user_created":"1.5""#, r#""user_created":0"#,
        r#""user_last_login":-1"#, r#""process_pid":-2"#, r#""login_status":"7""#,
    ] {
        s.push(format!(r#"dbsync users MODIFIED {{"user_name":"bob",{v},"checksum":"c"}}"#));
    }
    for v in [r#""service_frequency":-1"#, r#""process_pid":-1"#, r#""service_exit_code":"-4""#] {
        s.push(format!(r#"dbsync services INSERTED {{"service_id":"s1","file_path":"/f",{v},"checksum":"c"}}"#));
    }
    s.push(r#"dbsync groups INSERTED {"group_name":"g","group_id":-1,"checksum":"c"}"#.into());
    s.push(r#"dbsync ports INSERTED {"protocol":"tcp","local_ip":"0","local_port":"22","inode":"99","pid":"7x","checksum":"c"}"#.into());
    s.push(r#"dbsync ports INSERTED {"protocol":"tcp","local_ip":"0","local_port":"22","inode":"99","pid":7,"checksum":"c"}"#.into());
    s.push(r#"dbsync ports DELETED {"protocol":"tcp","local_ip":"0","local_port":"x","inode":"99"}"#.into());
    s.push(r#"dbsync ports DELETED {"protocol":"tcp","local_ip":"0","local_port":"22","inode":"99"}"#.into());
    s.push(r#"dbsync packages INSERTED {"name":"n","version":"1","architecture":"a","format":"","location":"","cpe":"ignored","groups":"g","checksum":"c"}"#.into());
    s.push(r#"dbsync osinfo INSERTED {"os_name":"W","reference":"ignored","os_display_version":"","checksum":"c"}"#.into());
    for t in ["sys_hwinfo", "sys_users", "sys_services", "sys_groups", "sys_ports", "sys_programs", "sys_osinfo"] {
        s.push(format!("sql SELECT * FROM {t} ORDER BY rowid"));
    }
    r.extend(s.into_iter().map(|x| format!("agent 1 {x}")));
    r
}

#[test]
fn dbsync_matches_old() {
    let p = common::Pair::new();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
#[ignore]
fn show_answers() {
    let p = common::Pair::new();
    for r in requests() {
        let (c, a) = p.new.handle(r.as_bytes(), 7);
        println!("{c} {}  <= {}", String::from_utf8_lossy(&a[..a.len().min(140)]), &r[..r.len().min(80)]);
        let (logs, _, _) = p.sn.take();
        for (l, m) in logs.iter().filter(|(l, _)| l != "DEBUG2") {
            println!("     {l}: {}", String::from_utf8_lossy(m));
        }
    }
}
