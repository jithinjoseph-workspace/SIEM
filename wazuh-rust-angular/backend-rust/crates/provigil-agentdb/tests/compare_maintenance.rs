//! Background jobs (idle commit, fragmentation check and vacuum, closing beyond the open limit,
//! newest backup, opening every agent database): old and new must match.
mod common;

use provigil_agentdb::Settings;
use siem_wdb::wdb::WdbConfig;

fn setup() -> Vec<String> {
    let mut r: Vec<String> = Vec::new();
    for id in [3, 1, 12, 2, 7] {
        r.push(format!(r#"global insert-agent {{"id":{id},"name":"pc{id}","date_add":1}}"#));
    }
    for id in [3, 1, 12, 2, 7] {
        r.push(format!("agent {id} sql SELECT 1"));
    }
    r.push("agent 2 begin".into());
    r.push("agent 7 begin".into());
    r
}

#[test]
fn jobs_match_old() {
    // commits always due, vacuum always due, at most two databases open
    let cfg = WdbConfig { commit_time_min: -1, open_db_limit: 2, max_fragmentation: -1, free_pages_percentage: 0, ..WdbConfig::default() };
    let settings = Settings { commit_time_min: -1, open_db_limit: 2, max_fragmentation: -1, free_pages_percentage: 0, ..Settings::default() };
    let p = common::Pair::configured(cfg, settings, false);
    let mut diffs = p.run(&setup(), &|s| s);
    diffs.extend(p.job("commit_old", &|o| o.commit_old(), &|n| n.commit_old()));
    diffs.extend(p.job("check_fragmentation", &|o| o.check_fragmentation(), &|n| n.check_fragmentation()));
    diffs.extend(p.job("check_fragmentation again", &|o| o.check_fragmentation(), &|n| n.check_fragmentation()));
    diffs.extend(p.job("close_old", &|o| o.close_old(), &|n| n.close_old()));
    diffs.extend(p.job("close_old again", &|o| o.close_old(), &|n| n.close_old()));
    diffs.extend(p.run(&["agent 2 sql SELECT count(*) AS n FROM metadata".to_string(), "agent 12 sql SELECT * FROM metadata ORDER BY key".to_string()], &|s| s));
    let (o, n) = (p.old.global_get_most_recent_backup().0, p.new.newest_backup_time());
    if o != n {
        diffs.push(format!("newest backup old {o} new {n}"));
    }
    diffs.extend(p.job("newest backup", &|_| {}, &|_| {}));
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
fn defaults_do_nothing_early() {
    // default limits: nothing is committed, vacuumed or closed right away
    let p = common::Pair::new();
    let mut diffs = p.run(&setup(), &|s| s);
    diffs.extend(p.job("commit_old", &|o| o.commit_old(), &|n| n.commit_old()));
    diffs.extend(p.job("check_fragmentation", &|o| o.check_fragmentation(), &|n| n.check_fragmentation()));
    diffs.extend(p.job("close_old", &|o| o.close_old(), &|n| n.close_old()));
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
fn opening_every_agent_matches_old() {
    let p = common::Pair::new();
    let mut diffs = p.run(&setup(), &|s| s);
    // close everything, then open each file again the way the start-up job does
    for id in [1, 2, 3, 7, 12] {
        diffs.extend(p.run(&[format!("agent {id} close")], &|s| s));
    }
    let names = |h: &std::path::Path| {
        let mut v: Vec<String> = std::fs::read_dir(h.join("queue/db")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    };
    diffs.extend(p.job(
        "open all",
        &|o| {
            // the old job sorted by the same directory listing, one database per second
            let mut files = names(p.homes()[0]);
            files.retain(|n| n != ".template.db" && n != "000.db" && !n.contains('-'));
            for n in files {
                if let Some(dot) = n.find('.') {
                    if let Some(w) = o.open_agent2(n[..dot].parse::<i32>().unwrap_or(0)) {
                        o.leave(w);
                    }
                }
            }
        },
        &|n| n.open_all_agents(&|| true),
    ));
    let (a, b) = (names(p.homes()[0]), names(p.homes()[1]));
    if a != b {
        diffs.push(format!("files old {a:?} new {b:?}"));
    }
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
#[ignore]
fn show_logs() {
    let cfg = WdbConfig { commit_time_min: -1, open_db_limit: 2, max_fragmentation: -1, ..WdbConfig::default() };
    let settings = Settings { commit_time_min: -1, open_db_limit: 2, max_fragmentation: -1, ..Settings::default() };
    let p = common::Pair::configured(cfg, settings, false);
    p.run(&setup(), &|s| s);
    p.sn.take();
    p.new.commit_old();
    p.new.check_fragmentation();
    p.new.close_old();
    for (l, m) in p.sn.take().0 {
        println!("{l}: {}", String::from_utf8_lossy(&m));
    }
}
