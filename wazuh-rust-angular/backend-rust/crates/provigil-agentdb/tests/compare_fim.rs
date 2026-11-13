//! FIM commands and the FIM integrity sync: old and new must match.
mod common;

use sha1::{Digest, Sha1};

fn sha1_hex(s: &str) -> String {
    Sha1::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn file2(path: &str, sum: &str, extra: &str) -> String {
    format!(
        r#"syscheck save2 {{"path":"{path}","timestamp":1700000000,"attributes":{{"type":"file","size":10,"perm":"rw-r--r--","uid":"0","gid":"0","user_name":"root","group_name":"root","inode":5,"mtime":1600000000,"hash_md5":"m","hash_sha1":"s","hash_sha256":"h","checksum":"{sum}"{extra}}}}}"#
    )
}

fn requests() -> Vec<String> {
    let all = sha1_hex("c1c2c3");
    let mut r: Vec<String> = vec![r#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#.into()];
    let mut s: Vec<String> = vec![
        // syntax
        "syscheck".into(),
        "syscheck nosuch".into(),
        "syscheck nosuch x".into(),
        // scan info
        "syscheck scan_info_get start_scan".into(),
        "syscheck scan_info_get bogus".into(),
        "syscheck scan_info_update start_scan 123".into(),
        "syscheck scan_info_update first_start 5".into(),
        "syscheck scan_info_update first_end -7x".into(),
        "syscheck scan_info_update bogus 5".into(),
        "syscheck scan_info_update nospace".into(),
        "syscheck scan_info_get first_start".into(),
        "syscheck scan_info_get end_scan".into(),
        "syscheck control 1700000001".into(),
        "syscheck control 1700000002".into(),
        "syscheck control abc".into(),
        "syscheck scan_info_get fim_third_check".into(),
        // old-format save
        r"syscheck save file 10:33188:0:0:md5a:sha1a:root:root:1600000000:5:sha256a:attr!3:1700000000 /etc/a".into(),
        r"syscheck save file 11:33188:0:0:md5b:sha1b:Admin\ User:root:1600000001:6:sha256b:32!1:1700000001:/link\:x /etc/a".into(),
        r"syscheck save file 12:|S-1-5-32-544,0,2032127|S-1-5-18,1,1:0:0:md5c:sha1c:Administrators:SYSTEM:1600000000:0:sha256c:34!0:1700000000 C:\x.txt".into(),
        r"syscheck save file 5:420:0:0:md5d:sha1d /etc/short".into(),
        r"syscheck save file 5:420:0:0:md5d:sha1d:u /etc/bad".into(),
        r"syscheck save file 10:abc /etc/bad".into(),
        r"syscheck save file -1 /etc/gone".into(),
        r"syscheck save file 10:rw:0:0:m:s:u:g:1:2 /etc/winperm".into(),
        r"syscheck save registry 0:::::sha1r HKLM\x".into(),
        r"syscheck save other 1:2 /x".into(),
        r"syscheck save file".into(),
        r"syscheck save file 1:2".into(),
        "syscheck load /etc/a".into(),
        "syscheck load /etc/none".into(),
        "sql UPDATE fim_entry SET date = 1700000005".into(),
        "syscheck load /etc/a".into(),
        r"syscheck load C:\x.txt".into(),
        "syscheck load /etc/short".into(),
        "syscheck load /etc/winperm".into(),
        r"syscheck load HKLM\x".into(),
        "syscheck delete /etc/short".into(),
        "syscheck delete /nothing".into(),
        "syscheck updatedate /etc/a".into(),
        "sql UPDATE fim_entry SET date = 1700000005".into(),
        "syscheck cleandb ".into(),
        "sql UPDATE fim_entry SET date = 1".into(),
        "syscheck cleandb ".into(),
        // JSON save
        file2("/a", "c1", ""),
        file2("/b", "c2", r#","inode":"77""#),
        file2("/c", "c3", r#","attributes":"A","symbolic_path":"/l","value_type":"x""#),
        file2("/d", "", r#","inode":"12x""#),
        file2("/e", "c5", r#","inode":"99999999999999999999""#),
        file2("/f", "c6", r#","bogus":"1""#),
        file2("/g", "c7", r#","size":"1""#),
        file2("/h", "c8", r#","perm":{"S-1":{"name":"x","allowed":["read"]}}"#),
        file2("/i", "c9", r#","bogus":{"a":1}"#),
        file2("/j", "c10", r#","nums":5"#),
        file2("/k", "c11", r#","inode":"-9223372036854775808""#),
        file2("/k2", "c12", r#","inode":"9223372036854775807""#),
        "syscheck save2 {bad".into(),
        r#"syscheck save2 {"timestamp":1,"attributes":{"type":"file"}}"#.into(),
        r#"syscheck save2 {"path":"/x","attributes":{"type":"file"}}"#.into(),
        r#"syscheck save2 {"path":"/x","timestamp":1,"attributes":5}"#.into(),
        r#"syscheck save2 {"path":"/x","timestamp":1,"attributes":{}}"#.into(),
        r#"syscheck save2 {"path":"/x","timestamp":1,"attributes":{"type":"bogus"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\r","timestamp":1,"attributes":{"type":"registry","checksum":"r0"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\k1","timestamp":1,"attributes":{"type":"registry_key","checksum":"k1"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\k:1","version":2.0,"arch":"[x64]","timestamp":1,"attributes":{"type":"registry_key","checksum":"k2"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\k:1","version":2.0,"timestamp":1,"attributes":{"type":"registry_key","checksum":"k3"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\v","version":2.0,"arch":"[x32]","value_name":"n:a\\m","timestamp":1,"attributes":{"type":"registry_value","checksum":"v1"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\v","version":2.0,"arch":"[x32]","timestamp":1,"attributes":{"type":"registry_value","checksum":"v1"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\v","version":2.0,"arch":"[x32]","timestamp":1,"attributes":{"type":"registry_other"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\p1","index":"dup","version":3.0,"timestamp":1,"attributes":{"type":"registry_key","checksum":"d1"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\p2","index":"dup","version":3.0,"timestamp":1,"attributes":{"type":"registry_key","checksum":"d2"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\p3","version":3.0,"timestamp":1,"attributes":{"type":"registry_key"}}"#.into(),
        r#"syscheck save2 {"path":"HKLM\\p4","version":4.0,"timestamp":1,"attributes":{"type":"registry_key"}}"#.into(),
        r#"syscheck save2 {"index":"onlyindex","timestamp":1,"attributes":{"type":"file"}}"#.into(),
        "sql SELECT file,checksum,full_path,inode,perm FROM fim_entry ORDER BY rowid".into(),
        // integrity
        r#"fim_file integrity_check_global {"begin":"/a","end":"/a","checksum":"x","id":1700000007}"#.into(),
        r#"fim_registry_key integrity_check_global {"begin":"dup","end":"dup","checksum":"x","id":1700000008}"#.into(),
        r#"fim_registry integrity_check_left {"begin":" ","end":"~","tail":"~~","checksum":"x","id":1700000009}"#.into(),
        r#"fim_registry_value integrity_check_global {"begin":" ","end":"~","checksum":"x","id":1700000010}"#.into(),
        r#"syscheck integrity_check_global {bad"#.into(),
        r#"syscheck integrity_check_global {"end":"/c","checksum":"x","id":1}"#.into(),
        r#"syscheck integrity_check_global {"begin":"/a","checksum":"x","id":1}"#.into(),
        r#"syscheck integrity_check_global {"begin":"/a","end":"/c","id":1}"#.into(),
        r#"syscheck integrity_check_global {"begin":"/a","end":"/c","checksum":"x"}"#.into(),
        r#"syscheck integrity_check_global {"begin":"/a","end":"/c","checksum":"x","id":"1"}"#.into(),
        r#"syscheck integrity_check_global {"begin":"/a","end":"/c","checksum":"wrong","id":1700000001}"#.into(),
        format!(r#"syscheck integrity_check_left {{"begin":"/a","end":"/c","checksum":"{all}","id":1700000002}}"#),
        format!(r#"syscheck integrity_check_right {{"begin":"/a","end":"/c","checksum":"{all}","id":1700000003}}"#),
        format!(r#"syscheck integrity_check_bogus {{"begin":"/a","end":"/c","checksum":"{all}","id":1700000003}}"#),
        format!(r#"syscheck integrity_check_global {{"begin":"/a","end":"/c","checksum":"{all}","id":1700000004}}"#),
        format!(r#"syscheck integrity_check_global {{"begin":"/a","end":"/c","checksum":"{all}","id":1700000005.7}}"#),
        r#"syscheck integrity_check_left {"begin":"/a","end":"/b","tail":"/d","checksum":"x","id":1700000006}"#.into(),
        r#"syscheck integrity_check_global {"begin":"/zz","end":"/zzz","checksum":"x","id":1700000000}"#.into(),
        r#"fim_registry_value integrity_clear {"id":1700000011}"#.into(),
        r#"fim_file integrity_clear {"begin":"x"}"#.into(),
        r#"fim_file integrity_clear {bad"#.into(),
        r#"syscheck integrity_clear {"id":1700000012}"#.into(),
        "fim_file nosuch x".into(),
        "fim_file".into(),
    ];
    for t in ["fim_entry", "scan_info", "sync_info"] {
        let cols = if t == "fim_entry" { "file,type,size,perm,uid,gid,md5,sha1,uname,gname,mtime,inode,sha256,attributes,symbolic_path,checksum,arch,value_name,value_type,full_path,changes" } else { "*" };
        s.push(format!("sql SELECT {cols} FROM {t} ORDER BY rowid"));
    }
    r.extend(s.into_iter().map(|x| format!("agent 1 {x}")));
    r
}

#[test]
fn fim_matches_old() {
    let p = common::Pair::new();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
fn fim_matches_old_with_router() {
    let p = common::Pair::routed();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
#[ignore]
fn show_answers() {
    let p = common::Pair::new();
    for r in requests() {
        let (c, a) = p.new.handle(r.as_bytes(), 7);
        println!("{c} {}  <= {}", String::from_utf8_lossy(&a), &r[..r.len().min(90)]);
    }
}
