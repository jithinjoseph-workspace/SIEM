//! `syscollector_<kind>` save2 and integrity commands on all 13 kinds: old and new must match.
mod common;

/// (command word, a full row, a row without key fields, a refused or odd row)
fn kinds() -> Vec<(&'static str, String, String, String)> {
    let v = |a: &str| format!(r#"{{"attributes":{{{a}}}}}"#);
    vec![
        (
            "processes",
            v(r#""scan_time":"t","pid":"100","name":"svchost","state":"R","ppid":4,"utime":-1,"stime":2,"cmd":"c","argvs":"a","euser":"e","ruser":"r","suser":"s","egroup":"g","rgroup":"g","sgroup":"g","fgroup":"g","priority":8,"nice":-5,"size":1,"vm_size":2,"resident":3,"share":4,"start_time":1700000000.9,"pgrp":1,"session":2,"nlwp":3,"tgid":4,"tty":-2,"processor":1,"checksum":"p1""#),
            v(r#""pid":"  101x","checksum":"p2","nice":true"#),
            v(r#""pid":"-3","checksum":"p3""#),
        ),
        (
            "packages",
            v(r#""scan_time":"t","format":"deb","name":"openssl","priority":"o","groups":"libs","size":1234,"vendor":"v","install_time":"i","version":"3.0","architecture":"amd64","multiarch":"m","source":"s","description":"d","location":"/usr","checksum":"k1","item_id":"pk1""#),
            v(r#""name":"curl","checksum":"k2","item_id":"pk1","size":-1"#),
            v(r#""name":"x","version":"1","architecture":"a","checksum":"legacy","item_id":"pk3","size":"big""#),
        ),
        ("hotfixes", v(r#""scan_time":"t","hotfix":"KB1","checksum":"h1""#), v(r#""hotfix":"KB2""#), v(r#""checksum":"h3""#)),
        (
            "ports",
            v(r#""scan_time":"t","protocol":"tcp","local_ip":"0.0.0.0","local_port":22,"remote_ip":"r","remote_port":-1,"tx_queue":0,"rx_queue":1,"inode":99999999999,"state":"listening","pid":7,"process":"sshd","checksum":"o1","item_id":"po1""#),
            v(r#""protocol":"udp","local_ip":"::","local_port":-5,"checksum":"o2","item_id":"po1""#),
            v(r#""protocol":"udp","local_ip":"::","local_port":5,"inode":-1,"checksum":"o3","item_id":"nosuch""#),
        ),
        (
            "network_protocol",
            v(r#""iface":"eth0","type":"ipv6","gateway":"g","dhcp":"enabled","metric":5,"checksum":"n1","item_id":"np1""#),
            v(r#""type":"ipv4","checksum":"n2","item_id":"np1""#),
            v(r#""iface":"eth1","type":"weird","metric":-1,"checksum":"n3","item_id":"np3""#),
        ),
        (
            "network_address",
            v(r#""iface":"eth0","proto":1,"address":"fe80::1","netmask":"ffff::","broadcast":"b","checksum":"a1","item_id":"na1""#),
            v(r#""iface":"eth0","checksum":"a2","item_id":"na1""#),
            v(r#""iface":"eth0","proto":0,"address":"10.0.0.1","checksum":"a3","item_id":"na3""#),
        ),
        (
            "network_iface",
            v(r#""scan_time":"t","name":"eth0","adapter":"Intel","type":"ethernet","state":"up","mtu":1500,"mac":"aa","tx_packets":1,"rx_packets":-2,"tx_bytes":3,"rx_bytes":4,"tx_errors":0,"rx_errors":0,"tx_dropped":0,"rx_dropped":0,"checksum":"i1","item_id":"ni1""#),
            v(r#""checksum":"i2","item_id":"ni1","mtu":0"#),
            v(r#""name":"eth9","checksum":"i3","item_id":"ni3","mtu":"1500""#),
        ),
        (
            "hwinfo",
            v(r#""scan_time":"t","board_serial":"SN1","cpu_name":"i7","cpu_cores":8,"cpu_mhz":2903.5,"ram_total":16000000,"ram_free":-5,"ram_usage":50,"checksum":"w1""#),
            v(r#""board_serial":"SN2","cpu_cores":0,"cpu_mhz":-1,"ram_usage":101,"checksum":"w2""#),
            v(r#""board_serial":"SN3","ram_total":0,"cpu_mhz":"x","checksum":"w3""#),
        ),
        (
            "osinfo",
            v(r#""scan_time":"t","hostname":"pc1","architecture":"x86_64","os_name":"Windows 11","os_version":"10.0","os_codename":"c","os_major":"10","os_minor":"0","os_patch":"p","os_build":"22631","os_platform":"windows","sysname":"Windows_NT","release":"r","version":"v","os_release":"23H2","os_display_version":"23H2","checksum":"s1""#),
            v(r#""os_name":"Windows 10","checksum":"s2""#),
            v(r#""checksum":"s3""#),
        ),
        (
            "users",
            v(r#""scan_time":"t","user_name":"bob","user_full_name":"Bob","user_home":"/home/bob","user_id":1000,"user_uid_signed":-1,"user_uuid":"u","user_groups":"g","user_group_id":1000,"user_group_id_signed":5,"user_created":1.5,"user_roles":"r","user_shell":"/bin/sh","user_type":"local","user_is_hidden":0,"user_is_remote":1,"user_last_login":1700000000,"user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_password_last_change":2.5,"user_password_expiration_date":10,"user_password_hash_algorithm":"sha512","user_password_inactive_days":0,"user_password_max_days_between_changes":90,"user_password_min_days_between_changes":-1,"user_password_status":"active","user_password_warning_days_before_expiration":7,"process_pid":55,"host_ip":"1.2.3.4","login_status":1,"login_type":"tty","login_tty":"pts/0","checksum":"u1""#),
            v(r#""user_name":"alice","checksum":"u2""#),
            v(r#""user_name":"","checksum":"u3""#),
        ),
        (
            "groups",
            v(r#""scan_time":"t","group_id":10,"group_name":"wheel","group_description":"d","group_id_signed":-10,"group_uuid":"g","group_is_hidden":1,"group_users":"bob","checksum":"g1""#),
            v(r#""group_name":"users","checksum":"g2""#),
            v(r#""checksum":"g3""#),
        ),
        (
            "browser_extensions",
            v(r#""scan_time":"t","browser_name":"chrome","user_id":"1000","package_name":"ub","package_id":"id","package_version":"1.0","package_description":"d","package_vendor":"v","package_build_version":"b","package_path":"/p","browser_profile_name":"Default","browser_profile_path":"/pp","package_reference":"r","package_permissions":"[]","package_type":"extension","package_enabled":1,"package_visible":0,"package_autoupdate":1,"package_persistent":0,"package_from_webstore":1,"browser_profile_referenced":1,"package_installed":"2023","file_hash_sha256":"h","checksum":"b1","item_id":"be1""#),
            v(r#""browser_name":"edge","user_id":"1","browser_profile_path":"/x","package_name":"n","package_version":"2","checksum":"b2","item_id":"be2""#),
            v(r#""browser_name":"edge","user_id":"1","browser_profile_path":"","package_name":"n","package_version":"2","checksum":"b3""#),
        ),
        (
            "services",
            v(r#""scan_time":"t","service_id":"sshd","service_name":"SSH","service_description":"d","service_type":"own","service_state":"running","service_sub_state":"s","service_enabled":"yes","service_start_type":"auto","service_restart":"always","service_frequency":5,"service_starts_on_mount":1,"service_starts_on_path_modified":"p","service_starts_on_not_empty_directory":"n","service_inetd_compatibility":0,"process_pid":77,"process_executable":"/usr/sbin/sshd","process_args":"-D","process_user_name":"root","process_group_name":"root","process_working_directory":"/","process_root_directory":"/","file_path":"/lib/sshd.service","service_address":"a","log_file_path":"l","error_log_file_path":"e","service_exit_code":0,"service_win32_exit_code":-1,"service_following":"f","service_object_path":"o","service_target_ephemeral_id":3,"service_target_type":"t","service_target_address":"ta","checksum":"v1","item_id":"sv1""#),
            v(r#""service_id":"cron","file_path":"/c","checksum":"v2","item_id":"sv2""#),
            v(r#""service_id":"x","checksum":"v3""#),
        ),
    ]
}

fn requests() -> Vec<String> {
    let mut r: Vec<String> = vec![r#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#.into()];
    let mut s: Vec<String> = vec![
        "syscollector_nosuch save2 {}".into(),
        "syscollector_processes".into(),
        "syscollector_processes save2".into(),
        "syscollector_processes nosuch {}".into(),
        "syscollector_processes save2 {bad".into(),
        "syscollector_processes save2 {}".into(),
        r#"syscollector_processes save2 {"attributes":5}"#.into(),
    ];
    for (k, full, keyless, odd) in kinds() {
        for row in [&full, &keyless, &odd] {
            s.push(format!("syscollector_{k} save2 {row}"));
        }
        s.push(format!("syscollector_{k} save2 {full}"));
    }
    for t in [
        "sys_processes", "sys_programs", "sys_hotfixes", "sys_ports", "sys_netproto", "sys_netaddr", "sys_netiface", "sys_hwinfo", "sys_osinfo", "sys_users",
        "sys_groups", "sys_browser_extensions", "sys_services",
    ] {
        s.push(format!("sql SELECT * FROM {t} ORDER BY rowid"));
    }
    // integrity on every kind: a range around everything, then one that removes (and publishes)
    for (k, ..) in kinds() {
        s.push(format!(r#"syscollector_{k} integrity_check_left {{"begin":" ","end":"~","tail":"~~","checksum":"x","id":1700000001}}"#));
        s.push(format!(r#"syscollector_{k} integrity_check_right {{"begin":" ","end":"~","checksum":"x","id":1700000002}}"#));
        s.push(format!(r#"syscollector_{k} integrity_check_global {{"begin":"0","end":"0","checksum":"x","id":1700000003}}"#));
        s.push(format!(r#"syscollector_{k} integrity_check_global {{"begin":"zzz","end":"zzzz","checksum":"x","id":1700000004}}"#));
        s.push(format!(r#"syscollector_{k} integrity_clear {{"id":1700000005}}"#));
    }
    // a fresh row set, then one clear per kind with publishing
    for (k, full, ..) in kinds() {
        s.push(format!("syscollector_{k} save2 {full}"));
        s.push(format!(r#"syscollector_{k} integrity_check_global {{"begin":"zzz","end":"zzzz","checksum":"x","id":1700000006}}"#));
    }
    s.push(r#"syscollector_osinfo integrity_clear {"x":1}"#.into());
    s.push(r#"syscollector_osinfo integrity_check_global {"begin":"a"}"#.into());
    for t in ["sys_processes", "sys_programs", "sys_ports", "sys_osinfo", "sync_info"] {
        s.push(format!("sql SELECT * FROM {t} ORDER BY rowid"));
    }
    r.extend(s.into_iter().map(|x| format!("agent 1 {x}")));
    r
}

#[test]
fn syscollector_matches_old() {
    let p = common::Pair::new();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
fn syscollector_matches_old_with_router() {
    let p = common::Pair::routed();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
#[ignore]
fn show_answers() {
    let p = common::Pair::routed();
    for r in requests() {
        let (c, a) = p.new.handle(r.as_bytes(), 7);
        let (_, routed, _) = p.sn.take();
        for (t, m) in routed {
            println!("ROUTER {t} {}", String::from_utf8_lossy(&m));
        }
        let _ = (c, a);
    }
}
