//! Throughput of the analysisd stream consumer (`stream_conn` -> `on_alerts` / `on_events`),
//! `#[ignore]`, run by hand:
//!
//! cargo test --release -p siem-api --bin siem-api provigil_manager::stream_bench -- --ignored --nocapture --test-threads=1
//!
//! In-process, with the bench state of agent_grpc_bench (manager off, nothing of the live
//! services). ClickHouse is unreachable unless PV_BENCH_CLICKHOUSE names a private one
//! (e.g. `docker run -p 127.0.0.1:18123:8123 -e CLICKHOUSE_SKIP_USER_SETUP=1 clickhouse/clickhouse-server`).
//! PV_BENCH_SIGMA=<n> loads n synthetic Windows Sigma rules (SigmaHQ has ~2,000).
//! PV_BENCH_WAL=1 sends through a daemon's write-ahead Stream instead of straight on the socket.

use std::io::Write;
use std::time::Instant;

use serde_json::{json, Value};
use siem_ipc::platform_stream::{frame, ALERT, EVENT, HELLO};

/// An analysisd archive line of a Windows event: logon (4624), failed logon (4625),
/// process creation (4688) or Sysmon 1, as the eventchannel decoder writes them.
fn windows_line(i: usize) -> Value {
    let agent = format!("{:03}", 100 + i % 1000);
    let (channel, provider, id, ed) = match i % 4 {
        0 => ("Security", "Microsoft-Windows-Security-Auditing", "4624", json!({ "subjectUserSid": "S-1-5-18", "subjectUserName": "WIN-LT$", "subjectDomainName": "WORKGROUP", "subjectLogonId": "0x3e7", "targetUserSid": "S-1-5-21-1-1001", "targetUserName": format!("user{}", i % 50), "targetDomainName": "LAB", "targetLogonId": format!("0x{:x}", i), "logonType": "2", "logonProcessName": "User32", "authenticationPackageName": "Negotiate", "workstationName": "WIN-LT", "logonGuid": "{00000000-0000-0000-0000-000000000000}", "processId": "0x2a4", "processName": "C:\\\\Windows\\\\System32\\\\svchost.exe", "ipAddress": "127.0.0.1", "ipPort": "0", "impersonationLevel": "%%1833", "elevatedToken": "%%1842" })),
        1 => ("Security", "Microsoft-Windows-Security-Auditing", "4625", json!({ "subjectUserSid": "S-1-5-18", "subjectUserName": "WIN-LT$", "targetUserName": format!("admin{}", i % 7), "targetDomainName": "LAB", "status": "0xc000006d", "failureReason": "%%2313", "subStatus": "0xc000006a", "logonType": "3", "ipAddress": format!("10.1.{}.{}", i % 250, i % 200), "ipPort": "51515", "workstationName": "ATTACKER" })),
        2 => ("Security", "Microsoft-Windows-Security-Auditing", "4688", json!({ "subjectUserSid": "S-1-5-21-1-1001", "subjectUserName": "analyst", "subjectDomainName": "LAB", "newProcessId": format!("0x{:x}", 4000 + i % 999), "newProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe", "tokenElevationType": "%%1936", "processId": "0x1f00", "commandLine": format!("cmd.exe /c dir C:\\\\Users\\\\analyst\\\\Documents\\\\{}", i), "parentProcessName": "C:\\\\Windows\\\\explorer.exe", "mandatoryLabel": "S-1-16-8192" })),
        _ => ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", "1", json!({ "ruleName": "-", "utcTime": "2026-11-05 10:53:00.123", "processGuid": "{8f0a1b2c-0000-0000-0000-000000000000}", "processId": format!("{}", 5000 + i % 999), "image": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe", "fileVersion": "130.0.6723.92", "description": "Google Chrome", "product": "Google Chrome", "company": "Google LLC", "originalFileName": "chrome.exe", "commandLine": format!("\\\"C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe\\\" --type=renderer --field-trial-handle={}", i), "currentDirectory": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\", "user": "LAB\\\\analyst", "logonGuid": "{8f0a1b2c-1111-0000-0000-000000000000}", "logonId": "0x3a1f2", "terminalSessionId": "1", "integrityLevel": "Low", "hashes": "SHA256=3A1F0C8B2D7E6F5A4B3C2D1E0F9A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A", "parentProcessGuid": "{8f0a1b2c-2222-0000-0000-000000000000}", "parentProcessId": "4120", "parentImage": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe", "parentCommandLine": "\\\"C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe\\\"", "parentUser": "LAB\\\\analyst" })),
    };
    let win = json!({ "system": { "providerName": provider, "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": id, "version": "2", "level": "0", "task": "12544", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2026-11-05T10:53:00.1234567Z", "eventRecordID": format!("{}", 100000 + i), "processID": "760", "threadID": "4428", "channel": channel, "computer": format!("WIN-LT-{agent}"), "severityValue": "AUDIT_SUCCESS", "message": format!("\"An account was successfully logged on. (event {i})\"") }, "eventdata": ed });
    json!({
        "timestamp": "2026-11-05T10:53:00.123+0000",
        "rule": { "level": 3, "description": "Windows logon success.", "id": "60106", "firedtimes": i, "mail": false, "groups": ["windows", "windows_security", "authentication_success"], "mitre": { "id": ["T1078"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], "technique": ["Valid Accounts"] } },
        "agent": { "id": agent, "name": format!("WIN-LT-{agent}"), "ip": "10.0.0.5" },
        "manager": { "name": "provigil-manager" },
        "id": format!("1762339980.{i}"),
        "full_log": json!({ "win": win }).to_string(),
        "decoder": { "name": "windows_eventchannel" },
        "data": { "win": win },
        "location": "EventChannel"
    })
}

/// An analysisd archive line of one SCA check result.
fn sca_line(i: usize) -> Value {
    let agent = format!("{:03}", 100 + i % 1000);
    let data = json!({ "type": "check", "id": format!("{}", 900000 + i), "policy": "ProVigil load test policy", "policy_id": "provigil_loadtest", "check": { "id": format!("{}", 26000 + i % 300), "title": "Ensure 'Enforce password history' is set to '24 or more password(s)'.", "description": "This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password.", "rationale": "The longer a user uses the same password, the greater the chance that an attacker can determine the password through brute force attacks.", "remediation": "To establish the recommended configuration via GP, set the following UI path to 24 or more password(s): Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Enforce password history.", "compliance": { "cis": "1.1.1", "cis_csc_v8": "5.2", "cis_csc_v7": "16", "nist_sp_800-53": "IA-5(1)", "pci_dss_v3.2.1": "8.2.5", "pci_dss_v4.0": "2.2.2,8.3.7", "soc_2": "CC6.1" }, "rules": ["c:net.exe accounts -> n:Length of password history maintained:\\s+(\\d+) compare >= 24"], "condition": "all", "command": "net.exe accounts", "result": if i.is_multiple_of(3) { "failed" } else { "passed" } } });
    json!({
        "timestamp": "2026-11-05T10:53:00.456+0000",
        "rule": { "level": 3, "description": "ProVigil load test policy: Ensure 'Enforce password history' is set to '24 or more password(s)'.", "id": "19009", "firedtimes": i, "mail": false, "groups": ["sca"] },
        "agent": { "id": agent, "name": format!("WIN-LT-{agent}"), "ip": "10.0.0.5" },
        "manager": { "name": "provigil-manager" },
        "id": format!("1762339981.{i}"),
        "full_log": data.to_string(),
        "decoder": { "name": "sca" },
        "data": data,
        "location": "sca"
    })
}

/// Synthetic Windows Sigma rules shaped like SigmaHQ's (process creation and Security log).
fn sigma_rules(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let (ls, sel) = match i % 3 {
                0 => ("  category: process_creation", format!("    Image|endswith: '\\\\bench{i}.exe'\n    CommandLine|contains:\n      - ' -enc{i} '\n      - 'downloadstring{i}'")),
                1 => ("  service: security", format!("    EventID: 4625\n    TargetUserName|startswith: 'svc_bench{i}'")),
                _ => ("  category: process_creation", format!("    ParentImage|endswith: '\\\\winword{i}.exe'\n    Image|endswith:\n      - '\\\\cmd.exe'\n      - '\\\\powershell.exe'")),
            };
            format!("title: Bench rule {i}\nid: 00000000-0000-0000-0000-{i:012}\nstatus: test\nlogsource:\n  product: windows\n{ls}\ndetection:\n  selection:\n{sel}\n  condition: selection\nlevel: high\n")
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn stream_throughput() {
    let state = crate::test_state::state().await;
    let ch = state.db.is_connected();
    let rules = std::env::var("PV_BENCH_SIGMA").ok().and_then(|n| n.parse().ok()).unwrap_or(0);
    let loaded = crate::sigma::load_for_test(&sigma_rules(rules));
    // the load test's mix: Windows events (half with an alert) and SCA checks (each an alert)
    let n: usize = std::env::var("PV_BENCH_LINES").ok().and_then(|n| n.parse().ok()).unwrap_or(100_000);
    let wal = std::env::var("PV_BENCH_WAL").is_ok();
    let spool = tempfile::tempdir().unwrap();
    let mut wire = frame(HELLO, 0, b"t0k bench-raw");
    let mut queued = Vec::new();
    let mut lines = 0usize;
    for i in 0.. {
        if lines >= n {
            break;
        }
        let v = if i % 4 == 3 { sca_line(i) } else { windows_line(i) };
        let b = serde_json::to_vec(&v).unwrap();
        lines += 1;
        if wal {
            queued.push((EVENT, b.clone()));
        } else {
            wire.extend(frame(EVENT, lines as u64, &b));
        }
        if i % 4 == 3 || i % 2 == 0 {
            lines += 1;
            if wal {
                queued.push((ALERT, b));
            } else {
                wire.extend(frame(ALERT, lines as u64, &b));
            }
        }
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let bytes: usize = wire.len() + queued.iter().map(|q| q.1.len()).sum::<usize>();
    let dir = spool.path().join(format!("bench-{}", uuid::Uuid::new_v4().simple()));
    let writer = std::thread::spawn(move || {
        if wal {
            // the whole path: spooled by a daemon's Stream, sent, stored, acknowledged
            let mut s = siem_ipc::platform_stream::Stream::start(addr.to_string(), "t0k".into(), &dir, siem_ipc::platform_stream::SPOOL_MAX).unwrap();
            let t = Instant::now();
            for (k, b) in queued {
                s.send(k, &b);
            }
            println!("  spooled in {:.2} s", t.elapsed().as_secs_f64());
            while s.pending() {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert_eq!(s.dropped, 0);
            return;
        }
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(&wire).unwrap();
        // the acknowledgements, read to the end: a socket closed with unread data resets
        c.shutdown(std::net::Shutdown::Write).unwrap();
        std::io::copy(&mut c, &mut std::io::sink()).unwrap();
    });
    let (sock, _) = l.accept().await.unwrap();
    let t0 = Instant::now();
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let (e, a) = (st.events.read().unwrap().len(), st.alerts.read().unwrap().len());
            println!("  {:.0} s: {e} events, {a} alerts in memory", t0.elapsed().as_secs_f64());
        }
    });
    super::stream_conn(state.clone(), sock, "t0k").await.unwrap();
    let secs = t0.elapsed().as_secs_f64();
    writer.join().unwrap();
    println!(
        "stream bench: {lines} lines ({} MB), ClickHouse {}, {loaded} Sigma rules: {secs:.2} s, {:.0} lines/s",
        bytes / 1_000_000,
        if ch { "private" } else { "unreachable" },
        lines as f64 / secs
    );
}
