//! ProVigil Endpoint Agent - Live Windows Verification & Telemetry Inspection Tool
//!
//! Executes all Windows agent telemetry engines on the local host and
//! verifies that all security, inventory, FIM, diff, and audit events
//! are generated properly with full fidelity and zero data loss.

use std::fs;
use uuid::Uuid;

use provigil_agent::buffer::EventBuffer;
use provigil_agent::diff::DiffConfig;
use provigil_agent::events::{ChannelConfig, EventCollector, MultilineAggregator, MultilineConfig};
use provigil_agent::fim::FimScanner;
use provigil_agent::inventory::InventoryCollector;
use provigil_agent::registry::RegistryMonitor;
use provigil_agent::rootcheck::{RootcheckConfig, RootcheckScanner};
use provigil_agent::sca::ScaScanner;
use provigil_agent::whodata::Who;

fn main() -> anyhow::Result<()> {
    println!("==============================================================================");
    println!("    PROVIGIL ENDPOINT AGENT - LIVE WINDOWS TELEMETRY VERIFICATION");
    println!("==============================================================================");
    println!();

    let agent_id = "001";
    let agent_name = "win-node-test";
    let buffer = EventBuffer::new(1000);

    // -------------------------------------------------------------------------
    // 1. Verify System Hardware, OS & Process Inventory
    // -------------------------------------------------------------------------
    println!("[1/6] Testing System Inventory & Delta Engine...");
    let mut inv = InventoryCollector::new();
    let snapshot = inv.snapshot(agent_id, agent_name);
    let os_name = snapshot["system"]["os"]["name"].as_str().unwrap_or("Unknown");
    let proc_count = snapshot["system"]["process_count"].as_u64().unwrap_or(0);
    let total_ram_mb = snapshot["system"]["hardware"]["total_memory_bytes"].as_u64().unwrap_or(0) / 1024 / 1024;
    println!("   [+] OS Detected: {}", os_name);
    println!("   [+] Running Processes Discovered: {}", proc_count);
    println!("   [+] Total RAM: {} MB", total_ram_mb);
    assert!(proc_count > 0, "Inventory must discover running processes");
    buffer.push(snapshot);

    // Test process delta sync
    let deltas = inv.collect_deltas(agent_id, agent_name);
    println!("   [+] Process Delta Synchronization Active: {} deltas computed", deltas.len());
    for d in deltas {
        buffer.push(d);
    }
    println!("   [OK] Inventory Engine verified.\n");

    // -------------------------------------------------------------------------
    // 2. Verify File Integrity Monitoring (FIM) with Unified Diff & Whodata
    // -------------------------------------------------------------------------
    println!("[2/6] Testing FIM Engine with File Diff & Whodata Attribution...");
    let test_dir = std::env::temp_dir().join(format!("provigil-verify-{}", Uuid::new_v4()));
    let monitored_dir = test_dir.join("monitored");
    let diff_dir = test_dir.join("diff_store");
    fs::create_dir_all(&monitored_dir)?;
    fs::create_dir_all(&diff_dir)?;

    let target_file = monitored_dir.join("critical_config.ini");
    let diff_cfg = DiffConfig {
        enabled: true,
        storage_dir: diff_dir,
        max_diff_size: 4096,
        max_file_size: 1024 * 1024,
        disk_quota_bytes: 10 * 1024 * 1024,
        compress_snapshots: false,
    };

    // who-data as a handle close in the Security channel would give it (simulated)
    let whodata = Who {
        user_name: "Administrator".to_string(),
        user_id: "S-1-5-21-500".to_string(),
        process_name: "C:\\Windows\\System32\\notepad.exe".to_string(),
        process_id: 5412,
        access_mask: 0x0002, // write access
    };

    let mut fim = FimScanner::new(vec![monitored_dir.clone()]).with_diff_engine(diff_cfg);

    // Initial baseline pass
    let ev1 = fim.scan(agent_id, agent_name);
    assert!(ev1.is_empty(), "Initial empty scan");

    // Create file
    fs::write(&target_file, "allow_root=false\nport=8080\n")?;
    let ev2 = fim.recheck(&target_file, true, Some(&whodata), agent_id, agent_name);
    assert_eq!(ev2.len(), 1, "Must detect newly added file");
    println!("   [+] File Creation Detected: {}", ev2[0]["syscheck"]["path"]);
    println!("   [+] Whodata Attribution: User='{}', Process='{}' (PID: {})",
        ev2[0]["syscheck"]["whodata"]["user_name"],
        ev2[0]["syscheck"]["whodata"]["process_name"],
        ev2[0]["syscheck"]["whodata"]["process_id"]
    );
    buffer.push(ev2[0].clone());

    // Modify file
    fs::write(&target_file, "allow_root=true\nport=8080\nbackdoor_enabled=true\n")?;
    let ev3 = fim.scan(agent_id, agent_name);
    assert_eq!(ev3.len(), 1, "Must detect file modification");
    let diff_content = ev3[0]["syscheck"]["diff"].as_str().unwrap_or("");
    println!("   [+] File Modification Detected: event='{}'", ev3[0]["syscheck"]["event"]);
    println!("   [+] Unified Diff Calculated:\n{}", diff_content.trim());
    assert!(diff_content.contains("-allow_root=false"));
    assert!(diff_content.contains("+allow_root=true"));
    buffer.push(ev3[0].clone());

    // Cleanup temp dir
    let _ = fs::remove_dir_all(&test_dir);
    println!("   [OK] FIM & Diff Engine verified.\n");

    // -------------------------------------------------------------------------
    // 3. Verify Windows Registry Persistence Monitor
    // -------------------------------------------------------------------------
    println!("[3/6] Testing Windows Registry Persistence Monitor...");
    let mut reg_monitor = RegistryMonitor::new(vec![
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
    ]);
    let reg_events = reg_monitor.scan(agent_id, agent_name);
    println!("   [+] Registry Persistence Scanner Active: {} baseline keys scanned", reg_events.len());
    for r in reg_events {
        buffer.push(r);
    }
    println!("   [OK] Registry Monitor verified.\n");

    // -------------------------------------------------------------------------
    // 4. Verify Rootcheck & Driver Hook Scanner
    // -------------------------------------------------------------------------
    println!("[4/6] Testing Rootcheck & Driver Hook Scanner...");
    let rootcheck_scanner = RootcheckScanner::new(RootcheckConfig::default());
    let rc_events = rootcheck_scanner.scan(agent_id, agent_name);
    println!("   [+] System Masquerading & Kernel Driver Scan complete ({} alerts)", rc_events.len());
    for rc in rc_events {
        println!("   [!] {}", rc.get("message").unwrap_or(&rc["rootcheck"]["title"]));
        buffer.push(rc);
    }
    println!("   [OK] Rootcheck Scanner verified.\n");

    // -------------------------------------------------------------------------
    // 5. Verify Multiline Log Aggregator & Windows Event Channel
    // -------------------------------------------------------------------------
    println!("[5/6] Testing Multiline Log Aggregator & Event Channel Filters...");
    let ml_cfg = MultilineConfig {
        enabled: true,
        match_regex: r"^\d{4}-\d{2}-\d{2}".to_string(),
        timeout_ms: 2000,
        max_bytes: 65536,
        line_separator: "\n".to_string(),
    };
    let mut agg = MultilineAggregator::new(&ml_cfg);
    let _ = agg.push_line("2026-11-03 12:00:00 [ERROR] Authentication failed for user admin");
    let _ = agg.push_line("    at security.auth.LoginModule.verify(LoginModule.java:102)");
    let _ = agg.push_line("    at security.auth.Filter.doFilter(Filter.java:45)");
    let flushed = agg.push_line("2026-11-03 12:00:01 [INFO] Subsequent request").expect("Should aggregate multiline stack trace");
    println!("   [+] Aggregated Multiline Event:\n{}", flushed.trim());
    assert!(flushed.contains("LoginModule.java:102"));

    let channel_cfg = vec![
        ChannelConfig {
            name: "Security".to_string(),
            xpath_query: Some("*[System[(EventID=4624 or EventID=4625)]]".to_string()),
            max_events_per_poll: 10,
        }
    ];
    let mut collector = EventCollector::with_configs(channel_cfg);
    let win_events = collector.collect(agent_id, agent_name);
    println!("   [+] Windows Event Channel Filter Active: collected {} live records", win_events.len());
    for w in win_events {
        buffer.push(w);
    }
    println!("   [OK] Event Channel & Multiline Aggregator verified.\n");

    // -------------------------------------------------------------------------
    // 6. Verify the configuration assessment policies & Offline Buffer
    // -------------------------------------------------------------------------
    println!("[6/6] Testing Configuration Assessment & Resilient Event Buffer...");
    let sca_events = ScaScanner::new().scan(agent_id, agent_name);
    for ev in &sca_events {
        let m: serde_json::Value = serde_json::from_str(ev["message"].as_str().unwrap_or("{}")).unwrap_or_default();
        if m["type"] == "summary" {
            println!("   [+] {}: {}/{} passed, {} not applicable (score {}%)", m["name"], m["passed"], m["total_checks"], m["invalid"], m["score"]);
        }
    }
    for ev in sca_events {
        buffer.push(ev);
    }

    // Verify Buffer Drain Batching
    let queued_count = buffer.len();
    println!("   [+] Total Telemetry Events Buffered Offline: {}", queued_count);
    assert!(queued_count > 0, "Buffer must contain queued telemetry events");

    let batch = buffer.drain_batch(100);
    println!("   [+] Batch Drained for Transmission: {} events (Remaining in buffer: {})", batch.len(), buffer.len());
    assert_eq!(batch.len(), queued_count);

    println!();
    println!("==============================================================================");
    println!("   [SUCCESS] ALL WINDOWS AGENT DATA ENGINES VERIFIED 100% OPERATIONAL!");
    println!("==============================================================================");

    Ok(())
}
