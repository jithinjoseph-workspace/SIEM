//! The Rust twin of tools/oracle/router_tool.cpp (same modes and output),
//! for the interop test against Wazuh's C++ router.

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
fn main() {
    use siem_router::RouterFacade;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        std::process::exit(2);
    }
    let secs = |s: &str| Duration::from_secs(s.parse().unwrap_or(1));
    let f = RouterFacade::instance();
    match a[1].as_str() {
        "broker" => {
            f.initialize().unwrap();
            println!("BROKER");
            std::thread::sleep(secs(&a[2]));
            let _ = f.destroy();
        }
        "provide" if a.len() >= 4 => {
            let connected = Arc::new(AtomicBool::new(false));
            let c = connected.clone();
            let _ = f.init_provider_remote(&a[2], Arc::new(move || c.store(true, Ordering::SeqCst)));
            for _ in 0..100 {
                if connected.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            println!("{}", if connected.load(Ordering::SeqCst) { "CONNECTED" } else { "NOT CONNECTED" });
            for m in &a[4..] {
                let _ = f.push(&a[2], m.as_bytes());
            }
            std::thread::sleep(secs(&a[3]));
            let _ = f.remove_provider_remote(&a[2]);
        }
        "subscribe" if a.len() >= 5 => {
            let _ = f.add_subscriber_remote(
                &a[2],
                &a[3],
                Arc::new(|d: &[u8]| {
                    let h: String = d.iter().map(|b| format!("{b:02x}")).collect();
                    println!("GOT {h}");
                }),
                Arc::new(|| println!("CONNECTED")),
            );
            std::thread::sleep(secs(&a[4]));
            f.remove_subscriber_remote(&a[2], &a[3]);
        }
        _ => std::process::exit(2),
    }
}
