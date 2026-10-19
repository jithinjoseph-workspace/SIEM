//! `integrations/<name>`: the integration scripts. The name comes from the
//! file this program was installed as (slack, pagerduty, virustotal, shuffle,
//! maltiverse); integratord passes the same arguments it gives the Python scripts.

fn main() {
    let exe = std::env::current_exe().ok().and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned())).unwrap_or_default();
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(siem_integratord::scripts::run(&exe, args));
}
