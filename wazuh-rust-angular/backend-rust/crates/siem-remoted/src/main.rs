//! `wazuh-remoted` command line (`src/remoted/main.c`).

use siem_remoted::config::RemotedSettings;
use siem_remoted::{Deps, Remoted};

fn usage() -> ! {
    eprintln!(
        "  wazuh-remoted: -[Vhdtf] [-c config] [-D dir]\n\
         \x20   -V          Version and license message\n\
         \x20   -h          This help message\n\
         \x20   -d          Execute in debug mode (can be repeated)\n\
         \x20   -t          Test configuration\n\
         \x20   -f          Run in foreground (always the case here)\n\
         \x20   -c <config> Configuration file to use (default: etc/ossec.conf)\n\
         \x20   -D <dir>    Wazuh home directory (default: /var/ossec)\n\
         \x20   -m          Avoid creating shared merged file (read only)"
    );
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let mut debug = 0;
    let mut test_config = false;
    let mut nocmerged = false;
    let mut cfg: Option<String> = None;
    let mut home = std::env::var("WAZUH_HOME").unwrap_or_else(|_| "/var/ossec".to_string());
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-V" => {
                println!("Wazuh {} - wazuh-remoted (Rust port)", siem_remoted::config::OSSEC_VERSION);
                return;
            }
            "-h" => usage(),
            "-d" => debug += 1,
            "-dd" => debug += 2,
            "-t" => test_config = true,
            "-f" => {}
            "-m" => nocmerged = true,
            "-c" => cfg = Some(args.next().unwrap_or_else(|| usage())),
            "-D" => home = args.next().unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }

    let settings = match RemotedSettings::load(&home, cfg.as_deref(), nocmerged) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wazuh-remoted: CRITICAL: {e}");
            std::process::exit(1);
        }
    };
    if debug == 0 {
        debug = settings.internal.debug;
    }
    let level = match debug {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| level.into())).init();
    for w in &settings.warnings {
        tracing::warn!("{w}");
    }
    if test_config {
        return;
    }

    let deps = Deps::sockets(&settings);
    let remoted = match Remoted::new(settings, deps) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("CRITICAL: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = remoted.start().await {
        tracing::error!("CRITICAL: (1206): Unable to Bind port: {e}");
        std::process::exit(1);
    }
    tokio::signal::ctrl_c().await.ok();
}
