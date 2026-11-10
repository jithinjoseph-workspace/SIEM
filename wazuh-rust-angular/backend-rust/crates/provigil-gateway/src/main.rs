use std::process::ExitCode;

use provigil_gateway::settings::Settings;

const HELP: &str = "provigil-gateway: the ProVigil agent front door

  --version       the version
  --help          this text
  -d, -dd         more logging
  --test-config   checks the settings and exits

Settings come from the environment (specs/provigil-gateway.md, 3.12).";

#[tokio::main]
async fn main() -> ExitCode {
    let (mut level, mut test) = ("info", false);
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--version" => {
                println!("provigil-gateway {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--help" => {
                println!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "-d" => level = "debug",
            "-dd" => level = "trace",
            "--test-config" => test = true,
            other => {
                eprintln!("unknown argument {other}\n\n{HELP}");
                return ExitCode::from(2);
            }
        }
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let s = match Settings::from_env() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("provigil-gateway: {e}");
            return ExitCode::FAILURE;
        }
    };
    if test {
        println!("settings ok");
        return ExitCode::SUCCESS;
    }
    match provigil_gateway::run(s).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("provigil-gateway: {e}");
            ExitCode::FAILURE
        }
    }
}
