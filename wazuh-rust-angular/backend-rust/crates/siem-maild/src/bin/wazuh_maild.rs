use siem_maild::config::MailConfig;
use siem_maild::maild::MailDaemon;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut config_path = "var/ossec/etc/ossec.conf".to_string();
    let mut test_config = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    config_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "-t" => {
                test_config = true;
            }
            "-V" => {
                println!("Wazuh v4.14.7 - wazuh-maild (Rust engine)");
                return;
            }
            "-h" | "--help" => {
                println!("Wazuh wazuh-maild: Alert email notification daemon");
                println!("Usage: wazuh-maild [-c config] [-t] [-V] [-h]");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    println!("Starting wazuh-maild (Rust engine)...");
    let config = if std::path::Path::new(&config_path).exists() {
        match MailConfig::parse_file(&config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Warning: Failed to parse {}: {}. Using default config.", config_path, e);
                MailConfig::default()
            }
        }
    } else {
        println!("Config file '{}' not found, using default mail configuration.", config_path);
        MailConfig::default()
    };

    if test_config {
        println!("Configuration test successful: SMTP server={}, to={:?}", config.smtpserver, config.to);
        return;
    }

    let _daemon = MailDaemon::new(config);
    println!("wazuh-maild daemon initialized successfully.");
}
