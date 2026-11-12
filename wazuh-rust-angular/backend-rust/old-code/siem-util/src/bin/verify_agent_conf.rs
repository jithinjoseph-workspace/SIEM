use siem_util::agent_conf_validator::AgentConfValidator;
use std::env;

fn print_help() {
    println!("\nWazuh verify-agent-conf: Verify agent.conf syntax for errors.");
    println!("Usage: verify-agent-conf [-f <agent.conf file>]");
    println!("Available options:");
    println!("   -h          This help message.");
    println!("   -f          Full file name and path to config file to be tested.");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    if args[1] == "-h" {
        print_help();
        return;
    }

    if args[1] == "-f" {
        if args.len() < 3 {
            eprintln!("Option -f requires a file argument");
            return;
        }
        let file_path = &args[2];
        match AgentConfValidator::validate_file(file_path) {
            Ok(()) => println!("verify-agent-conf: OK"),
            Err(e) => {
                eprintln!("verify-agent-conf: ERROR: {e}");
                std::process::exit(1);
            }
        }
    } else {
        print_help();
    }
}
