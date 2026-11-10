use siem_util::agent_control_ops::{AgentControlOps, AgentFilter, OutputFormat};
use siem_wdb::GlobalDb;
use std::env;

fn print_help() {
    println!("\nWazuh agent_control: Control remote agents.");
    println!("Available options:");
    println!("   -h                This help message.");
    println!("   -l                List available (active or not) agents.");
    println!("   -lc               List active agents only.");
    println!("   -ln               List disconnected agents only.");
    println!("   -i <id>           Extracts information from an agent.");
    println!("   -R -a             Restart all agents.");
    println!("   -R -u <id>        Restart the specified agent.");
    println!("   -r -a             Runs the integrity/rootkit checking on all agents now.");
    println!("   -r -u <id>        Runs the integrity/rootkit checking on one agent now.");
    println!("   -s                Changes the output to CSV (comma delimited).");
    println!("   -j                Changes the output to JSON.");
    println!("Available options for active response:");
    println!("   -b <ip>           Blocks the specified ip address.");
    println!("   -f <ar> -a        Used with -b, specifies which response to run. Apply AR on all agents.");
    println!("   -f <ar> -u <id>   Used with -b, specifies which response to run. Apply AR on specified agent.");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    let mut format = OutputFormat::Text;
    if args.iter().any(|a| a == "-j") {
        format = OutputFormat::Json;
    } else if args.iter().any(|a| a == "-s") {
        format = OutputFormat::Csv;
    }

    let global = GlobalDb::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" => {
                print_help();
                return;
            }
            "-l" => {
                println!("{}", AgentControlOps::list_agents(&global, AgentFilter::All, format));
                return;
            }
            "-lc" => {
                println!("{}", AgentControlOps::list_agents(&global, AgentFilter::ActiveOnly, format));
                return;
            }
            "-ln" => {
                println!("{}", AgentControlOps::list_agents(&global, AgentFilter::DisconnectedOnly, format));
                return;
            }
            "-i" => {
                if i + 1 < args.len() {
                    let agent_id: u32 = args[i + 1].parse().unwrap_or(0);
                    match AgentControlOps::get_agent_info(&global, agent_id, format) {
                        Ok(res) => println!("{res}"),
                        Err(e) => eprintln!("{e}"),
                    }
                } else {
                    eprintln!("Option -i requires an agent id");
                }
                return;
            }
            "-R" => {
                if i + 1 < args.len() && args[i + 1] == "-a" {
                    println!("Restarting all agents: {}", AgentControlOps::build_restart_command(None));
                } else if i + 2 < args.len() && args[i + 1] == "-u" {
                    let id: u32 = args[i + 2].parse().unwrap_or(0);
                    println!("Restarting agent {:03}: {}", id, AgentControlOps::build_restart_command(Some(id)));
                } else {
                    eprintln!("Usage: -R -a | -R -u <id>");
                }
                return;
            }
            "-r" => {
                if i + 1 < args.len() && args[i + 1] == "-a" {
                    println!("Running syscheck on all agents: {}", AgentControlOps::build_syscheck_command(None));
                } else if i + 2 < args.len() && args[i + 1] == "-u" {
                    let id: u32 = args[i + 2].parse().unwrap_or(0);
                    println!("Running syscheck on agent {:03}: {}", id, AgentControlOps::build_syscheck_command(Some(id)));
                } else {
                    eprintln!("Usage: -r -a | -r -u <id>");
                }
                return;
            }
            _ => {}
        }
        i += 1;
    }
}
