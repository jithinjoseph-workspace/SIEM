use siem_util::agent_control_ops::{AgentControlOps, AgentFilter, OutputFormat};
use siem_wdb::GlobalDb;
use std::env;

fn print_help() {
    println!("\nWazuh list_agents: List available agents.");
    println!("Available options:");
    println!("   -h    This help message.");
    println!("   -a    List all agents.");
    println!("   -c    List the connected (active) agents.");
    println!("   -n    List the not connected agents.");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    let global = GlobalDb::new();

    match args[1].as_str() {
        "-h" => print_help(),
        "-a" => println!("{}", AgentControlOps::list_agents(&global, AgentFilter::All, OutputFormat::Text)),
        "-c" => println!("{}", AgentControlOps::list_agents(&global, AgentFilter::ActiveOnly, OutputFormat::Text)),
        "-n" => println!("{}", AgentControlOps::list_agents(&global, AgentFilter::DisconnectedOnly, OutputFormat::Text)),
        other => {
            eprintln!("Invalid option '{other}'.");
            print_help();
        }
    }
}
