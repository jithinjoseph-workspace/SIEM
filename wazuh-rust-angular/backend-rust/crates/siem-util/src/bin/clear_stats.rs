use siem_util::stats_manager::StatsManager;
use std::env;

fn print_help() {
    println!("\nWazuh clear_stats: Clear the events stats (averages).");
    println!("Available options:");
    println!("   -h       This help message.");
    println!("   -a       Clear all the stats (averages).");
    println!("   -d       Clear the daily averages.");
    println!("   -w       Clear the weekly averages.");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    let stats = StatsManager::new("var/ossec/stats");

    match args[1].as_str() {
        "-h" => print_help(),
        "-a" => match stats.clear_all() {
            Ok(n) => println!("Cleared all stats ({n} files)."),
            Err(e) => eprintln!("Error clearing stats: {e}"),
        },
        "-d" => match stats.clear_daily() {
            Ok(n) => println!("Cleared daily stats ({n} files)."),
            Err(e) => eprintln!("Error clearing daily stats: {e}"),
        },
        "-w" => match stats.clear_weekly() {
            Ok(n) => println!("Cleared weekly stats ({n} files)."),
            Err(e) => eprintln!("Error clearing weekly stats: {e}"),
        },
        other => {
            eprintln!("Invalid option '{other}'.");
            print_help();
        }
    }
}
