//! Wazuh Reportd CLI (reportd/report.c)
//!
//! Generates summary reports from stdin or alerts files based on filtering rules and relations.

use std::env;
use std::io::{self, BufRead};
use siem_util::report_generator::{AlertItem, ReportFilter, ReportGenerator};

fn print_help() {
    println!("  Generate reports (via stdin)");
    println!("  wazuh-reportd: -[Vhdtns] [-f filter value] [-r filter value] [-t field]");
    println!("    -V          Version and license message");
    println!("    -h          This help message");
    println!("    -n <name>   Create description for the report");
    println!("    -s          Show the alert dump");
    println!("    -t <field>  Set top field to summarize (rule, level, srcip, user, location)");
    println!("    -f <filter> <value> Filter the results");
    println!("    -r <primary> <related> Show related entries");
    println!("    Filters allowed: group, rule, level, location, user, srcip, filename");
    println!("  Examples:");
    println!("     cat alerts.json | wazuh-reportd -f group authentication_success");
    println!("     cat alerts.json | wazuh-reportd -f level 10");
    println!("     cat alerts.json | wazuh-reportd -f group authentication -r user srcip");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut filter = ReportFilter::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-V" | "--version" => {
                println!("Wazuh v4.14.7 - Wazuh Report Generator (wazuh-reportd)");
                return;
            }
            "-n" => {
                if i + 1 < args.len() {
                    filter.report_name = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-s" => {
                filter.show_alerts = true;
            }
            "-t" => {
                if i + 1 < args.len() {
                    filter.top_field = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-f" => {
                if i + 2 < args.len() {
                    let field = args[i + 1].to_lowercase();
                    let val = args[i + 2].clone();
                    match field.as_str() {
                        "group" => filter.group = Some(val),
                        "rule" | "rule_id" => filter.rule = Some(val),
                        "level" => filter.min_level = val.parse::<u32>().ok(),
                        "location" => filter.location = Some(val),
                        "srcip" => filter.srcip = Some(val),
                        "user" => filter.user = Some(val),
                        "filename" | "file" => filter.filename = Some(val),
                        other => eprintln!("Unknown filter: {}", other),
                    }
                    i += 2;
                }
            }
            "-r" => {
                if i + 2 < args.len() {
                    let primary = args[i + 1].clone();
                    let related = args[i + 2].clone();
                    filter.related = Some((primary, related));
                    i += 2;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let mut generator = ReportGenerator::new(filter);
    let stdin = io::stdin();
    let reader = stdin.lock();

    for line in reader.lines() {
        if let Ok(l) = line {
            let trimmed = l.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Attempt JSON alert format first
            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(alert) = AlertItem::from_json(&json_val) {
                    generator.process_alert(alert);
                }
            }
        }
    }

    print!("{}", generator.generate_report());
}
