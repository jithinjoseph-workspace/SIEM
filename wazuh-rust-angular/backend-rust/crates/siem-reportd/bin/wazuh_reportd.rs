//! Wazuh Reportd CLI Binary (`src/reportd/report.c`)

use siem_reportd::engine::ReportEngine;
use siem_reportd::filter::ReportFilter;
use std::env;
use std::fs::File;
use std::io::{self, BufReader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut filter = ReportFilter::default();
    let mut input_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-f" => {
                if i + 2 < args.len() {
                    let field = &args[i + 1];
                    let val = &args[i + 2];
                    match field.as_str() {
                        "group" => filter.group = Some(val.clone()),
                        "rule" => filter.rule = Some(val.clone()),
                        "level" => filter.level = val.parse::<u32>().ok(),
                        "location" => filter.location = Some(val.clone()),
                        "srcip" => filter.srcip = Some(val.clone()),
                        "user" => filter.user = Some(val.clone()),
                        "filename" => filter.filename = Some(val.clone()),
                        _ => eprintln!("Warning: unknown filter field '{}'", field),
                    }
                    i += 2;
                }
            }
            "-r" => {
                if i + 2 < args.len() {
                    filter.related_field = Some(args[i + 1].clone());
                    filter.related_value = Some(args[i + 2].clone());
                    i += 2;
                }
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
            "-i" | "--input" => {
                if i + 1 < args.len() {
                    input_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-h" | "--help" => {
                println!("Usage: wazuh-reportd [-f <field> <value>] [-r <field1> <field2>] [-n <name>] [-s] [-i <file>]");
                println!("  -f <filter> <val>   Filter by: group, rule, level, location, srcip, user, filename");
                println!("  -r <f1> <f2>        Show related cross-tabulation breakdown");
                println!("  -n <name>           Report title name");
                println!("  -s                  Show matching alert samples");
                println!("  -i <file>           Input alerts file (defaults to STDIN)");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let mut engine = ReportEngine::new();

    if let Some(ref path) = input_file {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        engine.process_stream(reader, &filter);
    } else {
        let stdin = io::stdin();
        let reader = stdin.lock();
        engine.process_stream(reader, &filter);
    }

    let stdout = io::stdout();
    let handle = stdout.lock();
    engine.write_report(handle, &filter)?;

    Ok(())
}
