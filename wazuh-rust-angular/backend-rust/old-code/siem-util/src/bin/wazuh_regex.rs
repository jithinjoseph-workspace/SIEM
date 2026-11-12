use siem_util::regex_evaluator::RegexEvaluator;
use std::env;
use std::io::{self, BufRead};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "-h" {
        println!("\nWazuh wazuh-regex: Test regular expression patterns against input.");
        println!("Usage: wazuh-regex <pattern>");
        return;
    }

    let pattern = &args[1];
    println!("Compiled pattern: {pattern}");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        if let Ok(l) = line {
            match RegexEvaluator::evaluate_os_regex(pattern, &l) {
                Ok(res) => {
                    if res.matched {
                        println!("+OSRegex_Execute: {l}");
                        for (idx, cap) in res.captures.iter().enumerate() {
                            println!(" -Substring {idx}: {cap}");
                        }
                    } else {
                        println!("-No match: {l}");
                    }
                }
                Err(e) => {
                    eprintln!("Regex syntax error: {e}");
                    break;
                }
            }
        }
    }
}
