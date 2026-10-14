//! Wazuh Logtest CLI Tool (mirroring src/analysisd/logtest.c `wazuh-logtest`)
//!
//! Interactive command-line tool to test and debug rules and decoders.
//! Usage:
//!   wazuh-logtest
//!   echo "Oct 03 14:00:00 ubuntu sshd[1234]: Failed password..." | wazuh-logtest

use siem_engine::logtest::LogtestEngine;
use std::io::{self, BufRead};

fn main() {
    println!("Starting wazuh-logtest v4.14.7 (Rust Engine)");
    println!("Type one log per line to analyze (press Ctrl+C or Ctrl+D to exit):");
    println!("-----------------------------------------------------------------");

    let logtest = LogtestEngine::default();
    let stdin = io::stdin();
    let handle = stdin.lock();

    for line in handle.lines() {
        match line {
            Ok(l) => {
                let trimmed = l.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let res = logtest.test_log(trimmed);
                println!("{}", res.format_wazuh_output());
                println!("-----------------------------------------------------------------");
            }
            Err(_) => break,
        }
    }
}
