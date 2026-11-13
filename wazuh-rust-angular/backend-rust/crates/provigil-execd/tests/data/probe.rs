// A stand-in response program for the comparison tests: records the lines it reads in
// `probe.log` (in its working folder) and answers with the line in `probe.answer`, if any.
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open("probe.log").unwrap();
    if let Some(Ok(first)) = lines.next() {
        writeln!(log, "IN1 {first}").unwrap();
        // no answer: end at once, as a program that has nothing to undo does
        match std::fs::read_to_string("probe.answer") {
            Ok(a) if !a.is_empty() => {
                let mut out = std::io::stdout();
                let _ = writeln!(out, "{}", a.trim_end());
                let _ = out.flush();
            }
            _ => return,
        }
        if let Some(Ok(second)) = lines.next() {
            writeln!(log, "IN2 {second}").unwrap();
        }
    }
}
