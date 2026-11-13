// A stand-in agentless script for the comparison tests: prints `lessprobe.out` (from its working
// folder) and ends with the exit code in `lessprobe.code` (0 without one); records its arguments.
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open("lessprobe.args").unwrap();
    writeln!(log, "{}", args.join(" ")).unwrap();
    if let Ok(out) = std::fs::read("lessprobe.out") {
        let mut o = std::io::stdout();
        let _ = o.write_all(&out);
        let _ = o.flush();
    }
    let code = std::fs::read_to_string("lessprobe.code").ok().and_then(|c| c.trim().parse().ok()).unwrap_or(0);
    std::process::exit(code);
}
