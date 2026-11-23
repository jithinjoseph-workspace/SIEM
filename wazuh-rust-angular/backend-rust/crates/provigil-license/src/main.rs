//! provigil-license: issue and check licences, sign and check update packages.
//!
//! Key pair (once, kept offline by ProVigil; only public.pem goes to clients and into release builds):
//!   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem
//!   openssl pkey -in private.pem -pubout -out public.pem

use provigil_license::{issue, sign_file, verify, verify_file, Claims, BUILT_IN_KEY};
use std::path::Path;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage:
  provigil-license issue  --key private.pem --tenant ID --customer NAME --days N [--pcs N] [--eps N] [--sensors N] [--features a,b]
  provigil-license show   [--pub public.pem] TOKEN | @token-file
  provigil-license sign   --key private.pem FILE          (writes FILE.sig)
  provigil-license verify [--pub public.pem] FILE         (checks FILE.sig; exit 0 = good)
--pub defaults to the public key built into this program, when it has one.";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn fail(m: &str) -> ! {
    eprintln!("{m}");
    exit(1)
}

/// `--name value` options and the rest, in order.
fn parse(args: &[String]) -> (std::collections::HashMap<String, String>, Vec<String>) {
    let (mut opts, mut rest) = (std::collections::HashMap::new(), Vec::new());
    let mut i = 0;
    while i < args.len() {
        if let Some(k) = args[i].strip_prefix("--") {
            let v = args.get(i + 1).cloned().unwrap_or_else(|| fail(&format!("--{k} needs a value")));
            opts.insert(k.to_string(), v);
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    (opts, rest)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("{path}: {e}")))
}

fn public_key(o: &std::collections::HashMap<String, String>) -> String {
    match o.get("pub") {
        Some(p) => read(p),
        None => BUILT_IN_KEY.map(str::to_string).unwrap_or_else(|| fail("no --pub given and no key built in")),
    }
}

fn num(o: &std::collections::HashMap<String, String>, k: &str) -> u32 {
    o.get(k).map(|v| v.parse().unwrap_or_else(|_| fail(&format!("--{k} must be a number")))).unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { fail(USAGE) };
    let (o, rest) = parse(&args[1..]);
    match cmd.as_str() {
        "issue" => {
            let key = read(o.get("key").unwrap_or_else(|| fail(USAGE)));
            let days = num(&o, "days");
            if days == 0 {
                fail("--days is required");
            }
            let tenant = o.get("tenant").cloned().unwrap_or_else(|| fail("--tenant is required"));
            let c = Claims {
                tenant_id: tenant,
                tenant_name: o.get("customer").cloned().unwrap_or_else(|| fail("--customer is required")),
                features: o.get("features").map(|f| f.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_else(|| vec!["siem".into()]),
                max_sensors: num(&o, "sensors"),
                issued_by: "ProVigil".into(),
                iat: now(),
                exp: now() + u64::from(days) * 86_400,
                max_agents: num(&o, "pcs"),
                max_eps: num(&o, "eps"),
            };
            println!("{}", issue(&c, &key).unwrap_or_else(|e| fail(&e)));
        }
        "show" => {
            let t = rest.first().unwrap_or_else(|| fail(USAGE));
            let token = if let Some(f) = t.strip_prefix('@') { read(f) } else { t.clone() };
            let c = verify(&token, &public_key(&o)).unwrap_or_else(|e| fail(&e));
            println!("{}", serde_json::to_string_pretty(&c).unwrap_or_default());
            if c.exp <= now() {
                fail("EXPIRED");
            }
            println!("valid, {} days left", (c.exp - now()) / 86_400);
        }
        "sign" => {
            let key = read(o.get("key").unwrap_or_else(|| fail(USAGE)));
            let f = rest.first().unwrap_or_else(|| fail(USAGE));
            let sig = sign_file(Path::new(f), &key).unwrap_or_else(|e| fail(&e));
            std::fs::write(format!("{f}.sig"), sig).unwrap_or_else(|e| fail(&e.to_string()));
            println!("signed: {f}.sig");
        }
        "verify" => {
            let f = rest.first().unwrap_or_else(|| fail(USAGE));
            let sig = read(&format!("{f}.sig"));
            verify_file(Path::new(f), &sig, &public_key(&o)).unwrap_or_else(|e| fail(&e));
            println!("good signature: {f}");
        }
        _ => fail(USAGE),
    }
}
