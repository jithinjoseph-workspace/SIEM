//! Checks SMTP settings the way maild's TLS/login extension uses them:
//! `smtp_check <host> <port> <starttls|tls|none> <user> <password> <to>`.

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() != 6 {
        eprintln!("usage: smtp_check <host> <port> <starttls|tls|none> <user> <password> <to>");
        std::process::exit(2);
    }
    let auth = siem_maild::smtp_ext::SmtpAuth { host: a[0].clone(), port: a[1].parse().expect("port"), security: a[2].clone(), user: a[3].clone(), password: a[4].clone() };
    match siem_maild::smtp_ext::send_test(&auth, &a[3], &a[5]) {
        Ok(()) => println!("sent"),
        Err(e) => {
            println!("failed: {e}");
            std::process::exit(1);
        }
    }
}
