//! Wazuh Agent Enrollment Client CLI (`src/os_auth/main-client.c`)

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut manager_ip: Option<String> = None;
    let mut port: u16 = 1515;
    let mut agent_name: Option<String> = None;
    let mut password: Option<String> = None;
    let mut groups: Option<String> = None;
    let mut sender_ip: Option<String> = None;
    let mut use_src_ip = false;
    let mut out_file: String = "etc/client.keys".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-m" => {
                if i + 1 < args.len() {
                    manager_ip = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-p" => {
                if i + 1 < args.len() {
                    if let Ok(p) = args[i + 1].parse::<u16>() {
                        port = p;
                    }
                    i += 1;
                }
            }
            "-A" => {
                if i + 1 < args.len() {
                    agent_name = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-P" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-G" => {
                if i + 1 < args.len() {
                    groups = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-I" => {
                if i + 1 < args.len() {
                    sender_ip = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-i" => {
                use_src_ip = true;
            }
            "-k" => {
                if i + 1 < args.len() {
                    out_file = args[i + 1].clone();
                    i += 1;
                }
            }
            "-h" | "--help" => {
                println!("Usage: agent-auth -m <manager_ip> [-p <port>] [-A <agent_name>] [-P <pass>] [-G <groups>] [-I <ip> | -i]");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let manager = match manager_ip {
        Some(m) => m,
        None => {
            eprintln!("Error: Manager IP address (-m) is required.");
            std::process::exit(1);
        }
    };

    let name = agent_name.unwrap_or_else(|| {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    });

    let mut request = String::new();
    if let Some(pw) = password {
        request.push_str(&format!("OSSEC PASS: {} ", pw));
    }
    request.push_str(&format!("OSSEC A:'{}'", name));
    request.push_str(" V:'v4.14.7'");

    if let Some(g) = groups {
        request.push_str(&format!(" G:'{}'", g));
    }

    if let Some(ip) = sender_ip {
        request.push_str(&format!(" IP:'{}'", ip));
    } else if use_src_ip {
        request.push_str(" IP:'src'");
    }

    request.push('\n');

    let target = format!("{}:{}", manager, port);
    println!("Connecting to {}...", target);

    let mut stream = TcpStream::connect(&target).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let (reader, _) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut response = String::new();
    buf_reader.read_line(&mut response).await?;

    let trimmed = response.trim();
    if trimmed.starts_with("OSSEC K:'") && trimmed.ends_with('\'') {
        let key_data = &trimmed[9..trimmed.len() - 1];
        println!("Received key: {}", key_data);

        // Append to client.keys
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out_file)?;
        writeln!(file, "{}", key_data)?;

        println!("Key successfully added to: {}", out_file);
        Ok(())
    } else {
        eprintln!("Enrollment failed: {}", trimmed);
        std::process::exit(1);
    }
}
