//! Wazuh Manage Agents CLI (`src/addagent/main.c`, `manage_agents.c`, `manage_keys.c`, `validate.c`)
//!
//! Provides the command-line and interactive menu utility for managing agents
//! and authentication keys in `client.keys`.

use base64::Engine;
use siem_crypto::keys::KeyStore;
use siem_shared::keys::{AgentKeyEntry, ClientKeys};
use siem_shared::validate::{is_valid_agent_id, is_valid_agent_ip, is_valid_agent_name};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const WAZUH_VERSION: &str = "v4.14.7";
const DEFAULT_CLIENT_KEYS: &str = "client.keys";

fn find_keys_path(custom: Option<&str>) -> PathBuf {
    if let Some(p) = custom {
        return PathBuf::from(p);
    }
    if let Ok(env_path) = env::var("CLIENT_KEYS_PATH") {
        return PathBuf::from(env_path);
    }

    let default_paths = [
        "/var/ossec/etc/client.keys",
        "etc/client.keys",
        "client.keys",
    ];

    for p in default_paths {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }

    PathBuf::from(DEFAULT_CLIENT_KEYS)
}

fn load_keys(path: &Path) -> ClientKeys {
    if path.exists() {
        ClientKeys::load_file(path).unwrap_or_else(|e| {
            eprintln!("Notice: Could not parse existing {}: {}. Starting fresh.", path.display(), e);
            ClientKeys::new()
        })
    } else {
        ClientKeys::new()
    }
}

fn next_available_id(keys: &ClientKeys) -> String {
    let mut max_id: u32 = 0;
    for agent in keys.list_agents() {
        if let Ok(id_num) = agent.id.parse::<u32>() {
            if id_num > max_id {
                max_id = id_num;
            }
        }
    }
    format!("{:03}", max_id + 1)
}

fn do_list(keys: &ClientKeys, json_output: bool) {
    let mut agents = keys.list_agents();
    agents.sort_by(|a, b| a.id.cmp(&b.id));

    if json_output {
        let json_arr: Vec<_> = agents.iter().map(|a| {
            serde_json::json!({
                "id": a.id,
                "name": a.name,
                "ip": a.ip,
            })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&json_arr).unwrap());
        return;
    }

    println!("\nAvailable agents: ");
    if agents.is_empty() {
        println!("   No agent available.");
    } else {
        for a in agents {
            println!("   ID: {}, Name: {}, IP: {}", a.id, a.name, a.ip);
        }
    }
    println!();
}

fn do_add(
    keys: &mut ClientKeys,
    keys_path: &Path,
    name: &str,
    ip: &str,
    custom_id: Option<&str>,
    json_output: bool,
) -> Result<AgentKeyEntry, String> {
    if !is_valid_agent_name(name) {
        return Err(format!("Invalid agent name: '{}'. Must be alphanumeric with '.', '-', '_', max 128 chars.", name));
    }
    if !is_valid_agent_ip(ip) {
        return Err(format!("Invalid IP or network CIDR: '{}'.", ip));
    }

    if keys.get_by_name(name).is_some() {
        return Err(format!("Agent with name '{}' already exists.", name));
    }

    let id = match custom_id {
        Some(cid) => {
            if !is_valid_agent_id(cid) {
                return Err(format!("Invalid custom agent ID: '{}'.", cid));
            }
            if keys.get_by_id(cid).is_some() {
                return Err(format!("Agent with ID '{}' already exists.", cid));
            }
            cid.to_string()
        }
        None => next_available_id(keys),
    };

    let raw_key = KeyStore::generate_raw_key();

    keys.add_agent(&id, name, ip, &raw_key)?;
    keys.save_atomic(keys_path)?;

    let entry = AgentKeyEntry {
        id,
        name: name.to_string(),
        ip: ip.to_string(),
        key: raw_key,
    };

    if json_output {
        println!("{}", serde_json::to_string(&entry).unwrap());
    } else {
        println!("Agent key information for '{}' is: ", entry.id);
        println!("   ID: {}", entry.id);
        println!("   Name: {}", entry.name);
        println!("   IP Address: {}", entry.ip);
        println!("   Key: {}", entry.key);
    }

    Ok(entry)
}

fn do_extract(keys: &ClientKeys, id: &str, json_output: bool) -> Result<String, String> {
    let agent = keys
        .get_by_id(id)
        .ok_or_else(|| format!("Agent with ID '{}' does not exist.", id))?;

    let raw_entry = format!("{} {} {} {}", agent.id, agent.name, agent.ip, agent.key);
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw_entry.as_bytes());

    if json_output {
        println!("{}", serde_json::json!({ "id": agent.id, "key": b64 }));
    } else {
        println!("\nAgent key information for '{}' is: ", agent.id);
        println!("   {}", b64);
        println!();
    }

    Ok(b64)
}

fn do_remove(keys: &mut ClientKeys, keys_path: &Path, id: &str, json_output: bool) -> Result<(), String> {
    let removed = keys
        .remove_agent(id)
        .ok_or_else(|| format!("Agent with ID '{}' does not exist.", id))?;

    keys.save_atomic(keys_path)?;

    if json_output {
        println!("{}", serde_json::json!({ "status": "ok", "removed_id": removed.id }));
    } else {
        println!("Agent '{}' removed successfully.", id);
    }

    Ok(())
}

fn do_import(keys_path: &Path, b64_key: &str, json_output: bool) -> Result<AgentKeyEntry, String> {
    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_key.trim())
        .map_err(|e| format!("Invalid base64 key string: {}", e))?;

    let decoded_str = String::from_utf8(decoded_bytes)
        .map_err(|e| format!("Invalid UTF-8 in key: {}", e))?;

    let tokens: Vec<&str> = decoded_str.split_whitespace().collect();
    if tokens.len() < 4 {
        return Err("Imported key must contain 4 tokens: ID NAME IP KEY".to_string());
    }

    let id = tokens[0];
    let name = tokens[1];
    let ip = tokens[2];
    let key = tokens[3];

    let mut single_keys = ClientKeys::new();
    single_keys.add_agent(id, name, ip, key)?;
    single_keys.save_atomic(keys_path)?;

    let entry = AgentKeyEntry {
        id: id.to_string(),
        name: name.to_string(),
        ip: ip.to_string(),
        key: key.to_string(),
    };

    if json_output {
        println!("{}", serde_json::to_string(&entry).unwrap());
    } else {
        println!("Agent key imported successfully:");
        println!("   ID: {}", entry.id);
        println!("   Name: {}", entry.name);
        println!("   IP Address: {}", entry.ip);
    }

    Ok(entry)
}

fn do_bulk_add(keys: &mut ClientKeys, keys_path: &Path, file_path: &str, json_output: bool) -> Result<(), String> {
    let file = File::open(file_path).map_err(|e| format!("Failed to open file {}: {}", file_path, e))?;
    let reader = BufReader::new(file);

    let mut count = 0;
    for (line_idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Accepts CSV (name,ip) or whitespace (name ip)
        let parts: Vec<&str> = if trimmed.contains(',') {
            trimmed.split(',').map(|s| s.trim()).collect()
        } else {
            trimmed.split_whitespace().collect()
        };

        if parts.len() < 2 {
            eprintln!("Line {}: skipped invalid entry '{}'", line_idx + 1, trimmed);
            continue;
        }

        let name = parts[0];
        let ip = parts[1];

        match do_add(keys, keys_path, name, ip, None, false) {
            Ok(_) => count += 1,
            Err(e) => eprintln!("Line {}: error adding agent '{}': {}", line_idx + 1, name, e),
        }
    }

    if json_output {
        println!("{}", serde_json::json!({ "added": count }));
    } else {
        println!("Bulk add completed: {} agents added.", count);
    }

    Ok(())
}

fn read_line_prompt(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    input.trim().to_string()
}

fn interactive_menu(mut keys: ClientKeys, keys_path: PathBuf) {
    loop {
        println!("****************************************");
        println!("* Wazuh-Manage-Agents - Manage keys    *");
        println!("****************************************");
        println!("\nChoose your action:\n");
        println!("   (A)dd an agent (A).");
        println!("   (E)xtract key for an agent (E).");
        println!("   (L)ist available agents (L).");
        println!("   (I)mport key from the server (I).");
        println!("   (R)emove an agent (R).");
        println!("   (Q)uit (Q).");

        let choice = read_line_prompt("Choose your action: A,E,L,I,R or Q: ");
        let choice_upper = choice.to_uppercase();

        match choice_upper.as_str() {
            "A" => {
                println!("\n- Adding a new agent (use '\\q' to return to the menu):");
                let name = read_line_prompt("   Please provide a name for the new agent: ");
                if name == "\\q" {
                    continue;
                }
                let ip = read_line_prompt("   Please provide the IP Address of the new agent [any]: ");
                if ip == "\\q" {
                    continue;
                }
                let ip_val = if ip.is_empty() { "any" } else { &ip };
                let custom_id = read_line_prompt("   An ID will be generated. Type a custom ID or press Enter to auto-generate: ");
                let id_opt = if custom_id.is_empty() || custom_id == "\\q" { None } else { Some(custom_id.as_str()) };

                println!("\nAgent information:");
                println!("   Name: {}", name);
                println!("   IP Address: {}", ip_val);
                let confirm = read_line_prompt("Confirm adding it?(y/n): ");
                if confirm.eq_ignore_ascii_case("y") {
                    if let Err(e) = do_add(&mut keys, &keys_path, &name, ip_val, id_opt, false) {
                        eprintln!("Error: {}", e);
                    }
                }
            }
            "E" => {
                let id = read_line_prompt("\nProvide the ID of the agent to extract the key (or '\\q' to quit): ");
                if id != "\\q" && !id.is_empty() {
                    if let Err(e) = do_extract(&keys, &id, false) {
                        eprintln!("Error: {}", e);
                    }
                }
            }
            "L" => {
                do_list(&keys, false);
            }
            "I" => {
                let key_str = read_line_prompt("\nProvide the Key generated by the server: ");
                if !key_str.is_empty() && key_str != "\\q" {
                    if let Err(e) = do_import(&keys_path, &key_str, false) {
                        eprintln!("Error: {}", e);
                    } else {
                        // Reload keys
                        keys = load_keys(&keys_path);
                    }
                }
            }
            "R" => {
                let id = read_line_prompt("\nProvide the ID of the agent to be removed (or '\\q' to quit): ");
                if id != "\\q" && !id.is_empty() {
                    let confirm = read_line_prompt(&format!("Confirm deleting agent '{}'?(y/n): ", id));
                    if confirm.eq_ignore_ascii_case("y") {
                        if let Err(e) = do_remove(&mut keys, &keys_path, &id, false) {
                            eprintln!("Error: {}", e);
                        }
                    }
                }
            }
            "Q" => {
                println!("Exiting manage-agents.");
                break;
            }
            _ => {
                println!("Invalid option. Please choose A, E, L, I, R or Q.");
            }
        }
    }
}

fn print_help() {
    println!("Wazuh {} - Manage Agents CLI", WAZUH_VERSION);
    println!("Usage: manage-agents [options]");
    println!();
    println!("Options:");
    println!("  -l                  List available agents");
    println!("  -a <ip>             Add agent with IP (prompts for name if -n omitted)");
    println!("  -n <name>           Specify agent name (with -a)");
    println!("  -e <id>             Extract authentication key for agent ID");
    println!("  -r <id>             Remove agent with ID");
    println!("  -i <key>            Import key (agent side)");
    println!("  -f <file>           Bulk add agents from file");
    println!("  -c <path>           Custom path to client.keys");
    println!("  -j                  Output results in JSON format");
    println!("  -m                  Launch interactive menu mode");
    println!("  -V                  Display version");
    println!("  -h, --help          Display this help message");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut custom_keys_path: Option<&str> = None;
    let mut json_output = false;
    let mut force_menu = false;

    let mut action_list = false;
    let mut action_add_ip: Option<String> = None;
    let mut action_add_name: Option<String> = None;
    let mut action_extract_id: Option<String> = None;
    let mut action_remove_id: Option<String> = None;
    let mut action_import_key: Option<String> = None;
    let mut action_bulk_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    custom_keys_path = Some(&args[i + 1]);
                    i += 1;
                }
            }
            "-j" => json_output = true,
            "-m" => force_menu = true,
            "-l" => action_list = true,
            "-a" => {
                if i + 1 < args.len() {
                    action_add_ip = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-n" => {
                if i + 1 < args.len() {
                    action_add_name = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-e" => {
                if i + 1 < args.len() {
                    action_extract_id = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-r" => {
                if i + 1 < args.len() {
                    action_remove_id = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-i" => {
                if i + 1 < args.len() {
                    action_import_key = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-f" => {
                if i + 1 < args.len() {
                    action_bulk_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-V" => {
                println!("Wazuh {} - Manage Agents", WAZUH_VERSION);
                return Ok(());
            }
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let keys_path = find_keys_path(custom_keys_path);
    let mut keys = load_keys(&keys_path);

    // If no action flags given, run interactive menu
    let has_action = action_list
        || action_add_ip.is_some()
        || action_extract_id.is_some()
        || action_remove_id.is_some()
        || action_import_key.is_some()
        || action_bulk_file.is_some();

    if force_menu || !has_action {
        interactive_menu(keys, keys_path);
        return Ok(());
    }

    if action_list {
        do_list(&keys, json_output);
    }

    if let Some(ip) = action_add_ip {
        let name = action_add_name.unwrap_or_else(|| {
            read_line_prompt("Enter agent name: ")
        });
        if let Err(e) = do_add(&mut keys, &keys_path, &name, &ip, None, json_output) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    if let Some(id) = action_extract_id {
        if let Err(e) = do_extract(&keys, &id, json_output) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    if let Some(id) = action_remove_id {
        if let Err(e) = do_remove(&mut keys, &keys_path, &id, json_output) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    if let Some(key_str) = action_import_key {
        if let Err(e) = do_import(&keys_path, &key_str, json_output) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    if let Some(file_str) = action_bulk_file {
        if let Err(e) = do_bulk_add(&mut keys, &keys_path, &file_str, json_output) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
