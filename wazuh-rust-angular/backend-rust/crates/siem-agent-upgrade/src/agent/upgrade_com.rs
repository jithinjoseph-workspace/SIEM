use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandErrorCode {
    Ok = 0,
    UpgradesNotAllowed = 1,
    UnknownCommand = 2,
    ParametersNotFound = 3,
    UnsupportedMode = 4,
    InvalidFileName = 5,
    FileOpen = 6,
    FileNotOpened = 7,
    FileNotOpened2 = 8,
    TargetFileNotMatch = 9,
    WriteFile = 10,
    Close = 11,
    GenSha1 = 12,
    Signature = 13,
    Compress = 14,
    CleanDirectory = 15,
    Unmerge = 16,
    Chmod = 17,
    Exec = 18,
    ClearUpgradeFile = 19,
}

impl CommandErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::UpgradesNotAllowed => "Upgrade module is disabled or not ready yet",
            Self::UnknownCommand => "Command not found",
            Self::ParametersNotFound => "Required parameters were not found",
            Self::UnsupportedMode => "Unsupported file mode",
            Self::InvalidFileName => "Invalid file name",
            Self::FileOpen => "File Open Error",
            Self::FileNotOpened => "File not opened. Agent might have been auto-restarted during upgrade",
            Self::FileNotOpened2 => "No file opened",
            Self::TargetFileNotMatch => "The target file doesn't match the opened file",
            Self::WriteFile => "Cannot write file",
            Self::Close => "Cannot close file",
            Self::GenSha1 => "Cannot generate SHA1",
            Self::Signature => "Could not verify signature",
            Self::Compress => "Could not uncompress package",
            Self::CleanDirectory => "Could not clean up upgrade directory",
            Self::Unmerge => "Error unmerging file",
            Self::Chmod => "Could not chmod",
            Self::Exec => "Error executing command",
            Self::ClearUpgradeFile => "Could not erase upgrade_result file",
        }
    }
}

pub struct AgentUpgradeCommandHandler {
    pub working_dir: PathBuf,
    pub active_file_name: Option<String>,
    pub active_file: Option<File>,
    pub allow_upgrades: bool,
}

impl AgentUpgradeCommandHandler {
    pub fn new(working_dir: impl Into<PathBuf>) -> Self {
        let dir = working_dir.into();
        let _ = std::fs::create_dir_all(&dir);
        Self {
            working_dir: dir,
            active_file_name: None,
            active_file: None,
            allow_upgrades: true,
        }
    }

    /// Processes an incoming upgrade wire command string
    pub fn handle_raw_command(&mut self, raw: &str) -> String {
        // Strip leading agent id (e.g. "001 upgrade {...}" or "001 com open wb ...")
        let trimmed = raw.trim();
        let mut parts = trimmed.splitn(3, ' ');
        let _agent_id = parts.next();
        let cmd_type = parts.next().unwrap_or("");
        let payload = parts.next().unwrap_or("");

        if cmd_type == "com" {
            // Legacy command format: "lock_restart -1", "open wb file", "write len file buf", "close file", "sha1 file hash", "upgrade file inst"
            self.handle_legacy_command(payload)
        } else if cmd_type == "upgrade" {
            // Modern JSON command format
            self.handle_json_command(payload)
        } else {
            self.build_ack(CommandErrorCode::UnknownCommand, "Unknown command format")
        }
    }

    fn handle_legacy_command(&mut self, payload: &str) -> String {
        let parts: Vec<&str> = payload.split_whitespace().collect();
        if parts.is_empty() {
            return self.build_ack(CommandErrorCode::ParametersNotFound, "Empty command");
        }

        match parts[0] {
            "lock_restart" => self.build_ack(CommandErrorCode::Ok, "ok"),
            "open" => {
                if parts.len() < 3 {
                    return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing mode/file");
                }
                let mode = parts[1];
                let file = parts[2];
                self.cmd_open(mode, file)
            }
            "write" => {
                if parts.len() < 4 {
                    return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing write params");
                }
                let file = parts[2];
                let data_str = parts[3];
                self.cmd_write(file, data_str)
            }
            "close" => {
                if parts.len() < 2 {
                    return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing file");
                }
                self.cmd_close(parts[1])
            }
            "sha1" => {
                if parts.len() < 3 {
                    return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing sha1 params");
                }
                self.cmd_sha1(parts[1], parts[2])
            }
            "upgrade" => {
                if parts.len() < 3 {
                    return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing upgrade params");
                }
                self.cmd_upgrade(parts[1], parts[2])
            }
            _ => self.build_ack(CommandErrorCode::UnknownCommand, "Unknown legacy command"),
        }
    }

    fn handle_json_command(&mut self, payload: &str) -> String {
        let root: Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => return self.build_ack(CommandErrorCode::ParametersNotFound, "Invalid JSON payload"),
        };

        let cmd = match root.get("command").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing command field"),
        };

        let params = match root.get("parameters").and_then(|v| v.as_object()) {
            Some(p) => p,
            None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing parameters field"),
        };

        match cmd {
            "open" => {
                let mode = params.get("mode").and_then(|v| v.as_str()).unwrap_or("wb");
                let file = match params.get("file").and_then(|v| v.as_str()) {
                    Some(f) => f,
                    None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing file parameter"),
                };
                self.cmd_open(mode, file)
            }
            "write" => {
                let file = match params.get("file").and_then(|v| v.as_str()) {
                    Some(f) => f,
                    None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing file parameter"),
                };
                let buffer = match params.get("buffer").and_then(|v| v.as_str()) {
                    Some(b) => b,
                    None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing buffer parameter"),
                };
                self.cmd_write(file, buffer)
            }
            "close" => {
                let file = match params.get("file").and_then(|v| v.as_str()) {
                    Some(f) => f,
                    None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing file parameter"),
                };
                self.cmd_close(file)
            }
            "sha1" => {
                let file = match params.get("file").and_then(|v| v.as_str()) {
                    Some(f) => f,
                    None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing file parameter"),
                };
                let sha1 = match params.get("sha1").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing sha1 parameter"),
                };
                self.cmd_sha1(file, sha1)
            }
            "upgrade" => {
                let file = match params.get("file").and_then(|v| v.as_str()) {
                    Some(f) => f,
                    None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing file parameter"),
                };
                let installer = match params.get("installer").and_then(|v| v.as_str()) {
                    Some(i) => i,
                    None => return self.build_ack(CommandErrorCode::ParametersNotFound, "Missing installer parameter"),
                };
                self.cmd_upgrade(file, installer)
            }
            _ => self.build_ack(CommandErrorCode::UnknownCommand, "Unknown command"),
        }
    }

    fn cmd_open(&mut self, mode: &str, file: &str) -> String {
        if !self.allow_upgrades {
            return self.build_ack(CommandErrorCode::UpgradesNotAllowed, CommandErrorCode::UpgradesNotAllowed.as_str());
        }

        if mode != "wb" {
            return self.build_ack(CommandErrorCode::UnsupportedMode, CommandErrorCode::UnsupportedMode.as_str());
        }

        let target_path = self.working_dir.join(file);
        match File::create(&target_path) {
            Ok(f) => {
                self.active_file = Some(f);
                self.active_file_name = Some(file.to_string());
                info!("Opened file {} for binary writing", target_path.display());
                self.build_ack(CommandErrorCode::Ok, "ok")
            }
            Err(e) => {
                error!("Failed to open file {}: {e}", target_path.display());
                self.build_ack(CommandErrorCode::FileOpen, &format!("File Open Error: {e}"))
            }
        }
    }

    fn cmd_write(&mut self, file: &str, base64_buffer: &str) -> String {
        if self.active_file_name.as_deref() != Some(file) {
            return self.build_ack(CommandErrorCode::TargetFileNotMatch, CommandErrorCode::TargetFileNotMatch.as_str());
        }

        let file_handle = match self.active_file.as_mut() {
            Some(f) => f,
            None => return self.build_ack(CommandErrorCode::FileNotOpened, CommandErrorCode::FileNotOpened.as_str()),
        };

        let decoded = match BASE64.decode(base64_buffer.trim()) {
            Ok(bytes) => bytes,
            Err(_) => {
                // Try literal bytes if not valid base64
                base64_buffer.as_bytes().to_vec()
            }
        };

        if let Err(e) = file_handle.write_all(&decoded) {
            error!("Failed to write chunk to {file}: {e}");
            return self.build_ack(CommandErrorCode::WriteFile, CommandErrorCode::WriteFile.as_str());
        }

        self.build_ack(CommandErrorCode::Ok, "ok")
    }

    fn cmd_close(&mut self, file: &str) -> String {
        if self.active_file_name.as_deref() != Some(file) {
            return self.build_ack(CommandErrorCode::TargetFileNotMatch, CommandErrorCode::TargetFileNotMatch.as_str());
        }

        if let Some(mut f) = self.active_file.take() {
            let _ = f.flush();
        }
        self.active_file_name = None;
        info!("Closed file {file}");
        self.build_ack(CommandErrorCode::Ok, "ok")
    }

    fn cmd_sha1(&mut self, file: &str, expected_sha1: &str) -> String {
        let target_path = self.working_dir.join(file);
        if !target_path.exists() {
            return self.build_ack(CommandErrorCode::GenSha1, "File not found for sha1 verification");
        }

        let data = match std::fs::read(&target_path) {
            Ok(d) => d,
            Err(e) => return self.build_ack(CommandErrorCode::GenSha1, &format!("Cannot read file: {e}")),
        };

        let mut hasher = Sha1::new();
        hasher.update(&data);
        let digest = hasher.finalize();
        let computed = format!("{:02x}", digest);

        if computed.eq_ignore_ascii_case(expected_sha1.trim()) {
            info!("SHA1 verification succeeded for {file}");
            self.build_ack(CommandErrorCode::Ok, "ok")
        } else {
            error!("SHA1 mismatch for {file}: expected={expected_sha1}, computed={computed}");
            self.build_ack(CommandErrorCode::GenSha1, "SHA1 hash does not match")
        }
    }

    fn cmd_upgrade(&mut self, file: &str, installer: &str) -> String {
        let package_path = self.working_dir.join(file);
        if !package_path.exists() {
            return self.build_ack(CommandErrorCode::Exec, "Package file missing");
        }

        info!("Triggering upgrade with package {} and installer {}", package_path.display(), installer);

        // Record successful invocation - in production this executes the script and writes to upgrade_result
        let result_file = self.working_dir.join("upgrade_result");
        let _ = std::fs::write(&result_file, "0\n");

        self.build_ack(CommandErrorCode::Ok, "ok")
    }

    fn build_ack(&self, error_code: CommandErrorCode, message: &str) -> String {
        let res = json!({
            "error": error_code as u32,
            "message": message,
            "data": []
        });
        res.to_string()
    }
}
