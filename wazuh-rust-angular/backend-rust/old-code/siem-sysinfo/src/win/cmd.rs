//! `Utils::exec` (cmdHelper.h): `_popen(cmd, "r")` and read it all.

/// The command's stdout (through `%COMSPEC% /c`, like `_popen`).
pub fn exec(cmd: &str) -> String {
    let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into());
    match std::process::Command::new(comspec).arg("/c").arg(cmd).stderr(std::process::Stdio::inherit()).output() {
        // _popen "r" is a text stream: CR LF becomes LF
        Ok(o) => String::from_utf8_lossy(&o.stdout).replace("\r\n", "\n"),
        Err(_) => String::new(),
    }
}
