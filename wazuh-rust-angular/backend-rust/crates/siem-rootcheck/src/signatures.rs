use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitFileSignature {
    pub pattern: String,
    pub rootkit_name: String,
    pub reference: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TrojanSignature {
    pub binary_name: String,
    pub pattern: String,
    pub compiled_regex: Regex,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct RootcheckDatabase {
    pub file_signatures: Vec<RootkitFileSignature>,
    pub trojan_signatures: Vec<TrojanSignature>,
}

impl Default for RootcheckDatabase {
    fn default() -> Self {
        Self::new_with_builtin_signatures()
    }
}

impl RootcheckDatabase {
    pub fn new() -> Self {
        Self {
            file_signatures: Vec::new(),
            trojan_signatures: Vec::new(),
        }
    }

    pub fn add_file_signature(&mut self, pattern: &str, rootkit_name: &str, reference: Option<&str>) {
        self.file_signatures.push(RootkitFileSignature {
            pattern: pattern.to_string(),
            rootkit_name: rootkit_name.to_string(),
            reference: reference.map(|r| r.to_string()),
        });
    }

    pub fn add_trojan_signature(
        &mut self,
        binary_name: &str,
        pattern: &str,
        description: &str,
    ) -> Result<(), regex::Error> {
        let compiled = Regex::new(pattern)?;
        self.trojan_signatures.push(TrojanSignature {
            binary_name: binary_name.to_string(),
            pattern: pattern.to_string(),
            compiled_regex: compiled,
            description: description.to_string(),
        });
        Ok(())
    }

    /// Load rootkit files from Wazuh rootkit_files.txt format
    pub fn load_rootkit_files_from_str(&mut self, content: &str) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(bang_idx) = trimmed.find('!') {
                let pattern = trimmed[..bang_idx].trim();
                let rest = trimmed[bang_idx + 1..].trim();

                let (name, reference) = if let Some(ref_idx) = rest.find("::") {
                    let n = rest[..ref_idx].trim();
                    let r = rest[ref_idx + 2..].trim();
                    (n, if r.is_empty() { None } else { Some(r) })
                } else {
                    (rest, None)
                };

                self.add_file_signature(pattern, name, reference);
                count += 1;
            }
        }
        count
    }

    /// Load trojan binary patterns from Wazuh rootkit_trojans.txt format
    pub fn load_rootkit_trojans_from_str(&mut self, content: &str) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split('!').collect();
            if parts.len() >= 2 {
                let binary = parts[0].trim();
                let pattern = parts[1].trim();
                let desc = if parts.len() >= 3 && !parts[2].trim().is_empty() {
                    parts[2].trim()
                } else {
                    "Trojan binary infected string detected"
                };

                if let Ok(_) = self.add_trojan_signature(binary, pattern, desc) {
                    count += 1;
                }
            }
        }
        count
    }

    /// Initialize database with built-in Wazuh rootkit & trojan signatures
    pub fn new_with_builtin_signatures() -> Self {
        let mut db = Self::new();

        // High-profile Linux & Windows rootkits
        db.add_file_signature("tmp/mcliZokhb", "Bash Door", Some("/rootkits/bashdoor.php"));
        db.add_file_signature("dev/.shit/red.tgz", "Adore Worm", Some("/rootkits/adorew.php"));
        db.add_file_signature("usr/bin/adore", "Adore Worm", Some("/rootkits/adorew.php"));
        db.add_file_signature("usr/lib/libt", "Adore Worm", Some("/rootkits/adorew.php"));
        db.add_file_signature("usr/bin/sourcemask", "TRK Rootkit", Some("/rootkits/trk.php"));
        db.add_file_signature("lib/security/.config", "Illogic Rootkit", Some("/rootkits/illogic.php"));
        db.add_file_signature("dev/ida/.drag-on", "SuckIt Rootkit", Some("/rootkits/suckit.php"));
        db.add_file_signature("sbin/in.slogind", "SuckIt Rootkit", Some("/rootkits/suckit.php"));
        db.add_file_signature("etc/rc.d/rc.sysinit", "Diamorphine LKM Hook", None);
        db.add_file_signature("dev/shm/.kbeast", "KBeast Rootkit", None);
        db.add_file_signature("dev/shm/.reptile", "Reptile LKM Rootkit", None);

        // Trojan binary signatures (checking for hidden shellcalls or /dev backdoor references)
        let _ = db.add_trojan_signature("ls", r"bash|/bin/sh|\.tmp/lsfile|duarawkz", "Trojaned ls binary");
        let _ = db.add_trojan_signature("login", r"elite|SucKIT|xlogin|vejeta|porcao|lets_log|sukasuk", "Trojaned login binary");
        let _ = db.add_trojan_signature("passwd", r"bash|file\.h|proc\.h|/dev/ttyo", "Trojaned passwd binary");
        let _ = db.add_trojan_signature("su", r"/dev/|satori|vejeta|conf\.inv", "Trojaned su binary");
        let _ = db.add_trojan_signature("sudo", r"satori|vejeta|conf\.inv", "Trojaned sudo binary");
        let _ = db.add_trojan_signature("sshd", r"backdoor|r00t|suckit|0xdeadbeef", "Backdoored OpenSSH daemon");

        db
    }
}
