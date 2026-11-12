use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::path::Path;

pub static VALID_AGENT_CONF_BLOCKS: &[&str] = &[
    "agent_config",
    "syscheck",
    "rootcheck",
    "localfile",
    "client",
    "client_buffer",
    "wodle",
    "labels",
    "active-response",
    "command",
];

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigValidationError {
    FileNotFound(String),
    XmlParseError(String),
    UnknownRootTag(String),
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileNotFound(path) => write!(f, "File not found: {path}"),
            Self::XmlParseError(msg) => write!(f, "XML syntax error: {msg}"),
            Self::UnknownRootTag(tag) => write!(f, "Unrecognized block tag: <{tag}>"),
        }
    }
}

pub struct AgentConfValidator;

impl AgentConfValidator {
    /// Validates an agent.conf XML file content
    pub fn validate_str(content: &str) -> Result<(), ConfigValidationError> {
        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut tag_stack = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    tag_stack.push(name.clone());
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if let Some(expected) = tag_stack.pop() {
                        if expected != name {
                            return Err(ConfigValidationError::XmlParseError(format!(
                                "Mismatched closing tag: expected </{expected}>, found </{name}>"
                            )));
                        }
                    } else {
                        return Err(ConfigValidationError::XmlParseError(format!(
                            "Unexpected closing tag </{name}>"
                        )));
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ConfigValidationError::XmlParseError(e.to_string()));
                }
                _ => {}
            }
            buf.clear();
        }

        if !tag_stack.is_empty() {
            return Err(ConfigValidationError::XmlParseError(format!(
                "Unclosed tags remaining: {:?}",
                tag_stack
            )));
        }

        Ok(())
    }

    /// Validates an agent.conf file from path
    pub fn validate_file(path: impl AsRef<Path>) -> Result<(), ConfigValidationError> {
        let p = path.as_ref();
        if !p.exists() {
            return Err(ConfigValidationError::FileNotFound(p.display().to_string()));
        }

        let content = std::fs::read_to_string(p).map_err(|e| {
            ConfigValidationError::XmlParseError(format!("Read error: {e}"))
        })?;

        Self::validate_str(&content)
    }
}
