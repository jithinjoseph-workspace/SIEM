use regex::Regex;

#[derive(Debug, PartialEq, Eq)]
pub struct RegexMatchResult {
    pub matched: bool,
    pub full_match: Option<String>,
    pub captures: Vec<String>,
}

pub struct RegexEvaluator;

impl RegexEvaluator {
    /// Evaluates a regex pattern against a sample line
    pub fn evaluate(pattern: &str, line: &str) -> Result<RegexMatchResult, regex::Error> {
        let re = Regex::new(pattern)?;
        if let Some(caps) = re.captures(line) {
            let full_match = caps.get(0).map(|m| m.as_str().to_string());
            let captures: Vec<String> = caps
                .iter()
                .skip(1)
                .flatten()
                .map(|m| m.as_str().to_string())
                .collect();

            Ok(RegexMatchResult {
                matched: true,
                full_match,
                captures,
            })
        } else {
            Ok(RegexMatchResult {
                matched: false,
                full_match: None,
                captures: Vec::new(),
            })
        }
    }

    /// Evaluates a Wazuh OSRegex pattern with capture substrings
    pub fn evaluate_os_regex(pattern: &str, line: &str) -> Result<RegexMatchResult, siem_shared::regex::RegexError> {
        let reg = siem_shared::regex::OSRegex::compile(
            pattern,
            siem_shared::regex::OS_RETURN_SUBSTRING,
        )?;
        if let Some(captures) = reg.execute(line) {
            Ok(RegexMatchResult {
                matched: true,
                full_match: Some(line.to_string()),
                captures,
            })
        } else {
            Ok(RegexMatchResult {
                matched: false,
                full_match: None,
                captures: Vec::new(),
            })
        }
    }

    /// Evaluates a Wazuh OSMatch pattern (supports negation and OR alternations)
    pub fn evaluate_os_match(pattern: &str, line: &str) -> Result<bool, siem_shared::regex::RegexError> {
        let m = siem_shared::regex::OSMatch::compile(pattern, 0)?;
        Ok(m.execute(line))
    }
}
