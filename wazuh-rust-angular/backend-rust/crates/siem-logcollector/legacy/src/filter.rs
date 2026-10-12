//! Wazuh Log Filter & OutFormat Processor (src/logcollector/logcollector.c)
//!
//! Provides:
//! - `check_ignore_and_restrict`: PCRE/Regex filtering matching `check_ignore_and_restrict()` in `logcollector.c`.
//! - `apply_out_format`: Out-format string substitution for target formatting.

use regex::Regex;

/// Evaluates ignore and restrict lists against a log line.
/// Returns `true` if the log should be IGNORED / DROPPED, `false` if it should be processed.
/// Matches `int check_ignore_and_restrict(OSList * ignore_exp, OSList * restrict_exp, const char *log_line)`
pub fn check_ignore_and_restrict(
    ignore_regexes: &[Regex],
    restrict_regexes: &[Regex],
    log_line: &str,
) -> bool {
    // 1. If any ignore regex matches -> drop
    for re in ignore_regexes {
        if re.is_match(log_line) {
            return true;
        }
    }

    // 2. If restrict regexes are present, at least one MUST match
    if !restrict_regexes.is_empty() {
        let mut matched_restrict = false;
        for re in restrict_regexes {
            if re.is_match(log_line) {
                matched_restrict = true;
                break;
            }
        }
        if !matched_restrict {
            return true; // Dropped because no restrict pattern matched
        }
    }

    false
}

/// Applies `<out_format>` template substitution to a log line.
/// Supported tokens:
/// - `$(location)`: source file path or command alias
/// - `$(log)`: the raw log line
pub fn apply_out_format(template: &str, location: &str, log_line: &str) -> String {
    template
        .replace("$(location)", location)
        .replace("$(log)", log_line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ignore_filter() {
        let ignore = vec![Regex::new("DEBUG").unwrap(), Regex::new("TRACE").unwrap()];
        let restrict = Vec::new();

        assert!(check_ignore_and_restrict(&ignore, &restrict, "2026-09-28 DEBUG: details"));
        assert!(check_ignore_and_restrict(&ignore, &restrict, "2026-09-28 TRACE: enter"));
        assert!(!check_ignore_and_restrict(&ignore, &restrict, "2026-09-28 INFO: starting"));
    }

    #[test]
    fn test_restrict_filter() {
        let ignore = Vec::new();
        let restrict = vec![Regex::new("ERROR").unwrap(), Regex::new("FATAL").unwrap()];

        assert!(!check_ignore_and_restrict(&ignore, &restrict, "2026-09-28 ERROR: fail"));
        assert!(!check_ignore_and_restrict(&ignore, &restrict, "2026-09-28 FATAL: crash"));
        assert!(check_ignore_and_restrict(&ignore, &restrict, "2026-09-28 INFO: normal"));
    }

    #[test]
    fn test_out_format_template() {
        let template = "source=$(location): $(log)";
        let res = apply_out_format(template, "/var/log/auth.log", "Failed login for admin");
        assert_eq!(res, "source=/var/log/auth.log: Failed login for admin");
    }
}
