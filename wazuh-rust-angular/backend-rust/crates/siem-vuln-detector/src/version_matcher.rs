use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    pub epoch: u32,
    pub segments: Vec<VersionSegment>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSegment {
    Number(u64),
    String(String),
}

impl ParsedVersion {
    pub fn parse(ver_str: &str) -> Self {
        let clean = ver_str.trim();
        let (epoch, rest) = if let Some(idx) = clean.find(':') {
            let ep = clean[..idx].parse::<u32>().unwrap_or(0);
            (ep, &clean[idx + 1..])
        } else {
            (0, clean)
        };

        let mut segments = Vec::new();
        let mut cur_num: Option<u64> = None;
        let mut cur_str = String::new();

        for ch in rest.chars() {
            if ch.is_ascii_digit() {
                if !cur_str.is_empty() {
                    segments.push(VersionSegment::String(cur_str.clone()));
                    cur_str.clear();
                }
                let digit = ch.to_digit(10).unwrap() as u64;
                cur_num = Some(cur_num.unwrap_or(0) * 10 + digit);
            } else if ch == '.' || ch == '-' || ch == '_' || ch == '+' || ch == '~' {
                if let Some(n) = cur_num.take() {
                    segments.push(VersionSegment::Number(n));
                }
                if !cur_str.is_empty() {
                    segments.push(VersionSegment::String(cur_str.clone()));
                    cur_str.clear();
                }
            } else {
                if let Some(n) = cur_num.take() {
                    segments.push(VersionSegment::Number(n));
                }
                cur_str.push(ch.to_ascii_lowercase());
            }
        }

        if let Some(n) = cur_num {
            segments.push(VersionSegment::Number(n));
        }
        if !cur_str.is_empty() {
            segments.push(VersionSegment::String(cur_str));
        }

        ParsedVersion {
            epoch,
            segments,
            raw: ver_str.to_string(),
        }
    }

    pub fn compare(&self, other: &Self) -> Ordering {
        // Compare epochs first
        match self.epoch.cmp(&other.epoch) {
            Ordering::Equal => {},
            ord => return ord,
        }

        // Compare segment by segment
        let max_len = self.segments.len().max(other.segments.len());
        for i in 0..max_len {
            let seg_a = self.segments.get(i);
            let seg_b = other.segments.get(i);

            match (seg_a, seg_b) {
                (Some(VersionSegment::Number(a)), Some(VersionSegment::Number(b))) => {
                    match a.cmp(b) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                (Some(VersionSegment::String(a)), Some(VersionSegment::String(b))) => {
                    match a.cmp(b) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                (Some(VersionSegment::Number(_)), Some(VersionSegment::String(_))) => {
                    return Ordering::Greater; // numeric > string
                }
                (Some(VersionSegment::String(_)), Some(VersionSegment::Number(_))) => {
                    return Ordering::Less;
                }
                (Some(_), None) => return Ordering::Greater,
                (None, Some(_)) => return Ordering::Less,
                (None, None) => break,
            }
        }

        Ordering::Equal
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionOp {
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Equal,
}

#[derive(Debug, Clone)]
pub struct VersionConstraint {
    pub op: VersionOp,
    pub target: ParsedVersion,
}

impl VersionConstraint {
    pub fn parse(expr: &str) -> Option<Self> {
        let trimmed = expr.trim();
        let (op, ver_part) = if trimmed.starts_with("<=") {
            (VersionOp::LessEqual, &trimmed[2..])
        } else if trimmed.starts_with(">=") {
            (VersionOp::GreaterEqual, &trimmed[2..])
        } else if trimmed.starts_with('<') {
            (VersionOp::Less, &trimmed[1..])
        } else if trimmed.starts_with('>') {
            (VersionOp::Greater, &trimmed[1..])
        } else if trimmed.starts_with('=') {
            (VersionOp::Equal, &trimmed[1..])
        } else {
            (VersionOp::Equal, trimmed)
        };

        Some(VersionConstraint {
            op,
            target: ParsedVersion::parse(ver_part),
        })
    }

    pub fn matches(&self, ver: &ParsedVersion) -> bool {
        let ord = ver.compare(&self.target);
        match self.op {
            VersionOp::Less => ord == Ordering::Less,
            VersionOp::LessEqual => ord == Ordering::Less || ord == Ordering::Equal,
            VersionOp::Greater => ord == Ordering::Greater,
            VersionOp::GreaterEqual => ord == Ordering::Greater || ord == Ordering::Equal,
            VersionOp::Equal => ord == Ordering::Equal,
        }
    }
}

pub fn matches_version_range(installed_version: &str, affected_range_expr: &str) -> bool {
    let installed = ParsedVersion::parse(installed_version);
    // Range can be comma-separated, e.g. ">= 1.0.0, < 2.3.4"
    let clauses: Vec<&str> = affected_range_expr.split(',').map(|s| s.trim()).collect();
    
    for clause in clauses {
        if let Some(constraint) = VersionConstraint::parse(clause) {
            if !constraint.matches(&installed) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparisons() {
        let v1 = ParsedVersion::parse("5.6.0");
        let v2 = ParsedVersion::parse("5.6.1");
        assert_eq!(v1.compare(&v2), Ordering::Less);

        let v3 = ParsedVersion::parse("1.2.3.4");
        let v4 = ParsedVersion::parse("1.2.3.4");
        assert_eq!(v3.compare(&v4), Ordering::Equal);

        let v5 = ParsedVersion::parse("2:1.0.0");
        let v6 = ParsedVersion::parse("1:2.0.0");
        assert_eq!(v5.compare(&v6), Ordering::Greater); // epoch wins
    }

    #[test]
    fn test_affected_range_matching() {
        // xz-utils backdoor: affected versions 5.6.0 and 5.6.1
        assert!(matches_version_range("5.6.0", ">= 5.6.0, < 5.6.2"));
        assert!(matches_version_range("5.6.1", ">= 5.6.0, < 5.6.2"));
        assert!(!matches_version_range("5.6.2", ">= 5.6.0, < 5.6.2"));
        assert!(!matches_version_range("5.4.5", ">= 5.6.0, < 5.6.2"));

        // Single inequality
        assert!(matches_version_range("1.1.1u", "< 1.1.1w"));
        assert!(!matches_version_range("1.1.1w", "< 1.1.1w"));
    }
}
