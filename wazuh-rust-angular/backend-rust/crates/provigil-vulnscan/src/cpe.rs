//! CPE texts (both `cpe:/` and `cpe:2.3:` forms).

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cpe {
    /// part, vendor, product, version, update, edition, language, sw edition, target sw,
    /// target hw, other.
    pub fields: [String; 11],
    pub field_count: usize,
}

pub fn is_cpe(s: &str) -> bool {
    s.starts_with("cpe:")
}

impl Cpe {
    pub fn parse(s: &str) -> Cpe {
        let mut pieces: Vec<&str> = s.split(':').collect();
        if pieces.last() == Some(&"") {
            pieces.pop();
        }
        let shift = usize::from(s.starts_with("cpe:2.3"));
        let mut c = Cpe { field_count: pieces.len().saturating_sub(shift + 1), ..Default::default() };
        for pos in 1..=11 {
            if pos <= 3 && pieces.len() < 4 + shift {
                continue;
            }
            if let Some(p) = pieces.get(pos + shift) {
                c.fields[pos - 1] = if pos == 1 { p.strip_prefix('/').unwrap_or(p) } else { p }.to_string();
            }
        }
        // An empty text has an unbounded field count: comparisons use the other side's count.
        if s.is_empty() {
            c.field_count = usize::MAX;
        }
        c
    }

    pub fn part(&self) -> &str {
        &self.fields[0]
    }
    pub fn product(&self) -> &str {
        &self.fields[2]
    }

    pub fn matches(&self, o: &Cpe) -> bool {
        let n = self.field_count.min(o.field_count);
        if n == 0 {
            return false;
        }
        (0..n.min(11)).all(|i| self.fields[i] == o.fields[i] || self.fields[i] == "*" || o.fields[i] == "*")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn examples() {
        let a = Cpe::parse("cpe:/o:microsoft:windows_10_22h2:10.0.19045.1:::::");
        assert_eq!((a.part(), a.product(), a.fields[3].as_str(), a.field_count), ("o", "windows_10_22h2", "10.0.19045.1", 8));
        let b = Cpe::parse("cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*");
        assert_eq!(b.field_count, 11);
        assert!(b.matches(&a) && a.matches(&b));
        assert!(!a.matches(&Cpe::parse("cpe:/o:microsoft:windows_11_22h2")));
        assert!(is_cpe("cpe:x") && !is_cpe("jammy"));
        // D29
        assert!(Cpe::parse("").matches(&Cpe::parse("")) && Cpe::parse("").matches(&Cpe::parse("cpe:/*:*:*")));
        assert!(!Cpe::parse("").matches(&Cpe::parse("cpe:")));
    }
}
