//! Wazuh Rule Expression Matching Engine (expression.c, rules_op.c)
//!
//! Evaluates field condition expressions including exact string matches, regexes,
//! CIDR IP subnet memberships, and numeric threshold operators (<, <=, >, >=, ==, !=).

use regex::Regex;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericOp {
    Equal,
    NotEqual,
    LessThan,
    LessOrEqual,
    GreaterThan,
    GreaterOrEqual,
}

#[derive(Debug, Clone)]
pub enum ExpressionPattern {
    Exact(String),
    Substring(String),
    Regex(Regex),
    Cidr(String),
    Numeric(NumericOp, f64),
}

#[derive(Debug, Clone)]
pub struct RuleExpression {
    pub pattern: ExpressionPattern,
    pub negate: bool,
}

impl RuleExpression {
    pub fn exact(val: &str, negate: bool) -> Self {
        Self {
            pattern: ExpressionPattern::Exact(val.to_string()),
            negate,
        }
    }

    pub fn substring(val: &str, negate: bool) -> Self {
        Self {
            pattern: ExpressionPattern::Substring(val.to_string()),
            negate,
        }
    }

    pub fn regex(pattern: &str, negate: bool) -> Result<Self, regex::Error> {
        let re = Regex::new(pattern)?;
        Ok(Self {
            pattern: ExpressionPattern::Regex(re),
            negate,
        })
    }

    pub fn cidr(cidr_str: &str, negate: bool) -> Self {
        Self {
            pattern: ExpressionPattern::Cidr(cidr_str.to_string()),
            negate,
        }
    }

    pub fn numeric(op: NumericOp, threshold: f64, negate: bool) -> Self {
        Self {
            pattern: ExpressionPattern::Numeric(op, threshold),
            negate,
        }
    }

    /// Evaluate expression against a candidate string value.
    pub fn matches(&self, candidate: &str) -> bool {
        let is_match = match &self.pattern {
            ExpressionPattern::Exact(expected) => candidate == expected,
            ExpressionPattern::Substring(sub) => candidate.contains(sub),
            ExpressionPattern::Regex(re) => re.is_match(candidate),
            ExpressionPattern::Cidr(cidr) => match candidate.parse::<IpAddr>() {
                Ok(ip) => match_ip_cidr(&ip, cidr),
                Err(_) => false,
            },
            ExpressionPattern::Numeric(op, threshold) => {
                if let Ok(num) = candidate.trim().parse::<f64>() {
                    match op {
                        NumericOp::Equal => (num - threshold).abs() < f64::EPSILON,
                        NumericOp::NotEqual => (num - threshold).abs() >= f64::EPSILON,
                        NumericOp::LessThan => num < *threshold,
                        NumericOp::LessOrEqual => num <= *threshold,
                        NumericOp::GreaterThan => num > *threshold,
                        NumericOp::GreaterOrEqual => num >= *threshold,
                    }
                } else {
                    false
                }
            }
        };

        if self.negate {
            !is_match
        } else {
            is_match
        }
    }
}

/// Check if an IP address belongs to a CIDR string (e.g. "192.168.1.0/24").
fn match_ip_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        if let Ok(target_ip) = cidr.parse::<IpAddr>() {
            return ip == &target_ip;
        }
        return false;
    }

    let net_ip: IpAddr = match parts[0].parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    let prefix: u8 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    match (ip, net_ip) {
        (IpAddr::V4(cand_v4), IpAddr::V4(net_v4)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix)
            };
            let cand_int = u32::from(*cand_v4);
            let net_int = u32::from(net_v4);
            (cand_int & mask) == (net_int & mask)
        }
        (IpAddr::V6(cand_v6), IpAddr::V6(net_v6)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix)
            };
            let cand_int = u128::from(*cand_v6);
            let net_int = u128::from(net_v6);
            (cand_int & mask) == (net_int & mask)
        }
        _ => false,
    }
}
