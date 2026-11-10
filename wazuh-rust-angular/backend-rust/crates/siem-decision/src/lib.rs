//! Neurosymbolic decision engine.
//!
//! The neural side (the AI triage verdict and confidence, threat intel, swarm
//! matches, risk scores) supplies *facts*; the symbolic side is a policy of
//! formal rules over those facts. Before a high-impact action the engine
//! evaluates every rule and records the facts, the rules, each comparison and
//! the outcome. The record is deterministic, so anyone can re-run it
//! ([`verify`]), and records are hash-chained, so none can be changed or
//! removed unnoticed ([`verify_chain`]).
//!
//! Semantics: **deny overrides approval overrides allow**. A rule that
//! needs a fact the decision does not have never lets an action through: the
//! decision then needs a person's approval at least (fail-safe).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Val {
    Bool(bool),
    Num(f64),
    Str(String),
}

impl std::fmt::Display for Val {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Val::Bool(b) => write!(f, "{b}"),
            Val::Num(n) => write!(f, "{n}"),
            Val::Str(s) => write!(f, "\"{s}\""),
        }
    }
}

/// Where a fact comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// An AI model's output (the triage verdict, its confidence).
    Neural,
    /// Derived by fixed logic (address class, protected list, rate counters).
    Symbolic,
    /// Taken from the alert or the request as is.
    Context,
    /// A person's input (an approval).
    Human,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    pub value: Val,
    pub origin: Origin,
    #[serde(default)]
    pub note: String,
}

pub type Facts = BTreeMap<String, Fact>;

pub fn fact(value: Val, origin: Origin, note: &str) -> Fact {
    Fact { value, origin, note: note.to_string() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    #[serde(rename = "==")]
    Eq,
    #[serde(rename = "!=")]
    Ne,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Ge,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Le,
}

/// A condition over facts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cond {
    All(Vec<Cond>),
    Any(Vec<Cond>),
    Not(Box<Cond>),
    Cmp { fact: String, op: Op, value: Val },
}

pub fn cmp(fact: &str, op: Op, value: Val) -> Cond {
    Cond::Cmp { fact: fact.to_string(), op, value }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub when: Cond,
    pub effect: Effect,
    /// A guardrail the tenant cannot remove.
    pub hard: bool,
    /// The control it implements (for auditors).
    #[serde(default)]
    pub reference: String,
}

/// One comparison as evaluated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub fact: String,
    pub op: Op,
    pub expected: Val,
    pub actual: Option<Val>,
    pub holds: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub rule_id: String,
    pub matched: bool,
    /// A fact the rule needs is missing.
    pub incomplete: bool,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    NeedsApproval,
    Denied,
}

fn compare(a: &Val, op: Op, b: &Val) -> bool {
    match (a, b) {
        (Val::Num(x), Val::Num(y)) => match op {
            Op::Eq => x == y,
            Op::Ne => x != y,
            Op::Gt => x > y,
            Op::Ge => x >= y,
            Op::Lt => x < y,
            Op::Le => x <= y,
        },
        (Val::Bool(x), Val::Bool(y)) => match op {
            Op::Eq => x == y,
            Op::Ne => x != y,
            _ => false,
        },
        (Val::Str(x), Val::Str(y)) => match op {
            Op::Eq => x == y,
            Op::Ne => x != y,
            _ => false,
        },
        // different types never compare equal
        _ => op == Op::Ne,
    }
}

/// Evaluates a condition, appending each comparison to `checks`. Returns
/// (holds, complete).
fn eval(c: &Cond, facts: &Facts, checks: &mut Vec<Check>) -> (bool, bool) {
    match c {
        Cond::Cmp { fact, op, value } => {
            let actual = facts.get(fact).map(|f| f.value.clone());
            let holds = actual.as_ref().is_some_and(|a| compare(a, *op, value));
            let complete = actual.is_some();
            checks.push(Check { fact: fact.clone(), op: *op, expected: value.clone(), actual, holds });
            (holds, complete)
        }
        // every branch is evaluated (no short circuit), so the record shows all of them
        Cond::All(cs) => cs.iter().map(|c| eval(c, facts, checks)).fold((true, true), |(h, k), (h2, k2)| (h && h2, k && k2)),
        Cond::Any(cs) => cs.iter().map(|c| eval(c, facts, checks)).fold((false, true), |(h, k), (h2, k2)| (h || h2, k && k2)),
        Cond::Not(c) => {
            let (h, k) = eval(c, facts, checks);
            (!h, k)
        }
    }
}

/// Every rule against the facts: the outcome and the steps.
pub fn evaluate(facts: &Facts, rules: &[Rule]) -> (Outcome, Vec<Step>) {
    let mut worst = Effect::Allow;
    let mut steps = Vec::with_capacity(rules.len());
    for r in rules {
        let mut checks = Vec::new();
        let (holds, complete) = eval(&r.when, facts, &mut checks);
        let matched = holds && complete;
        if matched {
            worst = worst.max(r.effect);
        } else if !complete && r.effect != Effect::Allow {
            // fail-safe: a guardrail that cannot be checked is not passed silently
            worst = worst.max(Effect::RequireApproval);
        }
        steps.push(Step { rule_id: r.id.clone(), matched, incomplete: !complete, checks });
    }
    let outcome = match worst {
        Effect::Allow => Outcome::Allowed,
        Effect::RequireApproval => Outcome::NeedsApproval,
        Effect::Deny => Outcome::Denied,
    };
    (outcome, steps)
}

/// A plain-language sentence for the decision (derived from the steps only).
pub fn summary(outcome: Outcome, rules: &[Rule], steps: &[Step]) -> String {
    let why = |e: Effect| -> Vec<String> {
        rules.iter().zip(steps).filter(|(r, s)| r.effect == e && s.matched).map(|(r, s)| {
            let facts: Vec<String> = s.checks.iter().filter(|c| c.holds).map(|c| format!("{} = {}", c.fact, c.actual.as_ref().map_or("?".into(), |v| v.to_string()))).collect();
            format!("{} \"{}\" ({})", r.id, r.title, facts.join(", "))
        }).collect()
    };
    let incomplete: Vec<&str> = rules.iter().zip(steps).filter(|(r, s)| s.incomplete && r.effect != Effect::Allow).map(|(r, _)| r.id.as_str()).collect();
    match outcome {
        Outcome::Denied => format!("Denied by {}", why(Effect::Deny).join("; ")),
        Outcome::NeedsApproval => {
            let mut w = why(Effect::RequireApproval);
            if !incomplete.is_empty() {
                w.push(format!("missing evidence for {}", incomplete.join(", ")));
            }
            format!("Needs a person's approval: {}", w.join("; "))
        }
        Outcome::Allowed if rules.is_empty() => "Recorded (no rule applies)".to_string(),
        Outcome::Allowed => format!("Allowed: all {} rules passed", rules.len()),
    }
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

pub fn policy_hash(rules: &[Rule]) -> String {
    sha256_hex(serde_json::to_string(rules).unwrap_or_default().as_bytes())
}

/// The audit record of one decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    /// Position in the tenant's chain, from 1.
    pub seq: u64,
    pub ts: u64,
    /// "block_ip", "suppress", or "review" (a person approving or rejecting a held decision).
    pub action: String,
    pub target: String,
    pub requested_by: String,
    pub facts: Facts,
    pub policy: Vec<Rule>,
    pub policy_hash: String,
    pub steps: Vec<Step>,
    pub outcome: Outcome,
    pub summary: String,
    /// What to run if it is approved later (not part of the reasoning).
    #[serde(default)]
    pub params: serde_json::Value,
    /// For a review: the decision it resolves.
    #[serde(default)]
    pub ref_id: String,
    pub prev_hash: String,
    pub hash: String,
}

pub fn record_hash(r: &Record) -> String {
    let mut c = r.clone();
    c.hash.clear();
    sha256_hex(serde_json::to_string(&c).unwrap_or_default().as_bytes())
}

/// A new record, evaluated and hashed onto the chain after `prev`.
#[allow(clippy::too_many_arguments)]
pub fn decide(id: &str, prev: Option<(u64, &str)>, ts: u64, action: &str, target: &str, requested_by: &str, facts: Facts, policy: Vec<Rule>, params: serde_json::Value, ref_id: &str) -> Record {
    let (outcome, steps) = evaluate(&facts, &policy);
    let mut r = Record {
        id: id.to_string(),
        seq: prev.map_or(1, |p| p.0 + 1),
        ts,
        action: action.to_string(),
        target: target.to_string(),
        requested_by: requested_by.to_string(),
        summary: summary(outcome, &policy, &steps),
        policy_hash: policy_hash(&policy),
        facts,
        policy,
        steps,
        outcome,
        params,
        ref_id: ref_id.to_string(),
        prev_hash: prev.map_or(String::new(), |p| p.1.to_string()),
        hash: String::new(),
    };
    r.hash = record_hash(&r);
    r
}

/// Re-derives a record from its own facts and rules: the policy hash, every
/// step, the outcome, the summary and the record hash must all match.
pub fn verify(r: &Record) -> Result<(), String> {
    if policy_hash(&r.policy) != r.policy_hash {
        return Err("the policy differs from its hash".into());
    }
    let (outcome, steps) = evaluate(&r.facts, &r.policy);
    if steps != r.steps {
        return Err("the recorded reasoning steps do not follow from the facts and rules".into());
    }
    if outcome != r.outcome {
        return Err(format!("the facts and rules give {outcome:?}, the record says {:?}", r.outcome));
    }
    if summary(outcome, &r.policy, &steps) != r.summary {
        return Err("the summary does not match the reasoning".into());
    }
    if record_hash(r) != r.hash {
        return Err("the record was changed after it was written".into());
    }
    Ok(())
}

/// Verifies every record and the links between them (ordered by `seq`).
/// Ok = number of records; Err = (seq of the first bad record, reason).
pub fn verify_chain(records: &[Record]) -> Result<usize, (u64, String)> {
    let mut prev: Option<&Record> = None;
    for r in records {
        verify(r).map_err(|e| (r.seq, e))?;
        match prev {
            None if r.seq != 1 || !r.prev_hash.is_empty() => return Err((r.seq, "the chain does not start at 1 (records missing)".into())),
            Some(p) if r.seq != p.seq + 1 => return Err((r.seq, format!("record {} is missing", p.seq + 1))),
            Some(p) if r.prev_hash != p.hash => return Err((r.seq, "it does not link to the record before it".into())),
            _ => {}
        }
        prev = Some(r);
    }
    Ok(records.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<Rule> {
        vec![
            Rule { id: "G1".into(), title: "Never block internal addresses".into(), when: cmp("target.public", Op::Eq, Val::Bool(false)), effect: Effect::Deny, hard: true, reference: "".into() },
            Rule {
                id: "P1".into(),
                title: "Weak evidence".into(),
                when: Cond::All(vec![cmp("alert.level", Op::Lt, Val::Num(10.0)), cmp("intel.malicious", Op::Eq, Val::Bool(false))]),
                effect: Effect::RequireApproval,
                hard: false,
                reference: "".into(),
            },
        ]
    }

    fn facts(public: bool, level: f64, intel: bool) -> Facts {
        let mut f = Facts::new();
        f.insert("target.public".into(), fact(Val::Bool(public), Origin::Symbolic, ""));
        f.insert("alert.level".into(), fact(Val::Num(level), Origin::Context, ""));
        f.insert("intel.malicious".into(), fact(Val::Bool(intel), Origin::Neural, ""));
        f
    }

    #[test]
    fn deny_overrides_approval_overrides_allow() {
        assert_eq!(evaluate(&facts(true, 12.0, false), &rules()).0, Outcome::Allowed);
        assert_eq!(evaluate(&facts(true, 5.0, false), &rules()).0, Outcome::NeedsApproval);
        assert_eq!(evaluate(&facts(true, 5.0, true), &rules()).0, Outcome::Allowed);
        // internal and weak: the deny wins
        assert_eq!(evaluate(&facts(false, 5.0, false), &rules()).0, Outcome::Denied);
    }

    #[test]
    fn a_missing_fact_never_allows() {
        let mut f = facts(true, 12.0, false);
        f.remove("target.public");
        let (o, steps) = evaluate(&f, &rules());
        assert_eq!(o, Outcome::NeedsApproval);
        assert!(steps[0].incomplete && !steps[0].matched);
        assert!(summary(o, &rules(), &steps).contains("missing evidence for G1"));
    }

    #[test]
    fn every_branch_is_recorded() {
        let (_, steps) = evaluate(&facts(true, 12.0, true), &rules());
        assert_eq!(steps[1].checks.len(), 2, "no short-circuit: both comparisons are in the record");
        assert_eq!(steps[1].checks[0].actual, Some(Val::Num(12.0)));
    }

    #[test]
    fn tampering_is_detected() {
        let a = decide("a", None, 100, "block_ip", "45.1.2.3", "soar", facts(true, 5.0, false), rules(), serde_json::json!({}), "");
        let b = decide("b", Some((a.seq, &a.hash)), 101, "block_ip", "10.0.0.1", "soar", facts(false, 12.0, false), rules(), serde_json::json!({}), "");
        assert_eq!(a.outcome, Outcome::NeedsApproval);
        assert_eq!(b.outcome, Outcome::Denied);
        assert_eq!(verify_chain(&[a.clone(), b.clone()]), Ok(2));
        // round trip through JSON (as stored) still verifies
        let back: Record = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(verify(&back), Ok(()));

        let mut t = a.clone();
        t.outcome = Outcome::Allowed; // forged outcome
        assert!(verify(&t).unwrap_err().contains("give NeedsApproval"));
        let mut t = a.clone();
        t.facts.insert("intel.malicious".into(), fact(Val::Bool(true), Origin::Neural, "")); // forged evidence
        assert!(verify(&t).is_err());
        let mut t = a.clone();
        t.policy[1].effect = Effect::Allow; // weakened rule
        assert!(verify(&t).unwrap_err().contains("policy"));
        let mut t = a.clone();
        t.target = "8.8.8.8".into(); // rewritten target
        assert!(verify(&t).unwrap_err().contains("changed"));
        // a removed or reordered record breaks the chain
        assert_eq!(verify_chain(&[b.clone()]).unwrap_err().0, 2);
        let c = decide("c", Some((b.seq, &b.hash)), 102, "block_ip", "45.1.2.3", "soar", facts(true, 12.0, false), rules(), serde_json::json!({}), "");
        assert!(verify_chain(&[a, c]).is_err());
    }
}
