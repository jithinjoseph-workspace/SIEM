use super::{SoarContext, SoarNativePlaybook};

/// Pure condition evaluator — no engine imports, no async, no I/O.
///
/// Each engine builds a [`SoarContext`] from its own event types and passes it here.
/// Returns `true` if the playbook condition is satisfied.
pub fn evaluate_condition(pb: &SoarNativePlaybook, ctx: &SoarContext) -> bool {
    match pb.cond_field.as_str() {
        "score" => {
            let threshold = pb.cond_value.parse::<f32>().unwrap_or(0.0);
            match pb.cond_op.as_str() {
                ">"  => ctx.score >  threshold,
                ">=" => ctx.score >= threshold,
                "<"  => ctx.score <  threshold,
                "<=" => ctx.score <= threshold,
                "==" => (ctx.score - threshold).abs() < f32::EPSILON,
                _    => false,
            }
        }

        "severity" => match pb.cond_op.as_str() {
            "==" => ctx.severity.eq_ignore_ascii_case(&pb.cond_value),
            "contains" => ctx.severity.to_lowercase().contains(&pb.cond_value.to_lowercase()),
            _ => false,
        },

        "threat_intel" => {
            let want = pb.cond_value.to_lowercase() == "true" || pb.cond_value == "1";
            match pb.cond_op.as_str() {
                "==" => ctx.is_malicious == want,
                _ => false,
            }
        }

        "src_country" => match pb.cond_op.as_str() {
            "==" => ctx.src_country.eq_ignore_ascii_case(&pb.cond_value),
            "contains" => ctx.src_country.to_lowercase().contains(&pb.cond_value.to_lowercase()),
            _ => false,
        },

        "sigma_tag" => match pb.cond_op.as_str() {
            "==" => ctx.tags.iter().any(|t| t.eq_ignore_ascii_case(&pb.cond_value)),
            "contains" => ctx.tags.iter().any(|t| t.to_lowercase().contains(&pb.cond_value.to_lowercase())),
            _ => false,
        },

        "src_ip" => match pb.cond_op.as_str() {
            "==" => ctx.src_ip == pb.cond_value,
            "contains" => ctx.src_ip.contains(&pb.cond_value),
            "startswith" => ctx.src_ip.starts_with(&pb.cond_value),
            _ => false,
        },

        "dst_ip" => match pb.cond_op.as_str() {
            "==" => ctx.dst_ip == pb.cond_value,
            "contains" => ctx.dst_ip.contains(&pb.cond_value),
            "startswith" => ctx.dst_ip.starts_with(&pb.cond_value),
            _ => false,
        },

        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pb(field: &str, op: &str, value: &str) -> SoarNativePlaybook {
        SoarNativePlaybook {
            id: "test".into(), name: "test".into(), description: "".into(),
            enabled: 1, cond_field: field.into(), cond_op: op.into(), cond_value: value.into(),
            action_type: "webhook".into(), action_config: "{}".into(),
            run_count: 0, last_run: None,
            created_at: "".into(), updated_at: "".into(), tenant_id: "default".into(),
        }
    }

    #[test]
    fn score_threshold() {
        let ctx = SoarContext { score: 85.0, ..Default::default() };
        assert!(evaluate_condition(&pb("score", ">", "80"), &ctx));
        assert!(!evaluate_condition(&pb("score", ">", "90"), &ctx));
    }

    #[test]
    fn severity_eq() {
        let ctx = SoarContext { severity: "CRITICAL".into(), ..Default::default() };
        assert!(evaluate_condition(&pb("severity", "==", "critical"), &ctx));
    }

    #[test]
    fn threat_intel_flag() {
        let ctx = SoarContext { is_malicious: true, ..Default::default() };
        assert!(evaluate_condition(&pb("threat_intel", "==", "true"), &ctx));
    }
}
