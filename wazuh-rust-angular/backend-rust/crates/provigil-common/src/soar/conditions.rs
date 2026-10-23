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

        // SIEM alert fields (Wazuh alert JSON); never true for NDR hits.
        "rule_level" => {
            let Some(level) = alert_str(ctx, &["rule", "level"]).and_then(|l| l.parse::<f64>().ok()) else { return false };
            let Ok(threshold) = pb.cond_value.trim().parse::<f64>() else { return false };
            match pb.cond_op.as_str() {
                ">"  => level >  threshold,
                ">=" => level >= threshold,
                "<"  => level <  threshold,
                "<=" => level <= threshold,
                "==" => level == threshold,
                _    => false,
            }
        }

        "rule_id" => {
            let Some(id) = alert_str(ctx, &["rule", "id"]) else { return false };
            match pb.cond_op.as_str() {
                "==" => id == pb.cond_value.trim(),
                "in" => pb.cond_value.split(',').any(|v| v.trim() == id),
                _ => false,
            }
        }

        "rule_group" => {
            let groups = ctx.alert.as_ref().and_then(|a| a["rule"]["groups"].as_array().cloned()).unwrap_or_default();
            let want = pb.cond_value.trim().to_lowercase();
            groups.iter().filter_map(|g| g.as_str()).any(|g| match pb.cond_op.as_str() {
                "==" => g.eq_ignore_ascii_case(&want),
                "contains" => g.to_lowercase().contains(&want),
                _ => false,
            })
        }

        "agent_name" => text_op(alert_str(ctx, &["agent", "name"]), &pb.cond_op, &pb.cond_value),
        "location" => text_op(alert_str(ctx, &["location"]), &pb.cond_op, &pb.cond_value),

        _ => false,
    }
}

/// A field of the SIEM alert as text (numbers included).
fn alert_str(ctx: &SoarContext, path: &[&str]) -> Option<String> {
    let mut v = ctx.alert.as_ref()?;
    for k in path {
        v = v.get(k)?;
    }
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn text_op(v: Option<String>, op: &str, want: &str) -> bool {
    let Some(v) = v else { return false };
    match op {
        "==" => v.eq_ignore_ascii_case(want.trim()),
        "contains" => v.to_lowercase().contains(&want.trim().to_lowercase()),
        "startswith" => v.to_lowercase().starts_with(&want.trim().to_lowercase()),
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
    fn siem_alert_fields() {
        let alert = serde_json::json!({"rule": {"level": 10, "id": "5712", "groups": ["syslog", "sshd", "authentication_failures"]}, "agent": {"name": "web-01"}, "location": "/var/log/auth.log"});
        let ctx = SoarContext { alert: Some(alert), ..Default::default() };
        assert!(evaluate_condition(&pb("rule_level", ">=", "10"), &ctx));
        assert!(!evaluate_condition(&pb("rule_level", ">", "10"), &ctx));
        assert!(evaluate_condition(&pb("rule_id", "in", "5710, 5712"), &ctx));
        assert!(evaluate_condition(&pb("rule_group", "==", "SSHD"), &ctx));
        assert!(evaluate_condition(&pb("rule_group", "contains", "authentication"), &ctx));
        assert!(evaluate_condition(&pb("agent_name", "startswith", "web"), &ctx));
        assert!(evaluate_condition(&pb("location", "contains", "auth.log"), &ctx));
        // an NDR hit has no alert
        assert!(!evaluate_condition(&pb("rule_level", ">=", "0"), &SoarContext::default()));
    }

    #[test]
    fn threat_intel_flag() {
        let ctx = SoarContext { is_malicious: true, ..Default::default() };
        assert!(evaluate_condition(&pb("threat_intel", "==", "true"), &ctx));
    }
}
