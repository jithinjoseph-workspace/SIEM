//! The SQL schemas of wazuh_db/ (`schema_*.sql`), embedded like Wazuh's
//! Makefile does: `tr -d "\n"` on each file, so the C strings have no
//! newlines (the files have no `--` comments, quotes or backslashes).

use std::sync::OnceLock;

fn strip(s: &'static str, cell: &'static OnceLock<String>) -> &'static str {
    cell.get_or_init(|| s.replace('\n', ""))
}

/// `schema_agents_sql`
pub fn agents() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_agents.sql"), &C)
}

/// `schema_global_sql`
pub fn global() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_global.sql"), &C)
}

/// `schema_global_upgrade_v1_sql`
pub fn global_upgrade_v1() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_global_upgrade_v1.sql"), &C)
}

/// `schema_global_upgrade_v2_sql`
pub fn global_upgrade_v2() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_global_upgrade_v2.sql"), &C)
}

/// `schema_global_upgrade_v3_sql`
pub fn global_upgrade_v3() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_global_upgrade_v3.sql"), &C)
}

/// `schema_global_upgrade_v4_sql`
pub fn global_upgrade_v4() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_global_upgrade_v4.sql"), &C)
}

/// `schema_global_upgrade_v5_sql`
pub fn global_upgrade_v5() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_global_upgrade_v5.sql"), &C)
}

/// `schema_global_upgrade_v6_sql`
pub fn global_upgrade_v6() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_global_upgrade_v6.sql"), &C)
}

/// `schema_global_upgrade_v7_sql`
pub fn global_upgrade_v7() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_global_upgrade_v7.sql"), &C)
}

/// `schema_task_manager_sql`
pub fn task_manager() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_task_manager.sql"), &C)
}

/// `schema_upgrade_v1_sql`
pub fn upgrade_v1() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v1.sql"), &C)
}

/// `schema_upgrade_v10_sql`
pub fn upgrade_v10() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v10.sql"), &C)
}

/// `schema_upgrade_v11_sql`
pub fn upgrade_v11() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v11.sql"), &C)
}

/// `schema_upgrade_v12_sql`
pub fn upgrade_v12() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v12.sql"), &C)
}

/// `schema_upgrade_v13_sql`
pub fn upgrade_v13() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v13.sql"), &C)
}

/// `schema_upgrade_v14_sql`
pub fn upgrade_v14() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v14.sql"), &C)
}

/// `schema_upgrade_v15_sql`
pub fn upgrade_v15() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v15.sql"), &C)
}

/// `schema_upgrade_v16_sql`
pub fn upgrade_v16() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v16.sql"), &C)
}

/// `schema_upgrade_v2_sql`
pub fn upgrade_v2() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v2.sql"), &C)
}

/// `schema_upgrade_v3_sql`
pub fn upgrade_v3() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v3.sql"), &C)
}

/// `schema_upgrade_v4_sql`
pub fn upgrade_v4() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v4.sql"), &C)
}

/// `schema_upgrade_v5_sql`
pub fn upgrade_v5() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v5.sql"), &C)
}

/// `schema_upgrade_v6_sql`
pub fn upgrade_v6() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v6.sql"), &C)
}

/// `schema_upgrade_v7_sql`
pub fn upgrade_v7() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v7.sql"), &C)
}

/// `schema_upgrade_v8_sql`
pub fn upgrade_v8() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v8.sql"), &C)
}

/// `schema_upgrade_v9_sql`
pub fn upgrade_v9() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    strip(include_str!("schemas/schema_upgrade_v9.sql"), &C)
}
