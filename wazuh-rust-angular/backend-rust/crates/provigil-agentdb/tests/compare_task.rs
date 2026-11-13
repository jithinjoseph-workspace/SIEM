//! The same `task` requests to the old and the new database: everything must match.
mod common;

fn requests() -> Vec<String> {
    let v = [
        "task",
        "task upgrade",
        "task nosuch {}",
        "task upgrade {",
        r#"task upgrade {"agent":1,"node":"node01","module":"upgrade_module"}"#,
        r#"task upgrade_custom {"agent":2,"node":"node01","module":"upgrade_module"}"#,
        r#"task upgrade {"agent":3,"node":"node02","module":"upgrade_module"}"#,
        r#"task upgrade {"node":"node01","module":"m"}"#,
        r#"task upgrade {"agent":1,"module":"m"}"#,
        r#"task upgrade {"agent":1,"node":"n"}"#,
        r#"task upgrade {"agent":"1","node":"n","module":"m"}"#,
        r#"task upgrade_get_status {"agent":1,"node":"node01"}"#,
        r#"task upgrade_get_status {"agent":3,"node":"node01"}"#,
        r#"task upgrade_get_status {"agent":3,"node":"node02"}"#,
        r#"task upgrade_get_status {"agent":99,"node":"node01"}"#,
        r#"task upgrade_get_status {"node":"node01"}"#,
        r#"task upgrade_get_status {"agent":1}"#,
        r#"task upgrade_update_status {"agent":1,"node":"node01","status":"In progress"}"#,
        r#"task upgrade_update_status {"agent":1,"node":"node01","status":"In progress"}"#,
        r#"task upgrade_update_status {"agent":1,"node":"node01","status":"Done","error_msg":"none"}"#,
        r#"task upgrade_update_status {"agent":2,"node":"other","status":"In progress"}"#,
        r#"task upgrade_update_status {"agent":2,"node":"node01","status":"In progress"}"#,
        r#"task upgrade_update_status {"agent":2,"node":"node01","status":"Legacy"}"#,
        r#"task upgrade_update_status {"agent":2,"node":"node01","status":"Weird"}"#,
        r#"task upgrade_update_status {"agent":77,"node":"node01","status":"Done"}"#,
        r#"task upgrade_update_status {"agent":1,"node":"node01"}"#,
        r#"task upgrade_update_status {"agent":1,"status":"Done"}"#,
        r#"task upgrade_update_status {"node":"n","status":"Done"}"#,
        r#"task upgrade_result {"agent":1}"#,
        r#"task upgrade_result {"agent":2}"#,
        r#"task upgrade_result {"agent":77}"#,
        r#"task upgrade_result {}"#,
        r#"task upgrade {"agent":4,"node":"node01","module":"m"}"#,
        r#"task upgrade {"agent":5,"node":"node01","module":"m"}"#,
        r#"task upgrade_update_status {"agent":5,"node":"node01","status":"In progress"}"#,
        r#"task upgrade_cancel_tasks {"node":"node01"}"#,
        r#"task upgrade_cancel_tasks {}"#,
        r#"task upgrade_result {"agent":4}"#,
        r#"task set_timeout {"now":1800000000,"interval":100}"#,
        r#"task set_timeout {"now":1800000200,"interval":100}"#,
        r#"task set_timeout {"now":1800000200}"#,
        r#"task set_timeout {"interval":100}"#,
        r#"task upgrade_result {"agent":5}"#,
        "task sql SELECT TASK_ID, AGENT_ID, NODE, MODULE, COMMAND, CREATE_TIME, LAST_UPDATE_TIME, STATUS, ERROR_MESSAGE FROM TASKS ORDER BY TASK_ID",
        "task sql SELECT nosuch FROM TASKS",
        r#"task delete_old {"timestamp":1800000000}"#,
        r#"task delete_old {"timestamp":"x"}"#,
        "task sql SELECT count(*) AS n FROM TASKS",
        "task sql SELECT * FROM METADATA",
    ];
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn task_matches_old() {
    let p = common::Pair::new();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}
