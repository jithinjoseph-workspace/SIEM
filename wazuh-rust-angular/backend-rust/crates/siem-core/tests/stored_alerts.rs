// Every alert stored in ClickHouse reads into these types and writes back the same.
// Export first, then run with the file:
//   curl -s http://localhost:8123/ --data-binary "SELECT alert_json FROM ndr.siem_alerts WHERE alert_json != '' FORMAT JSONEachRow" > alerts.jsonl
//   ALERTS_JSONL=alerts.jsonl cargo test -p siem-core --test stored_alerts -- --ignored
#[test]
#[ignore]
fn stored_alerts_round_trip() {
    let path = std::env::var("ALERTS_JSONL").expect("ALERTS_JSONL");
    let text = std::fs::read_to_string(path).unwrap();
    let mut n = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let raw = row["alert_json"].as_str().unwrap();
        let original: serde_json::Value = serde_json::from_str(raw).unwrap();
        let a: siem_core::Alert = serde_json::from_str(raw).unwrap_or_else(|e| panic!("{e}: {raw}"));
        let again = serde_json::to_value(&a).unwrap();
        assert_eq!(again, original, "differs: {raw}");
        n += 1;
    }
    assert!(n > 100, "{n}");
    println!("{n} stored alerts read and written back identically");
}
