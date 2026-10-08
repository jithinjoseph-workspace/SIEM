pub mod accumulator;
pub mod fingerprint;
pub mod models;
pub mod registry;
pub mod synthesizer;
pub mod validator;

pub use accumulator::*;
pub use fingerprint::*;
pub use models::*;
pub use registry::*;
pub use synthesizer::*;
pub use validator::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_end_to_end_synthesis_and_parsing() {
        let temp_dir = std::env::temp_dir().join(format!("siem_test_{}", uuid::Uuid::new_v4()));
        let storage = temp_dir.join("parsers.json");
        let registry = DynamicParserRegistry::new(storage);

        let samples = vec![
            "2026-10-03 14:22:11 LOGIN FAILED user=john src=192.168.1.50 reason=wrong_password".to_string(),
            "2026-10-03 14:25:30 LOGIN FAILED user=alice src=10.0.0.99 reason=account_expired".to_string(),
            "2026-10-03 14:27:01 LOGIN FAILED user=admin src=172.16.0.4 reason=brute_force".to_string(),
        ];

        let (fp, sig) = FingerprintEngine::compute(&samples[0]);

        // Synthesize parser using offline/heuristic synthesizer
        let parser = registry
            .synthesize_and_register(fp, &sig, &samples, None)
            .await
            .expect("Failed to synthesize parser");

        assert_eq!(parser.fingerprint, fp);
        assert!(!parser.fields.is_empty());

        // Now test hot-path execution on a brand new log of the same structure
        let incoming = "2026-10-03 14:30:15 LOGIN FAILED user=bob src=192.168.2.100 reason=bad_token";
        let res = registry.execute(incoming);
        assert!(res.is_some(), "Hot-path parser should immediately parse incoming log!");

        let parsed = res.unwrap();
        assert_eq!(parsed.extracted_fields.get("user").map(|s| s.as_str()), Some("bob"));
        assert_eq!(parsed.extracted_fields.get("src").map(|s| s.as_str()), Some("192.168.2.100"));
        println!("Execution time: {} microseconds", parsed.execution_time_us);
    }
}
