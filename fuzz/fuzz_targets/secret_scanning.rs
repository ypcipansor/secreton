#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::secret_scanning::*;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Test secret scanning operations
    if data.len() < 100 {
        return;
    }

    // Split data for different scanning components
    let content_end = data.len() / 4;
    let patterns_end = 2 * data.len() / 4;
    let rules_end = 3 * data.len() / 4;

    let content = &data[..content_end];
    let patterns = &data[content_end..patterns_end];
    let rules = &data[patterns_end..rules_end];
    let config = &data[rules_end..];

    // Test content scanning
    let _ = scan_content_for_secrets(content);
    let _ = detect_sensitive_data(content);
    let _ = extract_potential_secrets(content);

    // Test pattern matching
    if let Ok(patterns_str) = std::str::from_utf8(patterns) {
        if let Ok(pattern_list) = serde_json::from_str::<Vec<ScanPattern>>(patterns_str) {
            for pattern in pattern_list {
                let _ = validate_scan_pattern(&pattern);
                let _ = compile_regex_pattern(&pattern);
            }
        }
    }

    // Test scanning rules
    if let Ok(rules_str) = std::str::from_utf8(rules) {
        let _ = parse_scanning_rules(rules_str);
        let _ = validate_scanning_logic(rules_str);
        let _ = compile_scanning_rules(rules_str);
    }

    // Test scanner configuration
    if let Ok(config_str) = std::str::from_utf8(config) {
        if let Ok(scan_config) = serde_json::from_str::<SecretScannerConfig>(config_str) {
            let _ = validate_scanner_config(&scan_config);
            let _ = initialize_scanner(&scan_config);
        }
    }
});