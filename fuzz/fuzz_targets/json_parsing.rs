#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json;
use secreton_core::config::{ServerConfig, DatabaseConfig, AuthConfig, Config};

fuzz_target!(|data: &[u8]| {
    // Test JSON configuration parsing
    if data.is_empty() {
        return;
    }

    // Try to parse as JSON
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Test various configuration structures
        let _ = serde_json::from_str::<ServerConfig>(json_str);
        let _ = serde_json::from_str::<DatabaseConfig>(json_str);
        let _ = serde_json::from_str::<AuthConfig>(json_str);
        let _ = serde_json::from_str::<Config>(json_str);
    }
});