#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::storage::*;
use serde::{Serialize, Deserialize};

fuzz_target!(|data: &[u8]| {
    // Test serialization/deserialization operations
    if data.len() < 50 {
        return;
    }

    // Split data for different serialization formats
    let json_end = data.len() / 3;
    let bincode_end = 2 * data.len() / 3;

    let json_data = &data[..json_end];
    let bincode_data = &data[json_end..bincode_end];
    let raw_data = &data[bincode_end..];

    // Test JSON serialization/deserialization
    if let Ok(json_str) = std::str::from_utf8(json_data) {
        // Try to deserialize various types
        let _vault_entry: Result<VaultEntry, _> = serde_json::from_str(json_str);
        let _secret_data: Result<HashMap<String, String>, _> = serde_json::from_str(json_str);
        let _metadata: Result<HashMap<String, serde_json::Value>, _> = serde_json::from_str(json_str);

        // Test round-trip serialization
        if let Ok(secret_data) = serde_json::from_str::<HashMap<String, String>>(json_str) {
            let _reserialized = serde_json::to_string(&secret_data);
        }
    }

    // Test binary serialization/deserialization
    let _bincode_result: Result<HashMap<String, String>, _> = bincode::deserialize(bincode_data);
    let _bincode_metadata: Result<HashMap<String, serde_json::Value>, _> = bincode::deserialize(bincode_data);

    // Test raw data handling
    let _ = validate_raw_data(raw_data);
    let _ = sanitize_binary_data(raw_data);
    let _ = extract_data_metadata(raw_data);
});