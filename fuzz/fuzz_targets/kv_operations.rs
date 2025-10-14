#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::KVEngine;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Create a runtime for async operations
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Create a key-value engine for testing
    let kv_engine = KVEngine::new();

    // Split data into operations
    let mut pos = 0;
    while pos + 8 < data.len() {
        let op_type = data[pos] % 4; // 0=set, 1=get, 2=delete, 3=list
        let key_len = (data[pos + 1] as usize % 32) + 1; // 1-32 bytes
        let value_len = (data[pos + 2] as usize % 64) + 1; // 1-64 bytes

        if pos + 8 + key_len + value_len > data.len() {
            break;
        }

        let key = &data[pos + 8..pos + 8 + key_len];
        let value = &data[pos + 8 + key_len..pos + 8 + key_len + value_len];

        match op_type {
            0 => {
                // Set operation
                if let Ok(key_str) = std::str::from_utf8(key) {
                    if let Ok(value_str) = std::str::from_utf8(value) {
                        let mut data = HashMap::new();
                        data.insert("value".to_string(), value_str.to_string());
                        let _ = rt.block_on(kv_engine.put_secret(key_str, data));
                    }
                }
            }
            1 => {
                // Get operation
                if let Ok(key_str) = std::str::from_utf8(key) {
                    let _ = rt.block_on(kv_engine.get_secret(key_str, None));
                }
            }
            2 => {
                // Delete operation
                if let Ok(key_str) = std::str::from_utf8(key) {
                    let _ = rt.block_on(kv_engine.delete_secret(key_str, None));
                }
            }
            3 => {
                // List operation
                let _ = rt.block_on(kv_engine.list_secrets());
            }
            _ => {}
        }

        pos += 8 + key_len + value_len;
    }
});
