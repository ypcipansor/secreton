#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::secrets::key_value;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Create a mock key-value store for testing
    let mut kv_store = key_value::KeyValueStore::new();

    // Split data into operations
    let mut pos = 0;
    while pos + 8 < data.len() {
        let op_type = data[pos] % 4; // 0=set, 1=get, 2=delete, 3=list
        let key_len = (data[pos + 1] % 32) + 1; // 1-32 bytes
        let value_len = (data[pos + 2] % 64) + 1; // 1-64 bytes

        if pos + 8 + key_len + value_len > data.len() {
            break;
        }

        let key = &data[pos + 8..pos + 8 + key_len];
        let value = &data[pos + 8 + key_len..pos + 8 + key_len + value_len];

        match op_type {
            0 => {
                // Set operation
                let key_str = String::from_utf8_lossy(key);
                let value_str = String::from_utf8_lossy(value);
                let _ = kv_store.set(&key_str, &value_str);
            }
            1 => {
                // Get operation
                let key_str = String::from_utf8_lossy(key);
                let _ = kv_store.get(&key_str);
            }
            2 => {
                // Delete operation
                let key_str = String::from_utf8_lossy(key);
                let _ = kv_store.delete(&key_str);
            }
            3 => {
                // List operation with prefix
                let prefix = String::from_utf8_lossy(key);
                let _ = kv_store.list(&prefix);
            }
            _ => {}
        }

        pos += 8 + key_len + value_len;
    }
});