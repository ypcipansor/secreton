#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::transit::{KeyType, TransitEngine};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Create a transit engine for testing
    let engine = TransitEngine::new();

    // Test X25519 key creation
    if let Ok(key_name) = std::str::from_utf8(data) {
        if !key_name.is_empty() && key_name.len() < 64 {
            // Create X25519 key
            let _create_result = tokio::runtime::Runtime::new().unwrap().block_on(async {
                engine
                    .create_key(key_name.to_string(), KeyType::X25519, None)
                    .await
            });

            // Test key info retrieval
            let _key_info = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async { engine.get_key_info(key_name).await });

            // Test key rotation
            let _rotate_result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async { engine.rotate_key(key_name).await });

            // Test random data generation (used with X25519)
            let _random_data = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async { engine.random(32).await });
        }
    }

    // Test with binary data for key derivation context
    let _derive_result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { engine.derive_key("test-x25519-key", data, 32).await });
});
