#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::transit::{KeyType, SignatureAlgorithm, TransitEngine};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Create a transit engine for testing
    let engine = TransitEngine::new();

    // Test Ed25519 key generation
    let key_name = format!("ed25519_key_{}", data[0]);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        if let Ok(_) = engine.create_key(&key_name, KeyType::Ed25519, None).await {
            // Test signing with random message
            let message = &data[32..];
            if !message.is_empty() {
                if let Ok(signature) = engine
                    .sign(&key_name, message, Some(SignatureAlgorithm::Ed25519), None)
                    .await
                {
                    // Test signature verification
                    let _is_valid = engine
                        .verify(
                            &key_name,
                            message,
                            &signature,
                            Some(SignatureAlgorithm::Ed25519),
                        )
                        .await;

                    // Test signature verification with wrong message
                    if message.len() > 1 {
                        let wrong_message = &message[1..];
                        let _is_invalid = engine
                            .verify(
                                &key_name,
                                wrong_message,
                                &signature,
                                Some(SignatureAlgorithm::Ed25519),
                            )
                            .await;
                    }
                }
            }
        }
    });
});
