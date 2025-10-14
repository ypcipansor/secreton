#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::{
    derive_key_argon2id, derive_key_pbkdf2,
    transit::{KeyType, TransitEngine},
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 100 {
        return;
    }

    let key_seed = &data[..32];
    let message = &data[32..];

    // Test Ed25519 signature operations using TransitEngine
    let engine = TransitEngine::new();
    let key_name = "test-ed25519-key";

    // Create Ed25519 key
    let _create_result = tokio::runtime::Runtime::new().unwrap().block_on(async {
        engine
            .create_key(key_name.to_string(), KeyType::Ed25519, None)
            .await
    });

    // Test signing
    let sign_result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { engine.sign(key_name, message, None, None).await });

    if let Ok(signature) = sign_result {
        // Test verification with correct key
        let verify_result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { engine.verify(key_name, message, &signature, None).await });
        assert!(
            verify_result.unwrap_or(false),
            "Valid signature should verify correctly"
        );

        // Test verification with modified message (should fail)
        if message.len() > 0 {
            let mut modified_message = message.to_vec();
            if modified_message[0] == 0 {
                modified_message[0] = 1;
            } else {
                modified_message[0] = 0;
            }

            if message != modified_message.as_slice() {
                // Modified message should not verify (with very high probability)
                let verify_modified = tokio::runtime::Runtime::new().unwrap().block_on(async {
                    engine
                        .verify(key_name, &modified_message, &signature, None)
                        .await
                });
                assert!(
                    !verify_modified.unwrap_or(true),
                    "Modified message should not verify"
                );
            }
        }

        // Test verification with wrong key (should fail)
        let wrong_key_name = "wrong-key";
        let _wrong_key_result = tokio::runtime::Runtime::new().unwrap().block_on(async {
            engine
                .create_key(wrong_key_name.to_string(), KeyType::Ed25519, None)
                .await
        });

        let verify_wrong_key = tokio::runtime::Runtime::new().unwrap().block_on(async {
            engine
                .verify(wrong_key_name, message, &signature, None)
                .await
        });
        assert!(
            !verify_wrong_key.unwrap_or(true),
            "Wrong key should not verify signature"
        );
    }

    // Test key derivation functions
    let password = if message.len() > 0 {
        message
    } else {
        b"default_password"
    };
    let salt = if key_seed.len() >= 16 {
        &key_seed[..16]
    } else {
        b"default_salt_16b"
    };

    // Test PBKDF2
    if let Ok(derived_key) = derive_key_pbkdf2(password, salt, 1000, 32) {
        assert_eq!(derived_key.len(), 32, "PBKDF2 should produce 32-byte key");
    }

    // Test Argon2id
    if let Ok(derived_key) = derive_key_argon2id(password, salt, 2, 65536, 1, 32) {
        assert_eq!(derived_key.len(), 32, "Argon2id should produce 32-byte key");
    }
});
