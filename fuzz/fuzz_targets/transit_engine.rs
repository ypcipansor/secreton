#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::transit::{KeyType, TransitEngine};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let engine = TransitEngine::new();

    // Test key creation with different types
    let key_types = [
        KeyType::Aes256Gcm,
        KeyType::ChaCha20Poly1305,
        KeyType::Ed25519,
        KeyType::X25519,
        KeyType::EcdsaP256,
        KeyType::EcdsaSecp256k1,
    ];

    for key_type in &key_types {
        let key_name = format!("test-key-{:?}", key_type);
        let _create_result = tokio::runtime::Runtime::new().unwrap().block_on(async {
            engine
                .create_key(key_name.clone(), key_type.clone(), None)
                .await
        });
    }

    // Test encryption/decryption with different keys
    let test_key = "test-encryption-key";
    let _create_encrypt_key = tokio::runtime::Runtime::new().unwrap().block_on(async {
        engine
            .create_key(test_key.to_string(), KeyType::Aes256Gcm, None)
            .await
    });

    let plaintext = &data[16..];
    if !plaintext.is_empty() {
        let _encrypt_result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { engine.encrypt(test_key, plaintext, None, None).await });

        // Test decryption
        if let Ok(ciphertext) = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { engine.encrypt(test_key, plaintext, None, None).await })
        {
            let _decrypt_result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async { engine.decrypt(test_key, &ciphertext, None).await });
        }
    }

    // Test signing/verification
    let sign_key = "test-signing-key";
    let _create_sign_key = tokio::runtime::Runtime::new().unwrap().block_on(async {
        engine
            .create_key(sign_key.to_string(), KeyType::Ed25519, None)
            .await
    });

    let _sign_result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { engine.sign(sign_key, data, None, None).await });

    if let Ok(signature) = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { engine.sign(sign_key, data, None, None).await })
    {
        let _verify_result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { engine.verify(sign_key, data, &signature, None).await });
    }

    // Test key rotation
    let _rotate_result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { engine.rotate_key(test_key).await });

    // Test random generation
    let _random_bytes = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { engine.random(data.len().min(1024)).await });

    // Test key derivation
    let _derived_key = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { engine.derive_key("derived-key", data, 32).await });
});
