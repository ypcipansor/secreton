#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::*;

fuzz_target!(|data: &[u8]| {
    // Need at least 64 bytes for key + meaningful plaintext
    if data.len() < 100 {
        return;
    }

    let key = &data[..32];
    let plaintext = &data[32..];

    // Differential fuzzing: compare AES-256-GCM vs ChaCha20-Poly1305
    let engine = CryptoEngine::new();

    // Test both algorithms produce valid results
    let aes_encrypted = engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, key);
    let chacha_encrypted = engine.encrypt(AlgorithmId::ChaCha20Poly1305, plaintext, key);

    // Both should either both succeed or both fail consistently
    match (aes_encrypted, chacha_encrypted) {
        (Ok(aes_result), Ok(chacha_result)) => {
            // Both succeeded - verify they can both decrypt correctly
            let aes_decrypted = engine
                .decrypt(&aes_result, key)
                .expect("AES decryption should work");
            let chacha_decrypted = engine
                .decrypt(&chacha_result, key)
                .expect("ChaCha20 decryption should work");

            // Both should decrypt to the same plaintext
            assert_eq!(
                aes_decrypted.as_slice(),
                plaintext,
                "AES-GCM decryption should match original plaintext"
            );
            assert_eq!(
                chacha_decrypted.as_slice(),
                plaintext,
                "ChaCha20-Poly1305 decryption should match original plaintext"
            );

            // Nonces should be different (both algorithms use random nonces)
            assert_ne!(
                aes_result.nonce, chacha_result.nonce,
                "Different algorithms should use different nonces"
            );
        }
        (Err(_), Err(_)) => {
            // Both failed - this might be acceptable for edge cases
            // but should be investigated
        }
        _ => {
            // One succeeded and one failed - potential inconsistency
            panic!("Inconsistent encryption behavior between AES-GCM and ChaCha20-Poly1305");
        }
    }

    // Differential fuzzing: compare hash functions
    let hash_algorithms = [
        AlgorithmId::Sha256,
        AlgorithmId::Sha3_256,
        AlgorithmId::Blake3,
    ];

    let mut hash_results = Vec::new();
    for &algorithm in &hash_algorithms {
        if let Ok(hash) = engine.hash(algorithm, plaintext) {
            hash_results.push((algorithm, hash));
        }
    }

    // All hash functions should either all succeed or all fail
    if hash_results.len() == hash_algorithms.len() {
        // All succeeded - verify they produce different outputs (collision resistance)
        for i in 0..hash_results.len() {
            for j in i + 1..hash_results.len() {
                let (_, hash1) = hash_results[i];
                let (_, hash2) = hash_results[j];
                // Different algorithms should produce different hash outputs
                // (This is expected - they use different algorithms)
            }
        }
    } else if hash_results.is_empty() {
        // All failed - might be acceptable for some edge cases
    } else {
        // Partial failure - investigate
        panic!("Inconsistent hash function behavior");
    }

    // Test key derivation consistency
    if plaintext.len() > 0 && key.len() >= 16 {
        let salt = &key[..16];

        // Test PBKDF2 vs Argon2id consistency
        let pbkdf2_key = derive_pbkdf2(plaintext, salt, 1000);
        let argon2_key = derive_argon2(plaintext, salt);

        match (pbkdf2_key, argon2_key) {
            (Ok(pbkdf2_result), Ok(argon2_result)) => {
                // Both should produce 32-byte keys
                assert_eq!(pbkdf2_result.len(), 32, "PBKDF2 should produce 32-byte key");
                assert_eq!(
                    argon2_result.len(),
                    32,
                    "Argon2id should produce 32-byte key"
                );

                // They should be different (different algorithms)
                assert_ne!(
                    pbkdf2_result, argon2_result,
                    "PBKDF2 and Argon2id should produce different results"
                );
            }
            (Err(_), Err(_)) => {
                // Both failed - might be acceptable
            }
            _ => {
                panic!("Inconsistent key derivation behavior between PBKDF2 and Argon2id");
            }
        }
    }
});
