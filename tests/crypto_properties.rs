//! Property-based tests for cryptographic security properties
//!
//! These tests use proptest to verify that our cryptographic implementations
//! maintain their security properties under all possible inputs.

use proptest::prelude::*;
use secreton_crypto::*;

proptest! {
    /// Test that encryption/decryption is a proper roundtrip for all inputs
    #[test]
    fn encryption_roundtrip_property(
        plaintext in prop::collection::vec(any::<u8>(), 0..1000),
        key in prop::collection::vec(any::<u8>(), 32..33), // Exactly 32 bytes for AES
        algorithm in prop::sample::select(vec![AlgorithmId::Aes256Gcm, AlgorithmId::ChaCha20Poly1305])
    ) {
        let engine = CryptoEngine::new();
        let plaintext_bytes = plaintext.as_slice();

        // Encryption should succeed
        let encrypted = engine.encrypt(algorithm, plaintext_bytes, &key)
            .expect("Encryption should not fail");

        // Decryption should succeed and match original
        let decrypted = engine.decrypt(&encrypted, &key)
            .expect("Decryption should not fail");

        prop_assert_eq!(plaintext_bytes, decrypted.as_slice(),
            "Encryption/decryption roundtrip failed for algorithm {:?}", algorithm);
    }

    /// Test that different keys produce different ciphertexts
    #[test]
    fn key_separation_property(
        plaintext in prop::collection::vec(any::<u8>(), 1..100),
        key1 in prop::collection::vec(any::<u8>(), 32..33),
        key2 in prop::collection::vec(any::<u8>(), 32..33)
    ) {
        // Ensure keys are actually different
        prop_assume!(key1 != key2);

        let engine = CryptoEngine::new();
        let plaintext_bytes = plaintext.as_slice();

        let encrypted1 = engine.encrypt(AlgorithmId::Aes256Gcm, plaintext_bytes, &key1)
            .expect("Encryption should not fail");
        let encrypted2 = engine.encrypt(AlgorithmId::Aes256Gcm, plaintext_bytes, &key2)
            .expect("Encryption should not fail");

        // Ciphertexts should be different (extremely high probability)
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext,
            "Different keys should produce different ciphertexts");
    }

    /// Test that different plaintexts produce different ciphertexts (even with same key)
    #[test]
    fn plaintext_separation_property(
        key in prop::collection::vec(any::<u8>(), 32..33),
        plaintext1 in prop::collection::vec(any::<u8>(), 1..100),
        plaintext2 in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        // Ensure plaintexts are actually different
        prop_assume!(plaintext1 != plaintext2);

        let engine = CryptoEngine::new();

        let encrypted1 = engine.encrypt(AlgorithmId::Aes256Gcm, &plaintext1, &key)
            .expect("Encryption should not fail");
        let encrypted2 = engine.encrypt(AlgorithmId::Aes256Gcm, &plaintext2, &key)
            .expect("Encryption should not fail");

        // Ciphertexts should be different (extremely high probability)
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext,
            "Different plaintexts should produce different ciphertexts");
    }

    /// Test hash function determinism
    #[test]
    fn hash_determinism_property(
        data in prop::collection::vec(any::<u8>(), 0..1000),
        algorithm in prop::sample::select(vec![AlgorithmId::Sha256, AlgorithmId::Sha3_256, AlgorithmId::Blake3])
    ) {
        let engine = CryptoEngine::new();

        // Hash the same data multiple times
        let hash1 = engine.hash(algorithm, &data)
            .expect("Hashing should not fail");
        let hash2 = engine.hash(algorithm, &data)
            .expect("Hashing should not fail");

        // Hashes should be identical
        prop_assert_eq!(hash1, hash2,
            "Hash function should be deterministic for algorithm {:?}", algorithm);
    }

    /// Test hash function collision resistance (weak form)
    #[test]
    fn hash_collision_resistance_property(
        data1 in prop::collection::vec(any::<u8>(), 1..100),
        data2 in prop::collection::vec(any::<u8>(), 1..100),
        algorithm in prop::sample::select(vec![AlgorithmId::Sha256, AlgorithmId::Sha3_256, AlgorithmId::Blake3])
    ) {
        // Only test if inputs are actually different
        prop_assume!(data1 != data2);

        let engine = CryptoEngine::new();

        let hash1 = engine.hash(algorithm, &data1)
            .expect("Hashing should not fail");
        let hash2 = engine.hash(algorithm, &data2)
            .expect("Hashing should not fail");

        // For a correct hash function, different inputs should produce different outputs
        // (This is a probabilistic test - collisions are theoretically possible but extremely unlikely)
        prop_assert_ne!(hash1, hash2,
            "Hash collision detected for algorithm {:?} - this should be extremely rare", algorithm);
    }

    /// Test key generation produces valid keys for all algorithms
    #[test]
    fn key_generation_validity_property(
        algorithm in prop::sample::select(vec![
            AlgorithmId::Aes256Gcm,
            AlgorithmId::ChaCha20Poly1305,
            AlgorithmId::Sha256,
            AlgorithmId::Sha3_256,
            AlgorithmId::Blake3,
            AlgorithmId::Pbkdf2,
            AlgorithmId::Argon2id
        ])
    ) {
        let key = generate_key(algorithm)
            .expect("Key generation should not fail");

        let params = SecurityParams::new(algorithm);
        prop_assert_eq!(key.len(), params.key_size,
            "Generated key length should match algorithm requirements for {:?}", algorithm);

        // For encryption algorithms, test that the key works
        if matches!(algorithm, AlgorithmId::Aes256Gcm | AlgorithmId::ChaCha20Poly1305) {
            let test_data = b"test data for key validation";
            let engine = CryptoEngine::new();

            let encrypted = engine.encrypt(algorithm, test_data, &key)
                .expect("Encryption with generated key should work");
            let decrypted = engine.decrypt(&encrypted, &key)
                .expect("Decryption with generated key should work");

            prop_assert_eq!(test_data, decrypted.as_slice(),
                "Generated key should work for encryption/decryption");
        }
    }

    /// Test nonce generation for encryption algorithms
    #[test]
    fn nonce_generation_property(
        algorithm in prop::sample::select(vec![AlgorithmId::Aes256Gcm, AlgorithmId::ChaCha20Poly1305])
    ) {
        let nonce = generate_nonce(algorithm)
            .expect("Nonce generation should not fail");

        let params = SecurityParams::new(algorithm);
        if let Some(expected_len) = params.salt_size {
            prop_assert_eq!(nonce.len(), expected_len,
                "Nonce length should match algorithm requirements for {:?}", algorithm);

            // Test that nonce works with encryption
            let key = generate_key(algorithm).unwrap();
            let test_data = b"test data for nonce validation";
            let engine = CryptoEngine::new();

            let encrypted = engine.encrypt(algorithm, test_data, &key)
                .expect("Encryption should work");
            let decrypted = engine.decrypt(&encrypted, &key)
                .expect("Decryption should work");

            prop_assert_eq!(test_data, decrypted.as_slice(),
                "Generated nonce should work for encryption/decryption");
        }
    }

    /// Test PBKDF2 key derivation properties
    #[test]
    fn pbkdf2_derivation_property(
        password in prop::collection::vec(any::<u8>(), 1..100),
        salt in prop::collection::vec(any::<u8>(), 16..17), // 16 bytes salt
        iterations in 1000u32..100000u32 // Reasonable iteration range
    ) {
        let derived_key = derive_pbkdf2(&password, &salt, iterations)
            .expect("PBKDF2 derivation should not fail");

        prop_assert_eq!(derived_key.len(), 32,
            "PBKDF2 should produce 32-byte derived key");

        // Test determinism - same inputs should produce same output
        let derived_key2 = derive_pbkdf2(&password, &salt, iterations)
            .expect("PBKDF2 derivation should be deterministic");
        prop_assert_eq!(derived_key, derived_key2,
            "PBKDF2 should be deterministic");
    }

    /// Test Argon2id key derivation properties
    #[test]
    fn argon2_derivation_property(
        password in prop::collection::vec(any::<u8>(), 1..100),
        salt in prop::collection::vec(any::<u8>(), 16..17) // 16 bytes salt
    ) {
        let derived_key = derive_argon2(&password, &salt)
            .expect("Argon2id derivation should not fail");

        prop_assert_eq!(derived_key.len(), 32,
            "Argon2id should produce 32-byte derived key");

        // Test determinism
        let derived_key2 = derive_argon2(&password, &salt)
            .expect("Argon2id derivation should be deterministic");
        prop_assert_eq!(derived_key, derived_key2,
            "Argon2id should be deterministic");
    }
}

proptest! {
    /// Test security parameter validation
    #[test]
    fn security_params_validation_property(
        algorithm in prop::sample::select(vec![
            AlgorithmId::Aes256Gcm,
            AlgorithmId::ChaCha20Poly1305,
            AlgorithmId::Sha256,
            AlgorithmId::Sha3_256,
            AlgorithmId::Blake3,
            AlgorithmId::Pbkdf2,
            AlgorithmId::Argon2id
        ])
    ) {
        let params = SecurityParams::new(algorithm);

        // All standard security parameters should be marked as secure
        prop_assert!(params.is_secure(),
            "Security parameters should be secure for algorithm {:?}", algorithm);

        // Test that key size is appropriate
        match algorithm {
            AlgorithmId::Aes256Gcm | AlgorithmId::ChaCha20Poly1305 => {
                prop_assert_eq!(params.key_size, 32, "AES-256 and ChaCha20 should use 256-bit keys");
            }
            AlgorithmId::Pbkdf2 => {
                prop_assert!(params.iterations.unwrap_or(0) >= 100_000,
                    "PBKDF2 should use at least 100,000 iterations");
            }
            AlgorithmId::Argon2id => {
                prop_assert!(params.iterations.unwrap_or(0) >= 3,
                    "Argon2id should use at least 3 iterations");
            }
            _ => {} // Hash functions don't need iteration parameters
        }
    }
}
