#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::*;

fuzz_target!(|data: &[u8]| {
    // Test key generation for different algorithms
    let algorithms = [
        AlgorithmId::Aes256Gcm,
        AlgorithmId::ChaCha20Poly1305,
        AlgorithmId::Sha256,
        AlgorithmId::Sha3_256,
        AlgorithmId::Blake3,
        AlgorithmId::Pbkdf2,
        AlgorithmId::Argon2id,
    ];

    for &algorithm in &algorithms {
        // Test key generation
        if let Ok(key) = generate_key(algorithm) {
            // Verify key length matches algorithm requirements
            let expected_len = SecurityParams::new(algorithm).key_size;
            assert_eq!(
                key.len(),
                expected_len,
                "Key length mismatch for algorithm {:?}",
                algorithm
            );
        }

        // Test nonce generation where applicable
        if let Ok(nonce) = generate_nonce(algorithm) {
            // Verify nonce length matches algorithm requirements
            if let Some(expected_len) = SecurityParams::new(algorithm).salt_size {
                assert_eq!(
                    nonce.len(),
                    expected_len,
                    "Nonce length mismatch for algorithm {:?}",
                    algorithm
                );
            }
        }

        // Test security parameters validation
        let params = SecurityParams::new(algorithm);
        assert!(
            params.is_secure(),
            "Security parameters should be secure for algorithm {:?}",
            algorithm
        );
    }
});
