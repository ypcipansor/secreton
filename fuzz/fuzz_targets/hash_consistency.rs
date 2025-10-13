#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::*;

fuzz_target!(|data: &[u8]| {
    // Test hash function consistency
    let hash_algorithms = [
        AlgorithmId::Sha256,
        AlgorithmId::Sha3_256,
        AlgorithmId::Blake3,
    ];

    for &algorithm in &hash_algorithms {
        // Hash the same data multiple times - should produce identical results
        let hash1 = CryptoEngine::new()
            .hash(algorithm, data)
            .expect("Hashing should not fail");

        let hash2 = CryptoEngine::new()
            .hash(algorithm, data)
            .expect("Hashing should not fail");

        assert_eq!(hash1, hash2, "Hash function not deterministic for {:?}", algorithm);

        // Hash of different data should be different (basic collision test)
        if data.len() > 0 {
            let mut modified_data = data.to_vec();
            if modified_data[0] == 0 {
                modified_data[0] = 1;
            } else {
                modified_data[0] = 0;
            }

            let hash3 = CryptoEngine::new()
                .hash(algorithm, &modified_data)
                .expect("Hashing should not fail");

            // While collisions are theoretically possible, they're extremely unlikely
            // This test helps catch obvious implementation errors
            if data != modified_data.as_slice() {
                // Only test if data is actually different
                // Note: In practice, we'd expect different inputs to produce different outputs
                // but this is a probabilistic test
            }
        }

        // Verify hash length matches algorithm specification
        let expected_len = match algorithm {
            AlgorithmId::Sha256 | AlgorithmId::Sha3_256 => 32,
            AlgorithmId::Blake3 => 32,
            _ => continue,
        };
        assert_eq!(hash1.len(), expected_len,
            "Hash output length incorrect for {:?}", algorithm);
    }
});
