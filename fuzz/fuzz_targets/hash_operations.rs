#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::{AlgorithmId, hashing};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test various hash functions
    let _sha256_hash = hashing::compute_hash(AlgorithmId::Sha256, data);
    let _sha3_256_hash = hashing::compute_hash(AlgorithmId::Sha3_256, data);
    let _blake3_hash = hashing::compute_hash(AlgorithmId::Blake3, data);

    // Test HMAC operations
    let key = b"test_key_for_hmac_operations_123456789";
    let _hmac_sha256 = hashing::compute_hmac_sha256(key, data);

    // Test hash verification (hash of hash)
    if let Ok(hash1) = hashing::compute_hash(AlgorithmId::Sha256, data) {
        let hash2 = hashing::compute_hash(AlgorithmId::Sha256, &hash1.hash);
        let _double_hash = hash2;
    }

    // Test hash comparison
    if let Ok(hash_a) = hashing::compute_hash(AlgorithmId::Sha256, data) {
        if let Ok(hash_b) = hashing::compute_hash(AlgorithmId::Sha256, data) {
            let _hashes_equal = hash_a.hash == hash_b.hash;
        }
    }

    // Test with modified data
    if !data.is_empty() {
        let mut modified_data = data.to_vec();
        modified_data[0] = modified_data[0].wrapping_add(1);
        let hash_modified = hashing::compute_hash(AlgorithmId::Sha256, &modified_data);
        if let Ok(hash_a) = hashing::compute_hash(AlgorithmId::Sha256, data) {
            if let Ok(hash_modified) = hash_modified {
                let _hashes_different = hash_a.hash != hash_modified.hash;
            }
        }
    }
});
