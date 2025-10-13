#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::{hashing, AlgorithmId};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test SHA-256 specifically
    let _sha256_result = hashing::compute_hash(AlgorithmId::Sha256, data);

    // Test SHA3-256 specifically
    let _sha3_result = hashing::compute_hash(AlgorithmId::Sha3_256, data);

    // Test BLAKE3 specifically
    let _blake3_result = hashing::compute_hash(AlgorithmId::Blake3, data);

    // Test multiple data chunks
    if data.len() > 1 {
        let chunks = vec![&data[0..data.len()/2], &data[data.len()/2..]];
        let _sha256_multi = hashing::compute_hash_multiple(AlgorithmId::Sha256, &chunks);
        let _sha3_multi = hashing::compute_hash_multiple(AlgorithmId::Sha3_256, &chunks);
        let _blake3_multi = hashing::compute_hash_multiple(AlgorithmId::Blake3, &chunks);
    }

    // Test hash verification
    if let Ok(hash_result) = hashing::compute_hash(AlgorithmId::Sha256, data) {
        let _verify = hash_result.verify(data);
    }

    if let Ok(hash_result) = hashing::compute_hash(AlgorithmId::Sha3_256, data) {
        let _verify = hash_result.verify(data);
    }

    if let Ok(hash_result) = hashing::compute_hash(AlgorithmId::Blake3, data) {
        let _verify = hash_result.verify(data);
    }
});