#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::hash;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test various hash functions
    let _sha256_hash = hash::sha256(data);
    let _sha512_hash = hash::sha512(data);
    let _blake2b_hash = hash::blake2b(data);

    // Test HMAC operations
    let key = b"test_key_for_hmac_operations_123456789";
    let _hmac_sha256 = hash::hmac_sha256(key, data);
    let _hmac_sha512 = hash::hmac_sha512(key, data);

    // Test hash verification (hash of hash)
    let hash1 = hash::sha256(data);
    let hash2 = hash::sha256(&hash1);
    let _double_hash = hash2;

    // Test incremental hashing
    let mut hasher = hash::IncrementalHasher::new(hash::HashAlgorithm::Sha256);
    hasher.update(data);
    if data.len() > 1 {
        hasher.update(&data[1..]);
    }
    let _incremental_hash = hasher.finalize();

    // Test hash comparison
    let hash_a = hash::sha256(data);
    let hash_b = hash::sha256(data);
    let _hashes_equal = hash_a == hash_b;

    // Test with modified data
    if !data.is_empty() {
        let mut modified_data = data.to_vec();
        modified_data[0] = modified_data[0].wrapping_add(1);
        let hash_modified = hash::sha256(&modified_data);
        let _hashes_different = hash_a != hash_modified;
    }
});