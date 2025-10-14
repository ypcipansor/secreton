#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::hashing;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Split data into key and message
    let key = &data[0..16];
    let message = &data[16..];

    // Test HMAC-SHA256
    let _hmac_sha256 = hashing::compute_hmac_sha256(key, message);

    // Test HMAC verification
    if let Ok(mac) = hashing::compute_hmac_sha256(key, message) {
        let _verify = hashing::verify_hmac_sha256(key, message, &mac);
    }

    // Test with different key sizes
    if data.len() > 32 {
        let key_32 = &data[0..32];
        let _hmac_sha256_32 = hashing::compute_hmac_sha256(key_32, message);
    }

    // Test with empty message
    let _hmac_empty = hashing::compute_hmac_sha256(key, &[]);

    // Test with empty key (should fail gracefully)
    let _hmac_empty_key = hashing::compute_hmac_sha256(&[], message);

    // Test HMAC with modified data
    if !message.is_empty() {
        let mut modified_message = message.to_vec();
        modified_message[0] = modified_message[0].wrapping_add(1);
        let _hmac_modified = hashing::compute_hmac_sha256(key, &modified_message);

        // Verify that MACs are different
        if let (Ok(original_mac), Ok(modified_mac)) = (
            hashing::compute_hmac_sha256(key, message),
            hashing::compute_hmac_sha256(key, &modified_message),
        ) {
            let _macs_different = original_mac != modified_mac;
        }
    }
});
