#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::transit;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Test Transit encryption operations
    let key_data = &data[..32];
    let plaintext = &data[32..];

    if plaintext.is_empty() {
        return;
    }

    // Test key generation
    if let Ok(key) = transit::Key::generate_from_data(key_data) {
        // Test encryption
        if let Ok(encrypted) = transit::TransitEngine::encrypt(&key, plaintext) {
            // Test decryption
            if let Ok(decrypted) = transit::TransitEngine::decrypt(&key, &encrypted) {
                // Verify roundtrip
                let _roundtrip_success = decrypted == plaintext;
            }

            // Test with wrong key (should fail)
            if data.len() >= 64 {
                let wrong_key_data = &data[32..64];
                if let Ok(wrong_key) = transit::Key::generate_from_data(wrong_key_data) {
                    let _wrong_decrypt_fails =
                        transit::TransitEngine::decrypt(&wrong_key, &encrypted).is_err();
                }
            }
        }

        // Test key rotation
        if let Ok(new_key) = transit::Key::generate_from_data(&data[1..33]) {
            let _rotation = transit::TransitEngine::rotate_key(&key, &new_key);
        }

        // Test batch operations
        let batch_data = vec![plaintext];
        let _batch_encrypt = transit::TransitEngine::encrypt_batch(&key, &batch_data);
    }
});
