#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::{hashing, key_derivation};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test Argon2 password hashing
    if let Ok(password) = std::str::from_utf8(data) {
        // Test Argon2 password hashing
        let _hash_result = hashing::password::hash_password_argon2(password);

        // Test with existing hash verification
        if let Ok(hash_result) = hashing::password::hash_password_argon2(password) {
            let _verify_result = hashing::password::verify_password_argon2(password, &hash_result.hash);
        }

        // Test key derivation with Argon2
        let _derived_key_fast = key_derivation::presets::derive_aes256_argon2_fast(password);
        let _derived_key_secure = key_derivation::presets::derive_aes256_argon2_secure(password);
        let _derived_chacha = key_derivation::presets::derive_chacha20_argon2(password);

        // Test Argon2 KDF parameters
        let params = key_derivation::KdfParams::argon2id(65536, 3, 4, 32).unwrap();
        let _derived_key = key_derivation::derive_key(password.as_bytes(), &params);
    }

    // Test Argon2 with binary data
    let _stretched_key = key_derivation::stretch::stretch_key_sha256(data, 1000);
});