#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::{key_derivation, AlgorithmId};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Test PBKDF2 key derivation
    if let Ok(password) = std::str::from_utf8(data) {
        let _pbkdf2_key = key_derivation::derive_aes256_pbkdf2(password);

        // Test PBKDF2 parameters
        let pbkdf2_params = key_derivation::KdfParams::pbkdf2(100_000, 32).unwrap();
        let _pbkdf2_derived = key_derivation::derive_key(password.as_bytes(), &pbkdf2_params);
    }

    // Test Argon2 key derivation with binary data
    let _argon2_fast = key_derivation::derive_aes256_argon2_fast("test_password");
    let _argon2_secure = key_derivation::derive_aes256_argon2_secure("test_password");
    let _chacha_argon2 = key_derivation::derive_chacha20_argon2("test_password");

    // Test key stretching
    let _stretched = key_derivation::stretch_key_sha256(data, 1000);

    // Test multiple key derivation
    let params_list = vec![
        key_derivation::KdfParams::pbkdf2(1000, 32).unwrap(),
        key_derivation::KdfParams::argon2id(1024, 2, 1, 32).unwrap(),
    ];
    let _multiple_keys = key_derivation::derive_multiple_keys(data, &params_list);

    // Test key derivation with different algorithms
    let pbkdf2_params = key_derivation::KdfParams::pbkdf2(1000, 32).unwrap();
    let _pbkdf2_result = key_derivation::derive_key(data, &pbkdf2_params);

    let argon2_params = key_derivation::KdfParams::argon2id(1024, 2, 1, 32).unwrap();
    let _argon2_result = key_derivation::derive_key(data, &argon2_params);
});