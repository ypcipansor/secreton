#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::{encryption::CryptoEngine, AlgorithmId};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Split data into key and plaintext
    let key = &data[0..32];
    let plaintext = &data[32..];

    if plaintext.is_empty() {
        return;
    }

    let engine = CryptoEngine::new();

    // Test AES-256-GCM encryption/decryption
    let _aes_encrypt = engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, key);

    if let Ok(encrypted) = engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, key) {
        let _aes_decrypt = engine.decrypt(&encrypted, key);
    }

    // Test ChaCha20-Poly1305 encryption/decryption
    let _chacha_encrypt = engine.encrypt(AlgorithmId::ChaCha20Poly1305, plaintext, key);

    if let Ok(encrypted) = engine.encrypt(AlgorithmId::ChaCha20Poly1305, plaintext, key) {
        let _chacha_decrypt = engine.decrypt(&encrypted, key);
    }

    // Test with wrong key (should fail)
    if data.len() > 64 {
        let wrong_key = &data[32..64];
        if let Ok(encrypted) = engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, key) {
            let _wrong_key_decrypt = engine.decrypt(&encrypted, wrong_key);
        }
    }

    // Test with modified ciphertext
    if let Ok(mut encrypted) = engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, key) {
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] = encrypted.ciphertext[0].wrapping_add(1);
            let _modified_decrypt = engine.decrypt(&encrypted, key);
        }
    }
});