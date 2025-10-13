#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::*;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for key + some plaintext
    if data.len() < 40 {
        return;
    }

    let key = &data[..32];
    let plaintext = &data[32..];

    // Test AES-256-GCM encryption/decryption
    if let Ok(encrypted) = CryptoEngine::new()
        .encrypt(AlgorithmId::Aes256Gcm, plaintext, key)
    {
        if let Ok(decrypted) = CryptoEngine::new()
            .decrypt(&encrypted, key)
        {
            // Verify roundtrip correctness
            assert_eq!(plaintext, decrypted.as_slice(),
                "AES-GCM encryption/decryption roundtrip failed");
        }
    }

    // Test ChaCha20-Poly1305 encryption/decryption
    if let Ok(encrypted) = CryptoEngine::new()
        .encrypt(AlgorithmId::ChaCha20Poly1305, plaintext, key)
    {
        if let Ok(decrypted) = CryptoEngine::new()
            .decrypt(&encrypted, key)
        {
            // Verify roundtrip correctness
            assert_eq!(plaintext, decrypted.as_slice(),
                "ChaCha20-Poly1305 encryption/decryption roundtrip failed");
        }
    }
});
