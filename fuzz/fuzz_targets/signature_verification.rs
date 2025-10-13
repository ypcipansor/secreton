#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::*;

fuzz_target!(|data: &[u8]| {
    // Need at least 64 bytes for keypair + message
    if data.len() < 100 {
        return;
    }

    let key_seed = &data[..32];
    let message = &data[32..];

    // Test Ed25519 signature operations
    if let Ok(keypair) = generate_ed25519_keypair(key_seed) {
        // Test signing
        if let Ok(signature) = sign_ed25519(&keypair, message) {
            // Test verification with correct keypair
            assert!(verify_ed25519(&keypair.public_key, message, &signature)
                .unwrap_or(false), "Valid signature should verify correctly");

            // Test verification with modified message (should fail)
            if message.len() > 0 {
                let mut modified_message = message.to_vec();
                if modified_message[0] == 0 {
                    modified_message[0] = 1;
                } else {
                    modified_message[0] = 0;
                }

                if message != modified_message.as_slice() {
                    // Modified message should not verify (with very high probability)
                    assert!(!verify_ed25519(&keypair.public_key, &modified_message, &signature)
                        .unwrap_or(true), "Modified message should not verify");
                }
            }

            // Test verification with wrong key (should fail)
            if let Ok(wrong_keypair) = generate_ed25519_keypair(&key_seed[1..33]) {
                assert!(!verify_ed25519(&wrong_keypair.public_key, message, &signature)
                    .unwrap_or(true), "Wrong key should not verify signature");
            }
        }
    }

    // Test key derivation functions
    let password = if message.len() > 0 { message } else { b"default_password" };
    let salt = if key_seed.len() >= 16 { &key_seed[..16] } else { b"default_salt_16b" };

    // Test PBKDF2
    if let Ok(derived_key) = derive_pbkdf2(password, salt, 1000) {
        assert_eq!(derived_key.len(), 32, "PBKDF2 should produce 32-byte key");
    }

    // Test Argon2id
    if let Ok(derived_key) = derive_argon2(password, salt) {
        assert_eq!(derived_key.len(), 32, "Argon2id should produce 32-byte key");
    }
});
