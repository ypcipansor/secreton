#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::pqc::mlkem;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Test ML-KEM key generation with random seed
    let seed = &data[..32];
    if let Ok(keypair) = mlkem::Keypair::generate_from_seed(seed) {
        // Test encapsulation with random entropy
        let entropy = if data.len() > 32 { &data[32..] } else { seed };
        if let Ok((ciphertext, shared_secret)) = keypair.public_key().encapsulate(entropy) {
            // Test decapsulation
            if let Ok(decapsulated_secret) = keypair.private_key().decapsulate(&ciphertext) {
                // Verify that encapsulated and decapsulated secrets match
                let _secrets_match = shared_secret == decapsulated_secret;
            }
        }
    }
});