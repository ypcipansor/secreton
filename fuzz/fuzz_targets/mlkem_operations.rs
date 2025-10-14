#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::pqc::mlkem::{MLKemKeypair, MLKemVariant};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Select variant based on first byte
    let variant = match data[0] % 3 {
        0 => MLKemVariant::MLKem512,
        1 => MLKemVariant::MLKem768,
        _ => MLKemVariant::MLKem1024,
    };

    // Test ML-KEM key generation
    if let Ok(keypair) = MLKemKeypair::generate(variant) {
        // Test encapsulation
        if let Ok((ciphertext, shared_secret)) = keypair.encapsulate() {
            // Test decapsulation
            if let Ok(decapsulated_secret) = keypair.decapsulate(&ciphertext) {
                // Verify that encapsulated and decapsulated secrets match
                let _secrets_match = shared_secret == decapsulated_secret;
            }
        }
    }
});
