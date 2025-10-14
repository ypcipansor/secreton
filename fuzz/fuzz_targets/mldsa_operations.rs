#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::pqc::mldsa::{MLDsaKeypair, MLDsaVariant};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Select variant based on first byte
    let variant = match data[0] % 3 {
        0 => MLDsaVariant::MLDsa44,
        1 => MLDsaVariant::MLDsa65,
        _ => MLDsaVariant::MLDsa87,
    };

    // Test ML-DSA key generation
    if let Ok(keypair) = MLDsaKeypair::generate(variant) {
        // Test signing with random message
        let message = &data[1..];
        if !message.is_empty() {
            let _signature = keypair.sign(message);

            // Test signature verification
            if let Ok(sig) = keypair.sign(message) {
                let _is_valid = keypair.verify(message, &sig);
            }
        }
    }
});
