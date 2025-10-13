#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::pqc::falcon;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Test Falcon key generation with random seed
    let seed = &data[..32];
    if let Ok(keypair) = falcon::Keypair::generate_from_seed(seed) {
        // Test signing with random message
        let message = &data[32..];
        if !message.is_empty() {
            if let Ok(signature) = keypair.sign(message) {
                // Test signature verification
                let _is_valid = keypair.public_key().verify(message, &signature);
            }
        }
    }
});