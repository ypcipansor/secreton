#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::pqc::mldsa;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Test ML-DSA key generation with random seed
    let seed = &data[..32];
    if let Ok(keypair) = mldsa::Keypair::generate_from_seed(seed) {
        // Test signing with random message
        let message = &data[32..];
        if !message.is_empty() {
            let _signature = keypair.sign(message);

            // Test signature verification
            if let Ok(sig) = keypair.sign(message) {
                let _is_valid = keypair.public_key().verify(message, &sig);
            }
        }
    }
});