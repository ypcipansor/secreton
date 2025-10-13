#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::pqc;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test PQC provider creation
    let _mldsa_provider = pqc::create_mldsa_provider();
    let _mlkem_provider = pqc::create_mlkem_provider();
    let _falcon_provider = pqc::create_falcon_provider();

    // Test available algorithms
    let _algorithms = pqc::get_available_algorithms();

    // Test algorithm characteristics
    let _characteristics = pqc::get_algorithm_characteristics();

    // Test provider creation by name
    let algorithm_names = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "Falcon-512", "Falcon-1024"];
    for name in &algorithm_names {
        let _provider = pqc::create_provider_by_name(name);
    }

    // Test with actual data if we can create providers
    if let Ok(provider) = pqc::create_mldsa_provider() {
        // Test key generation
        let _keypair = provider.generate_keypair();

        // Test signing if keypair generation succeeds
        if let Ok(keypair) = provider.generate_keypair() {
            let _signature = provider.sign(&keypair, data);

            // Test verification
            if let Ok(signature) = provider.sign(&keypair, data) {
                let _verify = provider.verify(&keypair, data, &signature);
            }
        }
    }

    if let Ok(provider) = pqc::create_mlkem_provider() {
        // Test key encapsulation
        let _keypair = provider.generate_keypair();

        if let Ok(keypair) = provider.generate_keypair() {
            let _encapsulated = provider.encapsulate(&keypair);

            // Test decapsulation
            if let Ok((shared_secret, ciphertext)) = provider.encapsulate(&keypair) {
                let _decapsulated = provider.decapsulate(&keypair, &ciphertext);
            }
        }
    }
});