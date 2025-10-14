#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::pqc;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test PQC provider creation
    let _mldsa_provider =
        pqc::PQCRegistry::create_mldsa_provider(crate::pqc::mldsa::MLDsaVariant::MLDsa65);
    let _mlkem_provider =
        pqc::PQCRegistry::create_mlkem_provider(crate::pqc::mlkem::MLKemVariant::MLKem768);
    let _falcon_provider =
        pqc::PQCRegistry::create_falcon_provider(crate::pqc::falcon::FalconVariant::Falcon512);

    // Test available algorithms
    let _algorithms = pqc::PQCRegistry::get_available_algorithms();

    // Test algorithm characteristics
    let _characteristics = pqc::PQCRegistry::get_algorithm_characteristics();

    // Test provider creation by name
    let algorithm_names = [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "Falcon-512",
        "Falcon-1024",
    ];
    for name in &algorithm_names {
        let _provider = pqc::PQCRegistry::create_provider_by_name(name);
    }

    // Test with actual data if we can create providers
    let mldsa_provider =
        pqc::PQCRegistry::create_mldsa_provider(crate::pqc::mldsa::MLDsaVariant::MLDsa65);
    // Test key generation
    let _keypair = mldsa_provider.keypair_generate();

    // Test signing if keypair generation succeeds
    if let Ok((public_key, private_key)) = mldsa_provider.keypair_generate() {
        let _signature = mldsa_provider.sign(data, &private_key);

        // Test verification
        if let Ok(signature) = mldsa_provider.sign(data, &private_key) {
            let _verify = mldsa_provider.verify(data, &signature, &public_key);
        }
    }

    let mlkem_provider =
        pqc::PQCRegistry::create_mlkem_provider(crate::pqc::mlkem::MLKemVariant::MLKem768);
    // Test key encapsulation
    let _keypair = mlkem_provider.keypair_generate();

    if let Ok((public_key, private_key)) = mlkem_provider.keypair_generate() {
        let _encapsulated = mlkem_provider.encapsulate(&public_key);

        // Test decapsulation
        if let Ok((shared_secret, ciphertext)) = mlkem_provider.encapsulate(&public_key) {
            let _decapsulated = mlkem_provider.decapsulate(&private_key, &ciphertext);
        }
    }
});
