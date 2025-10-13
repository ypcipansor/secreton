#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::mtls;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    // Test mTLS certificate generation and validation
    let cert_data = &data[..64];
    let client_data = &data[64..];

    // Test certificate generation
    if let Ok(cert) = mtls::Certificate::generate_from_data(cert_data) {
        // Test certificate validation
        let _is_valid = cert.validate();

        // Test client certificate authentication
        if !client_data.is_empty() {
            if let Ok(client_cert) = mtls::Certificate::generate_from_data(client_data) {
                // Test mutual authentication
                let _mutual_auth = mtls::MutualTLS::authenticate(&cert, &client_cert);

                // Test certificate chain validation
                let chain = vec![cert.clone(), client_cert];
                let _chain_valid = mtls::CertificateChain::validate_chain(&chain);
            }
        }

        // Test certificate serialization/deserialization
        if let Ok(serialized) = cert.serialize() {
            let _deserialized = mtls::Certificate::deserialize(&serialized);
        }
    }
});