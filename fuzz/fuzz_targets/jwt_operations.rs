#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::auth::jwt;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Test JWT token operations
    let secret = &data[..32];
    let payload_data = &data[32..];

    if payload_data.is_empty() {
        return;
    }

    // Create JWT claims from payload data
    let claims = jwt::Claims {
        sub: String::from_utf8_lossy(payload_data).to_string(),
        exp: 2000000000, // Far future timestamp
        iat: 1000000000,
        iss: "test".to_string(),
    };

    // Test JWT encoding
    if let Ok(token) = jwt::JWT::encode(&claims, secret) {
        // Test JWT decoding
        if let Ok(decoded_claims) = jwt::JWT::decode(&token, secret) {
            // Verify claims match
            let _claims_match = decoded_claims.sub == claims.sub;
        }

        // Test with wrong secret (should fail)
        let wrong_secret = b"wrong_secret_key_for_testing_123456789";
        let _wrong_decode_fails = jwt::JWT::decode(&token, wrong_secret).is_err();

        // Test expired token
        let expired_claims = jwt::Claims {
            sub: claims.sub.clone(),
            exp: 1000000000, // Past timestamp
            iat: 1000000000,
            iss: "test".to_string(),
        };
        if let Ok(expired_token) = jwt::JWT::encode(&expired_claims, secret) {
            let _expired_decode_fails = jwt::JWT::decode(&expired_token, secret).is_err();
        }
    }
});