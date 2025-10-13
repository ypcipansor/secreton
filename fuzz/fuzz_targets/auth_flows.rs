#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::auth::*;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Test authentication flow parsing and validation
    if data.len() < 50 {
        return;
    }

    // Split data into different components
    let username_end = data.len() / 4;
    let password_end = 2 * data.len() / 4;
    let token_end = 3 * data.len() / 4;

    let username = &data[..username_end];
    let password = &data[username_end..password_end];
    let token = &data[password_end..token_end];
    let metadata = &data[token_end..];

    // Test username/password authentication
    if let (Ok(username_str), Ok(password_str)) = (
        std::str::from_utf8(username),
        std::str::from_utf8(password)
    ) {
        let mut credentials = HashMap::new();
        credentials.insert("username".to_string(), username_str.to_string());
        credentials.insert("password".to_string(), password_str.to_string());

        // Test credential validation (this will likely fail, but shouldn't crash)
        let _ = validate_credentials(&credentials);
    }

    // Test token validation
    if let Ok(token_str) = std::str::from_utf8(token) {
        let _ = validate_token(token_str);
        let _ = parse_jwt_token(token_str);
    }

    // Test metadata parsing
    if let Ok(metadata_str) = std::str::from_utf8(metadata) {
        let _ = parse_auth_metadata(metadata_str);
    }
});