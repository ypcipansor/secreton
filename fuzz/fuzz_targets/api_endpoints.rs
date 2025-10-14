#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::api::*;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Test API structures and serialization
    if data.len() < 50 {
        return;
    }

    // Test AuthenticationRequest parsing
    if let Ok(auth_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<AuthenticationRequest>(auth_str);
    }

    // Test HsmRequest parsing
    if let Ok(hsm_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<HsmRequest>(hsm_str);
    }

    // Test AuditRequest parsing
    if let Ok(audit_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<AuditRequest>(audit_str);
    }

    // Test API response creation
    let test_data = HashMap::from([("test_key".to_string(), "test_value".to_string())]);
    let _success_response: ApiResponse<HashMap<String, String>> =
        ApiResponse::success(test_data.clone());
    let _error_response: ApiResponse<HashMap<String, String>> =
        ApiResponse::error("Test error".to_string());

    // Test serialization of responses
    let _ = serde_json::to_string(&_success_response);
    let _ = serde_json::to_string(&_error_response);

    // Test various API structures
    let client_info = ClientInfo {
        ip_address: "127.0.0.1".to_string(),
        user_agent: Some("test-agent".to_string()),
        geo_location: Some("US".to_string()),
        device_fingerprint: Some("test-fingerprint".to_string()),
    };

    let mfa_response = MfaResponse {
        method: "totp".to_string(),
        response: "123456".to_string(),
    };

    let _auth_request = AuthenticationRequest {
        user_id: "test-user".to_string(),
        mfa_responses: vec![mfa_response],
        client_info,
    };

    // Test JSON parsing with various inputs
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<serde_json::Value>(json_str);
    }
});
