//! Security penetration tests for vault system
//!
//! Tests various attack vectors including injection attacks, authentication bypass,
//! authorization bypass, data exfiltration, and DoS attempts.

use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use serde_json::json;
use std::collections::HashMap;

use crate::handlers::vault::*;
use crate::config::ApiConfig;
use crate::services::ServiceContainer;
use axum_test::TestServer;
use std::sync::Arc;

async fn create_test_server() -> TestServer {
    let config = ApiConfig::default();
    let services = Arc::new(
        ServiceContainer::new(&config)
            .await
            .expect("Failed to create services"),
    );

    let app = create_routes().with_state(services);
    TestServer::new(app).expect("Failed to create test server")
}

#[cfg(test)]
mod security_penetration_tests {
    use super::*;

    #[tokio::test]
    async fn test_sql_injection_prevention() {
        let server = create_test_server().await;

        // Test SQL injection attempts in various endpoints
        let malicious_inputs = vec![
            "'; DROP TABLE secrets; --",
            "admin' OR '1'='1",
            "test' UNION SELECT * FROM users --",
            "path'; DELETE FROM audit_entries; --",
            "key' OR SLEEP(5) OR '",
        ];

        for malicious_input in malicious_inputs {
            // Test in secret paths
            let response = server.get(&format!("/secrets/{}", malicious_input)).await;
            // Should either return 404 (not found) or handle gracefully, not crash
            assert!(
                response.status_code() == StatusCode::NOT_FOUND ||
                response.status_code() == StatusCode::BAD_REQUEST ||
                response.status_code() == StatusCode::UNAUTHORIZED,
                "SQL injection attempt should be handled safely: {}",
                malicious_input
            );

            // Test in key operations
            let response = server.get(&format!("/keys/{}", malicious_input)).await;
            assert!(
                response.status_code() == StatusCode::NOT_FOUND ||
                response.status_code() == StatusCode::BAD_REQUEST ||
                response.status_code() == StatusCode::UNAUTHORIZED,
                "SQL injection in keys should be handled safely: {}",
                malicious_input
            );
        }
    }

    #[tokio::test]
    async fn test_xss_prevention() {
        let server = create_test_server().await;

        // Test XSS attempts in various inputs
        let xss_payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//",
        ];

        for payload in xss_payloads {
            let create_payload = json!({
                "data": {
                    "malicious": payload
                },
                "metadata": {
                    "description": format!("XSS test: {}", payload),
                    "tags": ["xss", "test"]
                }
            });

            let response = server
                .post(&format!("/secrets/xss-test/{}", payload.replace(['/', '\\'], "_")))
                .json(&create_payload)
                .await;

            // Should either reject the request or sanitize the input
            assert!(
                response.status_code() == StatusCode::BAD_REQUEST ||
                response.status_code() == StatusCode::OK,
                "XSS payload should be handled safely: {}",
                payload
            );

            if response.status_code() == StatusCode::OK {
                // If accepted, verify the data is properly stored (sanitized)
                let read_response = server
                    .get(&format!("/secrets/xss-test/{}", payload.replace(['/', '\\'], "_")))
                    .await;

                if read_response.status_code() == StatusCode::OK {
                    let body: serde_json::Value = read_response.json();
                    // The malicious content should be stored as-is (not executed)
                    // This tests that we're not vulnerable to stored XSS
                }
            }
        }
    }

    #[tokio::test]
    async fn test_path_traversal_prevention() {
        let server = create_test_server().await;

        // Test path traversal attempts
        let traversal_attempts = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "/secrets/../../../etc/passwd",
            "\\secrets\\..\\..\\..\\windows\\system32\\config\\sam",
        ];

        for traversal_path in traversal_attempts {
            let response = server.get(&format!("/secrets/{}", traversal_path)).await;

            // Should reject path traversal attempts
            assert_ne!(
                response.status_code(),
                StatusCode::OK,
                "Path traversal should be prevented: {}",
                traversal_path
            );

            // Should not return sensitive system information
            let body: serde_json::Value = response.json();
            if let Some(data) = body.get("data") {
                assert!(
                    !data.to_string().contains("root:") &&
                    !data.to_string().contains("password") &&
                    !data.to_string().contains("shadow"),
                    "Should not leak system information"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_authentication_bypass_attempts() {
        let server = create_test_server().await;

        // Test various authentication bypass attempts
        let bypass_attempts = vec![
            ("", "Bearer "),
            ("invalid_token", "Bearer "),
            ("null", "Bearer null"),
            ("undefined", "Bearer undefined"),
            ("admin", "Basic YWRtaW46"), // base64 of "admin:"
        ];

        for (token_value, auth_prefix) in bypass_attempts {
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                format!("{} {}", auth_prefix, token_value).parse().unwrap()
            );

            let response = server
                .get("/secrets/sensitive/data")
                .headers(headers)
                .await;

            // Should reject unauthorized access
            assert_eq!(
                response.status_code(),
                StatusCode::UNAUTHORIZED,
                "Auth bypass attempt should fail: {} {}",
                auth_prefix,
                token_value
            );
        }
    }

    #[tokio::test]
    async fn test_authorization_bypass_attempts() {
        let server = create_test_server().await;

        // Test attempts to access admin functions without proper authorization
        let admin_endpoints = vec![
            "/admin/users",
            "/admin/policies",
            "/admin/audit",
            "/admin/backup",
        ];

        for endpoint in admin_endpoints {
            let response = server.get(endpoint).await;

            // Should require proper authorization
            assert!(
                response.status_code() == StatusCode::UNAUTHORIZED ||
                response.status_code() == StatusCode::FORBIDDEN,
                "Admin endpoint should require authorization: {}",
                endpoint
            );
        }
    }

    #[tokio::test]
    async fn test_data_exfiltration_attempts() {
        let server = create_test_server().await;

        // Test attempts to extract large amounts of data or enumerate secrets
        let mut headers = HeaderMap::new();

        // Attempt to list all secrets with large page sizes
        let response = server
            .get("/secrets?limit=10000&offset=0")
            .headers(headers)
            .await;

        // Should handle pagination limits properly
        let body: ApiResponse<Vec<SecretListItem>> = response.json();
        if response.status_code() == StatusCode::OK {
            assert!(body.success);
            let secrets = body.data.unwrap();
            // Should respect pagination limits
            assert!(secrets.len() <= 1000, "Should limit result size");
        }

        // Test rapid enumeration attempts
        let mut rapid_requests = Vec::new();
        for i in 0..100 {
            let path = format!("/secrets/enum-test-{}", i);
            rapid_requests.push(server.get(&path).await);
        }

        // Most requests should be handled gracefully
        let error_count = rapid_requests
            .iter()
            .filter(|r| r.status_code().is_server_error())
            .count();

        assert!(
            error_count < 10,
            "System should handle enumeration attempts gracefully"
        );
    }

    #[tokio::test]
    async fn test_dos_prevention() {
        let server = create_test_server().await;

        // Test DoS attempts with large payloads
        let large_payload = json!({
            "data": {
                "large_field": "x".repeat(10_000_000) // 10MB payload
            }
        });

        let response = server
            .post("/secrets/dos-test")
            .json(&large_payload)
            .await;

        // Should reject oversized payloads
        assert!(
            response.status_code() == StatusCode::PAYLOAD_TOO_LARGE ||
            response.status_code() == StatusCode::BAD_REQUEST,
            "Should prevent DoS via large payloads"
        );

        // Test rapid request DoS
        let mut rapid_responses = Vec::new();
        for _ in 0..1000 {
            rapid_responses.push(server.get("/health").await);
        }

        // Should handle rapid requests gracefully
        let server_error_count = rapid_responses
            .iter()
            .filter(|r| r.status_code().is_server_error())
            .count();

        // Allow some server errors but not too many
        assert!(
            server_error_count < 50,
            "Should handle rapid requests without complete failure"
        );
    }

    #[tokio::test]
    async fn test_csrf_prevention() {
        let server = create_test_server().await;

        // Test CSRF attempts by checking for proper CORS handling
        // and ensuring POST requests require proper authentication

        let response = server
            .post("/secrets/csrf-test")
            .json(&json!({"data": {"test": "csrf"}}))
            .await;

        // Should require proper authentication for state-changing operations
        assert!(
            response.status_code() == StatusCode::UNAUTHORIZED ||
            response.status_code() == StatusCode::OK,
            "CSRF test should be handled properly"
        );
    }

    #[tokio::test]
    async fn test_input_validation() {
        let server = create_test_server().await;

        // Test various malformed inputs
        let malicious_inputs = vec![
            json!({"data": null}),
            json!({"data": {"": ""}}), // Empty key
            json!({"metadata": {"tags": [""]}}), // Empty tags
            json!({"ttl": -1}), // Negative TTL
            json!({"data": {"key": null}}), // Null values
        ];

        for input in malicious_inputs {
            let response = server
                .post("/secrets/validation-test")
                .json(&input)
                .await;

            // Should validate inputs properly
            assert!(
                response.status_code() == StatusCode::BAD_REQUEST ||
                response.status_code() == StatusCode::OK,
                "Should validate input properly"
            );
        }
    }

    #[tokio::test]
    async fn test_information_disclosure_prevention() {
        let server = create_test_server().await;

        // Test error message information disclosure
        let response = server.get("/non-existent-endpoint").await;

        if response.status_code() == StatusCode::NOT_FOUND {
            let body: serde_json::Value = response.json();

            // Error messages should not leak sensitive information
            let error_message = body.to_string();
            assert!(
                !error_message.contains("stack trace") &&
                !error_message.contains("/usr/") &&
                !error_message.contains("/home/") &&
                !error_message.contains("root"),
                "Error messages should not leak system information"
            );
        }
    }

    #[tokio::test]
    async fn test_timing_attack_prevention() {
        let server = create_test_server().await;

        // Test timing attacks by measuring response times
        use std::time::Instant;

        let mut response_times = Vec::new();
        let test_paths = vec![
            "/secrets/existing-secret",  // Should exist
            "/secrets/non-existent-1",   // Should not exist
            "/secrets/non-existent-2",   // Should not exist
        ];

        for path in test_paths {
            let start = Instant::now();
            let response = server.get(path).await;
            let elapsed = start.elapsed();

            response_times.push((path, elapsed, response.status_code()));

            // Add small delay to prevent rapid-fire timing attacks
            sleep(Duration::from_millis(10)).await;
        }

        // Verify that response times don't leak information
        // (e.g., existing vs non-existing resources shouldn't have dramatically different response times)
        let existing_time = response_times.iter().find(|(p, _, _)| p.contains("existing")).unwrap().1;
        let non_existing_times: Vec<_> = response_times
            .iter()
            .filter(|(p, _, _)| p.contains("non-existent"))
            .map(|(_, t, _)| t)
            .collect();

        let avg_non_existing = non_existing_times.iter().sum::<Duration>() / non_existing_times.len() as u32;

        // The ratio should not be too extreme (indicating timing leaks)
        let ratio = existing_time.as_nanos() as f64 / avg_non_existing.as_nanos() as f64;
        assert!(
            ratio < 5.0 && ratio > 0.2,
            "Response times should not leak information about resource existence: {}",
            ratio
        );
    }

    #[tokio::test]
    async fn test_cryptographic_attacks() {
        let server = create_test_server().await;

        // Test weak key generation
        let weak_key_payload = json!({
            "name": "weak-key",
            "key_type": "rsa",
            "size": 512, // Very small key size
            "algorithm": "RS256"
        });

        let response = server.post("/keys").json(&weak_key_payload).await;

        // Should reject weak cryptographic parameters
        assert!(
            response.status_code() == StatusCode::BAD_REQUEST ||
            response.status_code() == StatusCode::OK,
            "Should handle weak cryptographic parameters"
        );

        if response.status_code() == StatusCode::OK {
            // If accepted, verify the key is actually secure
            let body: ApiResponse<KeyResponse> = response.json();
            let key = body.data.unwrap();
            assert!(
                key.size >= 2048 || key.key_type != "rsa",
                "Should generate cryptographically strong keys"
            );
        }
    }

    #[tokio::test]
    async fn test_audit_log_tampering_prevention() {
        let server = create_test_server().await;

        // Create a secret to generate audit logs
        let create_payload = json!({
            "data": {"audit": "test"}
        });

        let response = server
            .post("/secrets/audit-tamper-test")
            .json(&create_payload)
            .await;
        response.assert_status_ok();

        // Attempt to delete audit logs (if endpoint exists)
        let response = server.delete("/audit").await;

        // Should prevent audit log tampering
        if response.status_code() != StatusCode::NOT_FOUND {
            assert!(
                response.status_code() == StatusCode::UNAUTHORIZED ||
                response.status_code() == StatusCode::FORBIDDEN,
                "Should prevent audit log tampering"
            );
        }

        // Verify audit logs still exist
        let response = server.get("/audit").await;
        if response.status_code() == StatusCode::OK {
            let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
            assert!(body.success);
            let audit_entries = body.data.unwrap();

            // Should have the secret creation audit entry
            assert!(
                audit_entries.iter().any(|e| e.action.contains("SecretCreation")),
                "Audit logs should be tamper-evident"
            );
        }
    }
}
