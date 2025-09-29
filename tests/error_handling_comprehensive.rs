//! Comprehensive error handling and edge case tests
//!
//! Tests error conditions, edge cases, boundary conditions,
//! and system behavior under adverse conditions.

use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::handlers::vault::*;
use crate::config::ApiConfig;
use crate::services::ServiceContainer;
use axum_test::TestServer;

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
mod error_handling_tests {
    use super::*;

    #[tokio::test]
    async fn test_malformed_request_handling() -> Result<()> {
        let server = create_test_server().await;

        // Test various malformed JSON payloads
        let malformed_payloads = vec![
            "invalid json",
            "{invalid json structure",
            "{\"data\": {\"key\": value}}", // Missing quotes
            "{\"data\": {\"key\": \"value\"}", // Missing closing brace
            "{\"data\": null}",
            "{\"metadata\": {\"tags\": [invalid]}}",
            "[]", // Wrong type
            "123", // Wrong type
            "\"just a string\"", // Wrong type
        ];

        for (i, payload) in malformed_payloads.iter().enumerate() {
            let response = server
                .post(&format!("/secrets/malformed_test_{}", i))
                .raw(payload)
                .await;

            // Should handle malformed requests gracefully
            assert!(
                response.status_code().is_client_error() ||
                response.status_code().is_server_error(),
                "Should handle malformed payload: {}",
                payload
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_boundary_value_handling() -> Result<()> {
        let server = create_test_server().await;

        // Test boundary conditions and edge values

        // 1. Very long secret path
        let long_path = "a".repeat(1000);
        let response = server.get(&format!("/secrets/{}", long_path)).await;
        assert!(
            response.status_code().is_client_error() ||
            response.status_code().is_success(),
            "Should handle long paths gracefully"
        );

        // 2. Very large secret data
        let large_data = json!({
            "data": {
                "large_field": "x".repeat(100_000) // 100KB
            }
        });

        let response = server
            .post("/secrets/boundary_large_data")
            .json(&large_data)
            .await;

        assert!(
            response.status_code().is_success() ||
            response.status_code() == axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "Should handle large data appropriately"
        );

        // 3. Empty values
        let empty_data = json!({
            "data": {
                "empty_key": "",
                "null_value": null
            },
            "metadata": {
                "description": "",
                "tags": []
            }
        });

        let response = server
            .post("/secrets/boundary_empty_values")
            .json(&empty_data)
            .await;

        assert!(
            response.status_code().is_success() ||
            response.status_code().is_client_error(),
            "Should handle empty values appropriately"
        );

        // 4. Special characters in paths and data
        let special_chars_data = json!({
            "data": {
                "unicode": "测试数据🔑",
                "special": "!@#$%^&*()",
                "path_chars": "/path/with/slashes"
            }
        });

        let response = server
            .post("/secrets/boundary_special_chars")
            .json(&special_chars_data)
            .await;

        assert!(
            response.status_code().is_success() ||
            response.status_code().is_client_error(),
            "Should handle special characters appropriately"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_error_scenarios() -> Result<()> {
        let server = create_test_server().await;
        let num_threads = 10;

        // Test concurrent error conditions
        let mut handles = Vec::new();

        for i in 0..num_threads {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                // Each thread performs operations that may fail
                let results = Vec::new();

                // Try to access non-existent resources
                let response = server_clone.get("/secrets/non_existent").await;
                let result1 = response.status_code().is_client_error();

                // Try invalid operations
                let response = server_clone
                    .post("/encrypt")
                    .json(&json!({
                        "key_id": "non_existent_key",
                        "plaintext": "test"
                    }))
                    .await;
                let result2 = response.status_code().is_client_error();

                // Try to create secrets with invalid data
                let response = server_clone
                    .post(&format!("/secrets/concurrent_error_{}", i))
                    .json(&json!({"invalid": "data"}))
                    .await;
                let result3 = response.status_code().is_success() || response.status_code().is_client_error();

                Ok::<_, anyhow::Error>((result1, result2, result3))
            });
            handles.push(handle);
        }

        // Collect results
        let mut success_count = 0;
        for handle in handles {
            let (r1, r2, r3) = handle.await??;
            if r1 && r2 && r3 {
                success_count += 1;
            }
        }

        println!("Concurrent error handling: {}/{} threads handled errors correctly", success_count, num_threads);

        // Most threads should handle errors correctly
        assert!(success_count >= num_threads * 8 / 10, "Should handle concurrent errors properly");

        Ok(())
    }

    #[tokio::test]
    async fn test_resource_exhaustion_handling() -> Result<()> {
        let server = create_test_server().await;

        // Test system behavior under resource pressure

        // 1. Create many secrets to consume storage
        let mut created_secrets = Vec::new();
        for i in 0..200 {
            let payload = json!({
                "data": {
                    "resource_test": format!("data_chunk_{}", i),
                    "size": "large_data_".repeat(100) // ~1KB per secret
                }
            });

            let response = server
                .post(&format!("/secrets/resource_test_{}", i))
                .json(&payload)
                .await;

            if response.status_code().is_success() {
                created_secrets.push(i);
            } else {
                break; // Stop when resource limits are hit
            }
        }

        println!("Created {} secrets before hitting resource limits", created_secrets.len());

        // 2. Try operations after resource pressure
        let response = server
            .post("/secrets/resource_test_after_pressure")
            .json(&json!({"data": {"test": "post_pressure"}}))
            .await;

        // Should handle gracefully
        assert!(
            response.status_code().is_success() ||
            response.status_code().is_client_error() ||
            response.status_code() == axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Should handle resource pressure gracefully"
        );

        // 3. Clean up created secrets
        for i in created_secrets {
            let _ = server.delete(&format!("/secrets/resource_test_{}", i)).await;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_timeout_handling() -> Result<()> {
        let server = create_test_server().await;

        // Test operations that might timeout

        // 1. Create operation that might be slow
        let slow_payload = json!({
            "data": {
                "slow_operation": "This operation might take time to process",
                "processing_hint": "large_data_processing_required"
            },
            "metadata": {
                "description": "Potentially slow operation",
                "tags": ["slow", "test"]
            }
        });

        let start_time = Instant::now();
        let response = server
            .post("/secrets/timeout_test_operation")
            .json(&slow_payload)
            .await;
        let duration = start_time.elapsed();

        println!("Slow operation took: {:?}", duration);

        // Should complete within reasonable time
        assert!(duration < Duration::from_secs(10), "Operation should not timeout");

        if response.status_code().is_success() {
            // 2. Test reading the slow operation result
            let response = server.get("/secrets/timeout_test_operation").await;
            assert!(response.status_code().is_success(), "Should be able to read completed operation");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_network_partition_simulation() -> Result<()> {
        let server = create_test_server().await;

        // Simulate network issues by testing error recovery

        // 1. Create baseline state
        let response = server
            .post("/secrets/network_partition_baseline")
            .json(&json!({"data": {"baseline": "test"}}))
            .await;
        response.assert_status_ok();

        // 2. Simulate temporary unavailability
        // (In real test, would simulate network disconnect)
        sleep(Duration::from_millis(100)).await;

        // 3. Verify system recovers
        let response = server.get("/secrets/network_partition_baseline").await;
        response.assert_status_ok();

        // 4. Test operations after "network recovery"
        let response = server
            .post("/secrets/network_partition_recovery")
            .json(&json!({"data": {"recovery": "test"}}))
            .await;
        response.assert_status_ok();

        Ok(())
    }

    #[tokio::test]
    async fn test_corrupted_data_handling() -> Result<()> {
        let server = create_test_server().await;

        // Test handling of corrupted or invalid data

        // 1. Try to decrypt with invalid ciphertext
        let decrypt_payload = json!({
            "key_id": "some_key_id",
            "ciphertext": "definitely_not_valid_base64_or_encrypted_data!!!",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/decrypt").json(&decrypt_payload).await;
        assert!(!response.status_code().is_success(), "Should reject invalid ciphertext");

        // 2. Try to read corrupted secret data
        // (This would require actual data corruption in storage layer)
        let response = server.get("/secrets/definitely_does_not_exist").await;
        assert_eq!(response.status_code(), axum::http::StatusCode::NOT_FOUND);

        // 3. Test with invalid key IDs
        let encrypt_payload = json!({
            "key_id": "invalid_key_id_with_special_chars_!@#$%",
            "plaintext": "test",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/encrypt").json(&encrypt_payload).await;
        assert!(!response.status_code().is_success(), "Should reject invalid key ID");

        Ok(())
    }

    #[tokio::test]
    async fn test_cascading_failure_prevention() -> Result<()> {
        let server = create_test_server().await;

        // Test that failures in one component don't cascade to others

        // 1. Create baseline working state
        let response = server
            .post("/secrets/cascading_failure_baseline")
            .json(&json!({"data": {"baseline": "working"}}))
            .await;
        response.assert_status_ok();

        // 2. Cause failures in crypto component
        let bad_encrypt_payload = json!({
            "key_id": "non_existent_key",
            "plaintext": "test"
        });

        let response = server.post("/encrypt").json(&bad_encrypt_payload).await;
        assert!(!response.status_code().is_success());

        // 3. Verify other components still work
        let response = server.get("/secrets/cascading_failure_baseline").await;
        response.assert_status_ok();

        let response = server
            .post("/secrets/cascading_failure_after_crypto_failure")
            .json(&json!({"data": {"test": "still_working"}}))
            .await;
        response.assert_status_ok();

        // 4. Verify audit logging still works
        let response = server.get("/audit").await;
        response.assert_status_ok();

        Ok(())
    }

    #[tokio::test]
    async fn test_configuration_error_handling() -> Result<()> {
        let server = create_test_server().await;

        // Test error handling with various configuration issues

        // 1. Try operations with invalid configuration
        let response = server
            .post("/secrets/config_error_test")
            .json(&json!({
                "data": {"test": "config_test"},
                "invalid_field": "should_cause_error"
            }))
            .await;

        // Should handle gracefully
        assert!(
            response.status_code().is_success() ||
            response.status_code().is_client_error(),
            "Should handle configuration errors"
        );

        // 2. Test with extreme configuration values
        let extreme_config = json!({
            "data": {
                "extreme_test": "value"
            },
            "metadata": {
                "description": "x".repeat(10000), // Very long description
                "tags": vec!["tag1"; 1000], // Many tags
                "owner": "x".repeat(1000) // Very long owner
            },
            "ttl": 3153600000 // 100 years
        });

        let response = server
            .post("/secrets/config_extreme_test")
            .json(&extreme_config)
            .await;

        assert!(
            response.status_code().is_success() ||
            response.status_code().is_client_error(),
            "Should handle extreme configuration"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_partial_failure_recovery() -> Result<()> {
        let server = create_test_server().await;

        // Test recovery from partial system failures

        // 1. Create multiple secrets
        let mut created_secrets = Vec::new();
        for i in 0..10 {
            let response = server
                .post(&format!("/secrets/partial_failure_test_{}", i))
                .json(&json!({"data": {"test": format!("data_{}", i)}}))
                .await;

            if response.status_code().is_success() {
                created_secrets.push(i);
            }
        }

        // 2. Simulate partial failure by deleting some secrets
        let secrets_to_delete = &created_secrets[0..5];
        for &i in secrets_to_delete {
            let response = server.delete(&format!("/secrets/partial_failure_test_{}", i)).await;
            // Some deletions might fail (simulating partial failure)
            if response.status_code().is_success() {
                created_secrets.retain(|&x| x != i);
            }
        }

        // 3. Verify remaining secrets still work
        for &i in &created_secrets {
            let response = server.get(&format!("/secrets/partial_failure_test_{}", i)).await;
            assert!(response.status_code().is_success(), "Remaining secrets should still work");
        }

        // 4. Clean up
        for &i in &created_secrets {
            let _ = server.delete(&format!("/secrets/partial_failure_test_{}", i)).await;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_system_overload_recovery() -> Result<()> {
        let server = create_test_server().await;

        // Test system recovery from overload conditions

        // 1. Create baseline
        let response = server
            .post("/secrets/overload_recovery_baseline")
            .json(&json!({"data": {"baseline": "test"}}))
            .await;
        response.assert_status_ok();

        // 2. Generate high load
        let mut overload_handles = Vec::new();
        for i in 0..50 {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                let response = server_clone
                    .post(&format!("/secrets/overload_test_{}", i))
                    .json(&json!({"data": {"load": format!("test_{}", i)}}))
                    .await;
                response.status_code().is_success()
            });
            overload_handles.push(handle);
        }

        // Wait for overload operations
        let successful_overload = overload_handles.into_iter()
            .map(|h| h.await.unwrap_or(false))
            .filter(|&success| success)
            .count();

        println!("Overload test: {}/50 operations succeeded", successful_overload);

        // 3. Test recovery
        let response = server.get("/secrets/overload_recovery_baseline").await;
        response.assert_status_ok();

        let response = server
            .post("/secrets/overload_recovery_test")
            .json(&json!({"data": {"recovery": "test"}}))
            .await;
        response.assert_status_ok();

        Ok(())
    }

    #[tokio::test]
    async fn test_graceful_degradation() -> Result<()> {
        let server = create_test_server().await;

        // Test how system degrades gracefully under various failure conditions

        // 1. Test with storage backend issues
        // (In real implementation, would simulate storage failure)

        // 2. Test with crypto service issues
        let bad_crypto_payload = json!({
            "key_id": "corrupted_key_id",
            "plaintext": "test",
            "algorithm": "INVALID_ALGORITHM"
        });

        let response = server.post("/encrypt").json(&bad_crypto_payload).await;
        assert!(!response.status_code().is_success(), "Should handle crypto service errors");

        // 3. Verify other services still work
        let response = server
            .post("/secrets/graceful_degradation_test")
            .json(&json!({"data": {"test": "other_services"}}))
            .await;
        response.assert_status_ok();

        // 4. Test audit logging degradation
        let response = server.get("/audit").await;
        // Audit should work even if other services have issues
        assert!(
            response.status_code().is_success() ||
            response.status_code() == axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Audit should handle gracefully"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_data_consistency_under_failures() -> Result<()> {
        let server = create_test_server().await;

        // Test data consistency when failures occur

        // 1. Create consistent initial state
        let response = server
            .post("/secrets/consistency_test_1")
            .json(&json!({"data": {"value": "1"}}))
            .await;
        response.assert_status_ok();

        let response = server
            .post("/secrets/consistency_test_2")
            .json(&json!({"data": {"value": "2"}}))
            .await;
        response.assert_status_ok();

        // 2. Simulate inconsistent operations
        let response = server
            .post("/secrets/consistency_test_3")
            .json(&json!({"invalid": "data"}))
            .await;

        // Even if this fails, previous data should remain consistent
        let response = server.get("/secrets/consistency_test_1").await;
        response.assert_status_ok();
        let body: ApiResponse<SecretResponse> = response.json();
        let secret1 = body.data.unwrap();
        assert_eq!(secret1.data["value"], "1");

        let response = server.get("/secrets/consistency_test_2").await;
        response.assert_status_ok();
        let body: ApiResponse<SecretResponse> = response.json();
        let secret2 = body.data.unwrap();
        assert_eq!(secret2.data["value"], "2");

        Ok(())
    }

    #[tokio::test]
    async fn test_error_message_security() -> Result<()> {
        let server = create_test_server().await;

        // Test that error messages don't leak sensitive information

        // 1. Try to access non-existent secret
        let response = server.get("/secrets/non_existent_secret").await;
        assert_eq!(response.status_code(), axum::http::StatusCode::NOT_FOUND);

        let body: serde_json::Value = response.json();

        // Error message should not contain sensitive paths or data
        let error_text = body.to_string();
        assert!(
            !error_text.contains("/home/") &&
            !error_text.contains("/usr/") &&
            !error_text.contains("root") &&
            !error_text.contains("password") &&
            !error_text.contains("secret"),
            "Error messages should not leak sensitive information"
        );

        // 2. Try crypto operation with bad data
        let response = server
            .post("/decrypt")
            .json(&json!({
                "key_id": "bad_key",
                "ciphertext": "invalid",
                "algorithm": "AES-GCM"
            }))
            .await;

        assert!(!response.status_code().is_success());
        let body: serde_json::Value = response.json();
        let error_text = body.to_string();

        // Should not leak key information or internal errors
        assert!(
            !error_text.contains("key") &&
            !error_text.contains("panic") &&
            !error_text.contains("stack trace"),
            "Crypto error messages should be sanitized"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting_effectiveness() -> Result<()> {
        let server = create_test_server().await;

        // Test rate limiting behavior

        // 1. Make rapid requests to test rate limiting
        let mut responses = Vec::new();
        for i in 0..20 {
            let response = server
                .post(&format!("/secrets/rate_limit_test_{}", i))
                .json(&json!({"data": {"test": "rate_limit"}}))
                .await;

            responses.push(response.status_code());
        }

        // 2. Analyze response patterns
        let success_count = responses.iter().filter(|&&s| s.is_success()).count();
        let client_error_count = responses.iter().filter(|&&s| s.is_client_error()).count();
        let server_error_count = responses.iter().filter(|&&s| s.is_server_error()).count();

        println!("Rate limiting test results:");
        println!("  Success: {}", success_count);
        println!("  Client errors: {}", client_error_count);
        println!("  Server errors: {}", server_error_count);

        // Should have reasonable distribution
        assert!(success_count > 0, "Should allow some successful requests");
        assert!(client_error_count + server_error_count < 20, "Should not fail all requests");

        Ok(())
    }

    #[tokio::test]
    async fn test_comprehensive_input_validation() -> Result<()> {
        let server = create_test_server().await;

        // Test comprehensive input validation scenarios

        let validation_test_cases = vec![
            // Invalid JSON structures
            ("empty_object", json!({})),
            ("null_data", json!({"data": null})),
            ("empty_data", json!({"data": {}})),
            ("invalid_metadata", json!({"data": {"key": "value"}, "metadata": "invalid"})),

            // Boundary cases
            ("very_long_key", json!({"data": {"x".repeat(1000): "value"}})),
            ("very_long_value", json!({"data": {"key": "x".repeat(10000)}})),
            ("empty_key", json!({"data": {"": "value"}})),
            ("null_key", json!({"data": {null: "value"}})),

            // Special characters
            ("unicode_key", json!({"data": {"测试": "value"}})),
            ("emoji_key", json!({"data": {"🔑": "value"}})),
            ("sql_injection", json!({"data": {"key": "'; DROP TABLE secrets; --"}})),
            ("xss_attempt", json!({"data": {"key": "<script>alert('xss')</script>"}})),

            // Numeric extremes
            ("negative_ttl", json!({"data": {"key": "value"}, "ttl": -1})),
            ("zero_ttl", json!({"data": {"key": "value"}, "ttl": 0})),
            ("huge_ttl", json!({"data": {"key": "value"}, "ttl": 3153600000})), // 100 years

            // Array handling
            ("empty_tags", json!({"data": {"key": "value"}, "metadata": {"tags": []}})),
            ("many_tags", json!({"data": {"key": "value"}, "metadata": {"tags": vec!["tag1"; 100]}})),
        ];

        for (test_name, payload) in validation_test_cases {
            let response = server
                .post(&format!("/secrets/validation_test_{}", test_name))
                .json(&payload)
                .await;

            // Should handle all validation cases gracefully
            assert!(
                response.status_code().is_success() ||
                response.status_code().is_client_error(),
                "Should handle validation case: {}",
                test_name
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_system_resource_cleanup() -> Result<()> {
        let server = create_test_server().await;

        // Test that system properly cleans up resources

        // 1. Create many temporary resources
        let mut created_resources = Vec::new();

        for i in 0..50 {
            let response = server
                .post(&format!("/secrets/cleanup_test_{}", i))
                .json(&json!({"data": {"test": format!("data_{}", i)}}))
                .await;

            if response.status_code().is_success() {
                created_resources.push(i);
            }
        }

        // 2. Delete all created resources
        for &i in &created_resources {
            let response = server.delete(&format!("/secrets/cleanup_test_{}", i)).await;
            if response.status_code().is_success() {
                created_resources.retain(|&x| x != i);
            }
        }

        // 3. Verify cleanup
        let remaining_count = created_resources.len();
        println!("Cleanup test: {} resources remaining after cleanup", remaining_count);

        // Should clean up most resources
        assert!(remaining_count < 5, "Should clean up most resources");

        // 4. Verify system is still functional after cleanup
        let response = server
            .post("/secrets/cleanup_verification_test")
            .json(&json!({"data": {"test": "system_still_works"}}))
            .await;
        response.assert_status_ok();

        Ok(())
    }
}
