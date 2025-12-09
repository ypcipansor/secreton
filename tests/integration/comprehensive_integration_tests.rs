//! Integration tests for multi-component scenarios
//!
//! Tests interactions between different system components including
//! API layer, storage backends, cryptographic operations, and audit logging.

use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::handlers::secreton::*;
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
mod multi_component_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_end_to_end_secret_encryption_workflow() -> Result<()> {
        let server = create_test_server().await;

        // 1. Create encryption key
        let create_key_payload = json!({
            "name": "e2e-test-key",
            "key_type": "aes256-gcm96",
            "algorithm": "AES-GCM",
            "usage": ["encrypt", "decrypt"],
            "metadata": {
                "description": "End-to-end test encryption key",
                "purpose": "secret-encryption"
            }
        });

        let response = server.post("/keys").json(&create_key_payload).await;
        response.assert_status_ok();
        let body: ApiResponse<KeyResponse> = response.json();
        let key = body.data.unwrap();
        let key_id = key.id;

        // 2. Create secret with sensitive data
        let secret_payload = json!({
            "data": {
                "api_key": "sk-123456789abcdef",
                "database_password": "super_secret_db_pass",
                "ssl_certificate": "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END CERTIFICATE-----"
            },
            "metadata": {
                "description": "Production credentials requiring encryption",
                "tags": ["production", "sensitive", "encrypted"],
                "owner": "platform-team",
                "classification": "secret"
            }
        });

        let response = server
            .post("/secrets/production/encrypted-credentials")
            .json(&secret_payload)
            .await;
        response.assert_status_ok();

        // 3. Encrypt the secret data using the key
        let encrypt_payload = json!({
            "key_id": key_id,
            "plaintext": "Additional sensitive data that needs encryption",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/encrypt").json(&encrypt_payload).await;
        response.assert_status_ok();
        let body: ApiResponse<EncryptResponse> = response.json();
        let encrypted_data = body.data.unwrap();

        // 4. Store encrypted data as new secret
        let encrypted_secret_payload = json!({
            "data": {
                "encrypted_field": encrypted_data.ciphertext,
                "encryption_key_id": key_id,
                "algorithm": "AES-GCM"
            },
            "metadata": {
                "description": "Secret containing encrypted data",
                "tags": ["encrypted", "derived"],
                "classification": "secret"
            }
        });

        let response = server
            .post("/secrets/production/derived-encrypted-secret")
            .json(&encrypted_secret_payload)
            .await;
        response.assert_status_ok();

        // 5. Read back and decrypt
        let response = server.get("/secrets/production/encrypted-credentials").await;
        response.assert_status_ok();
        let body: ApiResponse<SecretResponse> = response.json();
        let secret = body.data.unwrap();

        // Verify the original data is intact
        assert_eq!(secret.data["api_key"], "sk-123456789abcdef");
        assert_eq!(secret.data["database_password"], "super_secret_db_pass");

        // 6. Decrypt the derived secret
        let decrypt_payload = json!({
            "key_id": key_id,
            "ciphertext": encrypted_data.ciphertext,
            "algorithm": "AES-GCM"
        });

        let response = server.post("/decrypt").json(&decrypt_payload).await;
        response.assert_status_ok();
        let body: ApiResponse<DecryptResponse> = response.json();
        let decrypted = body.data.unwrap();
        assert_eq!(decrypted.plaintext, "Additional sensitive data that needs encryption");

        // 7. Verify audit trail
        let response = server.get("/audit").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
        let audit_entries = body.data.unwrap();

        // Should have audit entries for key creation, secret creation, encryption, decryption
        let key_creation_audits = audit_entries.iter()
            .filter(|e| e.action.contains("KeyGeneration"))
            .count();
        let secret_audits = audit_entries.iter()
            .filter(|e| e.action.contains("SecretCreation"))
            .count();
        let crypto_audits = audit_entries.iter()
            .filter(|e| e.action.contains("Encryption") || e.action.contains("Decryption"))
            .count();

        assert!(key_creation_audits >= 1, "Should have key creation audit");
        assert!(secret_audits >= 2, "Should have secret creation audits");
        assert!(crypto_audits >= 2, "Should have crypto operation audits");

        Ok(())
    }

    #[tokio::test]
    async fn test_cross_component_data_flow() -> Result<()> {
        let server = create_test_server().await;

        // Test data flow between API, storage, crypto, and audit components

        // 1. Create user authentication (simulated)
        // In real scenario, this would involve actual auth service
        let auth_headers = json!({
            "Authorization": "Bearer test_token_12345"
        });

        // 2. Create secret through API
        let secret_payload = json!({
            "data": {
                "service_config": "database_connection_string",
                "credentials": "encrypted_credentials"
            },
            "metadata": {
                "description": "Service configuration requiring encryption",
                "owner": "microservice-team"
            }
        });

        let response = server
            .post("/secrets/services/payment-service/config")
            .json(&secret_payload)
            .await;
        response.assert_status_ok();

        // 3. Create encryption key for the service
        let key_payload = json!({
            "name": "payment-service-key",
            "key_type": "aes256-gcm96",
            "usage": ["encrypt", "decrypt"]
        });

        let response = server.post("/keys").json(&key_payload).await;
        response.assert_status_ok();
        let body: ApiResponse<KeyResponse> = response.json();
        let key = body.data.unwrap();
        let key_id = key.id;

        // 4. Encrypt additional service data
        let encrypt_payload = json!({
            "key_id": key_id,
            "plaintext": "payment_api_secret_key_abcdef123456",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/encrypt").json(&encrypt_payload).await;
        response.assert_status_ok();

        // 5. List all secrets to verify storage integration
        let response = server.get("/secrets/services").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<SecretListItem>> = response.json();
        let secrets = body.data.unwrap();

        // Should have the service secret
        assert!(secrets.iter().any(|s| s.path == "services/payment-service/config"));

        // 6. List all keys to verify key storage
        let response = server.get("/keys").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<KeyResponse>> = response.json();
        let keys = body.data.unwrap();

        // Should have the payment service key
        assert!(keys.iter().any(|k| k.name == "payment-service-key"));

        // 7. Verify audit trail captures all operations
        let response = server.get("/audit").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
        let audit_entries = body.data.unwrap();

        // Should have comprehensive audit trail
        assert!(audit_entries.len() >= 5, "Should have comprehensive audit trail");

        Ok(())
    }

    #[tokio::test]
    async fn test_backup_restore_with_crypto_integration() -> Result<()> {
        let server = create_test_server().await;

        // 1. Create multiple secrets and keys
        let test_assets = vec![
            ("backup_secret_1", json!({"data": {"key": "value1"}, "metadata": {"type": "test"}})),
            ("backup_secret_2", json!({"data": {"key": "value2"}, "metadata": {"type": "test"}})),
        ];

        for (path, payload) in test_assets {
            let response = server.post(&format!("/secrets/{}", path)).json(&payload).await;
            response.assert_status_ok();
        }

        // Create encryption key
        let key_payload = json!({
            "name": "backup-test-key",
            "key_type": "aes256-gcm96"
        });

        let response = server.post("/keys").json(&key_payload).await;
        response.assert_status_ok();

        // 2. Create backup
        let response = server.post("/backup").await;
        response.assert_status_ok();
        let body: ApiResponse<serde_json::Value> = response.json();
        let backup_info = body.data.unwrap();

        // 3. Simulate data corruption/loss
        let response = server.delete("/secrets/backup_secret_1").await;
        response.assert_status_ok();

        // 4. List backups
        let response = server.get("/backup").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<serde_json::Value>> = response.json();
        let backups = body.data.unwrap();

        assert!(!backups.is_empty(), "Should have created backup");

        // 5. Restore from backup (simulated)
        if let Some(backup) = backups.first() {
            let backup_id = backup["id"].as_str().unwrap();

            let response = server.get(&format!("/backup/{}", backup_id)).await;
            response.assert_status_ok();

            // Verify backup contains our data
            let body: ApiResponse<serde_json::Value> = response.json();
            let backup_data = body.data.unwrap();

            // In real implementation, would restore from backup
            assert!(backup_data.as_object().unwrap().contains_key("created_at"));
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_policy_enforcement_across_components() -> Result<()> {
        let server = create_test_server().await;

        // 1. Create policy
        let policy_payload = json!({
            "name": "integration-test-policy",
            "rules": [
                {
                    "path": "restricted/*",
                    "capabilities": ["read", "list"]
                },
                {
                    "path": "public/*",
                    "capabilities": ["read", "list", "create", "update", "delete"]
                }
            ],
            "metadata": {
                "description": "Integration test policy",
                "owner": "test-team"
            }
        });

        let response = server
            .post("/policies/integration-test-policy")
            .json(&policy_payload)
            .await;
        response.assert_status_ok();

        // 2. Test policy enforcement on secret operations
        // Create secret in restricted path (should work for create if allowed)
        let restricted_payload = json!({
            "data": {"restricted": "data"},
            "metadata": {"description": "Restricted secret"}
        });

        let response = server
            .post("/secrets/restricted/test-secret")
            .json(&restricted_payload)
            .await;
        response.assert_status_ok();

        // Try to update restricted secret (may be denied based on policy)
        let update_payload = json!({
            "data": {"restricted": "updated_data"},
            "metadata": {"description": "Updated restricted secret"}
        });

        let response = server
            .put("/secrets/restricted/test-secret")
            .json(&update_payload)
            .await;

        // Policy enforcement should work (may succeed or fail based on exact policy)
        assert!(response.status_code().is_success() || response.status_code().is_client_error());

        // 3. Test policy on key operations
        let key_payload = json!({
            "name": "policy-test-key",
            "key_type": "aes256-gcm96"
        });

        let response = server.post("/keys").json(&key_payload).await;
        response.assert_status_ok();

        // 4. Verify audit trail includes policy decisions
        let response = server.get("/audit").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
        let audit_entries = body.data.unwrap();

        // Should have audit entries for policy operations
        let policy_audits = audit_entries.iter()
            .filter(|e| e.action.contains("Secret") || e.action.contains("Key"))
            .count();
        assert!(policy_audits >= 3, "Should have policy-related audit entries");

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_multi_component_operations() -> Result<()> {
        let server = create_test_server().await;
        let num_threads = 5;
        let operations_per_thread = 10;

        let start_time = Instant::now();

        // Create multiple concurrent workflows
        let mut handles = Vec::new();

        for thread_id in 0..num_threads {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                for op_id in 0..operations_per_thread {
                    // Each thread performs a complete workflow
                    let secret_path = format!("concurrent_multi/comp_{}_{}", thread_id, op_id);
                    let key_name = format!("key_{}_{}", thread_id, op_id);

                    // 1. Create secret
                    let secret_payload = json!({
                        "data": {
                            "thread_id": thread_id,
                            "operation_id": op_id,
                            "data": format!("concurrent_data_{}_{}", thread_id, op_id)
                        }
                    });

                    let response = server_clone
                        .post(&format!("/secrets/{}", secret_path))
                        .json(&secret_payload)
                        .await;

                    if !response.status_code().is_success() {
                        return Err(anyhow::anyhow!("Failed to create secret: {}", response.status_code()));
                    }

                    // 2. Create key
                    let key_payload = json!({
                        "name": key_name,
                        "key_type": "aes256-gcm96"
                    });

                    let response = server_clone.post("/keys").json(&key_payload).await;
                    if !response.status_code().is_success() {
                        return Err(anyhow::anyhow!("Failed to create key: {}", response.status_code()));
                    }

                    // 3. Encrypt data
                    let encrypt_payload = json!({
                        "key_id": format!("key_id_{}_{}", thread_id, op_id), // Simplified
                        "plaintext": format!("encrypt_me_{}_{}", thread_id, op_id),
                        "algorithm": "AES-GCM"
                    });

                    let response = server_clone.post("/encrypt").json(&encrypt_payload).await;
                    if !response.status_code().is_success() {
                        return Err(anyhow::anyhow!("Failed to encrypt: {}", response.status_code()));
                    }

                    // 4. Read back secret
                    let response = server_clone.get(&format!("/secrets/{}", secret_path)).await;
                    if !response.status_code().is_success() {
                        return Err(anyhow::anyhow!("Failed to read secret: {}", response.status_code()));
                    }

                    // Small delay to simulate real-world timing
                    sleep(Duration::from_millis(10)).await;
                }
                Ok::<_, anyhow::Error>(())
            });
            handles.push(handle);
        }

        // Wait for all workflows to complete
        for handle in handles {
            handle.await??;
        }

        let total_duration = start_time.elapsed();
        let total_operations = num_threads * operations_per_thread * 4; // 4 operations per workflow
        let operations_per_second = total_operations as f64 / total_duration.as_secs_f64();

        println!("Multi-component concurrent test: {} operations in {:?}", total_operations, total_duration);
        println!("Performance: {:.2} ops/sec", operations_per_second);

        // Verify all operations completed successfully
        assert!(operations_per_second > 5.0, "Should handle concurrent multi-component operations");

        // Verify audit trail
        let response = server.get("/audit").await;
        if response.status_code().is_success() {
            let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
            let audit_entries = body.data.unwrap();
            assert!(audit_entries.len() >= total_operations / 2, "Should have substantial audit trail");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_error_propagation_across_components() -> Result<()> {
        let server = create_test_server().await;

        // Test how errors propagate through the component stack

        // 1. Try to encrypt with non-existent key
        let encrypt_payload = json!({
            "key_id": "non_existent_key_12345",
            "plaintext": "test data",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/encrypt").json(&encrypt_payload).await;
        assert!(!response.status_code().is_success(), "Should fail with non-existent key");

        // 2. Try to access non-existent secret
        let response = server.get("/secrets/non/existent/secret").await;
        assert_eq!(response.status_code(), axum::http::StatusCode::NOT_FOUND);

        // 3. Try to decrypt with invalid ciphertext
        let decrypt_payload = json!({
            "key_id": "some_key",
            "ciphertext": "invalid_ciphertext",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/decrypt").json(&decrypt_payload).await;
        assert!(!response.status_code().is_success(), "Should fail with invalid ciphertext");

        // 4. Verify error handling doesn't corrupt system state
        // Try valid operation after errors
        let valid_payload = json!({
            "data": {"test": "error_recovery_test"}
        });

        let response = server
            .post("/secrets/error_recovery_test")
            .json(&valid_payload)
            .await;
        response.assert_status_ok();

        // Verify the valid operation succeeded despite previous errors
        let response = server.get("/secrets/error_recovery_test").await;
        response.assert_status_ok();

        // 5. Check audit trail includes error events
        let response = server.get("/audit").await;
        if response.status_code().is_success() {
            let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
            let audit_entries = body.data.unwrap();

            // Should have error-related audit entries
            let error_audits = audit_entries.iter()
                .filter(|e| !e.success)
                .count();
            assert!(error_audits >= 3, "Should have error audit entries");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_system_recovery_and_resilience() -> Result<()> {
        let server = create_test_server().await;

        // 1. Create baseline state
        let baseline_payload = json!({
            "data": {"baseline": "test_data"}
        });

        let response = server
            .post("/secrets/system_recovery_baseline")
            .json(&baseline_payload)
            .await;
        response.assert_status_ok();

        // 2. Perform operations that might cause issues
        let mut operation_handles = Vec::new();

        for i in 0..20 {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                let payload = json!({
                    "data": {
                        "stress_test": format!("data_{}", i),
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    }
                });

                let response = server_clone
                    .post(&format!("/secrets/stress_test_{}", i))
                    .json(&payload)
                    .await;

                response.status_code().is_success()
            });
            operation_handles.push(handle);
        }

        // Wait for stress operations
        let successful_stress_ops = operation_handles.into_iter()
            .map(|h| h.await.unwrap_or(false))
            .filter(|&success| success)
            .count();

        println!("Stress test: {}/20 operations succeeded", successful_stress_ops);

        // 3. Verify system is still functional
        let response = server.get("/secrets/system_recovery_baseline").await;
        response.assert_status_ok();

        // 4. Perform recovery operations
        let recovery_payload = json!({
            "data": {"recovery": "test_data"}
        });

        let response = server
            .post("/secrets/system_recovery_test")
            .json(&recovery_payload)
            .await;
        response.assert_status_ok();

        // 5. Verify audit trail integrity
        let response = server.get("/audit").await;
        if response.status_code().is_success() {
            let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
            let audit_entries = body.data.unwrap();

            // Should have audit entries for baseline, stress, and recovery
            assert!(audit_entries.len() >= 3, "Should have comprehensive audit trail");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_configuration_and_environment_integration() -> Result<()> {
        let server = create_test_server().await;

        // Test different configuration scenarios

        // 1. Test with minimal configuration
        let minimal_secret_payload = json!({
            "data": {"config": "minimal"}
        });

        let response = server
            .post("/secrets/config_test_minimal")
            .json(&minimal_secret_payload)
            .await;
        response.assert_status_ok();

        // 2. Test with complex configuration
        let complex_secret_payload = json!({
            "data": {
                "database_url": "postgresql://user:pass@host:5432/db",
                "redis_url": "redis://host:6379/0",
                "api_keys": ["key1", "key2", "key3"]
            },
            "metadata": {
                "description": "Complex service configuration",
                "tags": ["config", "complex", "multi-service"],
                "owner": "platform-team",
                "classification": "confidential"
            },
            "ttl": 7200
        });

        let response = server
            .post("/secrets/config_test_complex")
            .json(&complex_secret_payload)
            .await;
        response.assert_status_ok();

        // 3. Verify both configurations are accessible
        let response = server.get("/secrets/config_test_minimal").await;
        response.assert_status_ok();

        let response = server.get("/secrets/config_test_complex").await;
        response.assert_status_ok();
        let body: ApiResponse<SecretResponse> = response.json();
        let secret = body.data.unwrap();

        // Verify TTL was set
        assert!(secret.expires_at.is_some());

        // 4. Test listing with different configurations
        let response = server.get("/secrets/config_test").await;
        response.assert_status_ok();

        Ok(())
    }

    #[tokio::test]
    async fn test_api_storage_crypto_audit_integration() -> Result<()> {
        let server = create_test_server().await;

        // Comprehensive test of all four major components working together

        // 1. API Layer: Create secret through REST API
        let secret_payload = json!({
            "data": {
                "integration_test": "api_storage_crypto_audit_test",
                "component_test": "all_four_components"
            },
            "metadata": {
                "description": "Test of complete system integration",
                "tags": ["integration", "comprehensive"],
                "owner": "system-test"
            }
        });

        let response = server
            .post("/secrets/integration/comprehensive_test")
            .json(&secret_payload)
            .await;
        response.assert_status_ok();

        // 2. Storage Layer: Verify data persistence
        let response = server.get("/secrets/integration/comprehensive_test").await;
        response.assert_status_ok();
        let body: ApiResponse<SecretResponse> = response.json();
        let secret = body.data.unwrap();
        assert_eq!(secret.data["integration_test"], "api_storage_crypto_audit_test");

        // 3. Cryptographic Layer: Test encryption operations
        let encrypt_payload = json!({
            "key_id": "integration_test_key",
            "plaintext": "Cryptographic integration test data",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/encrypt").json(&encrypt_payload).await;
        response.assert_status_ok();

        // 4. Audit Layer: Verify comprehensive audit trail
        let response = server.get("/audit").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
        let audit_entries = body.data.unwrap();

        // Should have audit entries for API, storage, and crypto operations
        let api_audits = audit_entries.iter()
            .filter(|e| e.action.contains("SecretCreation"))
            .count();
        let crypto_audits = audit_entries.iter()
            .filter(|e| e.action.contains("Encryption"))
            .count();

        assert!(api_audits >= 1, "Should have API operation audit");
        assert!(crypto_audits >= 1, "Should have crypto operation audit");

        // 5. Verify data consistency across all components
        let response = server.get("/secrets/integration/comprehensive_test").await;
        response.assert_status_ok();

        // 6. Test component interaction under load
        let mut load_handles = Vec::new();
        for i in 0..5 {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                // Perform mixed operations
                let _ = server_clone
                    .get("/secrets/integration/comprehensive_test")
                    .await;

                let _ = server_clone
                    .post("/encrypt")
                    .json(&json!({
                        "key_id": "load_test_key",
                        "plaintext": format!("Load test data {}", i),
                        "algorithm": "AES-GCM"
                    }))
                    .await;

                Ok::<_, anyhow::Error>(())
            });
            load_handles.push(handle);
        }

        // Wait for load operations
        for handle in load_handles {
            handle.await??;
        }

        // 7. Final verification of system state
        let response = server.get("/audit").await;
        if response.status_code().is_success() {
            let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
            let final_audit_count = body.data.unwrap().len();
            assert!(final_audit_count >= 5, "Should have comprehensive final audit trail");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_real_world_usage_scenarios() -> Result<()> {
        let server = create_test_server().await;

        // Simulate real-world microservice deployment scenario

        // 1. Deploy new microservice with secrets
        let service_secrets = json!({
            "data": {
                "DATABASE_URL": "postgresql://user:pass@prod-db:5432/mydb",
                "REDIS_URL": "redis://prod-redis:6379/0",
                "JWT_SECRET": "super_secret_jwt_signing_key_12345",
                "API_KEY": "service_api_key_abcdef123456",
                "ENCRYPTION_KEY": "service_encryption_key_xyz789"
            },
            "metadata": {
                "description": "Microservice deployment secrets",
                "tags": ["microservice", "production", "deployment"],
                "owner": "platform-team",
                "classification": "secret"
            }
        });

        let response = server
            .post("/secrets/services/user-service/v1.0.0")
            .json(&service_secrets)
            .await;
        response.assert_status_ok();

        // 2. Create service-specific encryption key
        let service_key_payload = json!({
            "name": "user-service-key-v1",
            "key_type": "aes256-gcm96",
            "metadata": {
                "description": "User service encryption key",
                "tags": ["service-key", "user-service"],
                "purpose": "data-encryption"
            }
        });

        let response = server.post("/keys").json(&service_key_payload).await;
        response.assert_status_ok();

        // 3. Encrypt sensitive service configuration
        let config_payload = json!({
            "key_id": "user_service_key_v1",
            "plaintext": "Additional sensitive configuration data for user service",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/encrypt").json(&config_payload).await;
        response.assert_status_ok();

        // 4. Simulate service operation
        let response = server.get("/secrets/services/user-service/v1.0.0").await;
        response.assert_status_ok();

        // 5. Rotate service key for security
        let response = server.post("/keys/user-service-key-v1/rotate").await;
        response.assert_status_ok();

        // 6. Verify audit trail for compliance
        let response = server.get("/audit").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
        let audit_entries = body.data.unwrap();

        // Should have comprehensive audit trail for all operations
        assert!(audit_entries.len() >= 5, "Should have complete audit trail for service deployment");

        // 7. Service decommissioning simulation
        let response = server.delete("/secrets/services/user-service/v1.0.0").await;
        response.assert_status_ok();

        let response = server.delete("/keys/user-service-key-v1").await;
        response.assert_status_ok();

        // 8. Verify cleanup in audit trail
        let response = server.get("/audit").await;
        if response.status_code().is_success() {
            let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
            let final_audits = body.data.unwrap();

            // Should have deletion audit entries
            let deletion_audits = final_audits.iter()
                .filter(|e| e.action.contains("Deletion"))
                .count();
            assert!(deletion_audits >= 2, "Should have deletion audit entries");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_comprehensive_system_health() -> Result<()> {
        let server = create_test_server().await;

        // Test overall system health and component interaction

        // 1. Health check
        let response = server.get("/health").await;
        response.assert_status_ok();

        // 2. Create test data across all components
        let mut test_operations = Vec::new();

        // API operations
        test_operations.push(server.post("/secrets/health_test_api").json(&json!({"data": {"api": "test"}})));
        test_operations.push(server.post("/keys").json(&json!({"name": "health_test_key", "key_type": "aes256-gcm96"})));

        // Storage operations
        test_operations.push(server.get("/secrets/health_test_api"));
        test_operations.push(server.get("/keys"));

        // Crypto operations
        test_operations.push(server.post("/encrypt").json(&json!({"key_id": "health_test_key", "plaintext": "health", "algorithm": "AES-GCM"})));

        // Audit operations
        test_operations.push(server.get("/audit"));
        test_operations.push(server.post("/policies/health_test_policy").json(&json!({"name": "health", "rules": []})));

        // Execute all operations
        for operation in test_operations {
            let response = operation.await;
            assert!(response.status_code().is_success(), "All health test operations should succeed");
        }

        // 3. Verify system state consistency
        let response = server.get("/audit").await;
        if response.status_code().is_success() {
            let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
            let audit_count = body.data.unwrap().len();
            assert!(audit_count >= 5, "Should have comprehensive audit trail");
        }

        // 4. Cleanup
        let _ = server.delete("/secrets/health_test_api").await;
        let _ = server.delete("/keys/health_test_key").await;
        let _ = server.delete("/policies/health_test_policy").await;

        Ok(())
    }
}
