//! Comprehensive integration tests for Secret API handlers
//!
//! Tests all secret operations including secret management, key operations,
//! encryption/decryption, and policy enforcement with real-world scenarios.

use axum::http::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

use crate::handlers::secret::*;
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
mod secret_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_secret_lifecycle() {
        let server = create_test_server().await;

        // 1. Create a secret
        let create_payload = json!({
            "data": {
                "api_key": "secret-api-key-12345",
                "database_url": "postgresql://user:pass@localhost/db"
            },
            "metadata": {
                "description": "Production API credentials",
                "tags": ["api", "production"],
                "owner": "platform-team",
                "classification": "secret"
            },
            "ttl": 3600
        });

        let response = server
            .post("/secrets/production/api-keys")
            .json(&create_payload)
            .await;

        response.assert_status_ok();
        let body: ApiResponse<SecretResponse> = response.json();
        assert!(body.success);
        let secret = body.data.expect("secret response");
        assert_eq!(secret.path, "production/api-keys");
        assert!(secret.expires_at.is_some());

        // 2. Read the secret back
        let response = server.get("/secrets/production/api-keys").await;
        response.assert_status_ok();
        let body: ApiResponse<SecretResponse> = response.json();
        assert!(body.success);
        let read_secret = body.data.unwrap();
        assert_eq!(read_secret.data["api_key"], "secret-api-key-12345");

        // 3. Update the secret
        let update_payload = json!({
            "data": {
                "api_key": "updated-secret-api-key-67890",
                "database_url": "postgresql://user:pass@localhost/db"
            },
            "metadata": {
                "description": "Updated production API credentials",
                "tags": ["api", "production", "updated"],
                "owner": "platform-team",
                "classification": "secret"
            }
        });

        let response = server
            .put("/secrets/production/api-keys")
            .json(&update_payload)
            .await;

        response.assert_status_ok();
        let body: ApiResponse<SecretResponse> = response.json();
        assert!(body.success);
        let updated_secret = body.data.unwrap();
        assert_eq!(updated_secret.version, 2);
        assert_eq!(updated_secret.data["api_key"], "updated-secret-api-key-67890");

        // 4. List secrets
        let response = server.get("/secrets").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<SecretListItem>> = response.json();
        assert!(body.success);
        let secrets = body.data.unwrap();
        assert!(!secrets.is_empty());

        // 5. Delete the secret
        let response = server.delete("/secrets/production/api-keys").await;
        response.assert_status_ok();

        // 6. Verify deletion
        let response = server.get("/secrets/production/api-keys").await;
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_key_management_lifecycle() {
        let server = create_test_server().await;

        // 1. Create an encryption key
        let create_key_payload = json!({
            "name": "test-encryption-key",
            "key_type": "aes256-gcm96",
            "algorithm": "AES-GCM",
            "usage": ["encrypt", "decrypt"],
            "metadata": {
                "description": "Test encryption key for CI/CD",
                "tags": ["encryption", "test"],
                "owner": "devops-team",
                "purpose": "data-encryption"
            },
            "exportable": false
        });

        let response = server.post("/keys").json(&create_key_payload).await;
        response.assert_status_ok();
        let body: ApiResponse<KeyResponse> = response.json();
        assert!(body.success);
        let key = body.data.unwrap();
        assert_eq!(key.name, "test-encryption-key");
        assert_eq!(key.key_type, "aes256-gcm96");
        assert_eq!(key.status, "active");
        assert!(key.public_key.is_some());

        let key_id = key.id.clone();

        // 2. Read the key
        let response = server.get(&format!("/keys/{}", key_id)).await;
        response.assert_status_ok();

        // 3. List all keys
        let response = server.get("/keys").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<KeyResponse>> = response.json();
        assert!(body.success);
        let keys = body.data.unwrap();
        assert!(!keys.is_empty());

        // 4. Test encryption with the key
        let encrypt_payload = json!({
            "key_id": key_id,
            "plaintext": "This is sensitive data that needs encryption",
            "algorithm": "AES-GCM"
        });

        let response = server.post("/encrypt").json(&encrypt_payload).await;
        response.assert_status_ok();
        let body: ApiResponse<EncryptResponse> = response.json();
        assert!(body.success);
        let encrypt_response = body.data.unwrap();
        assert!(!encrypt_response.ciphertext.is_empty());

        // 5. Test decryption
        let decrypt_payload = json!({
            "key_id": key_id,
            "ciphertext": encrypt_response.ciphertext,
            "algorithm": "AES-GCM"
        });

        let response = server.post("/decrypt").json(&decrypt_payload).await;
        response.assert_status_ok();
        let body: ApiResponse<DecryptResponse> = response.json();
        assert!(body.success);
        let decrypt_response = body.data.unwrap();
        assert_eq!(decrypt_response.plaintext, "This is sensitive data that needs encryption");

        // 6. Rotate the key
        let response = server.post(&format!("/keys/{}/rotate", key_id)).await;
        response.assert_status_ok();
        let body: ApiResponse<KeyResponse> = response.json();
        assert!(body.success);
        let rotated_key = body.data.unwrap();
        assert_eq!(rotated_key.version, 2);

        // 7. Delete the key
        let response = server.delete(&format!("/keys/{}", key_id)).await;
        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_rbac_policy_enforcement() {
        let server = create_test_server().await;

        // Test unauthorized access to secrets
        let response = server.get("/secrets/restricted/secret").await;
        // Should fail with unauthorized (RBAC check)
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

        // Test unauthorized key creation
        let create_key_payload = json!({
            "name": "unauthorized-key",
            "key_type": "aes256-gcm96"
        });

        let response = server.post("/keys").json(&create_key_payload).await;
        // Should fail due to RBAC policy
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let server = create_test_server().await;

        // Test concurrent secret creation
        let mut handles = Vec::new();

        for i in 0..10 {
            let server_clone = &server;
            let handle = tokio::spawn(async move {
                let payload = json!({
                    "data": {
                        "service": format!("service-{}", i),
                        "key": format!("key-{}", i)
                    }
                });

                server_clone
                    .post(&format!("/secrets/concurrent/service-{}", i))
                    .json(&payload)
                    .await
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            let response = handle.await.unwrap();
            response.assert_status_ok();
        }

        // Verify all secrets were created
        let response = server.get("/secrets/concurrent").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<SecretListItem>> = response.json();
        assert!(body.success);
        let secrets = body.data.unwrap();
        assert_eq!(secrets.len(), 10);
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let server = create_test_server().await;

        // Perform operations that should generate audit logs
        let create_payload = json!({
            "data": {"test": "audit-log-test"}
        });

        let response = server
            .post("/secrets/audit-test/secret")
            .json(&create_payload)
            .await;
        response.assert_status_ok();

        // Check audit logs
        let response = server.get("/audit").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<secreton_core::audit::AuditEntry>> = response.json();
        assert!(body.success);
        let audit_entries = body.data.unwrap();

        // Should have at least one audit entry for the secret creation
        assert!(!audit_entries.is_empty());

        // Check that the audit entry contains expected information
        let secret_creation_entry = audit_entries
            .iter()
            .find(|entry| entry.action.contains("SecretCreation"))
            .expect("Should have secret creation audit entry");

        assert_eq!(secret_creation_entry.source, "api");
        assert!(secret_creation_entry.success);
    }

    #[tokio::test]
    async fn test_backup_and_restore() {
        let server = create_test_server().await;

        // Create some test data
        let create_payload = json!({
            "data": {"backup": "test-data"}
        });

        let response = server
            .post("/secrets/backup-test/data")
            .json(&create_payload)
            .await;
        response.assert_status_ok();

        // Create a backup
        let response = server.post("/backup").await;
        response.assert_status_ok();
        let body: ApiResponse<serde_json::Value> = response.json();
        assert!(body.success);

        // List backups
        let response = server.get("/backup").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<serde_json::Value>> = response.json();
        assert!(body.success);
        let backups = body.data.unwrap();
        assert!(!backups.is_empty());

        // Get specific backup info
        let first_backup = &backups[0];
        let backup_id = first_backup["id"].as_str().unwrap();

        let response = server.get(&format!("/backup/{}", backup_id)).await;
        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_error_handling_edge_cases() {
        let server = create_test_server().await;

        // Test with malformed JSON
        let response = server
            .post("/secrets/test")
            .raw("invalid json")
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

        // Test with missing required fields
        let invalid_payload = json!({
            "data": {}
            // Missing metadata
        });

        let response = server
            .post("/secrets/test")
            .json(&invalid_payload)
            .await;
        // Should handle gracefully
        assert!(response.status_code().is_client_error() || response.status_code().is_server_error());

        // Test with extremely long path
        let long_path = "a".repeat(1000);
        let response = server.get(&format!("/secrets/{}", long_path)).await;
        // Should handle gracefully without crashing
        assert!(response.status_code().is_client_error() || response.status_code().is_server_error());
    }

    #[tokio::test]
    async fn test_rate_limiting_simulation() {
        let server = create_test_server().await;

        // Simulate rapid requests to test rate limiting
        let mut responses = Vec::new();

        for _ in 0..50 {
            let response = server.get("/health").await;
            responses.push(response.status_code());
        }

        // Most requests should succeed, but some might be rate limited
        let success_count = responses.iter().filter(|&&status| status == StatusCode::OK).count();
        let rate_limited_count = responses.iter().filter(|&&status| status == StatusCode::TOO_MANY_REQUESTS).count();

        assert!(success_count > 0, "Should have some successful requests");
        // Note: Actual rate limiting implementation would need to be added
        // This test verifies the endpoint exists and responds
    }

    #[tokio::test]
    async fn test_policy_management() {
        let server = create_test_server().await;

        // Test listing policies
        let response = server.get("/policies").await;
        response.assert_status_ok();
        let body: ApiResponse<Vec<serde_json::Value>> = response.json();
        assert!(body.success);

        // Test creating a policy
        let policy_payload = json!({
            "name": "test-policy",
            "rules": [
                {
                    "path": "test/*",
                    "capabilities": ["read", "list"]
                }
            ],
            "metadata": {
                "description": "Test policy for automated testing",
                "owner": "qa-team"
            }
        });

        let response = server
            .post("/policies/test-policy")
            .json(&policy_payload)
            .await;
        response.assert_status_ok();

        // Test reading the policy
        let response = server.get("/policies/test-policy").await;
        response.assert_status_ok();
        let body: ApiResponse<serde_json::Value> = response.json();
        assert!(body.success);

        // Test updating the policy
        let update_payload = json!({
            "name": "test-policy",
            "rules": [
                {
                    "path": "test/*",
                    "capabilities": ["read", "list", "create"]
                }
            ],
            "metadata": {
                "description": "Updated test policy",
                "owner": "qa-team"
            }
        });

        let response = server
            .put("/policies/test-policy")
            .json(&update_payload)
            .await;
        response.assert_status_ok();

        // Test deleting the policy
        let response = server.delete("/policies/test-policy").await;
        response.assert_status_ok();
    }
}
