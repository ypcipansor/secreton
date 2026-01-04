//! Comprehensive API crate tests
//!
//! Tests for HTTP API handlers, middleware, services, and integration
//! using axum-test for realistic API interaction.

use secreton_api::{
    config::ApiConfig,
    services::ApiServiceContainer,
    handlers,
};
use secreton_api::services::admin::UserInfo;
use secreton_storage::{StorageBackend, SecretEntry, EncryptionMetadata, SecurityLevel};
use axum_test::TestServer;
use serde_json::json;
use axum::http::StatusCode;
use std::sync::Arc;

/// Helper to create a TestServer with seeded data
async fn create_test_server() -> TestServer {
    let config = ApiConfig::default();
    let shared_config = secreton_config::ApiConfig::default();
    
    // Create service container
    let services = Arc::new(
        ApiServiceContainer::new(&config)
        .await
        .expect("Failed to initialize service container")
    );
    
    // Seed a test user
    let user_id = uuid::Uuid::new_v4();
    let user = UserInfo {
        id: user_id.to_string(),
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        full_name: Some("Test User".to_string()),
        enabled: true,
        roles: vec!["user".to_string(), "admin".to_string()],
        permissions: vec![],
        last_login: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        metadata: Default::default(),
    };

    // Store user info
    let entry = SecretEntry::new(
        format!("users/{}", user.username), 
        serde_json::to_vec(&user).unwrap(),
        EncryptionMetadata::default(),
        SecurityLevel::Secret,
        user_id,
    );
    
    // Access storage directly from services
    services.storage.store(&entry).await.expect("Failed to seed user");
    
    // Create the router using the handlers module which includes all operational routes
    // Pass the shared_config which is secreton_config::ApiConfig
    let app = handlers::create_router(&shared_config, services);
    
    // Initialize TestServer
    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn test_health_check_flow() {
    let server = create_test_server().await;
    
    // Health check is at /api/v1/health (nested under /api/v1)
    let response = server.get("/api/v1/health").await;
    response.assert_status_ok();
    
    let text = response.text();
    // Assuming health check returns "healthy" or "ready" status in JSON
    // Note: The health handler returns ApiResult<Json<HealthStatus>>
    // The HealthStatus struct has a "status" field which is "healthy".
    assert!(text.contains("healthy") || text.contains("ready"));
}

#[tokio::test]
async fn test_auth_login_fails_wrong_creds() {
    let server = create_test_server().await;
    
    // Auth routes are nested under /api/v1/auth
    let response = server.post("/api/v1/auth/login")
        .json(&json!({
            "username": "nonexistent",
            "password": "password"
        }))
        .await;
        
    assert_ne!(response.status_code(), 200); 
}

#[tokio::test]
async fn test_protected_secret_endpoint_needs_auth() {
    let server = create_test_server().await;
    
    // Secret routes are nested under /api/v1/secret
    let response = server.post("/api/v1/secret/keys")
        .json(&json!({
            "name": "test-key",
            "key_type": "rsa-2048",
            "algorithm": "RSA-2048",
            "usage": ["encrypt", "decrypt"]
        }))
        .await;
        
    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_users_needs_auth() {
    let server = create_test_server().await;
    
    // Admin routes are nested under /api/v1/admin
    let response = server.get("/api/v1/admin/users").await;
    
    response.assert_status(StatusCode::UNAUTHORIZED);
}
