use secreton_api::config::AuthConfig;
use secreton_api::services::auth::AuthenticationService;
use secreton_api::services::crypto::CryptoService;
use secreton_storage::MockStorageBackend;
use std::sync::Arc;

#[tokio::test]
async fn test_verify_password_integration() {
    let storage = Arc::new(MockStorageBackend::new());
    let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
    let config = AuthConfig::default();

    let auth_service = AuthenticationService::new(storage, crypto, &config)
        .await
        .expect("Failed to create auth service");

    // Verify password should return false for non-existent user
    let result = auth_service
        .verify_password("any_user", "any_password")
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false, "Should return false for non-existent user/invalid credentials");
}
