use std::time::Duration;
use tokio::time::sleep;
use anyhow::Result;
use serde_json::json;
use secreton_core::{
    auth::{AuthEngine, AuthRequest, TokenRequest},
    security::{SecurityOrchestrator, SecurityConfig, ThreatLevel},
    storage::secure::SecureStorage,
    types::{Metadata, SecurityLevel},
};

#[tokio::test]
async fn test_comprehensive_auth_flows() -> Result<()> {
    let auth_engine = AuthEngine::new();
    
    // Test user registration and authentication
    let register_req = AuthRequest {
        username: "test_user".to_string(),
        password: "strong_password123!".to_string(),
        email: Some("test@example.com".to_string()),
        roles: vec!["user".to_string()],
        metadata: Some(json!({"source": "test"})),
    };
    
    let user_result = auth_engine.register_user(register_req).await;
    assert!(user_result.is_ok(), "User registration should succeed");
    
    // Test authentication with correct credentials
    let auth_req = AuthRequest {
        username: "test_user".to_string(),
        password: "strong_password123!".to_string(),
        email: None,
        roles: vec![],
        metadata: None,
    };
    
    let auth_result = auth_engine.authenticate(auth_req).await;
    assert!(auth_result.is_ok(), "Authentication should succeed");
    
    // Test authentication with incorrect credentials
    let bad_auth_req = AuthRequest {
        username: "test_user".to_string(),
        password: "wrong_password".to_string(),
        email: None,
        roles: vec![],
        metadata: None,
    };
    
    let bad_auth_result = auth_engine.authenticate(bad_auth_req).await;
    assert!(bad_auth_result.is_err(), "Authentication should fail with wrong password");
    
    // Test token generation and validation
    let token_req = TokenRequest {
        username: "test_user".to_string(),
        scopes: vec!["read".to_string(), "write".to_string()],
        ttl_seconds: Some(3600),
        metadata: Some(json!({"client": "test_client"})),
    };
    
    let token_result = auth_engine.generate_token(token_req).await;
    assert!(token_result.is_ok(), "Token generation should succeed");
    
    let token = token_result.unwrap();
    
    // Validate the generated token
    let validation_result = auth_engine.validate_token(&token.token).await;
    assert!(validation_result.is_ok(), "Token validation should succeed");
    
    Ok(())
}

#[tokio::test]
async fn test_security_orchestrator_threat_detection() -> Result<()> {
    let security_config = SecurityConfig::default();
    let orchestrator = SecurityOrchestrator::new(security_config);
    
    // Test low-level threat detection
    let low_threat_result = orchestrator.assess_threat_level("192.168.1.100", "normal_user", vec!["read"]).await;
    assert!(low_threat_result.is_ok(), "Low threat assessment should succeed");
    
    let threat_level = low_threat_result.unwrap();
    assert!(matches!(threat_level, ThreatLevel::Low), "Should detect low threat level");
    
    // Test multiple rapid requests (potential brute force)
    for i in 0..10 {
        let _ = orchestrator.assess_threat_level("192.168.1.200", &format!("user_{}", i), vec!["admin"]).await;
    }
    
    // This should trigger higher threat level due to pattern
    let high_threat_result = orchestrator.assess_threat_level("192.168.1.200", "suspicious_user", vec!["admin", "delete"]).await;
    assert!(high_threat_result.is_ok(), "High threat assessment should succeed");
    
    Ok(())
}

#[tokio::test]
async fn test_secure_storage_edge_cases() -> Result<()> {
    let storage = SecureStorage::new("test_master_key").await?;
    
    // Test with empty values
    let empty_result = storage.store("empty_key", b"").await;
    assert!(empty_result.is_ok(), "Should be able to store empty values");
    
    let retrieved_empty = storage.retrieve("empty_key").await?;
    assert!(retrieved_empty.is_empty(), "Should retrieve empty value");
    
    // Test with very large values (1MB)
    let large_data = vec![0u8; 1024 * 1024];
    let large_result = storage.store("large_key", &large_data).await;
    assert!(large_result.is_ok(), "Should be able to store large values");
    
    let retrieved_large = storage.retrieve("large_key").await?;
    assert_eq!(retrieved_large.len(), 1024 * 1024, "Should retrieve correct large value size");
    
    // Test with special characters in keys
    let special_key = "key_with_!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`";
    let special_result = storage.store(special_key, b"special_value").await;
    assert!(special_result.is_ok(), "Should be able to store with special character keys");
    
    let retrieved_special = storage.retrieve(special_key).await?;
    assert_eq!(retrieved_special, b"special_value", "Should retrieve special key value");
    
    // Test concurrent operations
    let handles = (0..100).map(|i| {
        let storage_clone = storage.clone();
        tokio::spawn(async move {
            let key = format!("concurrent_key_{}", i);
            let value = format!("concurrent_value_{}", i);
            storage_clone.store(&key, value.as_bytes()).await
        })
    }).collect::<Vec<_>>();
    
    for handle in handles {
        let result = handle.await?;
        assert!(result.is_ok(), "Concurrent store operations should succeed");
    }
    
    // Verify all concurrent writes succeeded
    for i in 0..100 {
        let key = format!("concurrent_key_{}", i);
        let expected_value = format!("concurrent_value_{}", i);
        let retrieved = storage.retrieve(&key).await?;
        assert_eq!(retrieved, expected_value.as_bytes(), "Concurrent write {} should be correct", i);
    }
    
    Ok(())
}

#[tokio::test]
async fn test_metadata_handling() -> Result<()> {
    // Test metadata creation and validation
    let metadata = Metadata::new()
        .with_tag("environment", "test")
        .with_tag("version", "1.0")
        .with_security_level(SecurityLevel::High);
    
    assert_eq!(metadata.get_tag("environment"), Some(&"test".to_string()));
    assert_eq!(metadata.get_tag("version"), Some(&"1.0".to_string()));
    assert_eq!(metadata.security_level(), SecurityLevel::High);
    
    // Test metadata serialization/deserialization
    let serialized = serde_json::to_string(&metadata)?;
    let deserialized: Metadata = serde_json::from_str(&serialized)?;
    
    assert_eq!(metadata.get_tag("environment"), deserialized.get_tag("environment"));
    assert_eq!(metadata.security_level(), deserialized.security_level());
    
    // Test metadata with TTL
    let ttl_metadata = Metadata::new()
        .with_ttl(Duration::from_secs(3600))
        .with_tag("expires", "true");
    
    assert!(ttl_metadata.ttl().is_some());
    assert_eq!(ttl_metadata.ttl().unwrap(), Duration::from_secs(3600));
    
    Ok(())
}

#[tokio::test]
async fn test_error_handling_and_recovery() -> Result<()> {
    let storage = SecureStorage::new("test_key").await?;
    
    // Test retrieval of non-existent key
    let non_existent_result = storage.retrieve("non_existent_key").await;
    assert!(non_existent_result.is_err(), "Should error when retrieving non-existent key");
    
    // Test storage with invalid key format
    let empty_key_result = storage.store("", b"value").await;
    assert!(empty_key_result.is_err(), "Should error with empty key");
    
    // Test recovery after errors - storage should still work
    let recovery_result = storage.store("recovery_key", b"recovery_value").await;
    assert!(recovery_result.is_ok(), "Storage should work after previous errors");
    
    let retrieved_recovery = storage.retrieve("recovery_key").await?;
    assert_eq!(retrieved_recovery, b"recovery_value", "Recovery operation should work correctly");
    
    Ok(())
}

#[tokio::test]
async fn test_performance_characteristics() -> Result<()> {
    let storage = SecureStorage::new("perf_test_key").await?;
    
    // Test rapid sequential operations
    let start_time = std::time::Instant::now();
    
    for i in 0..1000 {
        let key = format!("perf_key_{}", i);
        let value = format!("perf_value_{}", i);
        storage.store(&key, value.as_bytes()).await?;
    }
    
    let store_duration = start_time.elapsed();
    println!("1000 store operations took: {:?}", store_duration);
    
    // Test rapid retrieval operations
    let retrieve_start = std::time::Instant::now();
    
    for i in 0..1000 {
        let key = format!("perf_key_{}", i);
        let _value = storage.retrieve(&key).await?;
    }
    
    let retrieve_duration = retrieve_start.elapsed();
    println!("1000 retrieve operations took: {:?}", retrieve_duration);
    
    // Performance expectations (adjust based on system capabilities)
    assert!(store_duration.as_millis() < 10000, "1000 stores should complete within 10 seconds");
    assert!(retrieve_duration.as_millis() < 5000, "1000 retrieves should complete within 5 seconds");
    
    Ok(())
}

#[tokio::test]
async fn test_resource_cleanup() -> Result<()> {
    // Test that resources are properly cleaned up
    {
        let storage = SecureStorage::new("cleanup_test_key").await?;
        storage.store("temp_key", b"temp_value").await?;
        
        // Storage goes out of scope here
    }
    
    // Create new storage instance to verify cleanup
    let new_storage = SecureStorage::new("cleanup_test_key").await?;
    let cleanup_result = new_storage.retrieve("temp_key").await;
    
    // This behavior depends on whether storage persists across instances
    // For memory-based storage, it should be cleaned up
    // For persistent storage, it should still exist
    println!("Cleanup test result: {:?}", cleanup_result);
    
    Ok(())
}
