use brankas_adhyaksa::{
    auth::mfa::{
        MfaManager, MfaManagerConfig, MfaMethod, MfaError, MfaStatus,
        RateLimitConfig, RecoveryCodeSettings, MfaSetupInfo,
    },
    storage::StorageError,
};
use chrono::{DateTime, Utc};
use std::{collections::HashMap, sync::Arc, time::Duration};

mod mocks;
use mocks::mfa_storage::{MockMfaStorage, InMemoryMfaStorage};

// Helper function to create a test MFA manager with in-memory storage
fn create_test_manager() -> MfaManager {
    let storage = Arc::new(InMemoryMfaStorage::default());
    
    let config = MfaManagerConfig {
        rate_limit: RateLimitConfig {
            max_attempts: 5,
            window: Duration::from_secs(300),
            use_exponential_backoff: true,
            base_backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(3600),
        },
        recovery_codes: RecoveryCodeSettings {
            count: 10,
            length: 16,
            group_size: 4,
            charset: "0123456789ABCDEF".to_string(),
            lifetime_days: 90,
        },
        totp_issuer: "Test Issuer".to_string(),
    };
    
    MfaManager::with_config(storage, config)
}

#[test]
fn test_minimal() {
    println!("Minimal test ran");
    assert!(true);
}

#[tokio::test]
async fn test_totp_setup_and_verification() {
    let manager = create_test_manager();
    
    // Test TOTP setup
    let setup_result = manager.setup_totp("user1", "Test Issuer").await;
    assert!(setup_result.is_ok(), "TOTP setup should succeed");
    
    // Get the status to verify MFA is enabled
    let status = manager.get_mfa_status("user1").await.expect("Failed to get MFA status");
    assert!(status.contains_key(&MfaMethod::Totp), "MFA should be enabled after setup");
    
    // Test verification with correct code (mock the verification for testing)
    let result = manager.verify_totp("user1", "123456").await;
    match result {
        Ok(true) => (), // Expected case - verification succeeded
        _ => panic!("Verification with correct code should return Ok(true)"),
    }
    
    // Test verification with incorrect code
    let result = manager.verify_totp("user1", "wrong").await;
    match result {
        Ok(false) => (), // Expected case - verification failed
        _ => panic!("Verification with wrong code should return Ok(false)"),
    }
}

#[tokio::test]
async fn test_recovery_codes() {
    let manager = create_test_manager();
    
    // Set up TOTP to generate recovery codes
    let setup_result = manager.setup_totp("user1", "Test Issuer").await;
    assert!(setup_result.is_ok(), "TOTP setup should succeed: {:?}", setup_result);
    let setup_info = setup_result.expect("TOTP setup failed unexpectedly");
    assert!(!setup_info.recovery_codes.is_empty(), "Recovery codes should be generated");

    // Use one of the generated recovery codes for a valid test
    let valid_code = setup_info.recovery_codes[0].clone();
    let result = manager.verify_recovery_code("user1", &valid_code).await;
    match result {
        Ok(true) => (), // Expected case - verification succeeded
        _ => panic!("Verification with valid recovery code should return Ok(true)"),
    }

    // The same code should not work again (one-time use)
    let result = manager.verify_recovery_code("user1", &valid_code).await;
    match result {
        Ok(false) => (), // Expected case - code already used
        _ => panic!("Used recovery code should not work again"),
    }

    // Test with an obviously invalid code
    let result = manager.verify_recovery_code("user1", "INVALID-CODE").await;
    match result {
        Ok(false) => (),
        _ => panic!("Verification with invalid recovery code should return Ok(false)"),
    }
}

#[tokio::test]
async fn test_rate_limiting() {
    let manager = create_test_manager();

    // Set up TOTP first
    let setup_result = manager.setup_totp("user1", "Test Issuer").await;
    assert!(setup_result.is_ok(), "TOTP setup should succeed");

    // First 5 attempts should fail but not be rate limited
    for _ in 0..5 {
        let result = manager.verify_totp("user1", "wrong").await;
        match result {
            Ok(false) => (), // Expected for wrong code
            _ => panic!("Verification should fail with wrong code"),
        }
    }

    // 6th attempt should be rate limited
    let result = manager.verify_totp("user1", "123456").await;
    match result {
        Err(MfaError::RateLimitExceeded(_)) => (),
        _ => panic!("Should be rate limited after 5 failed attempts"),
    }
}

#[tokio::test]
async fn test_disable_mfa() {
    let manager = create_test_manager();

    // Set up MFA first
    let setup_result = manager.setup_totp("user1", "Test Issuer").await;
    assert!(setup_result.is_ok(), "TOTP setup should succeed");

    // Disable MFA
    let disable_result = manager.disable_mfa("user1").await;
    assert!(disable_result.is_ok(), "Disabling MFA should succeed");

    // Verify TOTP no longer works after disabling
    let result = manager.verify_totp("user1", "123456").await;
    match result {
        Ok(false) => (), // Expected when MFA is disabled
        _ => panic!("TOTP verification should fail after MFA is disabled"),
    }
}

#[tokio::test]
async fn test_mfa_status() {
    let manager = create_test_manager();

    // Initial status should be disabled
    let status = manager.get_mfa_status("user1").await.expect("Failed to get MFA status");
    assert!(!status.contains_key(&MfaMethod::Totp), "MFA should be disabled initially");

    // After TOTP setup, status should be enabled
    let setup_result = manager.setup_totp("user1", "Test Issuer").await;
    assert!(setup_result.is_ok(), "TOTP setup should succeed");
    let status = manager.get_mfa_status("user1").await.expect("Failed to get MFA status");
    assert!(status.get(&MfaMethod::Totp) == Some(&true), "MFA should be enabled after setup");

    // Test verification with wrong code
    let result = manager.verify_totp("user1", "wrong").await;
    match result {
        Ok(false) => (), // Expected for wrong code
        _ => panic!("Verification should fail with wrong code"),
    }
}
