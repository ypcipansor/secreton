//! Unit tests for Brankas Enterprise Vault core components

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Mock MFA system for testing
#[derive(Debug)]
struct MockMfaSystem {
    users: Arc<Mutex<HashMap<String, UserMfaState>>>,
}

#[derive(Debug, Clone)]
struct UserMfaState {
    secret: String,
    backup_codes: Vec<String>,
    failed_attempts: u32,
    last_failed_attempt: Option<SystemTime>,
    is_locked: bool,
}

#[derive(Debug, Clone)]
struct TotpConfig {
    secret: String,
    issuer: String,
    account_name: String,
}

impl MockMfaSystem {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    fn setup_mfa(&self, user_id: &str, secret: &str) -> Result<TotpConfig, Box<dyn std::error::Error>> {
        let mut users = self.users.lock().unwrap();
        
        let backup_codes: Vec<String> = (0..10)
            .map(|i| format!("BACKUP-{:08}", i))
            .collect();
        
        let user_state = UserMfaState {
            secret: secret.to_string(),
            backup_codes,
            failed_attempts: 0,
            last_failed_attempt: None,
            is_locked: false,
        };
        
        users.insert(user_id.to_string(), user_state);
        
        Ok(TotpConfig {
            secret: secret.to_string(),
            issuer: "Brankas Enterprise".to_string(),
            account_name: user_id.to_string(),
        })
    }
    
    fn verify_totp(&self, user_id: &str, code: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut users = self.users.lock().unwrap();
        let user_state = users.get_mut(user_id)
            .ok_or("User not found")?;
        
        if user_state.is_locked {
            return Err("Account is locked due to too many failed attempts".into());
        }
        
        // Mock TOTP verification - in real implementation would use TOTP algorithm
        let is_valid = code == "123456" || code == "654321"; // Mock valid codes
        
        if is_valid {
            user_state.failed_attempts = 0;
            user_state.last_failed_attempt = None;
            Ok(true)
        } else {
            user_state.failed_attempts += 1;
            user_state.last_failed_attempt = Some(SystemTime::now());
            
            if user_state.failed_attempts >= 5 {
                user_state.is_locked = true;
                return Err("Account locked due to too many failed attempts".into());
            }
            
            Ok(false)
        }
    }
    
    fn verify_backup_code(&self, user_id: &str, code: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut users = self.users.lock().unwrap();
        let user_state = users.get_mut(user_id)
            .ok_or("User not found")?;
        
        if let Some(index) = user_state.backup_codes.iter().position(|c| c == code) {
            user_state.backup_codes.remove(index);
            user_state.failed_attempts = 0;
            user_state.last_failed_attempt = None;
            user_state.is_locked = false;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    fn get_remaining_backup_codes(&self, user_id: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let users = self.users.lock().unwrap();
        let user_state = users.get(user_id)
            .ok_or("User not found")?;
        Ok(user_state.backup_codes.len())
    }
    
    fn reset_failed_attempts(&self, user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut users = self.users.lock().unwrap();
        let user_state = users.get_mut(user_id)
            .ok_or("User not found")?;
        
        user_state.failed_attempts = 0;
        user_state.last_failed_attempt = None;
        user_state.is_locked = false;
        
        Ok(())
    }
}

#[test]
fn test_mfa_setup() -> Result<(), Box<dyn std::error::Error>> {
    let mfa_system = MockMfaSystem::new();
    let user_id = "test_user";
    let secret = "JBSWY3DPEHPK3PXP";
    
    let config = mfa_system.setup_mfa(user_id, secret)?;
    
    assert_eq!(config.secret, secret);
    assert_eq!(config.issuer, "Brankas Enterprise");
    assert_eq!(config.account_name, user_id);
    
    // Verify user state was created
    let users = mfa_system.users.lock().unwrap();
    let user_state = users.get(user_id).expect("User should exist");
    assert_eq!(user_state.secret, secret);
    assert_eq!(user_state.backup_codes.len(), 10);
    assert_eq!(user_state.failed_attempts, 0);
    assert!(!user_state.is_locked);
    
    Ok(())
}

#[test]
fn test_totp_verification() -> Result<(), Box<dyn std::error::Error>> {
    let mfa_system = MockMfaSystem::new();
    let user_id = "test_user";
    
    mfa_system.setup_mfa(user_id, "JBSWY3DPEHPK3PXP")?;
    
    // Test valid code
    assert!(mfa_system.verify_totp(user_id, "123456")?);
    assert!(mfa_system.verify_totp(user_id, "654321")?);
    
    // Test invalid code
    assert!(!mfa_system.verify_totp(user_id, "000000")?);
    
    Ok(())
}

#[test]
fn test_backup_code_verification() -> Result<(), Box<dyn std::error::Error>> {
    let mfa_system = MockMfaSystem::new();
    let user_id = "test_user";
    
    mfa_system.setup_mfa(user_id, "JBSWY3DPEHPK3PXP")?;
    
    // Test valid backup code
    assert!(mfa_system.verify_backup_code(user_id, "BACKUP-00000000")?);
    
    // Code should be consumed
    assert!(!mfa_system.verify_backup_code(user_id, "BACKUP-00000000")?);
    
    // Test remaining codes
    assert_eq!(mfa_system.get_remaining_backup_codes(user_id)?, 9);
    
    Ok(())
}

#[test]
fn test_rate_limiting() -> Result<(), Box<dyn std::error::Error>> {
    let mfa_system = MockMfaSystem::new();
    let user_id = "test_user";
    
    mfa_system.setup_mfa(user_id, "JBSWY3DPEHPK3PXP")?;
    
    // Test failed attempts
    for i in 1..5 {
        let result = mfa_system.verify_totp(user_id, "wrong_code");
        assert!(result.is_ok());
        assert!(!result.unwrap());
        
        let users = mfa_system.users.lock().unwrap();
        let user_state = users.get(user_id).unwrap();
        assert_eq!(user_state.failed_attempts, i);
    }
    
    // 5th failed attempt should lock the account
    let result = mfa_system.verify_totp(user_id, "wrong_code");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("locked"));
    
    Ok(())
}

#[test]
fn test_account_unlock_with_backup_code() -> Result<(), Box<dyn std::error::Error>> {
    let mfa_system = MockMfaSystem::new();
    let user_id = "test_user";
    
    mfa_system.setup_mfa(user_id, "JBSWY3DPEHPK3PXP")?;
    
    // Lock account with failed attempts
    for _ in 0..5 {
        let _ = mfa_system.verify_totp(user_id, "wrong_code");
    }
    
    // Verify account is locked
    let result = mfa_system.verify_totp(user_id, "123456");
    assert!(result.is_err());
    
    // Unlock with backup code
    assert!(mfa_system.verify_backup_code(user_id, "BACKUP-00000000")?);
    
    // Account should be unlocked now
    assert!(mfa_system.verify_totp(user_id, "123456")?);
    
    Ok(())
}

#[test]
fn test_concurrent_mfa_operations() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::thread;
    
    let mfa_system = Arc::new(MockMfaSystem::new());
    let user_id = "concurrent_test_user";
    
    mfa_system.setup_mfa(user_id, "JBSWY3DPEHPK3PXP")?;
    
    let mut handles = vec![];
    
    // Test concurrent TOTP verifications
    for i in 0..10 {
        let mfa_clone = Arc::clone(&mfa_system);
        let user_id = user_id.to_string();
        
        let handle = thread::spawn(move || {
            let code = if i % 2 == 0 { "123456" } else { "654321" };
            mfa_clone.verify_totp(&user_id, code)
        });
        
        handles.push(handle);
    }
    
    // Collect results
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    Ok(())
}

#[test]
fn test_mfa_error_cases() -> Result<(), Box<dyn std::error::Error>> {
    let mfa_system = MockMfaSystem::new();
    
    // Test operations on non-existent user
    let result = mfa_system.verify_totp("non_existent", "123456");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
    
    let result = mfa_system.verify_backup_code("non_existent", "BACKUP-00000000");
    assert!(result.is_err());
    
    let result = mfa_system.get_remaining_backup_codes("non_existent");
    assert!(result.is_err());
    
    Ok(())
}
