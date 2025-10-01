//! Userpass authentication method for Secreton
//!
//! This module provides username/password-based authentication.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;

use super::{AuthEngine, AuthError, AuthConfig, AuthResult, AuthRequest, AuthResponse};
use super::traits::{AuthMethod, AuthProvider};

/// Userpass authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserpassConfig {
    /// Enable userpass authentication
    pub enabled: bool,
    /// Maximum number of login attempts before lockout
    pub max_login_attempts: u32,
    /// Lockout duration in minutes
    pub lockout_duration_minutes: u64,
    /// Password policy configuration
    pub password_policy: Option<UserpassPasswordPolicy>,
    /// Session configuration
    pub session_config: Option<UserpassSessionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserpassPasswordPolicy {
    /// Minimum password length
    pub min_length: usize,
    /// Require uppercase letters
    pub require_uppercase: bool,
    /// Require lowercase letters
    pub require_lowercase: bool,
    /// Require numbers
    pub require_numbers: bool,
    /// Require special characters
    pub require_special_chars: bool,
    /// Password expiration in days
    pub expiration_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserpassSessionConfig {
    /// Session timeout in minutes
    pub timeout_minutes: u64,
    /// Maximum number of concurrent sessions per user
    pub max_sessions_per_user: u32,
    /// Enable session refresh
    pub enable_refresh: bool,
}

/// Userpass authentication engine
pub struct UserpassAuth {
    config: UserpassConfig,
    users: HashMap<String, UserpassUser>,
    failed_attempts: HashMap<String, UserpassFailedAttempts>,
}

/// User data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserpassUser {
    /// Username
    pub username: String,
    /// Password hash (argon2)
    pub password_hash: String,
    /// User policies
    pub policies: Vec<String>,
    /// User groups
    pub groups: Vec<String>,
    /// Account creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last password change
    pub password_changed_at: chrono::DateTime<chrono::Utc>,
    /// Account disabled
    pub disabled: bool,
    /// Password expired
    pub password_expired: bool,
}

/// Failed login attempts tracking
#[derive(Debug, Clone)]
struct UserpassFailedAttempts {
    attempts: u32,
    last_attempt: chrono::DateTime<chrono::Utc>,
    locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl UserpassAuth {
    /// Create a new userpass authentication engine
    pub fn new(config: UserpassConfig) -> Self {
        Self {
            config,
            users: HashMap::new(),
            failed_attempts: HashMap::new(),
        }
    }

    /// Hash a password using Argon2
    fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::InternalError(format!("Password hashing failed: {}", e)))?
            .to_string();

        Ok(password_hash)
    }

    /// Verify a password against a hash
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let argon2 = Argon2::default();

        argon2
            .verify_password(password.as_bytes(), &password_hash::PasswordHash::new(hash)
                .map_err(|e| AuthError::InternalError(format!("Invalid password hash: {}", e)))?)
            .map_err(|_| AuthError::AuthenticationFailed("Invalid password".to_string()))?;

        Ok(true)
    }

    /// Check if user account is locked
    fn is_account_locked(&self, username: &str) -> bool {
        if let Some(attempts) = self.failed_attempts.get(username) {
            if let Some(locked_until) = attempts.locked_until {
                if chrono::Utc::now() < locked_until {
                    return true;
                }
            }
        }
        false
    }

    /// Record failed login attempt
    fn record_failed_attempt(&mut self, username: &str) {
        let now = chrono::Utc::now();
        let attempts = self.failed_attempts.entry(username.to_string()).or_insert(UserpassFailedAttempts {
            attempts: 0,
            last_attempt: now,
            locked_until: None,
        });

        attempts.attempts += 1;
        attempts.last_attempt = now;

        // Lock account if too many failed attempts
        if attempts.attempts >= self.config.max_login_attempts {
            let lockout_duration = chrono::Duration::minutes(self.config.lockout_duration_minutes as i64);
            attempts.locked_until = Some(now + lockout_duration);
            warn!("Account {} locked due to too many failed attempts", username);
        }
    }

    /// Reset failed attempts after successful login
    fn reset_failed_attempts(&mut self, username: &str) {
        self.failed_attempts.remove(username);
    }

    /// Validate password policy
    fn validate_password_policy(&self, password: &str) -> Result<(), AuthError> {
        if let Some(policy) = &self.config.password_policy {
            if password.len() < policy.min_length {
                return Err(AuthError::InvalidCredentials(format!(
                    "Password must be at least {} characters long", policy.min_length
                )));
            }

            if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
                return Err(AuthError::InvalidCredentials(
                    "Password must contain at least one uppercase letter".to_string()
                ));
            }

            if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
                return Err(AuthError::InvalidCredentials(
                    "Password must contain at least one lowercase letter".to_string()
                ));
            }

            if policy.require_numbers && !password.chars().any(|c| c.is_numeric()) {
                return Err(AuthError::InvalidCredentials(
                    "Password must contain at least one number".to_string()
                ));
            }

            if policy.require_special_chars && !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
                return Err(AuthError::InvalidCredentials(
                    "Password must contain at least one special character".to_string()
                ));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl AuthEngine for UserpassAuth {
    async fn authenticate(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        // Parse login request
        let username = request.get_string("username")
            .ok_or_else(|| AuthError::InvalidRequest("username field is required".to_string()))?;
        let password = request.get_string("password")
            .ok_or_else(|| AuthError::InvalidRequest("password field is required".to_string()))?;

        debug!("Userpass authentication attempt for user: {}", username);

        // Check if account is locked
        if self.is_account_locked(&username) {
            return Err(AuthError::AuthenticationFailed("Account is temporarily locked".to_string()));
        }

        // Get user data
        let user = self.users.get(&username)
            .ok_or_else(|| AuthError::AuthenticationFailed("Invalid username or password".to_string()))?;

        if user.disabled {
            return Err(AuthError::AuthenticationFailed("Account is disabled".to_string()));
        }

        if user.password_expired {
            return Err(AuthError::AuthenticationFailed("Password has expired".to_string()));
        }

        // Verify password
        match self.verify_password(&password, &user.password_hash) {
            Ok(true) => {
                // Successful authentication
                debug!("Userpass authentication successful for user: {}", username);

                let response = AuthResponse {
                    authenticated: true,
                    token: Some(format!("userpass_token_{}", username)),
                    policies: user.policies.clone(),
                    metadata: {
                        let mut metadata = HashMap::new();
                        metadata.insert("username".to_string(), username.clone());
                        metadata.insert("auth_method".to_string(), "userpass".to_string());
                        metadata
                    },
                    ttl: Some(3600), // 1 hour default TTL
                };

                Ok(response)
            }
            Ok(false) => {
                // Failed authentication
                self.record_failed_attempt(&username);
                Err(AuthError::AuthenticationFailed("Invalid username or password".to_string()))
            }
            Err(e) => {
                // Error during verification
                error!("Password verification error for user {}: {}", username, e);
                Err(e)
            }
        }
    }

    async fn validate_credentials(&self, username: &str, password: &str) -> Result<bool, AuthError> {
        // Check if account is locked
        if self.is_account_locked(username) {
            return Ok(false);
        }

        // Get user data
        let user = match self.users.get(username) {
            Some(user) => user,
            None => return Ok(false),
        };

        if user.disabled {
            return Ok(false);
        }

        // Verify password
        self.verify_password(password, &user.password_hash).map(|_| true)
    }

    fn name(&self) -> &str {
        "userpass"
    }
}

impl Default for UserpassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_login_attempts: 5,
            lockout_duration_minutes: 15,
            password_policy: Some(UserpassPasswordPolicy::default()),
            session_config: Some(UserpassSessionConfig::default()),
        }
    }
}

impl Default for UserpassPasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: false,
            expiration_days: Some(90),
        }
    }
}

impl Default for UserpassSessionConfig {
    fn default() -> Self {
        Self {
            timeout_minutes: 60,
            max_sessions_per_user: 5,
            enable_refresh: true,
        }
    }
}

/// Userpass authentication method implementation
pub struct UserpassAuthMethod;

impl UserpassAuthMethod {
    /// Create a new userpass authentication method
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AuthMethod for UserpassAuthMethod {
    async fn authenticate(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        let config = UserpassConfig::default();
        let auth_engine = UserpassAuth::new(config);
        auth_engine.authenticate(request).await
    }

    fn name(&self) -> &str {
        "userpass"
    }

    fn supported_request_types(&self) -> Vec<&str> {
        vec!["login", "verify"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthRequest, AuthResponse};
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn test_userpass_config_default() {
        let config = UserpassConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_login_attempts, 5);
        assert_eq!(config.lockout_duration_minutes, 15);
        assert!(config.password_policy.is_some());
        assert!(config.session_config.is_some());
    }

    #[test]
    fn test_password_policy_validation() {
        let config = UserpassConfig::default();
        let auth = UserpassAuth::new(config);

        // Test valid password
        assert!(auth.validate_password_policy("MySecure123!").is_ok());

        // Test password too short
        assert!(auth.validate_password_policy("123").is_err());

        // Test missing uppercase
        assert!(auth.validate_password_policy("mysecure123!").is_err());

        // Test missing lowercase
        assert!(auth.validate_password_policy("MYSECURE123!").is_err());

        // Test missing numbers
        assert!(auth.validate_password_policy("MySecure!").is_err());
    }

    #[test]
    fn test_password_hashing() {
        let config = UserpassConfig::default();
        let auth = UserpassAuth::new(config);

        let password = "MySecurePassword123!";
        let hash = auth.hash_password(password).unwrap();

        // Hash should be different from original password
        assert_ne!(hash, password);

        // Hash should contain argon2 identifier
        assert!(hash.contains("$argon2"));
    }

    #[test]
    fn test_password_verification() {
        let config = UserpassConfig::default();
        let auth = UserpassAuth::new(config);

        let password = "MySecurePassword123!";
        let hash = auth.hash_password(password).unwrap();

        // Correct password should verify
        assert!(auth.verify_password(password, &hash).unwrap());

        // Wrong password should fail
        assert!(!auth.verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_account_lockout() {
        let config = UserpassConfig {
            enabled: true,
            max_login_attempts: 2,
            lockout_duration_minutes: 1,
            ..Default::default()
        };
        let mut auth = UserpassAuth::new(config);

        // Add a test user
        let mut user = UserpassUser {
            username: "testuser".to_string(),
            password_hash: auth.hash_password("password123").unwrap(),
            policies: vec!["default".to_string()],
            groups: vec!["users".to_string()],
            created_at: Utc::now(),
            password_changed_at: Utc::now(),
            disabled: false,
            password_expired: false,
        };
        auth.users.insert("testuser".to_string(), user);

        // First failed attempt
        auth.record_failed_attempt("testuser");
        assert!(!auth.is_account_locked("testuser"));

        // Second failed attempt (should lock)
        auth.record_failed_attempt("testuser");
        assert!(auth.is_account_locked("testuser"));

        // Reset after lockout period
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(!auth.is_account_locked("testuser")); // Should be unlocked after lockout period
    }

    #[test]
    fn test_authentication_request() {
        let config = UserpassConfig::default();
        let mut auth = UserpassAuth::new(config);

        // Add a test user
        let mut user = UserpassUser {
            username: "testuser".to_string(),
            password_hash: auth.hash_password("password123").unwrap(),
            policies: vec!["default".to_string()],
            groups: vec!["users".to_string()],
            created_at: Utc::now(),
            password_changed_at: Utc::now(),
            disabled: false,
            password_expired: false,
        };
        auth.users.insert("testuser".to_string(), user);

        // Create authentication request
        let mut request_data = HashMap::new();
        request_data.insert("username".to_string(), "testuser".to_string());
        request_data.insert("password".to_string(), "password123".to_string());

        let request = AuthRequest::new(request_data);

        // Test successful authentication
        let response = tokio_test::block_on(auth.authenticate(request)).unwrap();
        assert!(response.authenticated);
        assert_eq!(response.policies, vec!["default".to_string()]);
        assert!(response.metadata.contains_key("username"));
        assert_eq!(response.metadata.get("username").unwrap(), "testuser");
    }

    #[test]
    fn test_failed_authentication() {
        let config = UserpassConfig::default();
        let auth = UserpassAuth::new(config);

        // Create authentication request with wrong password
        let mut request_data = HashMap::new();
        request_data.insert("username".to_string(), "nonexistent".to_string());
        request_data.insert("password".to_string(), "wrongpassword".to_string());

        let request = AuthRequest::new(request_data);

        // Test failed authentication
        let result = tokio_test::block_on(auth.authenticate(request));
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::AuthenticationFailed(msg) => {
                assert!(msg.contains("Invalid"));
            }
            _ => panic!("Expected AuthenticationFailed error"),
        }
    }

    #[test]
    fn test_userpass_auth_method() {
        let method = UserpassAuthMethod::new();
        assert_eq!(method.name(), "userpass");
        assert!(method.supported_request_types().contains(&"login"));
    }

    #[test]
    fn test_userpass_auth_provider() {
        let provider = UserpassAuthProvider::new();
        assert_eq!(provider.name(), "userpass");
    }

    #[tokio::test]
    async fn test_userpass_auth_provider_authenticate() {
        let provider = UserpassAuthProvider::new();

        // Create authentication request
        let mut request_data = HashMap::new();
        request_data.insert("username".to_string(), "testuser".to_string());
        request_data.insert("password".to_string(), "password123".to_string());

        let request = AuthRequest::new(request_data);

        // Test authentication (will fail because no user exists, but shouldn't panic)
        let result = provider.authenticate(request).await;
        assert!(result.is_err()); // Should fail gracefully
    }
}
