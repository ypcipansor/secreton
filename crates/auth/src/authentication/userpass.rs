//! UserPass Authentication Method
//!
//! Username/_password authentication for Secreton.
//! Provides simple credential-based authentication with secure _password hashing.

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Duration, Utc};
use secreton_errors::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::UserInfo;

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPassUser {
    /// Username
    pub _username: String,

    /// Password hash (Argon2id)
    pub password_hash: String,

    /// User metadata
    pub metadata: HashMap<String, String>,

    /// Associated policies
    pub policies: Vec<String>,

    /// Token TTL in seconds
    pub token_ttl: Option<u32>,

    /// Maximum token TTL in seconds
    pub token_max_ttl: Option<u32>,

    /// Account enabled
    pub enabled: bool,

    /// Account locked
    pub locked: bool,

    /// Password expiration date
    pub password_expires_at: Option<DateTime<Utc>>,

    /// Failed login attempts
    pub failed_attempts: u32,

    /// Last failed login
    pub last_failed_login: Option<DateTime<Utc>>,

    /// Last successful login
    pub last_login: Option<DateTime<Utc>>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl UserPassUser {
    /// Create a new _user with hashed _password
    pub fn new(
        _username: String,
        _password: &str,
        policies: Vec<String>,
    ) -> Result<Self, SecretonError> {
        let password_hash = Self::hash_password(_password)?;

        Ok(Self {
            _username,
            password_hash,
            metadata: HashMap::new(),
            policies,
            token_ttl: Some(3600),      // 1 hour default
            token_max_ttl: Some(86400), // 24 hours default
            enabled: true,
            locked: false,
            password_expires_at: None,
            failed_attempts: 0,
            last_failed_login: None,
            last_login: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    /// Hash a _password using Argon2id
    fn hash_password(_password: &str) -> Result<String, SecretonError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(_password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_e| SecretonError::HashingFailed {
                message: _e.to_string(),
            })
    }

    /// Verify a _password against the stored hash
    pub fn verify_password(&self, _password: &str) -> Result<bool, SecretonError> {
        let parsed_hash =
            PasswordHash::new(&self.password_hash).map_err(|_e| SecretonError::HashingFailed {
                message: _e.to_string(),
            })?;

        Ok(Argon2::default()
            .verify_password(_password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Update _password with new hash
    pub fn update_password(&mut self, new_password: &str) -> Result<(), SecretonError> {
        self.password_hash = Self::hash_password(new_password)?;
        self.updated_at = Utc::now();
        self.failed_attempts = 0;
        Ok(())
    }

    /// Check if account can login
    pub fn can_login(&self) -> Result<(), SecretonError> {
        if !self.enabled {
            return Err(SecretonError::AccountDisabled {
                username: self._username.clone(),
            });
        }

        if self.locked {
            return Err(SecretonError::AccountLocked {
                username: self._username.clone(),
            });
        }

        if let Some(expires_at) = self.password_expires_at {
            if Utc::now() > expires_at {
                return Err(SecretonError::PasswordExpired {
                    username: self._username.clone(),
                });
            }
        }

        Ok(())
    }

    /// Record successful login
    pub fn record_success(&mut self) {
        self.last_login = Some(Utc::now());
        self.failed_attempts = 0;
        self.updated_at = Utc::now();
    }

    /// Record failed login attempt
    pub fn record_failure(&mut self, max_attempts: u32) {
        self.failed_attempts += 1;
        self.last_failed_login = Some(Utc::now());
        self.updated_at = Utc::now();

        if self.failed_attempts >= max_attempts {
            self.locked = true;
        }
    }
}

/// UserPass authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPassConfig {
    /// Default token TTL in seconds
    pub default_token_ttl: u32,

    /// Maximum token TTL in seconds
    pub max_token_ttl: u32,

    /// Password policies
    pub password_policy: PasswordPolicy,

    /// Maximum failed login attempts before locking
    pub max_failed_attempts: u32,

    /// Account lockout duration in seconds
    pub lockout_duration: u32,
}

impl Default for UserPassConfig {
    fn default() -> Self {
        Self {
            default_token_ttl: 3600,
            max_token_ttl: 86400,
            password_policy: PasswordPolicy::default(),
            max_failed_attempts: 5,
            lockout_duration: 900, // 15 minutes
        }
    }
}

/// Password policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum _password length
    pub min_length: usize,

    /// Require uppercase letters
    pub require_uppercase: bool,

    /// Require lowercase letters
    pub require_lowercase: bool,

    /// Require numbers
    pub require_numbers: bool,

    /// Require special characters
    pub require_special: bool,

    /// Password expiration in days (None = never expires)
    pub expiration_days: Option<u32>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            expiration_days: Some(90),
        }
    }
}

impl PasswordPolicy {
    /// Validate _password against policy
    pub fn validate(&self, _password: &str) -> Result<(), String> {
        if _password.len() < self.min_length {
            return Err(format!(
                "Password must be at least {} characters",
                self.min_length
            ));
        }

        if self.require_uppercase && !_password.chars().any(|c| c.is_uppercase()) {
            return Err("Password must contain at least one uppercase letter".to_string());
        }

        if self.require_lowercase && !_password.chars().any(|c| c.is_lowercase()) {
            return Err("Password must contain at least one lowercase letter".to_string());
        }

        if self.require_numbers && !_password.chars().any(|c| c.is_numeric()) {
            return Err("Password must contain at least one number".to_string());
        }

        if self.require_special && !_password.chars().any(|c| !c.is_alphanumeric()) {
            return Err("Password must contain at least one special character".to_string());
        }

        Ok(())
    }
}

/// UserPass authentication service
pub struct UserPassAuth {
    _config: UserPassConfig,
    users: Arc<RwLock<HashMap<String, UserPassUser>>>,
}

impl UserPassAuth {
    /// Create new UserPass authentication service
    pub fn new(_config: UserPassConfig) -> Self {
        Self {
            _config,
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new _user
    pub async fn create_user(
        &self,
        _username: String,
        _password: &str,
        policies: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> Result<(), SecretonError> {
        // Validate _password policy
        self._config
            .password_policy
            .validate(_password)
            .map_err(|_e| SecretonError::HashingFailed { message: _e })?;

        let mut users = self.users.write().await;

        if users.contains_key(&_username) {
            return Err(SecretonError::UserAlreadyExists {
                username: _username,
            });
        }

        let mut _user = UserPassUser::new(_username.clone(), _password, policies)?;
        _user.metadata = metadata;

        // Set _password expiration if configured
        if let Some(days) = self._config.password_policy.expiration_days {
            _user.password_expires_at = Some(Utc::now() + Duration::days(days as i64));
        }

        users.insert(_username, _user);
        Ok(())
    }

    /// Update _user _password
    pub async fn update_password(
        &self,
        _username: &str,
        new_password: &str,
    ) -> Result<(), SecretonError> {
        // Validate _password policy
        self._config
            .password_policy
            .validate(new_password)
            .map_err(|_e| SecretonError::HashingFailed { message: _e })?;

        let mut users = self.users.write().await;

        let _user = users
            .get_mut(_username)
            .ok_or_else(|| SecretonError::UserNotFound {
                username: _username.to_string(),
            })?;

        _user.update_password(new_password)?;

        // Update expiration
        if let Some(days) = self._config.password_policy.expiration_days {
            _user.password_expires_at = Some(Utc::now() + Duration::days(days as i64));
        }

        Ok(())
    }

    /// Delete a _user
    pub async fn delete_user(&self, _username: &str) -> Result<(), SecretonError> {
        let mut users = self.users.write().await;
        users
            .remove(_username)
            .ok_or_else(|| SecretonError::UserNotFound {
                username: _username.to_string(),
            })?;
        Ok(())
    }

    /// List all users
    pub async fn list_users(&self) -> Vec<String> {
        let users = self.users.read().await;
        users.keys().cloned().collect()
    }

    /// Get _user information
    pub async fn get_user(&self, _username: &str) -> Result<UserPassUser, SecretonError> {
        let users = self.users.read().await;
        users
            .get(_username)
            .cloned()
            .ok_or_else(|| SecretonError::UserNotFound {
                username: _username.to_string(),
            })
    }

    /// Authenticate _user
    pub async fn authenticate(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<UserInfo, SecretonError> {
        let mut users = self.users.write().await;

        let _user = users
            .get_mut(_username)
            .ok_or_else(|| SecretonError::UserNotFound {
                username: _username.to_string(),
            })?;

        // Check if account can login
        _user.can_login()?;

        // Verify _password
        if !_user.verify_password(_password)? {
            _user.record_failure(self._config.max_failed_attempts);
            return Err(SecretonError::InvalidCredentials);
        }

        // Success!
        _user.record_success();

        Ok(UserInfo {
            username: _user._username.clone(),
            email: _user.metadata.get("email").cloned(),
            groups: _user.policies.clone(),
            metadata: _user.metadata.clone(),
        })
    }

    /// Enable/disable _user
    pub async fn set_user_enabled(
        &self,
        _username: &str,
        enabled: bool,
    ) -> Result<(), SecretonError> {
        let mut users = self.users.write().await;
        let _user = users
            .get_mut(_username)
            .ok_or_else(|| SecretonError::UserNotFound {
                username: _username.to_string(),
            })?;

        _user.enabled = enabled;
        _user.updated_at = Utc::now();
        Ok(())
    }

    /// Lock/unlock _user
    pub async fn set_user_locked(
        &self,
        _username: &str,
        locked: bool,
    ) -> Result<(), SecretonError> {
        let mut users = self.users.write().await;
        let _user = users
            .get_mut(_username)
            .ok_or_else(|| SecretonError::UserNotFound {
                username: _username.to_string(),
            })?;

        _user.locked = locked;
        if !locked {
            _user.failed_attempts = 0;
        }
        _user.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_authenticate() {
        let _config = UserPassConfig::default();
        let auth = UserPassAuth::new(_config);

        // Create _user
        auth.create_user(
            "testuser".to_string(),
            "TestPass123!",
            vec!["default".to_string()],
            HashMap::new(),
        )
        .await
        .unwrap();

        // Authenticate successfully
        let user_info = auth.authenticate("testuser", "TestPass123!").await.unwrap();
        assert_eq!(user_info.username, "testuser");

        // Wrong _password
        let result = auth.authenticate("testuser", "wrongpass").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_password_policy() {
        let policy = PasswordPolicy::default();

        assert!(policy.validate("short").is_err());
        assert!(policy.validate("nouppercase123!").is_err());
        assert!(policy.validate("NOLOWERCASE123!").is_err());
        assert!(policy.validate("NoNumbers!").is_err());
        assert!(policy.validate("NoSpecial123").is_err());
        assert!(policy.validate("ValidPass123!").is_ok());
    }

    #[tokio::test]
    async fn test_account_lockout() {
        let mut _config = UserPassConfig::default();
        _config.max_failed_attempts = 3;
        let auth = UserPassAuth::new(_config);

        auth.create_user(
            "locktest".to_string(),
            "TestPass123!",
            vec![],
            HashMap::new(),
        )
        .await
        .unwrap();

        // Fail 3 times
        for _ in 0..3 {
            let _ = auth.authenticate("locktest", "wrongpass").await;
        }

        // Account should be locked
        let result = auth.authenticate("locktest", "TestPass123!").await;
        assert!(matches!(result, Err(SecretonError::AccountLocked { .. })));
    }
}
