//! Secure Authentication Module
//!
//! This module provides production-ready authentication with:
//! - Argon2id password hashing (OWASP recommended)
//! - Constant-time password comparison (timing attack prevention)
//! - Rate limiting (brute force prevention)
//! - Secure session management
//! - Password policy enforcement
//! - Account lockout after failed attempts

use chrono::{DateTime, Duration, Utc};
use secreton_crypto::hashing::password::{hash_password_argon2, verify_password_argon2};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// User entity for UI authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub email: String,
    pub full_name: Option<String>,
    pub is_active: bool,
    pub is_superuser: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub mfa_enabled: bool,
    pub roles: HashSet<String>,
    pub namespace: String,
    pub is_locked: bool,
    pub failed_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
}

impl User {
    /// Check if the user account is currently locked
    pub fn is_currently_locked(&self) -> bool {
        if !self.is_locked {
            return false;
        }

        if let Some(locked_until) = self.locked_until {
            Utc::now() < locked_until
        } else {
            true // Permanently locked
        }
    }
}

/// Authentication error types
#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidCredentials,
    AccountLocked,
    RateLimitExceeded,
    SessionExpired,
    SessionNotFound,
    PasswordTooWeak,
    HashingError(String),
    DatabaseError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::AccountLocked => {
                write!(f, "Account is locked due to too many failed attempts")
            }
            AuthError::RateLimitExceeded => write!(f, "Too many attempts. Please try again later"),
            AuthError::SessionExpired => write!(f, "Session has expired"),
            AuthError::SessionNotFound => write!(f, "Session not found"),
            AuthError::PasswordTooWeak => write!(f, "Password does not meet security requirements"),
            AuthError::HashingError(msg) => write!(f, "Hashing error: {}", msg),
            AuthError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

// User is now imported from secreton_core::models above
// All User-related methods are in the core implementation

/// Secure session with expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl Session {
    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session is still valid
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// Update last activity time
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// Password policy configuration
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    pub min_special_chars: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12, // OWASP recommendation: minimum 12 characters
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            min_special_chars: 1,
        }
    }
}

impl PasswordPolicy {
    /// Validate password against policy
    pub fn validate(&self, password: &str) -> Result<(), AuthError> {
        if password.len() < self.min_length {
            return Err(AuthError::PasswordTooWeak);
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AuthError::PasswordTooWeak);
        }

        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(AuthError::PasswordTooWeak);
        }

        if self.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            return Err(AuthError::PasswordTooWeak);
        }

        if self.require_special {
            let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
            let special_count = password
                .chars()
                .filter(|c| special_chars.contains(*c))
                .count();
            if special_count < self.min_special_chars {
                return Err(AuthError::PasswordTooWeak);
            }
        }

        Ok(())
    }
}

/// Rate limiter for login attempts
#[derive(Debug)]
struct RateLimiter {
    attempts: HashMap<String, Vec<DateTime<Utc>>>,
    max_attempts: usize,
    window_duration: Duration,
}

impl RateLimiter {
    fn new(max_attempts: usize, window_minutes: i64) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window_duration: Duration::minutes(window_minutes),
        }
    }

    /// Check if rate limit is exceeded
    fn check_rate_limit(&mut self, identifier: &str) -> bool {
        let now = Utc::now();
        let window_start = now - self.window_duration;

        // Get attempts for this identifier
        let attempts = self
            .attempts
            .entry(identifier.to_string())
            .or_insert_with(Vec::new);

        // Remove old attempts outside the window
        attempts.retain(|&timestamp| timestamp > window_start);

        // Check if limit exceeded
        attempts.len() < self.max_attempts
    }

    /// Record an attempt
    fn record_attempt(&mut self, identifier: &str) {
        let now = Utc::now();
        let attempts = self
            .attempts
            .entry(identifier.to_string())
            .or_insert_with(Vec::new);
        attempts.push(now);
    }

    /// Clear attempts for identifier (after successful login)
    fn clear_attempts(&mut self, identifier: &str) {
        self.attempts.remove(identifier);
    }
}

/// Secure Session Management Service
pub struct SessionService {
    users: Arc<RwLock<HashMap<String, User>>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    password_policy: PasswordPolicy,
    session_duration: Duration,
    max_failed_attempts: u32,
    lockout_duration: Duration,
}

impl SessionService {
    /// Create new session management service
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(5, 15))), // 5 attempts per 15 minutes
            password_policy: PasswordPolicy::default(),
            session_duration: Duration::hours(8), // 8 hour sessions
            max_failed_attempts: 5,
            lockout_duration: Duration::minutes(30), // 30 minute lockout
        }
    }

    /// Hash password using Argon2id (OWASP recommended)
    pub fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        // Validate password policy first
        self.password_policy.validate(password)?;

        hash_password_argon2(password)
            .map(|result| result.hash)
            .map_err(|e| AuthError::HashingError(e.to_string()))
    }

    /// Verify password using constant-time comparison
    fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool, AuthError> {
        verify_password_argon2(password, password_hash)
            .map_err(|e| AuthError::HashingError(e.to_string()))
    }

    /// Register new user
    pub async fn register_user(
        &self,
        username: String,
        password: String,
        email: Option<String>,
    ) -> Result<User, AuthError> {
        // Hash password
        let password_hash = self.hash_password(&password)?;

        let user = User {
            id: Uuid::new_v4(),
            username: username.clone(),
            password_hash,
            email: email.unwrap_or_default(), // Convert Option<String> to String
            full_name: None,
            is_active: true,
            is_superuser: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
            mfa_enabled: false,
            roles: vec!["user".to_string()].into_iter().collect(), // Convert to HashSet
            namespace: "default".to_string(),
            is_locked: false,
            failed_attempts: 0,
            locked_until: None,
        };

        // Store user
        let mut users = self.users.write().await;
        users.insert(username, user.clone());

        Ok(user)
    }

    /// Authenticate user and create session
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Session, AuthError> {
        // Check rate limit
        let mut rate_limiter = self.rate_limiter.write().await;
        if !rate_limiter.check_rate_limit(username) {
            rate_limiter.record_attempt(username);
            return Err(AuthError::RateLimitExceeded);
        }

        // Get user
        let mut users = self.users.write().await;
        let user = users
            .get_mut(username)
            .ok_or(AuthError::InvalidCredentials)?;

        // Check if account is locked
        if user.is_currently_locked() {
            return Err(AuthError::AccountLocked);
        }

        // Verify password with constant-time comparison
        let password_valid = self.verify_password(password, &user.password_hash)?;

        if !password_valid {
            // Record failed attempt
            user.failed_attempts += 1;
            rate_limiter.record_attempt(username);

            // Lock account if too many failures
            if user.failed_attempts >= self.max_failed_attempts {
                user.is_locked = true;
                user.locked_until = Some(Utc::now() + self.lockout_duration);
            }

            return Err(AuthError::InvalidCredentials);
        }

        // Successful login - reset failed attempts
        user.failed_attempts = 0;
        user.last_login = Some(Utc::now());
        rate_limiter.clear_attempts(username);

        // Create session
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let session = Session {
            session_id: session_id.clone(),
            user_id: user.id,
            username: username.to_string(),
            created_at: now,
            expires_at: now + self.session_duration,
            last_activity: now,
            ip_address,
            user_agent,
        };

        // Store session
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session.clone());

        Ok(session)
    }

    /// Validate session
    pub async fn validate_session(&self, session_id: &str) -> Result<Session, AuthError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or(AuthError::SessionNotFound)?;

        if session.is_expired() {
            sessions.remove(session_id);
            return Err(AuthError::SessionExpired);
        }

        // Update last activity
        session.update_activity();

        Ok(session.clone())
    }

    /// Logout (invalidate session)
    pub async fn logout(&self, session_id: &str) -> Result<(), AuthError> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    /// Get user by username
    pub async fn get_user(&self, username: &str) -> Option<User> {
        let users = self.users.read().await;
        users.get(username).cloned()
    }

    /// List all users
    pub async fn list_users(&self) -> Vec<User> {
        let users = self.users.read().await;
        users.values().cloned().collect()
    }

    /// Change password
    pub async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        // Verify old password first
        let users_read = self.users.read().await;
        let user = users_read
            .get(username)
            .ok_or(AuthError::InvalidCredentials)?;

        let old_password_valid = self.verify_password(old_password, &user.password_hash)?;
        if !old_password_valid {
            return Err(AuthError::InvalidCredentials);
        }
        drop(users_read);

        // Hash new password
        let new_password_hash = self.hash_password(new_password)?;

        // Update user
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(username) {
            user.password_hash = new_password_hash;
        }

        Ok(())
    }

    /// Cleanup expired sessions (call periodically)
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| !session.is_expired());
    }
}

impl Default for SessionService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_hashing() {
        let auth = SessionService::new();
        let password = "SecureP@ssw0rd123";

        let hash = auth.hash_password(password).unwrap();
        assert!(auth.verify_password(password, &hash).unwrap());
        assert!(!auth.verify_password("WrongPassword", &hash).unwrap());
    }

    #[tokio::test]
    async fn test_password_policy() {
        let auth = SessionService::new();

        // Too short
        assert!(auth.hash_password("Short1!").is_err());

        // No uppercase
        assert!(auth.hash_password("lowercase123!").is_err());

        // No special char
        assert!(auth.hash_password("NoSpecialChar123").is_err());

        // Valid password
        assert!(auth.hash_password("ValidP@ssw0rd123").is_ok());
    }

    #[tokio::test]
    async fn test_user_registration_and_login() {
        let auth = SessionService::new();

        // Register user
        let result = auth
            .register_user(
                "testuser".to_string(),
                "SecureP@ssw0rd123".to_string(),
                Some("test@example.com".to_string()),
            )
            .await;
        assert!(result.is_ok());

        // Login with correct credentials
        let session = auth
            .login("testuser", "SecureP@ssw0rd123", None, None)
            .await;
        assert!(session.is_ok());

        // Login with wrong credentials
        let wrong_login = auth.login("testuser", "WrongPassword", None, None).await;
        assert!(wrong_login.is_err());
    }

    #[tokio::test]
    async fn test_account_lockout() {
        let auth = SessionService::new();

        // Register user
        auth.register_user(
            "locktest".to_string(),
            "SecureP@ssw0rd123".to_string(),
            None,
        )
        .await
        .unwrap();

        // Try to login with wrong password multiple times
        for _ in 0..6 {
            let _ = auth.login("locktest", "WrongPassword", None, None).await;
        }

        // Account should be locked now
        let result = auth
            .login("locktest", "SecureP@ssw0rd123", None, None)
            .await;
        assert!(matches!(result, Err(AuthError::AccountLocked)));
    }

    #[tokio::test]
    async fn test_session_validation() {
        let auth = SessionService::new();

        // Register and login
        auth.register_user(
            "sessiontest".to_string(),
            "SecureP@ssw0rd123".to_string(),
            None,
        )
        .await
        .unwrap();

        let session = auth
            .login("sessiontest", "SecureP@ssw0rd123", None, None)
            .await
            .unwrap();

        // Validate session
        let validated = auth.validate_session(&session.session_id).await;
        assert!(validated.is_ok());

        // Logout
        auth.logout(&session.session_id).await.unwrap();

        // Session should be invalid now
        let invalid = auth.validate_session(&session.session_id).await;
        assert!(invalid.is_err());
    }
}
