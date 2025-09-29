//! Authentication service for user management and token validation.

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::config::AuthConfig;
use brankas_crypto::CryptoService;
use brankas_storage::StorageBackend;

/// Authentication service errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("MFA required")]
    MfaRequired,

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Storage error: {0}")]
    Storage(#[from] brankas_storage::StorageError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] brankas_crypto::CryptoError),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub full_name: Option<String>,
    pub enabled: bool,
    pub roles: Vec<String>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

/// Role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub refresh_token: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub last_accessed: chrono::DateTime<chrono::Utc>,
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: User,
}

/// Authentication service
pub struct AuthService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    config: AuthConfig,
}

impl AuthService {
    /// Create new authentication service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        config: &AuthConfig,
    ) -> Result<Self> {
        let service = Self {
            storage,
            crypto,
            config: config.clone(),
        };

        // Initialize default roles if they don't exist
        service.initialize_default_roles().await?;

        Ok(service)
    }

    /// Authenticate user with username and password
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        mfa_code: Option<&str>,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<AuthToken, AuthError> {
        // Get user from storage
        let user = self.get_user_by_username(username).await?;
        
        if !user.enabled {
            return Err(AuthError::InvalidCredentials);
        }

        // Verify password
        if !self.verify_password(password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        // Check MFA if enabled
        if user.mfa_enabled {
            if let Some(code) = mfa_code {
                self.verify_mfa_code(&user, code)?;
            } else {
                return Err(AuthError::MfaRequired);
            }
        }

        // Create session and tokens
        let session_id = Uuid::new_v4().to_string();
        let access_token = self.create_access_token(&user, &session_id)?;
        let refresh_token = self.create_refresh_token(&user, &session_id)?;

        // Store session
        let session = Session {
            id: session_id,
            user_id: user.id.clone(),
            token: access_token.clone(),
            refresh_token: Some(refresh_token.clone()),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(self.config.jwt.expiration.as_secs() as i64),
            last_accessed: chrono::Utc::now(),
        };

        self.store_session(&session).await?;

        // Update last login
        self.update_last_login(&user.id).await?;

        Ok(AuthToken {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt.expiration.as_secs(),
            user,
        })
    }

    /// Validate access token
    pub async fn validate_token(&self, token: &str) -> Result<User, AuthError> {
        // TODO: Implement JWT token validation
        // 1. Parse JWT token
        // 2. Verify signature
        // 3. Check expiration
        // 4. Get user from token claims
        // 5. Verify session still exists

        // For now, return mock user
        Ok(User {
            id: "user_1".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: String::new(),
            full_name: Some("Test User".to_string()),
            enabled: true,
            roles: vec!["user".to_string()],
            mfa_enabled: false,
            mfa_secret: None,
            last_login: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        })
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthToken, AuthError> {
        // TODO: Implement token refresh logic
        // 1. Validate refresh token
        // 2. Get user from token
        // 3. Generate new access token
        // 4. Optionally rotate refresh token

        Err(AuthError::Internal(anyhow::anyhow!("Not implemented")))
    }

    /// Create user
    pub async fn create_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
        full_name: Option<&str>,
        roles: Vec<String>,
    ) -> Result<User, AuthError> {
        // Check if user already exists
        if self.user_exists(username).await? {
            return Err(AuthError::UserAlreadyExists);
        }

        // Hash password
        let password_hash = self.hash_password(password)?;

        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            email: email.to_string(),
            password_hash,
            full_name: full_name.map(|s| s.to_string()),
            enabled: true,
            roles,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        self.store_user(&user).await?;
        Ok(user)
    }

    /// Get user by ID
    pub async fn get_user(&self, user_id: &str) -> Result<User, AuthError> {
        // TODO: Implement user retrieval from storage
        Err(AuthError::UserNotFound)
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<User, AuthError> {
        // TODO: Implement user retrieval from storage by username
        Err(AuthError::UserNotFound)
    }

    /// Check if user has permission
    pub async fn has_permission(&self, user: &User, permission: &str) -> Result<bool, AuthError> {
        // Get user roles and their permissions
        let mut all_permissions = Vec::new();
        
        for role_name in &user.roles {
            if let Ok(role) = self.get_role(role_name).await {
                all_permissions.extend(role.permissions);
            }
        }

        // Check for wildcard permission
        if all_permissions.contains(&"*".to_string()) {
            return Ok(true);
        }

        // Check for exact permission match
        if all_permissions.contains(&permission.to_string()) {
            return Ok(true);
        }

        // Check for pattern match (e.g., "vault:*" matches "vault:read")
        for perm in &all_permissions {
            if perm.ends_with("*") {
                let prefix = &perm[..perm.len() - 1];
                if permission.starts_with(prefix) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get role by name
    pub async fn get_role(&self, role_name: &str) -> Result<Role, AuthError> {
        // TODO: Implement role retrieval from storage
        Err(AuthError::Internal(anyhow::anyhow!("Role not found")))
    }

    /// Create role
    pub async fn create_role(
        &self,
        name: &str,
        description: Option<&str>,
        permissions: Vec<String>,
    ) -> Result<Role, AuthError> {
        let role = Role {
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            permissions,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        self.store_role(&role).await?;
        Ok(role)
    }

    /// Initialize default roles
    async fn initialize_default_roles(&self) -> Result<()> {
        // Create admin role
        if self.get_role("admin").await.is_err() {
            self.create_role(
                "admin",
                Some("System administrator with full access"),
                vec!["*".to_string()],
            ).await?;
        }

        // Create user role
        if self.get_role("user").await.is_err() {
            self.create_role(
                "user",
                Some("Regular user with basic vault access"),
                vec![
                    "vault:read".to_string(),
                    "vault:write".to_string(),
                    "vault:list".to_string(),
                ],
            ).await?;
        }

        // Create viewer role
        if self.get_role("viewer").await.is_err() {
            self.create_role(
                "viewer",
                Some("Read-only access to vault"),
                vec![
                    "vault:read".to_string(),
                    "vault:list".to_string(),
                ],
            ).await?;
        }

        Ok(())
    }

    /// Hash password
    fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        // TODO: Implement secure password hashing (bcrypt, argon2, etc.)
        Ok(format!("hashed_{}", password))
    }

    /// Verify password
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        // TODO: Implement password verification
        Ok(hash == &format!("hashed_{}", password))
    }

    /// Verify MFA code
    fn verify_mfa_code(&self, user: &User, code: &str) -> Result<(), AuthError> {
        // TODO: Implement TOTP verification
        if code == "123456" {
            Ok(())
        } else {
            Err(AuthError::InvalidMfaCode)
        }
    }

    /// Create access token (JWT)
    fn create_access_token(&self, user: &User, session_id: &str) -> Result<String, AuthError> {
        // TODO: Implement JWT token creation
        Ok(format!("access_token_for_{}", user.username))
    }

    /// Create refresh token
    fn create_refresh_token(&self, user: &User, session_id: &str) -> Result<String, AuthError> {
        // TODO: Implement refresh token creation
        Ok(format!("refresh_token_for_{}", user.username))
    }

    /// Check if user exists
    async fn user_exists(&self, username: &str) -> Result<bool, AuthError> {
        match self.get_user_by_username(username).await {
            Ok(_) => Ok(true),
            Err(AuthError::UserNotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Store user in storage
    async fn store_user(&self, user: &User) -> Result<(), AuthError> {
        // TODO: Implement user storage
        Ok(())
    }

    /// Store role in storage
    async fn store_role(&self, role: &Role) -> Result<(), AuthError> {
        // TODO: Implement role storage
        Ok(())
    }

    /// Store session
    async fn store_session(&self, session: &Session) -> Result<(), AuthError> {
        // TODO: Implement session storage
        Ok(())
    }

    /// Update last login timestamp
    async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError> {
        // TODO: Implement last login update
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use brankas_crypto::{CryptoService, SecurityParams};
    use brankas_storage::MockStorageBackend;

    #[tokio::test]
    async fn test_auth_service_creation() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();

        let auth_service = AuthService::new(storage, crypto, &config).await;
        assert!(auth_service.is_ok());
    }

    #[test]
    fn test_password_hashing() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();
        let auth_service = AuthService {
            storage,
            crypto,
            config,
        };

        let password = "test_password";
        let hash = auth_service.hash_password(password).unwrap();
        assert!(auth_service.verify_password(password, &hash).unwrap());
        assert!(!auth_service.verify_password("wrong_password", &hash).unwrap());
    }

    #[tokio::test]
    async fn test_authenticate_requires_mfa_code() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let mut config = AuthConfig::default();
        config.jwt_secret = "secret".into();
        let auth_service = AuthService::new(storage.clone(), crypto, &config)
            .await
            .expect("service");

        // Insert a user with MFA enabled by mocking storage behavior via store_user and get_user_by_username
        let user = User {
            id: "user123".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            password_hash: auth_service.hash_password("password").unwrap(),
            full_name: None,
            enabled: true,
            roles: vec!["user".into()],
            mfa_enabled: true,
            mfa_secret: Some("secret".into()),
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        auth_service.store_user(&user).await.unwrap();

        let result = auth_service
            .authenticate("alice", "password", None, "127.0.0.1", "test-agent")
            .await;
        assert!(matches!(result, Err(AuthError::MfaRequired)));

        let result = auth_service
            .authenticate(
                "alice",
                "password",
                Some("123456"),
                "127.0.0.1",
                "test-agent",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_has_permission_with_wildcard_role() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let auth_service = AuthService::new(storage.clone(), crypto, &AuthConfig::default())
            .await
            .expect("service");

        let user = User {
            id: "user1".into(),
            username: "wildcard".into(),
            email: "wildcard@example.com".into(),
            password_hash: "".into(),
            full_name: None,
            enabled: true,
            roles: vec!["admin".into()],
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        // admin role already initialized in service with "*"
        let allowed = auth_service
            .has_permission(&user, "vault:delete")
            .await
            .expect("has permission");
        assert!(allowed);
    }

    #[tokio::test]
    async fn test_initialize_default_roles_only_once() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();

        // First creation initializes roles
        let service = AuthService::new(storage.clone(), crypto.clone(), &config)
            .await
            .expect("service");
        // Second creation should not fail if roles already exist
        let result = AuthService::new(storage, crypto, &config).await;
        assert!(result.is_ok());
        // Basic permission check still works
        let user = User {
            id: "user2".into(),
            username: "viewer".into(),
            email: "viewer@example.com".into(),
            password_hash: "".into(),
            full_name: None,
            enabled: true,
            roles: vec!["viewer".into()],
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };
        let allowed = service
            .has_permission(&user, "vault:read")
            .await
            .expect("permission");
        assert!(allowed);
    }
}
