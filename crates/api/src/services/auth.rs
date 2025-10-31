//! Authentication service for user management and token validation.

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;
use thiserror::Error;
use uuid::Uuid;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};

use crate::config::AuthConfig;
use brankas_crypto::CryptoService;
use brankas_storage::{StorageBackend, EncryptionMetadata, SecurityLevel};

// Local User model for authentication service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
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

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// Email
    pub email: String,
    /// Roles
    pub roles: Vec<String>,
    /// Issued at
    pub iat: usize,
    /// Expiration
    pub exp: usize,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
}

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

// User is now imported from secreton_core::models

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
pub struct AuthenticationService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    config: AuthConfig,
}

impl AuthenticationService {
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
        // Parse and validate JWT token
        let decoding_key = DecodingKey::from_secret(self.config.jwt.secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.jwt.issuer]);
        validation.set_audience(&[&self.config.jwt.audience]);

        let token_data = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    _ => AuthError::InvalidToken,
                }
            })?;

        let claims = token_data.claims;

        // Get user from storage to verify they still exist and are enabled
        let user = self.get_user(&claims.sub).await?;

        // Verify user is enabled
        if !user.enabled {
            return Err(AuthError::PermissionDenied);
        }

        // Verify roles match (in case roles were updated)
        if user.roles != claims.roles {
            return Err(AuthError::InvalidToken);
        }

        Ok(user)
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthToken, AuthError> {
        // Validate refresh token
        let decoding_key = DecodingKey::from_secret(self.config.jwt.secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.jwt.issuer]);
        validation.set_audience(&[&self.config.jwt.audience]);

        let token_data = decode::<Claims>(refresh_token, &decoding_key, &validation)
            .map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    _ => AuthError::InvalidToken,
                }
            })?;

        let claims = token_data.claims;

        // Verify it's a refresh token (JTI starts with "refresh_")
        if !claims.jti.starts_with("refresh_") {
            return Err(AuthError::InvalidToken);
        }

        // Get user from storage
        let user = self.get_user(&claims.sub).await?;

        // Verify user is still enabled
        if !user.enabled {
            return Err(AuthError::PermissionDenied);
        }

        // Create new tokens
        let session_id = claims.jti.trim_start_matches("refresh_");
        let access_token = self.create_access_token(&user, session_id)?;
        let new_refresh_token = self.create_refresh_token(&user, session_id)?;

        // Update session last accessed time
        let session_path = format!("auth/sessions/{}", session_id);
        if let Ok(Some(session_entry)) = self.storage.get_by_path(&session_path).await {
            if let Some(session_data) = session_entry.metadata.get("session_data") {
                if let Ok(mut session) = serde_json::from_str::<Session>(session_data) {
                    session.last_accessed = chrono::Utc::now();
                    
                    // Re-serialize and store updated session
                    let updated_session_json = serde_json::to_string(&session)
                        .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;
                    
                    let mut updated_metadata = HashMap::new();
                    updated_metadata.insert("session_data".to_string(), updated_session_json);
                    
                    let updated_entry = brankas_storage::VaultEntry {
                        id: session_entry.id,
                        path: session_entry.path,
                        encrypted_data: Vec::new(),
                        encryption_metadata: EncryptionMetadata {
                            algorithm: "none".to_string(),
                            key_id: "none".to_string(),
                            iv: Vec::new(),
                            auth_tag: None,
                            aad: None,
                        },
                        security_level: SecurityLevel::Confidential,
                        metadata: updated_metadata,
                        tags: session_entry.tags,
                        version: session_entry.version + 1,
                        owner_id: session_entry.owner_id,
                        created_at: session_entry.created_at,
                        updated_at: chrono::Utc::now(),
                        expires_at: session_entry.expires_at,
                    };
                    
                    let _ = self.storage.store(&updated_entry).await;
                }
            }
        }

        Ok(AuthToken {
            access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt.expiration.as_secs(),
            user,
        })
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
        let path = format!("auth/users/{}", user_id);
        let entry = self.storage.get_by_path(&path).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Storage error: {}", e)))?
            .ok_or(AuthError::UserNotFound)?;

        let user_data = entry.metadata.get("user_data")
            .ok_or(AuthError::Internal(anyhow::anyhow!("Invalid user data")))?;

        serde_json::from_str(user_data)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<User, AuthError> {
        let path = format!("auth/users/by-username/{}", username);
        let entry = self.storage.get_by_path(&path).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Storage error: {}", e)))?
            .ok_or(AuthError::UserNotFound)?;

        let user_data = entry.metadata.get("user_data")
            .ok_or(AuthError::Internal(anyhow::anyhow!("Invalid user data")))?;

        serde_json::from_str(user_data)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))
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
        let path = format!("auth/roles/{}", role_name);
        let entry = self.storage.get_by_path(&path).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Storage error: {}", e)))?
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("Role not found")))?;

        let role_data = entry.metadata.get("role_data")
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("Invalid role data")))?;

        serde_json::from_str(role_data)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))
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

    /// Hash password using crypto service
    fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        use secreton_crypto::hashing::HashingService;
        
        let result = HashingService::hash_password_argon2(password)
            .map_err(|e| AuthError::InternalError(format!("Password hashing failed: {}", e)))?;
        
        Ok(result.hash)
    }

    /// Verify password using crypto service
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        use secreton_crypto::hashing::HashingService;
        
        HashingService::verify_password_argon2(password, hash)
            .map_err(|e| AuthError::InternalError(format!("Password verification failed: {}", e)))
    }

    /// Verify MFA code
    fn verify_mfa_code(&self, user: &User, code: &str) -> Result<(), AuthError> {
        if let Some(secret) = &user.mfa_secret {
            use totp_rs::{Algorithm, TOTP};

            let totp = TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                secret.clone().into_bytes(),
            ).map_err(|e| AuthError::Internal(anyhow::anyhow!("TOTP setup failed: {}", e)))?;

            let current_code = totp.generate_current().map_err(|e| AuthError::Internal(anyhow::anyhow!("TOTP generation failed: {}", e)))?;
            
            if current_code == code {
                Ok(())
            } else {
                Err(AuthError::InvalidMfaCode)
            }
        } else {
            Err(AuthError::Internal(anyhow::anyhow!("MFA not configured for user")))
        }
    }

    /// Create access token (JWT)
    fn create_access_token(&self, user: &User, session_id: &str) -> Result<String, AuthError> {
        let now = chrono::Utc::now();
        let expiration = now + chrono::Duration::seconds(self.config.jwt.expiration.as_secs() as i64);
        
        let claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            roles: user.roles.clone(),
            iat: now.timestamp() as usize,
            exp: expiration.timestamp() as usize,
            iss: self.config.jwt.issuer.clone(),
            aud: self.config.jwt.audience.clone(),
            jti: session_id.to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(self.config.jwt.secret.as_bytes());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("JWT encoding failed: {}", e)))
    }

    /// Create refresh token
    fn create_refresh_token(&self, user: &User, session_id: &str) -> Result<String, AuthError> {
        let now = chrono::Utc::now();
        let expiration = now + chrono::Duration::seconds(self.config.jwt.refresh_expiration.as_secs() as i64);
        
        let claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            roles: user.roles.clone(),
            iat: now.timestamp() as usize,
            exp: expiration.timestamp() as usize,
            iss: self.config.jwt.issuer.clone(),
            aud: self.config.jwt.audience.clone(),
            jti: format!("refresh_{}", session_id),
        };

        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(self.config.jwt.secret.as_bytes());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("JWT encoding failed: {}", e)))
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
        // Serialize user to JSON
        let user_json = serde_json::to_string(user)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        // Create vault entry for user by ID
        let mut metadata = HashMap::new();
        metadata.insert("user_data".to_string(), user_json.clone());

        let entry = brankas_storage::VaultEntry {
            id: Uuid::new_v4(),
            path: format!("auth/users/{}", user.id),
            encrypted_data: Vec::new(), // No encrypted data for user info
            encryption_metadata: EncryptionMetadata {
                algorithm: "none".to_string(),
                key_id: "none".to_string(),
                iv: Vec::new(),
                auth_tag: None,
                aad: None,
            },
            security_level: SecurityLevel::Confidential,
            metadata: metadata.clone(),
            tags: vec!["auth".to_string(), "user".to_string()],
            version: 1,
            owner_id: Uuid::new_v4(), // System owner
            created_at: user.created_at,
            updated_at: user.updated_at,
            expires_at: None,
        };

        self.storage.store(&entry).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Storage error: {}", e)))?;

        // Also store by username for lookup
        let username_entry = brankas_storage::VaultEntry {
            id: Uuid::new_v4(),
            path: format!("auth/users/by-username/{}", user.username),
            encrypted_data: Vec::new(),
            encryption_metadata: EncryptionMetadata {
                algorithm: "none".to_string(),
                key_id: "none".to_string(),
                iv: Vec::new(),
                auth_tag: None,
                aad: None,
            },
            security_level: SecurityLevel::Confidential,
            metadata,
            tags: vec!["auth".to_string(), "user".to_string(), "username-index".to_string()],
            version: 1,
            owner_id: Uuid::new_v4(),
            created_at: user.created_at,
            updated_at: user.updated_at,
            expires_at: None,
        };

        self.storage.store(&username_entry).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Storage error: {}", e)))
    }

    /// Store role in storage
    async fn store_role(&self, role: &Role) -> Result<(), AuthError> {
        // Serialize role to JSON
        let role_json = serde_json::to_string(role)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        // Create vault entry for role
        let mut metadata = HashMap::new();
        metadata.insert("role_data".to_string(), role_json);

        let entry = brankas_storage::VaultEntry {
            id: Uuid::new_v4(),
            path: format!("auth/roles/{}", role.name),
            encrypted_data: Vec::new(),
            encryption_metadata: EncryptionMetadata {
                algorithm: "none".to_string(),
                key_id: "none".to_string(),
                iv: Vec::new(),
                auth_tag: None,
                aad: None,
            },
            security_level: SecurityLevel::Confidential,
            metadata,
            tags: vec!["auth".to_string(), "role".to_string()],
            version: 1,
            owner_id: Uuid::new_v4(),
            created_at: role.created_at,
            updated_at: role.updated_at,
            expires_at: None,
        };

        self.storage.store(&entry).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Storage error: {}", e)))
    }

    /// Store session
    async fn store_session(&self, session: &Session) -> Result<(), AuthError> {
        // Serialize session to JSON
        let session_json = serde_json::to_string(session)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        // Create vault entry for session
        let mut metadata = HashMap::new();
        metadata.insert("session_data".to_string(), session_json);

        let entry = brankas_storage::VaultEntry {
            id: Uuid::new_v4(),
            path: format!("auth/sessions/{}", session.id),
            encrypted_data: Vec::new(),
            encryption_metadata: EncryptionMetadata {
                algorithm: "none".to_string(),
                key_id: "none".to_string(),
                iv: Vec::new(),
                auth_tag: None,
                aad: None,
            },
            security_level: SecurityLevel::Confidential,
            metadata,
            tags: vec!["auth".to_string(), "session".to_string()],
            version: 1,
            owner_id: Uuid::new_v4(),
            created_at: session.created_at,
            updated_at: session.last_accessed,
            expires_at: Some(session.expires_at),
        };

        self.storage.store(&entry).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Storage error: {}", e)))
    }

    /// Update last login timestamp
    async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError> {
        // Get the user
        let mut user = self.get_user(user_id).await?;
        
        // Update last login
        user.last_login = Some(chrono::Utc::now());
        user.updated_at = chrono::Utc::now();
        
        // Store the updated user
        self.store_user(&user).await
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

        let auth_service = AuthenticationService::new(storage, crypto, &config).await;
        assert!(auth_service.is_ok());
    }

    #[test]
    fn test_password_hashing() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();
        let auth_service = AuthenticationService {
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
        let auth_service = AuthenticationService::new(storage.clone(), crypto, &config)
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
        let auth_service = AuthenticationService::new(storage.clone(), crypto, &AuthConfig::default())
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
        let service = AuthenticationService::new(storage.clone(), crypto.clone(), &config)
            .await
            .expect("service");
        // Second creation should not fail if roles already exist
        let result = AuthenticationService::new(storage, crypto, &config).await;
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
