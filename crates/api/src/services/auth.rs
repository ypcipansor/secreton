//! Authentication service facade for the API layer.
//!
//! This service provides a simplified interface to the unified authentication system,
//! delegating actual authentication logic to the auth crate while maintaining
//! API-specific concerns like session management and storage integration.

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use serde_json;

use crate::config::AuthConfig;
use crate::services::crypto::CryptoService;
use secreton_storage::{StorageBackend, SecretEntry, EncryptionMetadata, SecurityLevel, QueryParams};
use secreton_auth::{AuthService as UnifiedAuthService, LoginRequest, TokenConfig, JwtTokenService, UserPassAuthMethod};
use secreton_core::User;
use thiserror::Error;
use crate::ApiResult;

pub const USER_STORAGE_PREFIX: &str = "users/";
const SESSION_STORAGE_PREFIX: &str = "sys/auth/sessions/";

#[derive(Debug, Deserialize)]
pub struct ApiLoginRequest {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
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
    /// Expiration time
    pub exp: usize,
    /// JWT ID
    pub jti: String,
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
    Storage(#[from] secreton_storage::StorageError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] secreton_crypto::CryptoError),

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

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiLoginResponse {
    pub token: AuthToken,
}


/// Authentication service facade
pub struct AuthenticationService {
    /// Unified authentication service
    auth_service: Arc<UnifiedAuthService>,

    /// Token service for JWT operations
    token_service: JwtTokenService,

    /// Storage backend for sessions

    storage: Arc<dyn StorageBackend + Send + Sync>,

    /// Configuration
    config: AuthConfig,

    /// Token blacklist
    token_blacklist: Arc<tokio::sync::RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
}

impl AuthenticationService {
    /// Create new authentication service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        _crypto: Arc<CryptoService>,
        config: &AuthConfig,
    ) -> Result<Self> {
        // Create token service
        let token_config = TokenConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_refresh_secret: config.jwt.secret.clone(), // Use same secret as no refresh_secret field
            access_token_duration: chrono::Duration::from_std(config.jwt.expiration).unwrap_or(chrono::Duration::hours(1)),
            refresh_token_duration: chrono::Duration::from_std(config.jwt.refresh_expiration).unwrap_or(chrono::Duration::days(7)),
            issuer: config.jwt.issuer.clone(),
            audience: config.jwt.audience.clone(),
        };
        let token_service = JwtTokenService::new(token_config);

        // Create unified auth service
        let auth_service = Arc::new(UnifiedAuthService::new());

        // Register default authentication methods
        auth_service.register_method("userpass".to_string(), Arc::new(UserPassAuthMethod::new())).await;

        Ok(Self {
            auth_service,
            token_service,
            storage,
            config: config.clone(),
            token_blacklist: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Authenticate user with username and password
    pub async fn login(&self, req: ApiLoginRequest) -> ApiResult<ApiLoginResponse> {
        // Create login request
        let request = LoginRequest {
            username: req.username.clone(),
            password: req.password.clone(),
            mfa_code: req.mfa_code.clone(),
            remember_me: Some(false),
        };

        // Authenticate using unified auth service
        let response = self.auth_service.login(&request).await
            .map_err(|e| secreton_errors::SecretonError::Authentication { message: e.to_string() })?;

        if !response.success {
            return Err(secreton_errors::SecretonError::Authentication { message: "Invalid credentials".to_string() }.into());
        }

        let user_info = response.user_info
            .ok_or_else(|| secreton_errors::SecretonError::Internal { message: "No user info returned".to_string() })?;

        // Convert UserInfo to User (simplified)
        let user = User {
            id: user_info.id.clone().unwrap_or_default(),
            username: user_info.username.clone(),
            email: user_info.email,
            display_name: user_info.display_name.clone(),
            full_name: user_info.display_name,
            password_hash: "".to_string(), // Not used in API responses
            is_active: true,
            is_superuser: false,
            disabled: false,
            roles: user_info.roles.clone(),
            policies: vec!["default".to_string()], // Default policies as UserInfo lacks them
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None, // UserInfo lacks last_login
            created_at: chrono::Utc::now(), // UserInfo lacks created_at
            updated_at: chrono::Utc::now(),
            metadata: user_info.metadata.clone(),
        };

        // Create token pair
        let token_pair = self.token_service.create_token_pair(
            &user.id,
            &user.username,
            user.email.as_deref(), // Convert Option<&String> to Option<&str>
            &user.roles,
            &user.policies, // Use user.policies which we just created
            false, // MFA status from auth result
        ).map_err(|e| secreton_errors::SecretonError::Authentication { message: e.to_string() })?;

        // Create and store session
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::from_std(self.config.jwt.expiration)
            .unwrap_or(chrono::Duration::hours(1));

        // Use JTI if available from tokens, otherwise generate UUID
        // The TokenPair from secreton_auth doesn't expose JTI directly, so we generate a session ID
        let session_id = Uuid::new_v4().to_string();

        let session = Session {
            id: session_id.clone(),
            user_id: user.id.clone(),
            token: token_pair.access_token.clone(),
            refresh_token: Some(token_pair.refresh_token.clone()),
            ip_address: "unknown".to_string(), // Request context not available here
            user_agent: "unknown".to_string(),
            created_at: now,
            expires_at,
            last_accessed: now,
        };

        // Serialize session
        let session_data = serde_json::to_vec(&session)
            .map_err(|e| secreton_errors::SecretonError::Internal { message: format!("Failed to serialize session: {}", e) })?;

        // Create storage entry
        let entry = SecretEntry::new(
            format!("{}{}", SESSION_STORAGE_PREFIX, session_id),
            session_data,
            EncryptionMetadata::default(), // No actual encryption for now as we don't have CryptoService active
            SecurityLevel::Secret,
            Uuid::parse_str(&user.id).unwrap_or_default(),
        ).with_expiration(expires_at);

        // Store session
        self.storage.store(&entry).await
            .map_err(|e| secreton_errors::SecretonError::Authentication { message: format!("Failed to store session: {}", e) })?;

        Ok(ApiLoginResponse {
            token: AuthToken {
                access_token: token_pair.access_token,
                refresh_token: token_pair.refresh_token,
                token_type: token_pair.token_type,
                expires_in: token_pair.expires_in,
                user,
            }
        })
    }

    /// Validate access token
    pub async fn validate_token(&self, token: &str) -> Result<User, AuthError> {
        // Check blacklist
        if self.is_token_revoked(token).await {
            return Err(AuthError::InvalidToken);
        }

        let claims = self.token_service.validate_access_token(token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Convert claims to User (simplified)
        Ok(User {
            id: claims.claims.sub,
            username: claims.claims.username.clone(),
            email: claims.claims.email.clone(),
            password_hash: "".to_string(),
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: claims.claims.roles.clone(),
            policies: vec!["default".to_string()],
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        })
    }

    /// Revoke a token
    pub async fn revoke_token(&self, token: String, expires_at: chrono::DateTime<chrono::Utc>) {
        let mut blacklist = self.token_blacklist.write().await;
        // Clean up expired entries while we're at it
        blacklist.retain(|_, &mut exp| exp > chrono::Utc::now());
        blacklist.insert(token, expires_at);
    }

    /// Check if a token is revoked
    pub async fn is_token_revoked(&self, token: &str) -> bool {
        let blacklist = self.token_blacklist.read().await;
        if let Some(expires_at) = blacklist.get(token) {
            *expires_at > chrono::Utc::now()
        } else {
            false
        }
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthToken, AuthError> {
        let token_pair = self.token_service.refresh_access_token(refresh_token)
            .map_err(|_| AuthError::InvalidToken)?;

        // For refresh, we need to get user info again
        // This is simplified - in production you'd cache or store user info
        let claims = self.token_service.validate_access_token(&token_pair.access_token)
            .map_err(|_| AuthError::InvalidToken)?;

        let user = User {
            id: claims.claims.sub.clone(),
            username: claims.claims.username.clone(),
            email: claims.claims.email.clone(),
            display_name: None,
            disabled: false,
            password_hash: "".to_string(),
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: claims.claims.roles.clone(),
            policies: vec!["default".to_string()],
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        Ok(AuthToken {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_in: token_pair.expires_in,
            user,
        })
    }

    /// Create user (simplified - delegates to unified auth system)
    pub async fn create_user(
        &self,
        username: &str,
        email: &str,
        _password: &str,
        roles: Vec<String>,
    ) -> Result<User, AuthError> {
        // This is a simplified implementation
        // In production, this would delegate to user management service
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            email: Some(email.to_string()),
            password_hash: "".to_string(), // Not stored in API layer
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles,
            policies: vec!["default".to_string()],
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        Ok(user)
    }

    /// Check if user has permission (simplified)
    pub async fn has_permission(&self, user: &User, permission: &str) -> Result<bool, AuthError> {
        // Simplified permission check based on roles
        // In production, this would use a proper RBAC system
        if user.roles.contains(&"admin".to_string()) {
            return Ok(true);
        }

        // Check for specific permissions based on roles
        match permission {
            "secreton:read" | "secreton:list" => {
                Ok(user.roles.contains(&"user".to_string()) || user.roles.contains(&"viewer".to_string()))
            }
            "secreton:write" => {
                Ok(user.roles.contains(&"user".to_string()))
            }
            _ => Ok(false),
        }
    }

    /// Get total user count
    pub async fn get_user_count(&self) -> Result<u64, AuthError> {
        let params = QueryParams::new().with_path_prefix(USER_STORAGE_PREFIX.to_string());
        let count = self.storage.count(&params).await?;
        Ok(count)
    }

    /// Get active session count
    pub async fn get_active_session_count(&self) -> Result<u64, AuthError> {
        let params = QueryParams {
            path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
            ..Default::default()
        };

        let count = self.storage.count(&params).await
            .map_err(AuthError::Storage)?;

        Ok(count)
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, AuthError> {
        // TODO: Optimize this for large datasets. Currently it fetches all sessions and filters in memory.
        // A better approach would be to have the storage backend support filtering by expiration or
        // a dedicated expiration index.
        let params = QueryParams {
            path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
            include_expired: true,
            ..Default::default()
        };

        let entries = self.storage.list(&params).await
            .map_err(AuthError::Storage)?;

        let mut deleted_count = 0;
        let now = chrono::Utc::now();

        for entry in entries {
            let is_expired = if let Some(expires_at) = entry.expires_at {
                expires_at < now
            } else {
                false
            };

            if is_expired {
                if let Err(e) = self.storage.delete_by_path(&entry.path).await {
                    tracing::warn!("Failed to delete expired session {}: {}", entry.path, e);
                    continue;
                }
                deleted_count += 1;
            }
        }

        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired sessions", deleted_count);
        }

        Ok(deleted_count)
    }

    /// Verify password for a user
    pub async fn verify_password(&self, username: &str, password: &str) -> Result<bool, AuthError> {
        let request = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
            mfa_code: None,
            remember_me: None,
        };

        match self.auth_service.login(&request).await {
            Ok(response) => Ok(response.success),
            Err(_) => Ok(false),
        }
    }

    /// Generate access token for user
    pub async fn generate_token(&self, user: &User) -> Result<String, AuthError> {
        self.token_service.create_access_token(
            &user.id,
            &user.username,
            user.email.as_deref(),
            &user.roles,
            &user.policies,
            false, // MFA not required for simple token generation
        ).map_err(|e| AuthError::Internal(anyhow::anyhow!("Token generation failed: {}", e)))
    }

    /// Generate refresh token for user
    pub async fn generate_refresh_token(&self, user: &User) -> Result<String, AuthError> {
        // Generate a longer-lived refresh token
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::days(7);
        
        let claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone().unwrap_or_default(),
            roles: user.roles.clone(),
            iat: now.timestamp() as usize,
            exp: exp.timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: self.config.jwt.issuer.clone(),
            aud: self.config.jwt.audience.clone(),
        };
        
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(self.config.jwt.secret.as_bytes()),
        ).map_err(|e| AuthError::Internal(anyhow::anyhow!("Refresh token generation failed: {}", e)))?;
        
        Ok(token)
    }

    /// Authenticate user
    pub async fn authenticate(&self, credentials: crate::services::auth::LoginRequest) -> Result<secreton_core::AuthResult, AuthError> {
        let request = secreton_auth::LoginRequest {
            username: credentials.username,
            password: credentials.password,
            mfa_code: credentials.mfa_code,
            remember_me: credentials.remember_me,
        };

        let result = self.auth_service.login(&request).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Auth failed: {}", e)))?;

        if !result.success {
             return Err(AuthError::InvalidCredentials);
        }

        // Generate token explicitly if not part of AuthResult yet in this version,
        // or ensure AuthResult has what we need. 
        // Logic in login() (line 175) generates tokens using self.token_service.
        // We should replicate that or use it.

        let user_info = result.user_info.as_ref()
            .ok_or(AuthError::Internal(anyhow::anyhow!("No user info")))?;
        
        let user_roles = &user_info.roles;
        let policies = vec!["default".to_string()]; // Placeholder policies

        // Generate tokens
        let token_pair = self.token_service.create_token_pair(
            user_info.id.as_deref().unwrap_or_default(),
            &user_info.username,
            user_info.email.as_deref(),
            user_roles,
            &policies,
            result.mfa_required,
        ).map_err(|_| AuthError::Internal(anyhow::anyhow!("Token generation failed")))?;

        Ok(secreton_core::AuthResult {
            success: true,
            token: Some(token_pair.access_token),
            user_info: result.user_info,
            policies,
            metadata: std::collections::HashMap::new(),
            mfa_required: result.mfa_required,
        })
    }

    /// OAuth login - create or update user from OAuth info
    pub async fn oauth_login(&self, oauth_user: &crate::handlers::auth::OAuthUserInfo) -> Result<User, AuthError> {
        // Try to find existing user by OAuth ID or email
        // For now, create a stub user
        let user = User {
            id: oauth_user.id.clone(),
            username: if oauth_user.username.is_empty() { oauth_user.email.clone() } else { oauth_user.username.clone() },
            email: Some(oauth_user.email.clone()),
            display_name: Some(oauth_user.name.clone()),
            disabled: false,
            password_hash: "".to_string(), // OAuth users don't have password
            full_name: Some(oauth_user.name.clone()),
            is_active: true,
            is_superuser: false,
            roles: vec!["user".to_string()],
            policies: vec!["default".to_string()],
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
        };
        
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::services::crypto::CryptoService;
    // use secreton_crypto::SecurityParams;
    use secreton_storage::MockStorageBackend;

    #[tokio::test]
    async fn test_auth_service_creation() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let config = AuthConfig::default();

        let auth_service = AuthenticationService::new(storage, crypto, &config).await;
        assert!(auth_service.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        use secreton_storage::{SecretEntry, EncryptionMetadata, SecurityLevel};
        use uuid::Uuid;

        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let config = AuthConfig::default();

        let auth_service = AuthenticationService::new(storage.clone(), crypto, &config).await.unwrap();

        // Add expired session
        let expired_session = SecretEntry::new(
            "sys/auth/sessions/expired1".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        ).with_expiration(chrono::Utc::now() - chrono::Duration::hours(1));
        storage.store(&expired_session).await.unwrap();

        // Add active session
        let active_session = SecretEntry::new(
            "sys/auth/sessions/active1".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        ).with_expiration(chrono::Utc::now() + chrono::Duration::hours(1));
        storage.store(&active_session).await.unwrap();

        // Add unrelated expired entry
        let unrelated_expired = SecretEntry::new(
            "other/path/expired2".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        ).with_expiration(chrono::Utc::now() - chrono::Duration::hours(1));
        storage.store(&unrelated_expired).await.unwrap();

        // Run cleanup
        let cleaned_count = auth_service.cleanup_expired_sessions().await.unwrap();

        // Verify results
        assert_eq!(cleaned_count, 1, "Should cleanup exactly 1 session");

        // Check storage state
        assert!(!storage.exists("sys/auth/sessions/expired1").await.unwrap(), "Expired session should be removed");
        assert!(storage.exists("sys/auth/sessions/active1").await.unwrap(), "Active session should remain");
        assert!(storage.exists("other/path/expired2").await.unwrap(), "Unrelated expired entry should remain");
    }

    #[tokio::test]
    async fn test_get_user_count() {
        use secreton_storage::{SecretEntry, EncryptionMetadata, SecurityLevel};

        let storage = Arc::new(MockStorageBackend::new());

        // Add some dummy users
        let user1 = SecretEntry::new(
            format!("{}user1", USER_STORAGE_PREFIX),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let user2 = SecretEntry::new(
            format!("{}user2", USER_STORAGE_PREFIX),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let other = SecretEntry::new(
            "secrets/something".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );

        storage.store(&user1).await.unwrap();
        storage.store(&user2).await.unwrap();
        storage.store(&other).await.unwrap();

        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let config = AuthConfig::default();
        let auth_service = AuthenticationService::new(storage, crypto, &config).await.unwrap();

        let count = auth_service.get_user_count().await.unwrap();
        assert_eq!(count, 2);
    }
}
