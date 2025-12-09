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

use crate::config::AuthConfig;
use secreton_crypto::CryptoService;
use secreton_storage::{StorageBackend, EncryptionMetadata, SecurityLevel};
use secreton_auth::{AuthService as UnifiedAuthService, AuthMethodImpl, UserInfo, AuthCredentials, AuthResult, LoginRequest, LoginResponse};
use secreton_common::User;

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

/// Authentication service facade
pub struct AuthenticationService {
    /// Unified authentication service
    auth_service: Arc<UnifiedAuthService>,

    /// Token service for JWT operations
    token_service: TokenService,

    /// Storage backend for sessions
    storage: Arc<dyn StorageBackend + Send + Sync>,

    /// Configuration
    config: AuthConfig,
}

impl AuthenticationService {
    /// Create new authentication service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        config: &AuthConfig,
    ) -> Result<Self> {
        // Create token service
        let token_config = TokenConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_refresh_secret: config.jwt.refresh_secret.clone().unwrap_or_else(|| config.jwt.secret.clone()),
            access_token_duration: config.jwt.expiration,
            refresh_token_duration: config.jwt.refresh_expiration.unwrap_or(config.jwt.expiration * 7),
            issuer: config.jwt.issuer.clone(),
            audience: config.jwt.audience.clone(),
        };
        let token_service = TokenService::new(token_config);

        // Create unified auth service
        let auth_service = Arc::new(UnifiedAuthService::new());

        Ok(Self {
            auth_service,
            token_service,
            storage,
            config: config.clone(),
        })
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
        // Create login request
        let credentials = AuthCredentials::Userpass {
            username: username.to_string(),
            password: password.to_string(),
        };

        let request = LoginRequest {
            method: "userpass".to_string(),
            credentials,
            mfa_code: mfa_code.map(|s| s.to_string()),
        };

        // Authenticate using unified auth service
        let response = self.auth_service.login(&request).await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Authentication failed: {}", e)))?;

        if !response.auth.success {
            return Err(AuthError::InvalidCredentials);
        }

        let user_info = response.auth.user_info
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("No user info returned")))?;

        // Convert UserInfo to User (simplified)
        let user = User {
            id: user_info.id.clone(),
            username: user_info.username.clone(),
            email: user_info.email,
            password_hash: "".to_string(), // Not used in API responses
            full_name: user_info.display_name,
            is_active: true,
            is_superuser: false,
            roles: user_info.roles.clone(),
            policies: user_info.policies.clone(),
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: user_info.last_login,
            created_at: user_info.created_at,
            updated_at: user_info.created_at,
            metadata: user_info.metadata.clone(),
        };

        // Create token pair
        let token_pair = self.token_service.create_token_pair(
            &user.id,
            &user.username,
            Some(&user.email),
            &user.roles,
            &user_info.policies,
            false, // MFA status from auth result
        ).map_err(|e| AuthError::Internal(anyhow::anyhow!("Token creation failed: {}", e)))?;

        Ok(AuthToken {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_in: token_pair.expires_in,
            user,
        })
    }

    /// Validate access token
    pub async fn validate_token(&self, token: &str) -> Result<User, AuthError> {
        let claims = self.token_service.validate_access_token(token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Convert claims to User (simplified)
        Ok(User {
            id: claims.sub,
            username: claims.username,
            email: claims.email,
            password_hash: "".to_string(),
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: claims.roles,
            policies: vec!["default".to_string()],
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        })
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
            id: claims.sub,
            username: claims.username,
            email: claims.email,
            password_hash: "".to_string(),
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: claims.roles,
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
        password: &str,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use secreton_crypto::{CryptoService, SecurityParams};
    use secreton_storage::MockStorageBackend;

    #[tokio::test]
    async fn test_auth_service_creation() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();

        let auth_service = AuthenticationService::new(storage, crypto, &config).await;
        assert!(auth_service.is_ok());
    }
}
