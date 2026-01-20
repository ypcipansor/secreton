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
use secreton_auth::{AuthService as UnifiedAuthService, LoginRequest, TokenConfig, JwtTokenService, UserPassAuthMethod, User, AuthResult};
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
#[derive(Debug, Serialize, Deserialize, Clone)]
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

    /// UserPass method (kept for direct user management)
    userpass_method: Arc<UserPassAuthMethod>,

    /// Token service for JWT operations
    token_service: JwtTokenService,

    /// Storage backend for sessions
    storage: Arc<dyn StorageBackend + Send + Sync>,

    /// Configuration
    config: AuthConfig,

    /// Token blacklist
    token_blacklist: Arc<tokio::sync::RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,

    /// Crypto service
    crypto: Arc<CryptoService>,

    /// Audit logger
    audit: Option<Arc<crate::services::audit::AuditLogger>>,
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
            jwt_secret: config.jwt.secret.clone().expect("JWT secret must be configured"),
            jwt_refresh_secret: config.jwt.secret.clone().expect("JWT secret must be configured"), // Use same secret as no refresh_secret field
            access_token_duration: chrono::Duration::from_std(std::time::Duration::from_secs(config.jwt.expiration)).unwrap_or(chrono::Duration::hours(1)),
            refresh_token_duration: chrono::Duration::from_std(std::time::Duration::from_secs(config.jwt.refresh_expiration)).unwrap_or(chrono::Duration::days(7)),
            issuer: config.jwt.issuer.clone(),
            audience: config.jwt.audience.clone(),
        };
        let token_service = JwtTokenService::new(token_config);

        // Create unified auth service
        let auth_service = Arc::new(UnifiedAuthService::new());

        // Register default authentication methods
        let mut userpass_method_impl = UserPassAuthMethod::new();
        // Initialize/Enable the method
        // Manually enable as we are skipping the full init flow for built-in method
        use secreton_auth::service::AuthMethodImpl;
        let _ = userpass_method_impl.init(&secreton_auth::model::AuthMethod {
            method_type: secreton_auth::model::AuthMethodType::UserPass,
            enabled: true,
            config: HashMap::new(),
        }).await;

        let userpass_method = Arc::new(userpass_method_impl);
        auth_service.register_method("userpass".to_string(), userpass_method.clone()).await;

        // Load existing users from storage
        let params = QueryParams::new().with_path_prefix(USER_STORAGE_PREFIX.to_string());
        if let Ok(entries) = storage.list(&params).await {
            for entry in entries {
                // Try decrypting the data, strictly requiring encryption
                let user_data = match crypto.decrypt(&entry.encrypted_data).await {
                    Ok(decrypted) => decrypted,
                    Err(_) => {
                        // Skip users with invalid encryption (removes plaintext fallback weakness)
                        continue;
                    }
                };

                if let Ok(user) = serde_json::from_slice::<User>(&user_data) {
                    userpass_method.add_user(
                        user.username.clone(),
                        user.password_hash.clone(),
                        user.id.clone(),
                        user.roles.clone(),
                        user.policies.clone(),
                        user.permissions.clone(),
                    ).await;
                }
            }
        }

        Ok(Self {
            auth_service,
            userpass_method,
            token_service,
            storage,
            config: config.clone(),
            token_blacklist: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            audit: None,
            crypto,
        })
    }

    pub fn with_audit(mut self, audit: Arc<crate::services::audit::AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Authenticate user with username and password
    pub async fn login(&self, req: ApiLoginRequest) -> ApiResult<ApiLoginResponse> {
        // Check lockout status before attempting login
        let user_path = format!("{}{}", USER_STORAGE_PREFIX, req.username);
        let user_entry = self.storage.get_by_path(&user_path).await.ok().flatten();
        let mut stored_user: Option<User> = None;

        if let Some(ref entry) = user_entry {
            // Decrypt and deserialize user
            if let Ok(decrypted) = self.crypto.decrypt(&entry.encrypted_data).await {
                if let Ok(u) = serde_json::from_slice::<User>(&decrypted) {
                    stored_user = Some(u.clone());
                    if let Some(locked_until) = u.locked_until {
                        if locked_until > chrono::Utc::now() {
                            if let Some(audit) = &self.audit {
                                let _ = audit.log_event(crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: req.username.clone(),
                                    method: "userpass".to_string(),
                                    reason: "Account locked".to_string(),
                                }).await;
                            }
                            return Err(secreton_errors::SecretonError::Authentication { message: "Account is locked. Please try again later.".to_string() }.into());
                        }
                    }
                }
            }
        }

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
            // Handle failed login attempt
            if let Some(mut u) = stored_user {
                u.failed_login_attempts += 1;

                // Max attempts check (e.g. 5), but exempt privileged users from auto-lockout (DoS protection)
                if !u.is_privileged() && u.failed_login_attempts >= 5 {
                     u.locked_until = Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                     // Log lockout
                     if let Some(audit) = &self.audit {
                        let _ = audit.log_event(crate::services::audit::SecurityEventType::AuthenticationFailure {
                            user: req.username.clone(),
                            method: "userpass".to_string(),
                            reason: "Account locked due to too many failed attempts".to_string(),
                        }).await;
                    }
                }

                // Encrypt and update user in storage
                if let Ok(user_data) = serde_json::to_vec(&u) {
                    if let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await {
                        if let Some(mut entry) = user_entry {
                            entry.encrypted_data = encrypted;
                            let _ = self.storage.store(&entry).await;
                        }
                    }
                }
            }

            return Err(secreton_errors::SecretonError::Authentication { message: "Invalid credentials".to_string() }.into());
        }

        let user_info = response.user_info
            .ok_or_else(|| secreton_errors::SecretonError::Internal { message: "No user info returned".to_string() })?;

        // Convert UserInfo to User (simplified)
        let mut user = if let Some(u) = stored_user {
             u
        } else {
             User {
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
                permissions: vec![],
                policies: vec!["default".to_string()], // Default policies as UserInfo lacks them
                enabled: true,
                mfa_enabled: false,
                mfa_secret: None,
                last_login: None, // UserInfo lacks last_login
                created_at: chrono::Utc::now(), // UserInfo lacks created_at
                updated_at: chrono::Utc::now(),
                metadata: user_info.metadata.clone(),
                failed_login_attempts: 0,
                locked_until: None,
            }
        };

        // Reset failed login attempts on success
        // Also ensure user is persisted if it didn't exist (new user)
        let should_persist = user_entry.is_none() || user.failed_login_attempts > 0 || user.locked_until.is_some();

        if user.failed_login_attempts > 0 || user.locked_until.is_some() {
            user.failed_login_attempts = 0;
            user.locked_until = None;
        }

        if should_persist {
             // Update user in storage
             if let Ok(user_data) = serde_json::to_vec(&user) {
                if let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await {
                    let entry = if let Some(mut e) = user_entry {
                        e.encrypted_data = encrypted;
                        e
                    } else {
                         SecretEntry::new(
                            user_path,
                            encrypted,
                            EncryptionMetadata::default(),
                            SecurityLevel::Secret,
                            Uuid::parse_str(&user.id).unwrap_or_default(),
                        )
                    };
                    let _ = self.storage.store(&entry).await;
                }
            }
        }

        // Generate session ID first to bind it to the token
        let session_id = Uuid::new_v4().to_string();

        // Create and store session
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::from_std(std::time::Duration::from_secs(self.config.jwt.expiration))
            .unwrap_or(chrono::Duration::hours(1));

        // Create token pair with session binding
        let token_pair = self.token_service.create_token_pair(
            &user.id,
            &user.username,
            user.email.as_deref(), // Convert Option<&String> to Option<&str>
            &user.roles,
            &user.policies, // Use user.policies which we just created
            false, // MFA status from auth result
            Some(session_id.clone()),
        ).map_err(|e| secreton_errors::SecretonError::Authentication { message: e.to_string() })?;

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

        // Verify session binding (Security hardening)
        // Ensure the session associated with this token still exists and is valid
        let session_path = format!("{}{}", SESSION_STORAGE_PREFIX, claims.claims.jti);
        if !self.storage.exists(&session_path).await.unwrap_or(false) {
             return Err(AuthError::InvalidToken);
        }

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
            permissions: vec![],
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
            failed_login_attempts: 0,
            locked_until: None,
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
        // Validate first to get user info for session creation
        let claims = self.token_service.validate_refresh_token(refresh_token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Generate session ID
        let session_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::from_std(std::time::Duration::from_secs(self.config.jwt.expiration))
            .unwrap_or(chrono::Duration::hours(1));

        let token_pair = self.token_service.refresh_access_token(refresh_token, Some(session_id.clone()))
            .map_err(|_| AuthError::InvalidToken)?;

        // Store session
        let session = Session {
            id: session_id.clone(),
            user_id: claims.sub.clone(),
            token: token_pair.access_token.clone(),
            refresh_token: Some(token_pair.refresh_token.clone()),
            ip_address: "unknown".to_string(),
            user_agent: "unknown".to_string(),
            created_at: now,
            expires_at,
            last_accessed: now,
        };

        let session_data = serde_json::to_vec(&session)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Failed to serialize session: {}", e)))?;

        let entry = SecretEntry::new(
            format!("{}{}", SESSION_STORAGE_PREFIX, session_id),
            session_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(&claims.sub).unwrap_or_default(),
        ).with_expiration(expires_at);

        self.storage.store(&entry).await.map_err(AuthError::Storage)?;

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
            permissions: vec![],
            policies: vec!["default".to_string()],
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
        };

        Ok(AuthToken {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_in: token_pair.expires_in,
            user,
        })
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        username: &str,
        password: &str,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<User, AuthError> {
        // Check if user exists
        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        if self.storage.exists(&path).await? {
            return Err(AuthError::UserAlreadyExists);
        }

        let user_id = Uuid::new_v4().to_string();

        // Create in UserPass method (generates hash)
        let password_hash = self.userpass_method.create_user(
            username.to_string(),
            password,
            user_id.clone(),
            roles.clone(),
            vec!["default".to_string()],
            permissions.clone(),
        ).await.map_err(|_| AuthError::Internal(anyhow::anyhow!("Failed to create user in auth method")))?;

        let user = User {
            id: user_id,
            username: username.to_string(),
            email: email.clone(),
            password_hash,
            full_name: None,
            is_active: true,
            is_superuser: roles.contains(&"admin".to_string()) || roles.contains(&"root".to_string()),
            roles,
            permissions,
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
            failed_login_attempts: 0,
            locked_until: None,
        };

        // Store user
        let user_data = serde_json::to_vec(&user)
             .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        // Encrypt user data
        let encrypted_data = self.crypto.encrypt_data(&user_data).await
            .map_err(|e| AuthError::Crypto(secreton_crypto::CryptoError::Internal(e.to_string())))?;

        let entry = SecretEntry::new(
            path,
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(&user.id).unwrap_or_default(),
        );

        self.storage.store(&entry).await?;

        Ok(user)
    }

    /// Create user (wrapper for register_user)
    pub async fn create_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<User, AuthError> {
        self.register_user(username, password, Some(email.to_string()), roles, permissions).await
    }

    /// Check if user has permission (simplified)
    pub async fn has_permission(&self, user: &User, permission: &str) -> Result<bool, AuthError> {
        // Simplified permission check based on roles
        // In production, this would use a proper RBAC system
        if user.is_admin() {
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

    /// List sessions for a specific user
    pub async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, AuthError> {
        // We scan all sessions and filter by user_id
        // In a real DB we would index this or use a secondary index
        let params = QueryParams {
            path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
            include_expired: false,
            ..Default::default()
        };

        let entries = self.storage.list(&params).await
            .map_err(AuthError::Storage)?;

        let mut sessions = Vec::new();
        for entry in entries {
            if let Ok(session) = serde_json::from_slice::<Session>(&entry.encrypted_data) {
                if session.user_id == user_id {
                    sessions.push(session);
                }
            } else if let Ok(session) = serde_json::from_slice::<Session>(&entry.encrypted_data) {
                 // Fallback? encrypted_data is actually plaintext in current impl since no crypto used for sessions yet
                 if session.user_id == user_id {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    /// Revoke a specific user session
    pub async fn revoke_user_session(&self, session_id: &str, user_id: &str) -> Result<(), AuthError> {
        let path = format!("{}{}", SESSION_STORAGE_PREFIX, session_id);

        // Verify ownership
        if let Some(entry) = self.storage.get_by_path(&path).await.map_err(AuthError::Storage)? {
             if let Ok(session) = serde_json::from_slice::<Session>(&entry.encrypted_data) {
                 if session.user_id != user_id {
                     return Err(AuthError::PermissionDenied);
                 }
                 // Revoke the token associated with this session
                 self.revoke_token(session.token, session.expires_at).await;
             }
        } else {
            return Err(AuthError::Storage(secreton_storage::StorageError::NotFound {
                resource_type: "session".to_string(),
                id: session_id.to_string()
            }));
        }

        self.storage.delete_by_path(&path).await
            .map_err(AuthError::Storage)?;

        Ok(())
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, AuthError> {
        let deleted_count = self.storage.delete_expired(Some(SESSION_STORAGE_PREFIX.to_string())).await
            .map_err(AuthError::Storage)?;

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
        let session_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::from_std(std::time::Duration::from_secs(self.config.jwt.expiration))
             .unwrap_or(chrono::Duration::hours(1));

        let token = self.token_service.create_access_token(
            &user.id,
            &user.username,
            user.email.as_deref(),
            &user.roles,
            &user.policies,
            false, // MFA not required for simple token generation
            Some(session_id.clone()),
        ).map_err(|e| AuthError::Internal(anyhow::anyhow!("Token generation failed: {}", e)))?;

        // Store session for API token
        let session = Session {
            id: session_id.clone(),
            user_id: user.id.clone(),
            token: token.clone(),
            refresh_token: None,
            ip_address: "api".to_string(),
            user_agent: "api".to_string(),
            created_at: now,
            expires_at,
            last_accessed: now,
        };

        let session_data = serde_json::to_vec(&session)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        let entry = SecretEntry::new(
            format!("{}{}", SESSION_STORAGE_PREFIX, session_id),
            session_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(&user.id).unwrap_or_default(),
        ).with_expiration(expires_at);

        self.storage.store(&entry).await.map_err(AuthError::Storage)?;

        Ok(token)
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
            &jsonwebtoken::EncodingKey::from_secret(self.config.jwt.secret.as_ref().expect("JWT secret must be configured").as_bytes()),
        ).map_err(|e| AuthError::Internal(anyhow::anyhow!("Refresh token generation failed: {}", e)))?;
        
        Ok(token)
    }

    /// Authenticate user
    pub async fn authenticate(&self, credentials: crate::services::auth::LoginRequest) -> Result<AuthResult, AuthError> {
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

        // Generate session ID
        let session_id = Uuid::new_v4().to_string();

        // Generate tokens with session binding
        let token_pair = self.token_service.create_token_pair(
            user_info.id.as_deref().unwrap_or_default(),
            &user_info.username,
            user_info.email.as_deref(),
            user_roles,
            &policies,
            result.mfa_required,
            Some(session_id.clone()),
        ).map_err(|_| AuthError::Internal(anyhow::anyhow!("Token generation failed")))?;

        // Store session
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::from_std(std::time::Duration::from_secs(self.config.jwt.expiration))
             .unwrap_or(chrono::Duration::hours(1));

        let session = Session {
            id: session_id.clone(),
            user_id: user_info.id.clone().unwrap_or_default(),
            token: token_pair.access_token.clone(),
            refresh_token: Some(token_pair.refresh_token.clone()),
            ip_address: "legacy".to_string(),
            user_agent: "legacy".to_string(),
            created_at: now,
            expires_at,
            last_accessed: now,
        };

        let session_data = serde_json::to_vec(&session)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        let entry = SecretEntry::new(
            format!("{}{}", SESSION_STORAGE_PREFIX, session_id),
            session_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(&session.user_id).unwrap_or_default(),
        ).with_expiration(expires_at);

        self.storage.store(&entry).await.map_err(AuthError::Storage)?;

        Ok(AuthResult {
            success: true,
            token: Some(token_pair.access_token),
            refresh_token: Some(token_pair.refresh_token),
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
            permissions: vec![],
            policies: vec!["default".to_string()],
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
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
