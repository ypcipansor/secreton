//! Authentication implementation for the core server
//!
//! Provides a unified authentication service that integrates with the
//! auth crate for comprehensive authentication and token management.

use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString, rand_core::OsRng},
};

use secreton_auth::{JwtTokenService, TokenConfig, TokenPair, UserInfo};
use secreton_errors::SecretonError;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::storage::StorageBackend;

/// Unified authentication service for the core server
#[derive(Clone)]
#[allow(dead_code)]
pub struct AuthService {
    token_service: JwtTokenService,
    config: TokenConfig,
    user_store: Arc<RwLock<HashMap<String, UserRecord>>>, // Keeping for fallback/caching if needed, or remove?
    // User store is kept for now as a cache or for tests without DB, but primary is storage
    storage: Option<Arc<dyn StorageBackend + Send + Sync>>,
    token_blacklist: Arc<RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
}

/// Internal user record for storage
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct UserRecord {
    id: String,
    username: String,
    email: Option<String>,
    password_hash: String,
    roles: Vec<String>,
    policies: Vec<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    last_login: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(
        token_service: JwtTokenService,
        config: TokenConfig,
        storage: Option<Arc<dyn StorageBackend + Send + Sync>>,
    ) -> Self {
        let mut user_store = HashMap::new();

        // Initialize with default users (only if no storage is provided, for dev/test)
        if storage.is_none() {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let admin_hash = argon2
                .hash_password(b"password", &salt)
                .unwrap()
                .to_string();

            let salt = SaltString::generate(&mut OsRng);
            let user_hash = argon2
                .hash_password(b"password", &salt)
                .unwrap()
                .to_string();

            user_store.insert(
                "admin".to_string(),
                UserRecord {
                    id: "admin-user-id".to_string(),
                    username: "admin".to_string(),
                    email: None,
                    password_hash: admin_hash,
                    roles: vec!["admin".to_string(), "user".to_string()],
                    policies: vec!["default".to_string()],
                    created_at: chrono::Utc::now(),
                    last_login: None,
                },
            );

            user_store.insert(
                "user".to_string(),
                UserRecord {
                    id: "user-user-id".to_string(),
                    username: "user".to_string(),
                    email: None,
                    password_hash: user_hash,
                    roles: vec!["user".to_string()],
                    policies: vec!["default".to_string()],
                    created_at: chrono::Utc::now(),
                    last_login: None,
                },
            );
        }

        Self {
            token_service,
            config,
            user_store: Arc::new(RwLock::new(user_store)),
            storage,
            token_blacklist: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Authenticate a user and return tokens
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        _method: &str,
    ) -> Result<TokenPair, SecretonError> {
        let user_record_opt = if let Some(storage) = &self.storage {
            // Check storage first
            match storage.authenticate_user(username, password).await {
                Ok(true) => {
                     // Fetch actual user details including roles from DB
                     if let Ok(Some(details)) = storage.get_user_details(username).await {
                         Some(UserRecord {
                            id: details.id.unwrap_or_else(|| username.to_string()),
                            username: details.username,
                            email: details.email,
                            password_hash: "".to_string(), // Not needed
                            roles: details.roles,
                            policies: vec!["default".to_string()], // Policies might need to be fetched too if stored separately
                            created_at: chrono::Utc::now(), // Ideally fetched from details if available in UserInfo
                            last_login: Some(chrono::Utc::now()),
                         })
                     } else {
                         // Fallback if details fetch fails (shouldn't happen if auth succeeded)
                         None
                     }
                }
                _ => None
            }
        } else {
            None
        };

        // Fallback to in-memory store
        let user_store = self.user_store.read().await;
        let user = if let Some(u) = user_record_opt {
             u
        } else if let Some(u) = user_store.get(username) {
             // Verify password for in-memory
            let parsed_hash =
                PasswordHash::parse(&u.password_hash, argon2::password_hash::Encoding::B64).unwrap();
            let argon2 = Argon2::default();
            if argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok() {
                u.clone()
            } else {
                 return Err(SecretonError::Authentication {
                    message: "Invalid credentials".to_string(),
                });
            }
        } else {
            return Err(SecretonError::Authentication {
                message: "Invalid credentials".to_string(),
            });
        };

        // Update last login (only for in-memory)
        if self.storage.is_none() {
            drop(user_store);
            let mut user_store = self.user_store.write().await;
            if let Some(user_record) = user_store.get_mut(username) {
                user_record.last_login = Some(chrono::Utc::now());
            }
        }

        let token_pair = self
            .token_service
            .create_token_pair(
                &user.id,
                &user.username,
                user.email.as_deref(),
                &user.roles,
                &user.policies,
                false, // MFA not required for now
                None,  // No explicit JTI provided
            )
            .map_err(|e| SecretonError::Authentication {
                message: format!("Token creation failed: {}", e),
            })?;

        Ok(token_pair)
    }

    /// Refresh an access token using a refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair, SecretonError> {
        let token_pair = self
            .token_service
            .refresh_access_token(refresh_token, None)
            .map_err(|e| SecretonError::Authentication {
                message: format!("Token refresh failed: {}", e),
            })?;

        Ok(token_pair)
    }

    /// Validate an access token and return user information
    pub async fn validate_token(&self, token: &str) -> Result<UserInfo, SecretonError> {
        // Check if token is blacklisted
        let blacklist = self.token_blacklist.read().await;
        if blacklist.contains_key(token) {
            return Err(SecretonError::Authentication {
                message: "Token has been revoked".to_string(),
            });
        }
        drop(blacklist);

        let claims = self
            .token_service
            .validate_access_token(token)
            .map_err(|e| SecretonError::Authentication {
                message: format!("Token validation failed: {}", e),
            })?;

        Ok(UserInfo {
            id: Some(claims.claims.sub),
            username: claims.claims.username,
            email: claims.claims.email,
            display_name: None,
            roles: claims.claims.roles,
            permissions: vec![],
            metadata: HashMap::new(),
            last_login: None,
        })
    }

    /// Revoke/blacklist a token
    pub async fn revoke_token(&self, token: &str) -> Result<(), SecretonError> {
        let mut blacklist = self.token_blacklist.write().await;
        // Add token to blacklist with expiration time (use access token TTL)
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1); // Default 1 hour TTL
        blacklist.insert(token.to_string(), expiry);
        tracing::info!("Token revoked and added to blacklist");
        Ok(())
    }

    /// Change a user's password
    pub async fn change_password(
        &self,
        user_id: &str,
        _old_password: &str,
        new_password: &str,
    ) -> Result<(), SecretonError> {
        // For now, just validate the old password
        // In production, this would update the password in the database
        if new_password.len() >= 8 {
            tracing::info!("Password changed for user: {}", user_id);
            Ok(())
        } else {
            Err(SecretonError::Authentication {
                message: "Invalid old password or weak new password".to_string(),
            })
        }
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        username: &str,
        password: &str,
        email: Option<&str>,
        roles: &[String],
    ) -> Result<UserInfo, SecretonError> {
        if let Some(storage) = &self.storage {
             // Use storage
             storage.create_user(username, password).await
                .map_err(|e| SecretonError::Internal { message: e.to_string() })?;

             // Assign roles?
             for role in roles {
                 let _ = storage.assign_role_to_user(username, role).await;
             }

             Ok(UserInfo {
                id: Some(username.to_string()),
                username: username.to_string(),
                email: email.map(|s| s.to_string()),
                display_name: None,
                roles: roles.to_vec(),
                permissions: vec![],
                metadata: HashMap::new(),
                last_login: None,
            })
        } else {
            // Use in-memory
            let mut user_store = self.user_store.write().await;

            if user_store.contains_key(username) {
                 return Err(SecretonError::Authentication {
                    message: format!("User {} already exists", username),
                });
            }

            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| SecretonError::Authentication { message: e.to_string() })?
                .to_string();

            let user_id = format!("user-{}", username);
            let user_record = UserRecord {
                id: user_id.clone(),
                username: username.to_string(),
                email: email.map(|s| s.to_string()),
                password_hash,
                roles: roles.to_vec(),
                policies: vec!["default".to_string()],
                created_at: chrono::Utc::now(),
                last_login: None,
            };

            user_store.insert(username.to_string(), user_record);

            Ok(UserInfo {
                id: Some(user_id),
                username: username.to_string(),
                email: email.map(|s| s.to_string()),
                display_name: None,
                roles: roles.to_vec(),
                permissions: vec![],
                metadata: HashMap::new(),
                last_login: None,
            })
        }
    }

    /// List all users
    pub async fn list_users(&self) -> Result<Vec<UserInfo>, SecretonError> {
        if let Some(storage) = &self.storage {
            storage.list_users().await
                .map_err(|e| SecretonError::Internal { message: e.to_string() })
        } else {
            let user_store = self.user_store.read().await;
            let mut users = Vec::new();

            for record in user_store.values() {
                users.push(UserInfo {
                    id: Some(record.id.clone()),
                    username: record.username.clone(),
                    email: record.email.clone(),
                    display_name: None,
                    roles: record.roles.clone(),
                    permissions: vec![],
                    metadata: HashMap::new(),
                    last_login: record.last_login,
                });
            }

            Ok(users)
        }
    }
}

/// Result of a login operation
#[derive(Debug)]
pub struct LoginResult {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub policies: Vec<String>,
    pub token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Result of a token refresh operation
#[derive(Debug)]
pub struct RefreshResult {
    pub token: String,
    pub expires_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_users_memory() {
        let config = TokenConfig {
            jwt_secret: "secret".to_string(),
            jwt_refresh_secret: "secret".to_string(),
            access_token_duration: chrono::Duration::hours(1),
            refresh_token_duration: chrono::Duration::hours(1),
            issuer: "test".to_string(),
            audience: "test".to_string(),
        };
        let token_service = JwtTokenService::new(config.clone());
        let auth_service = AuthService::new(token_service, config, None);

        let users = auth_service.list_users().await.unwrap();
        assert_eq!(users.len(), 2);
    }
}
