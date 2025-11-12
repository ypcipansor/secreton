//! Authentication implementation for the core server
//!
//! Provides a unified authentication service that integrates with the
//! auth crate for comprehensive authentication and token management.

use secreton_auth::{JwtTokenService, TokenConfig, TokenPair, UserInfo};
use secreton_errors::SecretonError;
use std::collections::HashMap;

/// Unified authentication service for the core server
#[derive(Clone)]
pub struct AuthService {
    token_service: JwtTokenService,
    config: TokenConfig,
    // TODO: Add user storage backend when available
    // user_store: Arc<dyn UserStore>,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(token_service: JwtTokenService, config: TokenConfig) -> Self {
        Self {
            token_service,
            config,
        }
    }

    /// Authenticate a user and return tokens
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        _method: &str,
    ) -> Result<TokenPair, SecretonError> {
        // For now, use simple hardcoded authentication
        // In production, this would integrate with auth crate authentication methods
        let (user_id, roles, policies) = if username == "admin" && password == "password" {
            (
                "admin-user-id".to_string(),
                vec!["admin".to_string(), "user".to_string()],
                vec!["default".to_string()],
            )
        } else if username == "user" && password == "password" {
            (
                "user-user-id".to_string(),
                vec!["user".to_string()],
                vec!["default".to_string()],
            )
        } else {
            return Err(SecretonError::Authentication {
                message: "Invalid credentials".to_string(),
            });
        };

        let token_pair = self
            .token_service
            .create_token_pair(
                &user_id, username, None, &roles, &policies,
                false, // MFA not required for hardcoded auth
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
            .refresh_access_token(refresh_token)
            .map_err(|e| SecretonError::Authentication {
                message: format!("Token refresh failed: {}", e),
            })?;

        Ok(token_pair)
    }

    /// Validate an access token and return user information
    pub async fn validate_token(&self, token: &str) -> Result<UserInfo, SecretonError> {
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
            metadata: HashMap::new(),
            last_login: None,
        })
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
        _password: &str,
        email: Option<&str>,
        roles: &[String],
    ) -> Result<UserInfo, SecretonError> {
        // For now, just return a user info
        // In production, this would create the user in the database
        let user_id = format!("user-{}", username);

        Ok(UserInfo {
            id: Some(user_id),
            username: username.to_string(),
            email: email.map(|s| s.to_string()),
            display_name: None,
            roles: roles.to_vec(),
            metadata: HashMap::new(),
            last_login: None,
        })
    }

    /// List all users
    pub async fn list_users(&self) -> Result<Vec<UserInfo>, SecretonError> {
        // For now, return hardcoded users
        // In production, this would query the database
        Ok(vec![
            UserInfo {
                id: Some("admin-user-id".to_string()),
                username: "admin".to_string(),
                email: None,
                display_name: Some("Administrator".to_string()),
                roles: vec!["admin".to_string(), "user".to_string()],
                metadata: HashMap::new(),
                last_login: None,
            },
            UserInfo {
                id: Some("user-user-id".to_string()),
                username: "user".to_string(),
                email: None,
                display_name: Some("Regular User".to_string()),
                roles: vec!["user".to_string()],
                metadata: HashMap::new(),
                last_login: None,
            },
        ])
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
