//! # Brankas Authentication
//!
//! Authentication and authorization system for the Brankas security vault.
//! Provides multi-factor authentication, role-based access control,
//! and secure token management.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod agent_auth;
pub mod agent_templating;
pub mod authentication;
pub mod identity;
pub mod mfa;
// pub mod privacy_preserving_auth; // Moved to enterprise crate
pub mod revocation;
pub mod token;

// Feature-gated modules
#[cfg(feature = "ldap")]
pub mod ldap;

// Re-export shared crates
pub use secreton_common::{SecurityLevel, Result as CommonResult};
pub use secreton_errors::{self, SecretonError};
pub use secreton_config::*;

// Re-export main types
pub use identity::{Entity as Identity, IdentityService as IdentityProvider};
pub use revocation::{RevocationRegistry, RevocationScope, RevocationEvent};
pub use token::{Token, TokenType};

// Type alias for backward compatibility
pub type AuthError = SecretonError;
pub type AuthResult<T> = std::result::Result<T, SecretonError>;

// Type alias for MFA method (backward compatibility)
pub use crate::mfa::MfaMethodType as MfaMethod;

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    /// Whether authentication was successful
    pub success: bool,
    /// User identity if authenticated
    pub identity: Option<Identity>,
    /// Authentication metadata
    pub metadata: HashMap<String, String>,
    /// Token if authentication successful
    pub token: Option<Token>,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Authentication manager trait
#[async_trait::async_trait]
pub trait AuthManager: Send + Sync {
    /// Authenticate a user with given credentials
    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthResult<AuthenticationResult>;

    /// Validate a token
    async fn validate_token(&self, token: &str) -> AuthResult<Token>;

    /// Revoke a token
    async fn revoke_token(&self, token: &str) -> AuthResult<()>;

    /// Create a new token for an identity
    async fn create_token(&self, identity: &Identity, token_type: TokenType) -> AuthResult<Token>;
}

/// Authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthCredentials {
    /// Username/password authentication
    Userpass { username: String, password: String },
    /// Token-based authentication
    Token(String),
    /// LDAP authentication
    #[cfg(feature = "ldap")]
    Ldap { username: String, password: String },
    /// OAuth2 authentication
    OAuth2 { provider: String, code: String },
}