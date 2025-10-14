//! Authentication and authorization for the Brankas API
//!
//! Provides JWT-based authentication, role-based access control,
//! and integration with external identity providers.

use axum::{
    Json,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{error, warn};
use uuid::Uuid;

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,              // Subject (user ID)
    pub name: String,             // User name
    pub email: String,            // User email
    pub roles: Vec<String>,       // User roles
    pub permissions: Vec<String>, // Specific permissions
    pub iat: u64,                 // Issued at
    pub exp: u64,                 // Expires at
    pub iss: String,              // Issuer
    pub aud: String,              // Audience
    pub jti: String,              // JWT ID
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
    pub issuer: String,
    pub audience: String,
    pub require_auth: bool,
    pub admin_roles: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "your-super-secret-key".to_string(),
            jwt_expiration_hours: 24,
            issuer: "secreton-vault".to_string(),
            audience: "secreton-api".to_string(),
            require_auth: true,
            admin_roles: vec!["admin".to_string(), "vault-admin".to_string()],
        }
    }
}

/// User roles for RBAC
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    VaultAdmin,
    KeyManager,
    CryptoUser,
    ReadOnly,
}

impl UserRole {
    pub fn as_string(&self) -> String {
        match self {
            UserRole::Admin => "admin".to_string(),
            UserRole::VaultAdmin => "vault-admin".to_string(),
            UserRole::KeyManager => "key-manager".to_string(),
            UserRole::CryptoUser => "crypto-user".to_string(),
            UserRole::ReadOnly => "read-only".to_string(),
        }
    }

    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(UserRole::Admin),
            "vault-admin" => Some(UserRole::VaultAdmin),
            "key-manager" => Some(UserRole::KeyManager),
            "crypto-user" => Some(UserRole::CryptoUser),
            "read-only" => Some(UserRole::ReadOnly),
            _ => None,
        }
    }
}

/// Permissions for fine-grained access control
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Permission {
    // Key management permissions
    CreateKey,
    DeleteKey,
    RotateKey,
    ReadKey,
    ListKeys,

    // Cryptographic operation permissions
    Encrypt,
    Decrypt,
    Sign,
    Verify,

    // Utility permissions
    GenerateRandom,
    HashData,
    DeriveKey,

    // Administrative permissions
    ViewMetrics,
    ConfigureSystem,
    ManageUsers,
    AccessAuditLogs,
}

impl Permission {
    pub fn as_string(&self) -> String {
        match self {
            Permission::CreateKey => "create-key".to_string(),
            Permission::DeleteKey => "delete-key".to_string(),
            Permission::RotateKey => "rotate-key".to_string(),
            Permission::ReadKey => "read-key".to_string(),
            Permission::ListKeys => "list-keys".to_string(),
            Permission::Encrypt => "encrypt".to_string(),
            Permission::Decrypt => "decrypt".to_string(),
            Permission::Sign => "sign".to_string(),
            Permission::Verify => "verify".to_string(),
            Permission::GenerateRandom => "generate-random".to_string(),
            Permission::HashData => "hash-data".to_string(),
            Permission::DeriveKey => "derive-key".to_string(),
            Permission::ViewMetrics => "view-metrics".to_string(),
            Permission::ConfigureSystem => "configure-system".to_string(),
            Permission::ManageUsers => "manage-users".to_string(),
            Permission::AccessAuditLogs => "access-audit-logs".to_string(),
        }
    }
}

/// Authentication service for JWT handling
pub struct AuthService {
    config: AuthConfig,
}

impl AuthService {
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Generate JWT token for a user
    pub fn generate_token(
        &self,
        user_id: &str,
        name: &str,
        email: &str,
        roles: Vec<String>,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.config.jwt_expiration_hours);

        // Generate permissions based on roles
        let permissions = self.generate_permissions_from_roles(&roles);

        let claims = Claims {
            sub: user_id.to_string(),
            name: name.to_string(),
            email: email.to_string(),
            roles,
            permissions,
            iat: now.timestamp() as u64,
            exp: exp.timestamp() as u64,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            jti: Uuid::new_v4().to_string(),
        };

        self.create_jwt(&claims)
    }

    /// Validate and decode JWT token
    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let claims = self.verify_jwt(token)?;

        // Check issuer
        if claims.iss != self.config.issuer {
            return Err(AuthError::TokenValidation("Invalid issuer".to_string()));
        }

        // Check audience
        if claims.aud != self.config.audience {
            return Err(AuthError::TokenValidation("Invalid audience".to_string()));
        }

        // Check expiration
        let now = Utc::now().timestamp() as u64;
        if claims.exp < now {
            return Err(AuthError::TokenValidation("Token expired".to_string()));
        }

        Ok(claims)
    }

    /// Check if user has required permission
    pub fn check_permission(&self, claims: &Claims, required_permission: Permission) -> bool {
        let permission_str = required_permission.as_string();

        // Check if user has the specific permission
        if claims.permissions.contains(&permission_str) {
            return true;
        }

        // Check if user has admin role (admins have all permissions)
        for admin_role in &self.config.admin_roles {
            if claims.roles.contains(admin_role) {
                return true;
            }
        }

        false
    }

    /// Generate permissions based on user roles
    fn generate_permissions_from_roles(&self, roles: &[String]) -> Vec<String> {
        let mut permissions = Vec::new();

        for role in roles {
            match UserRole::from_string(role) {
                Some(UserRole::Admin) => {
                    // Admins get all permissions
                    permissions.extend(vec![
                        Permission::CreateKey.as_string(),
                        Permission::DeleteKey.as_string(),
                        Permission::RotateKey.as_string(),
                        Permission::ReadKey.as_string(),
                        Permission::ListKeys.as_string(),
                        Permission::Encrypt.as_string(),
                        Permission::Decrypt.as_string(),
                        Permission::Sign.as_string(),
                        Permission::Verify.as_string(),
                        Permission::GenerateRandom.as_string(),
                        Permission::HashData.as_string(),
                        Permission::DeriveKey.as_string(),
                        Permission::ViewMetrics.as_string(),
                        Permission::ConfigureSystem.as_string(),
                        Permission::ManageUsers.as_string(),
                        Permission::AccessAuditLogs.as_string(),
                    ]);
                }
                Some(UserRole::VaultAdmin) => {
                    permissions.extend(vec![
                        Permission::CreateKey.as_string(),
                        Permission::RotateKey.as_string(),
                        Permission::ReadKey.as_string(),
                        Permission::ListKeys.as_string(),
                        Permission::Encrypt.as_string(),
                        Permission::Decrypt.as_string(),
                        Permission::Sign.as_string(),
                        Permission::Verify.as_string(),
                        Permission::GenerateRandom.as_string(),
                        Permission::HashData.as_string(),
                        Permission::DeriveKey.as_string(),
                        Permission::ViewMetrics.as_string(),
                        Permission::AccessAuditLogs.as_string(),
                    ]);
                }
                Some(UserRole::KeyManager) => {
                    permissions.extend(vec![
                        Permission::CreateKey.as_string(),
                        Permission::RotateKey.as_string(),
                        Permission::ReadKey.as_string(),
                        Permission::ListKeys.as_string(),
                        Permission::ViewMetrics.as_string(),
                    ]);
                }
                Some(UserRole::CryptoUser) => {
                    permissions.extend(vec![
                        Permission::ReadKey.as_string(),
                        Permission::ListKeys.as_string(),
                        Permission::Encrypt.as_string(),
                        Permission::Decrypt.as_string(),
                        Permission::Sign.as_string(),
                        Permission::Verify.as_string(),
                        Permission::GenerateRandom.as_string(),
                        Permission::HashData.as_string(),
                        Permission::DeriveKey.as_string(),
                    ]);
                }
                Some(UserRole::ReadOnly) => {
                    permissions.extend(vec![
                        Permission::ReadKey.as_string(),
                        Permission::ListKeys.as_string(),
                        Permission::ViewMetrics.as_string(),
                    ]);
                }
                None => {
                    warn!("Unknown role: {}", role);
                }
            }
        }

        permissions.sort();
        permissions.dedup();
        permissions
    }

    /// Create JWT token
    fn create_jwt(&self, claims: &Claims) -> Result<String, AuthError> {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header);

        let payload =
            serde_json::to_string(claims).map_err(|e| AuthError::TokenGeneration(e.to_string()))?;
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);

        let message = format!("{}.{}", header_b64, payload_b64);

        let mut mac = Hmac::<Sha256>::new_from_slice(self.config.jwt_secret.as_bytes())
            .map_err(|e| AuthError::TokenGeneration(e.to_string()))?;
        mac.update(message.as_bytes());
        let signature = mac.finalize().into_bytes();
        let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(signature);

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    /// Verify JWT token
    fn verify_jwt(&self, token: &str) -> Result<Claims, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::TokenValidation(
                "Invalid token format".to_string(),
            ));
        }

        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        let message = format!("{}.{}", header_b64, payload_b64);

        let signature = general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|e| AuthError::TokenValidation(e.to_string()))?;

        let mut mac = Hmac::<Sha256>::new_from_slice(self.config.jwt_secret.as_bytes())
            .map_err(|e| AuthError::TokenValidation(e.to_string()))?;
        mac.update(message.as_bytes());

        mac.verify_slice(&signature)
            .map_err(|e| AuthError::TokenValidation(e.to_string()))?;

        let payload = general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| AuthError::TokenValidation(e.to_string()))?;

        let claims: Claims = serde_json::from_slice(&payload)
            .map_err(|e| AuthError::TokenValidation(e.to_string()))?;

        Ok(claims)
    }
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(auth_header: &HeaderValue) -> Option<String> {
    let auth_str = auth_header.to_str().ok()?;
    auth_str
        .strip_prefix("Bearer ")
        .map(|stripped| stripped.to_string())
}

/// Authentication errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Token generation failed: {0}")]
    TokenGeneration(String),

    #[error("Token validation failed: {0}")]
    TokenValidation(String),

    #[error("Missing authorization header")]
    MissingAuthHeader,

    #[error("Invalid authorization header format")]
    InvalidAuthHeader,

    #[error("Missing credentials")]
    MissingCredentials,

    #[error("Permission denied")]
    PermissionDenied,

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingAuthHeader | AuthError::InvalidAuthHeader => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            AuthError::PermissionDenied => (StatusCode::FORBIDDEN, self.to_string()),
            AuthError::UserNotFound | AuthError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(serde_json::json!({
            "error": message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}

// Use canonical types from secreton_core::models
// LoginRequest, LoginResponse, UserInfo are now imported at the top

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_validation() {
        let config = AuthConfig::default();
        let auth_service = AuthService::new(config);

        let token = auth_service
            .generate_token(
                "user123",
                "Test User",
                "test@example.com",
                vec!["crypto-user".to_string()],
            )
            .unwrap();

        let token_data = auth_service.validate_token(&token).unwrap();

        assert_eq!(token_data.sub, "user123");
        assert_eq!(token_data.name, "Test User");
        assert_eq!(token_data.email, "test@example.com");
        assert!(token_data.roles.contains(&"crypto-user".to_string()));
    }

    #[test]
    fn test_permission_checking() {
        let config = AuthConfig::default();
        let auth_service = AuthService::new(config);

        let claims = Claims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            roles: vec!["crypto-user".to_string()],
            permissions: vec![
                Permission::Encrypt.as_string(),
                Permission::Decrypt.as_string(),
            ],
            exp: (Utc::now() + Duration::hours(24)).timestamp() as u64,
            iat: Utc::now().timestamp() as u64,
            iss: "secreton-vault".to_string(),
            aud: "secreton-api".to_string(),
            jti: Uuid::new_v4().to_string(),
        };

        assert!(auth_service.check_permission(&claims, Permission::Encrypt));
        assert!(auth_service.check_permission(&claims, Permission::Decrypt));
        assert!(!auth_service.check_permission(&claims, Permission::DeleteKey));
    }

    #[test]
    fn test_admin_role_grants_all_permissions() {
        let config = AuthConfig::default();
        let auth_service = AuthService::new(config);

        let claims = Claims {
            sub: "admin-user".to_string(),
            name: "Admin".to_string(),
            email: "admin@example.com".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec![],
            exp: (Utc::now() + Duration::hours(24)).timestamp() as u64,
            iat: Utc::now().timestamp() as u64,
            iss: "secreton-vault".to_string(),
            aud: "secreton-api".to_string(),
            jti: Uuid::new_v4().to_string(),
        };

        assert!(auth_service.check_permission(&claims, Permission::ManageUsers));
        assert!(auth_service.check_permission(&claims, Permission::AccessAuditLogs));
    }

    #[test]
    fn test_generate_token_includes_role_permissions() {
        let config = AuthConfig::default();
        let auth_service = AuthService::new(config);

        let token = auth_service
            .generate_token(
                "vault-admin",
                "Vault Admin",
                "vault.admin@example.com",
                vec!["vault-admin".to_string()],
            )
            .expect("token generation");

        let data = auth_service
            .validate_token(&token)
            .expect("token validation");
        let permissions = data.permissions;

        assert!(permissions.contains(&Permission::AccessAuditLogs.as_string()));
        assert!(permissions.contains(&Permission::Encrypt.as_string()));
        assert!(permissions.contains(&Permission::HashData.as_string()));
    }

    #[test]
    fn test_extract_bearer_token() {
        let header = HeaderValue::from_str("Bearer secret-token").unwrap();
        let token = extract_bearer_token(&header).expect("token expected");
        assert_eq!(token, "secret-token");
    }

    #[test]
    fn test_extract_bearer_token_invalid_format() {
        let header = HeaderValue::from_str("Basic abc123").unwrap();
        assert!(extract_bearer_token(&header).is_none());

        let header = HeaderValue::from_str("Bearer").unwrap();
        assert!(extract_bearer_token(&header).is_none());
    }
}
