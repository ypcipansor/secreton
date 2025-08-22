//! Authentication and authorization for the Brankas API
//!
//! Provides JWT-based authentication, role-based access control,
//! and integration with external identity providers.

use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation, Algorithm};
use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use tracing::{warn, error};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,          // Subject (user ID)
    pub name: String,         // User name
    pub email: String,        // User email
    pub roles: Vec<String>,   // User roles
    pub permissions: Vec<String>, // Specific permissions
    pub exp: usize,           // Expiration time
    pub iat: usize,           // Issued at
    pub iss: String,          // Issuer
    pub aud: String,          // Audience
    pub jti: String,          // JWT ID
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

/// Authentication service
#[derive(Clone)]
pub struct AuthService {
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    pub fn new(config: AuthConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
        
        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }
    
    /// Generate JWT token for a user
    pub fn generate_token(&self, user_id: &str, name: &str, email: &str, roles: Vec<String>) -> Result<String, AuthError> {
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
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            jti: Uuid::new_v4().to_string(),
        };
        
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenGeneration(e.to_string()))
    }
    
    /// Validate and decode JWT token
    pub fn validate_token(&self, token: &str) -> Result<TokenData<Claims>, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        
        decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AuthError::TokenValidation(e.to_string()))
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
                },
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
                },
                Some(UserRole::KeyManager) => {
                    permissions.extend(vec![
                        Permission::CreateKey.as_string(),
                        Permission::RotateKey.as_string(),
                        Permission::ReadKey.as_string(),
                        Permission::ListKeys.as_string(),
                        Permission::ViewMetrics.as_string(),
                    ]);
                },
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
                },
                Some(UserRole::ReadOnly) => {
                    permissions.extend(vec![
                        Permission::ReadKey.as_string(),
                        Permission::ListKeys.as_string(),
                        Permission::ViewMetrics.as_string(),
                    ]);
                },
                None => {
                    warn!("Unknown role: {}", role);
                }
            }
        }
        
        permissions.sort();
        permissions.dedup();
        permissions
    }
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(auth_header: &HeaderValue) -> Option<String> {
    let auth_str = auth_header.to_str().ok()?;
    if auth_str.starts_with("Bearer ") {
        Some(auth_str[7..].to_string())
    } else {
        None
    }
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
            },
            AuthError::PermissionDenied => {
                (StatusCode::FORBIDDEN, self.to_string())
            },
            AuthError::UserNotFound | AuthError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            },
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        
        let body = Json(serde_json::json!({
            "error": message,
            "status": status.as_u16()
        }));
        
        (status, body).into_response()
    }
}

/// Login request structure
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Login response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub user: UserInfo,
}

/// User information structure
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub email: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_token_generation_and_validation() {
        let config = AuthConfig::default();
        let auth_service = AuthService::new(config);
        
        let token = auth_service.generate_token(
            "user123",
            "Test User",
            "test@example.com",
            vec!["crypto-user".to_string()]
        ).unwrap();
        
        let token_data = auth_service.validate_token(&token).unwrap();
        
        assert_eq!(token_data.claims.sub, "user123");
        assert_eq!(token_data.claims.name, "Test User");
        assert_eq!(token_data.claims.email, "test@example.com");
        assert!(token_data.claims.roles.contains(&"crypto-user".to_string()));
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
            exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
            iss: "secreton-vault".to_string(),
            aud: "secreton-api".to_string(),
            jti: Uuid::new_v4().to_string(),
        };
        
        assert!(auth_service.check_permission(&claims, Permission::Encrypt));
        assert!(auth_service.check_permission(&claims, Permission::Decrypt));
        assert!(!auth_service.check_permission(&claims, Permission::DeleteKey));
    }
}
