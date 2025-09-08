use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Authentication credentials structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credentials {
    /// Username/password credentials
    Password { username: String, password: String },
    /// Token-based credentials
    Token(String),
    /// AppRole credentials
    AppRole { role_id: String, secret_id: String },
    /// Certificate credentials
    Certificate { 
        client_cert: Vec<u8>, 
        cert_chain: Vec<u8>,
        fingerprint: String,
        subject: String,
        issuer: String,
        serial_number: String,
    },
    /// LDAP credentials
    Ldap { username: String, password: String },
    /// OIDC credentials
    Oidc { 
        jwt_token: String,
        provider: Option<String>,
        context: HashMap<String, String>,
    },
    /// Generic credentials data
    Generic(Value),
}

/// Token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token ID
    pub id: String,
    
    /// Associated policies
    pub policies: Vec<String>,
    
    /// Token metadata
    pub metadata: HashMap<String, String>,
    
    /// Token TTL in seconds
    pub ttl: Option<u64>,
    
    /// Whether token is renewable
    pub renewable: bool,
    
    /// Entity ID associated with token
    pub entity_id: Option<String>,
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Authentication success status
    pub success: bool,
    
    /// Generated token information
    pub token: Option<TokenInfo>,
    
    /// User information
    pub user_info: Option<HashMap<String, Value>>,
    
    /// Assigned policies
    pub policies: Vec<String>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    
    /// Error message if authentication failed
    pub error: Option<String>,
}

/// Authentication method trait
#[async_trait]
pub trait AuthMethod: Send + Sync {
    /// Authenticate user with provided credentials
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResult>;
    
    /// Validate configuration for this auth method
    async fn validate_config(&self, config: &Value) -> Result<()>;
    
    /// List users managed by this auth method
    async fn list_users(&self) -> Result<Vec<String>>;
    
    /// Create a new user (if supported)
    async fn create_user(&self, username: &str, config: &Value) -> Result<()>;
    
    /// Delete a user (if supported)
    async fn delete_user(&self, username: &str) -> Result<()>;
    
    /// Get the name of this authentication method
    fn name(&self) -> &'static str;
    
    /// Get description of this authentication method
    fn description(&self) -> &'static str;
    
    /// Whether this method supports user management
    fn supports_user_management(&self) -> bool {
        true
    }
    
    /// Whether this method supports MFA
    fn supports_mfa(&self) -> bool {
        false
    }
}

/// Authentication method registry
pub struct AuthMethodRegistry {
    methods: HashMap<String, Box<dyn AuthMethod>>,
}

impl AuthMethodRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
        }
    }
    
    /// Register an authentication method
    pub fn register(&mut self, method: Box<dyn AuthMethod>) {
        let name = method.name().to_string();
        self.methods.insert(name, method);
    }
    
    /// Get authentication method by name
    pub fn get(&self, name: &str) -> Option<&dyn AuthMethod> {
        self.methods.get(name).map(|m| m.as_ref())
    }
    
    /// List all registered methods
    pub fn list_methods(&self) -> Vec<&str> {
        self.methods.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for AuthMethodRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_creation() {
        let creds = Credentials::Password {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };
        
        match creds {
            Credentials::Password { username, password } => {
                assert_eq!(username, "testuser");
                assert_eq!(password, "testpass");
            }
            _ => panic!("Expected Password variant"),
        }
    }

    #[test]
    fn test_token_info_creation() {
        let token_info = TokenInfo {
            id: "token-123".to_string(),
            policies: vec!["default".to_string()],
            metadata: HashMap::new(),
            ttl: Some(3600),
            renewable: true,
            entity_id: Some("user-123".to_string()),
        };
        
        assert_eq!(token_info.id, "token-123");
        assert!(token_info.renewable);
        assert_eq!(token_info.ttl, Some(3600));
    }

    #[test]
    fn test_auth_result_success() {
        let result = AuthResult {
            success: true,
            token: None,
            user_info: None,
            policies: vec!["default".to_string()],
            metadata: HashMap::new(),
            error: None,
        };
        
        assert!(result.success);
        assert!(result.error.is_none());
        assert_eq!(result.policies.len(), 1);
    }

    #[test]
    fn test_auth_result_failure() {
        let result = AuthResult {
            success: false,
            token: None,
            user_info: None,
            policies: vec![],
            metadata: HashMap::new(),
            error: Some("Authentication failed".to_string()),
        };
        
        assert!(!result.success);
        assert!(result.error.is_some());
        assert!(result.policies.is_empty());
    }

    #[test]
    fn test_auth_method_registry() {
        let registry = AuthMethodRegistry::new();
        assert!(registry.list_methods().is_empty());
        
        // Test that we can create the registry
        assert_eq!(registry.methods.len(), 0);
    }
}
