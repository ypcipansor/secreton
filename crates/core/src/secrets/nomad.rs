// Nomad Secrets Engine - HashiCorp Nomad ACL token generation
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum NomadError {
    #[error("Nomad error: {0}")]
    NomadError(String),
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    #[error("Token not found: {0}")]
    TokenNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("API error: {0}")]
    APIError(String),
}

pub type Result<T> = std::result::Result<T, NomadError>;

/// Nomad token type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Management, // Full cluster access
    Client,     // Limited by policies
}

/// Nomad configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NomadConfig {
    pub address: String,             // Nomad server address
    pub token: String,               // Root/management token
    pub ca_cert: Option<String>,     // CA certificate for TLS
    pub client_cert: Option<String>, // Client certificate
    pub client_key: Option<String>,  // Client key
    pub max_token_name_length: u32,  // Maximum token name length
}

/// Nomad role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NomadRole {
    pub name: String,
    pub token_type: TokenType,
    pub policies: Vec<String>, // ACL policies to attach
    pub global: bool,          // Global token or regional
    pub ttl: Duration,         // Token time-to-live
    pub max_ttl: Duration,     // Maximum TTL
}

/// Generated Nomad token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NomadToken {
    pub accessor_id: String, // Token accessor ID
    pub secret_id: String,   // Actual token secret
    pub name: String,        // Token name
    pub token_type: TokenType,
    pub policies: Vec<String>,
    pub global: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Nomad secrets engine
pub struct NomadEngine {
    config: Arc<RwLock<Option<NomadConfig>>>,
    roles: Arc<RwLock<HashMap<String, NomadRole>>>,
    tokens: Arc<RwLock<HashMap<String, NomadToken>>>,
}

impl NomadEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure Nomad connection
    pub async fn configure(&self, config: NomadConfig) -> Result<()> {
        if config.address.is_empty() {
            return Err(NomadError::ConfigError("Address is required".to_string()));
        }
        if config.token.is_empty() {
            return Err(NomadError::ConfigError("Token is required".to_string()));
        }

        // Validate connection (mock)
        self.validate_connection(&config).await?;

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Validate Nomad connection
    async fn validate_connection(&self, _config: &NomadConfig) -> Result<()> {
        // Mock validation
        // Real implementation would:
        // 1. Connect to Nomad API
        // 2. Verify token has management privileges
        // 3. Check API version compatibility
        Ok(())
    }

    /// Create a role
    pub async fn create_role(&self, role: NomadRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(NomadError::ConfigError("Role name is required".to_string()));
        }

        if role.token_type == TokenType::Client && role.policies.is_empty() {
            return Err(NomadError::ConfigError(
                "Client tokens must have at least one policy".to_string(),
            ));
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Generate credentials for a role
    pub async fn generate_credentials(&self, role_name: &str) -> Result<NomadToken> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(NomadError::ConfigError("Nomad not configured".to_string()));
        }

        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| NomadError::RoleNotFound(role_name.to_string()))?;

        // Generate token via Nomad API (mock)
        let accessor_id = format!("accessor-{}", uuid::Uuid::new_v4());
        let secret_id = format!("secret-{}", uuid::Uuid::new_v4());

        let token = NomadToken {
            accessor_id: accessor_id.clone(),
            secret_id,
            name: format!("vault-{}-{}", role_name, uuid::Uuid::new_v4()),
            token_type: role.token_type.clone(),
            policies: role.policies.clone(),
            global: role.global,
            created_at: Utc::now(),
            expires_at: Utc::now() + role.ttl,
        };

        // Store token
        let mut tokens = self.tokens.write().await;
        tokens.insert(accessor_id, token.clone());

        Ok(token)
    }

    /// Revoke a token
    pub async fn revoke_token(&self, accessor_id: &str) -> Result<()> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(NomadError::ConfigError("Nomad not configured".to_string()));
        }

        // Delete from Nomad API (mock)
        let mut tokens = self.tokens.write().await;
        tokens
            .remove(accessor_id)
            .ok_or_else(|| NomadError::TokenNotFound(accessor_id.to_string()))?;

        Ok(())
    }

    /// Get role
    pub async fn get_role(&self, name: &str) -> Result<NomadRole> {
        let roles = self.roles.read().await;
        roles
            .get(name)
            .cloned()
            .ok_or_else(|| NomadError::RoleNotFound(name.to_string()))
    }

    /// List all roles
    pub async fn list_roles(&self) -> Vec<String> {
        let roles = self.roles.read().await;
        roles.keys().cloned().collect()
    }

    /// Delete a role
    pub async fn delete_role(&self, name: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles
            .remove(name)
            .ok_or_else(|| NomadError::RoleNotFound(name.to_string()))?;
        Ok(())
    }

    /// List tokens (for management)
    pub async fn list_tokens(&self) -> Vec<String> {
        let tokens = self.tokens.read().await;
        tokens.keys().cloned().collect()
    }

    /// Get token info
    pub async fn get_token(&self, accessor_id: &str) -> Result<NomadToken> {
        let tokens = self.tokens.read().await;
        tokens
            .get(accessor_id)
            .cloned()
            .ok_or_else(|| NomadError::TokenNotFound(accessor_id.to_string()))
    }

    /// Lookup token by secret
    pub async fn lookup_token(&self, secret_id: &str) -> Result<NomadToken> {
        let tokens = self.tokens.read().await;
        tokens
            .values()
            .find(|t| t.secret_id == secret_id)
            .cloned()
            .ok_or_else(|| NomadError::TokenNotFound(secret_id.to_string()))
    }

    /// Cleanup expired tokens
    pub async fn cleanup_expired_tokens(&self) -> usize {
        let mut tokens = self.tokens.write().await;
        let now = Utc::now();

        let expired: Vec<String> = tokens
            .iter()
            .filter(|(_, token)| token.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for id in expired {
            tokens.remove(&id);
        }

        count
    }
}

impl Default for NomadEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> NomadConfig {
        NomadConfig {
            address: "http://localhost:4646".to_string(),
            token: "test-root-token".to_string(),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            max_token_name_length: 256,
        }
    }

    #[tokio::test]
    async fn test_configure_nomad() {
        let engine = NomadEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        let cfg = engine.config.read().await;
        assert!(cfg.is_some());
        assert_eq!(cfg.as_ref().unwrap().address, "http://localhost:4646");
    }

    #[tokio::test]
    async fn test_generate_management_token() {
        let engine = NomadEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = NomadRole {
            name: "management-role".to_string(),
            token_type: TokenType::Management,
            policies: vec![],
            global: true,
            ttl: Duration::hours(24),
            max_ttl: Duration::hours(72),
        };

        engine.create_role(role).await.unwrap();

        let token = engine
            .generate_credentials("management-role")
            .await
            .unwrap();

        assert_eq!(token.token_type, TokenType::Management);
        assert!(token.global);
        assert!(token.accessor_id.starts_with("accessor-"));
        assert!(token.secret_id.starts_with("secret-"));
    }

    #[tokio::test]
    async fn test_generate_client_token_with_policies() {
        let engine = NomadEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = NomadRole {
            name: "app-role".to_string(),
            token_type: TokenType::Client,
            policies: vec!["read-jobs".to_string(), "submit-jobs".to_string()],
            global: false,
            ttl: Duration::hours(1),
            max_ttl: Duration::hours(24),
        };

        engine.create_role(role).await.unwrap();

        let token = engine.generate_credentials("app-role").await.unwrap();

        assert_eq!(token.token_type, TokenType::Client);
        assert_eq!(token.policies.len(), 2);
        assert!(token.policies.contains(&"read-jobs".to_string()));
        assert!(token.policies.contains(&"submit-jobs".to_string()));
        assert!(!token.global);
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let engine = NomadEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = NomadRole {
            name: "temp-role".to_string(),
            token_type: TokenType::Client,
            policies: vec!["read-only".to_string()],
            global: false,
            ttl: Duration::hours(1),
            max_ttl: Duration::hours(24),
        };

        engine.create_role(role).await.unwrap();

        let token = engine.generate_credentials("temp-role").await.unwrap();
        let accessor_id = token.accessor_id.clone();

        // Token should exist
        assert!(engine.get_token(&accessor_id).await.is_ok());

        // Revoke token
        engine.revoke_token(&accessor_id).await.unwrap();

        // Token should not exist
        assert!(engine.get_token(&accessor_id).await.is_err());
    }

    #[tokio::test]
    async fn test_role_crud_operations() {
        let engine = NomadEngine::new();

        let role = NomadRole {
            name: "test-role".to_string(),
            token_type: TokenType::Client,
            policies: vec!["policy1".to_string()],
            global: true,
            ttl: Duration::hours(2),
            max_ttl: Duration::hours(48),
        };

        // Create
        engine.create_role(role.clone()).await.unwrap();

        // Read
        let retrieved = engine.get_role("test-role").await.unwrap();
        assert_eq!(retrieved.name, "test-role");
        assert_eq!(retrieved.policies.len(), 1);

        // List
        let roles = engine.list_roles().await;
        assert_eq!(roles.len(), 1);
        assert!(roles.contains(&"test-role".to_string()));

        // Delete
        engine.delete_role("test-role").await.unwrap();
        assert!(engine.get_role("test-role").await.is_err());
    }
}
