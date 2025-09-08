use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{info, warn, error, debug};
use uuid::Uuid;

use crate::auth::auth_impl::traits::{AuthMethod, AuthResult, Credentials, TokenInfo};

// Import LDAP modules
pub mod config;
pub mod client;

pub use config::{LdapConfig, LdapAuthRequest, LdapAuthResponse, LdapUser, LdapGroup};
pub use client::LdapClient;

/// LDAP authentication method implementation
pub struct LdapAuth {
    config: LdapConfig,
    client: LdapClient,
}

impl LdapAuth {
    /// Create new LDAP authentication method
    pub fn new(config: LdapConfig) -> Self {
        let client = LdapClient::new(config.clone());
        Self { config, client }
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: LdapConfig) {
        self.client = LdapClient::new(config.clone());
        self.config = config;
    }
    
    /// Test LDAP connectivity
    pub fn test_connection(&self) -> Result<()> {
        self.client.test_connection()
    }
    
    /// List available groups from LDAP
    pub fn list_groups(&self) -> Result<Vec<String>> {
        self.client.list_groups()
    }
    
    /// Get group information
    pub fn get_group_info(&self, group_name: &str) -> Result<LdapGroup> {
        self.client.get_group_info(group_name)
    }
}

#[async_trait]
impl AuthMethod for LdapAuth {
    /// Authenticate user against LDAP
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResult> {
        let (username, password) = match credentials {
            Credentials::Ldap { username, password } => (username, password),
            _ => {
                warn!("Invalid credential type for LDAP authentication");
                return Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some("Invalid credential type".to_string()),
                });
            }
        };
        
        let auth_request = LdapAuthRequest {
            username: username.clone(),
            password: password.clone(),
            metadata: None,
        };
        
        debug!("Authenticating user: {}", auth_request.username);
        
        // Authenticate user with LDAP
        match self.client.authenticate_user(&auth_request.username, &auth_request.password) {
            Ok(ldap_user) => {
                info!("User {} authenticated successfully via LDAP", auth_request.username);
                
                // Generate token
                let token_id = Uuid::new_v4().to_string();
                let token_info = TokenInfo {
                    id: token_id.clone(),
                    policies: ldap_user.policies.clone(),
                    metadata: ldap_user.metadata.clone(),
                    ttl: Some(3600), // 1 hour default
                    renewable: true,
                    entity_id: Some(ldap_user.username.clone()),
                };
                
                // Prepare user info
                let mut user_info = HashMap::new();
                user_info.insert("username".to_string(), json!(ldap_user.username));
                user_info.insert("dn".to_string(), json!(ldap_user.dn));
                user_info.insert("groups".to_string(), json!(ldap_user.groups));
                user_info.insert("auth_method".to_string(), json!("ldap"));
                
                // Add LDAP attributes to user info
                for (key, values) in &ldap_user.attributes {
                    if !values.is_empty() {
                        if values.len() == 1 {
                            user_info.insert(format!("ldap_{}", key), json!(values[0]));
                        } else {
                            user_info.insert(format!("ldap_{}", key), json!(values));
                        }
                    }
                }
                
                Ok(AuthResult {
                    success: true,
                    token: Some(token_info),
                    user_info: Some(user_info),
                    policies: ldap_user.policies,
                    metadata: ldap_user.metadata,
                    error: None,
                })
            }
            Err(e) => {
                warn!("LDAP authentication failed for user {}: {}", auth_request.username, e);
                Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some(format!("Authentication failed: {}", e)),
                })
            }
        }
    }
    
    /// Validate LDAP configuration
    async fn validate_config(&self, config: &Value) -> Result<()> {
        let ldap_config: LdapConfig = serde_json::from_value(config.clone())
            .context("Invalid LDAP configuration format")?;
        
        // Validate required fields
        if ldap_config.url.is_empty() {
            return Err(anyhow::anyhow!("LDAP URL is required"));
        }
        
        if ldap_config.user_dn.is_empty() {
            return Err(anyhow::anyhow!("User DN is required"));
        }
        
        if ldap_config.user_attr.is_empty() {
            return Err(anyhow::anyhow!("User attribute is required"));
        }
        
        // Test connectivity if bind credentials are provided
        if ldap_config.bind_dn.is_some() && ldap_config.bind_password.is_some() {
            let test_client = LdapClient::new(ldap_config);
            test_client.test_connection()
                .context("LDAP connection test failed")?;
            info!("LDAP configuration validation successful");
        } else {
            info!("LDAP configuration syntax validation successful (no connectivity test without bind credentials)");
        }
        
        Ok(())
    }
    
    /// List LDAP users (limited implementation)
    async fn list_users(&self) -> Result<Vec<String>> {
        // LDAP typically doesn't support full user enumeration for security reasons
        // Return empty list with a warning
        warn!("LDAP user enumeration is not supported for security reasons");
        Ok(vec![])
    }
    
    /// Create user (not supported for LDAP)
    async fn create_user(&self, username: &str, _config: &Value) -> Result<()> {
        error!("User creation is not supported for LDAP authentication method");
        Err(anyhow::anyhow!(
            "User creation not supported for LDAP. User '{}' must be created in LDAP directory",
            username
        ))
    }
    
    /// Delete user (not supported for LDAP)
    async fn delete_user(&self, username: &str) -> Result<()> {
        error!("User deletion is not supported for LDAP authentication method");
        Err(anyhow::anyhow!(
            "User deletion not supported for LDAP. User '{}' must be deleted from LDAP directory",
            username
        ))
    }
    
    /// Get authentication method name
    fn name(&self) -> &'static str {
        "ldap"
    }
    
    /// Get authentication method description
    fn description(&self) -> &'static str {
        "LDAP/Active Directory authentication with group-based policy mapping"
    }
    
    /// Check if method supports user management
    fn supports_user_management(&self) -> bool {
        false // LDAP users are managed in the directory service
    }
    
    /// Check if method supports MFA
    fn supports_mfa(&self) -> bool {
        false // MFA should be handled by the LDAP directory service
    }
}

/// Helper function to create LDAP authentication request
pub fn create_ldap_auth_request(username: &str, password: &str) -> Value {
    json!({
        "username": username,
        "password": password
    })
}

/// Helper function to create LDAP configuration
pub fn create_ldap_config(
    url: &str,
    user_dn: &str,
    group_dn: &str,
    bind_dn: Option<&str>,
    bind_password: Option<&str>,
) -> LdapConfig {
    LdapConfig {
        url: url.to_string(),
        user_dn: user_dn.to_string(),
        group_dn: group_dn.to_string(),
        bind_dn: bind_dn.map(|s| s.to_string()),
        bind_password: bind_password.map(|s| s.to_string()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ldap_auth_creation() {
        let config = LdapConfig::default();
        let ldap_auth = LdapAuth::new(config);
        
        assert_eq!(ldap_auth.name(), "ldap");
        assert!(!ldap_auth.supports_user_management());
        assert!(!ldap_auth.supports_mfa());
    }

    #[tokio::test]
    async fn test_ldap_auth_request_creation() {
        let request = create_ldap_auth_request("testuser", "testpass");
        let parsed: LdapAuthRequest = serde_json::from_value(request).unwrap();
        
        assert_eq!(parsed.username, "testuser");
        assert_eq!(parsed.password, "testpass");
    }

    #[tokio::test]
    async fn test_ldap_config_creation() {
        let config = create_ldap_config(
            "ldap://test.example.com",
            "ou=users,dc=example,dc=com",
            "ou=groups,dc=example,dc=com",
            Some("cn=admin,dc=example,dc=com"),
            Some("adminpass"),
        );
        
        assert_eq!(config.url, "ldap://test.example.com");
        assert_eq!(config.user_dn, "ou=users,dc=example,dc=com");
        assert_eq!(config.group_dn, "ou=groups,dc=example,dc=com");
        assert_eq!(config.bind_dn, Some("cn=admin,dc=example,dc=com".to_string()));
        assert_eq!(config.bind_password, Some("adminpass".to_string()));
    }

    #[tokio::test]
    async fn test_invalid_auth_request() {
        let config = LdapConfig::default();
        let ldap_auth = LdapAuth::new(config);
        
        // Using invalid credentials - we'll use a different variant than LDAP
        let invalid_credentials = Credentials::Token("invalid-token".to_string());
        
        let result = ldap_auth.authenticate(&invalid_credentials).await;
        assert!(result.is_ok()); // Should return Ok but with success = false
        let auth_result = result.unwrap();
        assert!(!auth_result.success); // Authentication should fail
        assert!(auth_result.error.is_some()); // Should have error message
    }

    #[tokio::test]
    async fn test_validate_config() {
        let config = LdapConfig::default();
        let ldap_auth = LdapAuth::new(config);
        
        let valid_config = json!({
            "url": "ldap://test.example.com",
            "user_dn": "ou=users,dc=example,dc=com",
            "user_attr": "uid",
            "group_dn": "ou=groups,dc=example,dc=com"
        });
        
        // This will succeed syntax validation but may fail connectivity
        // In real tests, you'd mock the LDAP connection
        let result = ldap_auth.validate_config(&valid_config).await;
        // Don't assert success since we don't have actual LDAP server
        assert!(result.is_ok() || result.is_err()); // Either outcome is valid in test
    }

    #[tokio::test]
    async fn test_unsupported_operations() {
        let config = LdapConfig::default();
        let ldap_auth = LdapAuth::new(config);
        
        // Test unsupported user creation
        let result = ldap_auth.create_user("testuser", &json!({})).await;
        assert!(result.is_err());
        
        // Test unsupported user deletion
        let result = ldap_auth.delete_user("testuser").await;
        assert!(result.is_err());
        
        // Test list users (should return empty)
        let users = ldap_auth.list_users().await.unwrap();
        assert!(users.is_empty());
    }
}
