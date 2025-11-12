// Terraform Cloud Secrets Engine - Dynamic Terraform Cloud/Enterprise token generation
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum TerraformCloudError {
    #[error("Terraform Cloud error: {0}")]
    TerraformError(String),
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    #[error("Token not found: {0}")]
    TokenNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("API error: {0}")]
    APIError(String),
}

pub type Result<T> = std::result::Result<T, TerraformCloudError>;

/// Token type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    User,         // User token
    Team,         // Team token
    Organization, // Organization token
}

/// Terraform Cloud configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformCloudConfig {
    pub address: String,      // TFC/TFE address (e.g., app.terraform.io)
    pub token: String,        // Admin token for API access
    pub organization: String, // Default organization
    pub base_url: String,     // Base API URL
}

/// Run permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunPermissions {
    pub read: bool,
    pub plan: bool,
    pub apply: bool,
}

/// State version permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatePermissions {
    pub read: bool,
    pub write: bool,
}

/// Variable permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariablePermissions {
    pub read: bool,
    pub write: bool,
}

/// Workspace access configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceAccess {
    pub workspace_id: String,
    pub runs: RunPermissions,
    pub state_versions: StatePermissions,
    pub variables: VariablePermissions,
}

/// Terraform Cloud role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFRole {
    pub name: String,
    pub organization: String,
    pub token_type: TokenType,
    pub team_id: Option<String>, // For team tokens
    pub user_id: Option<String>, // For user tokens
    pub workspace_access: Vec<WorkspaceAccess>,
    pub ttl: Duration, // Token TTL
}

/// Generated Terraform Cloud token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFToken {
    pub token: String,    // Token value (tf-XXXX format)
    pub token_id: String, // Token ID
    pub token_type: TokenType,
    pub organization: String,
    pub team_id: Option<String>,
    pub user_id: Option<String>,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Terraform Cloud secrets engine
pub struct TerraformCloudEngine {
    config: Arc<RwLock<Option<TerraformCloudConfig>>>,
    roles: Arc<RwLock<HashMap<String, TFRole>>>,
    tokens: Arc<RwLock<HashMap<String, TFToken>>>,
}

impl TerraformCloudEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure Terraform Cloud connection
    pub async fn configure(&self, config: TerraformCloudConfig) -> Result<()> {
        if config.address.is_empty() {
            return Err(TerraformCloudError::ConfigError(
                "Address is required".to_string(),
            ));
        }
        if config.token.is_empty() {
            return Err(TerraformCloudError::ConfigError(
                "Token is required".to_string(),
            ));
        }
        if config.organization.is_empty() {
            return Err(TerraformCloudError::ConfigError(
                "Organization is required".to_string(),
            ));
        }

        // Validate connection (mock)
        self.validate_connection(&config).await?;

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Validate Terraform Cloud connection
    async fn validate_connection(&self, _config: &TerraformCloudConfig) -> Result<()> {
        // Mock validation
        // Real implementation would:
        // 1. Connect to TFC/TFE API
        // 2. Verify token has admin access
        // 3. Check organization exists
        Ok(())
    }

    /// Create a role
    pub async fn create_role(&self, role: TFRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(TerraformCloudError::ConfigError(
                "Role name is required".to_string(),
            ));
        }

        // Validate role based on token type
        match role.token_type {
            TokenType::Team => {
                if role.team_id.is_none() {
                    return Err(TerraformCloudError::ConfigError(
                        "Team ID is required for team tokens".to_string(),
                    ));
                }
            }
            TokenType::User => {
                if role.user_id.is_none() {
                    return Err(TerraformCloudError::ConfigError(
                        "User ID is required for user tokens".to_string(),
                    ));
                }
            }
            TokenType::Organization => {
                // No additional validation
            }
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Generate credentials for a role
    pub async fn generate_credentials(&self, role_name: &str) -> Result<TFToken> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(TerraformCloudError::ConfigError(
                "Terraform Cloud not configured".to_string(),
            ));
        }

        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| TerraformCloudError::RoleNotFound(role_name.to_string()))?;

        // Generate token via TFC API (mock)
        let token_id = format!("at-{}", uuid::Uuid::new_v4());
        let token_value = format!("tf-{}", uuid::Uuid::new_v4());

        let token = TFToken {
            token: token_value.clone(),
            token_id: token_id.clone(),
            token_type: role.token_type.clone(),
            organization: role.organization.clone(),
            team_id: role.team_id.clone(),
            user_id: role.user_id.clone(),
            description: format!("Secret generated token for role: {}", role_name),
            created_at: Utc::now(),
            expires_at: Utc::now() + role.ttl,
        };

        // Apply workspace access (mock)
        for workspace in &role.workspace_access {
            self.apply_workspace_access(&token_id, workspace).await?;
        }

        // Store token
        let mut tokens = self.tokens.write().await;
        tokens.insert(token_id, token.clone());

        Ok(token)
    }

    /// Apply workspace access permissions
    async fn apply_workspace_access(
        &self,
        _token_id: &str,
        _workspace: &WorkspaceAccess,
    ) -> Result<()> {
        // Mock implementation
        // Real implementation would call TFC API to:
        // 1. Grant workspace access to token
        // 2. Set run permissions (read, plan, apply)
        // 3. Set state version permissions (read, write)
        // 4. Set variable permissions (read, write)
        Ok(())
    }

    /// Revoke a token
    pub async fn revoke_token(&self, token_id: &str) -> Result<()> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(TerraformCloudError::ConfigError(
                "Terraform Cloud not configured".to_string(),
            ));
        }

        // Delete from TFC API (mock)
        let mut tokens = self.tokens.write().await;
        tokens
            .remove(token_id)
            .ok_or_else(|| TerraformCloudError::TokenNotFound(token_id.to_string()))?;

        Ok(())
    }

    /// Get role
    pub async fn get_role(&self, name: &str) -> Result<TFRole> {
        let roles = self.roles.read().await;
        roles
            .get(name)
            .cloned()
            .ok_or_else(|| TerraformCloudError::RoleNotFound(name.to_string()))
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
            .ok_or_else(|| TerraformCloudError::RoleNotFound(name.to_string()))?;
        Ok(())
    }

    /// List tokens (for management)
    pub async fn list_tokens(&self) -> Vec<String> {
        let tokens = self.tokens.read().await;
        tokens.keys().cloned().collect()
    }

    /// Get token info
    pub async fn get_token(&self, token_id: &str) -> Result<TFToken> {
        let tokens = self.tokens.read().await;
        tokens
            .get(token_id)
            .cloned()
            .ok_or_else(|| TerraformCloudError::TokenNotFound(token_id.to_string()))
    }

    /// Lookup token by value
    pub async fn lookup_token(&self, token_value: &str) -> Result<TFToken> {
        let tokens = self.tokens.read().await;
        tokens
            .values()
            .find(|t| t.token == token_value)
            .cloned()
            .ok_or_else(|| TerraformCloudError::TokenNotFound(token_value.to_string()))
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

    /// Update workspace access for a token
    pub async fn update_workspace_access(
        &self,
        token_id: &str,
        workspace_access: Vec<WorkspaceAccess>,
    ) -> Result<()> {
        let tokens = self.tokens.read().await;
        if !tokens.contains_key(token_id) {
            return Err(TerraformCloudError::TokenNotFound(token_id.to_string()));
        }
        drop(tokens);

        // Apply new workspace access (mock)
        for workspace in workspace_access {
            self.apply_workspace_access(token_id, &workspace).await?;
        }

        Ok(())
    }
}

impl Default for TerraformCloudEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> TerraformCloudConfig {
        TerraformCloudConfig {
            address: "app.terraform.io".to_string(),
            token: "test-admin-token".to_string(),
            organization: "my-org".to_string(),
            base_url: "https://app.terraform.io/api/v2".to_string(),
        }
    }

    #[tokio::test]
    async fn test_configure_terraform_cloud() {
        let engine = TerraformCloudEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        let cfg = engine.config.read().await;
        assert!(cfg.is_some());
        assert_eq!(cfg.as_ref().unwrap().organization, "my-org");
    }

    #[tokio::test]
    async fn test_generate_team_token() {
        let engine = TerraformCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = TFRole {
            name: "team-role".to_string(),
            organization: "my-org".to_string(),
            token_type: TokenType::Team,
            team_id: Some("team-123".to_string()),
            user_id: None,
            workspace_access: vec![],
            ttl: Duration::hours(24),
        };

        engine.create_role(role).await.unwrap();

        let token = engine.generate_credentials("team-role").await.unwrap();

        assert_eq!(token.token_type, TokenType::Team);
        assert_eq!(token.team_id, Some("team-123".to_string()));
        assert!(token.token.starts_with("tf-"));
        assert!(token.token_id.starts_with("at-"));
    }

    #[tokio::test]
    async fn test_generate_user_token() {
        let engine = TerraformCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = TFRole {
            name: "user-role".to_string(),
            organization: "my-org".to_string(),
            token_type: TokenType::User,
            team_id: None,
            user_id: Some("user-456".to_string()),
            workspace_access: vec![],
            ttl: Duration::hours(12),
        };

        engine.create_role(role).await.unwrap();

        let token = engine.generate_credentials("user-role").await.unwrap();

        assert_eq!(token.token_type, TokenType::User);
        assert_eq!(token.user_id, Some("user-456".to_string()));
        assert!(token.token.starts_with("tf-"));
    }

    #[tokio::test]
    async fn test_workspace_access_permissions() {
        let engine = TerraformCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = TFRole {
            name: "workspace-role".to_string(),
            organization: "my-org".to_string(),
            token_type: TokenType::Team,
            team_id: Some("team-789".to_string()),
            user_id: None,
            workspace_access: vec![
                WorkspaceAccess {
                    workspace_id: "ws-abc123".to_string(),
                    runs: RunPermissions {
                        read: true,
                        plan: true,
                        apply: false,
                    },
                    state_versions: StatePermissions {
                        read: true,
                        write: false,
                    },
                    variables: VariablePermissions {
                        read: true,
                        write: false,
                    },
                },
                WorkspaceAccess {
                    workspace_id: "ws-def456".to_string(),
                    runs: RunPermissions {
                        read: true,
                        plan: true,
                        apply: true,
                    },
                    state_versions: StatePermissions {
                        read: true,
                        write: true,
                    },
                    variables: VariablePermissions {
                        read: true,
                        write: true,
                    },
                },
            ],
            ttl: Duration::hours(8),
        };

        engine.create_role(role).await.unwrap();

        let token = engine.generate_credentials("workspace-role").await.unwrap();

        assert_eq!(token.organization, "my-org");
        assert!(token.description.contains("workspace-role"));
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let engine = TerraformCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = TFRole {
            name: "temp-role".to_string(),
            organization: "my-org".to_string(),
            token_type: TokenType::User,
            team_id: None,
            user_id: Some("user-temp".to_string()),
            workspace_access: vec![],
            ttl: Duration::hours(1),
        };

        engine.create_role(role).await.unwrap();

        let token = engine.generate_credentials("temp-role").await.unwrap();
        let token_id = token.token_id.clone();

        // Token should exist
        assert!(engine.get_token(&token_id).await.is_ok());

        // Revoke token
        engine.revoke_token(&token_id).await.unwrap();

        // Token should not exist
        assert!(engine.get_token(&token_id).await.is_err());
    }

    #[tokio::test]
    async fn test_role_crud_operations() {
        let engine = TerraformCloudEngine::new();

        let role = TFRole {
            name: "test-role".to_string(),
            organization: "test-org".to_string(),
            token_type: TokenType::Organization,
            team_id: None,
            user_id: None,
            workspace_access: vec![],
            ttl: Duration::hours(24),
        };

        // Create
        engine.create_role(role.clone()).await.unwrap();

        // Read
        let retrieved = engine.get_role("test-role").await.unwrap();
        assert_eq!(retrieved.name, "test-role");
        assert_eq!(retrieved.token_type, TokenType::Organization);

        // List
        let roles = engine.list_roles().await;
        assert_eq!(roles.len(), 1);
        assert!(roles.contains(&"test-role".to_string()));

        // Delete
        engine.delete_role("test-role").await.unwrap();
        assert!(engine.get_role("test-role").await.is_err());
    }

    #[tokio::test]
    async fn test_lookup_token_by_value() {
        let engine = TerraformCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = TFRole {
            name: "lookup-role".to_string(),
            organization: "my-org".to_string(),
            token_type: TokenType::Team,
            team_id: Some("team-lookup".to_string()),
            user_id: None,
            workspace_access: vec![],
            ttl: Duration::hours(6),
        };

        engine.create_role(role).await.unwrap();

        let token = engine.generate_credentials("lookup-role").await.unwrap();
        let token_value = token.token.clone();

        // Lookup by token value
        let found = engine.lookup_token(&token_value).await.unwrap();

        assert_eq!(found.token, token_value);
        assert_eq!(found.token_id, token.token_id);
    }
}
