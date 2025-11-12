// Azure Secrets Engine - Microsoft Azure dynamic credentials
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum AzureError {
    #[error("Azure error: {0}")]
    AzureError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),
}

pub type Result<T> = std::result::Result<T, AzureError>;

/// Azure environment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AzureEnvironment {
    AzurePublicCloud,
    AzureUSGovernmentCloud,
    AzureChinaCloud,
    AzureGermanCloud,
}

/// Azure configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    pub subscription_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub environment: AzureEnvironment,
    pub ttl: Duration,
    pub max_ttl: Duration,
}

/// Azure role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureRoleDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub scope: String, // e.g., "/subscriptions/{id}"
}

/// Azure role assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureRole {
    pub name: String,
    pub azure_roles: Vec<AzureRoleDefinition>,
    pub application_object_id: Option<String>,
    pub ttl: Duration,
    pub max_ttl: Duration,
    pub created_at: DateTime<Utc>,
}

/// Azure service principal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureServicePrincipal {
    pub application_id: String,
    pub object_id: String,
    pub display_name: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Azure credentials response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub subscription_id: String,
    pub expires_at: DateTime<Utc>,
}

/// Role assignment record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub principal_id: String,
    pub role_definition_id: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
}

/// Azure secrets engine
pub struct AzureSecretsEngine {
    config: Arc<RwLock<Option<AzureConfig>>>,
    roles: Arc<RwLock<HashMap<String, AzureRole>>>,
    service_principals: Arc<RwLock<HashMap<String, AzureServicePrincipal>>>,
    role_assignments: Arc<RwLock<Vec<RoleAssignment>>>,
}

impl AzureSecretsEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            service_principals: Arc::new(RwLock::new(HashMap::new())),
            role_assignments: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Configure Azure connection
    pub async fn configure(&self, config: AzureConfig) -> Result<()> {
        if config.subscription_id.is_empty() {
            return Err(AzureError::ConfigError(
                "Subscription ID is required".to_string(),
            ));
        }
        if config.tenant_id.is_empty() {
            return Err(AzureError::ConfigError("Tenant ID is required".to_string()));
        }
        if config.client_id.is_empty() {
            return Err(AzureError::ConfigError("Client ID is required".to_string()));
        }
        if config.client_secret.is_empty() {
            return Err(AzureError::ConfigError(
                "Client secret is required".to_string(),
            ));
        }

        // Validate credentials (mock)
        self.validate_credentials(&config).await?;

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Validate Azure credentials
    async fn validate_credentials(&self, config: &AzureConfig) -> Result<()> {
        // Mock validation
        // In real implementation, this would:
        // 1. Attempt to get OAuth token
        // 2. Verify subscription access
        // 3. Test API connectivity

        if config.client_secret.len() < 10 {
            return Err(AzureError::AuthError("Invalid client secret".to_string()));
        }

        Ok(())
    }

    /// Create an Azure role
    pub async fn create_role(&self, role: AzureRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(AzureError::ConfigError("Role name is required".to_string()));
        }
        if role.azure_roles.is_empty() {
            return Err(AzureError::ConfigError(
                "At least one Azure role is required".to_string(),
            ));
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Get Azure role
    pub async fn get_role(&self, name: &str) -> Result<AzureRole> {
        let roles = self.roles.read().await;
        roles
            .get(name)
            .cloned()
            .ok_or_else(|| AzureError::RoleNotFound(name.to_string()))
    }

    /// List roles
    pub async fn list_roles(&self) -> Vec<String> {
        let roles = self.roles.read().await;
        roles.keys().cloned().collect()
    }

    /// Generate dynamic Azure credentials
    pub async fn generate_credentials(&self, role_name: &str) -> Result<AzureCredentials> {
        let role = self.get_role(role_name).await?;

        // Check if Azure is configured
        let config = self.config.read().await;
        let cfg = config
            .as_ref()
            .ok_or_else(|| AzureError::ConfigError("Azure not configured".to_string()))?;

        // Create service principal
        let sp = self.create_service_principal(&role, cfg).await?;

        // Assign roles
        for azure_role in &role.azure_roles {
            self.assign_role(&sp.object_id, azure_role).await?;
        }

        // Store service principal
        let mut sps = self.service_principals.write().await;
        sps.insert(sp.application_id.clone(), sp.clone());

        Ok(AzureCredentials {
            client_id: sp.application_id,
            client_secret: sp.client_secret,
            tenant_id: sp.tenant_id,
            subscription_id: cfg.subscription_id.clone(),
            expires_at: sp.expires_at,
        })
    }

    /// Create Azure service principal
    async fn create_service_principal(
        &self,
        role: &AzureRole,
        config: &AzureConfig,
    ) -> Result<AzureServicePrincipal> {
        // Mock SP creation
        // In real implementation, this would:
        // 1. Create Azure AD application
        // 2. Create service principal
        // 3. Generate client secret
        // 4. Return SP details

        let app_id = uuid::Uuid::new_v4().to_string();
        let object_id = uuid::Uuid::new_v4().to_string();
        let display_name = format!("vault-{}-{}", role.name, Utc::now().timestamp());

        let client_secret = self.generate_client_secret();

        let sp = AzureServicePrincipal {
            application_id: app_id,
            object_id,
            display_name,
            client_secret,
            tenant_id: config.tenant_id.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + role.ttl,
        };

        Ok(sp)
    }

    /// Generate client secret
    fn generate_client_secret(&self) -> String {
        // Generate 40-character secret
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();

        (0..40)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Assign Azure role to service principal
    pub async fn assign_role(
        &self,
        principal_id: &str,
        role_definition: &AzureRoleDefinition,
    ) -> Result<()> {
        // Mock role assignment
        // In real implementation, this would call Azure ARM API

        let assignment = RoleAssignment {
            principal_id: principal_id.to_string(),
            role_definition_id: role_definition.id.clone(),
            scope: role_definition.scope.clone(),
            created_at: Utc::now(),
        };

        let mut assignments = self.role_assignments.write().await;
        assignments.push(assignment);

        Ok(())
    }

    /// Rotate root credentials
    pub async fn rotate_root_credentials(&self) -> Result<()> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(AzureError::ConfigError("Azure not configured".to_string()));
        }

        // Mock root credential rotation
        // In real implementation, this would:
        // 1. Generate new client secret for root SP
        // 2. Update Secret configuration
        // 3. Delete old secret

        Ok(())
    }

    /// Revoke credentials
    pub async fn revoke_credentials(&self, client_id: &str) -> Result<()> {
        let mut sps = self.service_principals.write().await;
        let sp = sps
            .remove(client_id)
            .ok_or_else(|| AzureError::InvalidCredentials("Not found".to_string()))?;

        // Delete service principal from Azure (mock)
        self.delete_service_principal(&sp.object_id).await?;

        // Remove role assignments
        let mut assignments = self.role_assignments.write().await;
        assignments.retain(|a| a.principal_id != sp.object_id);

        Ok(())
    }

    /// Delete service principal from Azure
    async fn delete_service_principal(&self, _object_id: &str) -> Result<()> {
        // Mock deletion
        // In real implementation, this would call Azure AD Graph API
        Ok(())
    }

    /// Get configuration status
    pub async fn is_configured(&self) -> bool {
        let config = self.config.read().await;
        config.is_some()
    }

    /// List service principals
    pub async fn list_service_principals(&self) -> Vec<String> {
        let sps = self.service_principals.read().await;
        sps.keys().cloned().collect()
    }

    /// List role assignments
    pub async fn list_role_assignments(&self) -> Vec<RoleAssignment> {
        let assignments = self.role_assignments.read().await;
        assignments.clone()
    }
}

impl Default for AzureSecretsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AzureConfig {
        AzureConfig {
            subscription_id: "12345678-1234-1234-1234-123456789012".to_string(),
            tenant_id: "87654321-4321-4321-4321-210987654321".to_string(),
            client_id: "abcdef12-3456-7890-abcd-ef1234567890".to_string(),
            client_secret: "very-secret-password-123".to_string(),
            environment: AzureEnvironment::AzurePublicCloud,
            ttl: Duration::hours(8),
            max_ttl: Duration::days(30),
        }
    }

    #[tokio::test]
    async fn test_configure_azure() {
        let engine = AzureSecretsEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        assert!(engine.is_configured().await);
    }

    #[tokio::test]
    async fn test_create_role() {
        let engine = AzureSecretsEngine::new();

        let role = AzureRole {
            name: "my-app".to_string(),
            azure_roles: vec![AzureRoleDefinition {
                id: "/subscriptions/sub-id/providers/Microsoft.Authorization/roleDefinitions/reader-id".to_string(),
                name: "Reader".to_string(),
                description: "Read-only access".to_string(),
                scope: "/subscriptions/sub-id".to_string(),
            }],
            application_object_id: None,
            ttl: Duration::hours(24),
            max_ttl: Duration::days(7),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let retrieved = engine.get_role("my-app").await.unwrap();
        assert_eq!(retrieved.name, "my-app");
        assert_eq!(retrieved.azure_roles.len(), 1);
    }

    #[tokio::test]
    async fn test_generate_credentials() {
        let engine = AzureSecretsEngine::new();
        let config = create_test_config();
        engine.configure(config.clone()).await.unwrap();

        let role = AzureRole {
            name: "webapp".to_string(),
            azure_roles: vec![
                AzureRoleDefinition {
                    id: "/subscriptions/sub-id/providers/Microsoft.Authorization/roleDefinitions/contributor-id".to_string(),
                    name: "Contributor".to_string(),
                    description: "Full access".to_string(),
                    scope: "/subscriptions/sub-id/resourceGroups/my-rg".to_string(),
                },
            ],
            application_object_id: None,
            ttl: Duration::hours(12),
            max_ttl: Duration::days(3),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let creds = engine.generate_credentials("webapp").await.unwrap();

        assert!(!creds.client_id.is_empty());
        assert_eq!(creds.client_secret.len(), 40);
        assert_eq!(creds.tenant_id, config.tenant_id);
        assert_eq!(creds.subscription_id, config.subscription_id);
    }

    #[tokio::test]
    async fn test_rotate_root_credentials() {
        let engine = AzureSecretsEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        // Should not error
        engine.rotate_root_credentials().await.unwrap();
    }

    #[tokio::test]
    async fn test_revoke_credentials() {
        let engine = AzureSecretsEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let role = AzureRole {
            name: "temp-app".to_string(),
            azure_roles: vec![AzureRoleDefinition {
                id: "/subscriptions/sub-id/providers/Microsoft.Authorization/roleDefinitions/reader-id".to_string(),
                name: "Reader".to_string(),
                description: "Read access".to_string(),
                scope: "/subscriptions/sub-id".to_string(),
            }],
            application_object_id: None,
            ttl: Duration::hours(1),
            max_ttl: Duration::hours(2),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let creds = engine.generate_credentials("temp-app").await.unwrap();

        // Verify exists
        let sps = engine.list_service_principals().await;
        assert!(sps.contains(&creds.client_id));

        // Revoke
        engine.revoke_credentials(&creds.client_id).await.unwrap();

        // Verify removed
        let sps = engine.list_service_principals().await;
        assert!(!sps.contains(&creds.client_id));
    }

    #[tokio::test]
    async fn test_role_assignment() {
        let engine = AzureSecretsEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let role = AzureRole {
            name: "multi-role-app".to_string(),
            azure_roles: vec![
                AzureRoleDefinition {
                    id: "role-1".to_string(),
                    name: "Reader".to_string(),
                    description: "Read".to_string(),
                    scope: "/subscriptions/sub-id".to_string(),
                },
                AzureRoleDefinition {
                    id: "role-2".to_string(),
                    name: "Contributor".to_string(),
                    description: "Write".to_string(),
                    scope: "/subscriptions/sub-id/resourceGroups/rg1".to_string(),
                },
            ],
            application_object_id: None,
            ttl: Duration::hours(24),
            max_ttl: Duration::days(7),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let creds = engine.generate_credentials("multi-role-app").await.unwrap();

        // Verify role assignments
        let assignments = engine.list_role_assignments().await;
        let sp_assignments: Vec<_> = assignments
            .iter()
            .filter(|_a| {
                let sps = futures::executor::block_on(engine.list_service_principals());
                sps.contains(&creds.client_id)
            })
            .collect();

        // Should have 2 role assignments
        assert!(sp_assignments.len() >= 2);
    }
}
