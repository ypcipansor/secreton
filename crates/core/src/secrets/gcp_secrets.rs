// GCP Secrets Engine - Google Cloud Platform dynamic credentials
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum GCPError {
    #[error("GCP error: {0}")]
    GCPError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("RoleSet not found: {0}")]
    RoleSetNotFound(String),
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),
}

pub type Result<T> = std::result::Result<T, GCPError>;

/// GCP secret type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GCPSecretType {
    AccessToken,
    ServiceAccountKey,
}

/// GCP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCPConfig {
    pub project_id: String,
    pub credentials: String, // JSON service account key
    pub scopes: Vec<String>, // OAuth2 scopes
    pub ttl: Duration,
    pub max_ttl: Duration,
}

/// IAM policy binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAMBinding {
    pub resource: String,   // e.g., "projects/my-project"
    pub roles: Vec<String>, // IAM roles to grant
}

/// GCP RoleSet definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCPRoleSet {
    pub name: String,
    pub project: String,
    pub bindings: Vec<IAMBinding>,
    pub secret_type: GCPSecretType,
    pub token_scopes: Vec<String>, // For access tokens
    pub ttl: Duration,
    pub max_ttl: Duration,
    pub created_at: DateTime<Utc>,
}

/// GCP service account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCPServiceAccount {
    pub email: String,
    pub private_key: String,
    pub project_id: String,
    pub unique_id: String,
    pub created_at: DateTime<Utc>,
}

/// GCP access token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCPAccessToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub token_type: String, // "Bearer"
}

/// GCP credentials response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCPCredentials {
    pub secret_type: GCPSecretType,
    pub access_token: Option<GCPAccessToken>,
    pub service_account_key: Option<GCPServiceAccount>,
}

/// GCP secrets engine
pub struct GCPSecretsEngine {
    config: Arc<RwLock<Option<GCPConfig>>>,
    rolesets: Arc<RwLock<HashMap<String, GCPRoleSet>>>,
    service_accounts: Arc<RwLock<HashMap<String, GCPServiceAccount>>>,
    access_tokens: Arc<RwLock<HashMap<String, GCPAccessToken>>>,
}

impl GCPSecretsEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            rolesets: Arc::new(RwLock::new(HashMap::new())),
            service_accounts: Arc::new(RwLock::new(HashMap::new())),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure GCP connection
    pub async fn configure(&self, config: GCPConfig) -> Result<()> {
        if config.project_id.is_empty() {
            return Err(GCPError::ConfigError("Project ID is required".to_string()));
        }
        if config.credentials.is_empty() {
            return Err(GCPError::ConfigError(
                "Service account credentials are required".to_string(),
            ));
        }

        // Validate credentials format (mock)
        self.validate_credentials(&config.credentials).await?;

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Validate GCP credentials
    async fn validate_credentials(&self, credentials: &str) -> Result<()> {
        // Parse JSON credentials
        let creds: serde_json::Value = serde_json::from_str(credentials)
            .map_err(|_| GCPError::InvalidCredentials("Invalid JSON format".to_string()))?;

        // Validate required fields
        let creds_obj = creds.as_object().ok_or_else(|| {
            GCPError::InvalidCredentials("Credentials must be a JSON object".to_string())
        })?;

        // Check for service account type
        if let Some(type_field) = creds_obj.get("type") {
            if let Some(type_str) = type_field.as_str() {
                if type_str != "service_account" {
                    return Err(GCPError::InvalidCredentials(
                        "Only service account credentials are supported".to_string(),
                    ));
                }
            } else {
                return Err(GCPError::InvalidCredentials(
                    "Type field must be a string".to_string(),
                ));
            }
        } else {
            return Err(GCPError::InvalidCredentials(
                "Type field is required".to_string(),
            ));
        }

        // Check for project_id
        if let Some(project_id) = creds_obj.get("project_id") {
            if !project_id.is_string() {
                return Err(GCPError::InvalidCredentials(
                    "project_id must be a string".to_string(),
                ));
            }
        } else {
            return Err(GCPError::InvalidCredentials(
                "project_id is required".to_string(),
            ));
        }

        // Check for private_key_id
        if let Some(private_key_id) = creds_obj.get("private_key_id") {
            if !private_key_id.is_string() {
                return Err(GCPError::InvalidCredentials(
                    "private_key_id must be a string".to_string(),
                ));
            }
        } else {
            return Err(GCPError::InvalidCredentials(
                "private_key_id is required".to_string(),
            ));
        }

        // Check for private_key
        if let Some(private_key) = creds_obj.get("private_key") {
            if !private_key.is_string() {
                return Err(GCPError::InvalidCredentials(
                    "private_key must be a string".to_string(),
                ));
            }
            let key_str = private_key.as_str().unwrap();
            if !key_str.contains("BEGIN PRIVATE KEY") {
                return Err(GCPError::InvalidCredentials(
                    "private_key must be in PEM format".to_string(),
                ));
            }
        } else {
            return Err(GCPError::InvalidCredentials(
                "private_key is required".to_string(),
            ));
        }

        // Check for client_email
        if let Some(client_email) = creds_obj.get("client_email") {
            if !client_email.is_string() {
                return Err(GCPError::InvalidCredentials(
                    "client_email must be a string".to_string(),
                ));
            }
            let email = client_email.as_str().unwrap();
            if !email.ends_with(".iam.gserviceaccount.com") {
                return Err(GCPError::InvalidCredentials(
                    "client_email must be a service account email".to_string(),
                ));
            }
        } else {
            return Err(GCPError::InvalidCredentials(
                "client_email is required".to_string(),
            ));
        }

        Ok(())
    }

    /// Create a RoleSet
    pub async fn create_roleset(&self, roleset: GCPRoleSet) -> Result<()> {
        if roleset.name.is_empty() {
            return Err(GCPError::ConfigError(
                "RoleSet name is required".to_string(),
            ));
        }
        if roleset.project.is_empty() {
            return Err(GCPError::ConfigError("Project is required".to_string()));
        }

        let mut rolesets = self.rolesets.write().await;
        rolesets.insert(roleset.name.clone(), roleset);

        Ok(())
    }

    /// Get RoleSet
    pub async fn get_roleset(&self, name: &str) -> Result<GCPRoleSet> {
        let rolesets = self.rolesets.read().await;
        rolesets
            .get(name)
            .cloned()
            .ok_or_else(|| GCPError::RoleSetNotFound(name.to_string()))
    }

    /// List RoleSets
    pub async fn list_rolesets(&self) -> Vec<String> {
        let rolesets = self.rolesets.read().await;
        rolesets.keys().cloned().collect()
    }

    /// Generate dynamic GCP credentials
    pub async fn generate_credentials(&self, roleset_name: &str) -> Result<GCPCredentials> {
        let roleset = self.get_roleset(roleset_name).await?;

        // Check if GCP is configured
        let config = self.config.read().await;
        if config.is_none() {
            return Err(GCPError::ConfigError("GCP not configured".to_string()));
        }

        match roleset.secret_type {
            GCPSecretType::AccessToken => {
                let token = self.generate_access_token(&roleset).await?;
                Ok(GCPCredentials {
                    secret_type: GCPSecretType::AccessToken,
                    access_token: Some(token),
                    service_account_key: None,
                })
            }
            GCPSecretType::ServiceAccountKey => {
                let sa = self.generate_service_account(&roleset).await?;
                Ok(GCPCredentials {
                    secret_type: GCPSecretType::ServiceAccountKey,
                    access_token: None,
                    service_account_key: Some(sa),
                })
            }
        }
    }

    /// Generate access token
    async fn generate_access_token(&self, roleset: &GCPRoleSet) -> Result<GCPAccessToken> {
        // Generate a more realistic token
        // In real implementation, this would:
        // 1. Use service account credentials to authenticate with GCP
        // 2. Request OAuth2 token with specified scopes
        // 3. Return actual token with proper expiration

        // Generate random token payload
        let token_payload = format!(
            "{{\"iss\":\"secreton@{}.iam.gserviceaccount.com\",\"scope\":\"{}\",\"aud\":\"https://oauth2.googleapis.com/token\",\"exp\":{},\"iat\":{}}}",
            roleset.project,
            roleset.token_scopes.join(" "),
            (Utc::now() + roleset.ttl).timestamp(),
            Utc::now().timestamp()
        );

        // Base64 encode the payload (simplified - real JWT would have proper signing)
        let token = BASE64_ENGINE.encode(token_payload.as_bytes());
        let access_token = format!("ya29.{}", token);

        let expires_at = Utc::now() + roleset.ttl;

        let gcp_token = GCPAccessToken {
            token: access_token.clone(),
            expires_at,
            token_type: "Bearer".to_string(),
        };

        // Store token
        let mut tokens = self.access_tokens.write().await;
        tokens.insert(access_token, gcp_token.clone());

        Ok(gcp_token)
    }

    /// Generate service account key
    async fn generate_service_account(&self, roleset: &GCPRoleSet) -> Result<GCPServiceAccount> {
        // Mock service account creation
        // In real implementation, this would:
        // 1. Create service account in GCP
        // 2. Apply IAM bindings
        // 3. Generate and download key
        // 4. Return key data

        let unique_id = uuid::Uuid::new_v4().to_string();
        let email = format!(
            "secreton-{}-{}@{}.iam.gserviceaccount.com",
            roleset.name,
            unique_id.chars().take(8).collect::<String>(),
            roleset.project
        );

        // Generate mock private key
        let private_key = self.generate_private_key();

        // Apply IAM bindings (mock)
        for binding in &roleset.bindings {
            self.apply_iam_bindings(&email, binding).await?;
        }

        let sa = GCPServiceAccount {
            email: email.clone(),
            private_key,
            project_id: roleset.project.clone(),
            unique_id,
            created_at: Utc::now(),
        };

        // Store service account
        let mut accounts = self.service_accounts.write().await;
        accounts.insert(email, sa.clone());

        Ok(sa)
    }

    /// Generate mock private key
    fn generate_private_key(&self) -> String {
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            uuid::Uuid::new_v4()
        )
    }

    /// Apply IAM bindings
    async fn apply_iam_bindings(&self, _email: &str, _binding: &IAMBinding) -> Result<()> {
        // Mock IAM binding
        // In real implementation, this would:
        // 1. Call GCP IAM API
        // 2. Add service account to roles
        // 3. Verify bindings applied

        Ok(())
    }

    /// Rotate root credentials
    pub async fn rotate_root_credentials(&self) -> Result<()> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(GCPError::ConfigError("GCP not configured".to_string()));
        }

        // Mock root credential rotation
        // In real implementation, this would:
        // 1. Generate new service account key
        // 2. Update Secret configuration
        // 3. Delete old key

        Ok(())
    }

    /// Revoke credentials
    pub async fn revoke_credentials(&self, identifier: &str) -> Result<()> {
        // Try to revoke as service account
        {
            let mut accounts = self.service_accounts.write().await;
            if accounts.remove(identifier).is_some() {
                // Mock deletion from GCP
                self.delete_service_account(identifier).await?;
                return Ok(());
            }
        }

        // Try to revoke as access token
        {
            let mut tokens = self.access_tokens.write().await;
            if tokens.remove(identifier).is_some() {
                // Tokens expire automatically, no action needed
                return Ok(());
            }
        }

        Err(GCPError::InvalidCredentials(
            "Credential not found".to_string(),
        ))
    }

    /// Delete service account from GCP
    async fn delete_service_account(&self, _email: &str) -> Result<()> {
        // Mock deletion
        // In real implementation, this would call GCP IAM API to delete
        Ok(())
    }

    /// Get configuration status
    pub async fn is_configured(&self) -> bool {
        let config = self.config.read().await;
        config.is_some()
    }

    /// List service accounts
    pub async fn list_service_accounts(&self) -> Vec<String> {
        let accounts = self.service_accounts.read().await;
        accounts.keys().cloned().collect()
    }
}

impl Default for GCPSecretsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> GCPConfig {
        GCPConfig {
            project_id: "my-test-project".to_string(),
            credentials: r#"{
                "type": "service_account",
                "project_id": "my-test-project",
                "private_key_id": "mock_key_id",
                "private_key": "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----",
                "client_email": "secreton@my-test-project.iam.gserviceaccount.com"
            }"#
            .to_string(),
            scopes: vec!["https://www.googleapis.com/auth/cloud-platform".to_string()],
            ttl: Duration::hours(1),
            max_ttl: Duration::hours(24),
        }
    }

    #[tokio::test]
    async fn test_configure_gcp() {
        let engine = GCPSecretsEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        assert!(engine.is_configured().await);
    }

    #[tokio::test]
    async fn test_create_roleset() {
        let engine = GCPSecretsEngine::new();

        let roleset = GCPRoleSet {
            name: "my-roleset".to_string(),
            project: "my-project".to_string(),
            bindings: vec![IAMBinding {
                resource: "projects/my-project".to_string(),
                roles: vec!["roles/viewer".to_string()],
            }],
            secret_type: GCPSecretType::AccessToken,
            token_scopes: vec!["https://www.googleapis.com/auth/cloud-platform".to_string()],
            ttl: Duration::hours(1),
            max_ttl: Duration::hours(12),
            created_at: Utc::now(),
        };

        engine.create_roleset(roleset).await.unwrap();

        let retrieved = engine.get_roleset("my-roleset").await.unwrap();
        assert_eq!(retrieved.name, "my-roleset");
        assert_eq!(retrieved.secret_type, GCPSecretType::AccessToken);
    }

    #[tokio::test]
    async fn test_generate_access_token() {
        let engine = GCPSecretsEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let roleset = GCPRoleSet {
            name: "token-role".to_string(),
            project: "my-project".to_string(),
            bindings: vec![],
            secret_type: GCPSecretType::AccessToken,
            token_scopes: vec!["https://www.googleapis.com/auth/compute.readonly".to_string()],
            ttl: Duration::minutes(30),
            max_ttl: Duration::hours(4),
            created_at: Utc::now(),
        };

        engine.create_roleset(roleset).await.unwrap();

        let creds = engine.generate_credentials("token-role").await.unwrap();

        assert_eq!(creds.secret_type, GCPSecretType::AccessToken);
        assert!(creds.access_token.is_some());

        let token = creds.access_token.unwrap();
        assert!(token.token.starts_with("ya29."));
        assert_eq!(token.token_type, "Bearer");
    }

    #[tokio::test]
    async fn test_generate_service_account_key() {
        let engine = GCPSecretsEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let roleset = GCPRoleSet {
            name: "app-sa".to_string(),
            project: "my-app-project".to_string(),
            bindings: vec![IAMBinding {
                resource: "projects/my-app-project".to_string(),
                roles: vec!["roles/storage.objectViewer".to_string()],
            }],
            secret_type: GCPSecretType::ServiceAccountKey,
            token_scopes: vec![],
            ttl: Duration::days(30),
            max_ttl: Duration::days(90),
            created_at: Utc::now(),
        };

        engine.create_roleset(roleset).await.unwrap();

        let creds = engine.generate_credentials("app-sa").await.unwrap();

        assert_eq!(creds.secret_type, GCPSecretType::ServiceAccountKey);
        assert!(creds.service_account_key.is_some());

        let sa = creds.service_account_key.unwrap();
        assert!(sa.email.contains("secreton-app-sa"));
        assert!(sa.email.ends_with(".iam.gserviceaccount.com"));
        assert!(sa.private_key.contains("BEGIN PRIVATE KEY"));
    }

    #[tokio::test]
    async fn test_rotate_root_credentials() {
        let engine = GCPSecretsEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        // Should not error
        engine.rotate_root_credentials().await.unwrap();
    }

    #[tokio::test]
    async fn test_revoke_service_account() {
        let engine = GCPSecretsEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let roleset = GCPRoleSet {
            name: "temp-sa".to_string(),
            project: "temp-project".to_string(),
            bindings: vec![],
            secret_type: GCPSecretType::ServiceAccountKey,
            token_scopes: vec![],
            ttl: Duration::hours(1),
            max_ttl: Duration::hours(2),
            created_at: Utc::now(),
        };

        engine.create_roleset(roleset).await.unwrap();

        let creds = engine.generate_credentials("temp-sa").await.unwrap();
        let sa = creds.service_account_key.unwrap();

        // Verify exists
        let accounts = engine.list_service_accounts().await;
        assert!(accounts.contains(&sa.email));

        // Revoke
        engine.revoke_credentials(&sa.email).await.unwrap();

        // Verify removed
        let accounts = engine.list_service_accounts().await;
        assert!(!accounts.contains(&sa.email));
    }
}
