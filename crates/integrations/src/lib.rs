//! # Secreton External Integrations
//!
//! Third-party service integrations and connectors for the Secreton
//! security vault, including cloud providers, CI/CD systems, and infrastructure tools.

#![allow(async_fn_in_trait)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod error;
pub mod database_rotation;
pub mod snapshot;
pub mod dynamic;

// Cloud provider integrations
#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "azure")]
pub mod azure;
#[cfg(feature = "gcp")]
pub mod gcp;

// Infrastructure integrations
#[cfg(feature = "kubernetes")]
pub mod kubernetes;

// CI/CD integrations
// pub mod cicd;

// Service mesh integrations
// pub mod service_mesh;

// All integrations
pub mod integrations;

// Re-export main types
pub use error::IntegrationError;

/// Integration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationResult {
    /// Whether the integration operation was successful
    pub success: bool,
    /// Integration provider
    pub provider: String,
    /// Operation performed
    pub operation: String,
    /// Result data
    pub data: Option<serde_json::Value>,
    /// Error message if failed
    pub error: Option<String>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Integration provider trait
#[async_trait::async_trait]
pub trait IntegrationProvider: Send + Sync {
    /// Provider name
    fn name(&self) -> &str;

    /// Test connectivity to the external service
    async fn test_connection(&self) -> Result<(), IntegrationError>;

    /// Sync data from external service
    async fn sync_data(&self, config: &IntegrationConfig) -> Result<IntegrationResult, IntegrationError>;

    /// Push data to external service
    async fn push_data(&self, data: serde_json::Value, config: &IntegrationConfig) -> Result<IntegrationResult, IntegrationError>;
}

/// Integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    /// Integration endpoint URL
    pub endpoint: String,
    /// Authentication credentials
    pub credentials: IntegrationCredentials,
    /// Additional configuration
    pub options: HashMap<String, String>,
}

/// Integration credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrationCredentials {
    /// API key authentication
    ApiKey(String),
    /// OAuth2 authentication
    OAuth2 { client_id: String, client_secret: String },
    /// AWS IAM authentication
    AwsIam,
    /// Azure authentication
    Azure { tenant_id: String, client_id: String, client_secret: String },
    /// Service account key
    ServiceAccount(String),
}

/// Supported integration types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntegrationType {
    /// AWS Secrets Manager
    AwsSecretsManager,
    /// Azure Key Vault
    AzureKeyVault,
    /// Google Cloud Secret Manager
    GcpSecretManager,
    /// HashiCorp Vault
    HashiCorpVault,
    /// Kubernetes secrets
    Kubernetes,
    /// Jenkins CI/CD
    Jenkins,
    /// GitLab CI/CD
    GitLab,
    /// GitHub Actions
    GitHubActions,
    /// Ansible
    Ansible,
    /// Terraform
    Terraform,
}