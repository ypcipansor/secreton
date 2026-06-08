//! Integrations service for managing external cloud secret providers.

use crate::services::audit::AuditLogger;
use crate::services::crypto::CryptoService;
use anyhow::Result;
use secreton_integrations::integrations::aws_secrets_manager::{
    AWSSecretsConfig, AWSSecretsManager,
};
use secreton_integrations::integrations::azure_secrets_backend::{
    AzureSecretsBackend, AzureSecretsConfig, SyncConfig,
};
use secreton_storage::{
    EncryptionMetadata, QueryParams, SecretEntry, SecurityLevel, StorageBackend,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;

/// Integration type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrationType {
    AwsSecretsManager,
    AzureKeyVault,
}

/// Integration configuration entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub id: String,
    pub name: String,
    pub integration_type: IntegrationType,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct IntegrationsService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    _audit: Arc<AuditLogger>,
}

impl IntegrationsService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        audit: Arc<AuditLogger>,
    ) -> Self {
        Self {
            storage,
            crypto,
            _audit: audit,
        }
    }

    /// List all registered integrations
    pub async fn list_integrations(&self) -> Result<Vec<IntegrationConfig>> {
        let query = QueryParams {
            path_prefix: Some("sys/integrations/".to_string()),
            ..Default::default()
        };

        let entries = self.storage.list(&query).await?;
        let mut integrations = Vec::new();

        for entry in entries {
            if let Ok(decrypted) = self.crypto.decrypt(&entry.encrypted_data).await {
                if let Ok(config) = serde_json::from_slice::<IntegrationConfig>(&decrypted) {
                    integrations.push(config);
                }
            }
        }

        Ok(integrations)
    }

    /// Get integration by ID
    pub async fn get_integration(&self, id: &str) -> Result<Option<IntegrationConfig>> {
        let path = format!("sys/integrations/{}", id);
        if let Some(entry) = self.storage.get_by_path(&path).await? {
            let decrypted = self.crypto.decrypt(&entry.encrypted_data).await?;
            let config = serde_json::from_slice::<IntegrationConfig>(&decrypted)?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    /// Save integration configuration
    pub async fn save_integration(&self, config: IntegrationConfig) -> Result<()> {
        let path = format!("sys/integrations/{}", config.id);
        let existing = self.storage.get_by_path(&path).await?;

        let data = serde_json::to_vec(&config)?;
        let encrypted_data = self.crypto.encrypt_data(&data).await?;

        if let Some(existing_entry) = existing {
            let mut entry = SecretEntry::new(
                path,
                encrypted_data,
                EncryptionMetadata::default(),
                SecurityLevel::Secret,
                uuid::Uuid::nil(),
            );
            entry.id = existing_entry.id;
            entry.version = existing_entry.version + 1;
            self.storage.update(&entry).await?;
        } else {
            let mut entry = SecretEntry::new(
                path,
                encrypted_data,
                EncryptionMetadata::default(),
                SecurityLevel::Secret,
                uuid::Uuid::nil(),
            );
            entry.id = uuid::Uuid::new_v4();
            self.storage.store(&entry).await?;
        }

        Ok(())
    }

    /// Delete integration configuration
    pub async fn delete_integration(&self, id: &str) -> Result<()> {
        let path = format!("sys/integrations/{}", id);
        self.storage.delete_by_path(&path).await?;
        Ok(())
    }

    /// Create AWS Secrets Manager client from config
    pub async fn get_aws_manager(&self, config_id: &str) -> Result<AWSSecretsManager> {
        let config_entry = self
            .get_integration(config_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Integration {} not found", config_id))?;

        let aws_config: AWSSecretsConfig = serde_json::from_value(config_entry.config)?;
        let sdk_config = aws_config::SdkConfig::builder().build();

        Ok(AWSSecretsManager::new(aws_config, &sdk_config))
    }
}
