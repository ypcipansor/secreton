// AWS Secrets Manager Integration - Bidirectional sync with AWS
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum AWSError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Sync error: {0}")]
    SyncError(String),
    #[error("AWS API error: {0}")]
    ApiError(String),
}

pub type Result<T> = std::result::Result<T, AWSError>;

/// Sync direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncDirection {
    VaultToAWS,
    AWSToVault,
    Bidirectional,
}

/// AWS Secrets Manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AWSSecretsConfig {
    pub region: String,
    pub cross_account_role_arn: Option<String>,
    pub sync_direction: SyncDirection,
    pub rotation_lambda_arn: Option<String>,
    pub enable_versioning: bool,
}

/// AWS Secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AWSSecret {
    pub secret_name: String,
    pub secret_arn: String,
    pub vault_path: String,
    pub description: String,
    pub tags: HashMap<String, String>,
    pub rotation_enabled: bool,
    pub rotation_lambda_arn: Option<String>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub last_accessed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOperation {
    pub operation_id: String,
    pub direction: SyncDirection,
    pub source_path: String,
    pub target_path: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: SyncStatus,
    pub records_synced: u32,
    pub error_message: Option<String>,
}

/// Sync status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// Rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub enabled: bool,
    pub automatically_after_days: u32,
    pub lambda_arn: String,
}

/// AWS Secrets Manager Integration
pub struct AWSSecretsManager {
    config: Arc<RwLock<AWSSecretsConfig>>,
    secrets: Arc<RwLock<HashMap<String, AWSSecret>>>,
    sync_operations: Arc<RwLock<Vec<SyncOperation>>>,
}

impl AWSSecretsManager {
    pub fn new(config: AWSSecretsConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            secrets: Arc::new(RwLock::new(HashMap::new())),
            sync_operations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Sync secret to AWS
    pub async fn sync_to_aws(&self, vault_path: &str, secret_name: &str) -> Result<SyncOperation> {
        let config = self.config.read().await;

        if config.sync_direction == SyncDirection::AWSToVault {
            return Err(AWSError::SyncError(
                "Sync direction is AWS to Vault only".to_string(),
            ));
        }

        drop(config);

        let operation_id = uuid::Uuid::new_v4().to_string();

        // Mock: Fetch from Vault
        let vault_data = self.mock_fetch_from_vault(vault_path).await?;

        // Mock: Store to AWS Secrets Manager
        let secret_arn = self
            .mock_store_to_aws(secret_name, &vault_data, vault_path)
            .await?;

        let operation = SyncOperation {
            operation_id: operation_id.clone(),
            direction: SyncDirection::VaultToAWS,
            source_path: vault_path.to_string(),
            target_path: secret_name.to_string(),
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            status: SyncStatus::Completed,
            records_synced: 1,
            error_message: None,
        };

        let mut sync_operations = self.sync_operations.write().await;
        sync_operations.push(operation.clone());

        Ok(operation)
    }

    /// Sync secret from AWS
    pub async fn sync_from_aws(
        &self,
        secret_name: &str,
        vault_path: &str,
    ) -> Result<SyncOperation> {
        let config = self.config.read().await;

        if config.sync_direction == SyncDirection::VaultToAWS {
            return Err(AWSError::SyncError(
                "Sync direction is Vault to AWS only".to_string(),
            ));
        }

        drop(config);

        let operation_id = uuid::Uuid::new_v4().to_string();

        // Mock: Fetch from AWS
        let aws_data = self.mock_fetch_from_aws(secret_name).await?;

        // Mock: Store to Vault
        self.mock_store_to_vault(vault_path, &aws_data).await?;

        let operation = SyncOperation {
            operation_id: operation_id.clone(),
            direction: SyncDirection::AWSToVault,
            source_path: secret_name.to_string(),
            target_path: vault_path.to_string(),
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            status: SyncStatus::Completed,
            records_synced: 1,
            error_message: None,
        };

        let mut sync_operations = self.sync_operations.write().await;
        sync_operations.push(operation.clone());

        Ok(operation)
    }

    /// Bidirectional sync
    pub async fn bidirectional_sync(
        &self,
        vault_path: &str,
        secret_name: &str,
    ) -> Result<SyncOperation> {
        let config = self.config.read().await;

        if config.sync_direction != SyncDirection::Bidirectional {
            return Err(AWSError::SyncError(
                "Bidirectional sync not enabled".to_string(),
            ));
        }

        drop(config);

        // Mock: Compare timestamps to determine sync direction
        let vault_timestamp = self.mock_get_vault_timestamp(vault_path).await?;
        let aws_timestamp = self.mock_get_aws_timestamp(secret_name).await?;

        if vault_timestamp > aws_timestamp {
            self.sync_to_aws(vault_path, secret_name).await
        } else {
            self.sync_from_aws(secret_name, vault_path).await
        }
    }

    /// Configure rotation
    pub async fn configure_rotation(
        &self,
        secret_name: &str,
        rotation_config: RotationConfig,
    ) -> Result<()> {
        let secrets = self.secrets.read().await;
        let secret = secrets
            .get(secret_name)
            .ok_or_else(|| AWSError::ConfigError("Secret not found".to_string()))?
            .clone();

        drop(secrets);

        let mut updated_secret = secret;
        updated_secret.rotation_enabled = rotation_config.enabled;
        updated_secret.rotation_lambda_arn = Some(rotation_config.lambda_arn);

        let mut secrets = self.secrets.write().await;
        secrets.insert(secret_name.to_string(), updated_secret);

        Ok(())
    }

    /// List synced secrets
    pub async fn list_synced_secrets(&self) -> Vec<AWSSecret> {
        let secrets = self.secrets.read().await;
        secrets.values().cloned().collect()
    }

    /// Get sync history
    pub async fn get_sync_history(
        &self,
        direction: Option<SyncDirection>,
        status: Option<SyncStatus>,
    ) -> Vec<SyncOperation> {
        let sync_operations = self.sync_operations.read().await;

        sync_operations
            .iter()
            .filter(|op| {
                let direction_match = direction
                    .as_ref()
                    .map(|d| &op.direction == d)
                    .unwrap_or(true);
                let status_match = status.as_ref().map(|s| &op.status == s).unwrap_or(true);
                direction_match && status_match
            })
            .cloned()
            .collect()
    }

    /// Get secret
    pub async fn get_secret(&self, secret_name: &str) -> Option<AWSSecret> {
        let secrets = self.secrets.read().await;
        secrets.get(secret_name).cloned()
    }

    /// Delete secret mapping
    pub async fn delete_secret(&self, secret_name: &str) -> Result<()> {
        let mut secrets = self.secrets.write().await;
        secrets
            .remove(secret_name)
            .ok_or_else(|| AWSError::ConfigError("Secret not found".to_string()))?;
        Ok(())
    }

    // Helper methods

    async fn mock_fetch_from_vault(&self, vault_path: &str) -> Result<HashMap<String, String>> {
        let mut data = HashMap::new();
        data.insert("username".to_string(), "vaultuser".to_string());
        data.insert("password".to_string(), "vaultpass123".to_string());
        Ok(data)
    }

    async fn mock_store_to_aws(
        &self,
        secret_name: &str,
        data: &HashMap<String, String>,
        vault_path: &str,
    ) -> Result<String> {
        let config = self.config.read().await;
        let region = config.region.clone();
        drop(config);

        let secret_arn = format!(
            "arn:aws:secretsmanager:{}:123456789012:secret:{}",
            region, secret_name
        );

        let aws_secret = AWSSecret {
            secret_name: secret_name.to_string(),
            secret_arn: secret_arn.clone(),
            vault_path: vault_path.to_string(),
            description: format!("Synced from Vault: {}", vault_path),
            tags: HashMap::from([
                ("source".to_string(), "vault".to_string()),
                ("managed-by".to_string(), "secreton".to_string()),
            ]),
            rotation_enabled: false,
            rotation_lambda_arn: None,
            last_rotated_at: None,
            last_accessed_at: Some(Utc::now()),
            created_at: Utc::now(),
        };

        let mut secrets = self.secrets.write().await;
        secrets.insert(secret_name.to_string(), aws_secret);

        Ok(secret_arn)
    }

    async fn mock_fetch_from_aws(&self, secret_name: &str) -> Result<HashMap<String, String>> {
        let mut data = HashMap::new();
        data.insert("username".to_string(), "awsuser".to_string());
        data.insert("password".to_string(), "awspass456".to_string());
        Ok(data)
    }

    async fn mock_store_to_vault(
        &self,
        vault_path: &str,
        data: &HashMap<String, String>,
    ) -> Result<()> {
        // Mock store to Vault
        Ok(())
    }

    async fn mock_get_vault_timestamp(&self, vault_path: &str) -> Result<DateTime<Utc>> {
        Ok(Utc::now())
    }

    async fn mock_get_aws_timestamp(&self, secret_name: &str) -> Result<DateTime<Utc>> {
        Ok(Utc::now() - chrono::Duration::hours(1))
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> SyncStatistics {
        let secrets = self.secrets.read().await;
        let sync_operations = self.sync_operations.read().await;

        let total_secrets = secrets.len();
        let total_syncs = sync_operations.len();
        let successful_syncs = sync_operations
            .iter()
            .filter(|op| op.status == SyncStatus::Completed)
            .count();
        let failed_syncs = sync_operations
            .iter()
            .filter(|op| op.status == SyncStatus::Failed)
            .count();
        let rotation_enabled_count = secrets.values().filter(|s| s.rotation_enabled).count();

        SyncStatistics {
            total_secrets,
            total_syncs,
            successful_syncs,
            failed_syncs,
            rotation_enabled_count,
        }
    }
}

/// Sync statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatistics {
    pub total_secrets: usize,
    pub total_syncs: usize,
    pub successful_syncs: usize,
    pub failed_syncs: usize,
    pub rotation_enabled_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AWSSecretsConfig {
        AWSSecretsConfig {
            region: "us-east-1".to_string(),
            cross_account_role_arn: None,
            sync_direction: SyncDirection::Bidirectional,
            rotation_lambda_arn: Some(
                "arn:aws:lambda:us-east-1:123456789012:function:rotate".to_string(),
            ),
            enable_versioning: true,
        }
    }

    #[tokio::test]
    async fn test_sync_to_aws() {
        let manager = AWSSecretsManager::new(create_test_config());

        let operation = manager
            .sync_to_aws("secret/data/db/prod", "db-credentials")
            .await
            .unwrap();

        assert_eq!(operation.direction, SyncDirection::VaultToAWS);
        assert_eq!(operation.status, SyncStatus::Completed);
        assert_eq!(operation.records_synced, 1);

        let secrets = manager.list_synced_secrets().await;
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_name, "db-credentials");
        assert_eq!(secrets[0].tags.get("source"), Some(&"vault".to_string()));
    }

    #[tokio::test]
    async fn test_sync_from_aws() {
        let manager = AWSSecretsManager::new(create_test_config());

        let operation = manager
            .sync_from_aws("api-key", "secret/data/api/prod")
            .await
            .unwrap();

        assert_eq!(operation.direction, SyncDirection::AWSToVault);
        assert_eq!(operation.status, SyncStatus::Completed);
    }

    #[tokio::test]
    async fn test_bidirectional_sync() {
        let manager = AWSSecretsManager::new(create_test_config());

        let operation = manager
            .bidirectional_sync("secret/data/app/config", "app-config")
            .await
            .unwrap();

        assert_eq!(operation.status, SyncStatus::Completed);
    }

    #[tokio::test]
    async fn test_configure_rotation() {
        let manager = AWSSecretsManager::new(create_test_config());

        // First sync to create secret
        manager
            .sync_to_aws("secret/data/db/prod", "db-credentials")
            .await
            .unwrap();

        let rotation_config = RotationConfig {
            enabled: true,
            automatically_after_days: 30,
            lambda_arn: "arn:aws:lambda:us-east-1:123456789012:function:rotate-db".to_string(),
        };

        manager
            .configure_rotation("db-credentials", rotation_config)
            .await
            .unwrap();

        let secret = manager.get_secret("db-credentials").await.unwrap();
        assert!(secret.rotation_enabled);
        assert_eq!(
            secret.rotation_lambda_arn,
            Some("arn:aws:lambda:us-east-1:123456789012:function:rotate-db".to_string())
        );
    }

    #[tokio::test]
    async fn test_sync_history() {
        let manager = AWSSecretsManager::new(create_test_config());

        manager
            .sync_to_aws("secret/data/db/prod", "db-credentials")
            .await
            .unwrap();

        manager
            .sync_from_aws("api-key", "secret/data/api/prod")
            .await
            .unwrap();

        let history = manager.get_sync_history(None, None).await;
        assert_eq!(history.len(), 2);

        let vault_to_aws = manager
            .get_sync_history(Some(SyncDirection::VaultToAWS), None)
            .await;
        assert_eq!(vault_to_aws.len(), 1);

        let completed = manager
            .get_sync_history(None, Some(SyncStatus::Completed))
            .await;
        assert_eq!(completed.len(), 2);
    }
}
