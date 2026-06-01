// AWS Secrets Manager Integration - Bidirectional sync with AWS
use aws_config::SdkConfig;
use aws_sdk_secretsmanager::Client;
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
    SecretToAWS,
    AWSToSecret,
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
    pub secreton_path: String,
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
    client: Client,
    secrets: Arc<RwLock<HashMap<String, AWSSecret>>>,
    sync_operations: Arc<RwLock<Vec<SyncOperation>>>,
}

impl AWSSecretsManager {
    pub fn new(config: AWSSecretsConfig, aws_config: &SdkConfig) -> Self {
        let client = Client::new(aws_config);
        Self {
            config: Arc::new(RwLock::new(config)),
            client,
            secrets: Arc::new(RwLock::new(HashMap::new())),
            sync_operations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Sync secret to AWS
    pub async fn sync_to_aws(
        &self,
        secreton_path: &str,
        secret_name: &str,
        secreton_data: &[u8],
    ) -> Result<SyncOperation> {
        let config = self.config.read().await;

        if config.sync_direction == SyncDirection::AWSToSecret {
            return Err(AWSError::SyncError(
                "Sync direction is AWS to Secret only".to_string(),
            ));
        }

        drop(config);

        let operation_id = uuid::Uuid::new_v4().to_string();

        // Create or update secret in AWS Secrets Manager
        let secret_value = std::str::from_utf8(secreton_data)
            .map_err(|e| AWSError::SyncError(format!("Invalid UTF-8 data: {}", e)))?;

        let request = self
            .client
            .create_secret()
            .name(secret_name)
            .secret_string(secret_value)
            .description(format!("Synced from Secreton path: {}", secreton_path));

        match request.send().await {
            Ok(response) => {
                let _secret_arn = response.arn().unwrap_or("unknown");

                let operation = SyncOperation {
                    operation_id: operation_id.clone(),
                    direction: SyncDirection::SecretToAWS,
                    source_path: secreton_path.to_string(),
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
            Err(_) => {
                // If create fails, try to update the existing secret
                let update_request = self
                    .client
                    .update_secret()
                    .secret_id(secret_name)
                    .secret_string(secret_value);

                update_request.send().await.map_err(|e| {
                    AWSError::ApiError(format!("Failed to create or update AWS secret: {}", e))
                })?;

                let operation = SyncOperation {
                    operation_id: operation_id.clone(),
                    direction: SyncDirection::SecretToAWS,
                    source_path: secreton_path.to_string(),
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
        }
    }

    /// Sync secret from AWS
    pub async fn sync_from_aws(&self, secret_name: &str) -> Result<(Vec<u8>, SyncOperation)> {
        let config = self.config.read().await;

        if config.sync_direction == SyncDirection::SecretToAWS {
            return Err(AWSError::SyncError(
                "Sync direction is Secret to AWS only".to_string(),
            ));
        }

        drop(config);

        let operation_id = uuid::Uuid::new_v4().to_string();

        // Fetch secret from AWS Secrets Manager
        let response = self
            .client
            .get_secret_value()
            .secret_id(secret_name)
            .send()
            .await
            .map_err(|e| AWSError::ApiError(format!("Failed to get AWS secret: {}", e)))?;

        let secret_string = response
            .secret_string()
            .ok_or_else(|| AWSError::SyncError("Secret has no string value".to_string()))?;

        let aws_data = secret_string.as_bytes().to_vec();

        let operation = SyncOperation {
            operation_id: operation_id.clone(),
            direction: SyncDirection::AWSToSecret,
            source_path: secret_name.to_string(),
            target_path: "".to_string(), // Will be set by caller
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            status: SyncStatus::Completed,
            records_synced: 1,
            error_message: None,
        };

        let mut sync_operations = self.sync_operations.write().await;
        sync_operations.push(operation.clone());

        Ok((aws_data, operation))
    }

    /// Bidirectional sync
    pub async fn bidirectional_sync(
        &self,
        secreton_path: &str,
        secret_name: &str,
        secreton_data: &[u8],
    ) -> Result<SyncOperation> {
        let config = self.config.read().await;

        if config.sync_direction != SyncDirection::Bidirectional {
            return Err(AWSError::SyncError(
                "Bidirectional sync not enabled".to_string(),
            ));
        }

        drop(config);

        // Get AWS secret metadata to compare timestamps
        let aws_metadata = match self
            .client
            .describe_secret()
            .secret_id(secret_name)
            .send()
            .await
        {
            Ok(response) => {
                let last_changed = response
                    .last_changed_date()
                    .and_then(|dt| dt.to_millis().ok())
                    .unwrap_or(0);
                Some(last_changed)
            }
            Err(_) => None, // AWS secret doesn't exist
        };

        // For now, assume secreton data is newer if AWS secret doesn't exist
        // In a real implementation, you'd get the secreton timestamp
        let secreton_timestamp = Utc::now().timestamp_millis();

        match aws_metadata {
            Some(aws_timestamp) if aws_timestamp > secreton_timestamp => {
                // AWS is newer, sync from AWS
                let (_data, operation) = self.sync_from_aws(secret_name).await?;
                Ok(operation)
            }
            _ => {
                // Secret is newer or AWS doesn't exist, sync to AWS
                self.sync_to_aws(secreton_path, secret_name, secreton_data)
                    .await
            }
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
    use aws_config::Region;

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

    fn create_test_aws_config() -> SdkConfig {
        SdkConfig::builder()
            .region(Region::new("us-east-1"))
            .build()
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials
    async fn test_sync_to_aws() {
        let aws_config = create_test_aws_config();
        let manager = AWSSecretsManager::new(create_test_config(), &aws_config);

        let test_data = br#"{"username":"testuser","password":"testpass"}"#;
        let operation = manager
            .sync_to_aws("secret/data/db/prod", "db-credentials", test_data)
            .await
            .unwrap();

        assert_eq!(operation.direction, SyncDirection::SecretToAWS);
        assert_eq!(operation.status, SyncStatus::Completed);
        assert_eq!(operation.records_synced, 1);
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials
    async fn test_sync_from_aws() {
        let aws_config = create_test_aws_config();
        let manager = AWSSecretsManager::new(create_test_config(), &aws_config);

        let (_data, operation) = manager.sync_from_aws("api-key").await.unwrap();

        assert_eq!(operation.direction, SyncDirection::AWSToSecret);
        assert_eq!(operation.status, SyncStatus::Completed);
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials
    async fn test_bidirectional_sync() {
        let aws_config = create_test_aws_config();
        let manager = AWSSecretsManager::new(create_test_config(), &aws_config);

        let test_data = br#"{"key":"value"}"#;
        let operation = manager
            .bidirectional_sync("secret/data/app/config", "app-config", test_data)
            .await
            .unwrap();

        assert_eq!(operation.status, SyncStatus::Completed);
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials
    async fn test_configure_rotation() {
        let aws_config = create_test_aws_config();
        let manager = AWSSecretsManager::new(create_test_config(), &aws_config);

        // First sync to create secret
        let test_data = br#"{"username":"test","password":"pass"}"#;
        manager
            .sync_to_aws("secret/data/db/prod", "db-credentials", test_data)
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
    #[ignore] // Requires AWS credentials
    async fn test_sync_history() {
        let aws_config = create_test_aws_config();
        let manager = AWSSecretsManager::new(create_test_config(), &aws_config);

        let test_data = br#"{"key":"value"}"#;
        manager
            .sync_to_aws("secret/data/db/prod", "db-credentials", test_data)
            .await
            .unwrap();

        let (_data, _operation) = manager.sync_from_aws("api-key").await.unwrap();

        let history = manager.get_sync_history(None, None).await;
        assert_eq!(history.len(), 2);

        let secreton_to_aws = manager
            .get_sync_history(Some(SyncDirection::SecretToAWS), None)
            .await;
        assert_eq!(secreton_to_aws.len(), 1);

        let completed = manager
            .get_sync_history(None, Some(SyncStatus::Completed))
            .await;
        assert_eq!(completed.len(), 2);
    }
}
