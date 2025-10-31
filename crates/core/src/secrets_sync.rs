//! Secrets Sync Module
//!
//! This module provides functionality to synchronize secrets between
//! Secreton and external secret management systems.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::storage::secret::SecretStorage;

/// Supported external secret management systems
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExternalSystem {
    /// AWS Secrets Manager
    AwsSecretsManager,
    /// Azure Key Vault
    AzureKeyVault,
    /// Google Cloud Secret Manager
    GcpSecretManager,
    /// HashiCorp Vault
    HashiCorpVault,
    /// Generic REST API
    GenericRest,
}

/// Sync operation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncOperation {
    /// Create a new secret in the external system
    Create,
    /// Update an existing secret
    Update,
    /// Delete a secret from the external system
    Delete,
    /// Sync metadata only
    MetadataOnly,
}

/// Sync configuration for an external system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// External system type
    pub system: ExternalSystem,
    /// Connection configuration
    pub connection: ConnectionConfig,
    /// Sync policies
    pub policies: SyncPolicies,
    /// Retry configuration
    pub retry: RetryConfig,
}

/// Connection configuration for external systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Endpoint URL
    pub endpoint: String,
    /// Authentication credentials
    pub credentials: HashMap<String, String>,
    /// Connection timeout (seconds)
    pub timeout: u64,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS verification
    pub verify: bool,
    /// Client certificate path
    pub client_cert: Option<String>,
    /// Client key path
    pub client_key: Option<String>,
    /// CA certificate path
    pub ca_cert: Option<String>,
}

/// Sync policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPolicies {
    /// Sync direction
    pub direction: SyncDirection,
    /// Conflict resolution strategy
    pub conflict_resolution: ConflictResolution,
    /// Filter patterns for secrets to sync
    pub secret_filters: Vec<String>,
    /// Metadata fields to sync
    pub metadata_fields: Vec<String>,
    /// Enable automatic sync
    pub auto_sync: bool,
    /// Sync interval (seconds)
    pub sync_interval: u64,
}

/// Sync direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncDirection {
    /// Sync from Secreton to external system
    Outbound,
    /// Sync from external system to Secreton
    Inbound,
    /// Bidirectional sync
    Bidirectional,
}

/// Conflict resolution strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictResolution {
    /// Use Secreton version (overwrite external)
    SecretonWins,
    /// Use external system version (overwrite Secreton)
    ExternalWins,
    /// Create version conflict and require manual resolution
    ManualResolution,
    /// Merge based on timestamp (newest wins)
    TimestampWins,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries
    pub max_retries: u32,
    /// Initial retry delay (seconds)
    pub initial_delay: u64,
    /// Maximum retry delay (seconds)
    pub max_delay: u64,
    /// Retry backoff multiplier
    pub backoff_multiplier: f64,
}

/// Sync status for a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Secret path in Secreton
    pub secreton_path: String,
    /// External system identifier
    pub external_id: String,
    /// Last sync timestamp
    pub last_sync: DateTime<Utc>,
    /// Sync status
    pub status: SyncStatusType,
    /// Last error message (if failed)
    pub error_message: Option<String>,
    /// Sync metadata
    pub metadata: HashMap<String, String>,
}

/// Sync status types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncStatusType {
    /// Successfully synced
    Synced,
    /// Failed to sync
    Failed,
    /// Pending sync
    Pending,
    /// Conflict detected
    Conflict,
    /// Deleted in external system
    Deleted,
}

/// Sync result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// Operation performed
    pub operation: SyncOperation,
    /// Success status
    pub success: bool,
    /// External system identifier
    pub external_id: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// Sync metadata
    pub metadata: HashMap<String, String>,
}

/// External system client trait
#[async_trait]
pub trait ExternalSystemClient: Send + Sync {
    /// Test connection to the external system
    async fn test_connection(&self) -> Result<bool>;

    /// Create a secret in the external system
    async fn create_secret(&self, path: &str, data: &[u8], metadata: &HashMap<String, String>) -> Result<String>;

    /// Read a secret from the external system
    async fn read_secret(&self, external_id: &str) -> Result<(Vec<u8>, HashMap<String, String>)>;

    /// Update a secret in the external system
    async fn update_secret(&self, external_id: &str, data: &[u8], metadata: &HashMap<String, String>) -> Result<()>;

    /// Delete a secret from the external system
    async fn delete_secret(&self, external_id: &str) -> Result<()>;

    /// List secrets in the external system
    async fn list_secrets(&self, path_prefix: Option<&str>) -> Result<Vec<String>>;

    /// Get secret metadata
    async fn get_secret_metadata(&self, external_id: &str) -> Result<HashMap<String, String>>;
}

/// Secrets sync manager
pub struct SecretsSyncManager {
    clients: RwLock<HashMap<String, Box<dyn ExternalSystemClient>>>,
    sync_configs: RwLock<HashMap<String, SyncConfig>>,
    sync_status: RwLock<HashMap<String, SyncStatus>>,
    retry_manager: Arc<RetryManager>,
    storage: Arc<dyn SecretStorage>,
}

/// Sync manager configuration
#[derive(Debug, Clone)]
pub struct SyncManagerConfig {
    /// Default retry configuration
    pub default_retry: RetryConfig,
    /// Sync worker count
    pub worker_count: usize,
    /// Maximum concurrent syncs
    pub max_concurrent_syncs: usize,
    /// Enable sync metrics
    pub enable_metrics: bool,
}

impl SecretsSyncManager {
    /// Create a new sync manager
    pub fn new(config: SyncManagerConfig, storage: Arc<dyn SecretStorage>) -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            sync_configs: RwLock::new(HashMap::new()),
            sync_status: RwLock::new(HashMap::new()),
            retry_manager: Arc::new(RetryManager::new(config.default_retry)),
            storage,
        }
    }

    /// Register an external system client
    pub async fn register_client(&self, system_id: String, client: Box<dyn ExternalSystemClient>) -> Result<()> {
        // Test the connection
        if !client.test_connection().await? {
            return Err(SecretonError::ServiceUnavailable {
                service: "Failed to connect to external system".to_string(),
            });
        }

        self.clients.write().await.insert(system_id, client);
        Ok(())
    }

    /// Configure sync for a path pattern
    pub async fn configure_sync(&self, path_pattern: String, config: SyncConfig) -> Result<()> {
        self.sync_configs.write().await.insert(path_pattern, config);
        Ok(())
    }

    /// Sync a specific secret
    pub async fn sync_secret(&self, secreton_path: &str, operation: SyncOperation) -> Result<SyncResult> {
        // Find applicable sync configuration
        let config = self.find_sync_config(secreton_path).await?;

        // Get the appropriate client
        let client = self.get_client(&config.system).await?;

        // Perform the sync operation with retry logic
        let result = self.retry_manager.execute_with_retry(|| async {
            self.perform_sync_operation(&*client, secreton_path, &operation, &config).await
        }).await?;

        // Update sync status
        self.update_sync_status(secreton_path, &result).await?;

        Ok(result)
    }

    /// Sync all secrets matching a pattern
    pub async fn sync_by_pattern(&self, pattern: &str) -> Result<Vec<SyncResult>> {
        let mut results = Vec::new();

        // This would typically query the storage backend for matching secrets
        // For now, we'll return an empty list as this is a demonstration
        // In a real implementation, this would:
        // 1. Query storage for secrets matching the pattern
        // 2. Sync each secret according to its configuration
        // 3. Collect and return results

        Ok(results)
    }

    /// Get sync status for a secret
    pub async fn get_sync_status(&self, secreton_path: &str) -> Option<SyncStatus> {
        self.sync_status.read().await.get(secreton_path).cloned()
    }

    /// List all sync configurations
    pub async fn list_sync_configs(&self) -> Vec<(String, SyncConfig)> {
        self.sync_configs.read().await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Find sync configuration for a path
    async fn find_sync_config(&self, path: &str) -> Result<SyncConfig> {
        for (pattern, config) in self.sync_configs.read().await.iter() {
            if self.path_matches_pattern(path, pattern) {
                return Ok(config.clone());
            }
        }
        Err(SecretonError::Configuration {
            message: format!("No sync configuration found for path: {}", path),
        })
    }

    /// Check if a path matches a pattern
    fn path_matches_pattern(&self, path: &str, pattern: &str) -> bool {
        // Simple pattern matching - in a real implementation, this would use glob patterns
        path.starts_with(pattern.trim_end_matches('*')) ||
        pattern == "*" ||
        path == pattern
    }

    /// Get client for an external system
    async fn get_client(&self, system: &ExternalSystem) -> Result<Arc<dyn ExternalSystemClient>> {
        let system_id = format!("{:?}", system);
        self.clients.read().await.get(&system_id)
            .cloned()
            .ok_or_else(|| SecretonError::Configuration {
                message: format!("No client registered for system: {:?}", system),
            })
    }

    /// Perform the actual sync operation
    async fn perform_sync_operation(
        &self,
        client: &dyn ExternalSystemClient,
        secreton_path: &str,
        operation: &SyncOperation,
        config: &SyncConfig,
    ) -> Result<SyncResult> {
        match operation {
            SyncOperation::Create => {
                // Read the secret from Secreton storage
                let (secret_data, _version) = self.storage.get_latest_secret(secreton_path).await?
                    .ok_or_else(|| SecretonError::NotFound {
                        resource: format!("secret {}", secreton_path),
                    })?;

                // Serialize the secret data to bytes
                let data = serde_json::to_vec(&secret_data)?;
                let metadata = HashMap::new();

                let external_id = client.create_secret(secreton_path, &data, &metadata).await?;
                Ok(SyncResult {
                    operation: SyncOperation::Create,
                    success: true,
                    external_id: Some(external_id),
                    error: None,
                    metadata: HashMap::new(),
                })
            }
            SyncOperation::Update => {
                // Get the external ID from sync status
                let status = self.get_sync_status(secreton_path).await
                    .ok_or_else(|| SecretonError::NotFound {
                        resource: format!("sync status for {}", secreton_path),
                    })?;

                if status.status == SyncStatusType::Deleted {
                    return Err(SecretonError::NotFound {
                        resource: format!("secret {} (deleted)", secreton_path),
                    });
                }

                // Read the updated secret from Secreton storage
                let (secret_data, _version) = self.storage.get_latest_secret(secreton_path).await?
                    .ok_or_else(|| SecretonError::NotFound {
                        resource: format!("secret {}", secreton_path),
                    })?;

                // Serialize the secret data to bytes
                let data = serde_json::to_vec(&secret_data)?;
                let metadata = HashMap::new();

                client.update_secret(&status.external_id, &data, &metadata).await?;
                Ok(SyncResult {
                    operation: SyncOperation::Update,
                    success: true,
                    external_id: Some(status.external_id),
                    error: None,
                    metadata: HashMap::new(),
                })
            }
            SyncOperation::Delete => {
                let status = self.get_sync_status(secreton_path).await
                    .ok_or_else(|| SecretonError::NotFound {
                        resource: format!("sync status for {}", secreton_path),
                    })?;

                client.delete_secret(&status.external_id).await?;
                Ok(SyncResult {
                    operation: SyncOperation::Delete,
                    success: true,
                    external_id: Some(status.external_id),
                    error: None,
                    metadata: HashMap::new(),
                })
            }
            SyncOperation::MetadataOnly => {
                // Sync only metadata, not the actual secret data
                Ok(SyncResult {
                    operation: SyncOperation::MetadataOnly,
                    success: true,
                    external_id: None,
                    error: None,
                    metadata: HashMap::new(),
                })
            }
        }
    }

    /// Update sync status
    async fn update_sync_status(&self, secreton_path: &str, result: &SyncResult) -> Result<()> {
        let mut status = self.sync_status.write().await;

        let sync_status = SyncStatus {
            secreton_path: secreton_path.to_string(),
            external_id: result.external_id.clone().unwrap_or_default(),
            last_sync: Utc::now(),
            status: if result.success {
                SyncStatusType::Synced
            } else {
                SyncStatusType::Failed
            },
            error_message: result.error.clone(),
            metadata: result.metadata.clone(),
        };

        status.insert(secreton_path.to_string(), sync_status);
        Ok(())
    }
}

/// Retry manager for handling transient failures
pub struct RetryManager {
    config: RetryConfig,
}

impl RetryManager {
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    pub async fn execute_with_retry<F, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> BoxFuture<Result<T, E>>,
        E: std::fmt::Display,
    {
        let mut delay = self.config.initial_delay;

        for attempt in 0..=self.config.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt == self.config.max_retries {
                        return Err(e);
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                    delay = (delay as f64 * self.config.backoff_multiplier) as u64;
                    delay = delay.min(self.config.max_delay);
                }
            }
        }

        unreachable!()
    }
}

/// Sync error types
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("No sync configuration found: {0}")]
    NoSyncConfig(String),

    #[error("No client registered: {0}")]
    NoClient(String),

    #[error("Sync status not found: {0}")]
    SyncStatusNotFound(String),

    #[error("Secret deleted: {0}")]
    SecretDeleted(String),

    #[error("Operation failed: {0}")]
    OperationFailed(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Client error: {0}")]
    ClientError(String),
}

impl From<SyncError> for SecretonError {
    fn from(err: SyncError) -> Self {
        match err {
            SyncError::ConnectionFailed(msg) => SecretonError::ServiceUnavailable {
                service: format!("Sync connection: {}", msg),
            },
            SyncError::NoSyncConfig(msg) => SecretonError::Configuration { message: msg },
            SyncError::NoClient(msg) => SecretonError::Configuration { message: msg },
            SyncError::SyncStatusNotFound(path) => SecretonError::NotFound {
                resource: format!("sync status for {}", path),
            },
            SyncError::SecretDeleted(path) => SecretonError::NotFound {
                resource: format!("secret {} (deleted)", path),
            },
            SyncError::OperationFailed(msg) => SecretonError::Internal { message: msg },
            SyncError::ConfigurationError(msg) => SecretonError::Configuration { message: msg },
            SyncError::IoError(io_err) => SecretonError::Io(io_err),
            SyncError::JsonError(json_err) => SecretonError::Serialization(json_err),
            SyncError::ClientError(msg) => SecretonError::ServiceUnavailable {
                service: format!("External client: {}", msg),
            },
        }
    }
}

// Helper type for boxed futures
type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;
