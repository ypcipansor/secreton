//! Secrets engine module for Brankas Adhyaksa
//!
//! This module provides the core abstractions and implementations for different
//! types of secrets engines.

pub mod aws;
pub mod database;
pub mod alicloud;
pub mod gcloud_secrets;
pub mod azure_keyvault;
pub mod gcp_secretmanager;
pub mod pkiext;
// pub mod azure; // TODO: Enable when Azure SDK dependencies are available
// pub mod gcp; // TODO: Enable when GCP SDK dependencies are available
// pub mod kubernetes; // TODO: Enable when Kubernetes SDK dependencies are available
// pub mod rabbitmq; // TODO: Enable when RabbitMQ SDK dependencies are available
pub mod kmip;

/// Metrics for a specific secrets engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineMetrics {
    /// Engine type (kv, database, aws, etc.)
    pub engine_type: String,
    /// Number of secrets created
    pub secrets_created: u64,
    /// Number of secrets read
    pub secrets_read: u64,
    /// Number of secrets updated
    pub secrets_updated: u64,
    /// Number of secrets deleted
    pub secrets_deleted: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Error count
    pub error_count: u64,
    /// Active secrets count
    pub active_secrets: u64,
    /// Total storage size in bytes
    pub storage_size_bytes: u64,
}
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::error;
use uuid::Uuid;

// Import AppError from the re-export
use crate::{storage::StorageEngine, AppError};

pub use aws::AwsEngine;
pub use database::DatabaseEngine;
pub use alicloud::{AliCloudEngine, AliCloudConfig, AliCloudCredentials, AliCloudRole, AliCloudPermission};
pub use gcloud_secrets::{GCloudSecretsEngine, GCloudConfig, GCloudServiceAccount, GCloudTokenData};
pub use azure_keyvault::{AzureKeyVaultEngine, AzureKeyVaultConfig};
pub use gcp_secretmanager::{GcpSecretManagerEngine, GcpSecretManagerConfig};
pub use pkiext::{PkiExtEngine, PkiExtConfig};
pub use kv::KVSecretsEngine;
pub use memory::MemorySecretsEngine;
pub use pki::PkiSecretsEngine; // Re-enabled for PKI certificate management
pub use shamir::{ShamirEngine, ShamirConfig, ShamirRequest, ShamirReconstructionRequest, ReconstructionMetadata};
pub use ssh::SshSecretsEngine;
pub use totp::TotpSecretsEngine;
pub use kmip::{KmipSecretsEngine, KmipConfig, KmipRequest, KmipResponse, KmipOperation, KmipObjectType, KmipCryptographicAlgorithm, new_kmip_engine};

/// Common error type for secrets engine operations
#[derive(Error, Debug)]
pub enum SecretsError {
    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid secret data: {0}")]
    InvalidData(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<crate::error::CoreError> for SecretsError {
    fn from(error: crate::error::CoreError) -> Self {
        match error {
            crate::error::CoreError::NotFound { resource } => SecretsError::NotFound(resource),
            crate::error::CoreError::Authorization { message } => {
                SecretsError::PermissionDenied(message)
            }
            crate::error::CoreError::Validation { message } => SecretsError::InvalidData(message),
            _ => SecretsError::ExecutionError(format!("Core error: {:?}", error)),
        }
    }
}

/// Metadata about a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
    pub ttl: Option<i64>, // dalam detik
    pub expired_at: Option<DateTime<Utc>>,
    pub custom_metadata: Option<HashMap<String, String>>,
}

/// A secret with its data and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub path: String,
    pub data: Value,
    pub metadata: SecretMetadata,
}

/// Trait that all secrets engines must implement
#[async_trait]
pub trait SecretsEngine: Send + Sync + 'static {
    /// Get the type of the secrets engine
    fn engine_type(&self) -> &'static str;

    /// Create a new secret
    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError>;

    /// Read a secret
    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError>;

    /// Update a secret
    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError>;

    /// Delete a secret
    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError>;

    /// List secrets under a path
    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError>;

    /// Collect metrics for this engine (optional)
    async fn collect_metrics(&self) -> Result<EngineMetrics, SecretsError>;
}

/// Type alias for a boxed secrets engine
pub type BoxedSecretsEngine = Box<dyn SecretsEngine>;

/// Registry of available secrets engines
#[derive(Default)]
pub struct SecretsEngineRegistry {
    engines: std::sync::RwLock<HashMap<String, Arc<BoxedSecretsEngine>>>,
}

impl SecretsEngineRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            engines: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Register a new secrets engine
    pub fn register(&self, engine: impl SecretsEngine) -> Result<(), AppError> {
        let engine_type = engine.engine_type().to_string();
        let mut engines = self.engines.write().map_err(|_| {
            AppError::InternalError("Failed to acquire write lock on engines registry".to_string())
        })?;

        if engines.contains_key(&engine_type) {
            return Err(AppError::BadRequest(format!(
                "Secrets engine '{}' is already registered",
                engine_type
            )));
        }

        engines.insert(
            engine_type,
            Arc::new(Box::new(engine) as BoxedSecretsEngine),
        );
        Ok(())
    }

    /// Get a secrets engine by type
    pub fn get_engine(&self, engine_type: &str) -> Option<Arc<BoxedSecretsEngine>> {
        self.engines.read().ok()?.get(engine_type).cloned()
    }

    /// Collect metrics from all registered engines
    pub async fn collect_metrics(&self) -> Result<HashMap<String, EngineMetrics>, SecretsError> {
        let engines = self.engines.read().map_err(|_| {
            SecretsError::ExecutionError(
                "Failed to acquire read lock on engines registry".to_string(),
            )
        })?;

        let mut metrics = HashMap::new();

        for (engine_name, engine) in engines.iter() {
            match engine.collect_metrics().await {
                Ok(engine_metrics) => {
                    metrics.insert(engine_name.clone(), engine_metrics);
                }
                Err(e) => {
                    error!(
                        "Failed to collect metrics from engine {}: {}",
                        engine_name, e
                    );
                }
            }
        }

        Ok(metrics)
    }
}

/// Initialize the default secrets engines
pub async fn init_default_engines(
    _data_dir: impl AsRef<Path>,
    _with_memory: bool,
) -> Result<SecretsEngineRegistry, AppError> {
    let registry = SecretsEngineRegistry::new();

    // Create storage instance using test utilities
    use std::collections::HashMap;

    #[derive(Debug)]
    struct TestStorageEngine {
        data: Arc<std::sync::RwLock<HashMap<String, crate::storage::StorageEntry>>>,
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageEngine for TestStorageEngine {
        async fn get(
            &self,
            key: &str,
        ) -> Result<Option<crate::storage::StorageEntry>, crate::error::CoreError> {
            let data = self.data.read().unwrap();
            Ok(data.get(key).cloned())
        }

        async fn put(
            &self,
            entry: crate::storage::StorageEntry,
        ) -> Result<(), crate::error::CoreError> {
            let mut data = self.data.write().unwrap();
            data.insert(entry.key.clone(), entry);
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), crate::error::CoreError> {
            let mut data = self.data.write().unwrap();
            data.remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::error::CoreError> {
            let data = self.data.read().unwrap();
            Ok(data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    let storage: Arc<tokio::sync::RwLock<dyn StorageEngine + Send + Sync>> =
        Arc::new(tokio::sync::RwLock::new(TestStorageEngine {
            data: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }));

    // Create a separate storage instance for AWS engine (needs Arc<dyn StorageEngine>)
    let aws_storage: Arc<dyn StorageEngine> = Arc::new(TestStorageEngine {
        data: Arc::new(std::sync::RwLock::new(HashMap::new())),
    });

    // Initialize and register the KV secrets engine
    let kv_base_path = std::env::temp_dir().join("kv");
    let kv_engine = KVSecretsEngine::new(kv_base_path).await?;
    registry.register(kv_engine)?;

    // Initialize and register the SSH secrets engine
    let ssh_engine = SshSecretsEngine::new(storage.clone()).await?;
    registry.register(ssh_engine)?;

    // Initialize and register the TOTP secrets engine
    let totp_engine = TotpSecretsEngine::new(storage.clone()).await?;
    registry.register(totp_engine)?;

    // Initialize and register the Memory secrets engine
    let memory_engine = MemorySecretsEngine::new();
    registry.register(memory_engine)?;

    // Initialize and register the KMIP secrets engine (sync constructor)
    let kmip_storage: Arc<dyn StorageEngine> = Arc::new(TestStorageEngine {
        data: Arc::new(std::sync::RwLock::new(HashMap::new())),
    });
    let kmip_engine = KmipSecretsEngine::new(kmip_storage, kmip::KmipConfig {
        server_port: 5696,
        server_host: "0.0.0.0".to_string(),
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        authentication_required: false,
        supported_operations: vec![kmip::KmipOperation::Create, kmip::KmipOperation::Get],
        supported_object_types: vec![kmip::KmipObjectType::SymmetricKey],
        max_message_size: 4096,
    });
    registry.register(kmip_engine)?;


    let aws_engine = AwsEngine::new(aws_storage, aws_config).await?;
    registry.register(aws_engine)?;

    // Initialize and register the Database secrets engine
    let db_engine = DatabaseEngine::new();
    registry.register(db_engine)?;

    // Initialize and register the AliCloud secrets engine
    let alicloud_engine = AliCloudEngine::new(alicloud::AliCloudConfig::default());
    registry.register(alicloud_engine)?;

    // Initialize and register the Google Cloud Secrets engine
    let gcloud_secrets_engine = GCloudSecretsEngine::new(gcloud_secrets::GCloudConfig::default());
    registry.register(gcloud_secrets_engine)?;

    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_secrets_engine_registry() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let registry = init_default_engines(temp_dir.path(), false).await?;

        // Test getting the KV engine
        let kv_engine = registry.get_engine("kv");
        assert!(kv_engine.is_some(), "KV engine should be registered");

        // Test getting the SSH engine
        let ssh_engine = registry.get_engine("ssh");
        assert!(ssh_engine.is_some(), "SSH engine should be registered");

        // Test getting the TOTP engine
        let totp_engine = registry.get_engine("totp");
        assert!(totp_engine.is_some(), "TOTP engine should be registered");

        // Test getting the PKI engine (not registered in this test)
        let pki_engine = registry.get_engine("pki");
        assert!(
            pki_engine.is_none(),
            "PKI engine should not be registered (requires config)"
        );

        // Test getting the KMIP engine
        let kmip_engine = registry.get_engine("kmip");
        assert!(
            kmip_engine.is_some(),
            "KMIP engine should be registered"
        );

        // Test getting the Transform engine
        let memory_engine = registry.get_engine("memory");
        assert!(
            memory_engine.is_some(),
            "Memory engine should be registered"
        );

        // Test getting the AWS engine
        let aws_engine = registry.get_engine("aws");
        assert!(aws_engine.is_some(), "AWS engine should be registered");

        // Test getting the Database engine
        let db_engine = registry.get_engine("database");
        assert!(db_engine.is_some(), "Database engine should be registered");

        // Test getting the AliCloud engine
        let alicloud_engine = registry.get_engine("alicloud");
        assert!(alicloud_engine.is_some(), "AliCloud engine should be registered");

        // Test getting the Google Cloud Secrets engine
        let gcloud_engine = registry.get_engine("gcloud_secrets");
        assert!(gcloud_engine.is_some(), "Google Cloud Secrets engine should be registered");

        Ok(())
    }

    #[tokio::test]
    async fn test_engine_metrics_collection() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let registry = init_default_engines(temp_dir.path(), false).await?;

        // Test collecting metrics from all engines
        let metrics = registry.collect_metrics().await?;

        // Verify we have metrics for all registered engines
        assert!(
            metrics.len() >= 11,
            "Should have metrics for at least 11 engines (including new AliCloud and GCloud engines)"
        );

        // Verify specific engines have metrics
        assert!(metrics.contains_key("kv"), "Should have KV engine metrics");
        assert!(
            metrics.contains_key("aws"),
            "Should have AWS engine metrics"
        );
        assert!(
            metrics.contains_key("database"),
            "Should have Database engine metrics"
        );
        assert!(
            metrics.contains_key("alicloud"),
            "Should have AliCloud engine metrics"
        );
        assert!(
            metrics.contains_key("gcloud_secrets"),
            "Should have Google Cloud Secrets engine metrics"
        );
        assert!(
            metrics.contains_key("transit"),
            "Should have Transit engine metrics"
        );
        assert!(
            metrics.contains_key("kmip"),
            "Should have KMIP engine metrics"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_engine_registration() -> Result<(), Box<dyn std::error::Error>> {
        let registry = SecretsEngineRegistry::new();

        // Create a test engine
        let memory_engine = MemorySecretsEngine::new();

        // Register the engine
        registry.register(memory_engine)?;

        // Verify it can be retrieved
        let retrieved = registry.get_engine("memory");
        assert!(
            retrieved.is_some(),
            "Registered engine should be retrievable"
        );

        Ok(())
    }
}
