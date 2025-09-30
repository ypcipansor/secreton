use crate::backends::*;
/// Storage Backend Factory
///
/// Provides easy creation and configuration of different storage backends
use crate::{StorageBackend, StorageError, StorageResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Storage backend type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackendType {
    /// File-based storage
    File,
    /// In-memory storage (for testing)
    Memory,
    /// PostgreSQL database
    Postgres,
    /// Redis cache
    Redis,
    /// Raft distributed storage
    Raft,
    /// Consul KV storage
    Consul,
    /// PostgreSQL storage (new implementation)
    PostgreSQL,
    /// etcd storage
    Etcd,
}

/// Unified storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageFactoryConfig {
    /// Backend type to use
    pub backend_type: StorageBackendType,

    /// File backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_config: Option<FileBackendConfig>,

    /// PostgreSQL backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres_config: Option<PostgresBackendConfig>,

    /// Redis backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis_config: Option<RedisBackendConfig>,

    /// Raft backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raft_config: Option<RaftConfig>,

    /// Consul backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consul_config: Option<ConsulStorageConfig>,

    /// etcd backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etcd_config: Option<EtcdStorageConfig>,
}

/// Placeholder configs for existing backends (to be replaced with actual configs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBackendConfig {
    pub base_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresBackendConfig {
    pub connection_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisBackendConfig {
    pub url: String,
}

impl Default for StorageFactoryConfig {
    fn default() -> Self {
        Self {
            backend_type: StorageBackendType::Memory,
            file_config: None,
            postgres_config: None,
            redis_config: None,
            raft_config: None,
            consul_config: None,
            etcd_config: None,
        }
    }
}

/// Storage factory for creating storage backends
pub struct StorageFactory;

impl StorageFactory {
    /// Create a new storage backend based on configuration
    pub async fn create(config: StorageFactoryConfig) -> StorageResult<Arc<dyn StorageBackend>> {
        match config.backend_type {
            StorageBackendType::Memory => Ok(Arc::new(crate::MockStorageBackend::new())),

            StorageBackendType::Consul => {
                let consul_config =
                    config
                        .consul_config
                        .ok_or_else(|| StorageError::ConfigurationError {
                            message: "Consul configuration is required".to_string(),
                        })?;

                let backend = ConsulStorage::new(consul_config).await?;
                Ok(Arc::new(backend))
            }

            StorageBackendType::PostgreSQL => {
                let pg_config =
                    config
                        .postgres_config
                        .ok_or_else(|| StorageError::ConfigurationError {
                            message: "PostgreSQL configuration is required".to_string(),
                        })?;

                let backend = PostgresBackend::new(&pg_config.connection_string).await?;
                Ok(Arc::new(backend))
            }

            StorageBackendType::Etcd => {
                let etcd_config =
                    config
                        .etcd_config
                        .ok_or_else(|| StorageError::ConfigurationError {
                            message: "etcd configuration is required".to_string(),
                        })?;

                let backend = EtcdStorage::new(etcd_config).await?;
                Ok(Arc::new(backend))
            }

            _ => Err(StorageError::ConfigurationError {
                message: format!(
                    "Backend type {:?} not yet implemented in factory",
                    config.backend_type
                ),
            }),
        }
    }

    /// Create a Consul storage backend with default configuration
    pub async fn create_consul(address: String) -> StorageResult<Arc<dyn StorageBackend>> {
        let config = ConsulStorageConfig {
            address,
            ..Default::default()
        };

        let backend = ConsulStorage::new(config).await?;
        Ok(Arc::new(backend))
    }

    /// Create a PostgreSQL storage backend with connection string
    pub async fn create_postgresql(
        connection_string: String,
    ) -> StorageResult<Arc<dyn StorageBackend>> {
        let backend = PostgresBackend::new(&connection_string).await?;
        Ok(Arc::new(backend))
    }

    /// Create an etcd storage backend with endpoints
    pub async fn create_etcd(endpoints: Vec<String>) -> StorageResult<Arc<dyn StorageBackend>> {
        let config = EtcdStorageConfig {
            endpoints,
            ..Default::default()
        };

        let backend = EtcdStorage::new(config).await?;
        Ok(Arc::new(backend))
    }

    /// Create an in-memory storage backend (for testing)
    pub fn create_memory() -> Arc<dyn StorageBackend> {
        Arc::new(crate::MockStorageBackend::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_factory_config_default() {
        let config = StorageFactoryConfig::default();
        assert_eq!(config.backend_type, StorageBackendType::Memory);
    }

    #[test]
    fn test_storage_backend_type_serialization() {
        let backend_type = StorageBackendType::Consul;
        let json = serde_json::to_string(&backend_type).unwrap();
        assert_eq!(json, "\"consul\"");

        let deserialized: StorageBackendType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, StorageBackendType::Consul);
    }

    #[tokio::test]
    async fn test_create_memory_backend() {
        let backend = StorageFactory::create_memory();
        assert!(backend.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_factory_create_memory() {
        let config = StorageFactoryConfig {
            backend_type: StorageBackendType::Memory,
            ..Default::default()
        };

        let result = StorageFactory::create(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_consul_config_serialization() {
        let config = StorageFactoryConfig {
            backend_type: StorageBackendType::Consul,
            consul_config: Some(ConsulStorageConfig::default()),
            ..Default::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("consul"));
    }
}
