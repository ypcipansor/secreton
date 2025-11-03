//! Service container for dependency injection.
//! 
//! Provides centralized access to all application services
//! including storage, crypto, authentication, and business logic.

pub mod auth;
pub mod vault;
pub mod admin;

use std::sync::Arc;
use anyhow::Result;

use crate::config::ApiConfig;
use brankas_core::audit::AuditLogger;
use brankas_crypto::{CryptoService, SecurityParams};
use brankas_storage::{StorageBackend, StorageFactory, StorageFactoryConfig, StorageBackendType};
use brankas_core::storage::StorageBackend as CoreStorageBackend;

/// Service container holding all application services
pub struct ServiceContainer {
    /// Configuration
    pub config: ApiConfig,
    
    /// Storage service (storage crate)
    pub storage: Arc<dyn StorageBackend + Send + Sync>,
    
    /// Core storage service (core crate)
    pub core_storage: Arc<dyn CoreStorageBackend + Send + Sync>,
    
    /// Cryptographic service
    pub crypto: Arc<CryptoService>,
    
    /// Authentication service
    pub auth: Arc<auth::AuthService>,
    
    /// Vault service
    pub vault: Arc<vault::VaultService>,
    
    /// Admin service
    pub admin: Arc<admin::AdminService>,
    
    /// Audit logger
    pub audit: Arc<AuditLogger>,
}

impl ServiceContainer {
    /// Create new service container
    pub async fn new(config: &ApiConfig) -> Result<Self> {
        // Initialize storage backend
        let storage = Self::create_storage_backend(config).await?;
        
        // Initialize crypto service
        let crypto = Arc::new(CryptoService::new(SecurityParams::default())?);
        
        // Initialize audit logger (memory/raft backends currently); Postgres wiring removed due to trait divergence
        let audit = Arc::new(AuditLogger::new(storage.clone()).await?);
        
        // Initialize authentication service
        let auth = Arc::new(auth::AuthService::new(
            storage.clone(),
            crypto.clone(),
            &config.auth,
        ).await?);
        
        // Initialize vault service
        let vault = Arc::new(vault::VaultService::new(
            storage.clone(),
            crypto.clone(),
            audit.clone(),
        ).await?);
        
        // Initialize admin service
        let admin = Arc::new(admin::AdminService::new(
            storage.clone(),
            auth.clone(),
            audit.clone(),
        ).await?);

        Ok(Self {
            config: config.clone(),
            storage,
            crypto,
            auth,
            vault,
            admin,
            audit,
        })
    }

    /// Create storage backend based on configuration
    async fn create_storage_backend(
        config: &ApiConfig,
    ) -> Result<Arc<dyn StorageBackend + Send + Sync>> {
        use brankas_storage::{RaftConfig, PostgresBackendConfig, RedisBackendConfig, FileBackendConfig};
        
        // Get storage backend type from config or environment
        let backend_type = std::env::var("BRANKAS_STORAGE_BACKEND")
            .unwrap_or_else(|_| "memory".to_string());
        
        tracing::info!("Initializing storage backend: {}", backend_type);
        
        let backend_type_enum = match backend_type.as_str() {
            "raft" | "integrated" => StorageBackendType::Raft,
            "postgres" | "postgresql" => StorageBackendType::Postgres,
            "redis" => StorageBackendType::Redis,
            "file" => StorageBackendType::File,
            "memory" | "mock" => StorageBackendType::Memory,
            "mysql" => StorageBackendType::MySQL,
            "dynamodb" => StorageBackendType::DynamoDB,
            "s3" => StorageBackendType::S3,
            "etcd" => StorageBackendType::Etcd,
            "consul" => StorageBackendType::Consul,
            "cockroachdb" => StorageBackendType::CockroachDB,
            "cassandra" => StorageBackendType::Cassandra,
            "mongodb" => StorageBackendType::MongoDB,
            _ => {
                tracing::warn!("Unknown storage backend '{}', defaulting to memory", backend_type);
                StorageBackendType::Memory
            }
        };
        
        // Build storage factory configuration
        let mut factory_config = StorageFactoryConfig {
            backend_type: backend_type_enum.clone(),
            file_config: None,
            postgres_config: None,
            redis_config: None,
            raft_config: None,
            consul_config: None,
            s3_config: None,
            etcd_config: None,
            dynamodb_config: None,
            mysql_config: None,
            cockroachdb_config: None,
            cassandra_config: None,
            mongodb_config: None,
        };
        
        // Configure specific backends based on environment variables
        match backend_type_enum {
            StorageBackendType::Postgres | StorageBackendType::PostgreSQL => {
                let connection_string = std::env::var("BRANKAS_POSTGRES_URL")
                    .unwrap_or_else(|_| "postgresql://localhost:5432/secreton".to_string());
                factory_config.postgres_config = Some(PostgresBackendConfig {
                    connection_string,
                });
                tracing::info!("Configured PostgreSQL backend");
            }
            
            StorageBackendType::Redis => {
                let url = std::env::var("BRANKAS_REDIS_URL")
                    .unwrap_or_else(|_| "redis://localhost:6379".to_string());
                factory_config.redis_config = Some(RedisBackendConfig { url });
                tracing::info!("Configured Redis backend");
            }
            
            StorageBackendType::File => {
                let base_path = std::env::var("BRANKAS_FILE_STORAGE_PATH")
                    .unwrap_or_else(|_| "./data/vault".to_string());
                factory_config.file_config = Some(FileBackendConfig { base_path });
                tracing::info!("Configured File backend");
            }
            
            StorageBackendType::Raft => {
                let raft_config = RaftConfig {
                    node_id: std::env::var("BRANKAS_NODE_ID")
                        .unwrap_or_else(|_| format!("secreton-node-{}", uuid::Uuid::new_v4())),
                    data_dir: std::env::var("BRANKAS_RAFT_DATA_DIR")
                        .unwrap_or_else(|_| "./data/raft".to_string())
                        .into(),
                    bind_addr: std::env::var("BRANKAS_RAFT_BIND_ADDR")
                        .unwrap_or_else(|_| "127.0.0.1:8201".to_string()),
                    advertise_addr: std::env::var("BRANKAS_RAFT_ADVERTISE_ADDR")
                        .unwrap_or_else(|_| "127.0.0.1:8201".to_string()),
                    peers: std::env::var("BRANKAS_RAFT_PEERS")
                        .unwrap_or_else(|_| "".to_string())
                        .split(',')
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.trim().to_string())
                        .collect(),
                    snapshot_enabled: std::env::var("BRANKAS_RAFT_SNAPSHOT_ENABLED")
                        .unwrap_or_else(|_| "true".to_string())
                        .parse()
                        .unwrap_or(true),
                    snapshot_interval_secs: std::env::var("BRANKAS_RAFT_SNAPSHOT_INTERVAL")
                        .unwrap_or_else(|_| "120".to_string())
                        .parse()
                        .unwrap_or(120),
                    log_retention_count: std::env::var("BRANKAS_RAFT_LOG_RETENTION")
                        .unwrap_or_else(|_| "10000".to_string())
                        .parse()
                        .unwrap_or(10000),
                    performance_multiplier: std::env::var("BRANKAS_RAFT_PERFORMANCE_MULTIPLIER")
                        .unwrap_or_else(|_| "1".to_string())
                        .parse()
                        .unwrap_or(1),
                };
                factory_config.raft_config = Some(raft_config);
                tracing::info!("Configured Raft backend");
            }
            
            StorageBackendType::Memory => {
                tracing::info!("Using in-memory mock storage backend");
            }
            
            // Other backends - configured via environment
            _ => {
                tracing::warn!("Backend type {:?} requires configuration", backend_type_enum);
            }
        }
        
        // Create backend using factory
        let backend = StorageFactory::create(factory_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create storage backend: {}", e))?;
        
        tracing::info!("Storage backend {:?} initialized successfully", backend_type_enum);
        Ok(backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_container_creation() {
        let config = ApiConfig::default();
        let container = ServiceContainer::new(&config).await;
        assert!(container.is_ok());
    }
}
