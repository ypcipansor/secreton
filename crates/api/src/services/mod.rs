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
use brankas_storage::StorageBackend;

/// Service container holding all application services
pub struct ServiceContainer {
    /// Configuration
    pub config: ApiConfig,
    
    /// Storage service
    pub storage: Arc<dyn StorageBackend + Send + Sync>,
    
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
        
        // Initialize audit logger
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
        use brankas_storage::{MockStorageBackend, RaftStorageBackend, RaftConfig};
        
        // Get storage backend type from config or environment
        let backend_type = std::env::var("BRANKAS_STORAGE_BACKEND")
            .unwrap_or_else(|_| "memory".to_string());
        
        tracing::info!("Initializing storage backend: {}", backend_type);
        
        match backend_type.as_str() {
            "raft" | "integrated" => {
                // Create Raft configuration
                let raft_config = RaftConfig {
                    node_id: std::env::var("BRANKAS_NODE_ID")
                        .unwrap_or_else(|_| format!("brankas-node-{}", uuid::Uuid::new_v4())),
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
                
                tracing::info!("Raft configuration: {:?}", raft_config);
                
                let backend = RaftStorageBackend::new(raft_config).await
                    .map_err(|e| anyhow::anyhow!("Failed to create Raft storage backend: {}", e))?;
                
                // Initialize the Raft cluster
                backend.initialize_cluster().await
                    .map_err(|e| anyhow::anyhow!("Failed to initialize Raft cluster: {}", e))?;
                
                tracing::info!("Raft integrated storage backend initialized successfully");
                Ok(Arc::new(backend))
            }
            
            "memory" | "mock" => {
                tracing::info!("Using in-memory mock storage backend");
                Ok(Arc::new(MockStorageBackend::new()))
            }
            
            // TODO: Add other backends (PostgreSQL, Redis, File)
            "postgres" => {
                tracing::warn!("PostgreSQL backend not yet implemented, falling back to memory");
                Ok(Arc::new(MockStorageBackend::new()))
            }
            
            "redis" => {
                tracing::warn!("Redis backend not yet implemented, falling back to memory");
                Ok(Arc::new(MockStorageBackend::new()))
            }
            
            "file" => {
                tracing::warn!("File backend not yet implemented, falling back to memory");
                Ok(Arc::new(MockStorageBackend::new()))
            }
            
            _ => {
                tracing::warn!("Unknown storage backend '{}', falling back to memory", backend_type);
                Ok(Arc::new(MockStorageBackend::new()))
            }
        }
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
