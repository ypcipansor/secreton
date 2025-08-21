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
        // TODO: Create storage backend based on config
        // For now, create a mock implementation
        
        use brankas_storage::MockStorageBackend;
        Ok(Arc::new(MockStorageBackend::new()))
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
