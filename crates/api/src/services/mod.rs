//! Service container for dependency injection.
//!
//! Provides centralized access to all application services
//! including storage, crypto, authentication, and business logic.

pub mod auth;
pub mod secret;
pub mod admin;

use std::sync::Arc;
use anyhow::Result;
use secreton_common::{ServiceContainer, InitResult, ServiceHealth, StandardServiceContainer};
use crate::config::ApiConfig;

/// Service container holding all application services
pub struct ApiServiceContainer {
    /// Configuration
    pub config: ApiConfig,

    /// Service registry for dependency injection
    registry: StandardServiceContainer,

    /// Initialization status
    initialized: std::sync::atomic::AtomicBool,
}

impl ApiServiceContainer {
    /// Create new service container
    pub async fn new(config: &ApiConfig) -> Result<Self> {
        let mut container = Self {
            config: config.clone(),
            registry: StandardServiceContainer::new(),
            initialized: std::sync::atomic::AtomicBool::new(false),
        };

        // Initialize services using the standardized pattern
        container.initialize_services().await?;

        Ok(container)
    }

    /// Initialize all services
    async fn initialize_services(&mut self) -> Result<()> {
        // Initialize storage backend
        let storage = self.create_storage_backend().await?;
        self.registry.register("storage".to_string(), storage);

        // Initialize crypto service
        let crypto = Arc::new(CryptoService::new(SecurityParams::default())?);
        self.registry.register("crypto".to_string(), crypto);

        // Initialize audit logger
        let audit = Arc::new(AuditLogger::new(self.get_service("storage")?.clone()).await?);
        self.registry.register("audit".to_string(), audit);

        // Initialize authentication service
        let auth = Arc::new(auth::AuthService::new(
            self.get_service("storage")?.clone(),
            self.get_service("crypto")?.clone(),
            &self.config.auth,
        ).await?);
        self.registry.register("auth".to_string(), auth);

        // Initialize secret service
        let secret = Arc::new(secret::SecretService::new(
            self.get_service("storage")?.clone(),
            self.get_service("crypto")?.clone(),
            self.get_service("audit")?.clone(),
        ).await?);
        self.registry.register("secret".to_string(), secret);

        // Initialize admin service
        let admin = Arc::new(admin::AdminService::new(
            self.get_service("storage")?.clone(),
            self.get_service("auth")?.clone(),
            self.get_service("audit")?.clone(),
        ).await?);
        self.registry.register("admin".to_string(), admin);

        // Initialize MFA service
        let mfa = Arc::new(secreton_auth::mfa::MfaService::new());
        self.registry.register("mfa".to_string(), mfa);

        Ok(())
    }

    /// Create storage backend based on configuration
    async fn create_storage_backend(&self) -> Result<Arc<dyn StorageBackend + Send + Sync>> {
        // Implementation would go here - simplified for now
        // This would use the config to determine which storage backend to create
        Ok(Arc::new(secreton_storage::MemoryStorage::new()))
    }

    /// Get a service from the registry
    pub fn get_service<T: 'static>(&self, name: &str) -> Result<&T> {
        self.registry.get(name)
            .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", name))
    }
}

#[async_trait::async_trait]
impl ServiceContainer for ApiServiceContainer {
    async fn initialize(&mut self) -> InitResult<()> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            self.initialize_services().await?;
            self.initialized.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    async fn start_services(&self) -> InitResult<()> {
        // Start services in dependency order
        // Implementation would start each service that implements the Service trait
        Ok(())
    }

    async fn stop_services(&self) -> InitResult<()> {
        // Stop services in reverse dependency order
        // Implementation would stop each service that implements the Service trait
        Ok(())
    }

    async fn health_check(&self) -> InitResult<ServiceHealth> {
        // Check health of all registered services
        // Implementation would check each service's health
        Ok(ServiceHealth::Healthy)
    }

    fn get_service<T: 'static>(&self, name: &str) -> Option<&T> {
        self.registry.get(name)
    }

    fn register_service<T: 'static>(&mut self, name: String, service: T) {
        self.registry.register(name, service);
    }
}
