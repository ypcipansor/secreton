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
use secreton_core::telemetry::{TelemetryCollector, TelemetryConfig};
use secreton_storage::StorageBackend;
pub mod audit;
pub mod crypto;
use crate::services::audit::AuditLogger;
use crate::config::ApiConfig;  // Use local ApiConfig with auth field
use crate::services::crypto::CryptoService;
use crate::services::auth::AuthenticationService;
use secreton_auth::policies::service::PolicyService;

/// Service container holding all application services
pub struct ApiServiceContainer {
    /// Configuration
    pub config: ApiConfig,

    /// Service registry for dependency injection
    pub registry: StandardServiceContainer,

    /// Initialization status
    initialized: std::sync::atomic::AtomicBool,

    // Publicly accessible services
    pub storage: Arc<dyn StorageBackend + Send + Sync>,
    pub crypto: Arc<CryptoService>,
    pub audit: Arc<AuditLogger>,
    pub auth: Arc<AuthenticationService>,
    pub secreton: Arc<secret::SecretService>,
    pub admin: Arc<admin::AdminService>,
}

impl ApiServiceContainer {
    /// Create new service container
    pub async fn new(config: &ApiConfig) -> Result<Self> {
        let _registry = StandardServiceContainer::new();
        
        // Initialize storage backend
        // Use default/mock for now as per create_storage_backend placeholder
        let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(secreton_storage::MockStorageBackend::new()); 
        // Note: Real implementation would use config to pick backend

        // Initialize crypto service
        let crypto = Arc::new(CryptoService::new());

        // Initialize audit logger
        let audit = Arc::new(AuditLogger::new(storage.clone()).await?);

        // Initialize authentication service
        let auth = Arc::new(AuthenticationService::new(
            storage.clone(),
            crypto.clone(),
            &config.auth,
        ).await?);

        // Initialize policy service
        let policy_service = Arc::new(PolicyService::new());

        // Initialize secret service
        let secreton = Arc::new(secret::SecretService::new(
            storage.clone(),
            crypto.clone(),
            audit.clone(),
            policy_service.clone(),
        ).await?);

        // Initialize admin service
        let admin = Arc::new(admin::AdminService::new(
            storage.clone(),
            auth.clone(),
            audit.clone(),
        ).await?);

        // Initialize Telemetry
        let telemetry = Arc::new(TelemetryCollector::new(TelemetryConfig::default()));
        if let Err(e) = telemetry.start_collection().await {
            tracing::warn!("Failed to start telemetry collection: {}", e);
        }

        // Register in registry (optional if we use fields, but good for trait support)
        let mut registry = StandardServiceContainer::new();
        registry.register_service("storage".to_string(), storage.clone());
        registry.register_service("crypto".to_string(), crypto.clone());
        registry.register_service("audit".to_string(), audit.clone());
        registry.register_service("auth".to_string(), auth.clone());
        registry.register_service("policy".to_string(), policy_service.clone());
        registry.register_service("secret".to_string(), secreton.clone());
        registry.register_service("admin".to_string(), admin.clone());
        registry.register_service("telemetry".to_string(), telemetry);

        Ok(Self {
            config: config.clone(),
            registry,
            initialized: std::sync::atomic::AtomicBool::new(true),
            storage,
            crypto,
            audit,
            auth,
            secreton,
            admin,
        })
    }

    /// Create storage backend based on configuration
    /// Reserved for future implementation of configurable storage backends
    #[allow(dead_code)]
    async fn create_storage_backend(&self) -> Result<Arc<dyn StorageBackend + Send + Sync>> {
        // Implementation would go here - simplified for now
        // This would use the config to determine which storage backend to create
        Ok(Arc::new(secreton_storage::MockStorageBackend::new()))
    }

    pub fn get_service<T: 'static>(&self, name: &str) -> Result<&T> {
        self.registry.get_service(name)
            .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", name))
    }

    /// Initialize core services
    async fn initialize_services(&self) -> Result<()> {
        // Initialize individual services if needed
        Ok(())
    }
}

#[async_trait::async_trait]
impl ServiceContainer for ApiServiceContainer {
    async fn initialize(&mut self) -> InitResult<()> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            self.initialize_services().await.map_err(|e| secreton_common::ServiceInitError::InitializationFailed { message: e.to_string() })?;
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
        self.registry.get_service(name)
    }

    fn register_service<T: Send + Sync + 'static>(&mut self, name: String, service: T) {
        self.registry.register_service(name, service);
    }
}
