//! Service container for dependency injection.
//!
//! Provides centralized access to all application services
//! including storage, crypto, authentication, and business logic.

pub mod auth;
pub mod secret;
pub mod admin;
pub mod config;

use std::sync::Arc;
use anyhow::Result;
use secreton_common::{ServiceContainer, InitResult, ServiceHealth, StandardServiceContainer};
use secreton_core::telemetry::{TelemetryCollector, TelemetryConfig};
use secreton_storage::StorageBackend;
pub mod audit;
pub mod crypto;
pub mod seal;
use crate::services::audit::AuditLogger;
use crate::config::ApiConfig;  // Use local ApiConfig with auth field
use crate::services::crypto::CryptoService;
use crate::services::seal::SealService;
use crate::services::auth::AuthenticationService;
use secreton_auth::policies::service::PolicyService;
use secreton_auth::{InMemoryIdentityService, IdentityService};
use secreton_performance::{SecretPerformanceOptimizer, SecretPerformanceConfig};

// MFA Services
use secreton_auth::mfa::{
    CombinedMfaService,
    InMemoryTotpService,
    InMemorySmsService,
    InMemoryEmailService,
    InMemoryHardwareService,
    DefaultPushService,
    DefaultWebAuthnService,
    DefaultRecoveryCodeService,
    SmsConfig, SmsProvider, EmailConfig,
};

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
    pub seal: Arc<SealService>,
    pub audit: Arc<AuditLogger>,
    pub auth: Arc<AuthenticationService>,
    pub policy: Arc<PolicyService>,
    pub secreton: Arc<secret::SecretService>,
    pub admin: Arc<admin::AdminService>,
    pub performance: Arc<SecretPerformanceOptimizer>,
    pub mfa: Arc<CombinedMfaService>,
    pub identity: Arc<dyn IdentityService + Send + Sync>,
}

impl ApiServiceContainer {
    /// Create new service container
    pub async fn new(config: &ApiConfig) -> Result<Self> {
        let _registry = StandardServiceContainer::new();
        
        // Initialize storage backend
        let storage = secreton_storage::StorageFactory::create(config.storage.clone()).await?;

        // Initialize crypto service
        let crypto = Arc::new(CryptoService::new(storage.clone()).await?);

        // Initialize seal service
        let seal = Arc::new(SealService::new(
            storage.clone(),
            crypto.clone(),
            config.auth.jwt.secret.clone(),
            config.auth.jwt.issuer.clone(),
            config.auth.jwt.audience.clone(),
        ));

        // Initialize audit logger
        let audit = Arc::new(AuditLogger::new(storage.clone()).await?);

        // Initialize authentication service
        let auth = Arc::new(AuthenticationService::new(
            storage.clone(),
            crypto.clone(),
            &config.auth,
        ).await?
        .with_audit(audit.clone()));

        // Initialize policy service
        let policy_service = Arc::new(PolicyService::new());
        // Initialize identity service
        let identity: Arc<dyn IdentityService + Send + Sync> = Arc::new(InMemoryIdentityService::new());

        // Initialize secret performance optimizer
        let performance = Arc::new(SecretPerformanceOptimizer::new(SecretPerformanceConfig::default()));

        // Initialize secret service
        let secreton = Arc::new(secret::SecretService::new(
            storage.clone(),
            crypto.clone(),
            audit.clone(),
            identity.clone(),
            policy_service.clone(),
            performance.clone(),
        ).await?);

        // Initialize admin service
        let admin = Arc::new(admin::AdminService::new(
            storage.clone(),
            auth.clone(),
            audit.clone(),
            performance.clone(),
        ).await?
        .with_crypto(crypto.clone()));

        // Initialize MFA Services using configuration
        let mfa_config = &config.auth.mfa;

        let totp_service = Arc::new(InMemoryTotpService::new(mfa_config.totp.issuer.clone()));

        // Configure SMS Config
        // Map from ApiConfig::SmsConfig to Auth::SmsConfig
        let sms_config = if let Some(sms) = &mfa_config.sms {
            SmsConfig {
                provider: match sms.provider.to_lowercase().as_str() {
                    "twilio" => SmsProvider::Twilio,
                    "awssns" | "aws_sns" => SmsProvider::AwsSns,
                    "nexmo" => SmsProvider::Nexmo,
                    _ => SmsProvider::Custom { url: "http://localhost/sms".to_string() },
                },
                api_key: sms.api_key.clone(),
                api_secret: None, // Config doesn't have secret yet
                from_number: sms.from_number.clone(),
                message_template: "Your Secreton code is {code}".to_string(),
                code_length: 6,
                code_expiry_seconds: 300,
            }
        } else {
            // Default config if not provided
            SmsConfig {
                provider: SmsProvider::Custom { url: "http://localhost/sms".to_string() },
                api_key: "dummy-key".to_string(),
                api_secret: None,
                from_number: "000000".to_string(),
                message_template: "Your Secreton code is {code}".to_string(),
                code_length: 6,
                code_expiry_seconds: 300,
            }
        };
        let sms_service = Arc::new(InMemorySmsService::new(sms_config));

        // Configure Email Config
        let email_config = if let Some(email) = &mfa_config.email {
            EmailConfig {
                smtp_server: email.smtp_server.clone(),
                smtp_port: email.smtp_port,
                smtp_username: email.username.clone(),
                smtp_password: email.password.clone(),
                from_email: email.from_address.clone(),
                subject_template: "Secreton Verification Code".to_string(),
                body_template: "Your verification code is: {code}".to_string(),
                code_length: 6,
                code_expiry_seconds: 300,
            }
        } else {
            EmailConfig {
                smtp_server: "localhost".to_string(),
                smtp_port: 1025,
                smtp_username: "user".to_string(),
                smtp_password: "password".to_string(),
                from_email: "noreply@secreton.io".to_string(),
                subject_template: "Secreton Verification Code".to_string(),
                body_template: "Your verification code is: {code}".to_string(),
                code_length: 6,
                code_expiry_seconds: 300,
            }
        };
        let email_service = Arc::new(InMemoryEmailService::new(email_config));

        let hardware_service = Arc::new(InMemoryHardwareService::new());
        let push_service = Arc::new(DefaultPushService::new_mock());
        let webauthn_service = Arc::new(DefaultWebAuthnService::new_default());
        let recovery_service = Arc::new(DefaultRecoveryCodeService::new());

        let mfa = Arc::new(CombinedMfaService::new(
            totp_service,
            sms_service,
            email_service,
            hardware_service,
            push_service,
            webauthn_service,
            recovery_service,
        ));

        // Initialize Telemetry
        let telemetry = Arc::new(TelemetryCollector::new(TelemetryConfig::default()));
        if let Err(e) = telemetry.start_collection().await {
            tracing::warn!("Failed to start telemetry collection: {}", e);
        }

        // Register in registry (optional if we use fields, but good for trait support)
        let mut registry = StandardServiceContainer::new();
        registry.register_service("storage".to_string(), storage.clone());
        registry.register_service("crypto".to_string(), crypto.clone());
        registry.register_service("seal".to_string(), seal.clone());
        registry.register_service("audit".to_string(), audit.clone());
        registry.register_service("auth".to_string(), auth.clone());
        registry.register_service("policy".to_string(), policy_service.clone());
        registry.register_service("mfa".to_string(), mfa.clone());
        registry.register_service("secret".to_string(), secreton.clone());
        registry.register_service("admin".to_string(), admin.clone());
        registry.register_service("telemetry".to_string(), telemetry);
        registry.register_service("identity".to_string(), identity.clone());

        Ok(Self {
            config: config.clone(),
            registry,
            initialized: std::sync::atomic::AtomicBool::new(true),
            storage,
            crypto,
            seal,
            audit,
            auth,
            policy: policy_service,
            secreton,
            admin,
            performance,
            mfa,
            identity,
        })
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
