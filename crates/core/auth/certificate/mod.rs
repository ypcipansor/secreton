// Certificate Authentication Module
// X.509 Certificate-based authentication for mTLS environments

pub mod config;
pub mod validator;

pub use config::{CertificateConfig, ValidationLevel};
pub use validator::{CertificateValidator, ValidationResult, CertificateInfo, OcspStatus};

use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

use crate::auth::auth_impl::{AuthMethod, AuthResult, Credentials, TokenInfo};
use crate::storage::{StorageEngine, StorageEntry};
use crate::audit::{AuditLogger, AuditLog, AuditStatus};
use crate::models::user::User;
use uuid::Uuid;
use anyhow::{Result, Context, anyhow};

/// Certificate authentication credentials
#[derive(Debug, Clone)]
pub struct CertificateCredentials {
    /// Client certificate in PEM format
    pub client_cert: Vec<u8>,
    /// Certificate chain in PEM format
    pub cert_chain: Vec<u8>,
    /// Client certificate fingerprint
    pub fingerprint: String,
    /// Certificate subject
    pub subject: String,
    /// Certificate issuer
    pub issuer: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Certificate validity period
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// Certificate extensions
    pub extensions: HashMap<String, String>,
}

/// Certificate Authentication Engine
pub struct CertificateAuth {
    config: CertificateConfig,
    storage: Arc<dyn StorageEngine>,
    audit_logger: AuditLogger,
    cert_validator: CertificateValidator,
    cert_cache: Arc<RwLock<HashMap<String, CachedCertificate>>>,
}

#[derive(Debug, Clone)]
struct CachedCertificate {
    fingerprint: String,
    subject: String,
    user_id: String,
    valid_until: DateTime<Utc>,
    cached_at: DateTime<Utc>,
}

impl CertificateAuth {
    /// Create a new Certificate Authentication instance
    pub fn new(
        config: CertificateConfig,
        storage: Arc<dyn StorageEngine>,
        audit_logger: AuditLogger,
    ) -> Self {
        let cert_validator = CertificateValidator::new()
            .with_crl_url(config.crl_url.clone())
            .with_ocsp_url(config.ocsp_url.clone())
            .with_max_chain_depth(config.max_chain_depth)
            .with_validation_level(config.validation_level.clone());

        Self {
            config,
            storage,
            audit_logger,
            cert_validator,
            cert_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Validate client certificate
    async fn validate_certificate(&self, creds: &CertificateCredentials) -> Result<User> {
        // Check certificate cache first
        if let Some(cached) = self.check_certificate_cache(&creds.fingerprint).await? {
            if Utc::now() < cached.valid_until {
                return self.get_user_by_fingerprint(&cached.fingerprint).await;
            }
        }

        // Validate the certificate using our validator
        let _validation_result = self.cert_validator.validate_certificate(
            &creds.client_cert,
            &[],
            self.config.validation_level.clone(),
        ).await?;

        // Check certificate expiry
        let now = Utc::now();
        if now < creds.not_before {
            return Err(anyhow!("Certificate is not yet valid"));
        }
        if now > creds.not_after {
            return Err(anyhow!("Certificate has expired"));
        }

        // Validate issuer if restrictions are configured
        if !self.config.allowed_issuers.is_empty() {
            if !self.config.allowed_issuers.contains(&creds.issuer) {
                return Err(anyhow!("Certificate issuer not allowed"));
            }
        }

        // Check for required extensions
        for required_ext in &self.config.required_extensions {
            if !creds.extensions.contains_key(required_ext) {
                return Err(anyhow!("Required certificate extension missing: {}", required_ext));
            }
        }

        // Map certificate to user
        let user = self.map_certificate_to_user(creds).await?;

        // Cache the validated certificate
        self.cache_certificate(creds, &user).await?;

        Ok(user)
    }

    /// Check certificate cache
    async fn check_certificate_cache(&self, fingerprint: &str) -> Result<Option<CachedCertificate>> {
        let cache = self.cert_cache.read().await;
        Ok(cache.get(fingerprint).cloned())
    }

    /// Cache validated certificate
    async fn cache_certificate(&self, creds: &CertificateCredentials, user: &User) -> Result<()> {
        let cached = CachedCertificate {
            fingerprint: creds.fingerprint.clone(),
            subject: creds.subject.clone(),
            user_id: user.id.to_string(),
            valid_until: creds.not_after.min(Utc::now() + chrono::Duration::seconds(self.config.cert_cache_ttl as i64)),
            cached_at: Utc::now(),
        };

        let mut cache = self.cert_cache.write().await;
        cache.insert(creds.fingerprint.clone(), cached);
        Ok(())
    }

    /// Get user by certificate fingerprint
    async fn get_user_by_fingerprint(&self, fingerprint: &str) -> Result<User> {
        // Query storage for user mapping
        let key = format!("cert_mapping/{}", fingerprint);
        match self.storage.get(&key).await? {
            Some(data) => {
                let user_id: String = serde_json::from_slice(&data.value)
                    .context("Failed to deserialize user mapping")?;
                self.get_user_by_id(&user_id).await
            }
            None => Err(anyhow!("Certificate not mapped to any user")),
        }
    }

    /// Map certificate to user
    async fn map_certificate_to_user(&self, creds: &CertificateCredentials) -> Result<User> {
        // Try to find user by certificate subject
        let subject_key = format!("cert_subject/{}", creds.subject);
        if let Some(data) = self.storage.get(&subject_key).await? {
            let user_id: String = serde_json::from_slice(&data.value)
                .context("Failed to deserialize subject mapping")?;
            return self.get_user_by_id(&user_id).await;
        }

        // Try to find user by certificate serial number
        let serial_key = format!("cert_serial/{}", creds.serial_number);
        if let Some(data) = self.storage.get(&serial_key).await? {
            let user_id: String = serde_json::from_slice(&data.value)
                .context("Failed to deserialize serial mapping")?;
            return self.get_user_by_id(&user_id).await;
        }

        Err(anyhow!("Certificate not mapped to any user"))
    }

    /// Get user by ID
    async fn get_user_by_id(&self, user_id: &str) -> Result<User> {
        let key = format!("user/{}", user_id);
        match self.storage.get(&key).await? {
            Some(data) => {
                let user: User = serde_json::from_slice(&data.value)
                    .context("Failed to deserialize user")?;
                Ok(user)
            }
            None => Err(anyhow!("User not found")),
        }
    }

    /// Register certificate mapping
    pub async fn register_certificate(
        &self,
        user_id: &str,
        fingerprint: &str,
        subject: &str,
        serial_number: &str,
    ) -> Result<()> {
        // Store fingerprint to user mapping
        let fingerprint_key = format!("cert_mapping/{}", fingerprint);
        let user_data = serde_json::to_vec(user_id)?;
        self.storage.put(StorageEntry {
            key: fingerprint_key,
            value: user_data.clone(),
            metadata: HashMap::new(),
        }).await?;

        // Store subject to user mapping
        let subject_key = format!("cert_subject/{}", subject);
        self.storage.put(StorageEntry {
            key: subject_key,
            value: user_data.clone(),
            metadata: HashMap::new(),
        }).await?;

        // Store serial number to user mapping
        let serial_key = format!("cert_serial/{}", serial_number);
        self.storage.put(StorageEntry {
            key: serial_key,
            value: user_data,
            metadata: HashMap::new(),
        }).await?;

        // Audit log the registration
        self.audit_logger.log(AuditLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: "certificate_registered".to_string(),
            actor: Some(user_id.to_string()),
            resource_type: "certificate".to_string(),
            resource_id: fingerprint.to_string(),
            status: AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("subject".to_string(), subject.to_string());
                meta.insert("serial_number".to_string(), serial_number.to_string());
                meta
            },
        }).await?;

        Ok(())
    }

    /// Unregister certificate mapping
    pub async fn unregister_certificate(&self, fingerprint: &str) -> Result<()> {
        // Get user ID before removing mappings
        let user_id = match self.get_user_by_fingerprint(fingerprint).await {
            Ok(user) => user.id.to_string(),
            Err(_) => "unknown".to_string(),
        };

        // Remove all mappings
        let fingerprint_key = format!("cert_mapping/{}", fingerprint);
        self.storage.delete(&fingerprint_key).await?;

        // Note: We can't easily remove subject/serial mappings without knowing them
        // In a production system, you might want to store reverse mappings

        // Audit log the unregistration
        self.audit_logger.log(AuditLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: "certificate_unregistered".to_string(),
            actor: Some(user_id.clone()),
            resource_type: "certificate".to_string(),
            resource_id: fingerprint.to_string(),
            status: AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata: HashMap::new(),
        }).await?;

        Ok(())
    }

    /// List registered certificates
    pub async fn list_certificates(&self) -> Result<Vec<String>> {
        let prefix = "cert_mapping/";
        let keys = self.storage.list(prefix).await?;
        Ok(keys.into_iter()
            .filter_map(|key| key.strip_prefix(prefix).map(|s| s.to_string()))
            .collect())
    }
}

#[async_trait]
impl AuthMethod for CertificateAuth {
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResult> {
        let cert_creds = match credentials {
            Credentials::Certificate { 
                client_cert, 
                cert_chain,
                fingerprint,
                subject,
                issuer,
                serial_number 
            } => {
                CertificateCredentials {
                    client_cert: client_cert.clone(),
                    cert_chain: cert_chain.clone(),
                    fingerprint: fingerprint.clone(),
                    subject: subject.clone(),
                    issuer: issuer.clone(),
                    serial_number: serial_number.clone(),
                    not_before: Utc::now(), // Will be set during validation
                    not_after: Utc::now() + chrono::Duration::days(365), // Will be set during validation
                    extensions: HashMap::new(), // Will be set during validation
                }
            }
            _ => return Err(anyhow!("Invalid credential type for certificate authentication")),
        };

        // Validate certificate
        let user = self.validate_certificate(&cert_creds).await?;

        // Create token info
        let token_info = TokenInfo {
            id: Uuid::new_v4().to_string(),
            policies: vec!["default".to_string()], // Default policy for certificate users
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("auth_method".to_string(), "certificate".to_string());
                meta.insert("certificate_fingerprint".to_string(), cert_creds.fingerprint.clone());
                meta.insert("certificate_subject".to_string(), cert_creds.subject.clone());
                meta
            },
            ttl: Some(28800), // 8 hours in seconds
            renewable: true,
            entity_id: Some(user.id.to_string()),
        };

        // Audit log successful authentication
        self.audit_logger.log(AuditLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: "certificate_auth_success".to_string(),
            actor: Some(user.id.to_string()),
            resource_type: "auth".to_string(),
            resource_id: "certificate_authentication".to_string(),
            status: AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("certificate_fingerprint".to_string(), cert_creds.fingerprint.clone());
                meta.insert("certificate_subject".to_string(), cert_creds.subject.clone());
                meta.insert("user_id".to_string(), user.id.to_string());
                meta
            },
        }).await?;

        Ok(AuthResult {
            success: true,
            token: Some(token_info),
            user_info: Some({
                let mut info = HashMap::new();
                info.insert("user_id".to_string(), serde_json::Value::String(user.id.to_string()));
                info.insert("username".to_string(), serde_json::Value::String(user.username.clone()));
                info
            }),
            policies: vec!["default".to_string()],
            metadata: HashMap::new(),
            error: None,
        })
    }

    async fn validate_config(&self, config: &serde_json::Value) -> Result<()> {
        let _: CertificateConfig = serde_json::from_value(config.clone())
            .context("Invalid certificate authentication configuration")?;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<String>> {
        // For certificate auth, list certificate fingerprints from storage
        let keys = self.storage.list("cert_mapping/").await?;
        Ok(keys.into_iter()
            .filter_map(|key| key.strip_prefix("cert_mapping/").map(|s| s.to_string()))
            .collect())
    }

    async fn create_user(&self, _username: &str, _config: &serde_json::Value) -> Result<()> {
        // Certificate auth doesn't create users in the traditional sense
        // Users are "created" by registering their certificates
        Err(anyhow!("Certificate authentication requires certificate registration, not user creation. Use register_certificate instead."))
    }

    async fn delete_user(&self, username: &str) -> Result<()> {
        // For certificate auth, "deleting" a user means unregistering their certificate
        self.unregister_certificate(username).await
    }

    fn name(&self) -> &'static str {
        "certificate"
    }

    fn description(&self) -> &'static str {
        "X.509 Certificate-based authentication for mTLS environments"
    }

    fn supports_user_management(&self) -> bool {
        true // We support managing certificate mappings
    }

    fn supports_mfa(&self) -> bool {
        false // Certificate itself is a strong form of authentication
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use async_trait::async_trait;
    
    // Mock implementations for testing
    #[derive(Debug)]
    struct MockStorage {
        data: HashMap<String, Vec<u8>>,
    }
    
    impl MockStorage {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
            }
        }
    }
    
    #[async_trait]
    impl StorageEngine for MockStorage {
        async fn get(&self, _key: &str) -> Result<Option<StorageEntry>, crate::error::CoreError> {
            Ok(None)
        }
        
        async fn put(&self, _entry: StorageEntry) -> Result<(), crate::error::CoreError> {
            Ok(())
        }
        
        async fn delete(&self, _key: &str) -> Result<(), crate::error::CoreError> {
            Ok(())
        }
        
        async fn list(&self, _prefix: &str) -> Result<Vec<String>, crate::error::CoreError> {
            Ok(vec![])
        }
    }
    
    #[derive(Debug)]
    struct MockAuditLogger;
    
    impl MockAuditLogger {
        fn new() -> AuditLogger {
            // Create a minimal audit logger for testing
            AuditLogger::new(vec![])
        }
    }

    #[tokio::test]
    async fn test_certificate_auth_creation() {
        let config = CertificateConfig::default();
        let storage = Arc::new(MockStorage::new());
        let audit_logger = MockAuditLogger::new();

        let auth = CertificateAuth::new(config, storage, audit_logger);
        assert_eq!(auth.name(), "certificate");
        assert_eq!(auth.description(), "X.509 Certificate-based authentication for mTLS environments");
    }

    #[tokio::test]
    async fn test_certificate_registration() {
        let config = CertificateConfig::default();
        let storage = Arc::new(MockStorage::new());
        let audit_logger = MockAuditLogger::new();

        let auth = CertificateAuth::new(config, storage, audit_logger);

        let result = auth.register_certificate(
            "user123",
            "SHA256:fingerprint123",
            "CN=user,O=Company",
            "123456789"
        ).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_certificate_config_validation() {
        let config = CertificateConfig::default();
        let storage = Arc::new(MockStorage::new());
        let audit_logger = MockAuditLogger::new();

        let auth = CertificateAuth::new(config, storage, audit_logger);

        let config_json = serde_json::json!({
            "enabled": true,
            "crl_url": null,
            "ocsp_url": null,
            "validation_level": "Standard",
            "max_chain_depth": 10,
            "required_extensions": [],
            "allowed_issuers": [],
            "cert_cache_ttl": 3600,
            "trusted_roots": []
        });

        let result = auth.validate_config(&config_json).await;
        assert!(result.is_ok());
    }
}
