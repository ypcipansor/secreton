//! # Secreton Unified Configuration
//!
//! Centralized configuration management for all Secreton components.
//! Provides unified configuration structures, loading, validation, and management.
//!
//! ## Features
//!
//! - **Unified Config Structures**: All configuration consolidated into logical groups
//! - **Layered Loading**: Environment variables, config files, and defaults
//! - **Validation**: Comprehensive configuration validation
//! - **Hot Reloading**: Support for runtime configuration updates
//! - **Type Safety**: Strongly typed configuration with compile-time guarantees
//!
//! ## Configuration Hierarchy
//!
//! 1. **Core Config**: Server, storage, security fundamentals
//! 2. **Auth Config**: Authentication and authorization settings
//! 3. **Monitoring Config**: Alerting, logging, and monitoring configuration
//! 4. **Service Configs**: Component-specific configurations
//!
//! ## Usage
//!
//! ```rust
//! use secreton_config_unified::{Config, CoreConfig};
//!
//! // Load configuration with layered sources
//! let config = CoreConfig::load()?;
//!
//! // Access specific configuration sections
//! let server_config = &config.server;
//! let auth_config = &config.auth;
//! ```

use secreton_common::utils::password::PasswordPolicy;
use secreton_errors::{Result as SecretonResult, SecretonError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Base configuration trait that all config structs should implement
pub trait Config: for<'de> Deserialize<'de> + Serialize + Clone + Default {
    /// Load configuration from a file
    fn load_from_file<P: AsRef<Path>>(path: P) -> SecretonResult<Self> {
        let content = fs::read_to_string(path).map_err(|e| SecretonError::Configuration {
            message: format!("Failed to read config file: {}", e),
        })?;

        let config: Self = toml::from_str(&content).map_err(|e| SecretonError::Parse {
            message: format!("Failed to parse config: {}", e),
        })?;

        config.validate()?;
        Ok(config)
    }

    /// Load configuration from environment variables
    fn load_from_env() -> SecretonResult<Self> {
        let config = Self::default();

        // This would be implemented by each config struct
        // For now, return default
        config.validate()?;
        Ok(config)
    }

    /// Load configuration with layered sources (file + env + defaults)
    fn load() -> SecretonResult<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false))
            .add_source(config::Environment::with_prefix("SECRETON"))
            .build()
            .map_err(|e| SecretonError::Configuration {
                message: format!("Failed to build config: {}", e),
            })?;

        let config: Self =
            settings
                .try_deserialize()
                .map_err(|e| SecretonError::Configuration {
                    message: format!("Failed to deserialize config: {}", e),
                })?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> SecretonResult<()>;

    /// Get configuration as a map for debugging
    fn as_map(&self) -> HashMap<String, serde_json::Value> {
        serde_json::to_value(self)
            .unwrap_or(serde_json::Value::Null)
            .as_object()
            .unwrap_or(&serde_json::Map::new())
            .clone()
            .into_iter()
            .collect()
    }
}

/// Core configuration - shared across all components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Server configuration
    pub server: ServerConfig,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Metrics configuration
    pub metrics: MetricsConfig,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

impl Config for CoreConfig {
    fn validate(&self) -> SecretonResult<()> {
        self.server.validate()?;
        self.storage.validate()?;
        self.security.validate()?;
        self.logging.validate()?;
        self.metrics.validate()?;
        Ok(())
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host
    pub host: String,

    /// Server port
    pub port: u16,

    /// TLS configuration
    pub tls: Option<TlsConfig>,

    /// Request timeout in seconds
    pub request_timeout: u64,

    /// Maximum request body size in bytes
    pub max_body_size: usize,

    /// CORS configuration
    pub cors: Option<CorsConfig>,

    /// Rate limiting configuration
    pub rate_limiting: Option<RateLimitConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8200,
            tls: None,
            request_timeout: 30,
            max_body_size: 10 * 1024 * 1024, // 10MB
            cors: Some(CorsConfig::default()),
            rate_limiting: Some(RateLimitConfig::default()),
        }
    }
}

impl Config for ServerConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.port == 0 {
            return Err(SecretonError::Configuration {
                message: "Server port cannot be zero".to_string(),
            });
        }

        if self.request_timeout == 0 {
            return Err(SecretonError::Configuration {
                message: "Request timeout cannot be zero".to_string(),
            });
        }

        if self.max_body_size == 0 {
            return Err(SecretonError::Configuration {
                message: "Max body size cannot be zero".to_string(),
            });
        }

        if let Some(tls) = &self.tls {
            tls.validate()?;
        }

        Ok(())
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: String,

    /// Path to private key file
    pub key_path: String,

    /// Minimum TLS version
    pub min_version: String,

    /// Cipher suites
    pub cipher_suites: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: "certs/server.crt".to_string(),
            key_path: "certs/server.key".to_string(),
            min_version: "1.2".to_string(),
            cipher_suites: vec![
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            ],
        }
    }
}

impl Config for TlsConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.cert_path.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Certificate path cannot be empty".to_string(),
            });
        }

        if self.key_path.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Key path cannot be empty".to_string(),
            });
        }

        Ok(())
    }
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,

    /// Allowed headers
    pub allowed_headers: Vec<String>,

    /// Allowed methods
    pub allowed_methods: Vec<String>,

    /// Allow credentials
    pub allow_credentials: bool,

    /// Max age in seconds
    pub max_age: Option<u64>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_headers: vec![
                "authorization".to_string(),
                "content-type".to_string(),
                "x-requested-with".to_string(),
            ],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allow_credentials: true,
            max_age: Some(86400), // 24 hours
        }
    }
}

impl Config for CorsConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.allowed_origins.is_empty() {
            return Err(SecretonError::Configuration {
                message: "At least one allowed origin must be specified".to_string(),
            });
        }

        Ok(())
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per second
    pub requests_per_second: u32,

    /// Burst size
    pub burst_size: u32,

    /// Time window in seconds
    pub time_window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst_size: 20,
            time_window_seconds: 60,
        }
    }
}

impl Config for RateLimitConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.requests_per_second == 0 {
            return Err(SecretonError::Configuration {
                message: "Requests per second cannot be zero".to_string(),
            });
        }

        if self.time_window_seconds == 0 {
            return Err(SecretonError::Configuration {
                message: "Time window cannot be zero".to_string(),
            });
        }

        Ok(())
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: StorageBackendType,

    /// File storage configuration
    pub file: Option<FileStorageConfig>,

    /// Database storage configuration
    pub database: Option<DatabaseStorageConfig>,

    /// Cloud storage configuration
    pub cloud: Option<CloudStorageConfig>,

    /// Encryption configuration
    pub encryption: EncryptionConfig,

    /// Connection pool configuration
    pub connection_pool: ConnectionPoolConfig,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackendType::File,
            file: Some(FileStorageConfig::default()),
            database: None,
            cloud: None,
            encryption: EncryptionConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
        }
    }
}

impl Config for StorageConfig {
    fn validate(&self) -> SecretonResult<()> {
        match self.backend {
            StorageBackendType::File => {
                if self.file.is_none() {
                    return Err(SecretonError::Configuration {
                        message: "File storage config required for file backend".to_string(),
                    });
                }
                self.file.as_ref().unwrap().validate()?;
            }
            StorageBackendType::Database => {
                if self.database.is_none() {
                    return Err(SecretonError::Configuration {
                        message: "Database storage config required for database backend"
                            .to_string(),
                    });
                }
                self.database.as_ref().unwrap().validate()?;
            }
            StorageBackendType::Cloud => {
                if self.cloud.is_none() {
                    return Err(SecretonError::Configuration {
                        message: "Cloud storage config required for cloud backend".to_string(),
                    });
                }
                self.cloud.as_ref().unwrap().validate()?;
            }
        }

        self.encryption.validate()?;
        self.connection_pool.validate()?;

        Ok(())
    }
}

/// Storage backend types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageBackendType {
    File,
    Database,
    Cloud,
}

/// File storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStorageConfig {
    /// Base directory for storage
    pub base_path: String,

    /// Maximum file size in bytes
    pub max_file_size: u64,

    /// File permissions
    pub file_permissions: u32,

    /// Directory permissions
    pub dir_permissions: u32,
}

impl Default for FileStorageConfig {
    fn default() -> Self {
        Self {
            base_path: "./data/storage".to_string(),
            max_file_size: 100 * 1024 * 1024, // 100MB
            file_permissions: 0o600,
            dir_permissions: 0o700,
        }
    }
}

impl Config for FileStorageConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.base_path.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Base path cannot be empty".to_string(),
            });
        }

        if self.max_file_size == 0 {
            return Err(SecretonError::Configuration {
                message: "Max file size cannot be zero".to_string(),
            });
        }

        Ok(())
    }
}

/// Database storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStorageConfig {
    /// Database URL
    pub url: String,

    /// Database type
    pub db_type: DatabaseType,

    /// Connection pool size
    pub max_connections: u32,

    /// Connection timeout in seconds
    pub connection_timeout: u64,

    /// Query timeout in seconds
    pub query_timeout: u64,
}

impl Default for DatabaseStorageConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost:5432/secreton".to_string(),
            db_type: DatabaseType::PostgreSQL,
            max_connections: 10,
            connection_timeout: 30,
            query_timeout: 60,
        }
    }
}

impl Config for DatabaseStorageConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.url.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Database URL cannot be empty".to_string(),
            });
        }

        if self.max_connections == 0 {
            return Err(SecretonError::Configuration {
                message: "Max connections cannot be zero".to_string(),
            });
        }

        Ok(())
    }
}

/// Database types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseType {
    PostgreSQL,
    MySQL,
    SQLite,
}

/// Cloud storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudStorageConfig {
    /// Cloud provider
    pub provider: CloudProvider,

    /// Bucket/container name
    pub bucket: String,

    /// Region
    pub region: String,

    /// Access key/credentials
    pub credentials: CloudCredentials,

    /// Endpoint (for S3-compatible services)
    pub endpoint: Option<String>,
}

impl Default for CloudStorageConfig {
    fn default() -> Self {
        Self {
            provider: CloudProvider::AWS,
            bucket: "secreton-storage".to_string(),
            region: "us-east-1".to_string(),
            credentials: CloudCredentials::default(),
            endpoint: None,
        }
    }
}

impl Config for CloudStorageConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.bucket.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Bucket name cannot be empty".to_string(),
            });
        }

        if self.region.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Region cannot be empty".to_string(),
            });
        }

        self.credentials.validate()?;

        Ok(())
    }
}

/// Cloud providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloudProvider {
    AWS,
    GCP,
    Azure,
}

/// Cloud credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudCredentials {
    /// Access key ID
    pub access_key_id: String,

    /// Secret access key
    pub secret_access_key: String,

    /// Session token (optional)
    pub session_token: Option<String>,
}

impl Default for CloudCredentials {
    fn default() -> Self {
        Self {
            access_key_id: String::new(),
            secret_access_key: String::new(),
            session_token: None,
        }
    }
}

impl Config for CloudCredentials {
    fn validate(&self) -> SecretonResult<()> {
        if self.access_key_id.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Access key ID cannot be empty".to_string(),
            });
        }

        if self.secret_access_key.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Secret access key cannot be empty".to_string(),
            });
        }

        Ok(())
    }
}

/// Crypto integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoIntegrationConfig {
    pub api: ApiConfig,
    pub storage: CryptoStorageConfig,
    pub rate_limit: CryptoRateLimitConfig,
    pub performance: PerformanceConfig,
}

impl Default for CryptoIntegrationConfig {
    fn default() -> Self {
        Self {
            api: ApiConfig::default(),
            storage: CryptoStorageConfig::default(),
            rate_limit: CryptoRateLimitConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Config for CryptoIntegrationConfig {
    fn validate(&self) -> SecretonResult<()> {
        self.api.validate()?;
        self.storage.validate()?;
        self.rate_limit.validate()?;
        self.performance.validate()?;
        Ok(())
    }
}

/// API configuration for crypto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub port: u16,
    pub host: String,
    pub tls_enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            host: "0.0.0.0".to_string(),
            tls_enabled: false,
            cert_path: None,
            key_path: None,
        }
    }
}

impl Config for ApiConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.port == 0 {
            return Err(SecretonError::Configuration {
                message: "API port cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Storage configuration for crypto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoStorageConfig {
    pub backend: String,
    pub path: String,
    pub encryption_enabled: bool,
}

impl Default for CryptoStorageConfig {
    fn default() -> Self {
        Self {
            backend: "file".to_string(),
            path: "./crypto".to_string(),
            encryption_enabled: true,
        }
    }
}

impl Config for CryptoStorageConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.path.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Crypto storage path cannot be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Rate limiting configuration for crypto integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoRateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub time_window_seconds: u32,
}

impl Default for CryptoRateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10,
            burst_size: 100,
            time_window_seconds: 60,
        }
    }
}

impl Config for CryptoRateLimitConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.requests_per_second == 0 {
            return Err(SecretonError::Configuration {
                message: "Requests per second cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Performance configuration for crypto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub thread_pool_size: usize,
    pub queue_size: usize,
    pub timeout: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            thread_pool_size: 4,
            queue_size: 1000,
            timeout: 30,
        }
    }
}

impl Config for PerformanceConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.thread_pool_size == 0 {
            return Err(SecretonError::Configuration {
                message: "Thread pool size cannot be zero".to_string(),
            });
        }
        if self.queue_size == 0 {
            return Err(SecretonError::Configuration {
                message: "Queue size cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// KMIP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipConfig {
    pub port: u16,
    pub host: String,
    pub tls_enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub ca_cert_path: Option<String>,
    pub client_auth: bool,
}

impl Default for KmipConfig {
    fn default() -> Self {
        Self {
            port: 5696,
            host: "0.0.0.0".to_string(),
            tls_enabled: true,
            cert_path: Some("certs/kmip.crt".to_string()),
            key_path: Some("certs/kmip.key".to_string()),
            ca_cert_path: Some("certs/ca.crt".to_string()),
            client_auth: true,
        }
    }
}

impl Config for KmipConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.port == 0 {
            return Err(SecretonError::Configuration {
                message: "KMIP port cannot be zero".to_string(),
            });
        }
        if self.tls_enabled {
            if self.cert_path.is_none() || self.key_path.is_none() {
                return Err(SecretonError::Configuration {
                    message: "Certificate and key paths required when TLS is enabled".to_string(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub algorithm: EncryptionAlgorithm,
    pub kdf: KeyDerivationFunction,
    pub key_size: u32,
    pub master_key: MasterKeyConfig,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: EncryptionAlgorithm::AES256GCM,
            kdf: KeyDerivationFunction::Argon2,
            key_size: 256,
            master_key: MasterKeyConfig::default(),
        }
    }
}

impl Config for EncryptionConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.enabled {
            if self.key_size == 0 {
                return Err(SecretonError::Configuration {
                    message: "Key size cannot be zero".to_string(),
                });
            }

            self.master_key.validate()?;
        }

        Ok(())
    }
}

/// Encryption algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
}

/// Key derivation functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyDerivationFunction {
    Argon2,
    PBKDF2,
}

/// Master key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKeyConfig {
    /// Key source
    pub source: KeySource,

    /// Key rotation interval in days
    pub rotation_interval_days: u32,

    /// Minimum key version to keep
    pub min_versions: usize,
}

impl Default for MasterKeyConfig {
    fn default() -> Self {
        Self {
            source: KeySource::Generated,
            rotation_interval_days: 90,
            min_versions: 3,
        }
    }
}

impl Config for MasterKeyConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.rotation_interval_days == 0 {
            return Err(SecretonError::Configuration {
                message: "Rotation interval cannot be zero".to_string(),
            });
        }

        if self.min_versions == 0 {
            return Err(SecretonError::Configuration {
                message: "Minimum versions cannot be zero".to_string(),
            });
        }

        Ok(())
    }
}

/// Key sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeySource {
    Generated,
    External,
    HSM,
}

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    /// Maximum connections
    pub max_connections: u32,

    /// Minimum idle connections
    pub min_idle: u32,

    /// Connection timeout in seconds
    pub connection_timeout: u64,

    /// Idle timeout in seconds
    pub idle_timeout: u64,

    /// Maximum lifetime in seconds
    pub max_lifetime: u64,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_idle: 1,
            connection_timeout: 30,
            idle_timeout: 300,
            max_lifetime: 3600,
        }
    }
}

impl Config for ConnectionPoolConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.max_connections == 0 {
            return Err(SecretonError::Configuration {
                message: "Max connections cannot be zero".to_string(),
            });
        }

        if self.min_idle > self.max_connections {
            return Err(SecretonError::Configuration {
                message: "Min idle cannot be greater than max connections".to_string(),
            });
        }

        Ok(())
    }
}

/// Agent security enforcement configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSecurityConfig {
    /// Security scan interval in seconds
    pub scan_interval_seconds: u64,

    /// Enable intrusion detection
    pub intrusion_detection_enabled: bool,

    /// Enable malware scanning
    pub malware_scan_enabled: bool,

    /// Enable vulnerability scanning
    pub vulnerability_scan_enabled: bool,

    /// Enable compliance checking
    pub compliance_check_enabled: bool,

    /// Auto-block suspicious IPs
    pub auto_block_ips: bool,

    /// Auto-quarantine infected files
    pub auto_quarantine: bool,

    /// Enable encryption compliance checks
    pub encryption_enabled: bool,

    /// Enable access control compliance checks
    pub access_control_enabled: bool,

    /// Enable data protection compliance checks
    pub data_protection_enabled: bool,
}

impl Default for AgentSecurityConfig {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 300, // 5 minutes
            intrusion_detection_enabled: true,
            malware_scan_enabled: true,
            vulnerability_scan_enabled: true,
            compliance_check_enabled: true,
            auto_block_ips: true,
            auto_quarantine: true,
            encryption_enabled: true,
            access_control_enabled: true,
            data_protection_enabled: true,
        }
    }
}

impl Config for AgentSecurityConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.scan_interval_seconds == 0 {
            return Err(SecretonError::Configuration {
                message: "Security scan interval cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// JWT configuration
    pub jwt: JwtConfig,

    /// MFA configuration
    pub mfa: MfaConfig,

    /// Password policy
    pub password_policy: secreton_common::utils::password::PasswordPolicy,

    /// Session configuration
    pub session: SessionConfig,

    /// Audit logging configuration
    pub audit: AuditConfig,

    /// Rate limiting
    pub rate_limiting: RateLimitConfig,

    /// Agent security enforcement settings
    pub agent: AgentSecurityConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt: JwtConfig::default(),
            mfa: MfaConfig::default(),
            password_policy: PasswordPolicy::default(),
            session: SessionConfig::default(),
            audit: AuditConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            agent: AgentSecurityConfig::default(),
        }
    }
}

impl Config for SecurityConfig {
    fn validate(&self) -> SecretonResult<()> {
        self.jwt.validate()?;
        self.mfa.validate()?;
        self.password_policy
            .validate()
            .map_err(|e| SecretonError::Configuration {
                message: format!("Password policy validation failed: {}", e),
            })?;
        self.session.validate()?;
        self.audit.validate()?;
        Ok(())
    }
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT secret key
    pub secret: String,

    /// Refresh token secret
    pub refresh_secret: Option<String>,

    /// Access token expiration in seconds
    pub expiration: u64,

    /// Refresh token expiration in seconds
    pub refresh_expiration: Option<u64>,

    /// JWT issuer
    pub issuer: String,

    /// JWT audience
    pub audience: String,

    /// Algorithm
    pub algorithm: JwtAlgorithm,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "change-this-in-production".to_string(),
            refresh_secret: None,
            expiration: 3600,                 // 1 hour
            refresh_expiration: Some(604800), // 7 days
            issuer: "secreton".to_string(),
            audience: "secreton-api".to_string(),
            algorithm: JwtAlgorithm::HS256,
        }
    }
}

impl Config for JwtConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.secret.is_empty() || self.secret == "change-this-in-production" {
            return Err(SecretonError::Configuration {
                message: "JWT secret must be set and not use default value".to_string(),
            });
        }

        if self.expiration == 0 {
            return Err(SecretonError::Configuration {
                message: "JWT expiration cannot be zero".to_string(),
            });
        }

        if self.issuer.is_empty() {
            return Err(SecretonError::Configuration {
                message: "JWT issuer cannot be empty".to_string(),
            });
        }

        if self.audience.is_empty() {
            return Err(SecretonError::Configuration {
                message: "JWT audience cannot be empty".to_string(),
            });
        }

        Ok(())
    }
}

/// JWT algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

/// MFA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    /// Enable MFA globally
    pub enabled: bool,

    /// Required MFA methods
    pub required_methods: Vec<MfaMethod>,

    /// MFA issuer name
    pub issuer: String,

    /// TOTP configuration
    pub totp: TotpConfig,

    /// SMS configuration
    pub sms: SmsConfig,

    /// Email configuration
    pub email: EmailConfig,

    /// Backup codes count
    pub backup_codes_count: usize,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required_methods: vec![MfaMethod::TOTP],
            issuer: "Secreton".to_string(),
            totp: TotpConfig::default(),
            sms: SmsConfig::default(),
            email: EmailConfig::default(),
            backup_codes_count: 10,
        }
    }
}

impl Config for MfaConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.enabled {
            if self.required_methods.is_empty() {
                return Err(SecretonError::Configuration {
                    message: "At least one MFA method must be required when MFA is enabled"
                        .to_string(),
                });
            }

            if self.issuer.is_empty() {
                return Err(SecretonError::Configuration {
                    message: "MFA issuer cannot be empty".to_string(),
                });
            }
        }

        if self.backup_codes_count == 0 {
            return Err(SecretonError::Configuration {
                message: "Backup codes count cannot be zero".to_string(),
            });
        }

        Ok(())
    }
}

/// MFA methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaMethod {
    TOTP,
    SMS,
    Email,
}

/// TOTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Algorithm
    pub algorithm: TotpAlgorithm,

    /// Digits
    pub digits: u8,

    /// Period in seconds
    pub period: u32,

    /// Skew (allowance for clock drift)
    pub skew: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::SHA1,
            digits: 6,
            period: 30,
            skew: 1,
        }
    }
}

/// TOTP algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

/// SMS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    /// SMS provider
    pub provider: SmsProvider,

    /// Account SID (for Twilio)
    pub account_sid: String,

    /// Auth token
    pub auth_token: String,

    /// From number
    pub from_number: String,

    /// To numbers (recipients)
    pub to_numbers: Vec<String>,

    /// Rate limiting
    pub rate_limit: SmsRateLimit,
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            provider: SmsProvider::Twilio,
            account_sid: String::new(),
            auth_token: String::new(),
            from_number: String::new(),
            to_numbers: Vec::new(),
            rate_limit: SmsRateLimit::default(),
        }
    }
}

/// SMS providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmsProvider {
    Twilio,
    AWS,
    GCP,
}

/// SMS rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsRateLimit {
    /// Messages per minute
    pub per_minute: u32,

    /// Messages per hour
    pub per_hour: u32,

    /// Messages per day
    pub per_day: u32,
}

impl Default for SmsRateLimit {
    fn default() -> Self {
        Self {
            per_minute: 10,
            per_hour: 100,
            per_day: 500,
        }
    }
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server
    pub smtp_server: String,

    /// SMTP port
    pub smtp_port: u16,

    /// SMTP username
    pub smtp_username: String,

    /// SMTP password
    pub smtp_password: String,

    /// From address
    pub from_address: String,

    /// To addresses (for notifications)
    pub to_addresses: Vec<String>,

    /// Use TLS
    pub use_tls: bool,

    /// Use STARTTLS
    pub use_starttls: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_server: "localhost".to_string(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            from_address: "noreply@secreton.local".to_string(),
            to_addresses: Vec::new(),
            use_tls: false,
            use_starttls: true,
        }
    }
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session timeout in seconds
    pub timeout_seconds: u64,

    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: usize,

    /// Enable session persistence
    pub persistence_enabled: bool,

    /// Session cleanup interval in seconds
    pub cleanup_interval_seconds: u64,

    /// Session cookie configuration
    pub cookie: SessionCookieConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 3600, // 1 hour
            max_concurrent_sessions: 5,
            persistence_enabled: true,
            cleanup_interval_seconds: 300, // 5 minutes
            cookie: SessionCookieConfig::default(),
        }
    }
}

impl Config for SessionConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.timeout_seconds == 0 {
            return Err(SecretonError::Configuration {
                message: "Session timeout cannot be zero".to_string(),
            });
        }

        if self.max_concurrent_sessions == 0 {
            return Err(SecretonError::Configuration {
                message: "Max concurrent sessions cannot be zero".to_string(),
            });
        }

        Ok(())
    }
}

/// Session cookie configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCookieConfig {
    /// Cookie name
    pub name: String,

    /// Domain
    pub domain: Option<String>,

    /// Path
    pub path: String,

    /// Secure flag
    pub secure: bool,

    /// HttpOnly flag
    pub http_only: bool,

    /// SameSite attribute
    pub same_site: SameSite,
}

impl Default for SessionCookieConfig {
    fn default() -> Self {
        Self {
            name: "secreton_session".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Strict,
        }
    }
}

/// SameSite cookie attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,

    /// Audit log level
    pub level: AuditLevel,

    /// Storage backend for audit logs
    pub storage: AuditStorage,

    /// Retention period in days
    pub retention_days: u32,

    /// Maximum audit entries per batch
    pub max_batch_size: usize,

    /// Audit filters
    pub filters: Vec<AuditFilter>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: AuditLevel::Detailed,
            storage: AuditStorage::File,
            retention_days: 365,
            max_batch_size: 100,
            filters: Vec::new(),
        }
    }
}

impl Config for AuditConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.enabled {
            if self.retention_days == 0 {
                return Err(SecretonError::Configuration {
                    message: "Audit retention days cannot be zero".to_string(),
                });
            }

            if self.max_batch_size == 0 {
                return Err(SecretonError::Configuration {
                    message: "Max batch size cannot be zero".to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Audit log levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditLevel {
    Minimal,
    Standard,
    Detailed,
}

/// Audit storage backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStorage {
    File,
    Database,
    Syslog,
    External,
}

/// Audit filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter name
    pub name: String,

    /// Filter rules
    pub rules: Vec<AuditRule>,
}

/// Audit rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRule {
    /// Field to filter on
    pub field: String,

    /// Operator
    pub operator: AuditOperator,

    /// Value to match
    pub value: String,
}

/// Audit operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    Regex,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,

    /// Log format
    pub format: String,

    /// Enable file logging
    pub file_enabled: bool,

    /// Log file path
    pub file_path: String,

    /// Maximum log file size in MB
    pub max_file_size_mb: u64,

    /// Number of log files to retain
    pub max_files: u32,

    /// Enable structured logging
    pub structured: bool,

    /// Enable console logging
    pub console_enabled: bool,

    /// Enable syslog
    pub syslog_enabled: bool,

    /// Syslog facility
    pub syslog_facility: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            file_enabled: true,
            file_path: "/var/log/secreton.log".to_string(),
            max_file_size_mb: 100,
            max_files: 10,
            structured: true,
            console_enabled: true,
            syslog_enabled: false,
            syslog_facility: Some("local0".to_string()),
        }
    }
}

impl Config for LoggingConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.file_enabled && self.file_path.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Log file path cannot be empty when file logging is enabled".to_string(),
            });
        }

        if self.max_file_size_mb == 0 {
            return Err(SecretonError::Configuration {
                message: "Max file size cannot be zero".to_string(),
            });
        }

        if self.max_files == 0 {
            return Err(SecretonError::Configuration {
                message: "Max files cannot be zero".to_string(),
            });
        }

        Ok(())
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,

    /// Metrics collection interval in seconds
    pub collection_interval_seconds: u64,

    /// Enable Prometheus metrics
    pub prometheus_enabled: bool,

    /// Prometheus metrics port
    pub prometheus_port: u16,

    /// Prometheus metrics path
    pub prometheus_path: String,

    /// Enable StatsD metrics
    pub statsd_enabled: bool,

    /// StatsD server address
    pub statsd_address: String,

    /// Metrics retention period in seconds
    pub retention_seconds: u64,

    /// Enable health check metrics
    pub health_metrics_enabled: bool,

    /// Enable performance metrics
    pub performance_metrics_enabled: bool,

    /// Enable security metrics
    pub security_metrics_enabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval_seconds: 60,
            prometheus_enabled: true,
            prometheus_port: 9090,
            prometheus_path: "/metrics".to_string(),
            statsd_enabled: false,
            statsd_address: "localhost:8125".to_string(),
            retention_seconds: 86400 * 7, // 7 days
            health_metrics_enabled: true,
            performance_metrics_enabled: true,
            security_metrics_enabled: true,
        }
    }
}

impl Config for MetricsConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.enabled {
            if self.collection_interval_seconds == 0 {
                return Err(SecretonError::Configuration {
                    message: "Collection interval cannot be zero".to_string(),
                });
            }

            if self.prometheus_enabled && self.prometheus_port == 0 {
                return Err(SecretonError::Configuration {
                    message: "Prometheus port cannot be zero".to_string(),
                });
            }

            if self.retention_seconds == 0 {
                return Err(SecretonError::Configuration {
                    message: "Retention seconds cannot be zero".to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Integrations configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationsConfig {
    /// General integration settings
    pub general: Option<IntegrationConfig>,
    /// Advanced backup recovery
    pub backup_recovery: Option<BackupConfig>,
    /// CI/CD pipeline integration
    pub cicd_pipeline: Option<PipelineConfig>,
    /// Distributed tracing
    pub distributed_tracing: Option<TracingConfig>,
    /// Secret migration
    pub secret_migration: Option<BackendConfig>,
    /// Plugin system
    pub plugin: Option<PluginConfig>,
}

impl Default for IntegrationsConfig {
    fn default() -> Self {
        Self {
            general: None,
            backup_recovery: None,
            cicd_pipeline: None,
            distributed_tracing: None,
            secret_migration: None,
            plugin: None,
        }
    }
}

impl Config for IntegrationsConfig {
    fn validate(&self) -> SecretonResult<()> {
        // Validate individual configs if present
        if let Some(general) = &self.general {
            general.validate()?;
        }
        if let Some(backup) = &self.backup_recovery {
            backup.validate()?;
        }
        if let Some(pipeline) = &self.cicd_pipeline {
            pipeline.validate()?;
        }
        Ok(())
    }
}

/// General integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub enabled: bool,
    pub timeout: u64,
    pub retry_count: u32,
    pub retry_delay: u64,
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout: 30,
            retry_count: 3,
            retry_delay: 5,
        }
    }
}

impl Config for IntegrationConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.timeout == 0 {
            return Err(SecretonError::Configuration {
                message: "Integration timeout cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Advanced backup recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub enabled: bool,
    pub schedule: String,
    pub retention_days: u32,
    pub compression: bool,
    pub encryption: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: "0 2 * * *".to_string(),
            retention_days: 30,
            compression: true,
            encryption: true,
        }
    }
}

impl Config for BackupConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.enabled && self.retention_days == 0 {
            return Err(SecretonError::Configuration {
                message: "Backup retention days cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// CI/CD pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub enabled: bool,
    pub providers: Vec<String>,
    pub webhook_url: String,
    pub secret_prefix: String,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            providers: vec![],
            webhook_url: String::new(),
            secret_prefix: "SECRETON_".to_string(),
        }
    }
}

impl Config for PipelineConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.enabled && self.webhook_url.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Webhook URL required when CI/CD pipeline is enabled".to_string(),
            });
        }
        Ok(())
    }
}

/// Secret migration backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub source_backend: String,
    pub target_backend: String,
    pub batch_size: usize,
    pub concurrency: usize,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            source_backend: String::new(),
            target_backend: String::new(),
            batch_size: 100,
            concurrency: 4,
        }
    }
}

impl Config for BackendConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.batch_size == 0 {
            return Err(SecretonError::Configuration {
                message: "Batch size cannot be zero".to_string(),
            });
        }
        if self.concurrency == 0 {
            return Err(SecretonError::Configuration {
                message: "Concurrency cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub directory: String,
    pub allowed_plugins: Vec<String>,
    pub sandbox_enabled: bool,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: "./plugins".to_string(),
            allowed_plugins: vec![],
            sandbox_enabled: true,
        }
    }
}

impl Config for PluginConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.enabled && self.directory.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Plugin directory cannot be empty when plugins are enabled".to_string(),
            });
        }
        Ok(())
    }
}

/// Distributed tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub service_name: String,
    pub collector_endpoint: String,
    pub sampling_rate: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: "secreton".to_string(),
            collector_endpoint: "http://localhost:14268/api/traces".to_string(),
            sampling_rate: 0.1,
        }
    }
}

impl Config for TracingConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.enabled {
            if self.service_name.is_empty() {
                return Err(SecretonError::Configuration {
                    message: "Service name is required for tracing".to_string(),
                });
            }
            if self.collector_endpoint.is_empty() {
                return Err(SecretonError::Configuration {
                    message: "Collector endpoint is required for tracing".to_string(),
                });
            }
            if self.sampling_rate < 0.0 || self.sampling_rate > 1.0 {
                return Err(SecretonError::Configuration {
                    message: "Sampling rate must be between 0.0 and 1.0".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Alerting configuration for monitoring system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    /// Processing interval in seconds
    pub processing_interval_seconds: u64,

    /// Maximum alert history size
    pub max_history_size: usize,

    /// Deduplication window in seconds
    pub deduplication_window_seconds: u64,

    /// Email notification configuration
    pub email: EmailConfig,

    /// Webhook notification configuration
    pub webhook: WebhookConfig,

    /// Slack notification configuration
    pub slack: SlackConfig,

    /// SMS notification configuration
    pub sms: SmsConfig,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            processing_interval_seconds: 60,
            max_history_size: 1000,
            deduplication_window_seconds: 300, // 5 minutes
            email: EmailConfig::default(),
            webhook: WebhookConfig::default(),
            slack: SlackConfig::default(),
            sms: SmsConfig::default(),
        }
    }
}

impl Config for AlertingConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.processing_interval_seconds == 0 {
            return Err(SecretonError::Configuration {
                message: "Processing interval cannot be zero".to_string(),
            });
        }
        if self.max_history_size == 0 {
            return Err(SecretonError::Configuration {
                message: "Max history size cannot be zero".to_string(),
            });
        }
        if self.deduplication_window_seconds == 0 {
            return Err(SecretonError::Configuration {
                message: "Deduplication window cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Webhook notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,

    /// Request timeout in seconds
    pub timeout_seconds: u64,

    /// Custom headers
    pub headers: HashMap<String, String>,

    /// Retry configuration
    pub retry_count: u32,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout_seconds: 30,
            headers: HashMap::new(),
            retry_count: 3,
        }
    }
}

impl Config for WebhookConfig {
    fn validate(&self) -> SecretonResult<()> {
        if !self.url.is_empty() && self.timeout_seconds == 0 {
            return Err(SecretonError::Configuration {
                message: "Webhook timeout cannot be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Slack notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    /// Slack webhook URL
    pub webhook_url: String,

    /// Default channel
    pub channel: String,

    /// Bot username
    pub username: String,

    /// Icon emoji
    pub icon_emoji: String,

    /// Mention users for critical alerts
    pub mention_users: Vec<String>,
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            webhook_url: String::new(),
            channel: "#alerts".to_string(),
            username: "Secreton Alert Bot".to_string(),
            icon_emoji: ":warning:".to_string(),
            mention_users: Vec::new(),
        }
    }
}

impl Config for SlackConfig {
    fn validate(&self) -> SecretonResult<()> {
        if !self.webhook_url.is_empty() && self.channel.is_empty() {
            return Err(SecretonError::Configuration {
                message: "Slack channel cannot be empty when webhook URL is set".to_string(),
            });
        }
        Ok(())
    }
}
