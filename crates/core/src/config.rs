//! Configuration management for Brankas

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::SecurityLevel;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrankasConfig {
    /// Server configuration
    pub server: ServerConfig,
    
    /// Security configuration  
    pub security: SecurityConfig,
    
    /// Database configuration
    pub database: DatabaseConfig,
    
    /// Audit configuration
    pub audit: AuditConfig,
    
    /// Metrics configuration
    pub metrics: MetricsConfig,
    
    /// Additional configuration parameters
    pub additional: HashMap<String, serde_json::Value>,
}

impl Default for BrankasConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            security: SecurityConfig::default(),
            database: DatabaseConfig::default(),
            audit: AuditConfig::default(),
            metrics: MetricsConfig::default(),
            additional: HashMap::new(),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server bind address
    pub host: String,
    
    /// Server port
    pub port: u16,
    
    /// Enable TLS
    pub tls_enabled: bool,
    
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    
    /// TLS private key path
    pub tls_key_path: Option<String>,
    
    /// Maximum request size in bytes
    pub max_request_size: usize,
    
    /// Request timeout in seconds
    pub request_timeout: u64,
    
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8443,
            tls_enabled: true,
            tls_cert_path: None,
            tls_key_path: None,
            max_request_size: 1024 * 1024, // 1MB
            request_timeout: 30,
            max_connections: 1000,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Default security level for new resources
    pub default_security_level: SecurityLevel,
    
    /// Enable multi-factor authentication
    pub mfa_enabled: bool,
    
    /// Session timeout in seconds
    pub session_timeout: u64,
    
    /// Maximum login attempts
    pub max_login_attempts: u32,
    
    /// Account lockout duration in seconds
    pub lockout_duration: u64,
    
    /// Password policy
    pub password_policy: PasswordPolicy,
    
    /// Encryption settings
    pub encryption: EncryptionConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_security_level: SecurityLevel::Internal,
            mfa_enabled: true,
            session_timeout: 3600, // 1 hour
            max_login_attempts: 5,
            lockout_duration: 300, // 5 minutes
            password_policy: PasswordPolicy::default(),
            encryption: EncryptionConfig::default(),
        }
    }
}

/// Password policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum password length
    pub min_length: usize,
    
    /// Require uppercase letters
    pub require_uppercase: bool,
    
    /// Require lowercase letters
    pub require_lowercase: bool,
    
    /// Require numbers
    pub require_numbers: bool,
    
    /// Require special characters
    pub require_special: bool,
    
    /// Password history count
    pub history_count: u32,
    
    /// Password expiration days
    pub expiration_days: Option<u32>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            history_count: 10,
            expiration_days: Some(90),
        }
    }
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Default encryption algorithm
    pub default_algorithm: String,
    
    /// Key derivation algorithm
    pub kdf_algorithm: String,
    
    /// KDF iterations
    pub kdf_iterations: u32,
    
    /// Key rotation interval in days
    pub key_rotation_days: u32,
    
    /// Enable at-rest encryption
    pub encrypt_at_rest: bool,
    
    /// Enable in-transit encryption
    pub encrypt_in_transit: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            default_algorithm: "AES-256-GCM".to_string(),
            kdf_algorithm: "Argon2id".to_string(),
            kdf_iterations: 100_000,
            key_rotation_days: 90,
            encrypt_at_rest: true,
            encrypt_in_transit: true,
        }
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,
    
    /// Maximum connections
    pub max_connections: u32,
    
    /// Connection timeout
    pub connect_timeout: u64,
    
    /// Query timeout
    pub query_timeout: u64,
    
    /// Enable SSL
    pub ssl_enabled: bool,
    
    /// Migration settings
    pub migration: MigrationConfig,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost:5432/brankas".to_string(),
            max_connections: 10,
            connect_timeout: 30,
            query_timeout: 60,
            ssl_enabled: true,
            migration: MigrationConfig::default(),
        }
    }
}

/// Migration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Auto-run migrations on startup
    pub auto_migrate: bool,
    
    /// Migration directory
    pub migration_dir: String,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            auto_migrate: false,
            migration_dir: "./migrations".to_string(),
        }
    }
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    
    /// Audit log level
    pub log_level: String,
    
    /// Maximum audit log size in MB
    pub max_log_size_mb: u32,
    
    /// Log retention days
    pub retention_days: u32,
    
    /// Enable real-time alerting
    pub real_time_alerts: bool,
    
    /// Audit storage backend
    pub storage_backend: String,
    
    /// Batch size for bulk operations
    pub batch_size: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: "info".to_string(),
            max_log_size_mb: 100,
            retention_days: 365,
            real_time_alerts: true,
            storage_backend: "database".to_string(),
            batch_size: 1000,
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    
    /// Metrics endpoint
    pub endpoint: String,
    
    /// Collection interval in seconds
    pub collection_interval: u64,
    
    /// Metrics retention days
    pub retention_days: u32,
    
    /// Enable performance monitoring
    pub performance_monitoring: bool,
    
    /// Enable health checks
    pub health_checks: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "/metrics".to_string(),
            collection_interval: 60,
            retention_days: 30,
            performance_monitoring: true,
            health_checks: true,
        }
    }
}

/// Configuration validation result
pub type ConfigResult<T> = Result<T, ConfigError>;

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid configuration: {field} - {message}")]
    Invalid { field: String, message: String },
    
    #[error("Missing required configuration: {field}")]
    Missing { field: String },
    
    #[error("Configuration load error: {source}")]
    LoadError { source: String },
    
    #[error("Configuration validation error: {message}")]
    ValidationError { message: String },
}

impl BrankasConfig {
    /// Validate configuration
    pub fn validate(&self) -> ConfigResult<()> {
        // Validate server configuration
        if self.server.port == 0 {
            return Err(ConfigError::Invalid {
                field: "server.port".to_string(),
                message: "Port must be greater than 0".to_string(),
            });
        }
        
        if self.server.tls_enabled {
            if self.server.tls_cert_path.is_none() {
                return Err(ConfigError::Missing {
                    field: "server.tls_cert_path".to_string(),
                });
            }
            if self.server.tls_key_path.is_none() {
                return Err(ConfigError::Missing {
                    field: "server.tls_key_path".to_string(),
                });
            }
        }
        
        // Validate security configuration
        if self.security.session_timeout == 0 {
            return Err(ConfigError::Invalid {
                field: "security.session_timeout".to_string(),
                message: "Session timeout must be greater than 0".to_string(),
            });
        }
        
        // Validate password policy
        if self.security.password_policy.min_length < 8 {
            return Err(ConfigError::Invalid {
                field: "security.password_policy.min_length".to_string(),
                message: "Minimum password length must be at least 8".to_string(),
            });
        }
        
        // Validate database configuration
        if self.database.url.is_empty() {
            return Err(ConfigError::Missing {
                field: "database.url".to_string(),
            });
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = BrankasConfig::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = BrankasConfig::default();
        config.server.port = 0;
        assert!(config.validate().is_err());
        
        config.server.port = 8443;
        config.security.password_policy.min_length = 4;
        assert!(config.validate().is_err());
    }
}
