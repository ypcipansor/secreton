//! Database Configuration Types
//! 
//! Defines configuration structures for database connections
//! and related settings.

use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::error::SecretonError;

/// Database connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database plugin name (e.g., "postgresql-database-plugin")
    pub plugin_name: String,

    /// Database connection URL
    pub connection_url: String,

    /// Database username for Vault connections
    pub username: Option<String>,

    /// Database password for Vault connections
    pub password: Option<String>,

    /// Maximum number of open connections
    pub max_open_connections: Option<i32>,

    /// Maximum number of idle connections
    pub max_idle_connections: Option<i32>,

    /// Maximum connection lifetime
    pub max_connection_lifetime: Option<Duration>,

    /// List of roles allowed to use this connection
    pub allowed_roles: Vec<String>,

    /// SQL statements for rotating root credentials
    pub root_rotation_statements: Vec<String>,

    /// Password policy name for generated passwords
    pub password_policy: Option<String>,
}

impl DatabaseConfig {
    /// Validate database configuration
    pub fn validate(&self) -> Result<(), SecretonError> {
        if self.plugin_name.is_empty() {
            return Err(SecretonError::InvalidInput(
                "Plugin name cannot be empty".to_string()
            ));
        }

        if self.connection_url.is_empty() {
            return Err(SecretonError::InvalidInput(
                "Connection URL cannot be empty".to_string()
            ));
        }

        // Validate connection limits
        if let Some(max_open) = self.max_open_connections {
            if max_open <= 0 {
                return Err(SecretonError::InvalidInput(
                    "Max open connections must be positive".to_string()
                ));
            }
        }

        if let Some(max_idle) = self.max_idle_connections {
            if max_idle < 0 {
                return Err(SecretonError::InvalidInput(
                    "Max idle connections cannot be negative".to_string()
                ));
            }
        }

        // Validate that max_idle <= max_open if both are specified
        if let (Some(max_open), Some(max_idle)) = (self.max_open_connections, self.max_idle_connections) {
            if max_idle > max_open {
                return Err(SecretonError::InvalidInput(
                    "Max idle connections cannot exceed max open connections".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Get effective max open connections (default: 4)
    pub fn effective_max_open_connections(&self) -> i32 {
        self.max_open_connections.unwrap_or(4)
    }

    /// Get effective max idle connections (default: 0)
    pub fn effective_max_idle_connections(&self) -> i32 {
        self.max_idle_connections.unwrap_or(0)
    }

    /// Get effective connection lifetime (default: 0 = no limit)
    pub fn effective_connection_lifetime(&self) -> Duration {
        self.max_connection_lifetime.unwrap_or(Duration::from_secs(0))
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            plugin_name: String::new(),
            connection_url: String::new(),
            username: None,
            password: None,
            max_open_connections: Some(4),
            max_idle_connections: Some(0),
            max_connection_lifetime: Some(Duration::from_secs(0)),
            allowed_roles: Vec::new(),
            root_rotation_statements: Vec::new(),
            password_policy: None,
        }
    }
}

/// Database connection wrapper
#[derive(Debug, Clone)]
pub struct DatabaseConnection {
    name: String,
    config: DatabaseConfig,
    // In production, would contain actual database connection pool
    created_at: std::time::SystemTime,
}

impl DatabaseConnection {
    /// Create database connection from configuration
    pub async fn from_config(name: String, config: DatabaseConfig) -> Result<Self, SecretonError> {
        config.validate()?;

        Ok(Self {
            name,
            config,
            created_at: std::time::SystemTime::now(),
        })
    }

    /// Get connection name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get connection configuration
    pub fn config(&self) -> &DatabaseConfig {
        &self.config
    }

    /// Get connection creation time
    pub fn created_at(&self) -> std::time::SystemTime {
        self.created_at
    }

    /// Check if connection is expired (based on lifetime setting)
    pub fn is_expired(&self) -> bool {
        if self.config.effective_connection_lifetime().as_secs() == 0 {
            return false; // No expiration
        }

        match self.created_at.elapsed() {
            Ok(elapsed) => elapsed > self.config.effective_connection_lifetime(),
            Err(_) => true, // Clock issues, consider expired
        }
    }
}

/// TLS Configuration for database connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,

    /// TLS CA certificate
    pub ca_cert: Option<String>,

    /// TLS client certificate
    pub client_cert: Option<String>,

    /// TLS client private key
    pub client_key: Option<String>,

    /// Server name for TLS verification
    pub server_name: Option<String>,

    /// Skip TLS verification (insecure)
    pub insecure_skip_verify: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            server_name: None,
            insecure_skip_verify: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config_validation() {
        let mut config = DatabaseConfig::default();
        
        // Empty plugin name should fail
        assert!(config.validate().is_err());
        
        config.plugin_name = "postgresql-database-plugin".to_string();
        // Empty connection URL should fail
        assert!(config.validate().is_err());
        
        config.connection_url = "postgresql://localhost:5432/test".to_string();
        // Valid config should pass
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_connection_limits_validation() {
        let mut config = DatabaseConfig::default();
        config.plugin_name = "test-plugin".to_string();
        config.connection_url = "test://localhost".to_string();
        
        // Invalid max open connections
        config.max_open_connections = Some(0);
        assert!(config.validate().is_err());
        
        config.max_open_connections = Some(-1);
        assert!(config.validate().is_err());
        
        // Invalid max idle connections
        config.max_open_connections = Some(10);
        config.max_idle_connections = Some(-1);
        assert!(config.validate().is_err());
        
        // max_idle > max_open
        config.max_idle_connections = Some(15);
        assert!(config.validate().is_err());
        
        // Valid configuration
        config.max_idle_connections = Some(5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_effective_values() {
        let config = DatabaseConfig::default();
        
        assert_eq!(config.effective_max_open_connections(), 4);
        assert_eq!(config.effective_max_idle_connections(), 0);
        assert_eq!(config.effective_connection_lifetime(), Duration::from_secs(0));
    }

    #[tokio::test]
    async fn test_database_connection_creation() {
        let config = DatabaseConfig {
            plugin_name: "postgresql-database-plugin".to_string(),
            connection_url: "postgresql://localhost:5432/test".to_string(),
            username: Some("test".to_string()),
            password: Some("test".to_string()),
            ..Default::default()
        };
        
        let connection = DatabaseConnection::from_config("test-db".to_string(), config).await.unwrap();
        
        assert_eq!(connection.name(), "test-db");
        assert_eq!(connection.config().plugin_name, "postgresql-database-plugin");
        assert!(!connection.is_expired()); // Should not be expired immediately
    }

    #[test]
    fn test_connection_expiration() {
        let config = DatabaseConfig {
            plugin_name: "test-plugin".to_string(),
            connection_url: "test://localhost".to_string(),
            max_connection_lifetime: Some(Duration::from_millis(1)),
            ..Default::default()
        };
        
        let connection = DatabaseConnection {
            name: "test".to_string(),
            config,
            created_at: std::time::SystemTime::now() - Duration::from_millis(10),
        };
        
        assert!(connection.is_expired());
    }
}
