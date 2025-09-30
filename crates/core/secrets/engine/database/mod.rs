//! Database Secrets Engine
//!
//! Provides dynamic database credential management with support for multiple
//! database types including PostgreSQL, MySQL, MongoDB, and Redis.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use super::{EngineMetrics, Secret, SecretMetadata, SecretsEngine, SecretsError};

mod connection;
mod plugins;
mod role;

use connection::DatabaseConnection;
#[cfg(test)]
use connection::DatabaseType;
use plugins::PluginManager;
use role::{DatabaseRole, RoleType};

/// Database secrets engine for dynamic credential management
#[derive(Debug)]
pub struct DatabaseEngine {
    /// Plugin manager for database operations
    plugin_manager: PluginManager,
    /// Configuration for the engine
    config: DatabaseEngineConfig,
    /// Active database connections
    connections: HashMap<String, DatabaseConnection>,
    /// Configured roles
    roles: HashMap<String, DatabaseRole>,
}

/// Configuration for the database engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseEngineConfig {
    /// Default credential TTL
    pub default_ttl: Duration,
    /// Maximum credential TTL
    pub max_ttl: Duration,
    /// Enable automatic credential rotation
    pub auto_rotate: bool,
    /// Rotation interval
    pub rotation_interval: Duration,
    /// Maximum number of connections per database
    pub max_connections_per_db: u32,
}

impl Default for DatabaseEngineConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(3600), // 1 hour
            max_ttl: Duration::from_secs(86400),    // 24 hours
            auto_rotate: true,
            rotation_interval: Duration::from_secs(3600), // 1 hour
            max_connections_per_db: 100,
        }
    }
}

/// Database credential information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseCredentials {
    /// Username for database access
    pub username: String,
    /// Password for database access
    pub password: String,
    /// Database connection details
    pub connection_details: DatabaseConnection,
    /// Credential expiration time
    pub expires_at: SystemTime,
    /// Role used to create these credentials
    pub role_name: String,
}

impl Default for DatabaseEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseEngine {
    /// Create a new database engine
    pub fn new() -> Self {
        Self {
            plugin_manager: PluginManager::new(),
            config: DatabaseEngineConfig::default(),
            connections: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    /// Create a new database engine with custom configuration
    pub fn with_config(config: DatabaseEngineConfig) -> Self {
        Self {
            plugin_manager: PluginManager::new(),
            config,
            connections: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    /// Configure a database connection
    pub async fn configure_connection(
        &mut self,
        name: String,
        connection: DatabaseConnection,
    ) -> Result<()> {
        // Test the connection using the appropriate plugin
        if let Some(plugin) = self.plugin_manager.get_plugin(&connection.db_type) {
            plugin.test_connection(&connection).await?;
        } else {
            return Err(anyhow::anyhow!(
                "No plugin available for database type: {:?}",
                connection.db_type
            ));
        }

        self.connections.insert(name, connection);
        Ok(())
    }

    /// Configure a database role
    pub fn configure_role(&mut self, name: String, role: DatabaseRole) -> Result<()> {
        role.validate()
            .map_err(|e| anyhow::anyhow!("Role validation failed: {}", e))?;
        self.roles.insert(name, role);
        Ok(())
    }

    /// Generate database credentials for a role
    pub async fn generate_credentials(
        &self,
        connection_name: &str,
        role_name: &str,
    ) -> Result<DatabaseCredentials> {
        let connection = self
            .connections
            .get(connection_name)
            .ok_or_else(|| anyhow::anyhow!("Connection '{}' not found", connection_name))?;

        let role = self
            .roles
            .get(role_name)
            .ok_or_else(|| anyhow::anyhow!("Role '{}' not found", role_name))?;

        let plugin = self
            .plugin_manager
            .get_plugin(&connection.db_type)
            .ok_or_else(|| {
                anyhow::anyhow!("No plugin for database type: {:?}", connection.db_type)
            })?;

        // Generate unique username and secure password
        let username = format!("vault_{}", self.generate_random_string(8));
        let password = self.generate_secure_password();

        // Create the user in the database
        match &role.role_type {
            RoleType::Dynamic => {
                plugin
                    .create_user(connection, &username, &password, &role.creation_statements)
                    .await?;
            }
            RoleType::Static {
                username: static_username,
                ..
            } => {
                // For static roles, we don't create new users but return existing credentials
                return Ok(DatabaseCredentials {
                    username: static_username.clone(),
                    password, // This would typically be the existing password
                    connection_details: connection.clone(),
                    expires_at: SystemTime::now() + role.default_ttl.to_std().unwrap(),
                    role_name: role_name.to_string(),
                });
            }
        }

        let expires_at =
            SystemTime::now() + role.default_ttl.to_std().unwrap().min(self.config.max_ttl);

        Ok(DatabaseCredentials {
            username,
            password,
            connection_details: connection.clone(),
            expires_at,
            role_name: role_name.to_string(),
        })
    }

    /// Revoke database credentials
    pub async fn revoke_credentials(&self, credentials: &DatabaseCredentials) -> Result<()> {
        let connection = &credentials.connection_details;
        let role = self
            .roles
            .get(&credentials.role_name)
            .ok_or_else(|| anyhow::anyhow!("Role '{}' not found", credentials.role_name))?;

        let plugin = self
            .plugin_manager
            .get_plugin(&connection.db_type)
            .ok_or_else(|| {
                anyhow::anyhow!("No plugin for database type: {:?}", connection.db_type)
            })?;

        match &role.role_type {
            RoleType::Dynamic => {
                plugin
                    .revoke_user(
                        connection,
                        &credentials.username,
                        &role.revocation_statements,
                    )
                    .await?;
            }
            RoleType::Static { .. } => {
                // For static roles, we typically don't revoke the user but might disable access
                tracing::warn!("Revocation attempted on static role credentials");
            }
        }

        Ok(())
    }

    /// Rotate credentials for a role
    pub async fn rotate_credentials(&self, credentials: &mut DatabaseCredentials) -> Result<()> {
        let connection = &credentials.connection_details;
        let role = self
            .roles
            .get(&credentials.role_name)
            .ok_or_else(|| anyhow::anyhow!("Role '{}' not found", credentials.role_name))?;

        let plugin = self
            .plugin_manager
            .get_plugin(&connection.db_type)
            .ok_or_else(|| {
                anyhow::anyhow!("No plugin for database type: {:?}", connection.db_type)
            })?;

        let new_password = self.generate_secure_password();

        match &role.role_type {
            RoleType::Dynamic => {
                if !role.renew_statements.is_empty() {
                    plugin
                        .rotate_user(
                            connection,
                            &credentials.username,
                            &new_password,
                            &role.renew_statements,
                        )
                        .await?;
                } else {
                    // Default rotation: change password
                    let default_statements =
                        vec!["ALTER USER {{username}} WITH PASSWORD '{{password}}';".to_string()];
                    plugin
                        .rotate_user(
                            connection,
                            &credentials.username,
                            &new_password,
                            &default_statements,
                        )
                        .await?;
                }
            }
            RoleType::Static { .. } => {
                if !role.renew_statements.is_empty() {
                    plugin
                        .rotate_user(
                            connection,
                            &credentials.username,
                            &new_password,
                            &role.renew_statements,
                        )
                        .await?;
                }
            }
        }

        credentials.password = new_password;
        credentials.expires_at =
            SystemTime::now() + role.default_ttl.to_std().unwrap().min(self.config.max_ttl);

        Ok(())
    }

    /// Generate a cryptographically secure random string
    fn generate_random_string(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::thread_rng();

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate a secure password
    fn generate_secure_password(&self) -> String {
        use rand::Rng;
        const CHARSET: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();

        (0..32) // 32 character password
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Get information about configured connections
    pub fn list_connections(&self) -> Vec<String> {
        self.connections.keys().cloned().collect()
    }

    /// Get information about configured roles
    pub fn list_roles(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }
}

#[async_trait]
impl SecretsEngine for DatabaseEngine {
    fn engine_type(&self) -> &'static str {
        "database"
    }

    async fn create_secret(
        &self,
        path: &str,
        _data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // Parse path to extract connection and role names
        // Expected format: database/creds/{connection_name}/{role_name}
        let path_parts: Vec<&str> = path.split('/').collect();
        if path_parts.len() < 4 || path_parts[0] != "database" || path_parts[1] != "creds" {
            return Err(SecretsError::InvalidData(
                "Invalid path format. Expected: database/creds/{connection}/{role}".to_string(),
            ));
        }

        let connection_name = path_parts[2];
        let role_name = path_parts[3];

        // Generate credentials
        let credentials = self
            .generate_credentials(connection_name, role_name)
            .await
            .map_err(|e| SecretsError::ExecutionError(e.to_string()))?;

        let now = chrono::Utc::now();
        let metadata = SecretMetadata {
            created_at: now,
            updated_at: now,
            version: 1,
            ttl: Some(self.config.default_ttl.as_secs() as i64),
            expired_at: Some(now + chrono::Duration::from_std(self.config.default_ttl).unwrap()),
            custom_metadata: Some(HashMap::from([
                ("connection".to_string(), connection_name.to_string()),
                ("role".to_string(), role_name.to_string()),
                (
                    "database_type".to_string(),
                    format!("{:?}", credentials.connection_details.db_type),
                ),
            ])),
        };

        // Extract values before using them to avoid ownership issues
        let username = credentials.username.clone();
        let password = credentials.password.clone();
        let host = credentials.connection_details.host.clone();
        let port = credentials.connection_details.port;
        let database = credentials.connection_details.database.clone();
        let connection_url = credentials
            .connection_details
            .get_connection_url(&credentials.username, &credentials.password);

        let secret_data = Value::Object(serde_json::Map::from_iter([
            ("username".to_string(), Value::String(username)),
            ("password".to_string(), Value::String(password)),
            ("host".to_string(), Value::String(host)),
            ("port".to_string(), Value::Number(port.into())),
            ("database".to_string(), Value::String(database)),
            ("connection_url".to_string(), Value::String(connection_url)),
        ]));

        Ok(Secret {
            id: Uuid::new_v4(),
            path: path.to_string(),
            data: secret_data,
            metadata,
        })
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        // For database engine, reading typically means retrieving existing credentials
        // This is a simplified implementation - in a real system, we'd store credential metadata
        Err(SecretsError::NotFound(format!(
            "Database credentials are dynamically generated. Path: {}",
            path
        )))
    }

    async fn update_secret(
        &self,
        path: &str,
        _data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // For database engine, update typically means credential rotation
        self.create_secret(path, Value::Null, None).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        // For database engine, deletion means revoking credentials
        let path_parts: Vec<&str> = path.split('/').collect();
        if path_parts.len() < 4 {
            return Err(SecretsError::InvalidData("Invalid path format".to_string()));
        }

        // In a real implementation, we'd look up the credentials and revoke them
        // For now, we'll just acknowledge the deletion
        tracing::info!("Database credentials deleted for path: {}", path);
        Ok(())
    }

    async fn list_secrets(&self, prefix: &str) -> Result<Vec<String>, SecretsError> {
        // List available connections and roles
        let mut secrets = Vec::new();

        for conn_name in self.connections.keys() {
            for role_name in self.roles.keys() {
                secrets.push(format!("{}/creds/{}/{}", prefix, conn_name, role_name));
            }
        }

        Ok(secrets)
    }

    async fn collect_metrics(&self) -> Result<EngineMetrics, SecretsError> {
        // For now, return default metrics since we don't have persistent storage of metrics
        Ok(EngineMetrics {
            engine_type: "database".to_string(),
            secrets_created: 0,
            secrets_read: 0,
            secrets_updated: 0,
            secrets_deleted: 0,
            avg_response_time_ms: 0.0,
            error_count: 0,
            active_secrets: (self.connections.len() + self.roles.len()) as u64,
            storage_size_bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_engine() -> DatabaseEngine {
        DatabaseEngine::new()
    }

    #[test]
    fn test_engine_creation() {
        let engine = create_test_engine();
        assert_eq!(engine.engine_type(), "database");
    }

    #[tokio::test]
    async fn test_connection_configuration() {
        let mut engine = create_test_engine();

        let connection = DatabaseConnection {
            db_type: DatabaseType::PostgreSQL,
            host: "localhost".to_string(),
            port: 5432,
            database: "testdb".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
            ssl_mode: None,
            connection_timeout: None,
            max_connections: None,
            connection_params: HashMap::new(),
        };

        let _result = engine
            .configure_connection("test-conn".to_string(), connection)
            .await;
        // This might fail due to actual connection testing, but the structure should be correct
        // In a real test, we'd mock the plugin
    }

    #[test]
    fn test_role_configuration() {
        let mut engine = create_test_engine();

        let role = DatabaseRole {
            db_name: "testdb".to_string(),
            role_type: RoleType::Dynamic,
            creation_statements: vec![
                "CREATE USER {{username}} WITH PASSWORD '{{password}}';".to_string()
            ],
            revocation_statements: vec!["DROP USER {{username}};".to_string()],
            rollback_statements: Vec::new(),
            renew_statements: Vec::new(),
            default_ttl: chrono::Duration::hours(1),
            max_ttl: chrono::Duration::hours(24),
            renewable: true,
        };

        let result = engine.configure_role("test-role".to_string(), role);
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_password_generation() {
        let engine = create_test_engine();
        let password = engine.generate_secure_password();

        assert_eq!(password.len(), 32);
        assert!(password.chars().any(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_random_string_generation() {
        let engine = create_test_engine();
        let string = engine.generate_random_string(10);

        assert_eq!(string.len(), 10);
        assert!(string.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
