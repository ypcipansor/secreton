//! Database secret engine for dynamic credential generation

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

/// Database type
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MongoDB,
}

/// Database role configuration
#[derive(Debug, Clone)]
pub struct DatabaseRole {
    pub sql: String,
    pub max_ttl: u64,
    pub default_ttl: u64,
}

/// Database secret engine for dynamic credentials
pub struct DatabaseEngine {
    config: DatabaseConfig,
    enabled: bool,
    roles: HashMap<String, DatabaseRole>,
    backend: Option<Box<dyn crate::backend::database::DatabaseBackend + Send + Sync>>,
}

impl DatabaseEngine {
    // Default configuration to use before initialization
    #[allow(dead_code)]
    fn default_config() -> DatabaseConfig {
        DatabaseConfig {
            plugin_name: "database".to_string(),
            connection_url: String::new(),
            allowed_roles: Vec::new(),
            username: None,
            password: None,
            max_open_connections: Some(10),
            max_idle_connections: Some(5),
            max_connection_lifetime: Some(30),
        }
    }

    pub fn new(config: DatabaseConfig) -> Self {
        Self {
            config,
            enabled: false,
            roles: HashMap::new(),
            backend: None,
        }
    }

    /// Generate database credentials
    async fn generate_credentials(&self, role_name: &str) -> SecretResult<HashMap<String, Value>> {
        // Enforce allowed_roles if configured
        if !self.config.allowed_roles.is_empty() {
            if !self.config.allowed_roles.contains(&role_name.to_string()) {
                return Err(SecretError::InvalidConfiguration(format!(
                    "Role '{}' is not in the allowed_roles list",
                    role_name
                )));
            }
        }

        // Get role configuration
        let role = self.roles.get(role_name).ok_or_else(|| {
            SecretError::InvalidConfiguration(format!("Role '{}' not found", role_name))
        })?;

        if let Some(backend) = &self.backend {
            backend.generate_credentials(role_name, &role.sql).await
        } else {
            Err(SecretError::InvalidConfiguration("Database backend not initialized".to_string()))
        }
    }

    /// Detect database type from connection URL
    fn detect_database_type(&self, connection_url: &str) -> SecretResult<DatabaseType> {
        if connection_url.starts_with("postgresql://") || connection_url.starts_with("postgres://")
        {
            Ok(DatabaseType::PostgreSQL)
        } else if connection_url.starts_with("mysql://") {
            Ok(DatabaseType::MySQL)
        } else if connection_url.starts_with("mongodb://") {
            Ok(DatabaseType::MongoDB)
        } else {
            Err(SecretError::InvalidConfiguration(format!(
                "Unsupported database type in URL: {}",
                connection_url
            )))
        }
    }

    /// Initialize the backend based on configuration
    /// This is now synchronous to allow lazy initialization in enable()
    fn init_backend(&mut self) -> SecretResult<()> {
        let db_type = self.detect_database_type(&self.config.connection_url)?;

        match db_type {
            DatabaseType::PostgreSQL => {
                let backend = crate::backend::database::postgres::PostgresBackend::new(
                    self.config.clone(),
                )?;
                self.backend = Some(Box::new(backend));
                Ok(())
            }
            DatabaseType::MySQL => {
                let backend = crate::backend::database::mysql::MysqlBackend::new(
                    self.config.clone(),
                )?;
                self.backend = Some(Box::new(backend));
                Ok(())
            }
            DatabaseType::MongoDB => {
                Err(SecretError::NotImplemented("MongoDB backend not fully implemented".to_string()))
            }
        }
    }
}

#[async_trait]
impl SecretEngine for DatabaseEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Database
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        let db_config_value = config.config.get("database");

        if config.enabled && db_config_value.is_none() {
            return Err(SecretError::InvalidConfiguration(
                "Database configuration missing for enabled engine".to_string()
            ));
        }

        if let Some(db_config) = db_config_value {
             match serde_json::from_value::<DatabaseConfig>(db_config.clone()) {
                 Ok(cfg) => {
                     self.config = cfg;
                     // Validate connection URL regardless of enabled state
                     self.detect_database_type(&self.config.connection_url)?;

                     // Initialize backend only if enabled to avoid wasteful resource allocation
                     if config.enabled {
                         self.init_backend()?;
                     }
                 },
                 Err(e) => return Err(SecretError::InvalidConfiguration(format!("Invalid database configuration: {}", e)))
             }
        }

        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        // Database engine generates credentials on demand
        // Reading a role generates new credentials
        if let Some(role_name) = path.strip_prefix("creds/") {
            let data = self.generate_credentials(role_name).await?;

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data,
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "system".to_string(),
                    updated_by: "system".to_string(),
                    lease_id: Some(uuid::Uuid::new_v4().to_string()),
                    lease_duration: Some(3600), // 1 hour default
                    tags: HashMap::new(),
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        // Handle role creation
        if let Some(role_name) = path.strip_prefix("roles/") {
            let sql = data.get("sql").and_then(|v| v.as_str()).ok_or_else(|| {
                SecretError::InvalidConfiguration("Missing SQL for role".to_string())
            })?;

            let max_ttl = data
                .get("max_ttl")
                .and_then(|v| v.as_u64())
                .unwrap_or(86400); // 24 hours default

            let default_ttl = data
                .get("default_ttl")
                .and_then(|v| v.as_u64())
                .unwrap_or(3600); // 1 hour default

            // Store role configuration
            let role = DatabaseRole {
                sql: sql.to_string(),
                max_ttl,
                default_ttl,
            };

            // Store the role (this would typically be persisted to storage)
            self.roles.insert(role_name.to_string(), role);

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data: HashMap::new(), // Don't expose sensitive role data
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "system".to_string(),
                    updated_by: "system".to_string(),
                    lease_id: None,
                    lease_duration: None,
                    tags: HashMap::new(),
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            Ok(secret)
        } else {
            Err(SecretError::InvalidConfiguration(
                "Invalid database path".to_string(),
            ))
        }
    }

    async fn delete(&mut self, path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        if let Some(role_name) = path.strip_prefix("roles/") {
            self.roles.remove(role_name);
            Ok(())
        } else {
            Err(SecretError::InvalidConfiguration(
                "Invalid database path".to_string(),
            ))
        }
    }

    async fn list(&self, path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        if path == "roles" || path == "roles/" {
            // Return list of role names
            Ok(self.roles.keys().cloned().collect())
        } else {
            Ok(vec![])
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
        // Lazily initialize backend if needed
        if self.backend.is_none() && !self.config.connection_url.is_empty() {
            if let Err(e) = self.init_backend() {
                // Since enable() cannot return result, we log the error
                // The backend will remain None, and subsequent calls will fail gracefully
                eprintln!("Failed to initialize database backend during enable: {}", e);
            }
        }
    }

    fn disable(&mut self) {
        self.enabled = false;
        // Optionally release backend resources?
        // self.backend = None;
        // Keeping it might be better for re-enable performance, but dropping it saves resources.
        // Given the Bug 1 concern about "wasteful resource allocation", dropping it makes sense?
        // But pooling libraries handle idle connections well.
        // Let's keep it to avoid thrashing if toggled often.
    }
}
