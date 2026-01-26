//! Database secret engine for dynamic credential generation

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
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

/// Database engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseEngineConfig {
    pub connection_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub database_name: Option<String>,
    pub max_open_connections: Option<u32>,
    pub max_idle_connections: Option<u32>,
    pub connection_timeout: Option<u64>,
    #[serde(default)]
    pub verify_connection: bool,
}

impl Default for DatabaseEngineConfig {
    fn default() -> Self {
        Self {
            connection_url: String::new(),
            username: None,
            password: None,
            database_name: None,
            max_open_connections: Some(10),
            max_idle_connections: Some(5),
            connection_timeout: Some(30),
            verify_connection: true,
        }
    }
}

/// Database secret engine for dynamic credentials
pub struct DatabaseEngine {
    config: DatabaseEngineConfig,
    enabled: bool,
    roles: HashMap<String, DatabaseRole>,
    backend: Option<Box<dyn crate::backend::database::DatabaseBackend + Send + Sync>>,
}

impl DatabaseEngine {
    pub fn new(config: DatabaseEngineConfig) -> Self {
        Self {
            config,
            enabled: false,
            roles: HashMap::new(),
            backend: None,
        }
    }

    /// Generate database credentials
    async fn generate_credentials(&self, role_name: &str) -> SecretResult<HashMap<String, Value>> {
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
    async fn init_backend(&mut self) -> SecretResult<()> {
        let db_type = self.detect_database_type(&self.config.connection_url)?;

        match db_type {
            DatabaseType::PostgreSQL => {
                let backend = crate::backend::database::postgres::PostgresBackend::new(
                    self.config.connection_url.clone(),
                )?;
                self.backend = Some(Box::new(backend));
                Ok(())
            }
            DatabaseType::MySQL => {
                let backend = crate::backend::database::mysql::MysqlBackend::new(
                    self.config.connection_url.clone(),
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
        if let Some(db_config) = config.config.get("database") {
             match serde_json::from_value::<DatabaseEngineConfig>(db_config.clone()) {
                 Ok(cfg) => {
                     self.config = cfg;
                     // Initialize backend
                     if config.enabled {
                         self.init_backend().await?;
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
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}
