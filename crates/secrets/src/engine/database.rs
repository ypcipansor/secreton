//! Database secret engine for dynamic credential generation

use async_trait::async_trait;
use std::collections::HashMap;
use serde_json::Value;
use crate::model::*;
use crate::error::*;
use crate::service::*;

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
}

impl DatabaseEngine {
    pub fn new(config: DatabaseConfig) -> Self {
        Self {
            config,
            enabled: false,
            roles: HashMap::new(),
        }
    }

    /// Generate database credentials
    async fn generate_credentials(&self, role_name: &str) -> SecretResult<HashMap<String, Value>> {
        // Get role configuration
        let role = self.roles.get(role_name)
            .ok_or_else(|| SecretError::InvalidConfiguration(format!("Role '{}' not found", role_name)))?;

        // Generate random username and password using shared utility
        let _password = secreton_common::generate_password()?;

        // Generate random username
        use rand::{distributions::Alphanumeric, Rng};
        let _username: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        // Determine database type from connection URL
        let db_type = self.detect_database_type(&self.config.connection_url)?;

        // Create appropriate backend and generate credentials
        match db_type {
            DatabaseType::PostgreSQL => {
                let backend = crate::backend::database::postgres::PostgresBackend::new(
                    self.config.connection_url.clone()
                );
                backend.generate_credentials(role_name, &role.sql).await
            }
            DatabaseType::MySQL => {
                let backend = crate::backend::database::mysql::MysqlBackend::new(
                    self.config.connection_url.clone()
                );
                backend.generate_credentials(role_name, &role.sql).await
            }
            DatabaseType::MongoDB => {
                let backend = crate::backend::database::mongodb::MongodbBackend::new(
                    self.config.connection_url.clone()
                );
                backend.generate_credentials(role_name, &role.sql).await
            }
        }
    }

    /// Detect database type from connection URL
    fn detect_database_type(&self, connection_url: &str) -> SecretResult<DatabaseType> {
        if connection_url.starts_with("postgresql://") || connection_url.starts_with("postgres://") {
            Ok(DatabaseType::PostgreSQL)
        } else if connection_url.starts_with("mysql://") {
            Ok(DatabaseType::MySQL)
        } else if connection_url.starts_with("mongodb://") {
            Ok(DatabaseType::MongoDB)
        } else {
            Err(SecretError::InvalidConfiguration(format!("Unsupported database type in URL: {}", connection_url)))
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
            if let Ok(db_config) = serde_json::from_value(db_config.clone()) {
                self.config = db_config;
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
        if path.starts_with("creds/") {
            let role_name = &path[6..]; // Remove "creds/" prefix

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
        if path.starts_with("roles/") {
            let role_name = &path[6..]; // Remove "roles/" prefix

            let sql = data.get("sql")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SecretError::InvalidConfiguration("Missing SQL for role".to_string()))?;

            let max_ttl = data.get("max_ttl")
                .and_then(|v| v.as_u64())
                .unwrap_or(86400); // 24 hours default

            let default_ttl = data.get("default_ttl")
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
            Err(SecretError::InvalidConfiguration("Invalid database path".to_string()))
        }
    }

    async fn delete(&mut self, path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        if path.starts_with("roles/") {
            let role_name = &path[6..]; // Remove "roles/" prefix
            self.roles.remove(role_name);
            Ok(())
        } else {
            Err(SecretError::InvalidConfiguration("Invalid database path".to_string()))
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