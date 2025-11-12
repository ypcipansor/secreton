//! Database secret engine for dynamic credential generation

use crate::error::DatabaseError;
use crate::model::{DatabaseConfig, DatabaseRole, DatabaseType};
use serde_json::Value;
use std::collections::HashMap;

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

    /// Generate database credentials for a role
    pub async fn generate_credentials(
        &self,
        role_name: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        // Get role configuration
        let role = self.roles.get(role_name).ok_or_else(|| {
            DatabaseError::RoleNotFound(format!("Role '{}' not found", role_name))
        })?;

        // Determine database type from connection URL
        let db_type = self.detect_database_type(&self.config.connection_url)?;

        // Generate credentials based on database type
        match db_type {
            DatabaseType::PostgreSQL => {
                self.generate_postgres_credentials(role_name, &role.sql)
                    .await
            }
            DatabaseType::MySQL => self.generate_mysql_credentials(role_name, &role.sql).await,
            DatabaseType::MongoDB => {
                self.generate_mongodb_credentials(role_name, &role.sql)
                    .await
            }
            DatabaseType::Redis => self.generate_redis_credentials(role_name).await,
        }
    }

    /// Generate PostgreSQL credentials
    async fn generate_postgres_credentials(
        &self,
        role_name: &str,
        _role_sql: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let username = self.generate_username();
        let password = self.generate_password();

        // In a real implementation, this would create the user in PostgreSQL
        // For now, just return the generated credentials
        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(username));
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.config.connection_url.clone()),
        );

        Ok(data)
    }

    /// Generate MySQL credentials
    async fn generate_mysql_credentials(
        &self,
        role_name: &str,
        _role_sql: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let username = self.generate_username();
        let password = self.generate_password();

        // In a real implementation, this would create the user in MySQL
        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(username));
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.config.connection_url.clone()),
        );

        Ok(data)
    }

    /// Generate MongoDB credentials
    async fn generate_mongodb_credentials(
        &self,
        role_name: &str,
        _role_sql: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let username = self.generate_username();
        let password = self.generate_password();

        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(username));
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.config.connection_url.clone()),
        );

        Ok(data)
    }

    /// Generate Redis credentials
    async fn generate_redis_credentials(
        &self,
        role_name: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let password = self.generate_password();

        let mut data = HashMap::new();
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.config.connection_url.clone()),
        );

        Ok(data)
    }

    /// Generate a random username
    fn generate_username(&self) -> String {
        use rand::{Rng, distributions::Alphanumeric};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect()
    }

    /// Generate a random password
    fn generate_password(&self) -> String {
        use rand::{Rng, distributions::Alphanumeric};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    /// Detect database type from connection URL
    fn detect_database_type(&self, connection_url: &str) -> Result<DatabaseType, DatabaseError> {
        if connection_url.starts_with("postgresql://") || connection_url.starts_with("postgres://")
        {
            Ok(DatabaseType::PostgreSQL)
        } else if connection_url.starts_with("mysql://") {
            Ok(DatabaseType::MySQL)
        } else if connection_url.starts_with("mongodb://") {
            Ok(DatabaseType::MongoDB)
        } else if connection_url.starts_with("redis://") {
            Ok(DatabaseType::Redis)
        } else {
            Err(DatabaseError::UnsupportedDatabaseType(format!(
                "Unsupported database type in URL: {}",
                connection_url
            )))
        }
    }

    /// Add a database role
    pub fn add_role(&mut self, name: String, role: DatabaseRole) {
        self.roles.insert(name, role);
    }

    /// Remove a database role
    pub fn remove_role(&mut self, name: &str) {
        self.roles.remove(name);
    }

    /// List all roles
    pub fn list_roles(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }

    /// Enable the engine
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the engine
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if engine is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
