//! MySQL database backend

use crate::backend::database::DatabaseBackend;
use crate::error::*;
use crate::model::DatabaseConfig;
use async_trait::async_trait;
use mysql_async::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use serde_json::Value;
use std::collections::HashMap;

/// MySQL database backend
pub struct MysqlBackend {
    pool: mysql_async::Pool,
}

impl MysqlBackend {
    pub fn new(config: DatabaseConfig) -> SecretResult<Self> {
        let opts = mysql_async::Opts::from_url(&config.connection_url).map_err(|e| {
            SecretError::InvalidConfiguration(format!("Invalid MySQL connection string: {}", e))
        })?;

        let mut builder = mysql_async::OptsBuilder::from_opts(opts);

        // Apply pool configuration
        if let Some(max_open) = config.max_open_connections {
            // MysqlAsync opts sets pool limits via pool_opts method
            // PoolConstraints is usually in mysql_async
            let min = std::cmp::min(5, max_open as usize);
            let constraints = mysql_async::PoolConstraints::new(min, max_open as usize).unwrap_or_default();
            builder = builder.pool_opts(
                mysql_async::PoolOpts::default().with_constraints(constraints)
            );
        }

        let pool = mysql_async::Pool::new(builder);
        Ok(Self { pool })
    }

    /// Generate a random username
    fn generate_username(&self) -> String {
        let suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        format!("v_{}", suffix.to_lowercase())
    }

    /// Generate a random password
    fn generate_password(&self) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }
}

#[async_trait]
impl DatabaseBackend for MysqlBackend {
    async fn generate_credentials(
        &self,
        role_name: &str,
        role_sql: &str,
    ) -> SecretResult<HashMap<String, Value>> {
        let mut conn = self.pool.get_conn().await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to get connection to MySQL: {}", e))
        })?;

        let username = self.generate_username();
        let password = self.generate_password();

        // 1. Create the user
        // Note: MySQL requires 'username'@'host' format
        let create_user_sql = format!(
            "CREATE USER '{}'@'%' IDENTIFIED BY '{}'",
            username, password
        );

        conn.query_drop(&create_user_sql).await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to create user: {}", e))
        })?;

        // 2. Execute role SQL with template substitution
        let sql = role_sql
            .replace("{{username}}", &username)
            .replace("{{password}}", &password)
            .replace("{{name}}", &username);

        // Handle multiple statements by splitting on ';'
        // This is a naive implementation but provides basic support for multi-statement SQL
        // like GRANT x; FLUSH PRIVILEGES;
        let statements: Vec<&str> = sql
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        for statement in statements {
            if let Err(e) = conn.query_drop(statement).await {
                // Attempt cleanup if role execution fails
                let _ = conn.query_drop(&format!("DROP USER IF EXISTS '{}'@'%'", username)).await;

                return Err(SecretError::BackendOperationFailed(format!(
                    "Failed to execute role SQL statement '{}': {}",
                    statement, e
                )));
            }
        }

        let mut result = HashMap::new();
        result.insert("username".to_string(), Value::String(username));
        result.insert("password".to_string(), Value::String(password));
        result.insert("role".to_string(), Value::String(role_name.to_string()));

        Ok(result)
    }

    async fn test_connection(&self) -> SecretResult<()> {
        let mut conn = self.pool.get_conn().await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to get connection to MySQL: {}", e))
        })?;

        conn.query_drop("SELECT 1").await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("MySQL connection test failed: {}", e))
        })?;

        Ok(())
    }

    async fn revoke_credentials(&self, username: &str) -> SecretResult<()> {
        let mut conn = self.pool.get_conn().await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to get connection to MySQL: {}", e))
        })?;

        // Sanitize username
        if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(SecretError::InvalidOperation("Invalid username format".to_string()));
        }

        let drop_user_sql = format!("DROP USER IF EXISTS '{}'@'%'", username);

        conn.query_drop(&drop_user_sql).await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to revoke user: {}", e))
        })?;

        Ok(())
    }
}
