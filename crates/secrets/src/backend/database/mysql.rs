//! MySQL database backend

use std::collections::HashMap;
use serde_json::Value;
use crate::error::*;
use mysql_async::prelude::*;

/// MySQL database backend
pub struct MysqlBackend {
    connection_string: String,
}

impl MysqlBackend {
    pub fn new(connection_string: String) -> Self {
        Self { connection_string }
    }

    /// Test connection to MySQL
    pub async fn test_connection(&self) -> SecretResult<()> {
        let opts = mysql_async::Opts::from_url(&self.connection_string)
            .map_err(|e| SecretError::InvalidConfiguration(format!("Invalid MySQL connection string: {}", e)))?;
        let pool = mysql_async::Pool::new(opts);
        let mut conn = pool.get_conn().await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to connect to MySQL: {}", e)))?;

        // Test with a simple query
        conn.query_drop("SELECT 1").await
            .map_err(|e| SecretError::InvalidConfiguration(format!("MySQL connection test failed: {}", e)))?;

        pool.disconnect().await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to disconnect from MySQL: {}", e)))?;

        Ok(())
    }

    /// Create a database user with specified privileges
    pub async fn create_user(&self, username: &str, password: &str, role_sql: &str) -> SecretResult<()> {
        let opts = mysql_async::Opts::from_url(&self.connection_string)
            .map_err(|e| SecretError::InvalidConfiguration(format!("Invalid MySQL connection string: {}", e)))?;
        let pool = mysql_async::Pool::new(opts);
        let mut conn = pool.get_conn().await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to connect to MySQL: {}", e)))?;

        // Create the user
        let create_user_sql = format!("CREATE USER '{}'@'%' IDENTIFIED BY '{}'", username, password);
        conn.query_drop(&create_user_sql).await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to create user: {}", e)))?;

        // Execute role SQL if provided
        if !role_sql.is_empty() {
            conn.query_drop(role_sql).await
                .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to execute role SQL: {}", e)))?;
        }

        pool.disconnect().await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to disconnect from MySQL: {}", e)))?;

        Ok(())
    }

    /// Revoke database user
    pub async fn revoke_user(&self, username: &str) -> SecretResult<()> {
        let opts = mysql_async::Opts::from_url(&self.connection_string)
            .map_err(|e| SecretError::InvalidConfiguration(format!("Invalid MySQL connection string: {}", e)))?;
        let pool = mysql_async::Pool::new(opts);
        let mut conn = pool.get_conn().await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to connect to MySQL: {}", e)))?;

        // Drop the user
        let drop_user_sql = format!("DROP USER IF EXISTS '{}'@'%'", username);
        conn.query_drop(&drop_user_sql).await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to revoke user: {}", e)))?;

        pool.disconnect().await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to disconnect from MySQL: {}", e)))?;

        Ok(())
    }

    /// Generate dynamic credentials
    pub async fn generate_credentials(&self, role_name: &str, role_sql: &str) -> SecretResult<HashMap<String, Value>> {
        // Generate random credentials
        use rand::{distributions::Alphanumeric, Rng};
        let username: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        let password: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Create the user in MySQL
        self.create_user(&username, &password, role_sql).await?;

        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(username));
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));

        Ok(data)
    }
}
