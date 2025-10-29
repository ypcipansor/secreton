//! PostgreSQL database backend

use std::collections::HashMap;
use serde_json::Value;
use crate::error::*;

/// PostgreSQL database backend
pub struct PostgresBackend {
    connection_string: String,
}

impl PostgresBackend {
    pub fn new(connection_string: String) -> Self {
        Self { connection_string }
    }

    /// Test connection to PostgreSQL
    pub async fn test_connection(&self) -> SecretResult<()> {
        let (client, connection) = tokio_postgres::connect(&self.connection_string, tokio_postgres::NoTls)
            .await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to connect to PostgreSQL: {}", e)))?;

        // Spawn the connection to run in background
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("PostgreSQL connection error: {}", e);
            }
        });

        // Test with a simple query
        client.execute("SELECT 1", &[]).await
            .map_err(|e| SecretError::InvalidConfiguration(format!("PostgreSQL connection test failed: {}", e)))?;

        Ok(())
    }

    /// Create a database user with specified privileges
    pub async fn create_user(&self, username: &str, password: &str, role_sql: &str) -> SecretResult<()> {
        let (client, connection) = tokio_postgres::connect(&self.connection_string, tokio_postgres::NoTls)
            .await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to connect to PostgreSQL: {}", e)))?;

        // Spawn the connection to run in background
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("PostgreSQL connection error: {}", e);
            }
        });

        // Create the user
        let create_user_sql = format!("CREATE USER \"{}\" PASSWORD '{}'", username, password);
        client.execute(&create_user_sql, &[]).await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to create user: {}", e)))?;

        // Execute role SQL if provided
        if !role_sql.is_empty() {
            client.execute(role_sql, &[]).await
                .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to execute role SQL: {}", e)))?;
        }

        Ok(())
    }

    /// Revoke database user
    pub async fn revoke_user(&self, username: &str) -> SecretResult<()> {
        let (client, connection) = tokio_postgres::connect(&self.connection_string, tokio_postgres::NoTls)
            .await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to connect to PostgreSQL: {}", e)))?;

        // Spawn the connection to run in background
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("PostgreSQL connection error: {}", e);
            }
        });

        // Drop the user
        let drop_user_sql = format!("DROP USER IF EXISTS \"{}\"", username);
        client.execute(&drop_user_sql, &[]).await
            .map_err(|e| SecretError::InvalidConfiguration(format!("Failed to revoke user: {}", e)))?;

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

        // Create the user in PostgreSQL
        self.create_user(&username, &password, role_sql).await?;

        let mut result = HashMap::new();
        result.insert("username".to_string(), Value::String(username));
        result.insert("password".to_string(), Value::String(password));
        result.insert("role".to_string(), Value::String(role_name.to_string()));

        Ok(result)
    }
}