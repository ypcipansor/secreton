//! PostgreSQL database backend

use crate::backend::database::DatabaseBackend;
use crate::error::*;
use async_trait::async_trait;
use deadpool_postgres::{Config, Pool, Runtime};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::Value;
use std::collections::HashMap;
use tokio_postgres::NoTls;

/// PostgreSQL database backend
pub struct PostgresBackend {
    pool: Pool,
}

impl PostgresBackend {
    pub fn new(connection_string: String) -> SecretResult<Self> {
        let mut cfg = Config::new();
        cfg.url = Some(connection_string);

        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls).map_err(|e| {
            SecretError::InvalidConfiguration(format!("Failed to create PostgreSQL pool: {}", e))
        })?;

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
impl DatabaseBackend for PostgresBackend {
    async fn generate_credentials(
        &self,
        role_name: &str,
        role_sql: &str,
    ) -> SecretResult<HashMap<String, Value>> {
        let client = self.pool.get().await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to get connection from pool: {}", e))
        })?;

        let username = self.generate_username();
        let password = self.generate_password();

        // 1. Create the user
        // Note: CREATE USER does not support parameters for username/password in most cases
        // Since we generate both username and password from alphanumeric characters, they are safe
        let create_user_sql = format!("CREATE USER \"{}\" WITH PASSWORD '{}'", username, password);

        client.batch_execute(&create_user_sql).await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to create user: {}", e))
        })?;

        // 2. Execute role SQL with template substitution
        // Simple template substitution: {{username}}, {{password}}, {{expiration}}
        let sql = role_sql
            .replace("{{username}}", &username)
            .replace("{{password}}", &password)
            .replace("{{name}}", &username); // Support both {{username}} and {{name}}

        // Use batch_execute to support multiple statements
        if let Err(e) = client.batch_execute(&sql).await {
            // Attempt cleanup if role execution fails
            let _ = client.batch_execute(&format!("DROP USER IF EXISTS \"{}\"", username)).await;

            return Err(SecretError::BackendOperationFailed(format!("Failed to execute role SQL: {}", e)));
        }

        let mut result = HashMap::new();
        result.insert("username".to_string(), Value::String(username));
        result.insert("password".to_string(), Value::String(password));
        result.insert("role".to_string(), Value::String(role_name.to_string()));

        Ok(result)
    }

    async fn test_connection(&self) -> SecretResult<()> {
        let client = self.pool.get().await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to get connection from pool: {}", e))
        })?;

        client.simple_query("SELECT 1").await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("PostgreSQL connection test failed: {}", e))
        })?;

        Ok(())
    }

    async fn revoke_credentials(&self, username: &str) -> SecretResult<()> {
        let client = self.pool.get().await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to get connection from pool: {}", e))
        })?;

        // Sanitize username to ensure it only contains allowed characters
        if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(SecretError::InvalidOperation("Invalid username format".to_string()));
        }

        let drop_user_sql = format!("DROP USER IF EXISTS \"{}\"", username);

        client.batch_execute(&drop_user_sql).await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("Failed to revoke user: {}", e))
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[tokio::test]
    async fn test_postgres_backend_integration() -> SecretResult<()> {
        let connection_string = match env::var("SECRETON_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                println!("SECRETON_DATABASE_URL not set, skipping integration test");
                return Ok(());
            }
        };

        // Create backend
        let backend = PostgresBackend::new(connection_string)?;

        // Test connection
        backend.test_connection().await?;

        // Generate credentials
        let role_sql = "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{username}}\";";
        let creds = backend.generate_credentials("test_role", role_sql).await?;

        let username = creds.get("username").and_then(|v| v.as_str()).unwrap();
        let _password = creds.get("password").and_then(|v| v.as_str()).unwrap();

        println!("Generated user: {}", username);

        // Verify credentials contain required fields
        assert!(creds.contains_key("username"));
        assert!(creds.contains_key("password"));
        assert_eq!(creds.get("role").and_then(|v| v.as_str()), Some("test_role"));

        // Clean up
        backend.revoke_credentials(username).await?;

        Ok(())
    }
}
