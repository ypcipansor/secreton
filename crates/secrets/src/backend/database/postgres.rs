//! PostgreSQL database backend

use crate::backend::database::DatabaseBackend;
use crate::error::*;
use crate::model::DatabaseConfig;
use async_trait::async_trait;
use deadpool_postgres::{Config, Pool, Runtime};
use rand::{Rng, distributions::Alphanumeric};
use serde_json::Value;
use std::collections::HashMap;
use tokio_postgres::NoTls;

/// PostgreSQL database backend
pub struct PostgresBackend {
    pool: Pool,
}

impl PostgresBackend {
    pub fn new(config: DatabaseConfig) -> SecretResult<Self> {
        let mut cfg = Config::new();
        cfg.url = Some(config.connection_url);

        // Apply pool configuration from DatabaseConfig if present
        // Since deadpool-postgres re-exports deadpool types, we can use them via deadpool_postgres::PoolConfig if available,
        // or just rely on the Config struct which should have fields.
        // BUT deadpool-postgres::Config has a `pool` field which expects `deadpool::managed::PoolConfig`.
        // We cannot import deadpool directly as it's not in our cargo.toml.
        // However, deadpool-postgres depends on it.
        // IF we cannot import it, we are stuck unless we add it or use a method on Config.
        // Most deadpool-postgres versions allow configuring via the Config struct itself or builders.

        // Since we can't import deadpool::managed::PoolConfig, let's try to see if deadpool_postgres re-exports it.
        // Use deadpool_postgres::PoolConfig if it exists (it usually doesn't, it uses the generic one).

        // Let's try to avoid setting pool config for now if we can't access the type, OR assume standard defaults.
        // User requirement is to use the config.
        // Wait, earlier I saw `deadpool` is not in workspace deps but `deadpool-postgres` is.
        // `deadpool-postgres` likely re-exports `PoolConfig`.

        // Let's try to access it via `deadpool_postgres::pool::PoolConfig` or similar.
        // Or simply `deadpool_postgres::PoolConfig` (unlikely).

        // If we can't fix this easily without adding a dep, and I just removed the dep, I made a mistake.
        // But the previous error was that `deadpool` was not found in *workspace*.
        // So I can't add it to secrets/Cargo.toml as `workspace = true` unless I add it to root.

        // So I must add it to root Cargo.toml first if I want to use it.
        // OR I define it in secrets/Cargo.toml without `workspace = true`.
        // Let's try defining it directly in secrets/Cargo.toml.

        // But for this file patch, I will temporarily comment out the pool config setting to allow compilation check
        // and then fix dependency.

        // actually, let's try to just set cfg.pool = Some(...) but we need the type.
        // If I can't name the type, I can't construct it.
        // unless I use `deadpool_postgres::Config::new().pool` which is None.

        // Apply pool configuration from DatabaseConfig if present
        if let Some(max_size) = config.max_open_connections {
            let mut pool_config = deadpool::managed::PoolConfig::default();
            pool_config.max_size = max_size as usize;
            cfg.pool = Some(pool_config);
        }

        // Note: max_idle_connections isn't directly mapped in basic PoolConfig usually (it has distinct properties like timeouts).
        // deadpool 0.9+ has `max_size` (total) and potentially others.
        // We will stick to `max_open_connections` -> `max_size` for now as primary tuning knob.

        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls).map_err(|e| {
            SecretError::InvalidConfiguration(format!("Failed to create PostgreSQL pool: {}", e))
        })?;

        Ok(Self { pool })
    }

    /// Generate a random username
    fn generate_username(&self) -> String {
        let suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(14)
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
            SecretError::BackendOperationFailed(format!(
                "Failed to get connection from pool: {}",
                e
            ))
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
            let _ = client
                .batch_execute(&format!("DROP USER IF EXISTS \"{}\"", username))
                .await;

            return Err(SecretError::BackendOperationFailed(format!(
                "Failed to execute role SQL: {}",
                e
            )));
        }

        let mut result = HashMap::new();
        result.insert("username".to_string(), Value::String(username));
        result.insert("password".to_string(), Value::String(password));
        result.insert("role".to_string(), Value::String(role_name.to_string()));

        Ok(result)
    }

    async fn test_connection(&self) -> SecretResult<()> {
        let client = self.pool.get().await.map_err(|e| {
            SecretError::BackendOperationFailed(format!(
                "Failed to get connection from pool: {}",
                e
            ))
        })?;

        client.simple_query("SELECT 1").await.map_err(|e| {
            SecretError::BackendOperationFailed(format!("PostgreSQL connection test failed: {}", e))
        })?;

        Ok(())
    }

    async fn revoke_credentials(&self, username: &str) -> SecretResult<()> {
        let client = self.pool.get().await.map_err(|e| {
            SecretError::BackendOperationFailed(format!(
                "Failed to get connection from pool: {}",
                e
            ))
        })?;

        // Sanitize username to ensure it only contains allowed characters
        if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(SecretError::InvalidOperation(
                "Invalid username format".to_string(),
            ));
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

        let config = DatabaseConfig {
            connection_url: connection_string,
            plugin_name: "test".to_string(),
            allowed_roles: vec![],
            username: None,
            password: None,
            max_open_connections: Some(2),
            max_idle_connections: None,
            max_connection_lifetime: None,
        };

        // Create backend
        let backend = PostgresBackend::new(config)?;

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
        assert_eq!(
            creds.get("role").and_then(|v| v.as_str()),
            Some("test_role")
        );

        // Clean up
        backend.revoke_credentials(username).await?;

        Ok(())
    }
}
