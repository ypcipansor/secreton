//! MongoDB database backend

use crate::error::*;
use serde_json::Value;
use std::collections::HashMap;

/// MongoDB database backend
pub struct MongodbBackend {
    connection_string: String,
}

impl MongodbBackend {
    pub fn new(connection_string: String) -> Self {
        Self { connection_string }
    }

    /// Test connection to MongoDB
    pub async fn test_connection(&self) -> SecretResult<()> {
        let client = mongodb::Client::with_uri_str(&self.connection_string)
            .await
            .map_err(|e| {
                SecretError::InvalidConfiguration(format!("Failed to connect to MongoDB: {}", e))
            })?;

        // Test with a simple ping
        client
            .database("admin")
            .run_command(mongodb::bson::doc! { "ping": 1 })
            .await
            .map_err(|e| {
                SecretError::InvalidConfiguration(format!("MongoDB connection test failed: {}", e))
            })?;

        Ok(())
    }

    /// Create a database user with specified privileges
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role_sql: &str,
    ) -> SecretResult<()> {
        let client = mongodb::Client::with_uri_str(&self.connection_string)
            .await
            .map_err(|e| {
                SecretError::InvalidConfiguration(format!("Failed to connect to MongoDB: {}", e))
            })?;

        let admin_db = client.database("admin");

        // Parse role_sql as JSON for MongoDB roles
        let roles: Vec<mongodb::bson::Document> = if !role_sql.is_empty() {
            serde_json::from_str(role_sql).map_err(|e| {
                SecretError::InvalidConfiguration(format!("Invalid role SQL JSON: {}", e))
            })?
        } else {
            vec![mongodb::bson::doc! {
                "role": "readWrite",
                "db": "test"
            }]
        };

        // Create the user
        let create_user_cmd = mongodb::bson::doc! {
            "createUser": username,
            "pwd": password,
            "roles": roles
        };

        admin_db.run_command(create_user_cmd).await.map_err(|e| {
            SecretError::InvalidConfiguration(format!("Failed to create user: {}", e))
        })?;

        Ok(())
    }

    /// Revoke database user
    pub async fn revoke_user(&self, username: &str) -> SecretResult<()> {
        let client = mongodb::Client::with_uri_str(&self.connection_string)
            .await
            .map_err(|e| {
                SecretError::InvalidConfiguration(format!("Failed to connect to MongoDB: {}", e))
            })?;

        let admin_db = client.database("admin");

        // Drop the user
        let drop_user_cmd = mongodb::bson::doc! {
            "dropUser": username
        };

        admin_db.run_command(drop_user_cmd).await.map_err(|e| {
            SecretError::InvalidConfiguration(format!("Failed to revoke user: {}", e))
        })?;

        Ok(())
    }

    /// Generate dynamic credentials
    pub async fn generate_credentials(
        &self,
        role_name: &str,
        role_sql: &str,
    ) -> SecretResult<HashMap<String, Value>> {
        // Generate random credentials
        use rand::{Rng, distributions::Alphanumeric};
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

        // Create the user in MongoDB
        self.create_user(&username, &password, role_sql).await?;

        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(username));
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));

        Ok(data)
    }
}
