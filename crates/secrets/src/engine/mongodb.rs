//! MongoDB secret engine for dynamic credential generation

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use mongodb::Client;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// MongoDB secret engine
pub struct MongodbEngine {
    config: MongodbConfig,
    enabled: bool,
    client: Option<Client>,
}

impl MongodbEngine {
    pub fn new(config: MongodbConfig) -> Self {
        Self {
            config,
            enabled: false,
            client: None,
        }
    }
}

#[async_trait]
impl SecretEngine for MongodbEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Mongodb
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        self.enabled = config.enabled;

        if self.enabled {
            // Establish MongoDB connection
            self.connect().await?;
        }

        Ok(())
    }

    async fn read(&self, _path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Mongodb".to_string()));
        }
        Ok(None)
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Mongodb".to_string()));
        }

        match path {
            "creds" => {
                // Generate MongoDB credentials
                let creds_data = self.generate_mongodb_credentials(&data).await?;
                Ok(Secret {
                    id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: creds_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_by: "mongodb-engine".to_string(),
                        updated_by: "mongodb-engine".to_string(),
                        lease_id: None,
                        lease_duration: Some(self.config.default_lease_ttl),
                        ..Default::default()
                    },
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
            }
            _ => Err(SecretError::InvalidPath(format!(
                "Unsupported MongoDB path: {}",
                path
            ))),
        }
    }

    async fn delete(&mut self, path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Mongodb".to_string()));
        }

        match path {
            "creds" => {
                // For credential revocation, we'd need to store the username somewhere
                // For now, this is a placeholder - in production, you'd revoke the specific user
                Ok(())
            }
            _ => Err(SecretError::InvalidPath(format!(
                "Unsupported MongoDB path: {}",
                path
            ))),
        }
    }

    async fn list(&self, _path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Mongodb".to_string()));
        }
        Ok(vec![])
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
        self.client = None;
    }
}

impl MongodbEngine {
    /// Connect to MongoDB
    async fn connect(&mut self) -> SecretResult<()> {
        if self.client.is_some() {
            return Ok(());
        }

        let client = Client::with_uri_str(&self.config.connection_uri)
            .await
            .map_err(|e| SecretError::BackendConnectionFailed(format!("MongoDB connection failed: {}", e)))?;

        // Test the connection
        if self.config.verify_connection {
            client
                .database("admin")
                .run_command(mongodb::bson::doc! { "ping": 1 })
                .await
                .map_err(|e| SecretError::BackendConnectionFailed(format!("MongoDB ping failed: {}", e)))?;
        }

        self.client = Some(client);
        Ok(())
    }
    /// Generate MongoDB credentials
    async fn generate_mongodb_credentials(
        &self,
        data: &HashMap<String, Value>,
    ) -> SecretResult<HashMap<String, Value>> {
        let client = self.client.as_ref()
            .ok_or_else(|| SecretError::BackendConnectionFailed("MongoDB client not connected".to_string()))?;

        // Extract database name from request data or use default
        let database_name = data
            .get("database")
            .and_then(|v| v.as_str())
            .unwrap_or("mydb");

        let roles = data
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec!["readWrite"]);

        // Generate unique username
        let username = self.generate_username("vault_user");

        // Generate secure password
        let password = self.generate_password(16);

        // Create user in MongoDB
        self.create_mongodb_user(client, &username, &password, database_name, &roles).await?;

        // Build connection string
        let connection_string = format!(
            "mongodb://{}:{}@localhost:27017/{}",
            username, password, database_name
        );

        let mut creds_data = HashMap::new();
        creds_data.insert("username".to_string(), Value::String(username));
        creds_data.insert("password".to_string(), Value::String(password));
        creds_data.insert("connection_string".to_string(), Value::String(connection_string));
        creds_data.insert("database".to_string(), Value::String(database_name.to_string()));

        Ok(creds_data)
    }

    /// Generate secure password
    fn generate_password(&self, length: usize) -> String {
        use secreton_common::utils::password::generate_password;
        generate_password(length)
    }

    /// Generate unique username for MongoDB
    fn generate_username(&self, base_username: &str) -> String {
        let timestamp = chrono::Utc::now().timestamp();
        format!("{}_{}", base_username, timestamp)
    }

    /// Create user in MongoDB
    async fn create_mongodb_user(
        &self,
        client: &Client,
        username: &str,
        password: &str,
        database: &str,
        roles: &[&str],
    ) -> SecretResult<()> {
        let db = client.database(database);

        // Convert roles to MongoDB role documents
        let role_docs: Vec<mongodb::bson::Document> = roles
            .iter()
            .map(|role| {
                if role.contains('.') {
                    // Role with database specification like "readWrite.myapp"
                    let parts: Vec<&str> = role.split('.').collect();
                    mongodb::bson::doc! {
                        "role": parts[0],
                        "db": parts[1]
                    }
                } else {
                    // Simple role name
                    mongodb::bson::doc! {
                        "role": role,
                        "db": database
                    }
                }
            })
            .collect();

        // Create user command
        let create_user_cmd = mongodb::bson::doc! {
            "createUser": username,
            "pwd": password,
            "roles": role_docs
        };

        db.run_command(create_user_cmd)
            .await
            .map_err(|e| SecretError::BackendOperationFailed(format!("Failed to create MongoDB user: {}", e)))?;

        Ok(())
    }
}
