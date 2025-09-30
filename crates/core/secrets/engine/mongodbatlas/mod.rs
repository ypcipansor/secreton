use super::{Secret, SecretMetadata, SecretsEngine, SecretsError, EngineMetrics};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// MongoDB Atlas secrets engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoDbAtlasConfig {
    /// Atlas public API key
    pub public_key: String,
    /// Atlas private API key
    pub private_key: String,
    /// Atlas project/group ID
    pub project_id: String,
    /// Default TTL for database users
    pub default_ttl: i64,
}

/// MongoDB Atlas database user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasDbUser {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
    /// Database name
    pub database_name: String,
    /// User roles
    pub roles: Vec<AtlasRole>,
    /// Connection strings
    pub connection_strings: HashMap<String, String>,
}

/// MongoDB Atlas role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasRole {
    /// Role name
    pub role_name: String,
    /// Database name
    pub database_name: String,
    /// Collection name (optional)
    pub collection_name: Option<String>,
}

/// MongoDB Atlas secrets engine
pub struct MongoDbAtlasEngine {
    config: MongoDbAtlasConfig,
    client: reqwest::Client,
}

impl MongoDbAtlasEngine {
    /// Create new MongoDB Atlas secrets engine
    pub async fn new(config: MongoDbAtlasConfig) -> Result<Self, SecretsError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SecretsError::InvalidConfiguration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Generate secure password
    fn generate_password(&self) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789";

        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Create MongoDB Atlas database user
    async fn create_atlas_user(
        &self,
        username: &str,
        database_name: &str,
        roles: Vec<AtlasRole>,
    ) -> Result<AtlasDbUser, SecretsError> {
        let password = self.generate_password();

        let user_data = json!({
            "databaseName": database_name,
            "username": username,
            "password": password,
            "roles": roles.iter().map(|r| json!({
                "roleName": r.role_name,
                "databaseName": r.database_name,
                "collectionName": r.collection_name,
            })).collect::<Vec<_>>(),
        });

        let url = format!(
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/{}/databaseUsers",
            self.config.project_id
        );

        let response = self.client
            .post(&url)
            .basic_auth(&self.config.public_key, Some(&self.config.private_key))
            .json(&user_data)
            .send()
            .await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to create Atlas user: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to create Atlas user: {}", response.status())));
        }

        // Generate connection strings
        let mut connection_strings = HashMap::new();
        connection_strings.insert(
            "standard".to_string(),
            format!("mongodb://{}:{}@cluster0.mongodb.net/{}", username, password, database_name),
        );
        connection_strings.insert(
            "standard_srv".to_string(),
            format!("mongodb+srv://{}:{}@cluster0.mongodb.net/{}", username, password, database_name),
        );

        Ok(AtlasDbUser {
            username: username.to_string(),
            password,
            database_name: database_name.to_string(),
            roles,
            connection_strings,
        })
    }

    /// Delete MongoDB Atlas database user
    async fn delete_atlas_user(&self, username: &str, database_name: &str) -> Result<(), SecretsError> {
        let url = format!(
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/{}/databaseUsers/{}/{}",
            self.config.project_id, database_name, username
        );

        let response = self.client
            .delete(&url)
            .basic_auth(&self.config.public_key, Some(&self.config.private_key))
            .send()
            .await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to delete Atlas user: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to delete Atlas user: {}", response.status())));
        }

        Ok(())
    }
}

#[async_trait]
impl SecretsEngine for MongoDbAtlasEngine {
    fn engine_type(&self) -> &'static str {
        "mongodbatlas"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        let username = data["username"].as_str()
            .ok_or(SecretsError::InvalidData("username field required".to_string()))?;

        let database_name = data["database_name"].as_str()
            .ok_or(SecretsError::InvalidData("database_name field required".to_string()))?;

        let roles = data["roles"].as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        Some(AtlasRole {
                            role_name: v["role_name"].as_str()?.to_string(),
                            database_name: v["database_name"].as_str()?.to_string(),
                            collection_name: v["collection_name"].as_str().map(|s| s.to_string()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_else(|| vec![AtlasRole {
                role_name: "readWrite".to_string(),
                database_name: database_name.to_string(),
                collection_name: None,
            }]);

        let user = self.create_atlas_user(username, database_name, roles).await?;

        let secret_data = json!({
            "username": user.username,
            "password": user.password,
            "database_name": user.database_name,
            "connection_string": user.connection_strings.get("standard_srv"),
            "connection_strings": user.connection_strings,
        });

        Ok(Secret {
            id: Uuid::new_v4(),
            path: path.to_string(),
            data: secret_data,
            metadata: SecretMetadata {
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 1,
                ttl: Some(self.config.default_ttl),
                expired_at: Some(Utc::now() + chrono::Duration::seconds(self.config.default_ttl)),
                custom_metadata: Some(HashMap::from([
                    ("username".to_string(), username.to_string()),
                    ("database".to_string(), database_name.to_string()),
                    ("engine".to_string(), "mongodbatlas".to_string()),
                ])),
            },
        })
    }

    async fn read_secret(&self, _path: &str) -> Result<Secret, SecretsError> {
        Err(SecretsError::InvalidData("MongoDB Atlas credentials must be regenerated on each access".to_string()))
    }

    async fn update_secret(&self, path: &str, data: Value, options: Option<Value>) -> Result<Secret, SecretsError> {
        self.create_secret(path, data, options).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 4 {
            return Err(SecretsError::InvalidData(format!("Invalid MongoDB Atlas path format: {}", path)));
        }

        let database_name = parts[2];
        let username = parts[3];

        self.delete_atlas_user(username, database_name).await
    }

    async fn list_secrets(&self, _prefix: &str) -> Result<Vec<String>, SecretsError> {
        Ok(vec![])
    }

    async fn collect_metrics(&self) -> Result<EngineMetrics, SecretsError> {
        Ok(EngineMetrics {
            engine_type: "mongodbatlas".to_string(),
            secrets_created: 0,
            secrets_read: 0,
            secrets_updated: 0,
            secrets_deleted: 0,
            avg_response_time_ms: 0.0,
            error_count: 0,
            active_secrets: 0,
            storage_size_bytes: 0,
        })
    }
}

impl Default for MongoDbAtlasConfig {
    fn default() -> Self {
        Self {
            public_key: String::new(),
            private_key: String::new(),
            project_id: String::new(),
            default_ttl: 3600,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mongodbatlas_config_default() {
        let config = MongoDbAtlasConfig::default();
        assert_eq!(config.default_ttl, 3600);
        assert!(config.public_key.is_empty());
    }

    #[tokio::test]
    async fn test_mongodbatlas_engine_creation() {
        let config = MongoDbAtlasConfig::default();
        let engine = MongoDbAtlasEngine::new(config).await;
        assert!(engine.is_ok());
    }
}
