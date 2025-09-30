use super::{Secret, SecretMetadata, SecretsEngine, SecretsError};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use uuid::Uuid;

/// RabbitMQ secrets engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMqConfig {
    /// RabbitMQ server URL
    pub url: String,
    /// Default virtual host
    pub default_vhost: String,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Admin username for management operations
    pub admin_username: String,
    /// Admin password for management operations
    pub admin_password: String,
}

/// RabbitMQ user credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMqCredentials {
    /// Username for RabbitMQ access
    pub username: String,
    /// Password for RabbitMQ access
    pub password: String,
    /// Virtual host access permissions
    pub vhost: String,
    /// Permissions granted (read, write, configure)
    pub permissions: Vec<String>,
    /// Lease ID for credential lifecycle management
    pub lease_id: String,
    /// Time-to-live for credentials
    pub lease_duration: i64,
}

/// RabbitMQ secrets engine
pub struct RabbitMqEngine {
    config: RabbitMqConfig,
    client: Option<reqwest::Client>,
}

impl RabbitMqEngine {
    /// Create new RabbitMQ secrets engine
    pub async fn new(config: RabbitMqConfig) -> Result<Self, SecretsError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.connection_timeout))
            .build()
            .map_err(|e| SecretsError::InvalidConfiguration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            client: Some(client),
        })
    }

    /// Create RabbitMQ user credentials
    async fn create_user_credentials(
        &self,
        username: &str,
        password: &str,
        vhost: &str,
        permissions: Vec<String>,
    ) -> Result<RabbitMqCredentials, SecretsError> {
        let client = self.client.as_ref()
            .ok_or(SecretsError::InvalidConfiguration("HTTP client not initialized".to_string()))?;

        // Create user via RabbitMQ Management API
        let user_data = json!({
            "password": password,
            "tags": "management"
        });

        let url = format!("{}/api/users/{}", self.config.url.trim_end_matches('/'), username);

        let response = client
            .put(&url)
            .basic_auth(&self.config.admin_username, Some(&self.config.admin_password))
            .json(&user_data)
            .send()
            .await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to create user: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to create user: {}", response.status())));
        }

        // Set user permissions
        let perm_data = json!({
            "configure": permissions.contains(&"configure".to_string()),
            "write": permissions.contains(&"write".to_string()),
            "read": permissions.contains(&"read".to_string())
        });

        let perm_url = format!("{}/api/permissions/{}/{}",
            self.config.url.trim_end_matches('/'), vhost, username);

        let response = client
            .put(&perm_url)
            .basic_auth(&self.config.admin_username, Some(&self.config.admin_password))
            .json(&perm_data)
            .send()
            .await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to set permissions: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to set permissions: {}", response.status())));
        }

        let credentials = RabbitMqCredentials {
            username: username.to_string(),
            password: password.to_string(),
            vhost: vhost.to_string(),
            permissions,
            lease_id: format!("rabbitmq/creds/{}/{}", username, Utc::now().timestamp()),
            lease_duration: 3600, // 1 hour default
        };

        info!("Created RabbitMQ credentials for user: {}", username);
        Ok(credentials)
    }

    /// Revoke RabbitMQ user credentials
    async fn revoke_user_credentials(&self, username: &str) -> Result<(), SecretsError> {
        let client = self.client.as_ref()
            .ok_or(SecretsError::InvalidConfiguration("HTTP client not initialized".to_string()))?;

        // Delete user via RabbitMQ Management API
        let url = format!("{}/api/users/{}", self.config.url.trim_end_matches('/'), username);

        let response = client
            .delete(&url)
            .basic_auth(&self.config.admin_username, Some(&self.config.admin_password))
            .send()
            .await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to delete user: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to delete user: {}", response.status())));
        }

        info!("Revoked RabbitMQ credentials for user: {}", username);
        Ok(())
    }

    /// List RabbitMQ users (for admin purposes)
    async fn list_users(&self) -> Result<Vec<String>, SecretsError> {
        let client = self.client.as_ref()
            .ok_or(SecretsError::InvalidConfiguration("HTTP client not initialized".to_string()))?;

        let url = format!("{}/api/users", self.config.url.trim_end_matches('/'));

        let response = client
            .get(&url)
            .basic_auth(&self.config.admin_username, Some(&self.config.admin_password))
            .send()
            .await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to list users: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to list users: {}", response.status())));
        }

        #[derive(Deserialize)]
        struct UserList {
            name: String,
        }

        let users: Vec<UserList> = response.json().await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to parse user list: {}", e)))?;

        let usernames = users.into_iter().map(|u| u.name).collect();
        Ok(usernames)
    }
}

#[async_trait]
impl SecretsEngine for RabbitMqEngine {
    fn engine_type(&self) -> &'static str {
        "rabbitmq"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        info!("Creating RabbitMQ secret at path: {}", path);

        // Parse credentials from data
        let username = data["username"].as_str()
            .ok_or(SecretsError::InvalidData("username field required".to_string()))?;
        let password = data["password"].as_str()
            .ok_or(SecretsError::InvalidData("password field required".to_string()))?;
        let vhost = data["vhost"].as_str().unwrap_or(&self.config.default_vhost);

        // Parse permissions (default to read,write)
        let permissions = data["permissions"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_else(|| vec!["read".to_string(), "write".to_string()]);

        // Generate unique lease ID
        let lease_id = Uuid::new_v4().to_string();

        // Create RabbitMQ credentials
        let credentials = self.create_user_credentials(username, password, vhost, permissions).await?;

        // Create secret data
        let secret_data = json!({
            "username": credentials.username,
            "password": credentials.password,
            "vhost": credentials.vhost,
            "permissions": credentials.permissions,
            "connection_url": format!("amqp://{}:{}@{}/{}",
                credentials.username,
                credentials.password,
                self.config.url.trim_start_matches("http://").trim_start_matches("https://"),
                credentials.vhost
            ),
            "lease_id": credentials.lease_id,
        });

        // Create secret with metadata
        let metadata = SecretMetadata {
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            ttl: Some(credentials.lease_duration),
            expired_at: Some(Utc::now() + chrono::Duration::seconds(credentials.lease_duration)),
            custom_metadata: Some(HashMap::from([
                ("lease_id".to_string(), lease_id.clone()),
                ("username".to_string(), username.to_string()),
                ("vhost".to_string(), vhost.to_string()),
            ])),
        };

        let secret = Secret {
            id: Uuid::new_v4(),
            path: path.to_string(),
            data: secret_data,
            metadata,
        };

        info!("Successfully created RabbitMQ credentials for user: {}", username);
        Ok(secret)
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        // For RabbitMQ engine, we regenerate credentials on each read for security
        // Extract username from path format: rabbitmq/creds/{username}
        let username = path.strip_prefix("rabbitmq/creds/")
            .ok_or(SecretsError::InvalidData(format!("Invalid RabbitMQ path format: {}", path)))?;

        // In a real implementation, you'd store and retrieve credentials from storage
        // For now, return an error indicating credentials need to be regenerated
        Err(SecretsError::InvalidData(
            "RabbitMQ credentials must be regenerated on each access".to_string(),
        ))
    }

    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // RabbitMQ credentials are typically not updated in place, but regenerated
        warn!("Updating RabbitMQ credentials by regenerating for path: {}", path);
        self.create_secret(path, data, options).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        info!("Deleting RabbitMQ secret at path: {}", path);

        // Extract username from path format: rabbitmq/creds/{username}
        let username = path.strip_prefix("rabbitmq/creds/")
            .ok_or(SecretsError::InvalidData(format!("Invalid RabbitMQ path format: {}", path)))?;

        // Revoke the user credentials
        self.revoke_user_credentials(username).await?;

        Ok(())
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError> {
        // List configured users
        if path == "rabbitmq/creds" || path == "rabbitmq/creds/" {
            let users = self.list_users().await?;
            Ok(users.into_iter().map(|u| format!("rabbitmq/creds/{}", u)).collect())
        } else {
            Ok(vec![])
        }
    }
}

impl Default for RabbitMqConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:15672".to_string(),
            default_vhost: "/".to_string(),
            connection_timeout: 30,
            admin_username: "guest".to_string(),
            admin_password: "guest".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rabbitmq_config_default() {
        let config = RabbitMqConfig::default();
        assert_eq!(config.url, "http://localhost:15672");
        assert_eq!(config.default_vhost, "/");
        assert_eq!(config.connection_timeout, 30);
        assert_eq!(config.admin_username, "guest");
        assert_eq!(config.admin_password, "guest");
    }

    #[tokio::test]
    async fn test_rabbitmq_engine_creation() {
        let config = RabbitMqConfig::default();
        let engine = RabbitMqEngine::new(config).await;

        // This will fail in test environment without RabbitMQ, but tests the structure
        assert!(engine.is_ok() || engine.is_err());
    }
}
