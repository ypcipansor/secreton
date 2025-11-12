//! # RabbitMQ Integration
//!
//! Message queue integration for RabbitMQ operations.
//! Provides abstracted RabbitMQ operations for authentication, user management, and virtual host permissions.

use reqwest::Client;
use secreton_errors::{Result, SecretonError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use urlencoding;

/// RabbitMQ configuration for connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMqConfig {
    pub connection_uri: String,
    pub username: String,
    pub password: String,
    pub vhost: Option<String>,
    pub default_lease_ttl: i64,
}

/// RabbitMQ user data for management API
#[derive(Debug, Serialize, Deserialize)]
pub struct RabbitMqUser {
    pub name: String,
    pub password_hash: String,
    pub tags: String,
}

/// RabbitMQ permissions for a user on a vhost
#[derive(Debug, Serialize, Deserialize)]
pub struct RabbitMqPermissions {
    pub user: String,
    pub vhost: String,
    pub configure: String,
    pub write: String,
    pub read: String,
}

/// RabbitMQ connection manager with automatic user management
pub struct RabbitMqConnection {
    config: RabbitMqConfig,
    http_client: Client,
}

impl RabbitMqConnection {
    /// Create new RabbitMQ connection manager
    pub fn new(config: RabbitMqConfig) -> Self {
        let http_client = Client::new();
        Self {
            config,
            http_client,
        }
    }

    /// Get management API base URL from connection URI
    pub fn management_url(&self) -> Result<String> {
        // Convert AMQP URI to management API URL
        // amqp://user:pass@host:port/vhost -> http://host:15672/api
        let uri = &self.config.connection_uri;
        if let Some(at_pos) = uri.find('@') {
            if let Some(colon_pos) = uri[at_pos..].find(':') {
                let host_start = at_pos + 1;
                let port_end = at_pos + colon_pos;
                let host = &uri[host_start..port_end];
                Ok(format!("http://{}:15672/api", host))
            } else {
                // Default management port
                Ok(format!("http://{}:15672/api", &uri[at_pos + 1..]))
            }
        } else {
            // Fallback
            Ok("http://localhost:15672/api".to_string())
        }
    }

    /// Create RabbitMQ user via management API
    pub async fn create_user(&self, username: &str, password: &str, tags: &str) -> Result<()> {
        let url = format!("{}/users/{}", self.management_url()?, username);

        let user_data = RabbitMqUser {
            name: username.to_string(),
            password_hash: self.hash_password(password),
            tags: tags.to_string(),
        };

        let response = self
            .http_client
            .put(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .json(&user_data)
            .send()
            .await
            .map_err(|e| SecretonError::RabbitmqEngine {
                message: format!("Failed to create user: {}", e),
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(SecretonError::RabbitmqEngine {
                message: format!("Failed to create RabbitMQ user: {}", error_text),
            });
        }

        Ok(())
    }

    /// Set user permissions on vhost
    pub async fn set_permissions(
        &self,
        username: &str,
        vhost: &str,
        permissions: &RabbitMqPermissions,
    ) -> Result<()> {
        let url = format!(
            "{}/permissions/{}/{}",
            self.management_url()?,
            urlencoding::encode(vhost),
            username
        );

        let response = self
            .http_client
            .put(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .json(permissions)
            .send()
            .await
            .map_err(|e| SecretonError::RabbitmqEngine {
                message: format!("Failed to set permissions: {}", e),
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(SecretonError::RabbitmqEngine {
                message: format!("Failed to set RabbitMQ permissions: {}", error_text),
            });
        }

        Ok(())
    }

    /// Delete RabbitMQ user
    pub async fn delete_user(&self, username: &str) -> Result<()> {
        let url = format!("{}/users/{}", self.management_url()?, username);

        let response = self
            .http_client
            .delete(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .send()
            .await
            .map_err(|e| SecretonError::RabbitmqEngine {
                message: format!("Failed to delete user: {}", e),
            })?;

        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let error_text = response.text().await.unwrap_or_default();
            return Err(SecretonError::RabbitmqEngine {
                message: format!("Failed to delete RabbitMQ user: {}", error_text),
            });
        }

        Ok(())
    }

    /// Generate connection URI for user
    pub fn generate_connection_uri(&self, username: &str, password: &str) -> Result<String> {
        let vhost = self.config.vhost.as_deref().unwrap_or("/");
        let connection_uri = if let Some(at_pos) = self.config.connection_uri.find('@') {
            if let Some(colon_pos) = self.config.connection_uri[at_pos..].find(':') {
                let host_start = at_pos + 1;
                let port_end = at_pos + colon_pos;
                let host = &self.config.connection_uri[host_start..port_end];
                format!("amqp://{}:{}@{}:5672{}", username, password, host, vhost)
            } else {
                format!(
                    "amqp://{}:{}@{}:5672{}",
                    username,
                    password,
                    &self.config.connection_uri[at_pos + 1..],
                    vhost
                )
            }
        } else {
            format!("amqp://{}:{}@localhost:5672{}", username, password, vhost)
        };

        Ok(connection_uri)
    }

    /// Hash password for RabbitMQ (RabbitMQ uses SHA-256)
    fn hash_password(&self, password: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// RabbitMQ operations for common credential management
pub struct RabbitMqOperations;

impl RabbitMqOperations {
    /// Generate RabbitMQ credentials with permissions
    pub async fn generate_credentials(
        config: &RabbitMqConfig,
        username: &str,
        password: &str,
        tags: &str,
        vhost: &str,
        configure_perm: &str,
        write_perm: &str,
        read_perm: &str,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let conn = RabbitMqConnection::new(config.clone());

        // Create user
        conn.create_user(username, password, tags).await?;

        // Set permissions
        let permissions = RabbitMqPermissions {
            user: username.to_string(),
            vhost: vhost.to_string(),
            configure: configure_perm.to_string(),
            write: write_perm.to_string(),
            read: read_perm.to_string(),
        };

        conn.set_permissions(username, vhost, &permissions).await?;

        // Generate connection URI
        let connection_uri = conn.generate_connection_uri(username, password)?;

        let mut creds_data = HashMap::new();
        creds_data.insert(
            "username".to_string(),
            serde_json::Value::String(username.to_string()),
        );
        creds_data.insert(
            "password".to_string(),
            serde_json::Value::String(password.to_string()),
        );
        creds_data.insert(
            "vhost".to_string(),
            serde_json::Value::String(vhost.to_string()),
        );
        creds_data.insert(
            "connection_uri".to_string(),
            serde_json::Value::String(connection_uri),
        );
        creds_data.insert(
            "tags".to_string(),
            serde_json::Value::String(tags.to_string()),
        );

        Ok(creds_data)
    }
}
