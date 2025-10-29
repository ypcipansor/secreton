// RabbitMQ Secrets Engine - Dynamic RabbitMQ credential generation
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use reqwest;

#[derive(Debug, Error)]
pub enum RabbitMQError {
    #[error("RabbitMQ error: {0}")]
    RabbitMQError(String),
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Permission error: {0}")]
    PermissionError(String),
}

pub type Result<T> = std::result::Result<T, RabbitMQError>;

/// RabbitMQ configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMQConfig {
    pub connection_uri: String,      // amqp://user:pass@host:port/vhost
    pub username: String,            // Admin username
    pub password: String,            // Admin password
    pub verify_connection: bool,     // Verify connection on configure
    pub username_template: String,   // Template for generated usernames
    pub password_policy: PasswordPolicy,
}

/// Password generation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub length: u32,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
}

/// RabbitMQ role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMQRole {
    pub name: String,
    pub vhosts: Vec<VHostPermission>,  // Permissions per vhost
    pub tags: Vec<String>,             // User tags (administrator, management, etc.)
    pub ttl: Duration,                 // Credential TTL
}

/// Permissions for a specific vhost
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VHostPermission {
    pub vhost: String,
    pub configure: String,   // Configure permission regex
    pub write: String,       // Write permission regex
    pub read: String,        // Read permission regex
    pub topic_permissions: Vec<TopicPermission>,
}

/// Topic-specific permissions (RabbitMQ 3.7+)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicPermission {
    pub exchange: String,
    pub write: String,       // Write permission regex
    pub read: String,        // Read permission regex
}

/// Generated RabbitMQ user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMQUser {
    pub username: String,
    pub password: String,
    pub tags: Vec<String>,
    pub vhosts: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// RabbitMQ secrets engine
pub struct RabbitMQEngine {
    config: Arc<RwLock<Option<RabbitMQConfig>>>,
    roles: Arc<RwLock<HashMap<String, RabbitMQRole>>>,
    users: Arc<RwLock<HashMap<String, RabbitMQUser>>>,
}

impl RabbitMQEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure RabbitMQ connection
    pub async fn configure(&self, config: RabbitMQConfig) -> Result<()> {
        if config.connection_uri.is_empty() {
            return Err(RabbitMQError::ConfigError(
                "Connection URI is required".to_string(),
            ));
        }

        if config.verify_connection {
            self.verify_connection(&config).await?;
        }

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Verify RabbitMQ connection
    async fn verify_connection(&self, config: &RabbitMQConfig) -> Result<()> {
        // Extract management API URL from connection URI
        // Assume management API is available at the same host:port with /api/overview endpoint
        let management_url = self.get_management_url(&config.connection_uri)?;

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/api/overview", management_url))
            .basic_auth(&config.username, Some(&config.password))
            .send()
            .await
            .map_err(|e| RabbitMQError::RabbitMQError(format!("Failed to connect to RabbitMQ Management API: {}", e)))?;

        if !response.status().is_success() {
            return Err(RabbitMQError::RabbitMQError(format!(
                "RabbitMQ Management API returned status: {}",
                response.status()
            )));
        }

        // Parse response to verify it's valid JSON
        let _overview: serde_json::Value = response.json().await
            .map_err(|e| RabbitMQError::RabbitMQError(format!("Invalid JSON response from RabbitMQ: {}", e)))?;

        Ok(())
    }

    /// Extract management API URL from connection URI
    fn get_management_url(&self, connection_uri: &str) -> Result<String> {
        // Parse AMQP URI: amqp://user:pass@host:port/vhost
        let url = url::Url::parse(connection_uri)
            .map_err(|e| RabbitMQError::ConfigError(format!("Invalid connection URI: {}", e)))?;

        let host = url.host_str()
            .ok_or_else(|| RabbitMQError::ConfigError("Missing host in connection URI".to_string()))?;
        let port = url.port().unwrap_or(5672); // Default AMQP port

        // Management API typically runs on port 15672 (AMQP port + 10000)
        let management_port = port + 10000;

        Ok(format!("http://{}:{}", host, management_port))
    }

    /// Create a role
    pub async fn create_role(&self, role: RabbitMQRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(RabbitMQError::ConfigError(
                "Role name is required".to_string(),
            ));
        }

        if role.vhosts.is_empty() {
            return Err(RabbitMQError::ConfigError(
                "At least one vhost is required".to_string(),
            ));
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Generate credentials for a role
    pub async fn generate_credentials(&self, role_name: &str) -> Result<RabbitMQUser> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| RabbitMQError::ConfigError("RabbitMQ not configured".to_string()))?;

        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| RabbitMQError::RoleNotFound(role_name.to_string()))?;

        // Generate username
        let username = format!("vault-token-{}", uuid::Uuid::new_v4());

        // Generate password
        let password = self.generate_password(&config.password_policy);

        // Create user in RabbitMQ (mock)
        self.create_rabbitmq_user(&username, &password, &role.tags)
            .await?;

        // Set permissions for each vhost
        for vhost_perm in &role.vhosts {
            self.set_permissions(
                &username,
                &vhost_perm.vhost,
                &vhost_perm.configure,
                &vhost_perm.write,
                &vhost_perm.read,
            )
            .await?;

            // Set topic permissions if any
            for topic_perm in &vhost_perm.topic_permissions {
                self.set_topic_permissions(
                    &username,
                    &vhost_perm.vhost,
                    &topic_perm.exchange,
                    &topic_perm.write,
                    &topic_perm.read,
                )
                .await?;
            }
        }

        let user = RabbitMQUser {
            username: username.clone(),
            password,
            tags: role.tags.clone(),
            vhosts: role.vhosts.iter().map(|v| v.vhost.clone()).collect(),
            created_at: Utc::now(),
            expires_at: Utc::now() + role.ttl,
        };

        // Store user
        let mut users = self.users.write().await;
        users.insert(username, user.clone());

        Ok(user)
    }

    /// Generate password based on policy
    fn generate_password(&self, policy: &PasswordPolicy) -> String {
        use secreton_common::utils::password::{generate_password_with_policy, PasswordPolicy as CommonPolicy};

        // Convert local policy to common policy
        let common_policy = CommonPolicy {
            min_length: policy.length as usize,
            max_length: None,
            require_uppercase: policy.use_uppercase,
            require_lowercase: policy.use_lowercase,
            require_numbers: policy.use_numbers,
            require_special: policy.use_symbols,
            allowed_special_chars: Some("!@#$%^&*".to_string()),
        };

        generate_password_with_policy(&common_policy)
    }

    /// Create user in RabbitMQ
    async fn create_rabbitmq_user(
        &self,
        username: &str,
        password: &str,
        tags: &[String],
    ) -> Result<()> {
        let config = self.config.read().await;
        let config = config.as_ref().ok_or_else(|| {
            RabbitMQError::ConfigError("RabbitMQ not configured".to_string())
        })?;

        let management_url = self.get_management_url(&config.connection_uri)?;
        let client = reqwest::Client::new();

        // Create user payload
        let user_payload = serde_json::json!({
            "password": password,
            "tags": tags.join(",")
        });

        let response = client
            .put(&format!("{}/api/users/{}", management_url, username))
            .basic_auth(&config.username, Some(&config.password))
            .json(&user_payload)
            .send()
            .await
            .map_err(|e| RabbitMQError::RabbitMQError(format!("Failed to create user: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(RabbitMQError::RabbitMQError(format!(
                "Failed to create user {}: {} - {}",
                username, status, error_text
            )));
        }

        Ok(())
    }

    /// Set permissions for user on vhost
    async fn set_permissions(
        &self,
        username: &str,
        vhost: &str,
        configure: &str,
        write: &str,
        read: &str,
    ) -> Result<()> {
        let config = self.config.read().await;
        let config = config.as_ref().ok_or_else(|| {
            RabbitMQError::ConfigError("RabbitMQ not configured".to_string())
        })?;

        let management_url = self.get_management_url(&config.connection_uri)?;
        let client = reqwest::Client::new();

        // Set permissions payload
        let permissions_payload = serde_json::json!({
            "configure": configure,
            "write": write,
            "read": read
        });

        let response = client
            .put(&format!("{}/api/permissions/{}/{}", management_url, urlencoding::encode(vhost), username))
            .basic_auth(&config.username, Some(&config.password))
            .json(&permissions_payload)
            .send()
            .await
            .map_err(|e| RabbitMQError::RabbitMQError(format!("Failed to set permissions: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(RabbitMQError::RabbitMQError(format!(
                "Failed to set permissions for user {} on vhost {}: {} - {}",
                username, vhost, status, error_text
            )));
        }

        Ok(())
    }

    /// Set topic permissions for user
    async fn set_topic_permissions(
        &self,
        _username: &str,
        _vhost: &str,
        _exchange: &str,
        _write: &str,
        _read: &str,
    ) -> Result<()> {
        // Mock implementation
        // Real implementation would call:
        // PUT /api/topic-permissions/{vhost}/{username}
        Ok(())
    }

    /// Revoke credentials
    pub async fn revoke_credentials(&self, username: &str) -> Result<()> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(RabbitMQError::ConfigError(
                "RabbitMQ not configured".to_string(),
            ));
        }

        // Delete user from RabbitMQ
        self.delete_rabbitmq_user(username).await?;

        // Remove from local storage
        let mut users = self.users.write().await;
        users
            .remove(username)
            .ok_or_else(|| RabbitMQError::UserNotFound(username.to_string()))?;

        Ok(())
    }

    /// Delete user from RabbitMQ
    async fn delete_rabbitmq_user(&self, username: &str) -> Result<()> {
        let config = self.config.read().await;
        let config = config.as_ref().ok_or_else(|| {
            RabbitMQError::ConfigError("RabbitMQ not configured".to_string())
        })?;

        let management_url = self.get_management_url(&config.connection_uri)?;
        let client = reqwest::Client::new();

        let response = client
            .delete(&format!("{}/api/users/{}", management_url, username))
            .basic_auth(&config.username, Some(&config.password))
            .send()
            .await
            .map_err(|e| RabbitMQError::RabbitMQError(format!("Failed to delete user: {}", e)))?;

        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(RabbitMQError::RabbitMQError(format!(
                "Failed to delete user {}: {} - {}",
                username, status, error_text
            )));
        }

        Ok(())
    }

    /// Get role
    pub async fn get_role(&self, name: &str) -> Result<RabbitMQRole> {
        let roles = self.roles.read().await;
        roles
            .get(name)
            .cloned()
            .ok_or_else(|| RabbitMQError::RoleNotFound(name.to_string()))
    }

    /// List all roles
    pub async fn list_roles(&self) -> Vec<String> {
        let roles = self.roles.read().await;
        roles.keys().cloned().collect()
    }

    /// Delete a role
    pub async fn delete_role(&self, name: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles
            .remove(name)
            .ok_or_else(|| RabbitMQError::RoleNotFound(name.to_string()))?;
        Ok(())
    }

    /// List users
    pub async fn list_users(&self) -> Vec<String> {
        let users = self.users.read().await;
        users.keys().cloned().collect()
    }

    /// Get user
    pub async fn get_user(&self, username: &str) -> Result<RabbitMQUser> {
        let users = self.users.read().await;
        users
            .get(username)
            .cloned()
            .ok_or_else(|| RabbitMQError::UserNotFound(username.to_string()))
    }

    /// Cleanup expired users
    pub async fn cleanup_expired_users(&self) -> Result<usize> {
        let mut users = self.users.write().await;
        let now = Utc::now();

        let expired: Vec<String> = users
            .iter()
            .filter(|(_, user)| user.expires_at < now)
            .map(|(username, _)| username.clone())
            .collect();

        let count = expired.len();
        for username in expired {
            users.remove(&username);
            // Also delete from RabbitMQ in real implementation
        }

        Ok(count)
    }
}

impl Default for RabbitMQEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RabbitMQConfig {
        RabbitMQConfig {
            connection_uri: "amqp://admin:password@localhost:5672/".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
            verify_connection: false,
            username_template: "vault-{{random}}".to_string(),
            password_policy: PasswordPolicy {
                length: 24,
                use_uppercase: true,
                use_lowercase: true,
                use_numbers: true,
                use_symbols: true,
            },
        }
    }

    #[tokio::test]
    async fn test_configure_rabbitmq() {
        let engine = RabbitMQEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        let cfg = engine.config.read().await;
        assert!(cfg.is_some());
        assert_eq!(
            cfg.as_ref().unwrap().username,
            "admin"
        );
    }

    #[tokio::test]
    async fn test_generate_credentials_with_vhosts() {
        let engine = RabbitMQEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = RabbitMQRole {
            name: "app-role".to_string(),
            vhosts: vec![
                VHostPermission {
                    vhost: "/app".to_string(),
                    configure: ".*".to_string(),
                    write: ".*".to_string(),
                    read: ".*".to_string(),
                    topic_permissions: vec![],
                },
                VHostPermission {
                    vhost: "/logs".to_string(),
                    configure: "".to_string(),
                    write: "logs.*".to_string(),
                    read: "logs.*".to_string(),
                    topic_permissions: vec![],
                },
            ],
            tags: vec!["management".to_string()],
            ttl: Duration::hours(24),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("app-role").await.unwrap();

        assert!(user.username.starts_with("vault-token-"));
        assert_eq!(user.password.len(), 24);
        assert_eq!(user.tags.len(), 1);
        assert_eq!(user.vhosts.len(), 2);
        assert!(user.vhosts.contains(&"/app".to_string()));
        assert!(user.vhosts.contains(&"/logs".to_string()));
    }

    #[tokio::test]
    async fn test_set_permissions_per_vhost() {
        let engine = RabbitMQEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = RabbitMQRole {
            name: "restricted-role".to_string(),
            vhosts: vec![VHostPermission {
                vhost: "/production".to_string(),
                configure: "".to_string(),           // No configure
                write: "^app\\..*".to_string(),      // Only write to app.* queues
                read: "^app\\..*".to_string(),       // Only read from app.* queues
                topic_permissions: vec![],
            }],
            tags: vec![],
            ttl: Duration::hours(12),
        };

        engine.create_role(role).await.unwrap();

        let user = engine
            .generate_credentials("restricted-role")
            .await
            .unwrap();

        assert_eq!(user.vhosts.len(), 1);
        assert_eq!(user.vhosts[0], "/production");
    }

    #[tokio::test]
    async fn test_revoke_credentials() {
        let engine = RabbitMQEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = RabbitMQRole {
            name: "temp-role".to_string(),
            vhosts: vec![VHostPermission {
                vhost: "/".to_string(),
                configure: ".*".to_string(),
                write: ".*".to_string(),
                read: ".*".to_string(),
                topic_permissions: vec![],
            }],
            tags: vec!["administrator".to_string()],
            ttl: Duration::hours(1),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("temp-role").await.unwrap();
        let username = user.username.clone();

        // User should exist
        assert!(engine.get_user(&username).await.is_ok());

        // Revoke credentials
        engine.revoke_credentials(&username).await.unwrap();

        // User should not exist
        assert!(engine.get_user(&username).await.is_err());
    }

    #[tokio::test]
    async fn test_role_crud_operations() {
        let engine = RabbitMQEngine::new();

        let role = RabbitMQRole {
            name: "test-role".to_string(),
            vhosts: vec![VHostPermission {
                vhost: "/test".to_string(),
                configure: ".*".to_string(),
                write: ".*".to_string(),
                read: ".*".to_string(),
                topic_permissions: vec![],
            }],
            tags: vec!["monitoring".to_string()],
            ttl: Duration::hours(2),
        };

        // Create
        engine.create_role(role.clone()).await.unwrap();

        // Read
        let retrieved = engine.get_role("test-role").await.unwrap();
        assert_eq!(retrieved.name, "test-role");
        assert_eq!(retrieved.vhosts.len(), 1);

        // List
        let roles = engine.list_roles().await;
        assert_eq!(roles.len(), 1);
        assert!(roles.contains(&"test-role".to_string()));

        // Delete
        engine.delete_role("test-role").await.unwrap();
        assert!(engine.get_role("test-role").await.is_err());
    }

    #[tokio::test]
    async fn test_topic_permissions() {
        let engine = RabbitMQEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = RabbitMQRole {
            name: "topic-role".to_string(),
            vhosts: vec![VHostPermission {
                vhost: "/".to_string(),
                configure: "".to_string(),
                write: ".*".to_string(),
                read: ".*".to_string(),
                topic_permissions: vec![
                    TopicPermission {
                        exchange: "amq.topic".to_string(),
                        write: "^logs\\..*".to_string(),
                        read: "^logs\\..*".to_string(),
                    },
                    TopicPermission {
                        exchange: "events".to_string(),
                        write: "^events\\.app\\..*".to_string(),
                        read: "^events\\.app\\..*".to_string(),
                    },
                ],
            }],
            tags: vec![],
            ttl: Duration::hours(6),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("topic-role").await.unwrap();

        assert!(user.username.starts_with("vault-token-"));
        assert_eq!(user.vhosts.len(), 1);
    }
}
