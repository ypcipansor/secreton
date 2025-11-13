//! RabbitMQ secret engine implementation

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// rabbitmq secret engine
pub struct RabbitmqEngine {
    config: RabbitmqConfig,
    _http_client: Client,
    enabled: bool,
}

impl RabbitmqEngine {
    pub fn new(config: RabbitmqConfig) -> Self {
        let http_client = Client::new();
        Self {
            config,
            _http_client: http_client,
            enabled: false,
        }
    }
}

#[async_trait]
impl SecretEngine for RabbitmqEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Rabbitmq
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, _path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Rabbitmq".to_string()));
        }
        Ok(None)
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Rabbitmq".to_string()));
        }

        match path {
            "creds" => {
                // Generate RabbitMQ credentials
                let creds_data = self.generate_rabbitmq_credentials(&data).await?;
                Ok(Secret {
                    id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: creds_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_by: "rabbitmq-engine".to_string(),
                        updated_by: "rabbitmq-engine".to_string(),
                        lease_id: None,
                        lease_duration: Some(self.config.default_lease_ttl),
                        ..Default::default()
                    },
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
            }
            _ => Err(SecretError::InvalidPath(format!(
                "Unsupported RabbitMQ path: {}",
                path
            ))),
        }
    }

    async fn delete(&mut self, _path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Rabbitmq".to_string()));
        }
        Ok(())
    }

    async fn list(&self, _path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Rabbitmq".to_string()));
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
    }
}

impl RabbitmqEngine {
    /// Generate a secure random password
    fn generate_password(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate RabbitMQ credentials
    async fn generate_rabbitmq_credentials(
        &self,
        _data: &HashMap<String, Value>,
    ) -> SecretResult<HashMap<String, Value>> {
        // Generate unique username and password
        let username = format!("vault_{}", Uuid::new_v4().simple());
        let password = self.generate_password(16);

        // Default vhost
        let vhost = self.config.vhost.as_deref().unwrap_or("/");

        // Create user via RabbitMQ Management API
        self.create_rabbitmq_user(&username, &password, &[]).await?;

        // Set default permissions for the user
        self.set_rabbitmq_permissions(&username, vhost, ".*", ".*", ".*").await?;

        let mut result = HashMap::new();
        result.insert("username".to_string(), Value::String(username.clone()));
        result.insert("password".to_string(), Value::String(password));
        result.insert("vhost".to_string(), Value::String(vhost.to_string()));
        result.insert(
            "connection_uri".to_string(),
            Value::String(self.config.connection_uri.clone()),
        );
        result.insert(
            "management_url".to_string(),
            Value::String(format!(
                "{}/#/login/{}/{}",
                self.get_management_url(&self.config.connection_uri)?, username, vhost
            )),
        );

        Ok(result)
    }

    /// Get management API URL from connection URI
    fn get_management_url(&self, connection_uri: &str) -> SecretResult<String> {
        // Parse AMQP URI: amqp://user:pass@host:port/vhost
        let url = url::Url::parse(connection_uri)
            .map_err(|e| SecretError::InvalidConfiguration(format!("Invalid connection URI: {}", e)))?;

        let host = url.host_str().ok_or_else(|| {
            SecretError::InvalidConfiguration("Missing host in connection URI".to_string())
        })?;
        let port = url.port().unwrap_or(5672); // Default AMQP port

        // Management API typically runs on port 15672 (AMQP port + 10000)
        let management_port = port + 10000;

        Ok(format!("http://{}:{}", host, management_port))
    }

    /// Create user in RabbitMQ via Management API
    async fn create_rabbitmq_user(&self, username: &str, password: &str, tags: &[String]) -> SecretResult<()> {
        let management_url = self.get_management_url(&self.config.connection_uri)?;
        let client = reqwest::Client::new();

        // Create user payload
        let user_payload = serde_json::json!({
            "password": password,
            "tags": tags.join(",")
        });

        let response = client
            .put(&format!("{}/api/users/{}", management_url, username))
            .basic_auth(&self.config.username, Some(&self.config.password))
            .json(&user_payload)
            .send()
            .await
            .map_err(|e| SecretError::BackendConnectionFailed(format!("Failed to create user: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(SecretError::BackendOperationFailed(format!(
                "Failed to create user {}: {} - {}",
                username, status, error_text
            )));
        }

        Ok(())
    }

    /// Set permissions for user on vhost via Management API
    async fn set_rabbitmq_permissions(&self, username: &str, vhost: &str, configure: &str, write: &str, read: &str) -> SecretResult<()> {
        let management_url = self.get_management_url(&self.config.connection_uri)?;
        let client = reqwest::Client::new();

        // Set permissions payload
        let permissions_payload = serde_json::json!({
            "configure": configure,
            "write": write,
            "read": read
        });

        let response = client
            .put(&format!(
                "{}/api/permissions/{}/{}",
                management_url,
                urlencoding::encode(vhost),
                username
            ))
            .basic_auth(&self.config.username, Some(&self.config.password))
            .json(&permissions_payload)
            .send()
            .await
            .map_err(|e| {
                SecretError::BackendConnectionFailed(format!("Failed to set permissions: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(SecretError::BackendOperationFailed(format!(
                "Failed to set permissions for user {} on vhost {}: {} - {}",
                username, vhost, status, error_text
            )));
        }

        Ok(())
    }
}
