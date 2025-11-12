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

        // TODO: Implement when secreton_rabbitmq_utils is available
        // For now, return mock credentials
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
                self.config.connection_uri, username, vhost
            )),
        );

        tracing::warn!(
            "RabbitMQ credentials generated with stub implementation - secreton_rabbitmq_utils not available"
        );
        Ok(result)

        // Commented out until secreton_rabbitmq_utils is available:
        // let utils_config = secreton_rabbitmq_utils::RabbitMqConfig {
        //     connection_uri: self.config.connection_uri.clone(),
        //     username: self.config.username.clone(),
        //     password: self.config.password.clone(),
        //     vhost: self.config.vhost.clone(),
        //     default_lease_ttl: self.config.default_lease_ttl,
        // };
        // let creds_data = secreton_rabbitmq_utils::RabbitMqOperations::generate_credentials(
        //     &utils_config, &username, &password, "management", vhost, ".*", ".*", ".*"
        // ).await?;
        // let mut result = HashMap::new();
        // for (key, value) in creds_data {
        //     result.insert(key, Value::String(value.as_str().unwrap_or("").to_string()));
        // }
        // Ok(result)
    }
}
