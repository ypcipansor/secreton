//! AWS secret engine for AWS integration

use crate::backend::AwsBackend;
use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// AWS secret engine
pub struct AwsEngine {
    config: AwsConfig,
    backend: AwsBackend,
    enabled: bool,
}

impl AwsEngine {
    pub fn new(config: AwsConfig) -> Self {
        let backend = AwsBackend::new(
            config.access_key.clone(),
            config.secret_key.clone(),
            config.region.clone(),
        );

        Self {
            config,
            backend,
            enabled: false,
        }
    }
}

#[async_trait]
impl SecretEngine for AwsEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Aws
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        if let Some(aws_config) = config.config.get("aws")
            && let Ok(aws_config) = serde_json::from_value(aws_config.clone())
        {
            self.config = aws_config;
        }

        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("aws".to_string()));
        }

        match path {
            "creds/sts" => {
                // Generate STS credentials
                let creds_data = self.generate_sts_credentials().await?;
                Ok(Some(Secret {
                    id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: creds_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_by: "aws-engine".to_string(),
                        updated_by: "aws-engine".to_string(),
                        lease_id: None,
                        lease_duration: Some(self.config.default_lease_ttl),
                        ..Default::default()
                    },
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                }))
            }
            _ => Ok(None),
        }
    }

    async fn write(&mut self, path: &str, _data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("aws".to_string()));
        }

        match path {
            "creds" => {
                // Generate AWS credentials
                let creds_data = self.generate_sts_credentials().await?;
                Ok(Secret {
                    id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: creds_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_by: "aws-engine".to_string(),
                        updated_by: "aws-engine".to_string(),
                        lease_id: None,
                        lease_duration: Some(self.config.default_lease_ttl),
                        ..Default::default()
                    },
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
            }
            _ => Err(SecretError::InvalidPath(format!(
                "Unsupported AWS path: {}",
                path
            ))),
        }
    }

    async fn delete(&mut self, _path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("aws".to_string()));
        }
        Ok(())
    }

    async fn list(&self, _path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("aws".to_string()));
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

impl AwsEngine {
    /// Generate STS credentials
    async fn generate_sts_credentials(&self) -> SecretResult<HashMap<String, Value>> {
        // Use the AWS backend to generate real STS credentials
        let ttl_seconds = self.config.default_lease_ttl as u32;
        let credentials = self
            .backend
            .generate_credentials(None, ttl_seconds)
            .await
            .map_err(|e| SecretError::BackendOperationFailed(format!("AWS STS error: {}", e)))?;

        // Convert to the expected format
        let mut creds_data = HashMap::new();
        for (key, value) in credentials {
            creds_data.insert(key, value);
        }

        Ok(creds_data)
    }
}
