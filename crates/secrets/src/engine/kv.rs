//! Key-Value secret engine implementation

use async_trait::async_trait;
use std::collections::HashMap;
use serde_json::Value;
use tokio::sync::RwLock;
use crate::model::*;
use crate::error::*;
use crate::service::*;

/// KV v2 secret engine with versioning support
pub struct KvEngine {
    config: KvConfig,
    enabled: bool,
    storage: RwLock<HashMap<String, Vec<SecretVersion>>>,
}

impl KvEngine {
    pub fn new(config: KvConfig) -> Self {
        Self {
            config,
            enabled: false,
            storage: RwLock::new(HashMap::new()),
        }
    }

    /// Get the latest version of a secret
    async fn get_latest_version(&self, path: &str) -> SecretResult<Option<SecretVersion>> {
        let storage = self.storage.read().await;
        let versions = storage.get(path);

        match versions {
            Some(versions) if !versions.is_empty() => {
                // Find the latest non-deleted version
                for version in versions.iter().rev() {
                    if !version.deleted {
                        return Ok(Some(version.clone()));
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Add a new version to a secret
    async fn add_version(&mut self, path: String, data: HashMap<String, Value>, created_by: String) -> SecretResult<SecretVersion> {
        let mut storage = self.storage.write().await;
        let versions = storage.entry(path.clone()).or_insert_with(Vec::new);

        // Check if we need to delete old versions
        if versions.len() >= self.config.max_versions as usize {
            // Remove oldest versions, keeping at least one
            let keep_versions = (self.config.max_versions / 2) as usize;
            versions.drain(0..versions.len().saturating_sub(keep_versions));
        }

        let version = versions.len() as u64 + 1;
        let secret_version = SecretVersion {
            version,
            data,
            created_at: chrono::Utc::now(),
            created_by,
            deleted: false,
        };

        versions.push(secret_version.clone());
        Ok(secret_version)
    }
}

#[async_trait]
impl SecretEngine for KvEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Kv
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        // Validate configuration
        if let Some(kv_config) = config.config.get("kv") {
            if let Ok(kv_config) = serde_json::from_value(kv_config.clone()) {
                self.config = kv_config;
            }
        }

        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("kv".to_string()));
        }

        let version = self.get_latest_version(path).await?;
        match version {
            Some(version) => {
                let secret = Secret {
                    id: uuid::Uuid::new_v4(),
                    path: path.to_string(),
                    data: version.data,
                    metadata: SecretMetadata {
                        version: version.version,
                        created_by: version.created_by.clone(),
                        updated_by: version.created_by,
                        lease_id: None,
                        lease_duration: None,
                        tags: HashMap::new(),
                    },
                    created_at: version.created_at,
                    updated_at: version.created_at,
                };
                Ok(Some(secret))
            }
            None => Ok(None),
        }
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("kv".to_string()));
        }

        let version = self.add_version(path.to_string(), data, "system".to_string()).await?;

        let secret = Secret {
            id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            data: version.data,
            metadata: SecretMetadata {
                version: version.version,
                created_by: version.created_by.clone(),
                updated_by: version.created_by,
                lease_id: None,
                lease_duration: None,
                tags: HashMap::new(),
            },
            created_at: version.created_at,
            updated_at: version.created_at,
        };

        Ok(secret)
    }

    async fn delete(&mut self, path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("kv".to_string()));
        }

        let mut storage = self.storage.write().await;
        if let Some(versions) = storage.get_mut(path) {
            if let Some(latest) = versions.last_mut() {
                latest.deleted = true;
            }
        }

        Ok(())
    }

    async fn list(&self, path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("kv".to_string()));
        }

        let storage = self.storage.read().await;
        let mut keys = Vec::new();

        for key in storage.keys() {
            if key.starts_with(path) {
                keys.push(key.clone());
            }
        }

        Ok(keys)
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