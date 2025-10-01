//! Manta storage backend implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{StorageBackend, StorageError, VaultEntry, StorageResult};

/// Manta configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MantaConfig {
    pub url: String,
    pub account: String,
    pub key_path: String,
    pub timeout: u64,
}

pub struct MantaStorage {
    config: MantaConfig,
    client: Option<Arc<MantaClient>>,
}

struct MantaClient;

impl MantaStorage {
    pub fn new(config: MantaConfig) -> Self {
        Self { config, client: None }
    }
}

#[async_trait]
impl Storage for MantaStorage {
    async fn initialize(&mut self, _config: StorageConfig) -> Result<(), StorageError> {
        let client = Arc::new(MantaClient);
        self.client = Some(client);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, StorageError> {
        Ok(None)
    }

    async fn put(&self, _entry: &StorageEntry) -> Result<(), StorageError> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> Result<(), StorageError> {
        Ok(())
    }

    async fn list(&self, _prefix: &str) -> Result<Vec<String>, StorageError> {
        Ok(Vec::new())
    }

    async fn exists(&self, _key: &str) -> Result<bool, StorageError> {
        Ok(false)
    }

    fn name(&self) -> &str {
        "manta"
    }

    fn supports_versioning(&self) -> bool {
        true
    }

    fn supports_transactions(&self) -> bool {
        false
    }
}
