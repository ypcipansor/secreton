//! ZooKeeper storage backend implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{StorageBackend, StorageError, VaultEntry, StorageResult};

/// ZooKeeper configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZooKeeperConfig {
    pub hosts: Vec<String>,
    pub base_path: String,
    pub connection_timeout: u64,
    pub session_timeout: u64,
}

pub struct ZooKeeperStorage {
    config: ZooKeeperConfig,
    client: Option<Arc<ZooKeeperClient>>,
}

struct ZooKeeperClient;

impl ZooKeeperStorage {
    pub fn new(config: ZooKeeperConfig) -> Self {
        Self { config, client: None }
    }
}

#[async_trait]
impl Storage for ZooKeeperStorage {
    async fn initialize(&mut self, _config: StorageConfig) -> Result<(), StorageError> {
        let client = Arc::new(ZooKeeperClient);
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
        "zookeeper"
    }

    fn supports_versioning(&self) -> bool {
        true
    }

    fn supports_transactions(&self) -> bool {
        false
    }
}
