//! AliCloud OSS storage backend implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{StorageBackend, StorageError, SecretEntry, StorageResult};

/// AliCloud OSS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliCloudOSSConfig {
    pub endpoint: String,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub bucket: String,
    pub region: String,
    pub connection_timeout: u64,
    pub request_timeout: u64,
}

pub struct AliCloudOSSStorage {
    config: AliCloudOSSConfig,
    client: Option<Arc<AliCloudOSSClient>>,
}

struct AliCloudOSSClient;

impl AliCloudOSSStorage {
    pub fn new(config: AliCloudOSSConfig) -> Self {
        Self { config, client: None }
    }
}

#[async_trait]
impl Storage for AliCloudOSSStorage {
    async fn initialize(&mut self, _config: StorageConfig) -> Result<(), StorageError> {
        let client = Arc::new(AliCloudOSSClient);
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
        "alicloud_oss"
    }

    fn supports_versioning(&self) -> bool {
        true
    }

    fn supports_transactions(&self) -> bool {
        false
    }
}
