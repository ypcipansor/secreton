//! OCI storage backend implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{Storage, StorageError, StorageEntry, StorageConfig};

/// OCI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCIConfig {
    pub compartment_id: String,
    pub bucket: String,
    pub region: String,
    pub config_file: String,
    pub profile: String,
}

pub struct OCIStorage {
    config: OCIConfig,
    client: Option<Arc<OCIClient>>,
}

struct OCIClient;

impl OCIStorage {
    pub fn new(config: OCIConfig) -> Self {
        Self { config, client: None }
    }
}

#[async_trait]
impl Storage for OCIStorage {
    async fn initialize(&mut self, _config: StorageConfig) -> Result<(), StorageError> {
        let client = Arc::new(OCIClient);
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
        "oci"
    }

    fn supports_versioning(&self) -> bool {
        true
    }

    fn supports_transactions(&self) -> bool {
        false
    }
}
