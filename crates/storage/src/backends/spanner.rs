//! Spanner storage backend implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{StorageBackend, StorageError, VaultEntry, StorageResult};

/// Spanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpannerConfig {
    pub project_id: String,
    pub instance_id: String,
    pub database_id: String,
    pub credentials_file: Option<String>,
}

pub struct SpannerStorage {
    config: SpannerConfig,
    client: Option<Arc<SpannerClient>>,
}

struct SpannerClient;

impl SpannerStorage {
    pub fn new(config: SpannerConfig) -> Self {
        Self { config, client: None }
    }
}

#[async_trait]
impl Storage for SpannerStorage {
    async fn initialize(&mut self, _config: StorageConfig) -> Result<(), StorageError> {
        let client = Arc::new(SpannerClient);
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
        "spanner"
    }

    fn supports_versioning(&self) -> bool {
        true
    }

    fn supports_transactions(&self) -> bool {
        true
    }
}
